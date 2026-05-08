/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — Symmetric Cipher (AES-CBC and AES-GCM).
 *
 * Pattern demonstrated:
 *   • encrypt_init / decrypt_init distinction.
 *   • update() output buffering (CBC block alignment).
 *   • final() with padding (PKCS#7 for CBC) and tag handling (GCM).
 *   • AEAD get_ctx_params / set_ctx_params: IV, tag, AAD.
 *   • Static get_params: key/block/iv sizes, flags.
 *   • One CIPHER_IMPL descriptor drives all four variants.
 *
 * The actual AES key schedule and block encryption are delegated to a child
 * OSSL_LIB_CTX so we avoid re-entering this provider.  Replace the child-ctx
 * EVP_* calls with your hardware engine calls to accelerate AES.
 */

#include "provider.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── Cipher variant descriptor ───────────────────────────────────────────── */

typedef struct cipher_impl_st {
    const char *evp_name;       /* name used with child EVP_CIPHER_fetch()  */
    int         key_bits;
    int         iv_len;
    int         block_size;
    int         is_aead;        /* 1 = GCM/CCM; 0 = CBC/ECB               */
    uint64_t    flags;          /* PROV_CIPHER_FLAG_* bits                  */
} CIPHER_IMPL;

/* ── Per-instance context ────────────────────────────────────────────────── */

typedef struct cipher_ctx_st {
    void             *provctx;
    const CIPHER_IMPL *impl;
    EVP_CIPHER_CTX   *evpctx;  /* child-ctx cipher handle                  */

    /* AEAD extras */
    unsigned char tag[16];
    size_t        tag_len;
    int           tag_set;     /* 1 after explicit set_ctx_params(tag)      */
    int           enc;         /* 1 = encrypting, 0 = decrypting            */
    int           padding;     /* 1 = PKCS#7 padding enabled (default), 0 = disabled */
} CIPHER_CTX;

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

static void *cipher_newctx(void *vprovctx, const CIPHER_IMPL *impl)
{
    CIPHER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->provctx  = vprovctx;
    ctx->impl     = impl;
    ctx->tag_len  = 16;
    ctx->enc      = -1;
    ctx->padding  = 1;
    return ctx;
}

static void cipher_freectx(void *vctx)
{
    CIPHER_CTX *ctx = vctx;
    if (!ctx) return;
    EVP_CIPHER_CTX_free(ctx->evpctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *cipher_dupctx(void *vctx)
{
    CIPHER_CTX *src = vctx;
    CIPHER_CTX *dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst) return NULL;
    *dst = *src;
    dst->evpctx = NULL;
    if (src->evpctx) {
        dst->evpctx = EVP_CIPHER_CTX_new();
        if (!dst->evpctx || !EVP_CIPHER_CTX_copy(dst->evpctx, src->evpctx)) {
            EVP_CIPHER_CTX_free(dst->evpctx);
            OPENSSL_free(dst);
            return NULL;
        }
    }
    return dst;
}

/* ── Internal helper: (re-)initialise the child EVP_CIPHER_CTX ───────────── */

static int cipher_do_init(CIPHER_CTX *ctx, const unsigned char *key,
                          size_t keylen, const unsigned char *iv,
                          size_t ivlen, int enc,
                          const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = prov_libctx(ctx->provctx);
    EVP_CIPHER    *ciph;
    int            rc = 0;

    (void)params;

    /* For GCM, enforce standard 12-byte IV */
    if (ctx->impl->is_aead && iv && ivlen != (size_t)ctx->impl->iv_len)
        return 0;

    /* keylen == 0 means "use the algorithm's natural key length" */
    if (key) {
        size_t expected = (size_t)(ctx->impl->key_bits / 8);
        if (keylen == 0)
            keylen = expected;
        else if (keylen != expected)
            return 0;
    }

    /* Fetch from child lib context (won't re-enter this provider) */
    ciph = EVP_CIPHER_fetch(libctx, ctx->impl->evp_name, "provider!=sample");
    if (!ciph) return 0;

    if (!ctx->evpctx) {
        ctx->evpctx = EVP_CIPHER_CTX_new();
        if (!ctx->evpctx) goto out;
    }

    ctx->enc = enc;

    if (!EVP_CipherInit_ex2(ctx->evpctx, ciph, key, iv, enc, NULL))
        goto out;

    EVP_CIPHER_CTX_set_padding(ctx->evpctx, ctx->padding);
    rc = 1;
out:
    EVP_CIPHER_free(ciph);
    return rc;
}

static int cipher_encrypt_init(void *vctx,
                                const unsigned char *key, size_t keylen,
                                const unsigned char *iv,  size_t ivlen,
                                const OSSL_PARAM params[])
{
    return cipher_do_init(vctx, key, keylen, iv, ivlen, 1, params);
}

static int cipher_decrypt_init(void *vctx,
                                const unsigned char *key, size_t keylen,
                                const unsigned char *iv,  size_t ivlen,
                                const OSSL_PARAM params[])
{
    return cipher_do_init(vctx, key, keylen, iv, ivlen, 0, params);
}

/* ── update / final ───────────────────────────────────────────────────────── */

static int cipher_update(void *vctx,
                          unsigned char *out, size_t *outl, size_t outsz,
                          const unsigned char *in,  size_t inl)
{
    CIPHER_CTX *ctx = vctx;
    int outlen = 0;

    if (!ctx->evpctx) return 0;

    /* out == NULL: AAD input for AEAD ciphers — forward directly */
    if (out == NULL) {
        if (!EVP_CipherUpdate(ctx->evpctx, NULL, &outlen, in, (int)inl))
            return 0;
        *outl = 0;
        return 1;
    }

    if (outsz < inl + (size_t)(ctx->impl->block_size - 1)) return 0;

    if (!EVP_CipherUpdate(ctx->evpctx, out, &outlen, in, (int)inl))
        return 0;
    *outl = (size_t)outlen;
    return 1;
}

static int cipher_final(void *vctx,
                         unsigned char *out, size_t *outl, size_t outsz)
{
    CIPHER_CTX *ctx = vctx;
    int outlen = 0;

    if (!ctx->evpctx) return 0;

    /* For GCM decrypt: set expected tag before finalising */
    if (ctx->impl->is_aead && !ctx->enc && ctx->tag_set) {
        OSSL_PARAM tp[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                              ctx->tag, ctx->tag_len),
            OSSL_PARAM_construct_end()
        };
        if (!EVP_CIPHER_CTX_set_params(ctx->evpctx, tp))
            return 0;
    }

    /* For AEAD (GCM): OpenSSL passes outsz=0 to final; no plaintext is produced */
    if (!ctx->impl->is_aead && outsz < (size_t)ctx->impl->block_size) return 0;

    if (!EVP_CipherFinal_ex(ctx->evpctx, out, &outlen))
        return 0;

    /* Retrieve GCM auth tag after successful encryption */
    if (ctx->impl->is_aead && ctx->enc) {
        OSSL_PARAM tp[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                              ctx->tag, ctx->tag_len),
            OSSL_PARAM_construct_end()
        };
        (void)EVP_CIPHER_CTX_get_params(ctx->evpctx, tp);
    }

    *outl = (size_t)outlen;
    return 1;
}

/* One-shot cipher() (optional but convenient for short messages) */
static int cipher_cipher(void *vctx,
                          unsigned char *out, size_t *outl, size_t outsz,
                          const unsigned char *in, size_t inl)
{
    size_t part = 0;
    if (!cipher_update(vctx, out, &part, outsz, in, inl)) return 0;
    size_t fin = 0;
    if (!cipher_final(vctx, out + part, &fin, outsz - part)) return 0;
    *outl = part + fin;
    return 1;
}

/* ── Static algorithm parameters ─────────────────────────────────────────── */

static int cipher_get_params(const CIPHER_IMPL *impl, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, (size_t)(impl->key_bits / 8)))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, (size_t)impl->iv_len))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, (size_t)impl->block_size))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) != NULL) {
        unsigned int mode = impl->is_aead ? EVP_CIPH_GCM_MODE : EVP_CIPH_CBC_MODE;
        if (!OSSL_PARAM_set_uint(p, mode)) return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD)) != NULL
        && !OSSL_PARAM_set_int(p, impl->is_aead))
        return 0;

    return 1;
}

static const OSSL_PARAM cipher_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN,     NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN,      NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_uint  (OSSL_CIPHER_PARAM_MODE,       NULL),
    OSSL_PARAM_int   (OSSL_CIPHER_PARAM_AEAD,       NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *cipher_gettable_params(void *vpctx)
{ (void)vpctx; return cipher_known_gettable_params; }

/* ── Per-context parameters (IV, AEAD tag, AAD) ─────────────────────────── */

static int cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    CIPHER_CTX *ctx = vctx;
    OSSL_PARAM *p;

    /* Current IV — forward to the child EVP_CIPHER_CTX */
    if (ctx->evpctx &&
        (OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV) != NULL ||
         OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV) != NULL)) {
        if (!EVP_CIPHER_CTX_get_params(ctx->evpctx, params))
            return 0;
    }

    /* AEAD tag (after encryption) */
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG)) != NULL) {
        if (!ctx->impl->is_aead || !ctx->enc) return 0;
        if (p->data_size < ctx->tag_len) return 0;
        memcpy(p->data, ctx->tag, ctx->tag_len);
        p->return_size = ctx->tag_len;
    }

    /* Tag length */
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, ctx->tag_len))
        return 0;

    return 1;
}

static int cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    CIPHER_CTX        *ctx = vctx;
    const OSSL_PARAM  *p;

    /* Padding enable/disable */
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING)) != NULL) {
        unsigned int pad = 1;
        if (!OSSL_PARAM_get_uint(p, &pad)) return 0;
        ctx->padding = (int)pad;
        if (ctx->evpctx)
            EVP_CIPHER_CTX_set_padding(ctx->evpctx, ctx->padding);
    }

    /* IV */
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL) {
        size_t ivl = 0;
        if (!OSSL_PARAM_get_size_t(p, &ivl)) return 0;
        if (ctx->evpctx)
            (void)EVP_CIPHER_CTX_set_params(ctx->evpctx, params);
    }

    /* AEAD tag (for decryption) */
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG)) != NULL) {
        if (!ctx->impl->is_aead) return 0;
        if (p->data_size > sizeof(ctx->tag)) return 0;
        memcpy(ctx->tag, p->data, p->data_size);
        ctx->tag_len = p->data_size;
        ctx->tag_set = 1;
    }

    /*
     * AAD for GCM: no OSSL_CIPHER_PARAM_AEAD_AAD in OpenSSL 3.x.
     * Callers must supply AAD via EVP_CipherUpdate(ctx, NULL, &outl, aad, len)
     * before the first data update.  The cipher context simply forwards
     * that call through to the child EVP_CIPHER_CTX automatically in
     * cipher_update() when out == NULL.
     */

    return 1;
}

static const OSSL_PARAM cipher_known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV,           NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV,   NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,     NULL, 0),
    OSSL_PARAM_size_t      (OSSL_CIPHER_PARAM_AEAD_TAGLEN,  NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM cipher_known_settable_ctx_params[] = {
    OSSL_PARAM_uint        (OSSL_CIPHER_PARAM_PADDING,  NULL),
    OSSL_PARAM_size_t      (OSSL_CIPHER_PARAM_IVLEN,    NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *cipher_gettable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return cipher_known_gettable_ctx_params; }

static const OSSL_PARAM *cipher_settable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return cipher_known_settable_ctx_params; }

/* ═══════════════════════════════════════════════════════════════════════════
 * §  Variant descriptors + dispatch tables
 *    One macro generates the four variants to avoid repetition.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAKE_CIPHER(PREFIX, EVP_NAME, KEY_BITS, IV_LEN, BLK, IS_AEAD, FLAGS) \
static const CIPHER_IMPL PREFIX##_impl = {                                    \
    EVP_NAME, KEY_BITS, IV_LEN, BLK, IS_AEAD, FLAGS                          \
};                                                                            \
static void *PREFIX##_newctx(void *vp)                                        \
{ return cipher_newctx(vp, &PREFIX##_impl); }                                 \
static int PREFIX##_get_params(OSSL_PARAM p[])                                \
{ return cipher_get_params(&PREFIX##_impl, p); }                              \
const OSSL_DISPATCH sample_##PREFIX##_functions[] = {                         \
    { OSSL_FUNC_CIPHER_NEWCTX,              FN(PREFIX##_newctx)           },  \
    { OSSL_FUNC_CIPHER_FREECTX,             FN(cipher_freectx)            },  \
    { OSSL_FUNC_CIPHER_DUPCTX,              FN(cipher_dupctx)             },  \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        FN(cipher_encrypt_init)       },  \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,        FN(cipher_decrypt_init)       },  \
    { OSSL_FUNC_CIPHER_UPDATE,              FN(cipher_update)             },  \
    { OSSL_FUNC_CIPHER_FINAL,               FN(cipher_final)              },  \
    { OSSL_FUNC_CIPHER_CIPHER,              FN(cipher_cipher)             },  \
    { OSSL_FUNC_CIPHER_GET_PARAMS,          FN(PREFIX##_get_params)       },  \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      FN(cipher_get_ctx_params)     },  \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      FN(cipher_set_ctx_params)     },  \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     FN(cipher_gettable_params)    },  \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, FN(cipher_gettable_ctx_params)},  \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, FN(cipher_settable_ctx_params)},  \
    PROV_DISPATCH_END                                                         \
}

/* AES-128-CBC:  128-bit key, 16-byte IV, 16-byte block, not AEAD */
MAKE_CIPHER(aes128cbc, "AES-128-CBC", 128, 16, 16, 0, 0);

/* AES-256-CBC:  256-bit key, 16-byte IV, 16-byte block, not AEAD */
MAKE_CIPHER(aes256cbc, "AES-256-CBC", 256, 16, 16, 0, 0);

/* AES-128-GCM:  128-bit key, 12-byte IV, 1-byte block (stream), AEAD */
MAKE_CIPHER(aes128gcm, "AES-128-GCM", 128, 12,  1, 1, 0);

/* AES-256-GCM:  256-bit key, 12-byte IV, 1-byte block (stream), AEAD */
MAKE_CIPHER(aes256gcm, "AES-256-GCM", 256, 12,  1, 1, 0);
