/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — Asymmetric Cipher (RSA-OAEP / PKCS#1 v1.5).
 *
 * Pattern demonstrated:
 *   • encrypt_init / decrypt_init sharing one context struct.
 *   • encrypt() / decrypt(): compute in single call (asymmetric ciphers
 *     do not support streaming update/final).
 *   • set_ctx_params: padding mode, OAEP digest/MGF1 digest, OAEP label.
 *   • get_ctx_params: max output length.
 *
 * Delegation to child OSSL_LIB_CTX prevents re-entry.
 */

#include "provider.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── Key accessor (same layout trick as signature.c) ─────────────────────── */

typedef struct { EVP_PKEY *pkey; } KEY_COMMON_AC;

/* ── Context ─────────────────────────────────────────────────────────────── */

typedef struct asym_ctx_st {
    void         *provctx;
    EVP_PKEY     *pkey;           /* borrowed */
    int           enc;            /* 1=encrypt, 0=decrypt */

    /* RSA-OAEP parameters */
    int           pad_mode;       /* RSA_PKCS1_OAEP_PADDING etc. */
    char          oaep_digest[64];
    char          mgf1_digest[64];
    unsigned char oaep_label[256];
    size_t        oaep_label_len;
} ASYM_CTX;

static void *asym_newctx(void *vprovctx, const char *propq)
{
    ASYM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    (void)propq;
    if (!ctx) return NULL;
    ctx->provctx  = vprovctx;
    ctx->pad_mode = RSA_PKCS1_OAEP_PADDING;
    memcpy(ctx->oaep_digest, "SHA2-256", 9);
    memcpy(ctx->mgf1_digest, "SHA2-256", 9);
    return ctx;
}

static void asym_freectx(void *vctx)
{
    OPENSSL_clear_free(vctx, sizeof(ASYM_CTX));
}

static void *asym_dupctx(void *vctx)
{
    ASYM_CTX *src = vctx;
    ASYM_CTX *dst = OPENSSL_memdup(src, sizeof(*src));
    return dst;
}

/* ── Init ────────────────────────────────────────────────────────────────── */

static int asym_encrypt_init(void *vctx, void *vkey,
                               const OSSL_PARAM params[])
{
    ASYM_CTX *ctx = vctx;
    ctx->pkey = ((KEY_COMMON_AC *)vkey)->pkey;
    ctx->enc  = 1;
    (void)params;
    return ctx->pkey != NULL;
}

static int asym_decrypt_init(void *vctx, void *vkey,
                               const OSSL_PARAM params[])
{
    ASYM_CTX *ctx = vctx;
    ctx->pkey = ((KEY_COMMON_AC *)vkey)->pkey;
    ctx->enc  = 0;
    (void)params;
    return ctx->pkey != NULL;
}

/* ── Encrypt / Decrypt ───────────────────────────────────────────────────── */

static int asym_do_crypt(ASYM_CTX *ctx, int enc,
                          unsigned char *out, size_t *outlen, size_t outsize,
                          const unsigned char *in, size_t inlen)
{
    OSSL_LIB_CTX *libctx = prov_libctx(ctx->provctx);
    EVP_PKEY_CTX *pkctx  = EVP_PKEY_CTX_new_from_pkey(libctx, ctx->pkey,
                                                        "provider!=sample");
    if (!pkctx) return 0;

    int rc = 0;

    if (enc ? EVP_PKEY_encrypt_init(pkctx) <= 0 : EVP_PKEY_decrypt_init(pkctx) <= 0) {
        goto init_failed;
    }

    /* Set padding */
    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, ctx->pad_mode) <= 0)
        goto out;

    if (ctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
        EVP_MD *md = EVP_MD_fetch(libctx, ctx->oaep_digest, "provider!=sample");
        if (md) {
            EVP_PKEY_CTX_set_rsa_oaep_md(pkctx, md);
            EVP_MD_free(md); /* OpenSSL 3.x: name-only path, no ownership transfer */
        }
        EVP_MD *mgf1 = EVP_MD_fetch(libctx, ctx->mgf1_digest, "provider!=sample");
        if (mgf1) {
            EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1);
            EVP_MD_free(mgf1);
        }
        if (ctx->oaep_label_len) {
            unsigned char *lbl = OPENSSL_memdup(ctx->oaep_label,
                                                ctx->oaep_label_len);
            if (lbl)
                EVP_PKEY_CTX_set0_rsa_oaep_label(pkctx, lbl,
                                                   (int)ctx->oaep_label_len);
        }
    }

    /* Probe output size when out == NULL */
    if (!out) {
        rc = (enc ? EVP_PKEY_encrypt : EVP_PKEY_decrypt)
                 (pkctx, NULL, outlen, in, inlen) > 0;
        goto out;
    }

    rc = (enc ? EVP_PKEY_encrypt : EVP_PKEY_decrypt)
             (pkctx, out, outlen, in, inlen) > 0;
    if (rc && *outlen > outsize) rc = 0;
    goto out;

init_failed:
out:
    EVP_PKEY_CTX_free(pkctx);
    return rc;
}

static int asym_encrypt(void *vctx,
                          unsigned char *out, size_t *outlen, size_t outsize,
                          const unsigned char *in, size_t inlen)
{
    return asym_do_crypt(vctx, 1, out, outlen, outsize, in, inlen);
}

static int asym_decrypt(void *vctx,
                          unsigned char *out, size_t *outlen, size_t outsize,
                          const unsigned char *in, size_t inlen)
{
    return asym_do_crypt(vctx, 0, out, outlen, outsize, in, inlen);
}

/* ── Parameters ──────────────────────────────────────────────────────────── */

static int asym_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    ASYM_CTX   *ctx = vctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE)) != NULL
        && !OSSL_PARAM_set_int(p, ctx->pad_mode)) return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, ctx->oaep_digest)) return 0;

    return 1;
}

static int asym_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    ASYM_CTX         *ctx = vctx;
    const OSSL_PARAM *p;
    size_t            len;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE)) != NULL)
        OSSL_PARAM_get_int(p, &ctx->pad_mode);

    if ((p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST)) != NULL) {
        size_t olen = p->data_size < sizeof(ctx->oaep_digest) - 1
                      ? p->data_size : sizeof(ctx->oaep_digest) - 1;
        memcpy(ctx->oaep_digest, p->data, olen);
        ctx->oaep_digest[olen] = '\0';
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST)) != NULL) {
        size_t mlen = p->data_size < sizeof(ctx->mgf1_digest) - 1
                      ? p->data_size : sizeof(ctx->mgf1_digest) - 1;
        memcpy(ctx->mgf1_digest, p->data, mlen);
        ctx->mgf1_digest[mlen] = '\0';
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL)) != NULL) {
        len = p->data_size < sizeof(ctx->oaep_label)
              ? p->data_size : sizeof(ctx->oaep_label);
        memcpy(ctx->oaep_label, p->data, len);
        ctx->oaep_label_len = len;
    }

    return 1;
}

static const OSSL_PARAM asym_settable_ctx_params_tbl[] = {
    OSSL_PARAM_int        (OSSL_ASYM_CIPHER_PARAM_PAD_MODE,    NULL),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM asym_gettable_ctx_params_tbl[] = {
    OSSL_PARAM_int        (OSSL_ASYM_CIPHER_PARAM_PAD_MODE,    NULL),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *asym_gettable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return asym_gettable_ctx_params_tbl; }
static const OSSL_PARAM *asym_settable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return asym_settable_ctx_params_tbl; }

/* ── Dispatch table ──────────────────────────────────────────────────────── */

const OSSL_DISPATCH sample_rsa_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX,              FN(asym_newctx)              },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX,             FN(asym_freectx)             },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX,              FN(asym_dupctx)              },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,        FN(asym_encrypt_init)        },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT,             FN(asym_encrypt)             },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,        FN(asym_decrypt_init)        },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT,             FN(asym_decrypt)             },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,      FN(asym_get_ctx_params)      },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,      FN(asym_set_ctx_params)      },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, FN(asym_gettable_ctx_params) },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, FN(asym_settable_ctx_params) },
    PROV_DISPATCH_END
};
