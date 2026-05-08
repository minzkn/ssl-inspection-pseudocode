/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — MAC (HMAC-SHA256).
 *
 * Pattern demonstrated:
 *   • MAC lifecycle: newctx / dupctx / freectx.
 *   • init() accepts a raw key via OSSL_MAC_PARAM_KEY set_ctx_params, or
 *     via the key/keylen arguments (OpenSSL 3.2+ style).
 *   • update / final streaming.
 *   • get_params: output size.
 *   • set_ctx_params: key, digest name (shows parameterised MACs).
 *
 * HMAC is built on the provider's own SHA-256 state so it works completely
 * standalone without calling back into libcrypto for the digest.
 */

#include "provider.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "sha256_internal.h"

/* Alias SHA256_STATE for HMAC internal use */
#define HMAC_SHA256_STATE  SHA256_STATE
#define hmac_sha256_init   sha256_init
#define hmac_sha256_update sha256_update
#define hmac_sha256_final  sha256_final

/* ── HMAC-SHA256 context ─────────────────────────────────────────────────── */

#define HMAC_SHA256_OUTLEN  32
#define HMAC_SHA256_KEYLEN  64   /* block size = padded key length */

typedef struct hmac_ctx_st {
    void             *provctx;
    HMAC_SHA256_STATE inner;     /* H(K XOR ipad || message) */
    HMAC_SHA256_STATE outer;     /* H(K XOR opad || inner)   */
    uint8_t           key[HMAC_SHA256_KEYLEN];
    size_t            keylen;
    int               key_set;
} HMAC_CTX;

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

static void *hmac_newctx(void *vprovctx)
{
    HMAC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx) ctx->provctx = vprovctx;
    return ctx;
}

static void *hmac_dupctx(void *vctx)
{
    HMAC_CTX *src = vctx;
    HMAC_CTX *dst = OPENSSL_memdup(src, sizeof(*src));
    return dst;
}

static void hmac_freectx(void *vctx)
{
    OPENSSL_clear_free(vctx, sizeof(HMAC_CTX));
}

/* ── Key setup helper ────────────────────────────────────────────────────── */

static void hmac_set_key(HMAC_CTX *ctx, const uint8_t *key, size_t keylen)
{
    uint8_t k[HMAC_SHA256_KEYLEN];
    memset(k, 0, sizeof(k));

    if (keylen > HMAC_SHA256_KEYLEN) {
        /* RFC 2104: hash the key if longer than block size */
        HMAC_SHA256_STATE tmp;
        hmac_sha256_init(&tmp);
        hmac_sha256_update(&tmp, key, keylen);
        hmac_sha256_final(&tmp, k);
        OPENSSL_cleanse(&tmp, sizeof(tmp));
    } else {
        memcpy(k, key, keylen);
    }

    memcpy(ctx->key, k, sizeof(k));
    ctx->keylen  = sizeof(k);
    ctx->key_set = 1;
    OPENSSL_cleanse(k, sizeof(k));
}

/* ── Streaming ────────────────────────────────────────────────────────────── */

static int hmac_init(void *vctx,
                     const unsigned char *key, size_t keylen,
                     const OSSL_PARAM params[])
{
    HMAC_CTX *ctx = vctx;
    uint8_t ipad[HMAC_SHA256_KEYLEN], opad[HMAC_SHA256_KEYLEN];

    /* Accept key via direct argument (OpenSSL 3.x style) */
    if (key && keylen > 0)
        hmac_set_key(ctx, key, keylen);

    /* Accept key via params (e.g. from EVP_MAC_CTX_set_params) */
    if (params) {
        const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
        if (p && p->data && p->data_size > 0)
            hmac_set_key(ctx, p->data, p->data_size);
    }

    if (!ctx->key_set) return 0;

    /* Build ipad / opad */
    for (size_t i = 0; i < HMAC_SHA256_KEYLEN; i++) {
        ipad[i] = ctx->key[i] ^ 0x36;
        opad[i] = ctx->key[i] ^ 0x5c;
    }

    /* Inner hash: H(K XOR ipad || ...) */
    hmac_sha256_init(&ctx->inner);
    hmac_sha256_update(&ctx->inner, ipad, sizeof(ipad));

    /* Outer hash: H(K XOR opad || inner) — will be completed in final() */
    hmac_sha256_init(&ctx->outer);
    hmac_sha256_update(&ctx->outer, opad, sizeof(opad));

    OPENSSL_cleanse(ipad, sizeof(ipad));
    OPENSSL_cleanse(opad, sizeof(opad));
    return 1;
}

static int hmac_update(void *vctx, const unsigned char *in, size_t inl)
{
    HMAC_CTX *ctx = vctx;
    hmac_sha256_update(&ctx->inner, in, inl);
    return 1;
}

static int hmac_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    HMAC_CTX *ctx = vctx;
    uint8_t inner_hash[32];

    if (outsz < HMAC_SHA256_OUTLEN) return 0;

    /* Complete inner hash */
    hmac_sha256_final(&ctx->inner, inner_hash);

    /* Feed inner hash into outer */
    hmac_sha256_update(&ctx->outer, inner_hash, sizeof(inner_hash));
    hmac_sha256_final(&ctx->outer, out);

    OPENSSL_cleanse(inner_hash, sizeof(inner_hash));
    *outl = HMAC_SHA256_OUTLEN;
    return 1;
}

/* ── Parameters ──────────────────────────────────────────────────────────── */

static const OSSL_PARAM hmac_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hmac_gettable_params(void *vpctx)
{ (void)vpctx; return hmac_known_gettable_params; }

static int hmac_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, HMAC_SHA256_OUTLEN))
        return 0;
    return 1;
}

static const OSSL_PARAM hmac_known_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY,    NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hmac_settable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return hmac_known_settable_ctx_params; }

static int hmac_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    HMAC_CTX         *ctx = vctx;
    const OSSL_PARAM *p   = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (p) hmac_set_key(ctx, p->data, p->data_size);
    return 1;
}

static const OSSL_PARAM hmac_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hmac_gettable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return hmac_known_gettable_ctx_params; }

static int hmac_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    (void)vctx;
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, HMAC_SHA256_OUTLEN))
        return 0;
    return 1;
}

/* ── Dispatch table ──────────────────────────────────────────────────────── */

const OSSL_DISPATCH sample_hmac_sha256_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX,              FN(hmac_newctx)              },
    { OSSL_FUNC_MAC_DUPCTX,              FN(hmac_dupctx)              },
    { OSSL_FUNC_MAC_FREECTX,             FN(hmac_freectx)             },
    { OSSL_FUNC_MAC_INIT,                FN(hmac_init)                },
    { OSSL_FUNC_MAC_UPDATE,              FN(hmac_update)              },
    { OSSL_FUNC_MAC_FINAL,               FN(hmac_final)               },
    { OSSL_FUNC_MAC_GET_PARAMS,          FN(hmac_get_params)          },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,      FN(hmac_get_ctx_params)      },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      FN(hmac_set_ctx_params)      },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,     FN(hmac_gettable_params)     },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, FN(hmac_gettable_ctx_params) },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, FN(hmac_settable_ctx_params) },
    PROV_DISPATCH_END
};
