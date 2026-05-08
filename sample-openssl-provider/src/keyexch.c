/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — Key Exchange (ECDH).
 *
 * Pattern demonstrated:
 *   • init(): associate local private key.
 *   • set_peer(): associate remote public key.
 *   • derive(): compute shared secret.
 *   • set_ctx_params / get_ctx_params: KDF hint, cofactor mode, pad.
 *   • dupctx: copy in-progress derivation.
 *
 * Delegation to child OSSL_LIB_CTX prevents re-entry.
 */

#include "provider.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── Key accessor ────────────────────────────────────────────────────────── */

typedef struct { EVP_PKEY *pkey; } KEY_COMMON_KE;

/* ── Context ─────────────────────────────────────────────────────────────── */

typedef struct keyexch_ctx_st {
    void     *provctx;
    EVP_PKEY *local_key;    /* our private EC key (borrowed) */
    EVP_PKEY *peer_key;     /* remote public EC key (borrowed) */
    int       cofactor;     /* 0 = disabled (standard ECDH)   */
    char      kdf_type[32]; /* e.g. "" = raw shared secret    */
} KEYEXCH_CTX;

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

static void *keyexch_newctx(void *vprovctx)
{
    KEYEXCH_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx) ctx->provctx = vprovctx;
    return ctx;
}

static void keyexch_freectx(void *vctx)
{
    OPENSSL_clear_free(vctx, sizeof(KEYEXCH_CTX));
}

static void *keyexch_dupctx(void *vctx)
{
    KEYEXCH_CTX *src = vctx;
    KEYEXCH_CTX *dst = OPENSSL_memdup(src, sizeof(*src));
    /* Keys are borrowed — no ref-count increment needed here;
     * the key objects outlive the exchange context.             */
    return dst;
}

/* ── init / set_peer ─────────────────────────────────────────────────────── */

static int keyexch_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    KEYEXCH_CTX *ctx = vctx;
    ctx->local_key = ((KEY_COMMON_KE *)vkey)->pkey;
    (void)params;
    return ctx->local_key != NULL;
}

static int keyexch_set_peer(void *vctx, void *vkey)
{
    KEYEXCH_CTX *ctx = vctx;
    ctx->peer_key = ((KEY_COMMON_KE *)vkey)->pkey;
    return ctx->peer_key != NULL;
}

/* ── derive ──────────────────────────────────────────────────────────────── */

static int keyexch_derive(void *vctx,
                           unsigned char *secret, size_t *secretlen,
                           size_t outsize)
{
    KEYEXCH_CTX  *ctx    = vctx;
    OSSL_LIB_CTX *libctx = prov_libctx(ctx->provctx);

    if (!ctx->local_key || !ctx->peer_key) return 0;

    EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new_from_pkey(libctx, ctx->local_key,
                                                       "provider!=sample");
    if (!pkctx) return 0;

    int rc = 0;
    if (EVP_PKEY_derive_init(pkctx) <= 0) goto out;

    if (ctx->cofactor) {
        OSSL_PARAM p[2] = {
            OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
                                     &ctx->cofactor),
            OSSL_PARAM_construct_end()
        };
        EVP_PKEY_CTX_set_params(pkctx, p);
    }

    if (EVP_PKEY_derive_set_peer(pkctx, ctx->peer_key) <= 0) goto out;

    /* First call with secret=NULL to get required size */
    if (EVP_PKEY_derive(pkctx, NULL, secretlen) <= 0) goto out;

    if (!secret) { rc = 1; goto out; }   /* size query only */
    if (*secretlen > outsize) goto out;

    rc = EVP_PKEY_derive(pkctx, secret, secretlen) > 0;

out:
    EVP_PKEY_CTX_free(pkctx);
    return rc;
}

/* ── Parameters ──────────────────────────────────────────────────────────── */

static int keyexch_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    KEYEXCH_CTX      *ctx = vctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params,
                 OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE)) != NULL)
        OSSL_PARAM_get_int(p, &ctx->cofactor);

    if ((p = OSSL_PARAM_locate_const(params,
                 OSSL_EXCHANGE_PARAM_KDF_TYPE)) != NULL) {
        size_t klen = p->data_size < sizeof(ctx->kdf_type) - 1
                      ? p->data_size : sizeof(ctx->kdf_type) - 1;
        memcpy(ctx->kdf_type, p->data, klen);
        ctx->kdf_type[klen] = '\0';
    }

    return 1;
}

static int keyexch_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    KEYEXCH_CTX *ctx = vctx;
    OSSL_PARAM  *p;

    if ((p = OSSL_PARAM_locate(params,
                OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE)) != NULL
        && !OSSL_PARAM_set_int(p, ctx->cofactor)) return 0;

    return 1;
}

static const OSSL_PARAM keyexch_settable_ctx_params_tbl[] = {
    OSSL_PARAM_int       (OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,             NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM keyexch_gettable_ctx_params_tbl[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *keyexch_settable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return keyexch_settable_ctx_params_tbl; }
static const OSSL_PARAM *keyexch_gettable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return keyexch_gettable_ctx_params_tbl; }

/* ── Dispatch table ──────────────────────────────────────────────────────── */

const OSSL_DISPATCH sample_ecdh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX,              FN(keyexch_newctx)              },
    { OSSL_FUNC_KEYEXCH_FREECTX,             FN(keyexch_freectx)             },
    { OSSL_FUNC_KEYEXCH_DUPCTX,              FN(keyexch_dupctx)              },
    { OSSL_FUNC_KEYEXCH_INIT,                FN(keyexch_init)                },
    { OSSL_FUNC_KEYEXCH_SET_PEER,            FN(keyexch_set_peer)            },
    { OSSL_FUNC_KEYEXCH_DERIVE,              FN(keyexch_derive)              },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,      FN(keyexch_set_ctx_params)      },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,      FN(keyexch_get_ctx_params)      },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, FN(keyexch_settable_ctx_params) },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, FN(keyexch_gettable_ctx_params) },
    PROV_DISPATCH_END
};
