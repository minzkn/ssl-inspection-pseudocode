/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — KDF (HKDF and PBKDF2).
 *
 * Pattern demonstrated:
 *   • KDF lifecycle: newctx / dupctx / freectx / reset.
 *   • set_ctx_params: mode (extract/expand/both), salt, IKM, info, key,
 *     desired output length.
 *   • derive(): single call produces keying material.
 *   • Two separate algorithms sharing generic glue code.
 *
 * Both KDFs delegate their underlying HMAC to the child OSSL_LIB_CTX so
 * we can call EVP_MAC safely without re-entering this provider.
 */

#include "provider.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * §1  HKDF (RFC 5869)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct hkdf_ctx_st {
    void          *provctx;
    EVP_KDF_CTX   *kctx;     /* child KDF handle        */
    EVP_KDF       *kdf;      /* child KDF object        */

    /* Current parameters — stored so reset() can recreate kctx */
    char           digest[64];    /* e.g. "SHA2-256"         */
    unsigned char  salt[256];
    size_t         saltlen;
    unsigned char  key[256];      /* IKM for HKDF            */
    size_t         keylen;
    unsigned char  info[256];
    size_t         infolen;
    int            mode;          /* HKDF_MODE_EXTRACT_AND_EXPAND etc. */
} HKDF_CTX;

static void *hkdf_newctx(void *vprovctx)
{
    HKDF_CTX       *ctx  = OPENSSL_zalloc(sizeof(*ctx));
    OSSL_LIB_CTX   *libctx = prov_libctx(vprovctx);

    if (!ctx) return NULL;
    ctx->provctx = vprovctx;
    memcpy(ctx->digest, "SHA2-256", 9);
    ctx->mode    = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

    ctx->kdf  = EVP_KDF_fetch(libctx, "HKDF", "provider!=sample");
    if (!ctx->kdf) { OPENSSL_free(ctx); return NULL; }

    ctx->kctx = EVP_KDF_CTX_new(ctx->kdf);
    if (!ctx->kctx) { EVP_KDF_free(ctx->kdf); OPENSSL_free(ctx); return NULL; }

    return ctx;
}

static void hkdf_freectx(void *vctx)
{
    HKDF_CTX *ctx = vctx;
    if (!ctx) return;
    EVP_KDF_CTX_free(ctx->kctx);
    EVP_KDF_free(ctx->kdf);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *hkdf_dupctx(void *vctx)
{
    HKDF_CTX *src = vctx;
    HKDF_CTX *dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst) return NULL;
    *dst = *src;
    dst->kdf  = NULL;
    dst->kctx = NULL;
    if (src->kctx) {
        dst->kctx = EVP_KDF_CTX_dup(src->kctx);
        if (!dst->kctx) { OPENSSL_free(dst); return NULL; }
        /* EVP_KDF_CTX_dup keeps a reference to the kdf object internally */
    }
    return dst;
}

static int hkdf_reset(void *vctx)
{
    HKDF_CTX *ctx = vctx;
    EVP_KDF_CTX_free(ctx->kctx);
    ctx->kctx = EVP_KDF_CTX_new(ctx->kdf);
    return ctx->kctx != NULL;
}

static int hkdf_derive(void *vctx, unsigned char *key, size_t keylen,
                        const OSSL_PARAM params[])
{
    HKDF_CTX *ctx = vctx;
    OSSL_PARAM p[8];
    int n = 0;
    int mode = ctx->mode;

    /* Allow derive-time param overrides */
    if (params) {
        const OSSL_PARAM *pp;
        if ((pp = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE)) != NULL)
            OSSL_PARAM_get_int(pp, &mode);
    }

    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                               ctx->digest, 0);
    p[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    if (ctx->saltlen)
        p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                    ctx->salt, ctx->saltlen);
    if (ctx->keylen)
        p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    ctx->key, ctx->keylen);
    if (ctx->infolen)
        p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                    ctx->info, ctx->infolen);
    p[n]   = OSSL_PARAM_construct_end();

    if (!EVP_KDF_CTX_set_params(ctx->kctx, p)) return 0;
    return EVP_KDF_derive(ctx->kctx, key, keylen, NULL);
}

/* ── Parameters ──────────────────────────────────────────────────────────── */

static const OSSL_PARAM hkdf_settable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_int        (OSSL_KDF_PARAM_MODE,   NULL),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT,  NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY,   NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO,  NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hkdf_settable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return hkdf_settable_ctx_params_tbl; }

static int hkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    HKDF_CTX         *ctx = vctx;
    const OSSL_PARAM *p;
    size_t            len;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST)) != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING || p->data == NULL)
            return 0;
        len = p->data_size < sizeof(ctx->digest) - 1
              ? p->data_size : sizeof(ctx->digest) - 1;
        memcpy(ctx->digest, p->data, len);
        ctx->digest[len] = '\0';
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE)) != NULL)
        OSSL_PARAM_get_int(p, &ctx->mode);

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL) {
        len = p->data_size < sizeof(ctx->salt) ? p->data_size : sizeof(ctx->salt);
        memcpy(ctx->salt, p->data, len);
        ctx->saltlen = len;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL) {
        len = p->data_size < sizeof(ctx->key) ? p->data_size : sizeof(ctx->key);
        memcpy(ctx->key, p->data, len);
        ctx->keylen = len;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO)) != NULL) {
        len = p->data_size < sizeof(ctx->info) ? p->data_size : sizeof(ctx->info);
        memcpy(ctx->info, p->data, len);
        ctx->infolen = len;
    }
    return 1;
}

static const OSSL_PARAM hkdf_gettable_ctx_params_tbl[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hkdf_gettable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return hkdf_gettable_ctx_params_tbl; }

static int hkdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)vctx;
    /* HKDF output length is variable — return SIZE_MAX to indicate "flexible" */
    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, SIZE_MAX))
        return 0;
    return 1;
}

static int hkdf_get_params(OSSL_PARAM params[])
{
    (void)params;
    return 1;
}
static const OSSL_PARAM *hkdf_gettable_params(void *vpctx)
{ (void)vpctx; static const OSSL_PARAM none[]={OSSL_PARAM_END}; return none; }

const OSSL_DISPATCH sample_hkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX,              FN(hkdf_newctx)              },
    { OSSL_FUNC_KDF_DUPCTX,              FN(hkdf_dupctx)              },
    { OSSL_FUNC_KDF_FREECTX,             FN(hkdf_freectx)             },
    { OSSL_FUNC_KDF_RESET,               FN(hkdf_reset)               },
    { OSSL_FUNC_KDF_DERIVE,              FN(hkdf_derive)              },
    { OSSL_FUNC_KDF_GET_PARAMS,          FN(hkdf_get_params)          },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      FN(hkdf_get_ctx_params)      },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      FN(hkdf_set_ctx_params)      },
    { OSSL_FUNC_KDF_GETTABLE_PARAMS,     FN(hkdf_gettable_params)     },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, FN(hkdf_gettable_ctx_params) },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, FN(hkdf_settable_ctx_params) },
    PROV_DISPATCH_END
};

/* ═══════════════════════════════════════════════════════════════════════════
 * §2  PBKDF2 (RFC 2898 / PKCS #5 v2)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct pbkdf2_ctx_st {
    void          *provctx;
    EVP_KDF_CTX   *kctx;
    EVP_KDF       *kdf;

    char           digest[64];
    unsigned char  pass[256];
    size_t         passlen;
    unsigned char  salt[256];
    size_t         saltlen;
    uint32_t       iter;
} PBKDF2_CTX;

static void *pbkdf2_newctx(void *vprovctx)
{
    PBKDF2_CTX     *ctx    = OPENSSL_zalloc(sizeof(*ctx));
    OSSL_LIB_CTX   *libctx = prov_libctx(vprovctx);

    if (!ctx) return NULL;
    ctx->provctx = vprovctx;
    memcpy(ctx->digest, "SHA2-256", 9);
    ctx->iter    = 10000;

    ctx->kdf  = EVP_KDF_fetch(libctx, "PBKDF2", "provider!=sample");
    if (!ctx->kdf) { OPENSSL_free(ctx); return NULL; }

    ctx->kctx = EVP_KDF_CTX_new(ctx->kdf);
    if (!ctx->kctx) { EVP_KDF_free(ctx->kdf); OPENSSL_free(ctx); return NULL; }

    return ctx;
}

static void pbkdf2_freectx(void *vctx)
{
    PBKDF2_CTX *ctx = vctx;
    if (!ctx) return;
    EVP_KDF_CTX_free(ctx->kctx);
    EVP_KDF_free(ctx->kdf);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *pbkdf2_dupctx(void *vctx)
{
    PBKDF2_CTX *src = vctx;
    PBKDF2_CTX *dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst) return NULL;
    *dst = *src;
    dst->kdf  = NULL;
    dst->kctx = src->kctx ? EVP_KDF_CTX_dup(src->kctx) : NULL;
    return dst;
}

static int pbkdf2_reset(void *vctx)
{
    PBKDF2_CTX *ctx = vctx;
    EVP_KDF_CTX_free(ctx->kctx);
    ctx->kctx = EVP_KDF_CTX_new(ctx->kdf);
    return ctx->kctx != NULL;
}

static int pbkdf2_derive(void *vctx, unsigned char *key, size_t keylen,
                          const OSSL_PARAM params[])
{
    PBKDF2_CTX *ctx = vctx;
    OSSL_PARAM p[8];
    int n = 0;
    uint32_t iter = ctx->iter;
    (void)params;

    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                               ctx->digest, 0);
    p[n++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);
    if (ctx->passlen)
        p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                    ctx->pass, ctx->passlen);
    if (ctx->saltlen)
        p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                    ctx->salt, ctx->saltlen);
    p[n]   = OSSL_PARAM_construct_end();

    if (!EVP_KDF_CTX_set_params(ctx->kctx, p)) return 0;
    return EVP_KDF_derive(ctx->kctx, key, keylen, NULL);
}

static const OSSL_PARAM pbkdf2_settable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string (OSSL_KDF_PARAM_DIGEST,   NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT,     NULL, 0),
    OSSL_PARAM_uint        (OSSL_KDF_PARAM_ITER,     NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *pbkdf2_settable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return pbkdf2_settable_ctx_params_tbl; }

static int pbkdf2_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PBKDF2_CTX       *ctx = vctx;
    const OSSL_PARAM *p;
    size_t            len;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST)) != NULL) {
        strncpy(ctx->digest, (char *)p->data,
                p->data_size < sizeof(ctx->digest)
                    ? p->data_size : sizeof(ctx->digest) - 1);
        ctx->digest[sizeof(ctx->digest) - 1] = '\0';
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD)) != NULL) {
        len = p->data_size < sizeof(ctx->pass) ? p->data_size : sizeof(ctx->pass);
        memcpy(ctx->pass, p->data, len);
        ctx->passlen = len;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL) {
        len = p->data_size < sizeof(ctx->salt) ? p->data_size : sizeof(ctx->salt);
        memcpy(ctx->salt, p->data, len);
        ctx->saltlen = len;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER)) != NULL)
        OSSL_PARAM_get_uint(p, &ctx->iter);

    return 1;
}

static int pbkdf2_get_params(OSSL_PARAM params[])
{ (void)params; return 1; }
static const OSSL_PARAM *pbkdf2_gettable_params(void *vpctx)
{ (void)vpctx; static const OSSL_PARAM none[]={OSSL_PARAM_END}; return none; }
static int pbkdf2_get_ctx_params(void *vctx, OSSL_PARAM params[])
{ (void)vctx; (void)params; return 1; }
static const OSSL_PARAM *pbkdf2_gettable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; static const OSSL_PARAM none[]={OSSL_PARAM_END}; return none; }

const OSSL_DISPATCH sample_pbkdf2_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX,              FN(pbkdf2_newctx)              },
    { OSSL_FUNC_KDF_DUPCTX,              FN(pbkdf2_dupctx)              },
    { OSSL_FUNC_KDF_FREECTX,             FN(pbkdf2_freectx)             },
    { OSSL_FUNC_KDF_RESET,               FN(pbkdf2_reset)               },
    { OSSL_FUNC_KDF_DERIVE,              FN(pbkdf2_derive)              },
    { OSSL_FUNC_KDF_GET_PARAMS,          FN(pbkdf2_get_params)          },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      FN(pbkdf2_get_ctx_params)      },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      FN(pbkdf2_set_ctx_params)      },
    { OSSL_FUNC_KDF_GETTABLE_PARAMS,     FN(pbkdf2_gettable_params)     },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, FN(pbkdf2_gettable_ctx_params) },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, FN(pbkdf2_settable_ctx_params) },
    PROV_DISPATCH_END
};
