/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — Signature (RSA-PSS and ECDSA).
 *
 * Pattern demonstrated:
 *   • Two sign/verify paths:
 *       (a) sign_init + sign / verify_init + verify  — caller supplies pre-hash.
 *       (b) digest_sign_init + digest_sign_update + digest_sign_final
 *           / digest_verify_* — provider does the hashing internally.
 *   • set_ctx_params: digest name, salt length (PSS), padding mode.
 *   • get_ctx_params: signature size.
 *   • One generic context struct drives both RSA and ECDSA via a variant flag.
 *
 * The EVP_DigestSign* delegation goes through a child OSSL_LIB_CTX.
 */

#include "provider.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── Variant ─────────────────────────────────────────────────────────────── */

typedef enum { SIG_RSA = 0, SIG_ECDSA = 1 } SIG_TYPE;

/* ── Context ─────────────────────────────────────────────────────────────── */

typedef struct sig_ctx_st {
    void           *provctx;
    SIG_TYPE        type;
    EVP_MD_CTX     *mdctx;       /* for digest_sign / digest_verify */
    EVP_PKEY       *pkey;        /* not owned — borrowed from key object */
    int             operation;   /* EVP_PKEY_OP_SIGN or _VERIFY */

    /* Params */
    char            digest[64];  /* e.g. "SHA2-256" */
    int             pad_mode;    /* RSA_PKCS1_PSS_PADDING or _PKCS1_PADDING */
    int             saltlen;     /* RSA-PSS salt length, -2 = digest size */
} SIG_CTX;

/* ── Key accessor ────────────────────────────────────────────────────────── */
/*
 * The key management types (RSA_KEY, EC_KEY_WRAP) are defined in their own
 * translation units.  Here we access pkey through the same layout assumption:
 * the first field is always EVP_PKEY*.
 */
typedef struct { EVP_PKEY *pkey; } KEY_COMMON;

static EVP_PKEY *key_get_pkey(void *vkey)
{
    return vkey ? ((KEY_COMMON *)vkey)->pkey : NULL;
}

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

static void *sig_newctx(void *vprovctx, SIG_TYPE type, const char *propq)
{
    SIG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    (void)propq;
    if (!ctx) return NULL;
    ctx->provctx  = vprovctx;
    ctx->type     = type;
    ctx->pad_mode = (type == SIG_RSA) ? RSA_PKCS1_PSS_PADDING : 0;
    ctx->saltlen  = RSA_PSS_SALTLEN_DIGEST;
    memcpy(ctx->digest, "SHA2-256", 9);
    return ctx;
}

static void sig_freectx(void *vctx)
{
    SIG_CTX *ctx = vctx;
    if (!ctx) return;
    EVP_MD_CTX_free(ctx->mdctx);
    OPENSSL_free(ctx);
}

static void *sig_dupctx(void *vctx)
{
    SIG_CTX *src = vctx;
    SIG_CTX *dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst) return NULL;
    *dst = *src;
    dst->mdctx = NULL;
    if (src->mdctx) {
        dst->mdctx = EVP_MD_CTX_new();
        if (!dst->mdctx || !EVP_MD_CTX_copy_ex(dst->mdctx, src->mdctx)) {
            EVP_MD_CTX_free(dst->mdctx);
            OPENSSL_free(dst);
            return NULL;
        }
    }
    return dst;
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int sig_setup_pkey_ctx(SIG_CTX *ctx, EVP_PKEY_CTX *pkctx)
{
    if (ctx->type == SIG_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkctx, ctx->pad_mode) <= 0)
            return 0;
        if (ctx->pad_mode == RSA_PKCS1_PSS_PADDING) {
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, ctx->saltlen) <= 0)
                return 0;
        }
    }
    return 1;
}

/* ── sign_init / verify_init (pre-hashed data) ────────────────────────────── */

static int sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    SIG_CTX *ctx = vctx;
    ctx->pkey = key_get_pkey(vkey);
    ctx->operation = EVP_PKEY_OP_SIGN;
    (void)params;
    return ctx->pkey != NULL;
}

static int sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    SIG_CTX *ctx = vctx;
    ctx->pkey = key_get_pkey(vkey);
    ctx->operation = EVP_PKEY_OP_VERIFY;
    (void)params;
    return ctx->pkey != NULL;
}

/* sign() takes a pre-hashed tbs (to-be-signed) buffer */
static int sig_sign(void *vctx,
                     unsigned char *sig, size_t *siglen, size_t sigsize,
                     const unsigned char *tbs, size_t tbslen)
{
    SIG_CTX      *ctx    = vctx;
    OSSL_LIB_CTX *libctx = prov_libctx(ctx->provctx);
    EVP_PKEY_CTX *pkctx  = EVP_PKEY_CTX_new_from_pkey(libctx, ctx->pkey,
                                                        "provider!=sample");
    if (!pkctx) return 0;

    int rc = 0;
    if (EVP_PKEY_sign_init(pkctx) <= 0) goto out;
    if (!sig_setup_pkey_ctx(ctx, pkctx)) goto out;

    /* Fetch EVP_MD and set it on pkey_ctx */
    EVP_MD *md = EVP_MD_fetch(libctx, ctx->digest, "provider!=sample");
    if (md) {
        EVP_PKEY_CTX_set_signature_md(pkctx, md);
        EVP_MD_free(md);
    }

    if (sig) *siglen = sigsize;
    rc = EVP_PKEY_sign(pkctx, sig, siglen, tbs, tbslen) > 0;

out:
    EVP_PKEY_CTX_free(pkctx);
    return rc;
}

static int sig_verify(void *vctx,
                       const unsigned char *sig,  size_t siglen,
                       const unsigned char *tbs, size_t tbslen)
{
    SIG_CTX      *ctx    = vctx;
    OSSL_LIB_CTX *libctx = prov_libctx(ctx->provctx);
    EVP_PKEY_CTX *pkctx  = EVP_PKEY_CTX_new_from_pkey(libctx, ctx->pkey,
                                                        "provider!=sample");
    if (!pkctx) return 0;

    int rc = 0;
    if (EVP_PKEY_verify_init(pkctx) <= 0) goto out;
    if (!sig_setup_pkey_ctx(ctx, pkctx)) goto out;

    EVP_MD *md = EVP_MD_fetch(libctx, ctx->digest, "provider!=sample");
    if (md) {
        EVP_PKEY_CTX_set_signature_md(pkctx, md);
        EVP_MD_free(md);
    }

    rc = EVP_PKEY_verify(pkctx, sig, siglen, tbs, tbslen) > 0;
out:
    EVP_PKEY_CTX_free(pkctx);
    return rc;
}

/* ── digest_sign_* (provider handles hashing) ───────────────────────────── */

static int sig_digest_sign_init(void *vctx, const char *mdname,
                                  void *vkey, const OSSL_PARAM params[])
{
    SIG_CTX      *ctx    = vctx;
    OSSL_LIB_CTX *libctx = prov_libctx(ctx->provctx);

    ctx->pkey      = key_get_pkey(vkey);
    ctx->operation = EVP_PKEY_OP_SIGN;
    if (mdname && *mdname)
        strncpy(ctx->digest, mdname, sizeof(ctx->digest) - 1);

    (void)params;

    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = EVP_MD_CTX_new();
    if (!ctx->mdctx) return 0;

    EVP_PKEY_CTX *pkctx = NULL;
    int rc = EVP_DigestSignInit_ex(ctx->mdctx, &pkctx, ctx->digest,
                                    libctx, "provider!=sample",
                                    ctx->pkey, NULL) > 0;
    if (rc) sig_setup_pkey_ctx(ctx, pkctx);
    return rc;
}

static int sig_digest_sign_update(void *vctx,
                                    const unsigned char *data, size_t datalen)
{
    SIG_CTX *ctx = vctx;
    return EVP_DigestSignUpdate(ctx->mdctx, data, datalen) > 0;
}

static int sig_digest_sign_final(void *vctx,
                                   unsigned char *sig, size_t *siglen,
                                   size_t sigsize)
{
    SIG_CTX *ctx = vctx;
    /* First call with sig=NULL to query length */
    if (!sig) {
        return EVP_DigestSignFinal(ctx->mdctx, NULL, siglen) > 0;
    }
    (void)sigsize;
    return EVP_DigestSignFinal(ctx->mdctx, sig, siglen) > 0;
}

static int sig_digest_verify_init(void *vctx, const char *mdname,
                                    void *vkey, const OSSL_PARAM params[])
{
    SIG_CTX      *ctx    = vctx;
    OSSL_LIB_CTX *libctx = prov_libctx(ctx->provctx);

    ctx->pkey      = key_get_pkey(vkey);
    ctx->operation = EVP_PKEY_OP_VERIFY;
    if (mdname && *mdname)
        strncpy(ctx->digest, mdname, sizeof(ctx->digest) - 1);

    (void)params;

    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = EVP_MD_CTX_new();
    if (!ctx->mdctx) return 0;

    EVP_PKEY_CTX *pkctx = NULL;
    int rc = EVP_DigestVerifyInit_ex(ctx->mdctx, &pkctx, ctx->digest,
                                      libctx, "provider!=sample",
                                      ctx->pkey, NULL) > 0;
    if (rc) sig_setup_pkey_ctx(ctx, pkctx);
    return rc;
}

static int sig_digest_verify_update(void *vctx,
                                      const unsigned char *data, size_t datalen)
{
    SIG_CTX *ctx = vctx;
    return EVP_DigestVerifyUpdate(ctx->mdctx, data, datalen) > 0;
}

static int sig_digest_verify_final(void *vctx,
                                     const unsigned char *sig, size_t siglen)
{
    SIG_CTX *ctx = vctx;
    return EVP_DigestVerifyFinal(ctx->mdctx, sig, siglen) > 0;
}

/* ── Parameters ──────────────────────────────────────────────────────────── */

static int sig_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    SIG_CTX    *ctx = vctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, ctx->digest)) return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE)) != NULL
        && ctx->type == SIG_RSA
        && !OSSL_PARAM_set_int(p, ctx->pad_mode)) return 0;

    return 1;
}

static int sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    SIG_CTX          *ctx = vctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL) {
        size_t dlen = p->data_size < sizeof(ctx->digest) - 1
                      ? p->data_size : sizeof(ctx->digest) - 1;
        memcpy(ctx->digest, p->data, dlen);
        ctx->digest[dlen] = '\0';
    }

    if (ctx->type == SIG_RSA) {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE)) != NULL)
            OSSL_PARAM_get_int(p, &ctx->pad_mode);
        if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN)) != NULL)
            OSSL_PARAM_get_int(p, &ctx->saltlen);
    }
    return 1;
}

static const OSSL_PARAM rsa_sig_settable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,      NULL, 0),
    OSSL_PARAM_int        (OSSL_SIGNATURE_PARAM_PAD_MODE,    NULL),
    OSSL_PARAM_int        (OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM ecdsa_sig_settable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM sig_gettable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,   NULL, 0),
    OSSL_PARAM_int        (OSSL_SIGNATURE_PARAM_PAD_MODE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *rsa_sig_settable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return rsa_sig_settable_ctx_params_tbl; }
static const OSSL_PARAM *ecdsa_sig_settable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return ecdsa_sig_settable_ctx_params_tbl; }
static const OSSL_PARAM *sig_gettable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return sig_gettable_ctx_params_tbl; }

/* ── RSA-specific newctx ─────────────────────────────────────────────────── */

static void *rsa_sig_newctx(void *vpctx, const char *propq)
{ return sig_newctx(vpctx, SIG_RSA, propq); }

const OSSL_DISPATCH sample_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,               FN(rsa_sig_newctx)               },
    { OSSL_FUNC_SIGNATURE_FREECTX,              FN(sig_freectx)                  },
    { OSSL_FUNC_SIGNATURE_DUPCTX,               FN(sig_dupctx)                   },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,            FN(sig_sign_init)                },
    { OSSL_FUNC_SIGNATURE_SIGN,                 FN(sig_sign)                     },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,          FN(sig_verify_init)              },
    { OSSL_FUNC_SIGNATURE_VERIFY,               FN(sig_verify)                   },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,     FN(sig_digest_sign_init)         },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,   FN(sig_digest_sign_update)       },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,    FN(sig_digest_sign_final)        },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,   FN(sig_digest_verify_init)       },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, FN(sig_digest_verify_update)     },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,  FN(sig_digest_verify_final)      },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,       FN(sig_get_ctx_params)           },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,       FN(sig_set_ctx_params)           },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,  FN(sig_gettable_ctx_params)      },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,  FN(rsa_sig_settable_ctx_params)  },
    PROV_DISPATCH_END
};

/* ── ECDSA-specific newctx ───────────────────────────────────────────────── */

static void *ecdsa_sig_newctx(void *vpctx, const char *propq)
{ return sig_newctx(vpctx, SIG_ECDSA, propq); }

const OSSL_DISPATCH sample_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,               FN(ecdsa_sig_newctx)               },
    { OSSL_FUNC_SIGNATURE_FREECTX,              FN(sig_freectx)                    },
    { OSSL_FUNC_SIGNATURE_DUPCTX,               FN(sig_dupctx)                     },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,            FN(sig_sign_init)                  },
    { OSSL_FUNC_SIGNATURE_SIGN,                 FN(sig_sign)                       },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,          FN(sig_verify_init)                },
    { OSSL_FUNC_SIGNATURE_VERIFY,               FN(sig_verify)                     },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,     FN(sig_digest_sign_init)           },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,   FN(sig_digest_sign_update)         },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,    FN(sig_digest_sign_final)          },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,   FN(sig_digest_verify_init)         },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, FN(sig_digest_verify_update)       },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,  FN(sig_digest_verify_final)        },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,       FN(sig_get_ctx_params)             },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,       FN(sig_set_ctx_params)             },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,  FN(sig_gettable_ctx_params)        },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,  FN(ecdsa_sig_settable_ctx_params)  },
    PROV_DISPATCH_END
};
