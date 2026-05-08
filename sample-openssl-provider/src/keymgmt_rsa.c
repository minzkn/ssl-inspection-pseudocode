/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — RSA Key Management.
 *
 * Pattern demonstrated:
 *   • Key data as an opaque struct wrapping EVP_PKEY.
 *   • new / free / dup — key object lifecycle.
 *   • gen_init / gen_set_params / gen / gen_cleanup — key generation.
 *   • has() — test which key components are present (public/private/params).
 *   • match() — compare two keys for equality.
 *   • import() / export() — serialise/deserialise key material from OSSL_PARAM.
 *   • get_params / set_params — read/write key attributes.
 *   • validate() — check key consistency.
 *
 * All heavy lifting is delegated to a child OSSL_LIB_CTX so RSA arithmetic
 * does not re-enter this provider.  A hardware provider would replace the
 * EVP_PKEY_generate() call with an HSM key-gen command and store a key handle
 * instead of raw RSA key material.
 */

#include "provider.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── Key object ──────────────────────────────────────────────────────────── */

typedef struct rsa_key_st {
    EVP_PKEY *pkey;       /* wraps RSA structure     */
    int       selection;  /* OSSL_KEYMGMT_SELECT_*   */
    void     *provctx;
} RSA_KEY;

/* ── Key lifecycle ────────────────────────────────────────────────────────── */

static void *rsa_new(void *vprovctx)
{
    RSA_KEY *k = OPENSSL_zalloc(sizeof(*k));
    if (k) k->provctx = vprovctx;
    return k;
}

static void rsa_free(void *vkey)
{
    RSA_KEY *k = vkey;
    if (!k) return;
    EVP_PKEY_free(k->pkey);
    OPENSSL_free(k);
}

static void *rsa_dup(const void *vkey, int selection)
{
    const RSA_KEY *src = vkey;
    RSA_KEY       *dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst) return NULL;

    if (src->pkey) {
        dst->pkey = EVP_PKEY_dup(src->pkey);
        if (!dst->pkey) { OPENSSL_free(dst); return NULL; }
    }
    dst->selection = selection;
    return dst;
}

/* ── Key generation ───────────────────────────────────────────────────────── */

typedef struct rsa_genctx_st {
    void          *provctx;
    unsigned int   bits;
    unsigned long  pub_exponent;
} RSA_GENCTX;

static void *rsa_gen_init(void *vprovctx, int selection,
                           const OSSL_PARAM params[])
{
    RSA_GENCTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    (void)selection; (void)params;
    if (!gctx) return NULL;
    gctx->provctx      = vprovctx;
    gctx->bits         = 2048;
    gctx->pub_exponent = RSA_F4;   /* 65537 */
    return gctx;
}

static int rsa_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    RSA_GENCTX       *gctx = vgctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL)
        OSSL_PARAM_get_uint(p, &gctx->bits);

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL) {
        BIGNUM *e = NULL;
        if (OSSL_PARAM_get_BN(p, &e)) {
            gctx->pub_exponent = (unsigned long)BN_get_word(e);
            BN_free(e);
        }
    }
    return 1;
}

static const OSSL_PARAM rsa_gen_settable_params_tbl[] = {
    OSSL_PARAM_uint(OSSL_PKEY_PARAM_RSA_BITS, NULL),
    OSSL_PARAM_BN  (OSSL_PKEY_PARAM_RSA_E,   NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *rsa_gen_settable_params(void *vgctx, void *vpctx)
{ (void)vgctx; (void)vpctx; return rsa_gen_settable_params_tbl; }

static void *rsa_gen(void *vgctx, OSSL_CALLBACK *cb, void *cbarg)
{
    RSA_GENCTX   *gctx   = vgctx;
    OSSL_LIB_CTX *libctx = prov_libctx(gctx->provctx);
    EVP_PKEY_CTX *pctx   = NULL;
    EVP_PKEY     *pkey   = NULL;
    RSA_KEY      *k      = NULL;

    (void)cb; (void)cbarg;

    pctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", "provider!=sample");
    if (!pctx) return NULL;

    if (EVP_PKEY_keygen_init(pctx) <= 0) goto err;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, (int)gctx->bits) <= 0)
        goto err;

    {
        unsigned long pubexp = gctx->pub_exponent;
        OSSL_PARAM ep[2] = {
            OSSL_PARAM_construct_ulong(OSSL_PKEY_PARAM_RSA_E, &pubexp),
            OSSL_PARAM_construct_end()
        };
        if (EVP_PKEY_CTX_set_params(pctx, ep) <= 0) goto err;
    }

    if (EVP_PKEY_generate(pctx, &pkey) <= 0) goto err;

    k = OPENSSL_zalloc(sizeof(*k));
    if (!k) { EVP_PKEY_free(pkey); goto err; }
    k->pkey      = pkey;
    k->selection = OSSL_KEYMGMT_SELECT_ALL;

err:
    EVP_PKEY_CTX_free(pctx);
    return k;
}

static void rsa_gen_cleanup(void *vgctx)
{
    OPENSSL_free(vgctx);
}

/* ── has / match ──────────────────────────────────────────────────────────── */

static int rsa_has(const void *vkey, int selection)
{
    const RSA_KEY *k = vkey;
    if (!k || !k->pkey) return 0;

    /* OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: RSA has none, always present */

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        OSSL_PARAM *out = NULL;
        int ok = EVP_PKEY_todata(k->pkey, EVP_PKEY_PUBLIC_KEY, &out) > 0;
        OSSL_PARAM_free(out);
        if (!ok) return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        OSSL_PARAM *out = NULL;
        int ok = EVP_PKEY_todata(k->pkey, EVP_PKEY_KEYPAIR, &out) > 0;
        OSSL_PARAM_free(out);
        if (!ok) return 0;
    }
    return 1;
}

static int rsa_match(const void *vkey1, const void *vkey2, int selection)
{
    const RSA_KEY *k1 = vkey1, *k2 = vkey2;
    if (!k1->pkey || !k2->pkey) return 0;
    (void)selection;
    return EVP_PKEY_eq(k1->pkey, k2->pkey) == 1;
}

/* ── validate ─────────────────────────────────────────────────────────────── */

static int rsa_validate(const void *vkey, int selection, int checktype)
{
    const RSA_KEY *k = vkey;
    if (!k || !k->pkey) return 0;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(
        prov_libctx(k->provctx), k->pkey, "provider!=sample");
    if (!pctx) return 0;

    int rc = 0;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        rc = EVP_PKEY_check(pctx) > 0;
    else
        rc = EVP_PKEY_public_check(pctx) > 0;

    EVP_PKEY_CTX_free(pctx);
    (void)checktype;
    return rc;
}

/* ── import / export ──────────────────────────────────────────────────────── */

static int rsa_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    RSA_KEY      *k      = vkey;
    OSSL_LIB_CTX *libctx = prov_libctx(k->provctx);

    EVP_PKEY_free(k->pkey);
    k->pkey = NULL;

    /* Build key from OSSL_PARAM array using EVP_PKEY_fromdata */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", "provider!=sample");
    if (!pctx) return 0;

    EVP_PKEY *pkey = NULL;
    int rc = EVP_PKEY_fromdata_init(pctx) > 0
          && EVP_PKEY_fromdata(pctx, &pkey,
                               (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
                                   ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                               (OSSL_PARAM *)params) > 0;
    EVP_PKEY_CTX_free(pctx);
    if (rc) { k->pkey = pkey; k->selection = selection; }
    return rc;
}

static int rsa_export(void *vkey, int selection,
                       OSSL_CALLBACK *param_cb, void *cbarg)
{
    RSA_KEY      *k = vkey;
    OSSL_PARAM   *params = NULL;
    int           rc     = 0;

    if (!k->pkey) return 0;

    if (EVP_PKEY_todata(k->pkey,
                        (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
                            ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                        &params) > 0) {
        rc = param_cb(params, cbarg);
        OSSL_PARAM_free(params);
    }
    return rc;
}

static const OSSL_PARAM *rsa_import_types(int selection)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
        OSSL_PARAM_END
    };
    (void)selection;
    return types;
}

static const OSSL_PARAM *rsa_export_types(int selection)
{
    return rsa_import_types(selection);
}

/* ── get_params / set_params ─────────────────────────────────────────────── */

static int rsa_get_params(void *vkey, OSSL_PARAM params[])
{
    RSA_KEY    *k = vkey;
    OSSL_PARAM *p;
    if (!k->pkey) return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL) {
        int bits = EVP_PKEY_get_bits(k->pkey);
        if (!OSSL_PARAM_set_int(p, bits)) return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL) {
        int sb = EVP_PKEY_get_security_bits(k->pkey);
        if (!OSSL_PARAM_set_int(p, sb)) return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL) {
        int ms = EVP_PKEY_get_size(k->pkey);
        if (!OSSL_PARAM_set_int(p, ms)) return 0;
    }
    return 1;
}

static const OSSL_PARAM rsa_gettable_params_tbl[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS,          NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE,      NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *rsa_gettable_params(void *vpctx)
{ (void)vpctx; return rsa_gettable_params_tbl; }

static int rsa_set_params(void *vkey, const OSSL_PARAM params[])
{ (void)vkey; (void)params; return 1; }
static const OSSL_PARAM *rsa_settable_params(void *vpctx)
{ (void)vpctx; static const OSSL_PARAM n[]={OSSL_PARAM_END}; return n; }

/* ── query_operation_name ─────────────────────────────────────────────────── */
/*
 * Tells the core which operation type this KEYMGMT is for.
 * Returning "RSA" here means both SIGNATURE and ASYM_CIPHER can use it.
 */
static const char *rsa_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:   return "RSA";
    case OSSL_OP_ASYM_CIPHER: return "RSA";
    default:                  return NULL;
    }
}

/* ── Dispatch table ──────────────────────────────────────────────────────── */

const OSSL_DISPATCH sample_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                  FN(rsa_new)                    },
    { OSSL_FUNC_KEYMGMT_FREE,                 FN(rsa_free)                   },
    { OSSL_FUNC_KEYMGMT_DUP,                  FN(rsa_dup)                    },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,             FN(rsa_gen_init)               },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,       FN(rsa_gen_set_params)         },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,  FN(rsa_gen_settable_params)    },
    { OSSL_FUNC_KEYMGMT_GEN,                  FN(rsa_gen)                    },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,          FN(rsa_gen_cleanup)            },
    { OSSL_FUNC_KEYMGMT_HAS,                  FN(rsa_has)                    },
    { OSSL_FUNC_KEYMGMT_MATCH,                FN(rsa_match)                  },
    { OSSL_FUNC_KEYMGMT_VALIDATE,             FN(rsa_validate)               },
    { OSSL_FUNC_KEYMGMT_IMPORT,               FN(rsa_import)                 },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,         FN(rsa_import_types)           },
    { OSSL_FUNC_KEYMGMT_EXPORT,               FN(rsa_export)                 },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,         FN(rsa_export_types)           },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,           FN(rsa_get_params)             },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,      FN(rsa_gettable_params)        },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,           FN(rsa_set_params)             },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,      FN(rsa_settable_params)        },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, FN(rsa_query_operation_name)   },
    PROV_DISPATCH_END
};
