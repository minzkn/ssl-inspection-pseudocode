/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — EC Key Management.
 *
 * Pattern demonstrated:
 *   • EC key object with curve-name parameter.
 *   • gen_set_params: OSSL_PKEY_PARAM_GROUP_NAME to select curve.
 *   • import / export: both compressed and uncompressed point formats.
 *   • has(): PUBLIC_KEY vs PRIVATE_KEY selection.
 *   • query_operation_name: one KEYMGMT serving KEYEXCH (ECDH) and
 *     SIGNATURE (ECDSA).
 *
 * Delegation pattern is the same as keymgmt_rsa.c: child OSSL_LIB_CTX
 * drives all EVP_PKEY operations.
 */

#include "provider.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── Key object ──────────────────────────────────────────────────────────── */

typedef struct ec_key_st {
    EVP_PKEY *pkey;
    int       selection;
    void     *provctx;
} EC_KEY_WRAP;

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

static void *ec_new(void *vprovctx)
{
    EC_KEY_WRAP *k = OPENSSL_zalloc(sizeof(*k));
    if (k) k->provctx = vprovctx;
    return k;
}

static void ec_free(void *vkey)
{
    EC_KEY_WRAP *k = vkey;
    if (!k) return;
    EVP_PKEY_free(k->pkey);
    OPENSSL_free(k);
}

static void *ec_dup(const void *vkey, int selection)
{
    const EC_KEY_WRAP *src = vkey;
    EC_KEY_WRAP       *dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst) return NULL;
    if (src->pkey) {
        dst->pkey = EVP_PKEY_dup(src->pkey);
        if (!dst->pkey) { OPENSSL_free(dst); return NULL; }
    }
    dst->selection = selection;
    return dst;
}

/* ── Key generation ───────────────────────────────────────────────────────── */

typedef struct ec_genctx_st {
    void *provctx;
    char  group_name[64];  /* e.g. "P-256", "P-384", "prime256v1" */
} EC_GENCTX;

static void *ec_gen_init(void *vprovctx, int selection,
                          const OSSL_PARAM params[])
{
    EC_GENCTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    (void)selection; (void)params;
    if (!gctx) return NULL;
    gctx->provctx = vprovctx;
    memcpy(gctx->group_name, "P-256", 6);  /* default curve */
    return gctx;
}

static int ec_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    EC_GENCTX        *gctx = vgctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL) {
        strncpy(gctx->group_name, (char *)p->data,
                p->data_size < sizeof(gctx->group_name)
                    ? p->data_size : sizeof(gctx->group_name) - 1);
        gctx->group_name[sizeof(gctx->group_name) - 1] = '\0';
    }
    return 1;
}

static const OSSL_PARAM ec_gen_settable_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *ec_gen_settable_params(void *vgctx, void *vpctx)
{ (void)vgctx; (void)vpctx; return ec_gen_settable_params_tbl; }

static void *ec_gen(void *vgctx, OSSL_CALLBACK *cb, void *cbarg)
{
    EC_GENCTX    *gctx   = vgctx;
    OSSL_LIB_CTX *libctx = prov_libctx(gctx->provctx);
    EVP_PKEY_CTX *pctx   = NULL;
    EVP_PKEY     *pkey   = NULL;
    EC_KEY_WRAP  *k      = NULL;

    (void)cb; (void)cbarg;

    pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider!=sample");
    if (!pctx) return NULL;

    if (EVP_PKEY_keygen_init(pctx) <= 0) goto err;

    {
        OSSL_PARAM p[2] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                             gctx->group_name, 0),
            OSSL_PARAM_construct_end()
        };
        if (!EVP_PKEY_CTX_set_params(pctx, p)) goto err;
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

static void ec_gen_cleanup(void *vgctx) { OPENSSL_free(vgctx); }

/* ── has / match / validate ───────────────────────────────────────────────── */

static int ec_has(const void *vkey, int selection)
{
    const EC_KEY_WRAP *k = vkey;
    if (!k || !k->pkey) return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        /* EVP_PKEY_todata(KEYPAIR) fails when private key component is absent */
        OSSL_PARAM *out = NULL;
        int rc = EVP_PKEY_todata(k->pkey, EVP_PKEY_KEYPAIR, &out) > 0;
        OSSL_PARAM_free(out);
        if (!rc) return 0;
    }
    return 1;
}

static int ec_match(const void *vkey1, const void *vkey2, int selection)
{
    const EC_KEY_WRAP *k1 = vkey1, *k2 = vkey2;
    if (!k1->pkey || !k2->pkey) return 0;
    (void)selection;
    return EVP_PKEY_eq(k1->pkey, k2->pkey) == 1;
}

static int ec_validate(const void *vkey, int selection, int checktype)
{
    const EC_KEY_WRAP *k = vkey;
    if (!k || !k->pkey) return 0;
    (void)checktype;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(
        prov_libctx(k->provctx), k->pkey, "provider!=sample");
    if (!pctx) return 0;

    int rc = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
             ? EVP_PKEY_check(pctx) > 0
             : EVP_PKEY_public_check(pctx) > 0;

    EVP_PKEY_CTX_free(pctx);
    return rc;
}

/* ── import / export ──────────────────────────────────────────────────────── */

static int ec_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    EC_KEY_WRAP *k = vkey;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(
        prov_libctx(k->provctx), "EC", "provider!=sample");
    if (!pctx) return 0;

    EVP_PKEY_free(k->pkey);
    k->pkey = NULL;

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

static int ec_export(void *vkey, int selection,
                      OSSL_CALLBACK *param_cb, void *cbarg)
{
    EC_KEY_WRAP *k = vkey;
    OSSL_PARAM  *params = NULL;
    int          rc     = 0;
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

static const OSSL_PARAM ec_import_export_types_tbl[] = {
    OSSL_PARAM_utf8_string (OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,    NULL, 0),
    OSSL_PARAM_BN          (OSSL_PKEY_PARAM_PRIV_KEY,   NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *ec_import_types(int sel)
{ (void)sel; return ec_import_export_types_tbl; }
static const OSSL_PARAM *ec_export_types(int sel)
{ return ec_import_types(sel); }

/* ── get_params / set_params ─────────────────────────────────────────────── */

static int ec_get_params(void *vkey, OSSL_PARAM params[])
{
    EC_KEY_WRAP *k = vkey;
    OSSL_PARAM  *p;
    if (!k->pkey) return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, EVP_PKEY_get_bits(k->pkey))) return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, EVP_PKEY_get_security_bits(k->pkey))) return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, EVP_PKEY_get_size(k->pkey))) return 0;

    /* Forward remaining params to EVP_PKEY (e.g. GROUP_NAME, PUB_KEY) */
    return EVP_PKEY_get_params(k->pkey, params);
}

static const OSSL_PARAM ec_gettable_params_tbl[] = {
    OSSL_PARAM_int        (OSSL_PKEY_PARAM_BITS,          NULL),
    OSSL_PARAM_int        (OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int        (OSSL_PKEY_PARAM_MAX_SIZE,      NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,    NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,      NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *ec_gettable_params(void *vpctx)
{ (void)vpctx; return ec_gettable_params_tbl; }

static int ec_set_params(void *vkey, const OSSL_PARAM params[])
{ (void)vkey; (void)params; return 1; }
static const OSSL_PARAM *ec_settable_params(void *vpctx)
{ (void)vpctx; static const OSSL_PARAM n[]={OSSL_PARAM_END}; return n; }

/* ── query_operation_name ─────────────────────────────────────────────────── */

static const char *ec_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:  return "ECDH";
    case OSSL_OP_SIGNATURE: return "ECDSA";
    default:               return NULL;
    }
}

/* ── Dispatch table ──────────────────────────────────────────────────────── */

const OSSL_DISPATCH sample_ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                  FN(ec_new)                    },
    { OSSL_FUNC_KEYMGMT_FREE,                 FN(ec_free)                   },
    { OSSL_FUNC_KEYMGMT_DUP,                  FN(ec_dup)                    },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,             FN(ec_gen_init)               },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,       FN(ec_gen_set_params)         },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,  FN(ec_gen_settable_params)    },
    { OSSL_FUNC_KEYMGMT_GEN,                  FN(ec_gen)                    },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,          FN(ec_gen_cleanup)            },
    { OSSL_FUNC_KEYMGMT_HAS,                  FN(ec_has)                    },
    { OSSL_FUNC_KEYMGMT_MATCH,                FN(ec_match)                  },
    { OSSL_FUNC_KEYMGMT_VALIDATE,             FN(ec_validate)               },
    { OSSL_FUNC_KEYMGMT_IMPORT,               FN(ec_import)                 },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,         FN(ec_import_types)           },
    { OSSL_FUNC_KEYMGMT_EXPORT,               FN(ec_export)                 },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,         FN(ec_export_types)           },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,           FN(ec_get_params)             },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,      FN(ec_gettable_params)        },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,           FN(ec_set_params)             },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,      FN(ec_settable_params)        },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, FN(ec_query_operation_name)   },
    PROV_DISPATCH_END
};
