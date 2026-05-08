/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — provider entry point.
 *
 * This file is the only mandatory entry point for an OpenSSL provider.
 * It is called by libcrypto when the provider .so is loaded (via
 * OSSL_PROVIDER_load or openssl.cnf "providers" section).
 *
 * Key responsibilities:
 *   1. Collect the "in" dispatch table that core offers to the provider.
 *   2. Create a child OSSL_LIB_CTX so algorithm helpers can use EVP_*
 *      safely (without re-entering this provider).
 *   3. Return provider meta-information and the "out" dispatch table.
 *   4. Register all algorithms via query_operation().
 */

#include "provider.h"

#include <openssl/evp.h>
#include <openssl/provider.h>

/* ── Provider metadata ───────────────────────────────────────────────────── */

#define SAMPLE_PROV_NAME    "sample"
#define SAMPLE_PROV_VERSION "1.0.0"
#define SAMPLE_PROV_BUILDINFO "sample-openssl-provider reference implementation"

/* ── Algorithm tables ────────────────────────────────────────────────────── */
/*
 * Each OSSL_ALGORITHM row:  { "NAME[:ALIAS]", "provider=sample", dispatch[] }
 * The property string "provider=sample" lets callers request this provider
 * explicitly, e.g.  EVP_MD_fetch(NULL, "SHA2-256", "provider=sample").
 */

static const OSSL_ALGORITHM sample_digests[] = {
    { "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1",
      "provider=sample", sample_sha256_functions, "SHA-256 digest" },
    { "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3",
      "provider=sample", sample_sha512_functions, "SHA-512 digest" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sample_ciphers[] = {
    { "AES-128-CBC:2.16.840.1.101.3.4.1.2",
      "provider=sample", sample_aes128cbc_functions, "AES-128-CBC" },
    { "AES-256-CBC:2.16.840.1.101.3.4.1.42",
      "provider=sample", sample_aes256cbc_functions, "AES-256-CBC" },
    { "AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6",
      "provider=sample", sample_aes128gcm_functions, "AES-128-GCM" },
    { "AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46",
      "provider=sample", sample_aes256gcm_functions, "AES-256-GCM" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sample_macs[] = {
    { "HMAC-SHA256",
      "provider=sample", sample_hmac_sha256_functions,
      "HMAC with SHA-256 (fixed digest)" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sample_kdfs[] = {
    { "HKDF", "provider=sample", sample_hkdf_functions,
      "HKDF (RFC 5869)" },
    { "PBKDF2", "provider=sample", sample_pbkdf2_functions,
      "PBKDF2 (RFC 2898)" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sample_rands[] = {
    { "SAMPLE-RAND", "provider=sample", sample_rand_functions,
      "Sample PRNG (not for production use)" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sample_keymgmts[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1",
      "provider=sample", sample_rsa_keymgmt_functions, "RSA key management" },
    { "EC:id-ecPublicKey:1.2.840.10045.2.1",
      "provider=sample", sample_ec_keymgmt_functions, "EC key management" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sample_signatures[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1",
      "provider=sample", sample_rsa_signature_functions, "RSA signature" },
    { "ECDSA",
      "provider=sample", sample_ecdsa_signature_functions, "ECDSA signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sample_asym_ciphers[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1",
      "provider=sample", sample_rsa_asym_cipher_functions,
      "RSA asymmetric encryption" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sample_keyexchs[] = {
    { "ECDH",
      "provider=sample", sample_ecdh_keyexch_functions, "ECDH key exchange" },
    { NULL, NULL, NULL, NULL }
};

/* ── query_operation ─────────────────────────────────────────────────────── */
/*
 * Called by libcrypto to ask: "what algorithms does this provider implement
 * for operation_id X?"  Return NULL for unimplemented operations.
 *
 * *no_store = 1 tells the core to re-query every time (useful for dynamic
 * registration); set it to 0 to allow caching (better performance).
 */
static const OSSL_ALGORITHM *
sample_query_operation(void *vprovctx, int operation_id, int *no_store)
{
    (void)vprovctx;
    *no_store = 0;

    switch (operation_id) {
    case OSSL_OP_DIGEST:       return sample_digests;
    case OSSL_OP_CIPHER:       return sample_ciphers;
    case OSSL_OP_MAC:          return sample_macs;
    case OSSL_OP_KDF:          return sample_kdfs;
    case OSSL_OP_RAND:         return sample_rands;
    case OSSL_OP_KEYMGMT:      return sample_keymgmts;
    case OSSL_OP_SIGNATURE:    return sample_signatures;
    case OSSL_OP_ASYM_CIPHER:  return sample_asym_ciphers;
    case OSSL_OP_KEYEXCH:      return sample_keyexchs;
    default:                   return NULL;
    }
}

static void sample_unquery_operation(void *vprovctx, int operation_id,
                                     const OSSL_ALGORITHM *algs)
{
    (void)vprovctx;
    (void)operation_id;
    (void)algs;
}

/* ── Provider parameters ─────────────────────────────────────────────────── */

static const OSSL_PARAM sample_gettable_params_arr[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME,        OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION,     OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO,   OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS,      OSSL_PARAM_INTEGER,  NULL, 0),
    OSSL_PARAM_END
};

/* OSSL_FUNC_PROVIDER_GETTABLE_PARAMS expects a function, not an array.    */
static const OSSL_PARAM *sample_gettable_params(void *vprovctx)
{ (void)vprovctx; return sample_gettable_params_arr; }

static int sample_get_params(void *vprovctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)vprovctx;

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, SAMPLE_PROV_NAME))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, SAMPLE_PROV_VERSION))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, SAMPLE_PROV_BUILDINFO))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS)) != NULL
        && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

/* ── Teardown ────────────────────────────────────────────────────────────── */

static void sample_teardown(void *vprovctx)
{
    PROV_CTX *ctx = vprovctx;
    if (ctx == NULL)
        return;
    OSSL_LIB_CTX_free(ctx->libctx);
    OPENSSL_free(ctx);
}

/* ── Provider self-test ──────────────────────────────────────────────────── */
/*
 * Returning 1 means "self-test passed".  A real FIPS provider would run KATs
 * here.  We just return success.
 */
static int sample_self_test(void *vprovctx)
{
    (void)vprovctx;
    return 1;
}

/* ── Provider dispatch table (out) ──────────────────────────────────────── */

static const OSSL_DISPATCH sample_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,          FN(sample_teardown)           },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,   FN(sample_gettable_params)    },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,        FN(sample_get_params)         },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,   FN(sample_query_operation)    },
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, FN(sample_unquery_operation)  },
    { OSSL_FUNC_PROVIDER_SELF_TEST,         FN(sample_self_test)          },
    PROV_DISPATCH_END
};

/* ── Provider init ───────────────────────────────────────────────────────── */
/*
 * This symbol is the mandatory entry point.  Its name must match the .so
 * filename: for "sample.so" it must be OSSL_provider_init, OR the provider
 * can export a named init function registered via OSSL_PROVIDER_add_builtin().
 *
 * @handle  – opaque handle to pass back to core functions
 * @in      – dispatch table of core→provider functions offered by libcrypto
 * @out     – [out] dispatch table of provider functions we expose to core
 * @provctx – [out] provider context pointer (passed to every function)
 */
/* Mark as public so dlsym() can find it despite -fvisibility=hidden. */
__attribute__((visibility("default")))
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    PROV_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;

    /*
     * Create a child library context that is automatically populated with
     * all providers the parent (caller's) libctx has loaded.  This lets
     * our algorithm helpers call EVP_*_fetch() without triggering re-entry
     * into this provider.
     */
    ctx->libctx = OSSL_LIB_CTX_new_child(handle, in);
    if (ctx->libctx == NULL) {
        OPENSSL_free(ctx);
        return 0;
    }

    *provctx = ctx;
    *out     = sample_provider_functions;
    return 1;
}
