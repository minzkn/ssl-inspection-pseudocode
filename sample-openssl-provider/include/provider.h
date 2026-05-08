/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — shared types and forward declarations.
 *
 * Every algorithm implementation file includes this header.
 * The provider context (PROV_CTX) holds a child OSSL_LIB_CTX so that
 * internal helpers can safely call EVP_* without re-entering this provider.
 */
#ifndef SAMPLE_PROVIDER_H
#define SAMPLE_PROVIDER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/* ── Provider context ────────────────────────────────────────────────────── */

typedef struct prov_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX           *libctx;   /* child lib-ctx backed by default prov */
} PROV_CTX;

static inline OSSL_LIB_CTX *prov_libctx(void *vpctx)
{
    return vpctx ? ((PROV_CTX *)vpctx)->libctx : NULL;
}

/* ── Macro helpers ────────────────────────────────────────────────────────── */

#define PROV_DISPATCH_END  { 0, NULL }

/* Cast a function pointer to the generic void(*)(void) type required by
 * OSSL_DISPATCH.  The C standard prohibits this conversion but all major
 * platforms (LP64, ILP32) make it safe; suppress the -pedantic warning.  */
#ifdef __GNUC__
# pragma GCC diagnostic ignored "-Wpedantic"
#endif
#define FN(f)  ((void (*)(void))(f))

/* ── Algorithm dispatch table declarations ──────────────────────────────── */

/* digest.c */
extern const OSSL_DISPATCH sample_sha256_functions[];
extern const OSSL_DISPATCH sample_sha512_functions[];

/* cipher.c */
extern const OSSL_DISPATCH sample_aes128cbc_functions[];
extern const OSSL_DISPATCH sample_aes256cbc_functions[];
extern const OSSL_DISPATCH sample_aes128gcm_functions[];
extern const OSSL_DISPATCH sample_aes256gcm_functions[];

/* mac.c */
extern const OSSL_DISPATCH sample_hmac_sha256_functions[];

/* kdf.c */
extern const OSSL_DISPATCH sample_hkdf_functions[];
extern const OSSL_DISPATCH sample_pbkdf2_functions[];

/* rand.c */
extern const OSSL_DISPATCH sample_rand_functions[];

/* keymgmt_rsa.c */
extern const OSSL_DISPATCH sample_rsa_keymgmt_functions[];

/* keymgmt_ec.c */
extern const OSSL_DISPATCH sample_ec_keymgmt_functions[];

/* signature.c */
extern const OSSL_DISPATCH sample_rsa_signature_functions[];
extern const OSSL_DISPATCH sample_ecdsa_signature_functions[];

/* asymcipher.c */
extern const OSSL_DISPATCH sample_rsa_asym_cipher_functions[];

/* keyexch.c */
extern const OSSL_DISPATCH sample_ecdh_keyexch_functions[];

#endif /* SAMPLE_PROVIDER_H */
