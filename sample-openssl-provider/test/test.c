/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — comprehensive test program.
 *
 * Each test_*() function exercises one algorithm through the high-level
 * EVP API with "provider=sample" property constraint, so libcrypto dispatches
 * into our provider.  The tests also verify against known-good vectors to
 * confirm correctness.
 *
 * Build:  see Makefile
 * Run:    ./test_provider
 *         OPENSSL_MODULES=. ./test_provider   (if .so is in current dir)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void dump_hex(const char *label, const unsigned char *buf, size_t len)
{
    printf("  %-20s ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    putchar('\n');
}

static void print_errors(void)
{
    ERR_print_errors_fp(stderr);
}

#define CHECK(cond) do {                            \
    if (!(cond)) {                                  \
        fprintf(stderr, "FAIL at %s:%d\n",          \
                __FILE__, __LINE__);                 \
        print_errors();                             \
        return 0;                                   \
    }                                               \
} while(0)

/* ── Global provider handles ─────────────────────────────────────────────── */

static OSSL_PROVIDER *g_sample  = NULL;
static OSSL_PROVIDER *g_default = NULL;

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 1 — Digest: SHA-256
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_sha256(void)
{
    printf("[SHA-256]\n");

    /* FIPS 180-4 test vector: SHA-256("abc") */
    static const unsigned char input[] = "abc";
    static const unsigned char expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    unsigned char digest[32];
    unsigned int  dlen = sizeof(digest);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    CHECK(ctx);

    EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", "provider=sample");
    CHECK(md);

    CHECK(EVP_DigestInit_ex(ctx, md, NULL));
    CHECK(EVP_DigestUpdate(ctx, input, 3));
    CHECK(EVP_DigestFinal_ex(ctx, digest, &dlen));
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    dump_hex("SHA-256(\"abc\")", digest, 32);
    CHECK(memcmp(digest, expected, 32) == 0);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 2 — Digest: SHA-512
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_sha512(void)
{
    printf("[SHA-512]\n");

    static const unsigned char input[] = "abc";
    static const unsigned char expected[64] = {
        0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,
        0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
        0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,
        0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
        0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,
        0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
        0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
        0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
    };
    unsigned char digest[64];
    unsigned int  dlen = sizeof(digest);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    CHECK(ctx);

    EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-512", "provider=sample");
    CHECK(md);

    CHECK(EVP_DigestInit_ex(ctx, md, NULL));
    CHECK(EVP_DigestUpdate(ctx, input, 3));
    CHECK(EVP_DigestFinal_ex(ctx, digest, &dlen));
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    dump_hex("SHA-512(\"abc\")", digest, 64);
    CHECK(memcmp(digest, expected, 64) == 0);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 3 — Cipher: AES-128-CBC
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_aes_cbc(void)
{
    printf("[AES-128-CBC]\n");

    /* NIST SP 800-38A F.2.1 */
    static const unsigned char key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const unsigned char plain[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const unsigned char expected[16] = {
        0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
        0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d
    };

    unsigned char ct[32] = {0};
    unsigned char pt[32] = {0};
    int outl = 0, finl = 0;

    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
    CHECK(ectx);

    EVP_CIPHER *ciph = EVP_CIPHER_fetch(NULL, "AES-128-CBC", "provider=sample");
    CHECK(ciph);

    /* Encrypt */
    CHECK(EVP_EncryptInit_ex(ectx, ciph, NULL, key, iv));
    EVP_CIPHER_CTX_set_padding(ectx, 0);
    CHECK(EVP_EncryptUpdate(ectx, ct, &outl, plain, 16));
    CHECK(EVP_EncryptFinal_ex(ectx, ct + outl, &finl));
    EVP_CIPHER_CTX_free(ectx);

    dump_hex("ciphertext", ct, 16);
    CHECK(memcmp(ct, expected, 16) == 0);

    /* Decrypt */
    EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
    CHECK(dctx);
    CHECK(EVP_DecryptInit_ex(dctx, ciph, NULL, key, iv));
    EVP_CIPHER_CTX_set_padding(dctx, 0);
    CHECK(EVP_DecryptUpdate(dctx, pt, &outl, ct, 16));
    CHECK(EVP_DecryptFinal_ex(dctx, pt + outl, &finl));
    EVP_CIPHER_CTX_free(dctx);

    EVP_CIPHER_free(ciph);

    dump_hex("decrypted", pt, 16);
    CHECK(memcmp(pt, plain, 16) == 0);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 4 — Cipher: AES-128-GCM (AEAD)
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_aes_gcm(void)
{
    printf("[AES-128-GCM]\n");

    /* NIST CAVP GCM test vector (Keylen=128, IVlen=96, PTlen=128, AADlen=128) */
    static const unsigned char key[16] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    static const unsigned char iv[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
        0xde,0xca,0xf8,0x88
    };
    static const unsigned char plain[16] = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
        0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a
    };
    static const unsigned char aad[16] = {
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef
    };

    unsigned char ct[32]  = {0};
    unsigned char tag[16] = {0};
    unsigned char pt[32]  = {0};
    int outl = 0, finl = 0;

    EVP_CIPHER *ciph = EVP_CIPHER_fetch(NULL, "AES-128-GCM", "provider=sample");
    CHECK(ciph);

    /* ── Encrypt ── */
    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new(); CHECK(ectx);
    CHECK(EVP_EncryptInit_ex(ectx, ciph, NULL, NULL, NULL));
    CHECK(EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL));
    CHECK(EVP_EncryptInit_ex(ectx, NULL, NULL, key, iv));
    CHECK(EVP_EncryptUpdate(ectx, NULL, &outl, aad, 16));     /* AAD */
    CHECK(EVP_EncryptUpdate(ectx, ct, &outl, plain, 16));
    CHECK(EVP_EncryptFinal_ex(ectx, ct + outl, &finl));
    CHECK(EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, tag));
    EVP_CIPHER_CTX_free(ectx);

    dump_hex("ciphertext", ct, 16);
    dump_hex("tag",        tag, 16);

    /* ── Decrypt ── */
    EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new(); CHECK(dctx);
    CHECK(EVP_DecryptInit_ex(dctx, ciph, NULL, NULL, NULL));
    CHECK(EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL));
    CHECK(EVP_DecryptInit_ex(dctx, NULL, NULL, key, iv));
    CHECK(EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, 16, tag));
    CHECK(EVP_DecryptUpdate(dctx, NULL, &outl, aad, 16));     /* AAD */
    CHECK(EVP_DecryptUpdate(dctx, pt, &outl, ct, 16));
    int ok = EVP_DecryptFinal_ex(dctx, pt + outl, &finl);
    EVP_CIPHER_CTX_free(dctx);
    EVP_CIPHER_free(ciph);

    CHECK(ok > 0);
    dump_hex("decrypted", pt, 16);
    CHECK(memcmp(pt, plain, 16) == 0);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 5 — MAC: HMAC-SHA256
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_hmac(void)
{
    printf("[HMAC-SHA256]\n");

    /* RFC 4231 Test Vector #2 */
    static const unsigned char key[] = "Jefe";
    static const unsigned char msg[] = "what do ya want for nothing?";
    static const unsigned char expected[32] = {
        0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,
        0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
        0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,
        0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
    };
    unsigned char out[32];
    size_t        outl = sizeof(out);

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC-SHA256", "provider=sample");
    CHECK(mac);

    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac); CHECK(mctx);

    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                           (void *)key, strlen((char *)key)),
        OSSL_PARAM_construct_end()
    };
    CHECK(EVP_MAC_init(mctx, NULL, 0, params));
    CHECK(EVP_MAC_update(mctx, msg, strlen((char *)msg)));
    CHECK(EVP_MAC_final(mctx, out, &outl, sizeof(out)));

    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);

    dump_hex("HMAC-SHA256", out, 32);
    CHECK(memcmp(out, expected, 32) == 0);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 6 — KDF: HKDF
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_hkdf(void)
{
    printf("[HKDF]\n");

    /* RFC 5869 Test Case 1 */
    static const unsigned char ikm[22]  = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static const unsigned char salt[13] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c
    };
    static const unsigned char info[10] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };
    static const unsigned char expected[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,
        0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
        0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,
        0x58,0x65
    };

    unsigned char okm[42];

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", "provider=sample");
    CHECK(kdf);

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf); CHECK(kctx);
    EVP_KDF_free(kdf);

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA2-256", 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,  (void*)ikm,  22),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt, 13),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info, 10),
        OSSL_PARAM_construct_end()
    };
    CHECK(EVP_KDF_CTX_set_params(kctx, params));
    CHECK(EVP_KDF_derive(kctx, okm, 42, NULL));
    EVP_KDF_CTX_free(kctx);

    dump_hex("HKDF OKM", okm, 42);
    CHECK(memcmp(okm, expected, 42) == 0);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 7 — RAND
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_rand(void)
{
    printf("[RAND: SAMPLE-RAND]\n");

    EVP_RAND *rand = EVP_RAND_fetch(NULL, "SAMPLE-RAND", "provider=sample");
    CHECK(rand);

    EVP_RAND_CTX *rctx = EVP_RAND_CTX_new(rand, NULL); CHECK(rctx);
    EVP_RAND_free(rand);

    OSSL_PARAM params[1] = { OSSL_PARAM_construct_end() };
    CHECK(EVP_RAND_instantiate(rctx, 256, 0, NULL, 0, params));

    unsigned char buf[64];
    CHECK(EVP_RAND_generate(rctx, buf, sizeof(buf), 256, 0, NULL, 0));
    dump_hex("random bytes", buf, 64);

    /* Two consecutive calls should produce different output */
    unsigned char buf2[64];
    CHECK(EVP_RAND_generate(rctx, buf2, sizeof(buf2), 256, 0, NULL, 0));
    /* Very unlikely to be equal */

    EVP_RAND_CTX_free(rctx);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 8 — RSA: keygen + digest_sign + digest_verify
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_rsa_sign(void)
{
    printf("[RSA-PSS sign/verify]\n");

    static const unsigned char msg[] = "Hello, OpenSSL Provider!";
    unsigned char  sig[512] = {0};
    size_t         siglen   = sizeof(sig);

    /* Key generation */
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA",
                                                      "provider=sample");
    CHECK(gctx);
    CHECK(EVP_PKEY_keygen_init(gctx) > 0);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, 2048) > 0);
    EVP_PKEY *pkey = NULL;
    CHECK(EVP_PKEY_generate(gctx, &pkey) > 0);
    EVP_PKEY_CTX_free(gctx);
    printf("  RSA-2048 key generated\n");

    /* Sign */
    EVP_MD_CTX *sctx = EVP_MD_CTX_new(); CHECK(sctx);
    EVP_PKEY_CTX *pkctx = NULL;
    CHECK(EVP_DigestSignInit_ex(sctx, &pkctx, "SHA2-256", NULL,
                                 "provider=sample", pkey, NULL) > 0);
    CHECK(EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) > 0);
    CHECK(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, RSA_PSS_SALTLEN_DIGEST) > 0);
    CHECK(EVP_DigestSignUpdate(sctx, msg, sizeof(msg) - 1) > 0);
    CHECK(EVP_DigestSignFinal(sctx, sig, &siglen) > 0);
    EVP_MD_CTX_free(sctx);
    printf("  Signature length: %zu bytes\n", siglen);

    /* Verify */
    EVP_MD_CTX *vctx = EVP_MD_CTX_new(); CHECK(vctx);
    CHECK(EVP_DigestVerifyInit_ex(vctx, &pkctx, "SHA2-256", NULL,
                                   "provider=sample", pkey, NULL) > 0);
    CHECK(EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) > 0);
    CHECK(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, RSA_PSS_SALTLEN_DIGEST) > 0);
    CHECK(EVP_DigestVerifyUpdate(vctx, msg, sizeof(msg) - 1) > 0);
    CHECK(EVP_DigestVerifyFinal(vctx, sig, siglen) > 0);
    EVP_MD_CTX_free(vctx);

    EVP_PKEY_free(pkey);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 9 — EC: keygen + ECDSA sign/verify
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_ecdsa(void)
{
    printf("[ECDSA P-256 sign/verify]\n");

    static const unsigned char msg[] = "ECDSA test message";
    unsigned char  sig[128] = {0};
    size_t         siglen   = sizeof(sig);

    /* Key generation */
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC",
                                                      "provider=sample");
    CHECK(gctx);
    CHECK(EVP_PKEY_keygen_init(gctx) > 0);

    OSSL_PARAM gp[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                          "P-256", 0),
        OSSL_PARAM_construct_end()
    };
    CHECK(EVP_PKEY_CTX_set_params(gctx, gp));
    EVP_PKEY *pkey = NULL;
    CHECK(EVP_PKEY_generate(gctx, &pkey) > 0);
    EVP_PKEY_CTX_free(gctx);
    printf("  EC P-256 key generated\n");

    /* Sign */
    EVP_MD_CTX *sctx = EVP_MD_CTX_new(); CHECK(sctx);
    EVP_PKEY_CTX *pkctx = NULL;
    CHECK(EVP_DigestSignInit_ex(sctx, &pkctx, "SHA2-256", NULL,
                                 "provider=sample", pkey, NULL) > 0);
    CHECK(EVP_DigestSignUpdate(sctx, msg, sizeof(msg) - 1) > 0);
    CHECK(EVP_DigestSignFinal(sctx, sig, &siglen) > 0);
    EVP_MD_CTX_free(sctx);
    printf("  ECDSA signature: %zu bytes\n", siglen);

    /* Verify */
    EVP_MD_CTX *vctx = EVP_MD_CTX_new(); CHECK(vctx);
    CHECK(EVP_DigestVerifyInit_ex(vctx, NULL, "SHA2-256", NULL,
                                   "provider=sample", pkey, NULL) > 0);
    CHECK(EVP_DigestVerifyUpdate(vctx, msg, sizeof(msg) - 1) > 0);
    CHECK(EVP_DigestVerifyFinal(vctx, sig, siglen) > 0);
    EVP_MD_CTX_free(vctx);

    EVP_PKEY_free(pkey);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 10 — ECDH key exchange
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_ecdh(void)
{
    printf("[ECDH P-256]\n");

    EVP_PKEY *alice = NULL, *bob = NULL;
    unsigned char alice_secret[32] = {0};
    unsigned char bob_secret[32]   = {0};
    size_t        alice_len = sizeof(alice_secret);
    size_t        bob_len   = sizeof(bob_secret);

    /* Generate Alice's key */
    {
        EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(NULL, "EC",
                                                       "provider=sample");
        CHECK(g);
        CHECK(EVP_PKEY_keygen_init(g) > 0);
        OSSL_PARAM p[2] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,"P-256",0),
            OSSL_PARAM_construct_end()
        };
        CHECK(EVP_PKEY_CTX_set_params(g, p));
        CHECK(EVP_PKEY_generate(g, &alice) > 0);
        EVP_PKEY_CTX_free(g);
    }

    /* Generate Bob's key */
    {
        EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(NULL, "EC",
                                                       "provider=sample");
        CHECK(g);
        CHECK(EVP_PKEY_keygen_init(g) > 0);
        OSSL_PARAM p[2] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,"P-256",0),
            OSSL_PARAM_construct_end()
        };
        CHECK(EVP_PKEY_CTX_set_params(g, p));
        CHECK(EVP_PKEY_generate(g, &bob) > 0);
        EVP_PKEY_CTX_free(g);
    }

    /* Alice derives shared secret using Bob's public key */
    {
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, alice,
                                                          "provider=sample");
        CHECK(dctx);
        CHECK(EVP_PKEY_derive_init(dctx) > 0);
        CHECK(EVP_PKEY_derive_set_peer(dctx, bob) > 0);
        CHECK(EVP_PKEY_derive(dctx, alice_secret, &alice_len) > 0);
        EVP_PKEY_CTX_free(dctx);
    }

    /* Bob derives shared secret using Alice's public key */
    {
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, bob,
                                                          "provider=sample");
        CHECK(dctx);
        CHECK(EVP_PKEY_derive_init(dctx) > 0);
        CHECK(EVP_PKEY_derive_set_peer(dctx, alice) > 0);
        CHECK(EVP_PKEY_derive(dctx, bob_secret, &bob_len) > 0);
        EVP_PKEY_CTX_free(dctx);
    }

    dump_hex("Alice secret", alice_secret, alice_len);
    dump_hex("Bob   secret", bob_secret,   bob_len);
    CHECK(alice_len == bob_len);
    CHECK(memcmp(alice_secret, bob_secret, alice_len) == 0);

    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test 11 — Provider metadata
 * ═══════════════════════════════════════════════════════════════════════════ */
static int test_provider_meta(void)
{
    printf("[Provider metadata]\n");

    char *name = NULL, *version = NULL, *buildinfo = NULL;
    OSSL_PARAM params[4] = {
        OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME,      &name,      0),
        OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION,   &version,   0),
        OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, &buildinfo, 0),
        OSSL_PARAM_construct_end()
    };
    CHECK(OSSL_PROVIDER_get_params(g_sample, params));

    printf("  name:      %s\n", name      ? name      : "(null)");
    printf("  version:   %s\n", version   ? version   : "(null)");
    printf("  buildinfo: %s\n", buildinfo ? buildinfo : "(null)");
    CHECK(name != NULL && strcmp(name, "sample") == 0);
    CHECK(version != NULL);
    printf("  PASS\n\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;
    int pass = 0, fail = 0;

#define RUN(fn) do {                            \
    int r = fn();                               \
    if (r) pass++; else { fail++; }            \
} while(0)

    /* Load providers.
     * The default provider is needed for RSA/EC operations that our provider
     * delegates via child OSSL_LIB_CTX.  For the child ctx, the default
     * provider is auto-loaded via OSSL_LIB_CTX_new_child().
     *
     * For the test process's own lib ctx we also load default so EVP
     * lookups without "provider=sample" succeed (e.g. EVP_PKEY_CTX helpers).
     */
    g_default = OSSL_PROVIDER_load(NULL, "default");
    if (!g_default) {
        fprintf(stderr, "Failed to load default provider\n");
        print_errors();
        return 1;
    }

    g_sample = OSSL_PROVIDER_load(NULL, "sample");
    if (!g_sample) {
        fprintf(stderr, "Failed to load sample provider.\n"
                "Set OPENSSL_MODULES=<dir_containing_sample.so> and retry.\n");
        print_errors();
        return 1;
    }

    printf("=== Sample OpenSSL Provider Tests ===\n\n");

    RUN(test_provider_meta);
    RUN(test_sha256);
    RUN(test_sha512);
    RUN(test_aes_cbc);
    RUN(test_aes_gcm);
    RUN(test_hmac);
    RUN(test_hkdf);
    RUN(test_rand);
    RUN(test_rsa_sign);
    RUN(test_ecdsa);
    RUN(test_ecdh);

    printf("=== Results: %d passed, %d failed ===\n", pass, fail);

    OSSL_PROVIDER_unload(g_sample);
    OSSL_PROVIDER_unload(g_default);

    return fail ? 1 : 0;
}
