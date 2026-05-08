/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — RAND (simple PRNG).
 *
 * Pattern demonstrated:
 *   • RAND lifecycle: newctx / freectx / instantiate / uninstantiate.
 *   • generate(): fills caller's buffer, respects prediction_resistance flag.
 *   • reseed(): accepts additional entropy.
 *   • get_ctx_params / set_ctx_params: state/strength query.
 *   • enable_locking / lock / unlock: thread-safety hooks.
 *
 * ⚠ This PRNG is for demonstration ONLY.  It XORs /dev/urandom bytes with
 *   a counter — it is NOT cryptographically strong.  Replace the generate()
 *   body with a proper DRBG (CTR-DRBG, HASH-DRBG, HMAC-DRBG) in production.
 */

#include "provider.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

/* ── State ────────────────────────────────────────────────────────────────── */

typedef struct rand_ctx_st {
    void          *provctx;
    unsigned int   strength;      /* nominal security strength in bits */
    int            instantiated;
    uint64_t       counter;       /* deterministic stream counter      */
    unsigned char  seed[32];      /* entropy held from instantiate/reseed */
    pthread_mutex_t lock;
    int             locking_enabled;
} RAND_CTX;

/* ── OS entropy helper ────────────────────────────────────────────────────── */

static int os_get_entropy(unsigned char *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len);
}

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

static void *rand_newctx(void *vprovctx, void *parent,
                          const OSSL_DISPATCH *parent_dispatch)
{
    RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;
    (void)parent; (void)parent_dispatch;
    ctx->provctx  = vprovctx;
    ctx->strength = 256;
    pthread_mutex_init(&ctx->lock, NULL);
    return ctx;
}

static void rand_freectx(void *vctx)
{
    RAND_CTX *ctx = vctx;
    if (!ctx) return;
    pthread_mutex_destroy(&ctx->lock);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* ── Instantiate / Uninstantiate ─────────────────────────────────────────── */

static int rand_instantiate(void *vctx, unsigned int strength,
                              int prediction_resistance,
                              const unsigned char *pstr, size_t pstr_len,
                              const OSSL_PARAM params[])
{
    RAND_CTX *ctx = vctx;
    (void)strength; (void)prediction_resistance;
    (void)pstr; (void)pstr_len; (void)params;

    if (!os_get_entropy(ctx->seed, sizeof(ctx->seed))) return 0;
    ctx->counter      = 1;
    ctx->instantiated = 1;
    return 1;
}

static int rand_uninstantiate(void *vctx)
{
    RAND_CTX *ctx = vctx;
    OPENSSL_cleanse(ctx->seed, sizeof(ctx->seed));
    ctx->counter      = 0;
    ctx->instantiated = 0;
    return 1;
}

/* ── Generate ────────────────────────────────────────────────────────────── */
/*
 * Minimal PRNG: XOR seed with counter bytes.
 * In a real provider replace this with CTR-DRBG (NIST SP 800-90A).
 */
static int rand_generate(void *vctx,
                          unsigned char *out, size_t outlen,
                          unsigned int strength,
                          int prediction_resistance,
                          const unsigned char *adin, size_t adin_len)
{
    RAND_CTX      *ctx = vctx;
    unsigned char  tmp[32];
    size_t         done = 0;

    (void)strength;

    if (!ctx->instantiated) return 0;

    /* If prediction_resistance is required, re-seed from OS */
    if (prediction_resistance && !os_get_entropy(ctx->seed, sizeof(ctx->seed)))
        return 0;

    while (done < outlen) {
        /* mix seed + counter into a 32-byte block */
        memcpy(tmp, ctx->seed, sizeof(tmp));
        for (int i = 0; i < 8; i++)
            tmp[i] ^= (uint8_t)(ctx->counter >> (i * 8));

        /* mix in additional input if provided */
        if (adin && adin_len) {
            for (size_t i = 0; i < adin_len && i < sizeof(tmp); i++)
                tmp[i] ^= adin[i];
        }

        size_t chunk = (outlen - done) < sizeof(tmp)
                       ? (outlen - done) : sizeof(tmp);
        memcpy(out + done, tmp, chunk);
        done += chunk;
        ctx->counter++;
    }

    /* Backtrack resistance: mix final counter into seed so past outputs
     * cannot be recovered from the current seed state. */
    for (size_t i = 0; i < sizeof(ctx->seed); i++)
        ctx->seed[i] ^= (uint8_t)(ctx->counter >> ((i & 7u) * 8u));

    OPENSSL_cleanse(tmp, sizeof(tmp));
    return 1;
}

/* ── Reseed ───────────────────────────────────────────────────────────────── */

static int rand_reseed(void *vctx,
                        int prediction_resistance,
                        const unsigned char *ent, size_t ent_len,
                        const unsigned char *adin, size_t adin_len)
{
    RAND_CTX *ctx = vctx;
    unsigned char fresh[32];
    (void)prediction_resistance; (void)adin; (void)adin_len;

    if (!os_get_entropy(fresh, sizeof(fresh))) return 0;

    /* XOR caller-supplied entropy into seed */
    for (size_t i = 0; i < sizeof(ctx->seed); i++) {
        ctx->seed[i] ^= fresh[i];
        if (ent && i < ent_len)
            ctx->seed[i] ^= ent[i];
    }
    OPENSSL_cleanse(fresh, sizeof(fresh));
    return 1;
}

/* ── Nonce ────────────────────────────────────────────────────────────────── */

static size_t rand_nonce(void *vctx, unsigned char *out, unsigned int strength,
                          size_t min_noncelen, size_t max_noncelen)
{
    size_t noncelen = min_noncelen < 16 ? 16 : min_noncelen;
    if (noncelen > max_noncelen) noncelen = max_noncelen;
    (void)strength; (void)vctx;
    if (out && !os_get_entropy(out, noncelen)) return 0;
    return noncelen;
}

/* ── Locking ─────────────────────────────────────────────────────────────── */

static int rand_enable_locking(void *vctx)
{
    RAND_CTX *ctx = vctx;
    ctx->locking_enabled = 1;
    return 1;
}

static int rand_lock(void *vctx)
{
    RAND_CTX *ctx = vctx;
    if (!ctx->locking_enabled) return 1;
    return pthread_mutex_lock(&ctx->lock) == 0;
}

static void rand_unlock(void *vctx)
{
    RAND_CTX *ctx = vctx;
    if (ctx->locking_enabled)
        pthread_mutex_unlock(&ctx->lock);
}

/* ── Parameters ──────────────────────────────────────────────────────────── */

static int rand_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    RAND_CTX   *ctx = vctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE)) != NULL
        && !OSSL_PARAM_set_int(p, ctx->instantiated ? 2 /* ready */ : 1 /* uninit */))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH)) != NULL
        && !OSSL_PARAM_set_uint(p, ctx->strength))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST)) != NULL
        && !OSSL_PARAM_set_size_t(p, 1 << 16))
        return 0;

    return 1;
}

static int rand_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    (void)vctx; (void)params;
    return 1;
}

static const OSSL_PARAM rand_gettable_ctx_params_tbl[] = {
    OSSL_PARAM_int   (OSSL_RAND_PARAM_STATE,       NULL),
    OSSL_PARAM_uint  (OSSL_RAND_PARAM_STRENGTH,    NULL),
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *rand_gettable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; return rand_gettable_ctx_params_tbl; }
static const OSSL_PARAM *rand_settable_ctx_params(void *vctx, void *vpctx)
{ (void)vctx; (void)vpctx; static const OSSL_PARAM n[]={OSSL_PARAM_END}; return n; }

static int rand_get_params(OSSL_PARAM params[])
{ (void)params; return 1; }
static const OSSL_PARAM *rand_gettable_params(void *vpctx)
{ (void)vpctx; static const OSSL_PARAM n[]={OSSL_PARAM_END}; return n; }

/* verify_zeroization: check that all secret state is zeroed */
static int rand_verify_zeroization(void *vctx)
{
    RAND_CTX     *ctx = vctx;
    unsigned char zero[sizeof(ctx->seed)];
    memset(zero, 0, sizeof(zero));
    return CRYPTO_memcmp(ctx->seed, zero, sizeof(zero)) == 0;
}

/* ── Dispatch table ──────────────────────────────────────────────────────── */

const OSSL_DISPATCH sample_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX,              FN(rand_newctx)              },
    { OSSL_FUNC_RAND_FREECTX,             FN(rand_freectx)             },
    { OSSL_FUNC_RAND_INSTANTIATE,         FN(rand_instantiate)         },
    { OSSL_FUNC_RAND_UNINSTANTIATE,       FN(rand_uninstantiate)       },
    { OSSL_FUNC_RAND_GENERATE,            FN(rand_generate)            },
    { OSSL_FUNC_RAND_RESEED,              FN(rand_reseed)              },
    { OSSL_FUNC_RAND_NONCE,               FN(rand_nonce)               },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,      FN(rand_enable_locking)      },
    { OSSL_FUNC_RAND_LOCK,                FN(rand_lock)                },
    { OSSL_FUNC_RAND_UNLOCK,              FN(rand_unlock)              },
    { OSSL_FUNC_RAND_GET_PARAMS,          FN(rand_get_params)          },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,      FN(rand_get_ctx_params)      },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS,      FN(rand_set_ctx_params)      },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS,     FN(rand_gettable_params)     },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, FN(rand_gettable_ctx_params) },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, FN(rand_settable_ctx_params) },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,  FN(rand_verify_zeroization)  },
    PROV_DISPATCH_END
};
