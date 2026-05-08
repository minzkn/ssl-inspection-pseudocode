/* SPDX-License-Identifier: Apache-2.0
 * Sample OpenSSL 3.x Provider — Digest (SHA-256 and SHA-512).
 *
 * Pattern demonstrated:
 *   • Pure-C algorithm state (SHA-256/512 implemented from scratch so this
 *     file has zero dependency on libcrypto internals).
 *   • newctx / dupctx / freectx lifecycle.
 *   • init / update / final streaming interface.
 *   • get_params (static algorithm metadata): digest_size, block_size, flags.
 *   • get_ctx_params / set_ctx_params (per-instance state, e.g. xof_size).
 *   • Single-shot digest() shortcut.
 *
 * To add a new digest in your own provider:
 *   1. Implement the state struct + compress function.
 *   2. Fill in a SHA_IMPL descriptor (see bottom of file).
 *   3. Add the extern + algorithm entry in entry.c.
 */

#include "provider.h"
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "sha256_internal.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * §1  SHA-256 — provided by sha256_internal.h
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Wrapper aliases to preserve the original naming used by the digest context */
#define sha256_init_state  sha256_init
#define sha256_update_state sha256_update
#define sha256_final_state  sha256_final

/* ═══════════════════════════════════════════════════════════════════════════
 * §2  SHA-512 — RFC 6234 / FIPS 180-4
 * ═══════════════════════════════════════════════════════════════════════════ */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL,0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL,0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL,0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL,0x142929670a0e6e70ULL,0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL,0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL,0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL,0xca273eceea26619cULL,0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL,0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

#define ROTR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define EP0_512(x)  (ROTR64(x,28)^ROTR64(x,34)^ROTR64(x,39))
#define EP1_512(x)  (ROTR64(x,14)^ROTR64(x,18)^ROTR64(x,41))
#define SIG0_512(x) (ROTR64(x,1) ^ROTR64(x,8) ^((x)>>7))
#define SIG1_512(x) (ROTR64(x,19)^ROTR64(x,61)^((x)>>6))
#define CH(x,y,z)   (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z)  (((x)&(y))^((x)&(z))^((y)&(z)))

typedef struct {
    uint64_t  state[8];
    uint64_t  count;        /* total bytes processed */
    uint8_t   buf[128];
    uint32_t  buflen;
} SHA512_STATE;

static void sha512_compress(uint64_t state[8], const uint8_t block[128])
{
    uint64_t w[80], a,b,c,d,e,f,g,h, t1,t2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = 0;
        for (int j = 0; j < 8; j++)
            w[i] = (w[i] << 8) | block[i*8+j];
    }
    for (; i < 80; i++)
        w[i] = SIG1_512(w[i-2]) + w[i-7] + SIG0_512(w[i-15]) + w[i-16];

    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];

    for (i = 0; i < 80; i++) {
        t1 = h + EP1_512(e) + CH(e,f,g) + K512[i] + w[i];
        t2 = EP0_512(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static void sha512_init_state(SHA512_STATE *s)
{
    s->state[0]=0x6a09e667f3bcc908ULL; s->state[1]=0xbb67ae8584caa73bULL;
    s->state[2]=0x3c6ef372fe94f82bULL; s->state[3]=0xa54ff53a5f1d36f1ULL;
    s->state[4]=0x510e527fade682d1ULL; s->state[5]=0x9b05688c2b3e6c1fULL;
    s->state[6]=0x1f83d9abfb41bd6bULL; s->state[7]=0x5be0cd19137e2179ULL;
    s->count = 0; s->buflen = 0;
}

static void sha512_update_state(SHA512_STATE *s, const uint8_t *data, size_t len)
{
    size_t fill = 128 - s->buflen;
    s->count += len;

    if (s->buflen && len >= fill) {
        memcpy(s->buf + s->buflen, data, fill);
        sha512_compress(s->state, s->buf);
        data += fill; len -= fill; s->buflen = 0;
    }
    while (len >= 128) {
        sha512_compress(s->state, data);
        data += 128; len -= 128;
    }
    if (len > 0) {
        memcpy(s->buf + s->buflen, data, len);
        s->buflen += (uint32_t)len;
    }
}

static void sha512_final_state(SHA512_STATE *s, uint8_t out[64])
{
    uint64_t bits = s->count * 8;
    uint8_t pad[128] = {0x80};
    size_t padlen = (s->buflen < 112) ? (112 - s->buflen) : (240 - s->buflen);

    sha512_update_state(s, pad, padlen);

    uint8_t len_be[16] = {0};
    for (int i = 15; i >= 8; i--) { len_be[i]=(uint8_t)bits; bits>>=8; }
    sha512_update_state(s, len_be, 16);

    for (int i = 0; i < 8; i++) {
        uint64_t v = s->state[i];
        for (int j = 7; j >= 0; j--) { out[i*8+j]=(uint8_t)v; v>>=8; }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §3  Generic provider digest context
 *     One ctx type covers both SHA-256 and SHA-512; the SHA_IMPL descriptor
 *     plugs in the right sizes and function pointers.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct sha_impl_st {
    const char *name;
    size_t      digest_size;    /* output length in bytes */
    size_t      block_size;     /* compression block in bytes */
    void (*init_fn)(void *state);
    void (*update_fn)(void *state, const uint8_t *data, size_t len);
    void (*final_fn)(void *state, uint8_t *out);
    size_t      state_size;
} SHA_IMPL;

typedef struct digest_ctx_st {
    void            *provctx;
    const SHA_IMPL  *impl;
    void            *state;   /* SHA256_STATE or SHA512_STATE */
} DIGEST_CTX;

/* ── lifecycle ─────────────────────────────────────────────────────────────*/

static void *digest_newctx(void *vprovctx, const SHA_IMPL *impl)
{
    DIGEST_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->state = OPENSSL_zalloc(impl->state_size);
    if (!ctx->state) { OPENSSL_free(ctx); return NULL; }

    ctx->provctx = vprovctx;
    ctx->impl    = impl;
    return ctx;
}

static void digest_freectx(void *vctx)
{
    DIGEST_CTX *ctx = vctx;
    if (!ctx) return;
    OPENSSL_clear_free(ctx->state, ctx->impl->state_size);
    OPENSSL_free(ctx);
}

static void *digest_dupctx(void *vctx)
{
    DIGEST_CTX *src = vctx;
    DIGEST_CTX *dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst) return NULL;

    *dst = *src;
    dst->state = OPENSSL_memdup(src->state, src->impl->state_size);
    if (!dst->state) { OPENSSL_free(dst); return NULL; }
    return dst;
}

/* ── streaming ─────────────────────────────────────────────────────────────*/

static int digest_init(void *vctx, const OSSL_PARAM params[])
{
    DIGEST_CTX *ctx = vctx;
    (void)params;
    ctx->impl->init_fn(ctx->state);
    return 1;
}

static int digest_update(void *vctx, const unsigned char *in, size_t inl)
{
    DIGEST_CTX *ctx = vctx;
    ctx->impl->update_fn(ctx->state, in, inl);
    return 1;
}

static int digest_final(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsz)
{
    DIGEST_CTX *ctx = vctx;
    if (outsz < ctx->impl->digest_size) return 0;
    ctx->impl->final_fn(ctx->state, out);
    *outl = ctx->impl->digest_size;
    return 1;
}

/* ── single-shot ───────────────────────────────────────────────────────────*/

static int digest_digest(void *vprovctx, const SHA_IMPL *impl,
                         const unsigned char *in, size_t inl,
                         unsigned char *out, size_t *outl, size_t outsz)
{
    (void)vprovctx;
    if (outsz < impl->digest_size) return 0;

    /* stack-allocate state to avoid a malloc */
    union { SHA512_STATE sha512; SHA256_STATE sha256; } state_buf;
    impl->init_fn(&state_buf);
    impl->update_fn(&state_buf, in, inl);
    impl->final_fn(&state_buf, out);
    OPENSSL_cleanse(&state_buf, impl->state_size);

    *outl = impl->digest_size;
    return 1;
}

/* ── static parameters ─────────────────────────────────────────────────────*/

static int digest_get_params(const SHA_IMPL *impl, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, impl->block_size))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, impl->digest_size))
        return 0;

    /* OSSL_DIGEST_PARAM_FLAGS was removed in OpenSSL 3.x; expose XOF flag
     * via OSSL_DIGEST_PARAM_XOF instead (SHA-256/512 are not XOF).      */
    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF)) != NULL
        && !OSSL_PARAM_set_int(p, 0))
        return 0;

    return 1;
}

static const OSSL_PARAM digest_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE,       NULL),
    OSSL_PARAM_int   (OSSL_DIGEST_PARAM_XOF,        NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digest_gettable_params(void *vprovctx)
{
    (void)vprovctx;
    return digest_known_gettable_params;
}

/* ctx params: ctx_get_params, ctx_set_params are no-ops for these digests */
static int digest_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    (void)vctx; (void)params;
    return 1;
}
static int digest_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    (void)vctx; (void)params;
    return 1;
}
static const OSSL_PARAM *digest_gettable_ctx_params(void *vctx, void *vpctx)
{
    (void)vctx; (void)vpctx;
    static const OSSL_PARAM none[] = { OSSL_PARAM_END };
    return none;
}
static const OSSL_PARAM *digest_settable_ctx_params(void *vctx, void *vpctx)
{
    (void)vctx; (void)vpctx;
    static const OSSL_PARAM none[] = { OSSL_PARAM_END };
    return none;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §4  SHA-256 dispatch table
 * ═══════════════════════════════════════════════════════════════════════════ */

static const SHA_IMPL sha256_impl = {
    "SHA-256",
    32, 64,
    (void(*)(void*))sha256_init_state,
    (void(*)(void*, const uint8_t*, size_t))sha256_update_state,
    (void(*)(void*, uint8_t*))sha256_final_state,
    sizeof(SHA256_STATE)
};

static void *sha256_newctx(void *vpctx)
{ return digest_newctx(vpctx, &sha256_impl); }

static int sha256_get_params(OSSL_PARAM p[])
{ return digest_get_params(&sha256_impl, p); }

static int sha256_digest(void *vp,
                         const unsigned char *in, size_t inl,
                         unsigned char *out, size_t *outl, size_t outsz)
{ return digest_digest(vp, &sha256_impl, in, inl, out, outl, outsz); }

const OSSL_DISPATCH sample_sha256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,              FN(sha256_newctx)               },
    { OSSL_FUNC_DIGEST_FREECTX,             FN(digest_freectx)              },
    { OSSL_FUNC_DIGEST_DUPCTX,              FN(digest_dupctx)               },
    { OSSL_FUNC_DIGEST_INIT,                FN(digest_init)                 },
    { OSSL_FUNC_DIGEST_UPDATE,              FN(digest_update)               },
    { OSSL_FUNC_DIGEST_FINAL,               FN(digest_final)                },
    { OSSL_FUNC_DIGEST_DIGEST,              FN(sha256_digest)               },
    { OSSL_FUNC_DIGEST_GET_PARAMS,          FN(sha256_get_params)           },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,      FN(digest_get_ctx_params)       },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,      FN(digest_set_ctx_params)       },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,     FN(digest_gettable_params)      },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, FN(digest_gettable_ctx_params)  },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, FN(digest_settable_ctx_params)  },
    PROV_DISPATCH_END
};

/* ═══════════════════════════════════════════════════════════════════════════
 * §5  SHA-512 dispatch table
 * ═══════════════════════════════════════════════════════════════════════════ */

static const SHA_IMPL sha512_impl = {
    "SHA-512",
    64, 128,
    (void(*)(void*))sha512_init_state,
    (void(*)(void*, const uint8_t*, size_t))sha512_update_state,
    (void(*)(void*, uint8_t*))sha512_final_state,
    sizeof(SHA512_STATE)
};

static void *sha512_newctx(void *vpctx)
{ return digest_newctx(vpctx, &sha512_impl); }

static int sha512_get_params(OSSL_PARAM p[])
{ return digest_get_params(&sha512_impl, p); }

static int sha512_digest(void *vp,
                         const unsigned char *in, size_t inl,
                         unsigned char *out, size_t *outl, size_t outsz)
{ return digest_digest(vp, &sha512_impl, in, inl, out, outl, outsz); }

const OSSL_DISPATCH sample_sha512_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,              FN(sha512_newctx)               },
    { OSSL_FUNC_DIGEST_FREECTX,             FN(digest_freectx)              },
    { OSSL_FUNC_DIGEST_DUPCTX,              FN(digest_dupctx)               },
    { OSSL_FUNC_DIGEST_INIT,                FN(digest_init)                 },
    { OSSL_FUNC_DIGEST_UPDATE,              FN(digest_update)               },
    { OSSL_FUNC_DIGEST_FINAL,               FN(digest_final)                },
    { OSSL_FUNC_DIGEST_DIGEST,              FN(sha512_digest)               },
    { OSSL_FUNC_DIGEST_GET_PARAMS,          FN(sha512_get_params)           },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,      FN(digest_get_ctx_params)       },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,      FN(digest_set_ctx_params)       },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,     FN(digest_gettable_params)      },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, FN(digest_gettable_ctx_params)  },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, FN(digest_settable_ctx_params)  },
    PROV_DISPATCH_END
};
