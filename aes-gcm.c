/* reference by freebsd */

/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/*
    Copyright (C) MINZKN.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_aes_gcm_c__)
# define __def_sslid_source_aes_gcm_c__ "aes-gcm.c"

#include "sslid-lib.h"

#define WPA_PUT_BE64(a, val)				\
		do {						\
					(a)[0] = (uint8_t) (((uint64_t) (val)) >> 56);	\
					(a)[1] = (uint8_t) (((uint64_t) (val)) >> 48);	\
					(a)[2] = (uint8_t) (((uint64_t) (val)) >> 40);	\
					(a)[3] = (uint8_t) (((uint64_t) (val)) >> 32);	\
					(a)[4] = (uint8_t) (((uint64_t) (val)) >> 24);	\
					(a)[5] = (uint8_t) (((uint64_t) (val)) >> 16);	\
					(a)[6] = (uint8_t) (((uint64_t) (val)) >> 8);	\
					(a)[7] = (uint8_t) (((uint64_t) (val)) & 0xff);	\
				} while (0)

/* ---- */

static void aes_gctr(void *aes, const uint8_t *icb, const uint8_t *x, size_t xlen, uint8_t *y);
static void aes_gcm_prepare_j0(const uint8_t *iv, size_t iv_len, const uint8_t *H, uint8_t *J0);
static void aes_gcm_gctr(void *aes, const uint8_t *J0, const uint8_t *in, size_t len, uint8_t *out);
static void aes_gcm_ghash(const uint8_t *H, const uint8_t *aad, size_t aad_len, const uint8_t *crypt, size_t crypt_len, uint8_t *S);
int aes_gcm_ae(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len, const uint8_t *plain, size_t plain_len, const uint8_t *aad, size_t aad_len, uint8_t *crypt, uint8_t *tag);
int aes_gcm_ad(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len, const uint8_t *crypt, size_t crypt_len, const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *plain);
int aes_gmac(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len, uint8_t *tag);

/* ---- */

static void aes_gctr(void *aes, const uint8_t *icb, const uint8_t *x, size_t xlen, uint8_t *y)
{
	size_t i, n, last;
	uint8_t cb[def_hwport_aes_block_size], tmp[def_hwport_aes_block_size];
	const uint8_t *xpos = x;
	uint8_t *ypos = y;

	if (xlen == 0)
		return;

	n = xlen / 16;

	memcpy(cb, icb, def_hwport_aes_block_size);
	/* Full blocks */
	for (i = 0; i < n; i++) {
		(void)SSL_inspection_xor_block(
			hwport_encrypt_aes128_ecb(
				memcpy(ypos, cb, def_hwport_aes_block_size),
				def_hwport_aes_block_size,
				aes
			),
			(const void *)xpos,
			(size_t)def_hwport_aes_block_size
		);
		xpos += def_hwport_aes_block_size;
		ypos += def_hwport_aes_block_size;
		(void)SSL_inspection_increment_be_block(
			(void *)(&cb[def_hwport_aes_block_size - sizeof(uint32_t)]),
			(size_t)sizeof(uint32_t)
		);
	}

	last = xlen - n * (size_t)16u;
	if (last) {
		/* Last, partial block */
		(void)hwport_encrypt_aes128_ecb(
			memcpy(tmp, cb, def_hwport_aes_block_size),
			def_hwport_aes_block_size,
			aes
		);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ tmp[i];
	}
}

static void aes_gcm_prepare_j0(const uint8_t *iv, size_t iv_len, const uint8_t *H, uint8_t *J0)
{
	uint8_t len_buf[16];

	if (iv_len == 12) {
		/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
		memcpy(J0, iv, iv_len);
		memset(J0 + iv_len, 0, def_hwport_aes_block_size - iv_len);
		J0[def_hwport_aes_block_size - 1] = 0x01;
	} else {
		/*
		 * s = 128 * ceil(len(IV)/128) - len(IV)
		 * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		 */
		ghash_start(J0);
		ghash(H, iv, iv_len, J0);
		WPA_PUT_BE64(len_buf, 0);
		WPA_PUT_BE64(len_buf + 8, iv_len * 8);
		ghash(H, len_buf, sizeof(len_buf), J0);
	}
}

static void aes_gcm_gctr(void *aes, const uint8_t *J0, const uint8_t *in, size_t len, uint8_t *out)
{
	uint8_t J0inc[def_hwport_aes_block_size];

	if (len == 0)
		return;

	memcpy(J0inc, J0, def_hwport_aes_block_size);
	(void)SSL_inspection_increment_be_block(
		(void *)(&J0inc[def_hwport_aes_block_size - sizeof(uint32_t)]),
		(size_t)sizeof(uint32_t)
	);
	aes_gctr(aes, J0inc, in, len, out);
}

static void aes_gcm_ghash(const uint8_t *H, const uint8_t *aad, size_t aad_len, const uint8_t *crypt, size_t crypt_len, uint8_t *S)
{
	uint8_t len_buf[16];

	/*
	 * u = 128 * ceil[len(C)/128] - len(C)
	 * v = 128 * ceil[len(A)/128] - len(A)
	 * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	ghash_start(S);
	ghash(H, aad, aad_len, S);
	ghash(H, crypt, crypt_len, S);
	WPA_PUT_BE64(len_buf, aad_len * 8);
	WPA_PUT_BE64(len_buf + 8, crypt_len * 8);
	ghash(H, len_buf, sizeof(len_buf), S);
}

/**
 * aes_gcm_ae - GCM-AE_K(IV, P, A)
 */
int aes_gcm_ae(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len, const uint8_t *plain, size_t plain_len, const uint8_t *aad, size_t aad_len, uint8_t *crypt, uint8_t *tag)
{
	uint8_t s_round_key[def_hwport_aes128_round_key_size];
	uint8_t H[def_hwport_aes_block_size];
	uint8_t J0[def_hwport_aes_block_size];
	uint8_t S[16];
	
	(void)key_len;
 
	(void)hwport_make_round_key_aes128(
		(void *)(&s_round_key[0]),
		(const void *)key
	);

	/* Generate hash subkey H = AES_K(0^128) */
	(void)hwport_encrypt_aes128_ecb(
		memset((void *)(&H[0]), 0, sizeof(H)),
		sizeof(H),
		(const void *)(&s_round_key[0])
	);

	/* - */

	aes_gcm_prepare_j0(iv, iv_len, H, J0);

	/* C = GCTR_K(inc_32(J_0), P) */
	aes_gcm_gctr(s_round_key, J0, plain, plain_len, crypt);

	aes_gcm_ghash(H, aad, aad_len, crypt, plain_len, S);

	/* T = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(s_round_key, J0, S, sizeof(S), tag);

	/* Return (C, T) */
	
	/* - */

	/* clean round key */
	SSL_inspection_secure_memzero((void *)(&s_round_key[0]), sizeof(s_round_key));

	return 0;
}

/**
 * aes_gcm_ad - GCM-AD_K(IV, C, A, T)
 */
int aes_gcm_ad(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len, const uint8_t *crypt, size_t crypt_len, const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *plain)
{
	uint8_t s_round_key[def_hwport_aes128_round_key_size];
	uint8_t H[def_hwport_aes_block_size];
	uint8_t J0[def_hwport_aes_block_size];
	uint8_t S[16], T[16];

	(void)key_len;

	(void)hwport_make_round_key_aes128(
		(void *)(&s_round_key[0]),
		(const void *)key
	);

	/* Generate hash subkey H = AES_K(0^128) */
	(void)hwport_encrypt_aes128_ecb(
		memset((void *)(&H[0]), 0, sizeof(H)),
		sizeof(H),
		(const void *)(&s_round_key[0])
	);
	
	/* - */

	aes_gcm_prepare_j0(iv, iv_len, H, J0);

	/* P = GCTR_K(inc_32(J_0), C) */
	aes_gcm_gctr(s_round_key, J0, crypt, crypt_len, plain);

	aes_gcm_ghash(H, aad, aad_len, crypt, crypt_len, S);

	/* T' = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(s_round_key, J0, S, sizeof(S), T);

	/* - */

	/* clean round key */
	SSL_inspection_secure_memzero((void *)(&s_round_key[0]), sizeof(s_round_key));

	/* - */

	/* Constant-time tag comparison to prevent timing oracle attacks */
	if (CRYPTO_memcmp(tag, T, 16) != 0) { /* GCM: Tag mismatch ! */
		return -1;
	}

	return 0;
}

int aes_gmac(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len, uint8_t *tag)
{
	return aes_gcm_ae(key, key_len, iv, iv_len, NULL, 0, aad, aad_len, NULL,
			  tag);
}

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
