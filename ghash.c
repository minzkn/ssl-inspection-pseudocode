/*
    Copyright (C) MINZKN.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_ghash_c__)
# define __def_sslid_source_ghash_c__ "ghash.c"

#include "sslid-lib.h"

/* ---- */

void gf_mult128(const uint8_t *x, const uint8_t *y, uint8_t *z);
void ghash_start(uint8_t *y);
void ghash(const uint8_t *h, const uint8_t *x, size_t xlen, uint8_t *y);
    
/* ---- */

/*
	Multiplication in GF(2^128)

	Algorithm 1 Multiplication in Computes the value of Z = X · Y , where X, Y and Z ∈ GF(2128).

	Z ← 0, V ← X
	for i =0 to 127 do
		if Yi =1 then
			Z ← Z ⊕ V
		end if
		if V127 =0 then
			V ← rightshift(V )
		else
			V ← rightshift(V ) ⊕ R
		end if
	end for
	return Z
*/
void gf_mult128(const uint8_t *s_x, const uint8_t *s_y, uint8_t *s_z)
{
	uint8_t s_v[128 / 8];
	int i, j, k;

	/* Z_0 = 0^128 */
	(void)memset(s_z, 0, (size_t)(128u / 8u));

	/* V_0 = Y */
	(void)memcpy(s_v, s_y, sizeof(s_v));

	/*
	 * Constant-time GF(2^128) multiplication.
	 * Both conditional operations (Z ^= V and V reduction) are replaced
	 * with branchless mask-based XOR to prevent timing side-channel attacks.
	 */
	for (i = 0; i < (128 / 8); i++) {
		for (j = 0; j < 8; j++) {
			/* mask = 0xFF if X bit is 1, 0x00 if X bit is 0 */
			uint8_t x_mask = (uint8_t)(0u - ((s_x[i] >> (7 - j)) & 1u));
			/* Z_(i+1) = Z_i XOR (V_i AND mask): no branch */
			for (k = 0; k < (128 / 8); k++) {
				s_z[k] ^= s_v[k] & x_mask;
			}

			/* r_mask = 0xFF if V LSB is 1, 0x00 if V LSB is 0 */
			uint8_t r_mask = (uint8_t)(0u - (s_v[15] & 0x01u));
			/* V_(i+1) = V_i >> 1, then conditionally XOR R = 0xe1||0^120 */
			for (k = 15; k > 0; k--) {
				s_v[k] = (uint8_t)((s_v[k] >> 1) | (s_v[k - 1] << 7));
			}
			s_v[0] >>= 1;
			/* R = 11100001 || 0^120: conditional XOR, branchless */
			s_v[0] ^= 0xe1u & r_mask;
		}
	}
}

void ghash_start(uint8_t *y)
{
	/* Y_0 = 0^128 */
	(void)memset(y, 0, (size_t)def_hwport_ghash_block_size);
}

void ghash(const uint8_t *h, const uint8_t *x, size_t xlen, uint8_t *y)
{
	size_t m, i;
	const uint8_t *xpos = x;
	uint8_t tmp[def_hwport_ghash_block_size];

	m = xlen / def_hwport_ghash_block_size;

	for (i = 0; i < m; i++) {
		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		(void)SSL_inspection_xor_block(
			(void *)y,
			(const void *)xpos,
			(size_t)def_hwport_ghash_block_size
		);
		xpos += def_hwport_ghash_block_size;

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult128(y, h, tmp);
		memcpy(y, tmp, sizeof(tmp));
	}

	if (x + xlen > xpos) {
		/* Add zero padded last block */
		size_t last = xlen - m * def_hwport_ghash_block_size;
		memcpy(tmp, xpos, last);
		memset(tmp + last, 0, sizeof(tmp) - last);

		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		(void)SSL_inspection_xor_block(
			(void *)y,
			(const void *)tmp,
			(size_t)def_hwport_ghash_block_size
		);

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult128(y, h, tmp);
		memcpy(y, tmp, sizeof(tmp));
	}

	/* Return Y_m */
}

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
