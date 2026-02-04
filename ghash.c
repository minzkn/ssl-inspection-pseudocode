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
	int i, j;

	/* Z_0 = 0^128 */
	(void)memset(s_z, 0, (size_t)(128u / 8u));
	
	/* V_0 = Y */
	(void)memcpy(s_v, s_y, sizeof(s_v));

	for (i = 0; i < (128 / 8); i++) {
		for (j = 0; j < 8; j++) {
			if (s_x[i] & (1 << (7 - j) /* BIT */)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				(void)SSL_inspection_xor_block(
					(void *)s_z,
					(const void *)s_v,
					(size_t)(128u / 8u)
				);
			}
			else {
				/* Z_(i + 1) = Z_i */
			}

			if (s_v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				(void)SSL_inspection_right_shift_block(
					(void *)s_v,
					(size_t)(128u / 8u)
				);
				/* R = 11100001 || 0^120 */
				s_v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				(void)SSL_inspection_right_shift_block(
					(void *)s_v,
					(size_t)(128u / 8u)
				);
			}
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
		size_t last = ((size_t)x) + xlen - ((size_t)xpos);
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
