/*
    Copyright (C) MINZKN.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_test_vector_c__)
# define __def_sslid_source_test_vector_c__ "test-vector.c"

/* ---- */

#include "sslid-lib.h"

#if defined(def_sslid_test_vector)

/* ---- */

/* ---- */

int SSL_inspection_sha256_test0(int s_is_verbose);

int SSL_inspection_hmac_sha256_test0(int s_is_verbose);
int SSL_inspection_hmac_sha256_test1(int s_is_verbose);

int SSL_inspection_pseudo_random_function_tlsv1_2_sha256_test0(int s_is_verbose);

int SSL_inspection_evp_test0(int s_is_verbose);
int SSL_inspection_evp_test1(int s_is_verbose);

int SSL_inspection_internal_impl_test0(int s_is_verbose);

/* ---- */

int SSL_inspection_sha256_test0(int s_is_verbose)
{
	static const unsigned char cg_test_string[] = {
		"Hello"
	};
	static const uint8_t cg_digest_check[] = {
		0x18, 0x5f, 0x8d, 0xb3, 0x22, 0x71, 0xfe, 0x25,
		0xf5, 0x61, 0xa6, 0xfc, 0x93, 0x8b, 0x2e, 0x26,
		0x43, 0x06, 0xec, 0x30, 0x4e, 0xda, 0x51, 0x80,
		0x07, 0xd1, 0x76, 0x48, 0x26, 0x38, 0x19, 0x69
	};

	hwport_sha256_t s_sha256_local;
	hwport_sha256_t *s_sha256;
	uint8_t s_digest_local[ def_hwport_sha256_digest_size ];

	s_sha256 = hwport_init_sha256((hwport_sha256_t *)(&s_sha256_local));
	(void)hwport_sha256_push(
		s_sha256,
		(const char *)(&cg_test_string[0]),
		strlen((const char *)(&cg_test_string[0]))
	);

	(void)SSL_inspection_fprintf(
		stdout,
		"* TEST Digest SHA-256 push \"%s\" (%lu bytes, %s)\n",
		(const char *)(&cg_test_string[0]),
		(unsigned long)strlen((const char *)(&cg_test_string[0])),
		(
			memcmp(
				(const void *)hwport_sha256_digest(
					s_sha256,
					memset((void *)(&s_digest_local[0]), 0, sizeof(s_digest_local))
				),
				(const void *)(&cg_digest_check[0]),
				sizeof(cg_digest_check)) == 0
		) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
	);

	if(s_is_verbose >= 1) {
		(void)SSL_inspection_hexdump("  ", (const void *)(&s_digest_local[0]), sizeof(s_digest_local));
	}

	(void)SSL_inspection_fprintf(
		stdout,
		"* TEST Digest SHA-256 simple \"%s\" (%lu bytes, %s)\n",
		(const char *)(&cg_test_string[0]),
		(unsigned long)strlen((const char *)(&cg_test_string[0])),
		(
			memcmp(
				(const void *)hwport_sha256_simple(
					(const char *)(&cg_test_string[0]),
					(unsigned long)strlen((const char *)(&cg_test_string[0])),
					memset((void *)(&s_digest_local[0]), 0, sizeof(s_digest_local))
				),
				(const void *)(&cg_digest_check[0]),
				sizeof(cg_digest_check)) == 0
		) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
	);

	if(s_is_verbose >= 1) {
		(void)SSL_inspection_hexdump("  ", (const void *)(&s_digest_local[0]), sizeof(s_digest_local));
	}

	return(0);
}

int SSL_inspection_hmac_sha256_test0(int s_is_verbose)
{
	/* HMAC_SHA256("", "") = b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad */
	static const unsigned char cg_test_secret[] = {
		""
	};
	static const unsigned char cg_test_data[] = {
		""
	};
	static const uint8_t cg_digest_check[] = {
		0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec,
		0x77, 0x2f, 0x95, 0xd7, 0x78, 0xc3, 0x5f, 0xc5,
		0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53,
		0xc6, 0xc7, 0x12, 0x14, 0x42, 0x92, 0xc5, 0xad
	};

	hwport_sha256_t s_sha256_local;
	hwport_sha256_t *s_sha256;
	uint8_t s_digest_local[ def_hwport_sha256_digest_size ];

	s_sha256 = hwport_init_hmac_sha256(
		(hwport_sha256_t *)(&s_sha256_local),
		(const void *)(&cg_test_secret[0]),
		strlen((const char *)(&cg_test_secret[0]))
	);
	(void)hwport_sha256_push(
		s_sha256,
		(const char *)(&cg_test_data[0]),
		strlen((const char *)(&cg_test_data[0]))
	);

	(void)SSL_inspection_fprintf(
		stdout,
		"* TEST Digest HMAC-SHA-256 push (secret=\"%s\", data=\"%s\", %s)\n",
		(const char *)(&cg_test_secret[0]),
		(const char *)(&cg_test_data[0]),
		(
			memcmp(
				(const void *)hwport_hmac_sha256_digest(
					s_sha256,
					memset((void *)(&s_digest_local[0]), 0, sizeof(s_digest_local))
				),
				(const void *)(&cg_digest_check[0]),
				sizeof(cg_digest_check)) == 0
		) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
	);

	if(s_is_verbose >= 1) {
		(void)SSL_inspection_hexdump("  ", (const void *)(&s_digest_local[0]), sizeof(s_digest_local));
	}

#if 1L /* Test by OpenSSL */
	/* unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *data, size_t data_len, unsigned char *md, unsigned int *md_len); */
	if(HMAC(
		EVP_sha256(),
		(const void *)(&cg_test_secret[0]),
		(int)strlen((const char *)(&cg_test_secret[0])),
		(const unsigned char *)(&cg_test_data[0]),
		strlen((const char *)(&cg_test_data[0])),
		(unsigned char *)memset((void *)(&s_digest_local[0]), 0, sizeof(s_digest_local)),
		(unsigned int *)NULL
	) == ((unsigned char *)(NULL))) {
		(void)SSL_inspection_fprintf(
			stdout,
			"* TEST Digest HMAC-SHA-256 push by OpenSSL " def_hwport_color_red "FAILED" def_hwport_color_normal " ! (HMAC failed)\n"
		);
	}
	else {
		(void)SSL_inspection_fprintf(
			stdout,
			"* TEST Digest HMAC-SHA-256 push by OpenSSL (secret=\"%s\", data=\"%s\", %s)\n",
			(const char *)(&cg_test_secret[0]),
			(const char *)(&cg_test_data[0]),
			(
				memcmp(
					(const void *)(&s_digest_local[0]),
					(const void *)(&cg_digest_check[0]),
					sizeof(cg_digest_check)) == 0
			) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);

		if(s_is_verbose >= 1) {
			(void)SSL_inspection_hexdump("  ", (const void *)(&s_digest_local[0]), sizeof(s_digest_local));
		}
	}
#endif

	return(0);
}

int SSL_inspection_hmac_sha256_test1(int s_is_verbose)
{
	/* HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8 */
	static const unsigned char cg_test_secret[] = {
		"key"
	};
	static const unsigned char cg_test_data[] = {
		"The quick brown fox jumps over the lazy dog"
	};
	static const uint8_t cg_digest_check[] = {
		0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
		0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
		0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
		0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8
	};

	hwport_sha256_t s_sha256_local;
	hwport_sha256_t *s_sha256;
	uint8_t s_digest_local[ def_hwport_sha256_digest_size ];

	s_sha256 = hwport_init_hmac_sha256(
		(hwport_sha256_t *)(&s_sha256_local),
		(const void *)(&cg_test_secret[0]),
		strlen((const char *)(&cg_test_secret[0]))
	);

#if 0L
	(void)hwport_sha256_push(
		s_sha256,
		(const char *)(&cg_test_data[0]),
		strlen((const char *)(&cg_test_data[0]))
	);

#if 1L /* Test by OpenSSL */
	if(s_hmac_ctx != ((HMAC_CTX *)(NULL))) {
		if(HMAC_Update(
			s_hmac_ctx,
			(const unsigned char *)(&cg_test_data[0]),
			strlen((const char *)(&cg_test_data[0]))
			) <= 0) {
			(void)SSL_inspection_fprintf(
				stdout,
				"* TEST Digest HMAC-SHA-256 push by OpenSSL " def_hwport_color_red "FAILED" def_hwport_color_normal " ! (HMAC_Update failed)\n"
			);

			HMAC_CTX_free(s_hmac_ctx);
			s_hmac_ctx = (HMAC_CTX *)NULL;
		}
	}
#endif
#else /* partial test */
	do {
		size_t s_data_size;
		size_t s_offset;
		size_t s_unit_size;
		size_t s_rand_size;

		srand((unsigned int)time((time_t *)(NULL)));
		s_data_size = strlen((const char *)(&cg_test_data[0]));
		for(s_offset = (size_t)0u;s_offset < s_data_size;) {
			s_rand_size = ((size_t)(rand() % 10)) /* + ((size_t)1u) */;
			s_unit_size = s_data_size - s_offset;
			if(s_unit_size > s_rand_size) {
				s_unit_size = s_rand_size;
			}

			(void)hwport_sha256_push(
				s_sha256,
				(const char *)(&cg_test_data[s_offset]),
				s_unit_size
			);
			
			s_offset += s_unit_size;
			
			(void)SSL_inspection_fprintf(stdout, "partial push %lu/%lu/%lu\n", s_unit_size, s_offset, s_data_size);
		}
	}while(0);
#endif

	(void)SSL_inspection_fprintf(
		stdout,
		"* TEST Digest HMAC-SHA-256 push (secret=\"%s\", data=\"%s\", %s)\n",
		(const char *)(&cg_test_secret[0]),
		(const char *)(&cg_test_data[0]),
		(
			memcmp(
				(const void *)hwport_hmac_sha256_digest(
					s_sha256,
					memset((void *)(&s_digest_local[0]), 0, sizeof(s_digest_local))
				),
				(const void *)(&cg_digest_check[0]),
				sizeof(cg_digest_check)) == 0
		) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
	);

	if(s_is_verbose >= 1) {
		(void)SSL_inspection_hexdump("  ", (const void *)(&s_digest_local[0]), sizeof(s_digest_local));
	}
			
#if 1L /* Test by OpenSSL */
	/* unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *data, size_t data_len, unsigned char *md, unsigned int *md_len); */
	if(HMAC(
		EVP_sha256(),
		(const void *)(&cg_test_secret[0]),
		(int)strlen((const char *)(&cg_test_secret[0])),
		(const unsigned char *)(&cg_test_data[0]),
		strlen((const char *)(&cg_test_data[0])),
		(unsigned char *)memset((void *)(&s_digest_local[0]), 0, sizeof(s_digest_local)),
		(unsigned int *)NULL
	) == ((unsigned char *)(NULL))) {
		(void)SSL_inspection_fprintf(
			stdout,
			"* TEST Digest HMAC-SHA-256 push by OpenSSL " def_hwport_color_red "FAILED" def_hwport_color_normal " ! (HMAC failed)\n"
		);
	}
	else {
		(void)SSL_inspection_fprintf(
			stdout,
			"* TEST Digest HMAC-SHA-256 push by OpenSSL (secret=\"%s\", data=\"%s\", %s)\n",
			(const char *)(&cg_test_secret[0]),
			(const char *)(&cg_test_data[0]),
			(
				memcmp(
					(const void *)(&s_digest_local[0]),
					(const void *)(&cg_digest_check[0]),
					sizeof(cg_digest_check)) == 0
			) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);

		if(s_is_verbose >= 1) {
			(void)SSL_inspection_hexdump("  ", (const void *)(&s_digest_local[0]), sizeof(s_digest_local));
		}
	}
#endif

	return(0);
}

int SSL_inspection_pseudo_random_function_tlsv1_2_sha256_test0(int s_is_verbose)
{
	/*
		* https://www.ietf.org/mail-archive/web/tls/current/msg03416.html

		Generating 100 bytes of pseudo-randomness using TLS1.2PRF-SHA256
		Secret (16 bytes):
			0000    9b be 43 6b a9 40 f0 17    ..Ck....
			0008    b1 76 52 84 9a 71 db 35    .vR..q.5

		Seed (16 bytes):
			0000    a0 ba 9f 93 6c da 31 18    ....l.1.
			0008    27 a6 f7 96 ff d5 19 8c    ........

		Label (10 bytes):
			0000    74 65 73 74 20 6c 61 62    test lab
			0008    65 6c                      el

		Output (100 bytes):
			0000    e3 f2 29 ba 72 7b e1 7b    ....r...
			0008    8d 12 26 20 55 7c d4 53    ... U..S
			0010    c2 aa b2 1d 07 c3 d4 95    ........
			0018    32 9b 52 d4 e6 1e db 5a    2.R....Z
			0020    6b 30 17 91 e9 0d 35 c9    k0....5.
			0028    c9 a4 6b 4e 14 ba f9 af    ..kN....
			0030    0f a0 22 f7 07 7d ef 17    ........
			0038    ab fd 37 97 c0 56 4b ab    ..7..VK.
			0040    4f bc 91 66 6e 9d ef 9b    O..fn...
			0048    97 fc e3 4f 79 67 89 ba    ...Oyg..
			0050    a4 80 82 d1 22 ee 42 c5    ......B.
			0058    a7 2e 5a 51 10 ff f7 01    ..ZQ....
			0060    87 34 7b 66                .4.f
	*/
	static const uint8_t cg_secret[] = {
		0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
		0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35
	};
	static const uint8_t cg_label[] = {
		"test label"
	};
	static const uint8_t cg_seed[] = {
		0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
		0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c
	};
	static const uint8_t cg_output_check[] = {
		0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b,
		0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4, 0x53,
		0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95,
		0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e, 0xdb, 0x5a,
		0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9,
		0xc9, 0xa4, 0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf,
		0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17,
		0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab,
		0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b,
		0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba,
		0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5,
		0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01,
		0x87, 0x34, 0x7b, 0x66            
	};
	uint8_t s_output[ sizeof(cg_output_check) ];

	(void)hwport_pseudo_random_function_tlsv1_2_sha256(
		(const void *)(&cg_secret[0]),
		sizeof(cg_secret),
		(const void *)(&cg_label[0]),
		strlen((const char *)(&cg_label[0])),
		(const void *)(&cg_seed[0]),
		sizeof(cg_seed),
		(void *)(&s_output[0]),
		sizeof(s_output)
	);

	(void)SSL_inspection_fprintf(
		stdout,
		"* TEST TLS v1.2 PRF[Psudo Random Function] (label=\"%s\", %lu bytes, %s)\n",
		(const char *)(&cg_label[0]),
		(unsigned long)sizeof(s_output),
		(
			memcmp(
				(const void *)(&s_output[0]),
				(const void *)(&cg_output_check[0]),
				sizeof(cg_output_check)) == 0
		) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
	);

	if(s_is_verbose >= 1) {
		(void)SSL_inspection_hexdump(
			"  ",
			(const void *)(&s_output[0]),
			sizeof(s_output)
		);
	}

	return(0);
}

int SSL_inspection_evp_test0(int s_is_verbose)
{
	/*
	2.8.1 75-byte Packet Encryption Using GCM-AES-128
		This example performs authenticated encryption using GCM-AES-128. It produces a 128-bit integrity check value (ICV).
			key size = 128 bits
			P: 504 bits
			A: 160 bits
			IV: 96 bits
			ICV: 128 bits
			Key:
				88EE087FD95DA9FBF6725AA9D757B0CD
			P:
				08000F101112131415161718191A1B1C
				1D1E1F202122232425262728292A2B2C
				2D2E2F303132333435363738393A3B3C
				3D3E3F404142434445464748490008
			A:
				68F2E77696CE7AE8E2CA4EC588E54D00
				2E58495C
			IV:
				7AE8E2CA4EC500012E58495C
			GCM-AES Encryption
				H: AE19118C3B704FCE42AE0D15D2C15C7A
				Y[0]: 7AE8E2CA4EC500012E58495C00000001
				E(K,Y[0]): D2521AABC48C06033E112424D4A6DF74
				Y[1]: 7AE8E2CA4EC500012E58495C00000002
				E(K,Y[1]): CB1F5CC98F4494E323470EA02BC8B1FB
				C[1]: C31F53D99E5687F7365119B832D2AAE7
				Y[2]: 7AE8E2CA4EC500012E58495C00000003
				E(K,Y[2]): 1A5FCAB3D0DBC18F117350B32EA493D2
				C[2]: 0741D593F1F9E2AB3455779B078EB8FE
				Y[3]: 7AE8E2CA4EC500012E58495C00000004
				E(K,Y[3]): 81F1C32FBF0C6143CD2E3C7B0F255E2E
				C[3]: ACDFEC1F8E3E5277F8180B43361F6512
				Y[4]: 7AE8E2CA4EC500012E58495C00000005
				E(K,Y[4]): 908F526E7916C96834DBFD3A61D848B2
				C[4]: ADB16D2E38548A2C719DBA7228D840
				X[1]: A9845CAED3E164079E217A8D26A600DA
				X[2]: 09410740B1204002F754119A976F31C8
				X[3]: CB897D3B71442B121E77CEA5416D3931
				X[4]: 5F3A6A2D049FF2337096523ECAA1BD30
				X[5]: 0C95908AEEBDAF1B1C279837AE498000
				X[6]: 1ACA99E1E46D2395BC610D21BB4216A0
				GHASH(H,A,C): 5AAA6FD11F06A18BE6E77EF2BC18AF93
			C:
				C31F53D99E5687F7365119B832D2AAE7
				0741D593F1F9E2AB3455779B078EB8FE
				ACDFEC1F8E3E5277F8180B43361F6512
				ADB16D2E38548A2C719DBA7228D840
			T: 88F8757ADB8AA788D8F65AD668BE70E7
			ICV: 88F8757ADB8AA788D8F65AD668BE70E7

			The final MACsec processed packet combines the MAC DA, the MAC SA, the security tag, the encrypted user data, and the ICV.
				68F2E776 96CE7AE8 E2CA4EC5 88E54D00
				2E58495C C31F53D9 9E5687F7 365119B8
				32D2AAE7 0741D593 F1F9E2AB 3455779B
				078EB8FE ACDFEC1F 8E3E5277 F8180B43
				361F6512 ADB16D2E 38548A2C 719DBA72
				28D84088 F8757ADB 8AA788D8 F65AD668
				BE70E7
	*/
	static const unsigned char cg_key0[ /* 128 >> 3 */ ] = {
		0x88, 0xEE, 0x08, 0x7F, 0xD9, 0x5D, 0xA9, 0xFB, 0xF6, 0x72, 0x5A, 0xA9, 0xD7, 0x57, 0xB0, 0xCD
	};
	static const unsigned char cg_plaintext0[ /* 504 >> 3 */ ] = {
		0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
		0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
		0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
		0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x00, 0x08
	};
	static const unsigned char cg_aad0[ /* 160 >> 3 */ ] = {
		0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x88, 0xE5, 0x4D, 0x00,
		0x2E, 0x58, 0x49, 0x5C
	};
	static const unsigned char cg_iv0[ /* 96 >> 3 */ ] = {
		0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x00, 0x01, 0x2E, 0x58, 0x49, 0x5C
	};
	static const unsigned char cg_icv0[ /* 128 >> 3 */ ] = { /* integrity check value (ICV) */
		0x88, 0xF8, 0x75, 0x7A, 0xDB, 0x8A, 0xA7, 0x88, 0xD8, 0xF6, 0x5A, 0xD6, 0x68, 0xBE, 0x70, 0xE7
	};
	static const unsigned char cg_ciphertext_combines0[ /* (160 + 504 + 128) >> 3 */ ] = {
		0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x88, 0xE5, 0x4D, 0x00,
		0x2E, 0x58, 0x49, 0x5C,
		0xC3, 0x1F, 0x53, 0xD9, 0x9E, 0x56, 0x87, 0xF7, 0x36, 0x51, 0x19, 0xB8, 0x32, 0xD2, 0xAA, 0xE7,
		0x07, 0x41, 0xD5, 0x93, 0xF1, 0xF9, 0xE2, 0xAB, 0x34, 0x55, 0x77, 0x9B, 0x07, 0x8E, 0xB8, 0xFE,
		0xAC, 0xDF, 0xEC, 0x1F, 0x8E, 0x3E, 0x52, 0x77, 0xF8, 0x18, 0x0B, 0x43, 0x36, 0x1F, 0x65, 0x12,
		0xAD, 0xB1, 0x6D, 0x2E, 0x38, 0x54, 0x8A, 0x2C, 0x71, 0x9D, 0xBA, 0x72, 0x28, 0xD8, 0x40,
		0x88, 0xF8, 0x75, 0x7A, 0xDB, 0x8A, 0xA7, 0x88, 0xD8, 0xF6, 0x5A, 0xD6, 0x68, 0xBE, 0x70, 0xE7
	};

	unsigned char s_ciphertext0[ sizeof(cg_plaintext0) ] = {0, };
	unsigned char s_tag0[ 128 >> 3 ] = {0, };
	unsigned char s_plaintext0[ sizeof(cg_plaintext0) ] = {0, };

	const EVP_CIPHER *c_cipher;

	ssize_t s_process_size;

	(void)SSL_inspection_fprintf(stdout, "* TEST AEAD-AES128-GCM\n");

#if 1L
	c_cipher = EVP_get_cipherbyname("aes-128-gcm");
#else
	c_cipher = EVP_aes_128_gcm();
#endif

	if(s_is_verbose >= 1) {
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Key (%lu bytes)\n", (unsigned long)sizeof(cg_key0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_key0[0]), sizeof(cg_key0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Plain-Text (%lu bytes)\n", (unsigned long)sizeof(cg_plaintext0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_plaintext0[0]), sizeof(cg_plaintext0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Additional-Authenticated-Data (%lu bytes)\n", (unsigned long)sizeof(cg_aad0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_aad0[0]), sizeof(cg_aad0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Initial-Vector (%lu bytes)\n", (unsigned long)sizeof(cg_iv0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_iv0[0]), sizeof(cg_iv0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Integrity-Check-Value (%lu bytes)\n", (unsigned long)sizeof(cg_icv0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_icv0[0]), sizeof(cg_icv0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Cipher-Text-Combines (%lu bytes)\n", (unsigned long)sizeof(cg_ciphertext_combines0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_ciphertext_combines0[0]), sizeof(cg_ciphertext_combines0));
	}

	(void)SSL_inspection_fprintf(stdout, "  - Encrypt\n");
	s_process_size = SSL_inspection_encrypt_AES_GCM(
		c_cipher,
		(const void *)(&cg_plaintext0[0]),
		sizeof(cg_plaintext0),
		(const void *)(&cg_aad0[0]),
		sizeof(cg_aad0),
		(const void *)(&cg_key0[0]),
		(const void *)(&cg_iv0[0]),
		sizeof(cg_iv0),
		(void *)(&s_ciphertext0[0]),
		(void *)(&s_tag0[0])
	);
	if(s_process_size == ((ssize_t)(-1))) {
		(void)SSL_inspection_fprintf(stderr, def_hwport_color_red "SSL_inspection_encrypt_AES_GCM failed !" def_hwport_color_normal "\n");
	}
	else {
		(void)SSL_inspection_fprintf(stdout, "    - encrypted size : %ld\n", (long)s_process_size);
		if(s_is_verbose >= 1) {
			(void)SSL_inspection_hexdump("      [A] ", (const void *)(&cg_aad0[0]), sizeof(cg_aad0));
			(void)SSL_inspection_hexdump("      [E] ", (const void *)(&s_ciphertext0[0]), (size_t)s_process_size);
			(void)SSL_inspection_hexdump("      [T] ", (const void *)(&s_tag0[0]), sizeof(s_tag0));
		}
		(void)SSL_inspection_fprintf(
			stdout,
			"    - verify cipher-text : %s\n",
			(memcmp(
				(const void *)(&s_ciphertext0[0]),
				(const void *)(&cg_ciphertext_combines0[sizeof(cg_aad0)]),
				sizeof(cg_plaintext0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);
		(void)SSL_inspection_fprintf(
			stdout,
			"    - verify tag : %s\n",
			(memcmp(
				(const void *)(&s_tag0[0]),
				(const void *)(&cg_icv0[0]),
				sizeof(cg_icv0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);

		(void)SSL_inspection_fprintf(stdout, "  - Decrypt\n");
		s_process_size = SSL_inspection_decrypt_AES_GCM(
			c_cipher,
			(const void *)(&s_ciphertext0[0]),
			sizeof(s_ciphertext0),
			(const void *)(&cg_aad0[0]),
			sizeof(cg_aad0),
			(const void *)(&s_tag0[0]),
			(const void *)(&cg_key0[0]),
			(const void *)(&cg_iv0[0]),
			sizeof(cg_iv0),
			(void *)(&s_plaintext0[0])
		);
		if(s_process_size == ((ssize_t)(-1))) {
			(void)SSL_inspection_fprintf(stderr, def_hwport_color_red "SSL_inspection_decrypt_AES_GCM failed !" def_hwport_color_normal "\n");
		}
		else {
			(void)SSL_inspection_fprintf(stdout, "    - decrypted size : %ld\n", (long)s_process_size);
			if(s_is_verbose >= 1) {
				(void)SSL_inspection_hexdump("      [D] ", (const void *)(&s_plaintext0[0]), (size_t)s_process_size);
			}
			(void)SSL_inspection_fprintf(
				stdout,
				"    - verify cipher-text : %s\n",
				(memcmp(
					(const void *)(&s_plaintext0[0]),
					(const void *)(&cg_plaintext0[0]),
					sizeof(cg_plaintext0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
			);
		}
	}

	return(0);
}

int SSL_inspection_evp_test1(int s_is_verbose)
{
	static const unsigned char cg_key0[] = {
		0xB0, 0xA5, 0xD5, 0x3B, 0x85, 0xD5, 0x40, 0x91, 0x62, 0x7D, 0x15, 0x39, 0x7A, 0x16, 0x77, 0xA9
	};
	static const unsigned char cg_plaintext0[] = {
		0x47, 0x45, 0x54, 0x20, 0x2F, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x0D, 0x0A,
		0x48, 0x6F, 0x73, 0x74, 0x3A, 0x20, 0x64, 0x65, 0x76, 0x2E, 0x6D, 0x69, 0x6E, 0x7A, 0x6B, 0x6E,
		0x2E, 0x63, 0x6F, 0x6D, 0x3A, 0x38, 0x30, 0x0D, 0x0A, 0x55, 0x73, 0x65, 0x72, 0x2D, 0x41, 0x67,
		0x65, 0x6E, 0x74, 0x3A, 0x20, 0x63, 0x75, 0x72, 0x6C, 0x2F, 0x37, 0x2E, 0x35, 0x38, 0x2E, 0x30,
		0x0D, 0x0A, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3A, 0x20, 0x2A, 0x2F, 0x2A, 0x0D, 0x0A, 0x0D,
		0x0A
	};
	static const unsigned char cg_salt0[] = { /* Fixed */
		0x09, 0x4A, 0x8A, 0xD4 /* SALT */
	};
	static const unsigned char cg_iv0[] = {
		0xF4, 0xFB, 0x79, 0x4B, 0x2C, 0x5D, 0xA1, 0x9D /* IV */
	};
	static const unsigned char cg_icv0[] = { /* integrity check value (ICV) */
		0xDF, 0xDF, 0xB0, 0x06, 0x71, 0x4C, 0x0A ,0x50, 0xD0, 0x4F, 0xC8, 0x7E, 0x53, 0x2A, 0x84, 0x32
	};
	static const unsigned char cg_ciphertext_combines0[] = {
		/* AAD */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* sequence-number */
		0x17, /* record-type (application-data) */
		0x03, 0x03, /* TLS version 1.2 */
		0x00, sizeof(cg_plaintext0) + sizeof(cg_iv0) + sizeof(cg_icv0), /* length 105 bytes */

		/* cipher-text */
		0x73, 0xF5, 0x48, 0xDF, 0x87, 0xAC, 0x4C, 0x51, 0xF2, 0xAD, 0x46, 0xF0, 0x29, 0xF6, 0xCF, 0xD8,
		0x73, 0x2C, 0x3E, 0x64, 0x47, 0x8D, 0x08, 0x5E, 0xF9, 0x6E, 0xC3, 0x9E, 0x49, 0xD2, 0xA7, 0xCD,
		0xC1, 0x92, 0x4A, 0xE2, 0xD1, 0xD3, 0x40, 0xDA, 0xC3, 0xC3, 0x45, 0xCD, 0x53, 0x50, 0x31, 0xFC,
		0xF0, 0x45, 0xB6, 0x88, 0x7D, 0x92, 0x57, 0x4D, 0xF6, 0xEA, 0xA3, 0x23, 0xD3, 0x0B, 0x0D, 0x92,
		0x0C, 0x30, 0x83, 0xE1, 0x47, 0xD3, 0xE3, 0x77, 0xF6, 0x00, 0xE1, 0x4E, 0xE6, 0x53, 0x18, 0xD7,
		0x59,

		/* TAG */
		0xDF, 0xDF, 0xB0, 0x06, 0x71, 0x4C, 0x0A ,0x50, 0xD0, 0x4F, 0xC8, 0x7E, 0x53, 0x2A, 0x84, 0x32

		/* NO-MAC */
	};

	unsigned char s_salt_iv0[ sizeof(cg_salt0) + sizeof(cg_iv0) ] = {0, };
	unsigned char s_aad0[ 8 + 1 + 2 + 2 ] = {0, }; 
	unsigned char s_ciphertext0[ sizeof(cg_plaintext0) ] = {0, };
	unsigned char s_tag0[ 128 >> 3 ] = {0, };
	unsigned char s_plaintext0[ sizeof(cg_plaintext0) ] = {0, };

	const EVP_CIPHER *c_cipher;

	ssize_t s_process_size;

	(void)SSL_inspection_fprintf(stdout, "* TEST TLSv1.2 record (Cipher-suite is AES128-GCM-SHA256)\n");

#if 1L
	c_cipher = EVP_get_cipherbyname("aes-128-gcm");
#else
	c_cipher = EVP_aes_128_gcm();
#endif

	(void)memcpy((void *)(&s_salt_iv0[0]), (const void *)(&cg_salt0[0]), sizeof(cg_salt0));
	(void)memcpy((void *)(&s_salt_iv0[sizeof(cg_salt0)]), (const void *)(&cg_iv0[0]), sizeof(cg_iv0));
	/* record-sequence number */
	s_aad0[0] = (unsigned char)0x00;
	s_aad0[1] = (unsigned char)0x00;
	s_aad0[2] = (unsigned char)0x00;
	s_aad0[3] = (unsigned char)0x00;
	s_aad0[4] = (unsigned char)0x00;
	s_aad0[5] = (unsigned char)0x00;
	s_aad0[6] = (unsigned char)0x00;
	s_aad0[7] = (unsigned char)0x01;
	/* record-type */
	s_aad0[8] = (unsigned char)0x17;
	/* TLS version */
	s_aad0[9] = (unsigned char)0x03;
	s_aad0[10] = (unsigned char)0x03;
	/* record-length */
	s_aad0[11] = (unsigned char)(sizeof(cg_plaintext0) >> 8);
	s_aad0[12] = (unsigned char)(sizeof(cg_plaintext0) & ((size_t)0xffu));

	if(s_is_verbose >= 1) {
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Key (%lu bytes)\n", (unsigned long)sizeof(cg_key0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_key0[0]), sizeof(cg_key0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Plain-Text (%lu bytes)\n", (unsigned long)sizeof(cg_plaintext0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_plaintext0[0]), sizeof(cg_plaintext0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Additional-Authenticated-Data (%lu bytes)\n", (unsigned long)sizeof(s_aad0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&s_aad0[0]), sizeof(s_aad0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Salt (%lu bytes)\n", (unsigned long)sizeof(cg_salt0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_salt0[0]), sizeof(cg_salt0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Initial-Vector (%lu bytes)\n", (unsigned long)sizeof(cg_iv0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_iv0[0]), sizeof(cg_iv0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Salt+IV (%lu bytes)\n", (unsigned long)sizeof(s_salt_iv0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&s_salt_iv0[0]), sizeof(s_salt_iv0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Integrity-Check-Value (%lu bytes)\n", (unsigned long)sizeof(cg_icv0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_icv0[0]), sizeof(cg_icv0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Cipher-Text-Combines (%lu bytes)\n", (unsigned long)sizeof(cg_ciphertext_combines0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_ciphertext_combines0[0]), sizeof(cg_ciphertext_combines0));
	}

	(void)SSL_inspection_fprintf(stdout, "  - Encrypt\n");
	s_process_size = SSL_inspection_encrypt_AES_GCM(
		c_cipher,
		(const void *)(&cg_plaintext0[0]),
		sizeof(cg_plaintext0),
		(const void *)(&s_aad0[0]),
		sizeof(s_aad0),
		(const void *)(&cg_key0[0]),
		(const void *)(&s_salt_iv0[0]),
		sizeof(s_salt_iv0),
		(void *)(&s_ciphertext0[0]),
		(void *)(&s_tag0[0])
	);
	if(s_process_size == ((ssize_t)(-1))) {
		(void)SSL_inspection_fprintf(stderr, def_hwport_color_red "SSL_inspection_encrypt_AES_GCM failed !" def_hwport_color_normal "\n");
	}
	else {
		(void)SSL_inspection_fprintf(stdout, "    - encrypted size : %ld\n", (long)s_process_size);

		/* TLS record length update */
		s_aad0[11] = (unsigned char)((sizeof(cg_plaintext0) + sizeof(cg_iv0) + sizeof(cg_icv0)) >> 8);
		s_aad0[12] = (unsigned char)((sizeof(cg_plaintext0) + sizeof(cg_iv0) + sizeof(cg_icv0)) & ((size_t)0xffu));

		if(s_is_verbose >= 1) {
			(void)SSL_inspection_hexdump("      [H] ", (const void *)(&s_aad0[0]), sizeof(s_aad0));
			(void)SSL_inspection_hexdump("      [I] ", (const void *)(&cg_iv0[0]), sizeof(cg_iv0));
			(void)SSL_inspection_hexdump("      [E] ", (const void *)(&s_ciphertext0[0]), (size_t)s_process_size);
			(void)SSL_inspection_hexdump("      [T] ", (const void *)(&s_tag0[0]), sizeof(s_tag0));
		}
		(void)SSL_inspection_fprintf(
			stdout,
			"    - verify TLS header : %s\n",
			(memcmp(
				(const void *)(&s_aad0[0]),
				(const void *)(&cg_ciphertext_combines0[0]),
				sizeof(s_aad0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);
		(void)SSL_inspection_fprintf(
			stdout,
			"    - verify cipher-text : %s\n",
			(memcmp(
				(const void *)(&s_ciphertext0[0]),
				(const void *)(&cg_ciphertext_combines0[sizeof(s_aad0)]),
				sizeof(cg_plaintext0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);
		(void)SSL_inspection_fprintf(
			stdout,
			"    - verify tag : %s\n",
			(memcmp(
				(const void *)(&s_tag0[0]),
				(const void *)(&cg_icv0[0]),
				sizeof(cg_icv0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);

		(void)SSL_inspection_fprintf(stdout, "  - Decrypt\n");
		s_aad0[11] = (unsigned char)(sizeof(cg_plaintext0) >> 8);
		s_aad0[12] = (unsigned char)(sizeof(cg_plaintext0) & ((size_t)0xffu));
		s_process_size = SSL_inspection_decrypt_AES_GCM(
			c_cipher,
			(const void *)(&s_ciphertext0[0]),
			sizeof(s_ciphertext0),
			(const void *)(&s_aad0[0]),
			sizeof(s_aad0),
			(const void *)(&s_tag0[0]),
			(const void *)(&cg_key0[0]),
			(const void *)(&s_salt_iv0[0]),
			sizeof(s_salt_iv0),
			(void *)(&s_plaintext0[0])
		);
		if(s_process_size == ((ssize_t)(-1))) {
			(void)SSL_inspection_fprintf(stderr, def_hwport_color_red "SSL_inspection_decrypt_AES_GCM failed !" def_hwport_color_normal "\n");
		}
		else {
			(void)SSL_inspection_fprintf(stdout, "    - decrypted size : %ld\n", (long)s_process_size);
			if(s_is_verbose >= 1) {
				(void)SSL_inspection_hexdump("      [D] ", (const void *)(&s_plaintext0[0]), (size_t)s_process_size);
			}
			(void)SSL_inspection_fprintf(
				stdout,
				"    - verify cipher-text : %s\n",
				(memcmp(
					(const void *)(&s_plaintext0[0]),
					(const void *)(&cg_plaintext0[0]),
					sizeof(cg_plaintext0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
			);
		}
	}

	return(0);
}

int SSL_inspection_internal_impl_test0(int s_is_verbose)
{
	static const unsigned char cg_key0[] = {
		0xB0, 0xA5, 0xD5, 0x3B, 0x85, 0xD5, 0x40, 0x91, 0x62, 0x7D, 0x15, 0x39, 0x7A, 0x16, 0x77, 0xA9
	};
	static const unsigned char cg_plaintext0[] = {
		0x47, 0x45, 0x54, 0x20, 0x2F, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x0D, 0x0A,
		0x48, 0x6F, 0x73, 0x74, 0x3A, 0x20, 0x64, 0x65, 0x76, 0x2E, 0x6D, 0x69, 0x6E, 0x7A, 0x6B, 0x6E,
		0x2E, 0x63, 0x6F, 0x6D, 0x3A, 0x38, 0x30, 0x0D, 0x0A, 0x55, 0x73, 0x65, 0x72, 0x2D, 0x41, 0x67,
		0x65, 0x6E, 0x74, 0x3A, 0x20, 0x63, 0x75, 0x72, 0x6C, 0x2F, 0x37, 0x2E, 0x35, 0x38, 0x2E, 0x30,
		0x0D, 0x0A, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3A, 0x20, 0x2A, 0x2F, 0x2A, 0x0D, 0x0A, 0x0D,
		0x0A
	};
	static const unsigned char cg_salt0[] = { /* Fixed */
		0x09, 0x4A, 0x8A, 0xD4 /* SALT */
	};
	static const unsigned char cg_iv0[] = {
		0xF4, 0xFB, 0x79, 0x4B, 0x2C, 0x5D, 0xA1, 0x9D /* IV */
	};
	static const unsigned char cg_icv0[] = { /* integrity check value (ICV) */
		0xDF, 0xDF, 0xB0, 0x06, 0x71, 0x4C, 0x0A ,0x50, 0xD0, 0x4F, 0xC8, 0x7E, 0x53, 0x2A, 0x84, 0x32
	};
	static const unsigned char cg_ciphertext_combines0[] = {
		/* AAD */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* sequence-number */
		0x17, /* record-type (application-data) */
		0x03, 0x03, /* TLS version 1.2 */
		0x00, sizeof(cg_plaintext0) + sizeof(cg_iv0) + sizeof(cg_icv0), /* length 105 bytes */

		/* cipher-text */
		0x73, 0xF5, 0x48, 0xDF, 0x87, 0xAC, 0x4C, 0x51, 0xF2, 0xAD, 0x46, 0xF0, 0x29, 0xF6, 0xCF, 0xD8,
		0x73, 0x2C, 0x3E, 0x64, 0x47, 0x8D, 0x08, 0x5E, 0xF9, 0x6E, 0xC3, 0x9E, 0x49, 0xD2, 0xA7, 0xCD,
		0xC1, 0x92, 0x4A, 0xE2, 0xD1, 0xD3, 0x40, 0xDA, 0xC3, 0xC3, 0x45, 0xCD, 0x53, 0x50, 0x31, 0xFC,
		0xF0, 0x45, 0xB6, 0x88, 0x7D, 0x92, 0x57, 0x4D, 0xF6, 0xEA, 0xA3, 0x23, 0xD3, 0x0B, 0x0D, 0x92,
		0x0C, 0x30, 0x83, 0xE1, 0x47, 0xD3, 0xE3, 0x77, 0xF6, 0x00, 0xE1, 0x4E, 0xE6, 0x53, 0x18, 0xD7,
		0x59,

		/* TAG */
		0xDF, 0xDF, 0xB0, 0x06, 0x71, 0x4C, 0x0A ,0x50, 0xD0, 0x4F, 0xC8, 0x7E, 0x53, 0x2A, 0x84, 0x32

		/* NO-MAC */
	};

	unsigned char s_salt_iv0[ sizeof(cg_salt0) + sizeof(cg_iv0) ] = {0, };
	unsigned char s_aad0[ 8 + 1 + 2 + 2 ] = {0, }; 
	unsigned char s_ciphertext0[ sizeof(cg_plaintext0) ] = {0, };
	unsigned char s_tag0[ 128 >> 3 ] = {0, };
	unsigned char s_plaintext0[ sizeof(cg_plaintext0) ] = {0, };

	ssize_t s_process_size;

	(void)SSL_inspection_fprintf(stdout, "* TEST TLSv1.2 record (Cipher-suite is AES128-GCM-SHA256) => Using internal impl.\n");

	(void)memcpy((void *)(&s_salt_iv0[0]), (const void *)(&cg_salt0[0]), sizeof(cg_salt0));
	(void)memcpy((void *)(&s_salt_iv0[sizeof(cg_salt0)]), (const void *)(&cg_iv0[0]), sizeof(cg_iv0));
	/* record-sequence number */
	s_aad0[0] = (unsigned char)0x00;
	s_aad0[1] = (unsigned char)0x00;
	s_aad0[2] = (unsigned char)0x00;
	s_aad0[3] = (unsigned char)0x00;
	s_aad0[4] = (unsigned char)0x00;
	s_aad0[5] = (unsigned char)0x00;
	s_aad0[6] = (unsigned char)0x00;
	s_aad0[7] = (unsigned char)0x01;
	/* record-type */
	s_aad0[8] = (unsigned char)0x17;
	/* TLS version */
	s_aad0[9] = (unsigned char)0x03;
	s_aad0[10] = (unsigned char)0x03;
	/* record-length */
	s_aad0[11] = (unsigned char)(sizeof(cg_plaintext0) >> 8);
	s_aad0[12] = (unsigned char)(sizeof(cg_plaintext0) & ((size_t)0xffu));

	if(s_is_verbose >= 1) {
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Key (%lu bytes)\n", (unsigned long)sizeof(cg_key0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_key0[0]), sizeof(cg_key0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Plain-Text (%lu bytes)\n", (unsigned long)sizeof(cg_plaintext0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_plaintext0[0]), sizeof(cg_plaintext0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Additional-Authenticated-Data (%lu bytes)\n", (unsigned long)sizeof(s_aad0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&s_aad0[0]), sizeof(s_aad0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Salt (%lu bytes)\n", (unsigned long)sizeof(cg_salt0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_salt0[0]), sizeof(cg_salt0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Initial-Vector (%lu bytes)\n", (unsigned long)sizeof(cg_iv0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_iv0[0]), sizeof(cg_iv0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Salt+IV (%lu bytes)\n", (unsigned long)sizeof(s_salt_iv0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&s_salt_iv0[0]), sizeof(s_salt_iv0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Integrity-Check-Value (%lu bytes)\n", (unsigned long)sizeof(cg_icv0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_icv0[0]), sizeof(cg_icv0));
		(void)SSL_inspection_fprintf(stdout, "  - TEST-VECTOR:Cipher-Text-Combines (%lu bytes)\n", (unsigned long)sizeof(cg_ciphertext_combines0));
		(void)SSL_inspection_hexdump("    ", (const void *)(&cg_ciphertext_combines0[0]), sizeof(cg_ciphertext_combines0));
	}

	(void)SSL_inspection_fprintf(stdout, "  - Encrypt\n");
	s_process_size = (ssize_t)aes_gcm_ae(
		(const uint8_t *)(&cg_key0[0]),
		sizeof(cg_key0),
		(const uint8_t *)(&s_salt_iv0[0]),
		sizeof(s_salt_iv0),
		(const uint8_t *)(&cg_plaintext0[0]),
		sizeof(cg_plaintext0),
		(const uint8_t *)(&s_aad0[0]),
		sizeof(s_aad0),
		(uint8_t *)(&s_ciphertext0[0]),
		(uint8_t *)(&s_tag0[0])
	);
	if(s_process_size == ((ssize_t)(-1))) {
		(void)SSL_inspection_fprintf(stderr, def_hwport_color_red "SSL_inspection_encrypt_AES_GCM failed !" def_hwport_color_normal "\n");
	}
	else {
		s_process_size = (ssize_t)sizeof(cg_plaintext0);

		(void)SSL_inspection_fprintf(stdout, "    - encrypted size : %ld\n", (long)s_process_size);

		/* TLS record length update */
		s_aad0[11] = (unsigned char)((sizeof(cg_plaintext0) + sizeof(cg_iv0) + sizeof(cg_icv0)) >> 8);
		s_aad0[12] = (unsigned char)((sizeof(cg_plaintext0) + sizeof(cg_iv0) + sizeof(cg_icv0)) & ((size_t)0xffu));

		if(s_is_verbose >= 1) {
			(void)SSL_inspection_hexdump("      [H] ", (const void *)(&s_aad0[0]), sizeof(s_aad0));
			(void)SSL_inspection_hexdump("      [I] ", (const void *)(&cg_iv0[0]), sizeof(cg_iv0));
			(void)SSL_inspection_hexdump("      [E] ", (const void *)(&s_ciphertext0[0]), (size_t)s_process_size);
			(void)SSL_inspection_hexdump("      [T] ", (const void *)(&s_tag0[0]), sizeof(s_tag0));
		}
		(void)SSL_inspection_fprintf(
			stdout,
			"    - verify TLS header : %s\n",
			(memcmp(
				(const void *)(&s_aad0[0]),
				(const void *)(&cg_ciphertext_combines0[0]),
				sizeof(s_aad0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);
		(void)SSL_inspection_fprintf(
			stdout,
			"    - verify cipher-text : %s\n",
			(memcmp(
				(const void *)(&s_ciphertext0[0]),
				(const void *)(&cg_ciphertext_combines0[sizeof(s_aad0)]),
				sizeof(cg_plaintext0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);
		(void)SSL_inspection_fprintf(
			stdout,
			"    - verify tag : %s\n",
			(memcmp(
				(const void *)(&s_tag0[0]),
				(const void *)(&cg_icv0[0]),
				sizeof(cg_icv0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
		);

		(void)SSL_inspection_fprintf(stdout, "  - Decrypt\n");
		s_aad0[11] = (unsigned char)(sizeof(cg_plaintext0) >> 8);
		s_aad0[12] = (unsigned char)(sizeof(cg_plaintext0) & ((size_t)0xffu));
		s_process_size = (ssize_t)aes_gcm_ad(
			(const uint8_t *)(&cg_key0[0]),
			sizeof(cg_key0),
			(const uint8_t *)(&s_salt_iv0[0]),
			sizeof(s_salt_iv0),
			(const uint8_t *)(&s_ciphertext0[0]),
			sizeof(s_ciphertext0),
			(const uint8_t *)(&s_aad0[0]),
			sizeof(s_aad0),
			(const uint8_t *)(&s_tag0[0]),
			(uint8_t *)(&s_plaintext0[0])
		);
		if(s_process_size == ((ssize_t)(-1))) {
			(void)SSL_inspection_fprintf(stderr, def_hwport_color_red "SSL_inspection_decrypt_AES_GCM failed !" def_hwport_color_normal "\n");
		}
		else {
			s_process_size = (ssize_t)sizeof(s_ciphertext0);

			(void)SSL_inspection_fprintf(stdout, "    - decrypted size : %ld\n", (long)s_process_size);
			if(s_is_verbose >= 1) {
				(void)SSL_inspection_hexdump("      [D] ", (const void *)(&s_plaintext0[0]), (size_t)s_process_size);
			}
			(void)SSL_inspection_fprintf(
				stdout,
				"    - verify cipher-text : %s\n",
				(memcmp(
					(const void *)(&s_plaintext0[0]),
					(const void *)(&cg_plaintext0[0]),
					sizeof(cg_plaintext0)) == 0) ? def_hwport_color_blue "PASSED" def_hwport_color_normal : def_hwport_color_red "FAILED" def_hwport_color_normal
			);
		}
	}

	return(0);
}

#endif

/* ---- */

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
