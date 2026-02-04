/*
    Copyright (C) MINZKN.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_sha256_c__)
# define __def_sslid_source_sha256_c__ "sha256.c"

/* ---- */

#include "sslid-lib.h"

/* ---- */

#define __hwport_sha256_rotate_right(m_x,m_n) (((m_x) >> (m_n)) | ((m_x) << (32 - (m_n))))

#define __hwport_sha256_Ch(m_x,m_y,m_z) ((m_z) ^ ((m_x) & ((m_y) ^ (m_z))))
#define __hwport_sha256_Maj(m_x,m_y,m_z) (((m_x) & ((m_y) | (m_z))) | ((m_y) & (m_z)))

#define __hwport_sha256_SIGMA0(m_x) (__hwport_sha256_rotate_right((m_x),2) ^ __hwport_sha256_rotate_right((m_x),13) ^ __hwport_sha256_rotate_right((m_x),22))
#define __hwport_sha256_SIGMA1(m_x) (__hwport_sha256_rotate_right((m_x),6) ^ __hwport_sha256_rotate_right((m_x),11) ^ __hwport_sha256_rotate_right((m_x),25))
#define __hwport_sha256_sigma0(m_x) (__hwport_sha256_rotate_right((m_x),7) ^ __hwport_sha256_rotate_right((m_x),18) ^ ((m_x) >> 3))
#define __hwport_sha256_sigma1(m_x) (__hwport_sha256_rotate_right((m_x),17) ^ __hwport_sha256_rotate_right((m_x),19) ^ ((m_x) >> 10))

/* ---- */

hwport_sha256_t *hwport_init_sha256(hwport_sha256_t *s_sha256);

static void hwport_sha256_burn_stack(size_t s_size);
static void hwport_sha256_process(hwport_sha256_t *s_sha256, const uint32_t *s_cbuffer);

const void *hwport_sha256_push(hwport_sha256_t *s_sha256, const void *s_data, size_t s_size);
void *hwport_sha256_digest(hwport_sha256_t *s_sha256, void *s_digest);
void *hwport_sha256_simple(const void *s_data, size_t s_size, void *s_digest);

hwport_sha256_t *hwport_init_hmac_sha256(hwport_sha256_t *s_sha256, const void *s_key, size_t s_key_size);
void *hwport_hmac_sha256_digest(hwport_sha256_t *s_sha256, void *s_digest);
void *hwport_hmac_sha256_simple(const void *s_key, size_t s_key_size, const void *s_data, size_t s_size, void *s_digest);

void *hwport_pseudo_random_function_tlsv1_2_sha256(const void *s_secret, size_t s_secret_size, const void *s_label, size_t s_label_size, const void *s_seed, size_t s_seed_size, void *s_output, size_t s_output_size);

/* ---- */

hwport_sha256_t *hwport_init_sha256(hwport_sha256_t *s_sha256)
{
    static const uint32_t sg_sha256_hash_init_table[ def_hwport_sha256_hash_words ] = {
        (uint32_t)0x6a09e667u, (uint32_t)0xbb67ae85u,
        (uint32_t)0x3c6ef372u, (uint32_t)0xa54ff53au,
        (uint32_t)0x510e527fu, (uint32_t)0x9b05688cu,
        (uint32_t)0x1f83d9abu, (uint32_t)0x5be0cd19u
    };

    s_sha256->m_total_size = (unsigned long long)0u;
    (void)memcpy((void *)(&s_sha256->m_hash[0]), (const void *)(&sg_sha256_hash_init_table[0]), sizeof(sg_sha256_hash_init_table));
    s_sha256->m_buffer_size = (size_t)0u;

    return(s_sha256);
}

static void hwport_sha256_burn_stack(size_t s_size)
{
    uint8_t s_buffer[128];

    /* Use secure memory clearing to prevent compiler optimization */
    SSL_inspection_secure_memzero(&s_buffer[0], sizeof(s_buffer));
    if (s_size > sizeof(s_buffer)) {
        hwport_sha256_burn_stack(s_size - sizeof(s_buffer));
    }
}

static void hwport_sha256_process(hwport_sha256_t *s_sha256, const uint32_t *s_cbuffer)
{
    static const uint32_t sg_sha256_K[64] = {
        (uint32_t)0x428a2f98u, (uint32_t)0x71374491u, (uint32_t)0xb5c0fbcfu, (uint32_t)0xe9b5dba5u,
        (uint32_t)0x3956c25bu, (uint32_t)0x59f111f1u, (uint32_t)0x923f82a4u, (uint32_t)0xab1c5ed5u,
        (uint32_t)0xd807aa98u, (uint32_t)0x12835b01u, (uint32_t)0x243185beu, (uint32_t)0x550c7dc3u,
        (uint32_t)0x72be5d74u, (uint32_t)0x80deb1feu, (uint32_t)0x9bdc06a7u, (uint32_t)0xc19bf174u,
        (uint32_t)0xe49b69c1u, (uint32_t)0xefbe4786u, (uint32_t)0x0fc19dc6u, (uint32_t)0x240ca1ccu,
        (uint32_t)0x2de92c6fu, (uint32_t)0x4a7484aau, (uint32_t)0x5cb0a9dcu, (uint32_t)0x76f988dau,
        (uint32_t)0x983e5152u, (uint32_t)0xa831c66du, (uint32_t)0xb00327c8u, (uint32_t)0xbf597fc7u,
        (uint32_t)0xc6e00bf3u, (uint32_t)0xd5a79147u, (uint32_t)0x06ca6351u, (uint32_t)0x14292967u,
        (uint32_t)0x27b70a85u, (uint32_t)0x2e1b2138u, (uint32_t)0x4d2c6dfcu, (uint32_t)0x53380d13u,
        (uint32_t)0x650a7354u, (uint32_t)0x766a0abbu, (uint32_t)0x81c2c92eu, (uint32_t)0x92722c85u,
        (uint32_t)0xa2bfe8a1u, (uint32_t)0xa81a664bu, (uint32_t)0xc24b8b70u, (uint32_t)0xc76c51a3u,
        (uint32_t)0xd192e819u, (uint32_t)0xd6990624u, (uint32_t)0xf40e3585u, (uint32_t)0x106aa070u,
        (uint32_t)0x19a4c116u, (uint32_t)0x1e376c08u, (uint32_t)0x2748774cu, (uint32_t)0x34b0bcb5u,
        (uint32_t)0x391c0cb3u, (uint32_t)0x4ed8aa4au, (uint32_t)0x5b9cca4fu, (uint32_t)0x682e6ff3u,
        (uint32_t)0x748f82eeu, (uint32_t)0x78a5636fu, (uint32_t)0x84c87814u, (uint32_t)0x8cc70208u,
        (uint32_t)0x90befffau, (uint32_t)0xa4506cebu, (uint32_t)0xbef9a3f7u, (uint32_t)0xc67178f2u
    };

    uint32_t s_buffer[64];

    uint32_t *s_word;
    uint32_t *s_word2;
    uint32_t *s_word7;
    uint32_t *s_word15;
    uint32_t *s_word16;

    uint32_t s_a;
    uint32_t s_b;
    uint32_t s_c;
    uint32_t s_d;
    uint32_t s_e;
    uint32_t s_f;
    uint32_t s_g;
    uint32_t s_h;

    uint32_t s_temp1;
    uint32_t s_temp2;

    const uint32_t *s_K_ptr;

    int s_count;

    s_word = s_buffer;

    for(s_count = 0;s_count < 16;s_count++) {
        s_word[0] = be32toh(s_cbuffer[0]);
        s_word = (uint32_t *)(&s_word[1]);
        s_cbuffer = (const uint32_t *)(&s_cbuffer[1]);
    }

    s_word16 = &s_buffer[0];
    s_word15 = &s_buffer[1];
    s_word7 = &s_buffer[9];
    s_word2 = &s_buffer[14];

    for(s_count = 0;s_count < 48;s_count++) {
        s_word[0] = __hwport_sha256_sigma1(s_word2[0]) + s_word7[0] + __hwport_sha256_sigma0(s_word15[0]) + s_word16[0];
        s_word = (uint32_t *)(&s_word[1]);
        s_word2 = (uint32_t *)(&s_word2[1]);
        s_word7 = (uint32_t *)(&s_word7[1]);
        s_word15 = (uint32_t *)(&s_word15[1]);
        s_word16 = (uint32_t *)(&s_word16[1]);
    }

    s_a = s_sha256->m_hash[0];
    s_b = s_sha256->m_hash[1];
    s_c = s_sha256->m_hash[2];
    s_d = s_sha256->m_hash[3];
    s_e = s_sha256->m_hash[4];
    s_f = s_sha256->m_hash[5];
    s_g = s_sha256->m_hash[6];
    s_h = s_sha256->m_hash[7];

    s_K_ptr = sg_sha256_K;
    s_word = s_buffer;

    /* round */
    for(s_count = 0;s_count < def_hwport_sha256_round;s_count++) {
        s_temp1 = s_h + __hwport_sha256_SIGMA1(s_e) + __hwport_sha256_Ch(s_e, s_f, s_g) + s_K_ptr[0] + s_word[0];
        s_K_ptr = (const uint32_t *)(&s_K_ptr[1]);
        s_word = (uint32_t *)(&s_word[1]);
        s_temp2 = __hwport_sha256_SIGMA0(s_a) + __hwport_sha256_Maj(s_a, s_b, s_c);
        s_h = s_g;
        s_g = s_f;
        s_f = s_e;
        s_e = s_d + s_temp1;
        s_d = s_c;
        s_c = s_b;
        s_b = s_a;
        s_a = s_temp1 + s_temp2;
    }

    s_sha256->m_hash[0] += s_a;
    s_sha256->m_hash[1] += s_b;
    s_sha256->m_hash[2] += s_c;
    s_sha256->m_hash[3] += s_d;
    s_sha256->m_hash[4] += s_e;
    s_sha256->m_hash[5] += s_f;
    s_sha256->m_hash[6] += s_g;
    s_sha256->m_hash[7] += s_h;
}

const void *hwport_sha256_push(hwport_sha256_t *s_sha256, const void *s_data, size_t s_size)
{
    size_t s_remain_size;
    int s_need_burn_stack;

    s_need_burn_stack = 0;

    if(s_sha256->m_buffer_size > ((size_t)0u)) {
        s_remain_size = ((size_t)64u) - s_sha256->m_buffer_size;
        if(s_remain_size > s_size) {
            s_remain_size = s_size;
        }
        (void)memcpy((void *)(((uint8_t *)s_sha256->m_buffer) + s_sha256->m_buffer_size), s_data, s_remain_size);
        s_sha256->m_total_size += (unsigned long long)(s_remain_size << 3);
        s_sha256->m_buffer_size += s_remain_size;
        s_data = (const void *)(((const uint8_t *)s_data) + s_remain_size);
        s_size -= s_remain_size;
        if (s_sha256->m_buffer_size == ((size_t)64u)) 
        {
            hwport_sha256_process(s_sha256, (const uint32_t *)(&s_sha256->m_buffer[0]));
            s_need_burn_stack = 1;
            s_sha256->m_buffer_size = (size_t)0u;
        }
    }

    while(s_size >= ((size_t)64u)) {
        s_sha256->m_total_size += (unsigned long long)512u;

        hwport_sha256_process(s_sha256, (const uint32_t *)s_data);
        s_need_burn_stack = 1;

        s_data = (const void *)(((const uint8_t *)s_data) + 64);
        s_size -= (size_t)64u;
    }

    if(s_size > ((size_t)0u)) {
        (void)memcpy((void *)(((uint8_t *)s_sha256->m_buffer) + s_sha256->m_buffer_size), s_data, s_size);
        s_sha256->m_total_size += (unsigned long long)(s_size << 3);
        s_sha256->m_buffer_size += s_size;
    }

    if(s_need_burn_stack != 0) {
        hwport_sha256_burn_stack((sizeof(uint32_t) * ((size_t)74u)) + (sizeof(uint32_t *) * ((size_t)6u)) +  sizeof(int));
    }
    
    return(s_data);
}

void *hwport_sha256_digest(hwport_sha256_t *s_sha256, void *s_digest)
{
    static const uint8_t sg_sha256_padding[64] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    size_t s_padd_size;
    uint64_t s_length_pad;
    size_t s_count;

    s_padd_size = ((size_t)120u) - s_sha256->m_buffer_size;
    if(s_padd_size > ((size_t)64u)) {
        s_padd_size -= (size_t)64u;
    }

    s_length_pad = htobe64((uint64_t)s_sha256->m_total_size);

    (void)hwport_sha256_push(s_sha256, (const void *)(&sg_sha256_padding[0]), s_padd_size);
    (void)hwport_sha256_push(s_sha256, (const void *)(&s_length_pad), sizeof(uint64_t));

    if(s_digest == ((void *)(NULL))) {
        return((void *)(NULL));
    }
        
    /* get digest */
    for(s_count = (size_t)0u;s_count < ((size_t)def_hwport_sha256_hash_words);s_count++) {
		*((uint32_t *)(((uint8_t *)s_digest) + (s_count * sizeof(uint32_t)))) = be32toh(s_sha256->m_hash[s_count]);
    }

    return(s_digest);
}

void *hwport_sha256_simple(const void *s_data, size_t s_size, void *s_digest)
{
	hwport_sha256_t s_sha256_local;

	(void)hwport_sha256_push(
		hwport_init_sha256(
			(hwport_sha256_t *)(&s_sha256_local)
		),
		s_data,
		s_size
	);

	(void)hwport_sha256_digest((hwport_sha256_t *)(&s_sha256_local), s_digest);
	
	/* memwipe */
	(void)memset((void *)(&s_sha256_local), 0, sizeof(s_sha256_local));

	return(s_digest);
}

hwport_sha256_t *hwport_init_hmac_sha256(hwport_sha256_t *s_sha256, const void *s_key, size_t s_key_size)
{
	size_t s_offset;

	s_sha256 = hwport_init_sha256(s_sha256);

	/* copy key */
	s_sha256->m_key_size = s_key_size;
	if(s_sha256->m_key_size > sizeof(s_sha256->m_key)) {
		hwport_sha256_simple(s_key, s_key_size, (void *)(&s_sha256->m_key[0]));
		s_sha256->m_key_size = (size_t)def_hwport_sha256_digest_size;
	}
	else {
		(void)memcpy((void *)(&s_sha256->m_key[0]), s_key, s_key_size);
	}
	if(s_sha256->m_key_size < sizeof(s_sha256->m_key)) {
		(void)memset((void *)(&s_sha256->m_key[s_sha256->m_key_size]), 0, sizeof(s_sha256->m_key) - s_sha256->m_key_size);
	}

	/* ipad */
	for(s_offset = (size_t)0u;s_offset < sizeof(s_sha256->m_key);s_offset++) {
		s_sha256->m_key_pad[s_offset] = s_sha256->m_key[s_offset] ^ ((uint8_t)0x36);
	}

	(void)hwport_sha256_push(s_sha256, (const void *)(&s_sha256->m_key_pad[0]), sizeof(s_sha256->m_key_pad));

	return(s_sha256);
}

void *hwport_hmac_sha256_digest(hwport_sha256_t *s_sha256, void *s_digest)
{
	size_t s_offset;
	
	/* opad */
	for(s_offset = (size_t)0u;s_offset < sizeof(s_sha256->m_key);s_offset++) {
		s_sha256->m_key_pad[s_offset] = s_sha256->m_key[s_offset] ^ ((uint8_t)0x5c);
	}

	/* perform inner SHA256 to temp store */
	s_sha256->m_key_size = (size_t)def_hwport_sha256_digest_size;
	(void)hwport_sha256_digest(s_sha256, (void *)(&s_sha256->m_key[0]));

	/* reset context */
	s_sha256 = hwport_init_sha256(s_sha256);

	/* perform outer SHA256 */
	(void)hwport_sha256_push(
		s_sha256,
		(const void *)(&s_sha256->m_key_pad[0]),
		sizeof(s_sha256->m_key_pad)
	);
	(void)memset((void *)(&s_sha256->m_key_pad[0]), 0, sizeof(s_sha256->m_key_pad));

	(void)hwport_sha256_push(
		s_sha256,
		(const void *)(&s_sha256->m_key[0]),
		s_sha256->m_key_size
	);
	(void)memset((void *)(&s_sha256->m_key[0]), 0, sizeof(s_sha256->m_key));

	return(hwport_sha256_digest(s_sha256, s_digest));
}

void *hwport_hmac_sha256_simple(const void *s_key, size_t s_key_size, const void *s_data, size_t s_size, void *s_digest)
{
	hwport_sha256_t s_sha256_local;

	(void)hwport_sha256_push(
		hwport_init_hmac_sha256(
			(hwport_sha256_t *)(&s_sha256_local),
			s_key,
			s_key_size
		),
		s_data,
		s_size
	);

	(void)hwport_hmac_sha256_digest((hwport_sha256_t *)(&s_sha256_local), s_digest);
	
	/* memwipe */
	(void)memset((void *)(&s_sha256_local), 0, sizeof(s_sha256_local));

	return(s_digest);
}

void *hwport_pseudo_random_function_tlsv1_2_sha256(const void *s_secret, size_t s_secret_size, const void *s_label, size_t s_label_size, const void *s_seed, size_t s_seed_size, void *s_output, size_t s_output_size)
{
	/*
		in RFC5246 : The Transport Layer Security (TLS) Protocol Version 1.2

		----

		PRF(secret, label, seed) = P_<hash>(secret, label + seed)

		P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
								HMAC_hash(secret, A(2) + seed) +
								HMAC_hash(secret, A(3) + seed) + ...

		A(0) = seed
		A(i) = HMAC_hash(secret, A(i-1))

		----

		Master-Secret[0..47]: pre-master-secret, label="master secret", client-random + server-random

		Key-Block : master-secret, label="key expansion", server-random + client-random
			client write MAC key
			server write MAC key
			client write encryption key
			server write encryption key
			client write IV
			server write IV
	*/
#if 1L /* by my implementation */
	hwport_sha256_t s_sha256_local;
	hwport_sha256_t *s_sha256;

	uint8_t s_digest_local_A[ def_hwport_sha256_digest_size ];
	uint8_t s_digest_local_P[ def_hwport_sha256_digest_size ];

	size_t s_offset;
	size_t s_copy_size;

	s_sha256 = hwport_init_hmac_sha256((hwport_sha256_t *)(&s_sha256_local), s_secret, s_secret_size);
	(void)hwport_sha256_push(s_sha256, s_label, s_label_size);
	(void)hwport_sha256_push(s_sha256, s_seed, s_seed_size);
	(void)hwport_hmac_sha256_digest(s_sha256, (void *)(&s_digest_local_A[0]));

	for(s_offset = (size_t)0u;s_offset < s_output_size;) {
		s_sha256 = hwport_init_hmac_sha256((hwport_sha256_t *)(&s_sha256_local), s_secret, s_secret_size);
		
		(void)hwport_sha256_push(s_sha256, (const void *)(&s_digest_local_A), sizeof(s_digest_local_A));
		(void)hwport_sha256_push(s_sha256, s_label, s_label_size);
		(void)hwport_sha256_push(s_sha256, s_seed, s_seed_size);

		(void)hwport_hmac_sha256_digest(s_sha256, (void *)(&s_digest_local_P[0]));
		s_copy_size = s_output_size - s_offset;
		if(s_copy_size > sizeof(s_digest_local_P)) {
			s_copy_size = sizeof(s_digest_local_P);
		}
		(void)memcpy((void *)(((uint8_t *)s_output) + s_offset), (const void *)(&s_digest_local_P[0]), s_copy_size);
		s_offset += s_copy_size;
	
#if 0L
		(void)hwport_hmac_sha256_simple(
			s_secret,
			s_secret_size,
			(const void *)(&s_digest_local_A[0]),
			sizeof(s_digest_local_A),
			(void *)(&s_digest_local_A[0])
		);
#else
		s_sha256 = hwport_init_hmac_sha256((hwport_sha256_t *)(&s_sha256_local), s_secret, s_secret_size);
		(void)hwport_sha256_push(s_sha256, (const void *)(&s_digest_local_A[0]), sizeof(s_digest_local_A));
		(void)hwport_hmac_sha256_digest(s_sha256, (void *)(&s_digest_local_A[0]));
#endif
	}

	/* memwipe */
	(void)memset((void *)(&s_digest_local_P[0]), 0, sizeof(s_digest_local_P));
	(void)memset((void *)(&s_digest_local_A[0]), 0, sizeof(s_digest_local_A));
	(void)memset((void *)(&s_sha256_local), 0, sizeof(s_sha256_local));
#else /* by OpenSSL */
	HMAC_CTX *s_hmac_ctx;
	const EVP_MD *c_evp_md;

	uint8_t s_digest_local_A[ def_hwport_sha256_digest_size ];
	uint8_t s_digest_local_P[ def_hwport_sha256_digest_size ];

	size_t s_offset;
	size_t s_copy_size;

	s_hmac_ctx = HMAC_CTX_new();
	c_evp_md = EVP_sha256(); /* == EVP_get_digestbyname("sha256") */

	(void)HMAC_Init_ex(
		s_hmac_ctx,
		(const void *)s_secret,
		(int)s_secret_size,
		c_evp_md,
		(ENGINE *)NULL);
	(void)HMAC_Update(
		s_hmac_ctx,
		(const unsigned char *)s_label,
		s_label_size
		);
	(void)HMAC_Update(
		s_hmac_ctx,
		(const unsigned char *)s_seed,
		s_seed_size
		);
	(void)HMAC_Final(
		s_hmac_ctx,
		(unsigned char *)(&s_digest_local_A[0]),
		(unsigned int *)NULL
		);
	
	for(s_offset = (size_t)0u;s_offset < s_output_size;) {
		(void)HMAC_Init_ex(
			s_hmac_ctx,
			(const void *)s_secret,
			(int)s_secret_size,
			c_evp_md,
			(ENGINE *)NULL);
		(void)HMAC_Update(
			s_hmac_ctx,
			(const unsigned char *)(&s_digest_local_A),
			sizeof(s_digest_local_A)
			);
		(void)HMAC_Update(
			s_hmac_ctx,
			(const unsigned char *)s_label,
			s_label_size
			);
		(void)HMAC_Update(
			s_hmac_ctx,
			(const unsigned char *)s_seed,
			s_seed_size
			);
		(void)HMAC_Final(
			s_hmac_ctx,
			(unsigned char *)(&s_digest_local_P[0]),
			(unsigned int *)NULL
			);

		s_copy_size = s_output_size - s_offset;
		if(s_copy_size > sizeof(s_digest_local_P)) {
			s_copy_size = sizeof(s_digest_local_P);
		}
		(void)memcpy((void *)(((uint8_t *)s_output) + s_offset), (const void *)(&s_digest_local_P[0]), s_copy_size);
		s_offset += s_copy_size;
	
		(void)HMAC_Init_ex(
			s_hmac_ctx,
			(const void *)s_secret,
			(int)s_secret_size,
			c_evp_md,
			(ENGINE *)NULL);
		(void)HMAC_Update(
			s_hmac_ctx,
			(const unsigned char *)(&s_digest_local_A),
			sizeof(s_digest_local_A)
			);
		(void)HMAC_Final(
			s_hmac_ctx,
			(unsigned char *)(&s_digest_local_A[0]),
			(unsigned int *)NULL
			);
	}

	/* memwipe */
	(void)memset((void *)(&s_digest_local_P[0]), 0, sizeof(s_digest_local_P));
	(void)memset((void *)(&s_digest_local_A[0]), 0, sizeof(s_digest_local_A));

	HMAC_CTX_free(s_hmac_ctx);
#endif

	return(s_output);
}

/* ---- */

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
