static void test_crypto_aead_done(struct crypto_async_request *req, int err)
{
	(void)req;
	(void)err;
}

static ssize_t test_crypto_encrypt_AEAD(
	const char *s_alg_name,
	const void *s_plaintext,
	size_t s_plaintext_size,
	const void *s_aad,
	size_t s_aad_size,
	const void *s_key,
	size_t s_key_size,
	const void *s_salt,
	size_t s_salt_size,
	const void *s_iv,
	size_t s_iv_size,
	void *s_ciphertext,
	size_t s_ciphertext_size,
	void *s_tag,
	size_t s_tag_size
)
{
	static const char cg_default_alg_name[] = {"gcm(aes)"};

	ssize_t s_result;

	size_t s_temp_offset;
	uint8_t s_temp_buffer[ 128 ];

	struct crypto_aead *tfm;
	struct aead_request *req;

	struct scatterlist s_sg_plaintext[1] ;
	struct scatterlist s_sg_ciphertext[ 1 /* ciphertext */ + 1 /* tag */ ];
	struct scatterlist s_sg_gmactext[1];

	int s_check;

	if(unlikely(s_alg_name == ((const char *)0))) {
		s_alg_name = (const char *)(&cg_default_alg_name[0]);
	}

	/* struct crypto_aead *crypto_alloc_aead(const char *alg_name, u32 type, u32 mask) */
	tfm = crypto_alloc_aead(s_alg_name, (u32)0u, (u32)0u);
	if(IS_ERR(tfm)) {
		printk(KERN_WARNING "crypto_alloc_aead failed ! (tfm=%p, alg_name=\"%s\")\n", tfm, s_alg_name);
		s_result = (ssize_t)(-1);
		goto l_return0;
	}

#if 0L /* DEBUG : algorithm specification info */
	/* static inline unsigned int crypto_aead_authsize(struct crypto_aead *tfm) */
	printk(KERN_INFO "  - AEAD authsize (%u bytes)\n", crypto_aead_authsize(tfm));
	
	/* static inline unsigned int crypto_aead_ivsize(struct crypto_aead *tfm) */
	printk(KERN_INFO "  - AEAD ivsize (%u bytes)\n", crypto_aead_ivsize(tfm));
	
	/* static inline unsigned int crypto_aead_blocksize(struct crypto_aead *tfm) */
	printk(KERN_INFO "  - AEAD blocksize (%u bytes)\n", crypto_aead_blocksize(tfm));
#endif

	/* static inline struct aead_request *aead_request_alloc(struct crypto_aead *tfm, gfp_t gfp) */
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if(IS_ERR(req)) {
		printk(KERN_WARNING "aead_request_alloc failed ! (req=%p, alg_name=\"%s\")\n", req, s_alg_name);
		s_result = (ssize_t)(-1);
		goto l_return1;
	}

	/* static inline void aead_request_set_callback(struct aead_request *req, u32 flags, crypto_completion_t complete, void *data) */
	aead_request_set_callback(
		req,
		CRYPTO_TFM_REQ_MAY_BACKLOG,
		test_crypto_aead_done,
		(void *)0
	);

	/* static inline void crypto_aead_clear_flags(struct crypto_aead *tfm, u32 flags) */
	crypto_aead_clear_flags(tfm, ~((u32)0u));

	/* static inline int crypto_aead_setkey(struct crypto_aead *tfm, const u8 *key, unsigned int keylen) */
	s_check = crypto_aead_setkey(
		tfm,
		(const u8 *)s_key,
		(unsigned int)s_key_size
	);
	if(unlikely(s_check != 0)) {
		printk(KERN_WARNING "crypto_aead_setkey failed ! (check=%d, alg_name=\"%s\", key-size=%lu)\n", s_check, s_alg_name, (unsigned long)s_key_size);
		s_result = (ssize_t)(-1);
		goto l_return2;
	}

	/* This is the Integrity Check Value (aka the authentication tag length and can be 8, 12 or 16 bytes long. */
	/* Assuming we are supporting rfc4106 64-bit extended sequence numbers We need to have the AAD length equal to 8 or 12 bytes */
	/* int crypto_aead_setauthsize(struct crypto_aead *tfm, unsigned int authsize); */
	s_check = crypto_aead_setauthsize(tfm, (unsigned int)s_tag_size);
	if(unlikely(s_check != 0)) {
		printk(KERN_WARNING "crypto_aead_setauthsize failed ! (check=%d, alg_name=\"%s\", tag-size=%lu)\n", s_check, s_alg_name, (unsigned long)s_tag_size);
		s_result = (ssize_t)(-1);
		goto l_return2;
	}

	/* plaintext to scatterlist */
	sg_init_table(&s_sg_plaintext[0], sizeof(s_sg_plaintext) / sizeof(struct scatterlist));
	sg_set_buf(&s_sg_plaintext[0], s_plaintext, s_plaintext_size); /* IN: plaintext */
	/* ciphertext to scatterlist */
	sg_init_table(&s_sg_ciphertext[0], sizeof(s_sg_ciphertext) / sizeof(struct scatterlist));
	sg_set_buf(&s_sg_ciphertext[0], s_ciphertext, s_ciphertext_size); /* OUT: ciphertext */
	sg_set_buf(&s_sg_ciphertext[1], s_tag, s_tag_size); /* OUT: tag */
	s_temp_offset = (size_t)0u;
	(void)memcpy((void *)(&s_temp_buffer[s_temp_offset]), s_salt, s_salt_size);
	s_temp_offset += s_salt_size;
	(void)memcpy((void *)(&s_temp_buffer[s_temp_offset]), s_iv, s_iv_size);
	s_temp_offset += s_iv_size;
	/* static inline void aead_request_set_crypt(struct aead_request *req, struct scatterlist *src, struct scatterlist *dst, unsigned int cryptlen, u8 *iv) */
	aead_request_set_crypt(
		req,
		(struct scatterlist *)(&s_sg_plaintext[0]),
		(struct scatterlist *)(&s_sg_ciphertext[0]),
		(unsigned int)s_plaintext_size,
		(u8 *)(&s_temp_buffer[0])
	);
	
	sg_init_one(&s_sg_gmactext[0], s_aad, s_aad_size);
	/* static inline void aead_request_set_assoc(struct aead_request *req, struct scatterlist *assoc, unsigned int assoclen) */
	aead_request_set_assoc(
		req,
		(struct scatterlist *)(&s_sg_gmactext[0]),
		(unsigned int)s_aad_size
	);

	/* static inline int crypto_aead_encrypt(struct aead_request *req) */
	s_check = crypto_aead_encrypt(req);
	if(unlikely(s_check != 0)) {
		printk(KERN_WARNING "crypto_aead_encrypt failed ! (check=%d, alg_name=\"%s\")\n", s_check, s_alg_name);
		s_result = (ssize_t)(-1);
		goto l_return2;
	}

	/* SUCCESS */
	s_result = (ssize_t)s_ciphertext_size;

l_return2:;
	/* static inline void aead_request_free(struct aead_request *req) */
	aead_request_free(req);
	
l_return1:;
	/* static inline void crypto_free_aead(struct crypto_aead *tfm) */
	crypto_free_aead(tfm);

l_return0:;
	return(s_result);
}

static int test_crypto_tlsv1_2_AES128_GCM_SHA256_encrypt(void)
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

	unsigned char s_aad0[ 8 + 1 + 2 + 2 ] = {0, }; 
	unsigned char s_ciphertext0[ sizeof(cg_plaintext0) ] = {0, };
	unsigned char s_tag0[ 128 >> 3 ] = {0, };

	ssize_t s_process_size;
	
	(void)printk(KERN_INFO "* TEST TLSv1.2 record (Cipher-suite is AES128-GCM-SHA256)\n");

	/* record-sequence number */
	s_aad0[0] = (uint8_t)0x00u;
	s_aad0[1] = (uint8_t)0x00u;
	s_aad0[2] = (uint8_t)0x00u;
	s_aad0[3] = (uint8_t)0x00u;
	s_aad0[4] = (uint8_t)0x00u;
	s_aad0[5] = (uint8_t)0x00u;
	s_aad0[6] = (uint8_t)0x00u;
	s_aad0[7] = (uint8_t)0x01u;
	/* record type */
	*((uint8_t *)(&s_aad0[8])) = (uint8_t)0x17;
	/* record version */
	*((uint16_t *)(&s_aad0[9])) = htons(0x0303);
	/* record length */
	*((uint16_t *)(&s_aad0[11])) = htons(sizeof(cg_plaintext0));

	(void)printk(KERN_INFO "  - TEST-VECTOR:Key (%lu bytes)\n", (unsigned long)sizeof(cg_key0));
	print_hex_dump(
		KERN_INFO,
		"    ",
		DUMP_PREFIX_OFFSET,
		16,
		1,
		(const void *)(&cg_key0[0]),
		sizeof(cg_key0),
		true
	);
	(void)printk(KERN_INFO "  - TEST-VECTOR:Plain-Text (%lu bytes)\n", (unsigned long)sizeof(cg_plaintext0));
	print_hex_dump(
		KERN_INFO,
		"    ",
		DUMP_PREFIX_OFFSET,
		16,
		1,
		(const void *)(&cg_plaintext0[0]),
		sizeof(cg_plaintext0),
		true
	);
	(void)printk(KERN_INFO "  - TEST-VECTOR:Additional-Authenticated-Data (%lu bytes)\n", (unsigned long)sizeof(s_aad0));
	print_hex_dump(
		KERN_INFO,
		"    ",
		DUMP_PREFIX_OFFSET,
		16,
		1,
		(const void *)(&s_aad0[0]),
		sizeof(s_aad0),
		true
	);
	(void)printk(KERN_INFO "  - TEST-VECTOR:Salt (%lu bytes)\n", (unsigned long)sizeof(cg_salt0));
	print_hex_dump(
		KERN_INFO,
		"    ",
		DUMP_PREFIX_OFFSET,
		16,
		1,
		(const void *)(&cg_salt0[0]),
		sizeof(cg_salt0),
		true
	);
	(void)printk(KERN_INFO "  - TEST-VECTOR:Initial-Vector (%lu bytes)\n", (unsigned long)sizeof(cg_iv0));
	print_hex_dump(
		KERN_INFO,
		"    ",
		DUMP_PREFIX_OFFSET,
		16,
		1,
		(const void *)(&cg_iv0[0]),
		sizeof(cg_iv0),
		true
	);
	(void)printk(KERN_INFO "  - TEST-VECTOR:Integrity-Check-Value (%lu bytes)\n", (unsigned long)sizeof(cg_icv0));
	print_hex_dump(
		KERN_INFO,
		"    ",
		DUMP_PREFIX_OFFSET,
		16,
		1,
		(const void *)(&cg_icv0[0]),
		sizeof(cg_icv0),
		true
	);
	(void)printk(KERN_INFO "  - TEST-VECTOR:Cipher-Text-Combines (%lu bytes)\n", (unsigned long)sizeof(cg_ciphertext_combines0));
	print_hex_dump(
		KERN_INFO,
		"    ",
		DUMP_PREFIX_OFFSET,
		16,
		1,
		(const void *)(&cg_ciphertext_combines0[0]),
		sizeof(cg_ciphertext_combines0),
		true
	);

	(void)printk(KERN_INFO "  - Encrypt\n");
	s_process_size = test_crypto_encrypt_AEAD(
		"gcm(aes)",
		(const void *)(&cg_plaintext0[0]),
		sizeof(cg_plaintext0),
		(const void *)(&s_aad0[0]),
		sizeof(s_aad0),
		(const void *)(&cg_key0[0]),
		sizeof(cg_key0),
		(const void *)(&cg_salt0[0]),
		sizeof(cg_salt0),
		(const void *)(&cg_iv0[0]),
		sizeof(cg_iv0),
		(void *)(&s_ciphertext0[0]),
		sizeof(s_ciphertext0),
		(void *)(&s_tag0[0]),
		sizeof(s_tag0)
	);
	if(s_process_size == ((ssize_t)(-1))) {
		(void)printk(KERN_WARNING "test_crypto_encrypt_AEAD failed !\n");
	}
	else {
		(void)printk(KERN_INFO "    - encrypted size : %ld\n", (long)s_process_size);

		/* TLS record length update */
		*((uint16_t *)(&s_aad0[ 8 + 1 + 2 ])) = htons(sizeof(cg_plaintext0) + sizeof(cg_iv0) + sizeof(cg_icv0));

		print_hex_dump(
			KERN_INFO,
			"    [H] ",
			DUMP_PREFIX_OFFSET,
			16,
			1,
			(const void *)(&s_aad0[0]),
			sizeof(s_aad0),
			true
		);
		print_hex_dump(
			KERN_INFO,
			"    [I] ",
			DUMP_PREFIX_OFFSET,
			16,
			1,
			(const void *)(&cg_iv0[0]),
			sizeof(cg_iv0),
			true
		);
		print_hex_dump(
			KERN_INFO,
			"    [E] ",
			DUMP_PREFIX_OFFSET,
			16,
			1,
			(const void *)(&s_ciphertext0[0]),
			sizeof(s_ciphertext0),
			true
		);
		print_hex_dump(
			KERN_INFO,
			"    [T] ",
			DUMP_PREFIX_OFFSET,
			16,
			1,
			(const void *)(&s_tag0[0]),
			sizeof(s_tag0),
			true
		);
		(void)printk(
			KERN_INFO
			"    - verify TLS header : %s\n",
			(memcmp(
				(const void *)(&s_aad0[0]),
				(const void *)(&cg_ciphertext_combines0[0]),
				sizeof(s_aad0)) == 0) ? "PASSED" : "FAILED"
		);
		(void)printk(
			KERN_INFO
			"    - verify cipher-text : %s\n",
			(memcmp(
				(const void *)(&s_ciphertext0[0]),
				(const void *)(&cg_ciphertext_combines0[sizeof(s_aad0)]),
				sizeof(cg_plaintext0)) == 0) ? "PASSED" : "FAILED"
		);
		(void)printk(
			KERN_INFO
			"    - verify tag : %s\n",
			(memcmp(
				(const void *)(&s_tag0[0]),
				(const void *)(&cg_icv0[0]),
				sizeof(cg_icv0)) == 0) ? "PASSED" : "FAILED"
		);
	}

	return(0);
}
