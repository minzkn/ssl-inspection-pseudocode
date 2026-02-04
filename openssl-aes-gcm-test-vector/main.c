/*
	Copyright (C) MINZKN.COM
	All rights reserved.
	Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(_ISOC99_SOURCE)
# define _ISOC99_SOURCE (1L)
#endif

#if !defined(_GNU_SOURCE)
# define _GNU_SOURCE (1L)
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <getopt.h>
#include <signal.h>
#include <sched.h>
#include <execinfo.h>

#include "openssl/conf.h"
#include "openssl/engine.h"
#include "openssl/evp.h"
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "openssl/modes.h"
#include "openssl/aes.h"

static void hwport_dump_backtrace(void);
static void hwport_signal_handler(int s_signo);
static void hwport_setup_signal(void);

static int hwport_is_printable_ascii(int s_charactor, int s_is_level);
static const void *hwport_hexdump(const char *s_prefix, const void *s_data, size_t s_size);

static ssize_t hwport_encrypt_AES_GCM(ENGINE *s_engine, const EVP_CIPHER *s_cipher, const void *s_plaintext, size_t s_plaintext_size, const void *s_aad, size_t s_aad_size, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_ciphertext, void *s_tag);
static ssize_t hwport_decrypt_AES_GCM(ENGINE *s_engine, const EVP_CIPHER *s_cipher, const void *s_ciphertext, size_t s_ciphertext_size, const void *s_aad, size_t s_aad_size, const void *s_tag, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_plaintext);

static int hwport_test_vector_AES128_GCM(ENGINE *s_engine);

int main(int s_argc, char **s_argv);

static volatile int g_hwport_break = 0;

/*
 * 이 함수를 호출한 흐름의 call trace 를 dump 하는 구현
 */
static void hwport_dump_backtrace(void)
{
	/* IMPORTANT

		gcc need compile option "-fno-omit-frame-pointer"
		gcc optional linker option "-rdynamic"

	*/
	void *s_backtrace_buffer[16];
	char **s_backtrace_symbols;
	int s_backtrace_size;
	int s_backtrace_index;

	s_backtrace_size = backtrace(
		(void **)(&s_backtrace_buffer[0]),
		(int)(sizeof(s_backtrace_buffer) / sizeof(void *))
	);
	if(s_backtrace_size <= 0) {
		s_backtrace_symbols = (char **)0;
	}
	else {
		s_backtrace_symbols = backtrace_symbols(
			(void * const *)(&s_backtrace_buffer[0]),
			s_backtrace_size
		);
	}

	(void)fprintf(stderr, "backtrace() returned %d addresses\n", s_backtrace_size);
	for(s_backtrace_index = 0;s_backtrace_index < s_backtrace_size;s_backtrace_index++) {
		(void)fprintf(
			stderr,
			"%02d - %p - %s\n",
			s_backtrace_index + 1,
			s_backtrace_buffer[s_backtrace_index],
			(s_backtrace_symbols == ((char **)0)) ? "<unknown symbol>" : s_backtrace_symbols[s_backtrace_index]
		);
	}
	free((void *)s_backtrace_symbols);
}

/*
 * signal handler
 *
 * 비정상 시그널에 대하여 call trace 를 추적
 */
static void hwport_signal_handler(int s_signo)
{
	switch(s_signo) {
		case SIGSEGV:
		case SIGILL:
		case SIGABRT:
		case SIGFPE:
#if defined(SIGBUS)
		case SIGBUS:
#endif
#if defined(SIGSTKFLT)
		case SIGSTKFLT:
#endif
#if defined(SIGPWR)
		case SIGPWR:
#endif
#if defined(SIGSYS)
		case SIGSYS:
#endif
			(void)fprintf(stderr, "\n%s : Signal happened(%d) => ERROR\n", __func__, s_signo);
			hwport_dump_backtrace();
			*((volatile int *)(&g_hwport_break)) = 1;
			_exit(128 | s_signo);
			break;
		case SIGQUIT: /* 강제 종료 */
		case SIGINT: /* Ctrl + C */
		case SIGTERM:
			(void)fprintf(stderr, "\n%s : Signal happened(%d) => TERMINATE\n", __func__, s_signo);
			if(s_signo == SIGQUIT) {
				hwport_dump_backtrace();
			}
			*((volatile int *)(&g_hwport_break)) = 1;
			if(s_signo == SIGQUIT) {
				_exit(128 | s_signo);
			}
			break;
		case SIGHUP: /* reload */
		case SIGPIPE: /* broken pipe ! */
		default:
			/* 단순 발생유무만 확인하는 부분 */
			(void)fprintf(stderr, "\n%s : Signal happened(%d) => INFO\n", __func__, s_signo);
			hwport_dump_backtrace();
			break;
	}

	(void)signal(s_signo, hwport_signal_handler);
}

static int hwport_is_printable_ascii(int s_charactor, int s_is_level)
{
	if((s_charactor >= ' ') && (s_charactor < 0x7f)) {
		return(1);
	}

	if(s_is_level > 0) {
		if((s_charactor == '\t') || (s_charactor == '\n') || (s_charactor == '\r')) {
			return(1);
		}
	}

	return(0);
}

/*
 * 주어진 data를 hexa dump 로 출력
 */
static const void *hwport_hexdump(const char *s_prefix, const void *s_data, size_t s_size)
{
#if 0L
	(void)s_prefix;

	(void)BIO_dump_fp(stdout, s_data, s_size);
	
	(void)fflush(stdout);

	return(s_data);
#else
	size_t s_o, s_w, s_lo;
	unsigned char s_b[ 16 + 1 ];

	if(s_data == ((const void *)0))return((void *)0);

	s_b[sizeof(s_b) - 1] = (unsigned char)'\0';
	for(s_o = (size_t)0;s_o < s_size;s_o += (size_t)16) {
		s_w = ((s_size - s_o) <= ((size_t)16)) ? (s_size - s_o) : ((size_t)16);
		(void)fprintf(stdout, "%s%08lX", (s_prefix == ((const char *)0)) ? "" : s_prefix, (unsigned long)s_o);
		for(s_lo = (size_t)0;s_lo < s_w;s_lo++) {
			if(s_lo == ((size_t)(16 >> 1)))(void)fputs(" | ", stdout);
			else (void)fputs(" ", stdout);
			s_b[s_lo] = *(((const unsigned char *)s_data) + (s_o + s_lo));
			(void)fprintf(stdout, "%02X", (int)s_b[s_lo]);
			if(hwport_is_printable_ascii((int)s_b[s_lo], 0) == 0) {
				s_b[s_lo] = (unsigned char)'.';
			}
		}
		while(s_lo < ((size_t)16)) {
			if(s_lo == ((size_t)(16 >> 1)))(void)fputs("     ", stdout);
			else (void)fputs("   ", stdout);
			s_b[s_lo] = (unsigned char)' '; s_lo++;
		}
		(void)fprintf(stdout, " [%s]\n", (char *)(&s_b[0]));
	}
	(void)fflush(stdout);

	return(s_data);
#endif
}

/*
 * OpenSSL EVP interface 함수 중 AEAD Encrypt wrapper 구현
 */
static ssize_t hwport_encrypt_AES_GCM(ENGINE *s_engine, const EVP_CIPHER *s_cipher, const void *s_plaintext, size_t s_plaintext_size, const void *s_aad, size_t s_aad_size, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_ciphertext, void *s_tag)
{
	EVP_CIPHER_CTX *s_evp_cipher_ctx;
	int s_check;
	int s_size;
	ssize_t s_ciphertext_size;

	s_evp_cipher_ctx = EVP_CIPHER_CTX_new();
	if(s_evp_cipher_ctx == ((EVP_CIPHER_CTX *)0)) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_CIPHER_CTX_new failed !\n");
		errno = ENOMEM;
		return((ssize_t)(-1));
	}

	if(s_cipher == ((const EVP_CIPHER *)0)) {
		s_cipher = EVP_aes_256_gcm();
	}
	s_check = EVP_EncryptInit_ex(
		s_evp_cipher_ctx /* ctx */,
		s_cipher /* cipher */,
		s_engine /* engine */,
		(const unsigned char *)0 /* key */,
		(const unsigned char *)0 /* iv */
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_EncryptInit_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	s_check = EVP_CIPHER_CTX_ctrl(
		s_evp_cipher_ctx,
		EVP_CTRL_AEAD_SET_IVLEN,
		(int)s_iv_size,
		(void *)0
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Initialise key and IV */
	s_check = EVP_EncryptInit_ex(
		s_evp_cipher_ctx /* ctx */,
		(const EVP_CIPHER *)0 /* cipher */,
		s_engine /* engine */,
		(const unsigned char *)s_key /* key */,
		(const unsigned char *)s_iv /* iv */
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_EncryptInit_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	if((s_aad == ((const void *)0)) && (s_aad_size <= ((size_t)0u))) {
		static const uint8_t cg_empty[] = {};
		s_aad = (const void *)(&cg_empty[0]);
	}
	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	s_check = EVP_EncryptUpdate(
		s_evp_cipher_ctx,
		(unsigned char *)0,
		(int *)(&s_size),
		(const unsigned char *)s_aad,
		(int)s_aad_size
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_EncryptUpdate failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	s_check = EVP_EncryptUpdate(
		s_evp_cipher_ctx,
		(unsigned char *)s_ciphertext,
		(int *)(&s_size),
		(const unsigned char *)s_plaintext,
		(int)s_plaintext_size
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_EncryptUpdate failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}
	s_ciphertext_size = (ssize_t)s_size;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	s_check = EVP_EncryptFinal_ex(
		s_evp_cipher_ctx,
		((unsigned char *)s_ciphertext) + s_size,
		(int *)(&s_size)
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_EncryptFinal_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}
	s_ciphertext_size += (ssize_t)s_size;

	/* Get the tag */
	s_check = EVP_CIPHER_CTX_ctrl(
		s_evp_cipher_ctx,
		EVP_CTRL_AEAD_GET_TAG,
		16,
		(void *)s_tag
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	EVP_CIPHER_CTX_cleanup(s_evp_cipher_ctx);
	EVP_CIPHER_CTX_free(s_evp_cipher_ctx);

	return(s_ciphertext_size);
}

/*
 * OpenSSL EVP interface 함수 중 AEAD Decrypt wrapper 구현
 */
static ssize_t hwport_decrypt_AES_GCM(ENGINE *s_engine, const EVP_CIPHER *s_cipher, const void *s_ciphertext, size_t s_ciphertext_size, const void *s_aad, size_t s_aad_size, const void *s_tag, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_plaintext)
{
	union {
		const void *m_const_ptr;
		void *m_ptr;
	}s_union_ptr;
	EVP_CIPHER_CTX *s_evp_cipher_ctx;
	int s_check;
	int s_size;
	ssize_t s_plaintext_size;

	s_evp_cipher_ctx = EVP_CIPHER_CTX_new();
	if(s_evp_cipher_ctx == ((EVP_CIPHER_CTX *)0)) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_CIPHER_CTX_new failed !\n");
		errno = ENOMEM;
		return((ssize_t)(-1));
	}

	if(s_cipher == ((const EVP_CIPHER *)0)) {
		s_cipher = EVP_aes_128_gcm();
	}
	s_check = EVP_DecryptInit_ex(
		s_evp_cipher_ctx /* ctx */,
		s_cipher /* cipher */,
		s_engine /* engine */,
		(const unsigned char *)0 /* key */,
		(const unsigned char *)0 /* iv */
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_DecryptInit_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	s_check = EVP_CIPHER_CTX_ctrl(
		s_evp_cipher_ctx,
		EVP_CTRL_AEAD_SET_IVLEN,
		(int)s_iv_size,
		(void *)0
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Initialise key and IV */
	s_check = EVP_DecryptInit_ex(
		s_evp_cipher_ctx /* ctx */,
		(const EVP_CIPHER *)0 /* cipher */,
		s_engine /* engine */,
		(const unsigned char *)s_key /* key */,
		(const unsigned char *)s_iv /* iv */
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_DecryptInit_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	if((s_aad == ((const void *)0)) && (s_aad_size <= ((size_t)0u))) {
		static const uint8_t cg_empty[] = {};
		s_aad = (const void *)(&cg_empty[0]);
	}
	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	s_check = EVP_DecryptUpdate(
		s_evp_cipher_ctx,
		(unsigned char *)0,
		(int *)(&s_size),
		(const unsigned char *)s_aad,
		(int)s_aad_size
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_DecryptUpdate failed ! (aad)\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	s_check = EVP_DecryptUpdate(
		s_evp_cipher_ctx,
		(unsigned char *)s_plaintext,
		(int *)(&s_size),
		(const unsigned char *)s_ciphertext,
		(int)s_ciphertext_size
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_DecryptUpdate failed ! (cipher)\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}
	s_plaintext_size = (ssize_t)s_size;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	s_union_ptr.m_const_ptr = s_tag;
	s_check = EVP_CIPHER_CTX_ctrl(
		s_evp_cipher_ctx,
		EVP_CTRL_AEAD_SET_TAG,
		16,
		(void *)s_union_ptr.m_ptr
	);
	if(s_check <= 0) {
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	s_check = EVP_DecryptFinal_ex(
		s_evp_cipher_ctx,
		((unsigned char *)s_plaintext) + s_size,
		(int *)(&s_size)
	);
	if(s_check <= 0) { /* Verify failed */
		ERR_print_errors_fp(stderr);
		(void)fprintf(stderr, "EVP_EncryptFinal_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}
	else {
		s_plaintext_size += (ssize_t)s_size;
	}

	EVP_CIPHER_CTX_cleanup(s_evp_cipher_ctx);
	EVP_CIPHER_CTX_free(s_evp_cipher_ctx);

	return(s_plaintext_size);
}

/*
 * AEAD 알고리즘 AES128-GCM을 미리 공재적으로 알려진 Test-Vector로 검증
 */
static int hwport_test_vector_AES128_GCM(ENGINE *s_engine)
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
	
	(void)fprintf(stdout, "* TEST AEAD-AES128-GCM\n");

#if 1L
	c_cipher = EVP_get_cipherbyname("aes-128-gcm");
#else
	c_cipher = EVP_aes_128_gcm();
#endif

	(void)fprintf(stdout, "  - TEST-VECTOR:Key (%lu bytes)\n", (unsigned long)sizeof(cg_key0));
	(void)hwport_hexdump("    ", (const void *)(&cg_key0[0]), sizeof(cg_key0));
	(void)fprintf(stdout, "  - TEST-VECTOR:Plain-Text (%lu bytes)\n", (unsigned long)sizeof(cg_plaintext0));
	(void)hwport_hexdump("    ", (const void *)(&cg_plaintext0[0]), sizeof(cg_plaintext0));
	(void)fprintf(stdout, "  - TEST-VECTOR:Additional-Authenticated-Data (%lu bytes)\n", (unsigned long)sizeof(cg_aad0));
	(void)hwport_hexdump("    ", (const void *)(&cg_aad0[0]), sizeof(cg_aad0));
	(void)fprintf(stdout, "  - TEST-VECTOR:Initial-Vector (%lu bytes)\n", (unsigned long)sizeof(cg_iv0));
	(void)hwport_hexdump("    ", (const void *)(&cg_iv0[0]), sizeof(cg_iv0));
	(void)fprintf(stdout, "  - TEST-VECTOR:Integrity-Check-Value (%lu bytes)\n", (unsigned long)sizeof(cg_icv0));
	(void)hwport_hexdump("    ", (const void *)(&cg_icv0[0]), sizeof(cg_icv0));
	(void)fprintf(stdout, "  - TEST-VECTOR:Cipher-Text-Combines (%lu bytes)\n", (unsigned long)sizeof(cg_ciphertext_combines0));
	(void)hwport_hexdump("    ", (const void *)(&cg_ciphertext_combines0[0]), sizeof(cg_ciphertext_combines0));

	(void)fprintf(stdout, "  - Encrypt\n");
	s_process_size = hwport_encrypt_AES_GCM(
		s_engine,
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
		(void)fprintf(stderr, "hwport_encrypt_AES_GCM failed !\n");
	}
	else {
		(void)fprintf(stdout, "    - encrypted size : %ld\n", (long)s_process_size);
		(void)hwport_hexdump("      [A] ", (const void *)(&cg_aad0[0]), sizeof(cg_aad0));
		(void)hwport_hexdump("      [E] ", (const void *)(&s_ciphertext0[0]), (size_t)s_process_size);
		(void)hwport_hexdump("      [T] ", (const void *)(&s_tag0[0]), sizeof(s_tag0));
		(void)fprintf(
			stdout,
			"    - verify cipher-text : %s\n",
			(memcmp(
				(const void *)(&s_ciphertext0[0]),
				(const void *)(&cg_ciphertext_combines0[sizeof(cg_aad0)]),
				sizeof(cg_plaintext0)) == 0) ? "\x1b[1;34mPASSED\x1b[0m" : "\x1b[1;31mFAILED\x1b[0m"
		);
		(void)fprintf(
			stdout,
			"    - verify tag : %s\n",
			(memcmp(
				(const void *)(&s_tag0[0]),
				(const void *)(&cg_icv0[0]),
				sizeof(cg_icv0)) == 0) ? "\x1b[1;34mPASSED\x1b[0m" : "\x1b[1;31mFAILED\x1b[0m"
		);

		(void)fprintf(stdout, "  - Decrypt\n");
		s_process_size = hwport_decrypt_AES_GCM(
			s_engine,
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
			(void)fprintf(stderr, "hwport_decrypt_AES_GCM failed !\n");
		}
		else {
			(void)fprintf(stdout, "    - decrypted size : %ld\n", (long)s_process_size);
			(void)hwport_hexdump("      [D] ", (const void *)(&s_plaintext0[0]), (size_t)s_process_size);
			(void)fprintf(
				stdout,
				"    - verify cipher-text : %s\n",
				(memcmp(
					(const void *)(&s_plaintext0[0]),
					(const void *)(&cg_plaintext0[0]),
					sizeof(cg_plaintext0)) == 0) ? "\x1b[1;34mPASSED\x1b[0m" : "\x1b[1;31mFAILED\x1b[0m"
			);
		}
	}

	return(0);
}

/*
 * signal handler setup
 */
static void hwport_setup_signal(void)
{
	(void)signal(SIGSEGV, hwport_signal_handler);
	(void)signal(SIGILL, hwport_signal_handler);
	(void)signal(SIGABRT, hwport_signal_handler);
	(void)signal(SIGFPE, hwport_signal_handler);
#if defined(SIGBUS)
	(void)signal(SIGBUS, hwport_signal_handler);
#endif
#if defined(SIGSTKFLT)
	(void)signal(SIGSTKFLT, hwport_signal_handler);
#endif
#if defined(SIGPWR)
	(void)signal(SIGPWR, hwport_signal_handler);
#endif
#if defined(SIGSYS)
	(void)signal(SIGSYS, hwport_signal_handler);
#endif

	/* terminate */
	(void)signal(SIGQUIT, hwport_signal_handler);
	(void)signal(SIGINT, hwport_signal_handler);
	(void)signal(SIGTERM, hwport_signal_handler);

	/* ignore */
	(void)signal(SIGHUP, hwport_signal_handler);
	(void)signal(SIGPIPE, hwport_signal_handler);
}

int main(int s_argc, char **s_argv)
{
#if 1L /* default engine */
	const char *c_engine_name = (const char *)(NULL);
#else /* Octeon's OpenSSL engine DPDK use */
	const char *c_engine_name = "dpdk_engine";
#endif
	ENGINE *s_engine = (ENGINE *)(NULL);

	/* setup signal */
	hwport_setup_signal();
	
	/* argument */
	do {
		static const char *c_program_name = "openssl-aes-gcm-test-vector";
		static const struct option sg_options[] = {
			{"help", no_argument, (int *)0, 'h'},
			{"engine", required_argument, (int *)0, 'e'},
			{(char *)0, 0, (int *)0, 0}
		};
		int s_option_index;
		int s_short_option_index;
		int s_is_help = 0;

		if((s_argc >= 1) && (s_argv[0] != ((char *)0))) {
			c_program_name = strrchr(s_argv[0], '/');
			if(c_program_name != ((const char *)0)) {
				c_program_name = (const char *)(&c_program_name[1]);
			}
			else {
				c_program_name = (const char *)s_argv[0];
			}
		}

		for(s_option_index = 0;s_is_help == 0;) {
			s_short_option_index = getopt_long(
				s_argc,
				s_argv,
				"he:",
				sg_options,
				&s_option_index
			);
			if(s_short_option_index == (-1)) {
				break;
			}

			switch(s_short_option_index) {
				case 0:
					if(strcmp(sg_options[s_option_index].name, "engine") == 0) {
						c_engine_name = optarg;
					}
					else { /* unknown option (unlikely) */
						(void)fprintf(stderr, "unknown option \"%s\" !\n", sg_options[s_option_index].name);
						s_is_help = 1;
					}
					break;  
				case '?':
				case 'h': s_is_help = 1; break;  
				case 'e': c_engine_name = optarg; break;
				default: s_is_help = 1; break;
			}
		}

		if(s_is_help != 0) {
			(void)fprintf(
				stdout,
				"%s v0.0.1-0 (%s %s)\n"
				"Copyrights (C) MINZKN.COM - All rights reserved.\n"
				"\n"
				"usage: %s [<options>]\n"
				"\n"
				"options:\n"
				"\t-h, --help                  : help\n"
				"\t-e, --engine=<engine name>  : engine name (default: \"%s\")\n"
				"\n",
				c_program_name,
				__DATE__,
				__TIME__,
				c_program_name,
				(c_engine_name == ((const char *)(NULL))) ? "<builtin-use>" : c_engine_name
			);

			return(EXIT_FAILURE);
		}
	}while(0);

	/* initialize SSL library */
	(void)fprintf(
		stdout,
	       	"Initializing %s (OPENSSL_VERSION_NUMBER=0x%08lx)...\n",
		OPENSSL_VERSION_TEXT,
		(unsigned long)OPENSSL_VERSION_NUMBER
	);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG
#if !defined(OPENSSL_NO_ENGINE)
	                    |OPENSSL_INIT_ENGINE_ALL_BUILTIN
#endif /* !OPENSSL_NO_ENGINE */
	                    , NULL) <= 0) {
		/* Could not initialize the OpenSSL library ! */
		(void)fprintf(stderr, "OPENSSL_init_crypto failed !\n");
		return(EXIT_FAILURE);
	}
	if (OPENSSL_init_ssl(0, NULL) <= 0) {
		/* Could not initialize the OpenSSL library ! */
		(void)fprintf(stderr, "OPENSSL_init_ssl failed !\n");
		return(EXIT_FAILURE);
	}
#else
	if (SSL_library_init() <= 0) {
		/* Could not initialize the OpenSSL library ! */
		(void)fprintf(stderr, "SSL_library_init failed !\n");
		return(EXIT_FAILURE);
	}
	OPENSSL_load_builtin_modules();
	ENGINE_load_dynamic();
	ENGINE_load_builtin_engines();
#endif

	if ((c_engine_name != ((const char *)(NULL))) && (c_engine_name[0] != '\0')) {
#if !defined(OPENSSL_NO_ENGINE)
		(void)fprintf(stdout, "Loading engine : \"%s\"\n", c_engine_name);
		s_engine = ENGINE_by_id(c_engine_name);
		if (s_engine != ((ENGINE *)(NULL))) {
			(void)fprintf(stdout, "Loaded engine : \"%s\"\n", c_engine_name);

#if 0L
			do {
				BIO *s_bio;
			
				s_bio = BIO_new_fp(stderr, BIO_NOCLOSE);
				if (s_bio != ((BIO *)(NULL))) {
					ENGINE_ctrl(s_engine, ENGINE_CTRL_SET_LOGSTREAM, 0, s_bio, 0);
					BIO_free_all(s_bio);
				}
			} while(0);
#endif

			if (ENGINE_init(s_engine) <= 0) {
				(void)fprintf(stderr, "Not usable engine : \"%s\" ! (init failed)\n", c_engine_name);
				ENGINE_free(s_engine);
				s_engine = (ENGINE *)(NULL);
			}
			else {
				(void)fprintf(stdout, "Initialized engine : \"%s\"\n", c_engine_name);

#if 1L
				if (ENGINE_set_default(s_engine, ENGINE_METHOD_ALL) <= 0) {
					(void)fprintf(stderr, "Not usable engine : \"%s\" ! (set default)\n", c_engine_name);
				}
#else
				if (ENGINE_set_default_RSA(s_engine) <= 0) {
					(void)fprintf(stderr, "Not usable engine : \"%s\" ! (set default RSA)\n", c_engine_name);
				}
#endif
			}
		}
		else {
			(void)fprintf(stderr, "Not usable engine : \"%s\" ! (load failed)\n", c_engine_name);
		}
#else
		(void)fprintf(stderr, "Not usable engine : \"%s\" ! (defined OPENSSL_NO_ENGINE)\n", c_engine_name);
		(void)s_engine;
#endif
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#else
	/* Lets get nice error messages */
	SSL_load_error_strings();

	ERR_load_crypto_strings();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#else
	ERR_load_BIO_strings();
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#else
	ERR_load_ERR_strings();
#endif
#endif

	/* Do Test-Vector */
	(void)fprintf(stdout, "\nBEGIN: Do TestVector\n");
#if 0L /* CPU affinity check */
	do {
		pid_t s_pid = getpid();	
		cpu_set_t s_cpuset;

		CPU_ZERO(&s_cpuset);
		if (sched_getaffinity(s_pid, sizeof(s_cpuset), (cpu_set_t *)(&s_cpuset)) == 0) {
			int s_cpu_count = CPU_COUNT(&s_cpuset);

			(void)fprintf(stdout, "CPU affinity count %d\n", s_cpu_count);
		}
	} while(0);
#endif
	(void)hwport_test_vector_AES128_GCM(s_engine);
	(void)fprintf(stdout, "\nEND: Do TestVector\n");

	/* cleanup SSL library */
#if !defined(OPENSSL_NO_ENGINE)
	if (s_engine != ((ENGINE *)(NULL))) {
		(void)fprintf(stdout, "ENGINE_free...\n");
		ENGINE_finish(s_engine);
		ENGINE_free(s_engine);
	}
#endif
	(void)fprintf(stdout, "cleanup...\n");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	/* OpenSSL 1.1 deprecates all these cleanup functions and turns them into no-ops in OpenSSL 1.0 compatibility mode */
#else
	/* Free ciphers and digests lists */
	EVP_cleanup();

	/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
	CRYPTO_cleanup_all_ex_data();

#if !defined(OPENSSL_NO_ENGINE)
	/* Free engine list */
	ENGINE_cleanup();
#endif

	/* Free OpenSSL error strings */
	ERR_free_strings();

	/* Free thread local error state, destroying hash upon zero refcount */
	ERR_remove_thread_state(NULL);

	/* Free all memory allocated by all configuration modules */
	CONF_modules_free();

	SSL_COMP_free_compression_methods();
#endif
	
	(void)fprintf(stdout, "END.\n");

	return(EXIT_SUCCESS);
}

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
