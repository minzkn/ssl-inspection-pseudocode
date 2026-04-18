/*
	Copyright (C) MINZKN.COM
	All rights reserved.
	Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

/* PACKED declare NOTE: >= gnuc v2.95
# if (__GNUC__ <= 2L) && (__GNUC_MINOR__ <= 95L)
typedef struct mystruct {
	int m_member;
} __attribute__((packed)) mytypestruct;
# else
#  pragma pack(push,1)
#  pragma pack(pop)
#endif
*/

#if !defined(__def_sslid_header_sslid_lib_h__)
# define __def_sslid_header_sslid_lib_h__ "sslid-lib.h"

#if !defined(_ISOC99_SOURCE)
# define _ISOC99_SOURCE (1L)
#endif

#if !defined(_GNU_SOURCE)
# define _GNU_SOURCE (1L)
#endif

/* ---- */

/* 
   Header include 이전에 정의해야 하는 define 들은 여기에서 정의합니다.
*/
#if !defined(def_sslid_ktls_enable)
# define def_sslid_ktls_enable 1
#endif

/* ---- */

/*
   잘 짜여진 C Header 는 namespace 및 include 순서가 상관없습니다.
   하지만 우리는 경험상 그렇지 않은 header들이 분명 있습니다.

   아래와 같이 되도록이면 include 순서를 준수할 것을 권장합니다.
*/

/* system header */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/sendfile.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "netinet/tcp.h"
#include <netinet/in.h>

#include <arpa/inet.h>

/* kernel header */

#if def_sslid_ktls_enable != 0
# include <linux/tls.h>
# if !defined(TCP_ULP) /* in system header "netinet/tcp.h" */
#  if 0L /* ALERT */
#   warning TCP_ULP not defined ! (local define using to 31)
#  endif
#  define TCP_ULP 31
# endif
# if !defined(SOL_TLS) /* in system header "sys/socket.h" > "bits/socket.h" */
#  if 0L /* ALERT */
#   warning SOL_TLS not defined ! (local define using to 282)
#  endif
#  define SOL_TLS 282
# endif
# if !defined(TLS_TX) /* need linux kernel >=v4.13 - in kernel header "linux/tls.h" */
#  if 0L /* ALERT */
#   warning TLS_TX not defined ! (local define using to 1)
#  endif
#  define TLS_TX 1
# endif
# if !defined(TLS_RX) /* need linux kernel >=v4.19 - in kernel header "linux/tls.h"  */
#  if 0L /* ALERT */
#   warning TLS_RX not defined ! (local define using to 2)
#  endif
#  define TLS_RX 2
# endif
#endif

/* library header */

#include <pthread.h>

#include "openssl/conf.h"
#include "openssl/engine.h"
#include "openssl/evp.h"
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"

#include "openssl/modes.h"
#include "openssl/aes.h"

#include "openssl/md5.h"

#include "openssl/hmac.h"

/* ---- */

#define def_SSL_inspection_default_program_name "sslid"

#define def_SSL_inspection_listen_address "0.0.0.0" /* "0.0.0.0" or "::" */
#define def_SSL_inspection_listen_port 8443 /* listen port */

#if 1L /* test to cloud clare */
# define def_SSL_inspection_connect_address "1.0.0.1"
# define def_SSL_inspection_connect_port 443
#else /* our test server */
# define def_SSL_inspection_connect_address "192.168.0.2"
# define def_SSL_inspection_connect_port 5001
#endif

#if 0L
#define def_SSL_inspection_socket_buffer_rx (1u << 20)
#define def_SSL_inspection_socket_buffer_tx (1u << 20)
#else
#define def_SSL_inspection_socket_buffer_rx (-1)
#define def_SSL_inspection_socket_buffer_tx (-1)
#endif

#if 0L /* self-signed certificate generate */
# define def_SSL_inspection_default_certificate_pathname ((const char *)0)
# define def_SSL_inspection_default_privatekey_pathname ((const char *)0)
#else
# define def_SSL_inspection_default_certificate_pathname "./cert.pem"
# define def_SSL_inspection_default_privatekey_pathname "./key.pem"
#endif

#define def_SSL_inspection_splice_rx_size (64 << 10) /* limited 64KBytes : maximum splice */

#if def_sslid_ktls_enable != 0
# define def_SSL_inspection_cipher_list \
	"ECDH-ECDSA-AES128-GCM-SHA256" /* 1.0.2p */\
	":ECDH-RSA-AES128-GCM-SHA256" /* 1.0.2p */\
	":ECDHE-ECDSA-AES128-GCM-SHA256" \
	":ECDHE-RSA-AES128-GCM-SHA256" \
	":DHE-RSA-AES128-GCM-SHA256" \
	":DH-RSA-AES128-GCM-SHA256" /* 1.0.2p */ \
	":RSA-PSK-AES128-GCM-SHA256" \
	":DHE-PSK-AES128-GCM-SHA256" \
	":AES128-GCM-SHA256" \
	":PSK-AES128-GCM-SHA256"
#elif 0L /* TLSv1.2 list */
# define def_SSL_inspection_cipher_list \
	"ECDHE-RSA-AES256-GCM-SHA384" \
	":ECDHE-ECDSA-AES256-GCM-SHA384" \
	":ECDHE-RSA-AES256-SHA384" \
	":ECDHE-ECDSA-AES256-SHA384" \
	":DHE-DSS-AES256-GCM-SHA384" \
	":DHE-RSA-AES256-GCM-SHA384" \
	":DHE-RSA-AES256-SHA256" \
	":DHE-DSS-AES256-SHA256" \
	":AES256-GCM-SHA384" \
	":AES256-SHA256" \
	":ECDHE-RSA-AES128-GCM-SHA256" \
	":ECDHE-ECDSA-AES128-GCM-SHA256" \
	":ECDHE-RSA-AES128-SHA256" \
	":ECDHE-ECDSA-AES128-SHA256" \
	":DHE-DSS-AES128-GCM-SHA256" \
	":DHE-RSA-AES128-GCM-SHA256" \
	":DHE-RSA-AES128-SHA256" \
	":DHE-DSS-AES128-SHA256" \
	":AES128-GCM-SHA256" \
	":AES128-SHA256"
#elif 0L /* full list */
# define def_SSL_inspection_cipher_list \
	"ECDHE-ECDSA-AES256-GCM-SHA384" \
	":ECDHE-RSA-AES256-GCM-SHA384" \
	":DHE-RSA-AES256-GCM-SHA384" \
	":ECDHE-ECDSA-CHACHA20-POLY1305" \
	":ECDHE-RSA-CHACHA20-POLY1305" \
	":DHE-RSA-CHACHA20-POLY1305" \
	":ECDHE-ECDSA-AES128-GCM-SHA256" \
	":ECDHE-RSA-AES128-GCM-SHA256" \
	":DHE-RSA-AES128-GCM-SHA256" \
	":ECDHE-ECDSA-AES256-SHA384" \
	":ECDHE-RSA-AES256-SHA384" \
	":DHE-RSA-AES256-SHA256" \
	":ECDHE-ECDSA-AES128-SHA256" \
	":ECDHE-RSA-AES128-SHA256" \
	":DHE-RSA-AES128-SHA256" \
	":ECDHE-ECDSA-AES256-SHA" \
	":ECDHE-RSA-AES256-SHA" \
	":DHE-RSA-AES256-SHA" \
	":ECDHE-ECDSA-AES128-SHA" \
	":ECDHE-RSA-AES128-SHA" \
	":DHE-RSA-AES128-SHA" \
	":RSA-PSK-AES256-GCM-SHA384" \
	":DHE-PSK-AES256-GCM-SHA384" \
	":RSA-PSK-CHACHA20-POLY1305" \
	":DHE-PSK-CHACHA20-POLY1305" \
	":ECDHE-PSK-CHACHA20-POLY1305" \
	":AES256-GCM-SHA384" \
	":PSK-AES256-GCM-SHA384" \
	":PSK-CHACHA20-POLY1305" \
	":RSA-PSK-AES128-GCM-SHA256" \
	":DHE-PSK-AES128-GCM-SHA256" \
	":AES128-GCM-SHA256" \
	":PSK-AES128-GCM-SHA256" \
	":AES256-SHA256" \
	":AES128-SHA256" \
	":ECDHE-PSK-AES256-CBC-SHA384" \
	":ECDHE-PSK-AES256-CBC-SHA" \
	":SRP-RSA-AES-256-CBC-SHA" \
	":SRP-AES-256-CBC-SHA" \
	":RSA-PSK-AES256-CBC-SHA384" \
	":DHE-PSK-AES256-CBC-SHA384" \
	":RSA-PSK-AES256-CBC-SHA" \
	":DHE-PSK-AES256-CBC-SHA" \
	":AES256-SHA" \
	":PSK-AES256-CBC-SHA384" \
	":PSK-AES256-CBC-SHA" \
	":ECDHE-PSK-AES128-CBC-SHA256" \
	":ECDHE-PSK-AES128-CBC-SHA" \
	":SRP-RSA-AES-128-CBC-SHA" \
	":SRP-AES-128-CBC-SHA" \
	":RSA-PSK-AES128-CBC-SHA256" \
	":DHE-PSK-AES128-CBC-SHA256" \
	":RSA-PSK-AES128-CBC-SHA" \
	":DHE-PSK-AES128-CBC-SHA" \
	":AES128-SHA" \
	":PSK-AES128-CBC-SHA256" \
	":PSK-AES128-CBC-SHA"
#else /* all list */
# define def_SSL_inspection_cipher_list \
	(const char *)0
#endif

#define def_SSL_inspection_debug_flag_none 0x00000000u
#define def_SSL_inspection_debug_flag_first_recv 0x00000001u
#define def_SSL_inspection_debug_flag_send_delay 0x00000002u

#define def_SSL_inspection_use_ktls_none 0x00000000u
#define def_SSL_inspection_use_ktls_rx 0x00000001u
#define def_SSL_inspection_use_ktls_tx 0x00000002u
#define def_SSL_inspection_use_ktls_forward 0x00000004u

#define def_SSL_inspection_buffer_size (1 << 14) /* limited 16KBytes : maximum TLS record size */
typedef struct {
	int m_is_verbose;
	unsigned int m_debug_flags;
	const char *m_cipher_list;
	unsigned int m_use_ktls;
	int m_use_splice;
	const char *m_connect_address;
	int m_connect_port;

	SSL_CTX *m_ssl_ctx;
	int m_accept_socket;
	struct sockaddr_storage m_sockaddr_storage;
	socklen_t m_socklen;

	size_t m_buffer_size;
	void *m_buffer;
	void *m_dup_buffer; /* for dump */
}SSL_inspection_context_t;

/* ---- */

#define def_hwport_escape_code(m_code) "\x1b" m_code
#define def_hwport_color_user(m_code) def_hwport_escape_code("[" m_code)
#define def_hwport_color_normal       def_hwport_color_user("0m")
#define def_hwport_color_black        def_hwport_color_user("1;30m")
#define def_hwport_color_red          def_hwport_color_user("1;31m")
#define def_hwport_color_green        def_hwport_color_user("1;32m")
#define def_hwport_color_yellow       def_hwport_color_user("1;33m")
#define def_hwport_color_blue         def_hwport_color_user("1;34m")
#define def_hwport_color_magenta      def_hwport_color_user("1;35m")
#define def_hwport_color_cyan         def_hwport_color_user("1;36m")
#define def_hwport_color_white        def_hwport_color_user("1;37m")
#define def_hwport_color_brown        def_hwport_color_user("0;31m")

#define hwport_peek_const_vector(m_cast,m_base,m_sign,m_offset) ((m_cast)((const void *)(((const uint8_t *)(m_base)) m_sign ((size_t)(m_offset)))))
#define hwport_peek_const_f(m_cast,m_base,m_offset) hwport_peek_const_vector(m_cast,m_base,+,m_offset)
#define hwport_peek_const(m_base,m_offset) hwport_peek_const_vector(const void *,m_base,+,m_offset)

#define hwport_peek_vector(m_cast,m_base,m_sign,m_offset) ((m_cast)((void *)(((uint8_t *)(m_base)) m_sign ((size_t)(m_offset)))))
#define hwport_peek_f(m_cast,m_base,m_offset) hwport_peek_vector(m_cast,m_base,+,m_offset)
#define hwport_peek(m_base,m_offset) hwport_peek_vector(void *,m_base,+,m_offset)

#define hwport_peek_const_type(m_cast,m_from,m_offset) (*(hwport_peek_const_f(const m_cast *,m_from,m_offset)))
#define hwport_peek_uint8(m_from,m_offset) hwport_peek_const_type(uint8_t,m_from,m_offset)

#define hwport_peek_type(m_cast,m_from,m_offset) (*(hwport_peek_f(m_cast *,m_from,m_offset)))
#define hwport_poke_type(m_cast,m_to,m_offset,m_value) do{hwport_peek_type(m_cast,m_to,m_offset)=(m_cast)(m_value);}while(0)
#define hwport_poke_uint8(m_to,m_offset,m_value) hwport_poke_type(uint8_t,m_to,m_offset,m_value)

#define SSL_inspection_barrier() __asm__ __volatile__("": : :"memory") /* compiler barrier */

/* ---- */

#define def_hwport_sha256_hash_size (256>>3) /* 256 bits = 32 bytes */
#define def_hwport_sha256_hash_words (def_hwport_sha256_hash_size>>2) /* 64 bits = 8 bytes */
#define def_hwport_sha256_round 64

#define def_hwport_sha256_digest_size def_hwport_sha256_hash_size

#define def_hwport_sha256_key_pad_size 64

#if !defined(hwport_sha256_t)
typedef struct hwport_sha256_ts __hwport_sha256_t;
# define hwport_sha256_t __hwport_sha256_t
# pragma pack(push,8)
struct hwport_sha256_ts {
    unsigned long long m_total_size;
    uint32_t m_hash[ def_hwport_sha256_hash_words ];
    size_t m_buffer_size;

    uint32_t m_buffer[def_hwport_sha256_hash_words << 1];

	/* for hmac */
	size_t m_key_size;
	uint8_t m_key[ def_hwport_sha256_key_pad_size ];
	uint8_t m_key_pad[ def_hwport_sha256_key_pad_size ];
};
# pragma pack(pop)
#endif

#if !defined(__def_sslid_source_sha256_c__)
extern hwport_sha256_t *hwport_init_sha256(hwport_sha256_t *s_sha256);

extern const void *hwport_sha256_push(hwport_sha256_t *s_sha256, const void *s_data, size_t s_size);
extern void *hwport_sha256_digest(hwport_sha256_t *s_sha256, void *s_digest);
extern void *hwport_sha256_simple(const void *s_data, size_t s_size, void *s_digest);

extern hwport_sha256_t *hwport_init_hmac_sha256(hwport_sha256_t *s_sha256, const void *s_key, size_t s_key_size);
extern void *hwport_hmac_sha256_digest(hwport_sha256_t *s_sha256, void *s_digest);
extern void *hwport_hmac_sha256_simple(const void *s_key, size_t s_key_size, const void *s_data, size_t s_size, void *s_digest);

extern void *hwport_pseudo_random_function_tlsv1_2_sha256(const void *s_secret, size_t s_secret_size, const void *s_label, size_t s_label_size, const void *s_seed, size_t s_seed_size, void *s_output, size_t s_output_size);
#endif

/* ---- */

#define def_hwport_ghash_block_size 16
#define def_hwport_ghash_digest_size 16

#if !defined(__def_sslid_source_ghash_c__)
extern void gf_mult128(const uint8_t *x, const uint8_t *y, uint8_t *z);
extern void ghash_start(uint8_t *y);
extern void ghash(const uint8_t *h, const uint8_t *x, size_t xlen, uint8_t *y);
#endif

/* ---- */

#if !defined(hwport_make_round_key_handler_t)
typedef void * (*__hwport_make_round_key_handler_t)(void *s_round_key, const void *s_user_key);
# define hwport_make_round_key_handler_t __hwport_make_round_key_handler_t
#endif

#if !defined(hwport_encrypt_handler_t)
typedef void * (*__hwport_encrypt_handler_t)(void *s_data, size_t s_size, const void *s_round_key);
# define hwport_encrypt_handler_t __hwport_encrypt_handler_t
#endif

#if !defined(hwport_decrypt_handler_t)
typedef void * (*__hwport_decrypt_handler_t)(void *s_data, size_t s_size, const void *s_round_key);
# define hwport_decrypt_handler_t __hwport_decrypt_handler_t
#endif

#define def_hwport_aes_block_size 16 /* AES is always 16-bytes block */

#define def_hwport_aes128_block_size def_hwport_aes_block_size
#define def_hwport_aes128_rounds 10
#define def_hwport_aes128_user_key_size (128>>3) /* 128 bits = 16 bytes */
#define def_hwport_aes128_round_key_size ((1+def_hwport_aes128_rounds)*def_hwport_aes128_block_size)

#define def_hwport_aes192_block_size def_hwport_aes_block_size
#define def_hwport_aes192_rounds 12
#define def_hwport_aes192_user_key_size (192>>3) /* 192 bits = 24 bytes */
#define def_hwport_aes192_round_key_size ((1+def_hwport_aes192_rounds)*def_hwport_aes192_block_size)

#define def_hwport_aes256_block_size def_hwport_aes_block_size
#define def_hwport_aes256_rounds 14
#define def_hwport_aes256_user_key_size (256>>3) /* 256 bits = 32 bytes */
#define def_hwport_aes256_round_key_size ((1+def_hwport_aes256_rounds)*def_hwport_aes256_block_size)

#define def_hwport_aes_max_user_key_size def_hwport_aes256_user_key_size
#define def_hwport_aes_max_round_key_size def_hwport_aes256_round_key_size

#if !defined(__def_sslid_source_aes_c__)
extern void *hwport_encrypt_mode_cfb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_mode_cfb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

extern void *hwport_encrypt_mode_cfb8_for_product_key(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_mode_cfb8_for_product_key(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

extern void *hwport_encrypt_mode_ofb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_mode_ofb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

extern void *hwport_encrypt_mode_cbc(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_mode_cbc(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

extern void *hwport_make_round_key_aes128(void *s_round_key, const void *s_user_key);
extern void *hwport_make_round_key_aes192(void *s_round_key, const void *s_user_key);
extern void *hwport_make_round_key_aes256(void *s_round_key, const void *s_user_key);

extern void *hwport_encrypt_aes128_ecb(void *s_data, size_t s_size, const void *s_round_key);
extern void *hwport_decrypt_aes128_ecb(void *s_data, size_t s_size, const void *s_round_key);
extern void *hwport_encrypt_aes128_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_aes128_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_encrypt_aes128_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_aes128_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_encrypt_aes128_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_aes128_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

extern void *hwport_encrypt_aes192_ecb(void *s_data, size_t s_size, const void *s_round_key);
extern void *hwport_decrypt_aes192_ecb(void *s_data, size_t s_size, const void *s_round_key);
extern void *hwport_encrypt_aes192_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_aes192_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_encrypt_aes192_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_aes192_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_encrypt_aes192_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_aes192_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

extern void *hwport_encrypt_aes256_ecb(void *s_data, size_t s_size, const void *s_round_key);
extern void *hwport_decrypt_aes256_ecb(void *s_data, size_t s_size, const void *s_round_key);
extern void *hwport_encrypt_aes256_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_aes256_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_encrypt_aes256_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_aes256_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_encrypt_aes256_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
extern void *hwport_decrypt_aes256_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
#endif

/* ---- */

#if !defined(__def_sslid_source_aes_gcm_c__)
int aes_gcm_ae(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len, const uint8_t *plain, size_t plain_len, const uint8_t *aad, size_t aad_len, uint8_t *crypt, uint8_t *tag);
int aes_gcm_ad(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len, const uint8_t *crypt, size_t crypt_len, const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *plain);
int aes_gmac(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len, uint8_t *tag);
#endif

/* ---- */

#if !defined(__def_sslid_source_sslid_lib_c__)
extern void *SSL_inspection_increment_be_block(void *s_bigint_ptr, size_t s_size);
extern void *SSL_inspection_xor_block(void *s_to_ptr, const void *s_from_ptr, size_t s_size);
extern void *SSL_inspection_right_shift_block(void *s_block_ptr, size_t s_size);

extern int SSL_inspection_is_printable_ascii(int s_charactor, int s_is_level);
extern void *SSL_inspection_convert_printable_ascii(void *s_to, const void *s_from, size_t s_size);
extern const void *SSL_inspection_hexdump(const char *s_prefix, const void *s_data, size_t s_size);

extern void SSL_inspection_dump_backtrace(void);

extern int SSL_inspection_string_to_sockaddr(int s_family, const char *s_address, int s_port, void *s_sockaddr_ptr, socklen_t *s_socklen_ptr);

extern int SSL_inspection_set_reuse_socket(int s_socket, int s_is_enable);
extern int SSL_inspection_set_naggle_socket(int s_socket, int s_is_enable);
extern int SSL_inspection_set_tx_socket_buffer_size(int s_socket, size_t s_size);
extern int SSL_inspection_set_rx_socket_buffer_size(int s_socket, size_t s_size);

extern int SSL_inspection_is_readable(int s_socket, int s_timeout_msec);
extern int SSL_inspection_is_writable(int s_socket, int s_timeout_msec);

extern ssize_t SSL_inspection_recv(SSL *s_ssl, int s_socket, void *s_data, size_t s_size, int s_timeout_msec);
extern ssize_t SSL_inspection_send(SSL *s_ssl, int s_socket, const void *s_data, size_t s_size, int s_timeout_msec);

extern ssize_t SSL_inspection_recv_fill(SSL *s_ssl, int s_socket, void *s_data, size_t s_size, int s_timeout_msec);
extern ssize_t SSL_inspection_send_fill(SSL *s_ssl, int s_socket, const void *s_data, size_t s_size, int s_timeout_msec);

extern int SSL_inspection_connect(SSL_CTX *s_ssl_ctx, SSL **s_ssl_ptr /* OUT */, int s_socket, const void *s_sockaddr_ptr, socklen_t s_socklen, int s_timeout_msec);
extern int SSL_inspection_simple_connect(SSL_CTX *s_ssl_ctx, SSL **s_ssl_ptr /* OUT */, const char *s_address, int s_port, int s_timeout_msec);

extern ssize_t SSL_inspection_encrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_plaintext, size_t s_plaintext_size, const void *s_aad, size_t s_aad_size, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_ciphertext, void *s_tag);
extern ssize_t SSL_inspection_decrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_ciphertext, size_t s_ciphertext_size, const void *s_aad, size_t s_aad_size, const void *s_tag, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_plaintext);

extern int SSL_inspection_dump_crypto_info(const char *s_title, const void *s_crypto_info_ptr);

extern int SSL_inspection_set_ulp(int s_socket, const void *s_name, size_t s_name_size);
extern int SSL_inspection_set_ulp_tls(int s_socket);
extern void *SSL_inspection_get_crypto_info(int s_socket, int s_is_encrypt, size_t *s_size_ptr);
extern int SSL_inspection_set_crypto_info(int s_socket, int s_is_encrypt, const void *s_crypto_info_ptr, size_t s_crypto_info_size);

extern void *SSL_inspection_build_crypto_info(SSL *s_ssl, int s_is_encrypt, size_t *s_size_ptr);

extern void *SSL_inspection_pseudo_encrypt(SSL *s_ssl, int s_socket, const void *s_plaintext_ptr, size_t s_plaintext_size, size_t *s_tls_payload_size_ptr);

extern int SSL_inspection_pseudo_set_ktls_forward(int s_socket_client, int s_socket_server, unsigned int s_flags);
#endif

/* ---- */

#if !defined(__def_sslid_source_test_vector_c__)
extern int SSL_inspection_sha256_test0(int s_is_verbose);

extern int SSL_inspection_hmac_sha256_test0(int s_is_verbose);
extern int SSL_inspection_hmac_sha256_test1(int s_is_verbose);

extern int SSL_inspection_pseudo_random_function_tlsv1_2_sha256_test0(int s_is_verbose);

extern int SSL_inspection_evp_test0(int s_is_verbose);
extern int SSL_inspection_evp_test1(int s_is_verbose);

extern int SSL_inspection_internal_impl_test0(int s_is_verbose);
#endif

/* ---- */

#if !defined(__def_sslid_source_signal_handler_c__)
extern void SSL_inspection_break_main_loop(void);
extern int SSL_inspection_is_break_main_loop(void);

extern int SSL_inspection_install_signal_handler(void);
#endif

/* ---- */

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
