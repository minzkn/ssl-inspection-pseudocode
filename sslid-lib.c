/*
	Copyright (C) MINZKN.COM
	All rights reserved.
	Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_sslid_lib_c__)
# define __def_sslid_source_sslid_lib_c__ "sslid-lib.c"

#include "sslid-lib.h"

#include <sys/syscall.h>

#if 0L
# define def_SSL_inspection_recv_flags 0
# define def_SSL_inspection_send_flags 0
#else
# define def_SSL_inspection_recv_flags MSG_NOSIGNAL
# define def_SSL_inspection_send_flags MSG_NOSIGNAL
#endif

/* in OpenSSL source "crypto/evp/e_aes.c" - 각 OpenSSL 버젼마다 다를 수 있는 부분 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
# ifdef  TABLE_BITS /* Even though permitted values for TABLE_BITS are 8, 4 and 1, it should never be set to 8 [or 1]. For further information see gcm128.c.*/
#  undef  TABLE_BITS
# endif
# define TABLE_BITS 4
# define u64 uint64_t
# define u32 uint32_t
# define u8 uint8_t
typedef struct {
	u64 hi, lo;
} u128;
typedef struct {
    /* Following 6 names follow names in GCM specification */
    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Relative position of Xi, H and pre-computed Htable is used in some
     * assembler modules, i.e. don't change the order!
     */
#if TABLE_BITS==8
    u128 Htable[256];
#else
    u128 Htable[16];
    void (*gmult) (u64 Xi[2], const u128 Htable[16]);
    void (*ghash) (u64 Xi[2], const u128 Htable[16], const u8 *inp,
                   size_t len);
#endif
    unsigned int mres, ares;
    block128_f block;
    void *key;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    unsigned char Xn[48];
#endif
}gcm128_context_alias;
typedef struct {
    union {
        double align;
        AES_KEY ks;
    } ks;                       /* AES key schedule to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    gcm128_context_alias gcm;
    unsigned char *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */
    ctr128_f ctr;
} EVP_AES_GCM_CTX;
#else
# ifdef  TABLE_BITS /* Even though permitted values for TABLE_BITS are 8, 4 and 1, it should never be set to 8 [or 1]. For further information see gcm128.c.*/
#  undef  TABLE_BITS
# endif
# define TABLE_BITS 4
# define u64 uint64_t
# define u32 uint32_t
# define u8 uint8_t
typedef struct {
	u64 hi, lo;
} u128;
typedef struct {
    /* Following 6 names follow names in GCM specification */
    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Relative position of Xi, H and pre-computed Htable is used in some
     * assembler modules, i.e. don't change the order!
     */
#if TABLE_BITS==8
    u128 Htable[256];
#else
    u128 Htable[16];
    void (*gmult) (u64 Xi[2], const u128 Htable[16]);
    void (*ghash) (u64 Xi[2], const u128 Htable[16], const u8 *inp,
                   size_t len);
#endif
    unsigned int mres, ares;
    block128_f block;
    void *key;
}gcm128_context_alias;
typedef struct {
	union {
		double align;
		AES_KEY ks;
	} ks;                       /* AES key schedule to use */
	int key_set;                /* Set if key initialised */
	int iv_set;                 /* Set if an iv is set */
	gcm128_context_alias gcm;
	unsigned char *iv;          /* Temporary IV store */
	int ivlen;                  /* IV length */
	int taglen;
	int iv_gen;                 /* It is OK to generate IVs */
	int tls_aad_len;            /* TLS AAD length */
	ctr128_f ctr;
}EVP_AES_GCM_CTX;
#endif

#include <execinfo.h>

void *SSL_inspection_increment_be_block(void *s_bigint_ptr, size_t s_size);
void *SSL_inspection_xor_block(void *s_to_ptr, const void *s_from_ptr, size_t s_size);
void *SSL_inspection_right_shift_block(void *s_block_ptr, size_t s_size);

int SSL_inspection_is_printable_ascii(int s_charactor, int s_is_level);
void *SSL_inspection_convert_printable_ascii(void *s_to, const void *s_from, size_t s_size);
const void *SSL_inspection_hexdump(const char *s_prefix, const void *s_data, size_t s_size);

void SSL_inspection_dump_backtrace(void);

int SSL_inspection_string_to_sockaddr(int s_family, const char *s_address, int s_port, void *s_sockaddr_ptr, socklen_t *s_socklen_ptr);

int SSL_inspection_set_reuse_socket(int s_socket, int s_is_enable);
int SSL_inspection_set_naggle_socket(int s_socket, int s_is_enable);
int SSL_inspection_set_tx_socket_buffer_size(int s_socket, size_t s_size);
int SSL_inspection_set_rx_socket_buffer_size(int s_socket, size_t s_size);

int SSL_inspection_is_readable(int s_socket, int s_timeout_msec);
int SSL_inspection_is_writable(int s_socket, int s_timeout_msec);

ssize_t SSL_inspection_recv(SSL *s_ssl, int s_socket, void *s_data, size_t s_size, int s_timeout_msec);
ssize_t SSL_inspection_send(SSL *s_ssl, int s_socket, const void *s_data, size_t s_size, int s_timeout_msec);

ssize_t SSL_inspection_recv_fill(SSL *s_ssl, int s_socket, void *s_data, size_t s_size, int s_timeout_msec);
ssize_t SSL_inspection_send_fill(SSL *s_ssl, int s_socket, const void *s_data, size_t s_size, int s_timeout_msec);

static SSL *__SSL_inspection_ssl_connect(SSL_CTX *s_ssl_ctx, int s_socket, int s_timeout_msec);
int SSL_inspection_connect(SSL_CTX *s_ssl_ctx, SSL **s_ssl_ptr /* OUT */, int s_socket, const void *s_sockaddr_ptr, socklen_t s_socklen, int s_timeout_msec);
int SSL_inspection_simple_connect(SSL_CTX *s_ssl_ctx, SSL **s_ssl_ptr /* OUT */, const char *s_address, int s_port, int s_timeout_msec);

ssize_t SSL_inspection_encrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_plaintext, size_t s_plaintext_size, const void *s_aad, size_t s_aad_size, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_ciphertext, void *s_tag);
ssize_t SSL_inspection_decrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_ciphertext, size_t s_ciphertext_size, const void *s_aad, size_t s_aad_size, const void *s_tag, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_plaintext);

int SSL_inspection_dump_crypto_info(const char *s_title, const void *s_crypto_info_ptr);

int SSL_inspection_set_ulp(int s_socket, const void *s_name, size_t s_name_size);
int SSL_inspection_set_ulp_tls(int s_socket);
void *SSL_inspection_get_crypto_info(int s_socket, int s_is_encrypt, size_t *s_size_ptr);
int SSL_inspection_set_crypto_info(int s_socket, int s_is_encrypt, const void *s_crypto_info_ptr, size_t s_crypto_info_size);

void *SSL_inspection_build_crypto_info(SSL *s_ssl, int s_is_encrypt, size_t *s_size_ptr);

void *SSL_inspection_pseudo_encrypt(SSL *s_ssl, int s_socket, const void *s_plaintext_ptr, size_t s_plaintext_size, size_t *s_tls_payload_size_ptr);

int SSL_inspection_pseudo_set_ktls_forward(int s_socket_client, int s_socket_server, unsigned int s_flags);

void *SSL_inspection_increment_be_block(void *s_bigint_ptr, size_t s_size)
{
	if(s_size <= ((size_t)0u)) {
		return(s_bigint_ptr);
	}

	if((s_size % ((size_t)4u)) == ((size_t)0u)) { /* aligned 32bits */
		uint32_t *s_uint32_ptr = (uint32_t *)s_bigint_ptr;
		uint32_t s_uint32;

		s_size /= (size_t)4u;
		do {
			s_uint32 = ntohl(s_uint32_ptr[--s_size]);
			++s_uint32;
			s_uint32_ptr[s_size] = htonl(s_uint32);
		}while((s_size > ((size_t)0u)) && (s_uint32 == ((uint32_t)0u)) /* is overflow */);
	}
	else { /* not aligned 32bits */
		uint8_t *s_uint8_ptr = (uint8_t *)s_bigint_ptr;

		do {
			++s_uint8_ptr[--s_size];
		}while((s_size > ((size_t)0u)) && (s_uint8_ptr[s_size] == ((uint8_t)0u)) /* is overflow */);
	}

	return(s_bigint_ptr);
}

void *SSL_inspection_xor_block(void *s_to_ptr, const void *s_from_ptr, size_t s_size)
{
	if(s_size <= ((size_t)0u)) {
		return(s_to_ptr);
	}

	if((s_size % ((size_t)4u)) == ((size_t)0u)) { /* aligned 32bits */
		uint32_t *s_to = (uint32_t *)s_to_ptr;
		const uint32_t *s_from = (const uint32_t *)s_from_ptr;

		s_size /= (size_t)4u;
		do {
			--s_size;
			s_to[s_size] ^= s_from[s_size];
		}while(s_size > ((size_t)0u));
	}
	else { /* not aligned 32bits */
		uint8_t *s_to = (uint8_t *)s_to_ptr;
		const uint8_t *s_from = (const uint8_t *)s_from_ptr;

		do {
			--s_size;
			s_to[s_size] ^= s_from[s_size];
		}while(s_size > ((size_t)0u));
	}

	return(s_to_ptr);
}

void *SSL_inspection_right_shift_block(void *s_block_ptr, size_t s_size)
{
	uint8_t *s_uint8_ptr;

	if(s_size <= ((size_t)0u)) {
		return(s_block_ptr);
	}

	for(s_uint8_ptr = (uint8_t *)s_block_ptr;;) {
		--s_size;
		s_uint8_ptr[s_size] = (s_uint8_ptr[s_size] >> 1);
		if(s_size <= ((size_t)0u)) {
			break;
		}

		if(s_uint8_ptr[s_size - ((size_t)1u)] & ((uint8_t)0x01u)) {
			s_uint8_ptr[s_size] |= (uint8_t)0x80u;
		}
	}

	return(s_block_ptr);
}

int SSL_inspection_is_printable_ascii(int s_charactor, int s_is_level)
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

void *SSL_inspection_convert_printable_ascii(void *s_to, const void *s_from, size_t s_size)
{
	unsigned char *s_to_buffer = (unsigned char *)s_to;
	const unsigned char *s_from_buffer = (const unsigned char *)s_from;
	size_t s_offset;

	if(s_to == ((void *)0)) {
		union {
			const void *m_const_ptr;
			void *m_ptr;
		}s_ptr;

		s_ptr.m_const_ptr = s_from;
		s_to = s_ptr.m_ptr;
	}

	for(s_offset = (size_t)0u;s_offset < s_size;s_offset++) {
		if(SSL_inspection_is_printable_ascii((int)s_from_buffer[s_offset], 1) == 0) {
			/* filter */
			s_to_buffer[s_offset] = (unsigned char)'.';
		}
		else if(s_to != s_from) {
			s_to_buffer[s_offset] = s_from_buffer[s_offset];
		}
	}

	return(s_to);
}

const void *SSL_inspection_hexdump(const char *s_prefix, const void *s_data, size_t s_size)
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
			if(SSL_inspection_is_printable_ascii((int)s_b[s_lo], 0) == 0) {
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

void SSL_inspection_dump_backtrace(void)
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

int SSL_inspection_string_to_sockaddr(int s_family, const char *s_address, int s_port, void *s_sockaddr_ptr, socklen_t *s_socklen_ptr)
{
	socklen_t s_socklen;
	size_t s_offset;

	if(s_family == AF_UNSPEC) {
		if(SSL_inspection_string_to_sockaddr(AF_INET, s_address, s_port, s_sockaddr_ptr, s_socklen_ptr) == 0) {
			return(0);
		}
		if(SSL_inspection_string_to_sockaddr(AF_INET6, s_address, s_port, s_sockaddr_ptr, s_socklen_ptr) == 0) {
			return(0);
		}
#if defined(AF_UNIX) || defined(AF_FILE) || defined(AF_LOCAL)
# if defined(AF_UNIX)
		if(SSL_inspection_string_to_sockaddr(AF_UNIX, s_address, s_port, s_sockaddr_ptr, s_socklen_ptr) == 0) {
			return(0);
		}
# elif defined(AF_FILE)
		if(SSL_inspection_string_to_sockaddr(AF_FILE, s_address, s_port, s_sockaddr_ptr, s_socklen_ptr) == 0) {
			return(0);
		}
# elif defined(AF_LOCAL)
		if(SSL_inspection_string_to_sockaddr(AF_LOCAL, s_address, s_port, s_sockaddr_ptr, s_socklen_ptr) == 0) {
			return(0);
		}
# endif

		return(-1);
#endif
	}

	if(s_socklen_ptr == ((socklen_t *)0)) {
		s_socklen = (socklen_t)0;
	}
	else {
		s_socklen = *s_socklen_ptr;
	}

	if(s_address != ((const char *)0)) {
		if(strlen(s_address) <= ((size_t)0u)) {
			s_address = (const char *)0;
		}
	}

	if(s_family == AF_INET) {
		struct in_addr s_in_addr;
		struct sockaddr_in *s_sockaddr_in;

		if((s_socklen > ((socklen_t)0)) && (s_socklen < sizeof(struct sockaddr_in))) {
			/* not enough socklen */
			errno = EINVAL;
			return(-1);
		}

		if(s_port > 65535) {
			errno = EINVAL;
			return(-1);
		}
		if(s_port < 0) {
			s_port = 0;
		}

		if(s_address == ((const char *)0)) {
			s_in_addr.s_addr = htonl(INADDR_ANY);
		}
		else {
			for(s_offset = (size_t)0u;s_address[s_offset] != '\0';s_offset++) {
				if((isdigit(s_address[s_offset]) == 0) &&
					(s_address[s_offset] != '.')) {
					errno = EINVAL;
					return(-1);
				}
			}

			/* IPv4 address string validation check */
			if(inet_pton(s_family, s_address, (void *)(&s_in_addr)) <= 0) {
				return(-1);
			}
		}

		s_socklen = (socklen_t)sizeof(struct sockaddr_in);
		if(s_socklen_ptr != ((socklen_t *)0)) {
			*s_socklen_ptr = s_socklen;
		}

		s_sockaddr_in = (struct sockaddr_in *)memset(s_sockaddr_ptr, 0, (size_t)s_socklen);
		s_sockaddr_in->sin_family = (sa_family_t)s_family;
		s_sockaddr_in->sin_addr.s_addr = s_in_addr.s_addr;
		s_sockaddr_in->sin_port = htons((uint16_t)s_port);

		return(0);
	}

	if(s_family == AF_INET6) {
		struct in6_addr s_in6_addr;
		struct sockaddr_in6 *s_sockaddr_in6;

		if((s_socklen > ((socklen_t)0)) && (s_socklen < sizeof(struct sockaddr_in6))) {
			/* not enough socklen */
			errno = EINVAL;
			return(-1);
		}

		if(s_port > 65535) {
			errno = EINVAL;
			return(-1);
		}
		if(s_port < 0) {
			s_port = 0;
		}

		if(s_address == ((const char *)0)) {
			s_in6_addr = in6addr_any;
		}
		else {
			for(s_offset = (size_t)0u;s_address[s_offset] != '\0';s_offset++) {
				if((isxdigit(s_address[s_offset]) == 0) &&
					(s_address[s_offset] != ':') &&
					(s_address[s_offset] != '.')) {
					errno = EINVAL;
					return(-1);
				}
			}

			/* IPv6 address string validation check */
			if(inet_pton(s_family, s_address, (void *)(&s_in6_addr)) <= 0) {
				return(-1);
			}
		}

		s_socklen = (socklen_t)sizeof(struct sockaddr_in6);
		if(s_socklen_ptr != ((socklen_t *)0)) {
			*s_socklen_ptr = s_socklen;
		}

		s_sockaddr_in6 = (struct sockaddr_in6 *)memset(s_sockaddr_ptr, 0, (size_t)s_socklen);
		s_sockaddr_in6->sin6_family = (sa_family_t)s_family;
		s_sockaddr_in6->sin6_addr = s_in6_addr;
		s_sockaddr_in6->sin6_port = htons((uint16_t)s_port);

		return(0);
	}

#if defined(AF_UNIX) || defined(AF_FILE) || defined(AF_LOCAL)
	if(
# if defined(AF_UNIX)
		s_family == AF_UNIX
# elif defined(AF_FILE)
		s_family == AF_FILE
# elif defined(AF_LOCAL)
		s_family == AF_LOCAL
# else
		0
# endif
	  ) {
		struct sockaddr_un *s_sockaddr_un;

		if((s_socklen > ((socklen_t)0)) && (s_socklen < sizeof(struct sockaddr_un))) {
			/* not enough socklen */
			errno = EINVAL;
			return(-1);
		}

		/* sun-path string validation check */
		if(s_address == ((const char *)0)) { /* "" (unnamed path) */
			s_address = "";
		}
		else {
			int s_is_valid_sun_path;

			s_is_valid_sun_path = 0;

			if(s_address[0] == '/') { /* "/XXX" */
				s_is_valid_sun_path = 1;
			}
			else if(s_address[0] == '.') {
				if(s_address[1] == '.') {
					if(s_address[2] == '/') { /* "../XXX" */
						s_is_valid_sun_path = 1;
					}
				}
				else if(s_address[1] == '/') { /* "./XXX" */
					s_is_valid_sun_path = 1;
				}
			}
			else if(s_address[0] == '~') {
				if(s_address[1] == '/') { /* "~/XXX" */
					s_is_valid_sun_path = 1;
				}
			}

			if(s_is_valid_sun_path == 0) {
				errno = EINVAL;
				return(-1);
			}
		}

		s_socklen = (socklen_t)sizeof(struct sockaddr_un);
		if(s_socklen_ptr != ((socklen_t *)0)) {
			*s_socklen_ptr = s_socklen;
		}

		s_sockaddr_un = (struct sockaddr_un *)memset(s_sockaddr_ptr, 0, (size_t)s_socklen);
		s_sockaddr_un->sun_family = (sa_family_t)s_family;
		(void)snprintf((char *)(&s_sockaddr_un->sun_path), sizeof(s_sockaddr_un->sun_path), "%s", s_address);
#if !defined(__linux__) /* BSD like */
		s_sockaddr_un->sun_len = (sizeof(struct sockaddr_un) - sizeof(((struct sockaddr_un *)0)->sun_path)) + strlen((const char *)s_sockaddr_un->sun_path);
#endif

		return(0);
	}
#endif

	/* unknown address family */

	errno = EINVAL;

	return(-1);
}

int SSL_inspection_set_reuse_socket(int s_socket, int s_is_enable)
{
	int s_value;

	s_value = (s_is_enable == 0) ? 0 : 1;

	return(setsockopt(s_socket, SOL_SOCKET, SO_REUSEADDR, (const void *)(&s_value), (socklen_t)sizeof(s_value)));
}

int SSL_inspection_set_naggle_socket(int s_socket, int s_is_enable)
{
    int s_value;

    s_value = (s_is_enable == 0) ? 1 /* naggle disabled */ : 2 /* naggle enabled */;
    
    return(setsockopt(s_socket, IPPROTO_TCP, (int)(TCP_NODELAY), (const void *)(&s_value), (socklen_t)sizeof(s_value)));
}

int SSL_inspection_set_tx_socket_buffer_size(int s_socket, size_t s_size)
{
    int s_value;

    s_value = (int)s_size;

    return(setsockopt(s_socket, (int)(SOL_SOCKET), (int)(SO_SNDBUF), (const void *)(&s_value), (socklen_t)sizeof(s_value)));
}

int SSL_inspection_set_rx_socket_buffer_size(int s_socket, size_t s_size)
{
    int s_value;

    s_value = (int)s_size;

    return(setsockopt(s_socket, (int)(SOL_SOCKET), (int)(SO_RCVBUF), (const void *)(&s_value), (socklen_t)sizeof(s_value)));
}

int SSL_inspection_is_readable(int s_socket, int s_timeout_msec)
{
	fd_set s_fd_set;
	struct timeval s_timeval_local;
	struct timeval *s_timeval;

	int s_select_check;

	FD_ZERO(&s_fd_set);
	FD_SET(s_socket, &s_fd_set);

	if(s_timeout_msec < 0) {
		s_timeval = (struct timeval *)0;
	}
	else {
		s_timeval = (struct timeval *)(&s_timeval_local);
		s_timeval->tv_sec = s_timeout_msec / 1000;
		s_timeval->tv_usec = (s_timeout_msec % 1000) * 1000;
	}

	s_select_check = select(
			s_socket + 1,
			(fd_set *)(&s_fd_set),
			(fd_set *)0,
			(fd_set *)0,
			s_timeval
			);
	if(s_select_check == (-1)) {
		/* EINTR ? */
		return(-1);
	}

	if((s_select_check > 0) && (FD_ISSET(s_socket, &s_fd_set))) {
		return(s_select_check);
	}

	return(0);
}

int SSL_inspection_is_writable(int s_socket, int s_timeout_msec)
{
	fd_set s_fd_set;
	struct timeval s_timeval_local;
	struct timeval *s_timeval;

	int s_select_check;

	FD_ZERO(&s_fd_set);
	FD_SET(s_socket, &s_fd_set);

	if(s_timeout_msec < 0) {
		s_timeval = (struct timeval *)0;
	}
	else {
		s_timeval = (struct timeval *)(&s_timeval_local);
		s_timeval->tv_sec = s_timeout_msec / 1000;
		s_timeval->tv_usec = (s_timeout_msec % 1000) * 1000;
	}

	s_select_check = select(
		s_socket + 1,
		(fd_set *)0,
		(fd_set *)(&s_fd_set),
		(fd_set *)0,
		s_timeval
	);
	if(s_select_check == (-1)) {
		/* EINTR ? */
		return(-1);
	}

	if((s_select_check > 0) && (FD_ISSET(s_socket, &s_fd_set))) {
		return(s_select_check);
	}

	return(0);
}

ssize_t SSL_inspection_recv(SSL *s_ssl, int s_socket, void *s_data, size_t s_size, int s_timeout_msec)
{
	ssize_t s_read_bytes;
	int s_check;

	if(s_socket == (-1)) {
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	if(s_ssl != ((SSL *)0)) {
		int s_flags;
		int s_ssl_read_bytes;
		int s_ssl_error;

		s_flags = fcntl(s_socket, F_GETFL, 0);
		if(s_flags != (-1)) {
			(void)fcntl(s_socket, F_SETFL, s_flags | O_NONBLOCK);
		}
		for(;;) {
			if(SSL_pending(s_ssl) <= 0) {
				s_check = SSL_inspection_is_readable(s_socket, s_timeout_msec);
				if(s_check == (-1)) {
					return((ssize_t)(-1));
				}
				if(s_check == 0) {
					errno = ETIME;
					return((ssize_t)(-1));
				}
			}

			s_ssl_read_bytes = SSL_read(s_ssl, s_data, (int)s_size);
			if(s_ssl_read_bytes > 0) {
				s_read_bytes = (ssize_t)s_ssl_read_bytes;
				break;
			}
			if(s_ssl_read_bytes == 0) { /* disconnected */
				s_read_bytes = (ssize_t)0;
				break;
			}

			s_ssl_error = SSL_get_error(s_ssl, s_ssl_read_bytes);
			if(s_ssl_error == SSL_ERROR_WANT_READ) {
				continue;
			}
			else if(s_ssl_error == SSL_ERROR_WANT_WRITE) {
				continue;
			}
			else if(s_ssl_error == SSL_ERROR_ZERO_RETURN) { /* disconnected */
				s_read_bytes = (ssize_t)0;
				break;
			}
#if 0L
			else if(s_ssl_error == SSL_ERROR_SYSCALL) {
				s_read_bytes = (ssize_t)(-1);
				break;
			}
			else if(s_ssl_error == SSL_ERROR_SSL) {
				s_read_bytes = (ssize_t)(-1);
				break;
			}
#endif
			else {
				unsigned long s_error_code;

				for(;;) {
					s_error_code = ERR_get_error();
					if(s_error_code == 0UL) {
						break;
					}
					
					(void)fprintf(
						stderr,
						"SSL_inspection_recv failed ! (%lu: \"%s\")\n",
						s_error_code,
						ERR_error_string(s_error_code, NULL)
					);
				}

				s_read_bytes = (ssize_t)(-1);
				break;
			}
		}
		if(s_flags != (-1)) {
			(void)fcntl(s_socket, F_SETFL, s_flags);
		}

		return(s_read_bytes);
	}

	if(s_timeout_msec >= 0) {
		s_check = SSL_inspection_is_readable(s_socket, s_timeout_msec);
		if(s_check == (-1)) {
			return((ssize_t)(-1));
		}
		if(s_check == 0) {
			errno = ETIME;
			return((ssize_t)(-1));
		}
	}

	s_read_bytes = recv(s_socket, s_data, s_size, def_SSL_inspection_recv_flags); 

	return(s_read_bytes);
}

ssize_t SSL_inspection_send(SSL *s_ssl, int s_socket, const void *s_data, size_t s_size, int s_timeout_msec)
{
	ssize_t s_write_bytes;
	int s_check;

	if(s_socket == (-1)) {
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	if(s_size <= ((size_t)0u)) {
		return((ssize_t)0);
	}

	if(s_ssl != ((SSL *)0)) {
		int s_flags;
		int s_ssl_write_bytes;
		int s_ssl_error;

		s_flags = fcntl(s_socket, F_GETFL, 0);
		if(s_flags != (-1)) {
			(void)fcntl(s_socket, F_SETFL, s_flags | O_NONBLOCK);
		}
		for(;;) {
			s_check = SSL_inspection_is_writable(s_socket, s_timeout_msec);
			if(s_check == (-1)) {
				s_write_bytes = (ssize_t)(-1);
				break;
			}
			if(s_check == 0) {
				errno = ETIME;
				s_write_bytes = (ssize_t)(-1);
				break;
			}

			s_ssl_write_bytes = SSL_write(s_ssl, s_data, (int)s_size);
			if(s_ssl_write_bytes > 0) {
				s_write_bytes = (ssize_t)s_ssl_write_bytes;
				break;
			}

			s_ssl_error = SSL_get_error(s_ssl, s_ssl_write_bytes);
			if(s_ssl_error == SSL_ERROR_WANT_READ) {
				continue;
			}
			else if(s_ssl_error == SSL_ERROR_WANT_WRITE) {
				continue;
			}
			else if(s_ssl_error == SSL_ERROR_ZERO_RETURN) { /* disconnected */
				s_write_bytes = (ssize_t)(-1);
				break;
			}
#if 0L
			else if(s_ssl_error == SSL_ERROR_SYSCALL) {
				s_write_bytes = (ssize_t)(-1);
				break;
			}
			else if(s_ssl_error == SSL_ERROR_SSL) {
				s_write_bytes = (ssize_t)(-1);
				break;
			}
#endif
			else {
				s_write_bytes = (ssize_t)(-1);
				break;
			}
		}
		if(s_flags != (-1)) {
			(void)fcntl(s_socket, F_SETFL, s_flags);
		}

		return(s_write_bytes);
	}

	if(s_timeout_msec >= 0) {
		s_check = SSL_inspection_is_writable(s_socket, s_timeout_msec);
		if(s_check == (-1)) {
			return((ssize_t)(-1));
		}
		if(s_check == 0) {
			errno = ETIME;
			return((ssize_t)(-1));
		}
	}

	s_write_bytes = send(s_socket, s_data, s_size, def_SSL_inspection_send_flags);

	return(s_write_bytes);
}

ssize_t SSL_inspection_recv_fill(SSL *s_ssl, int s_socket, void *s_data, size_t s_size, int s_timeout_msec)
{
	ssize_t s_read_bytes;
	size_t s_offset;

	for(s_offset = (size_t)0u;s_offset < s_size;) {
		s_read_bytes = SSL_inspection_recv(
			s_ssl,
			s_socket,
			(void *)(((char *)s_data) + s_offset),
			s_size - s_offset,
			s_timeout_msec
		);
		if(s_read_bytes == ((ssize_t)(-1))) {
			return((ssize_t)(-1));
		}
		if(s_read_bytes == ((ssize_t)0)) { /* disconnected */
			return((ssize_t)0);
		}

		s_offset += (size_t)s_read_bytes;
	}

	return((ssize_t)s_offset);
}

ssize_t SSL_inspection_send_fill(SSL *s_ssl, int s_socket, const void *s_data, size_t s_size, int s_timeout_msec)
{
	ssize_t s_write_bytes;
	size_t s_offset;

	for(s_offset = (size_t)0u;s_offset < s_size;) {
		s_write_bytes = SSL_inspection_send(
			s_ssl,
			s_socket,
			(const void *)(((const char *)s_data) + s_offset),
			s_size - s_offset,
			s_timeout_msec
		);
		if(s_write_bytes == ((ssize_t)(-1))) {
			return((ssize_t)(-1));
		}
		if(s_write_bytes == ((ssize_t)0)) { /* disconnected */
			return((ssize_t)(-1));
		}

		s_offset += (size_t)s_write_bytes;
	}

	return((ssize_t)s_offset);
}

static SSL *__SSL_inspection_ssl_connect(SSL_CTX *s_ssl_ctx, int s_socket, int s_timeout_msec)
{
	SSL *s_ssl;
	int s_errno;
	int s_flags;
	int s_ssl_check;

	s_ssl = SSL_new(s_ssl_ctx);
	if(s_ssl == ((SSL *)0)) {
		errno = ENOMEM;
		return((SSL *)0);
	}

	if(SSL_set_fd(s_ssl, s_socket) <= 0) {
		SSL_free(s_ssl);
		errno = EINVAL;
		return((SSL *)0);
	}

	s_flags = fcntl(s_socket, F_GETFL, 0);
	if(s_flags != (-1)) {
		/* 비동기 SSL connection 처리 */
		/* non-blocking 설정을 하여 SSL_connect 에서 비동기 수행하도록 합니다. */
		(void)fcntl(s_socket, F_SETFL, s_flags | O_NONBLOCK);
	}
	for(;;) {
		s_ssl_check = SSL_connect(s_ssl);
		s_errno = errno;
		if(s_ssl_check == 0) {
			/* The TLS/SSL handshake was not successful but was shut down controlled and by the specifications of the TLS/SSL protocol. */
			break;
		}
		else if(s_ssl_check == 1) {
			/* The TLS/SSL handshake was successfully completed, a TLS/SSL connection has been established. */
			break;
		}
		else if(s_ssl_check < 0) {
			int s_ssl_error;
			int s_select_check;

			s_ssl_error = SSL_get_error(s_ssl, s_ssl_check);
			s_errno = errno;
			if(s_ssl_error == SSL_ERROR_WANT_READ) {
				s_select_check = SSL_inspection_is_readable(s_socket, s_timeout_msec);
				if(s_select_check == (-1)) {
					break;
				}
				if(s_select_check == 0) {
					break;
				}

				continue;
			}
			if(s_ssl_error == SSL_ERROR_WANT_WRITE) {
				s_select_check = SSL_inspection_is_writable(s_socket, s_timeout_msec);
				if(s_select_check == (-1)) {
					break;
				}
				if(s_select_check == 0) {
					break;
				}

				continue;
			}

			if(s_ssl_error == SSL_ERROR_SYSCALL) { /* 일부 플랫폼에서는 별도의 처리를 요구함 */
				if((s_errno == EINPROGRESS) || (s_errno == EAGAIN) || (s_errno == EINTR)) { /* is progress ? */
					if(SSL_want_write(s_ssl)) {
						s_select_check = SSL_inspection_is_writable(s_socket, s_timeout_msec);
						if(s_select_check == (-1)) {
							break;
						}
						if(s_select_check == 0) {
							break;
						}

						continue;
					}
					else if(SSL_want_read(s_ssl)) {
						s_select_check = SSL_inspection_is_readable(s_socket, s_timeout_msec);
						if(s_select_check == (-1)) {
							break;
						}
						if(s_select_check == 0) {
							break;
						}

						continue;
					}
				}

				/* socket error */
				break;
			}
			else {
				/* SSL error */
				s_ssl_check = (-1);
				break;
			}
		}
		else { /* what happen ? */
			break;
		}
	}
	if(s_flags != (-1)) {
		/* non-blocking 유무를 복구합니다. */
		(void)fcntl(s_socket, F_SETFL, s_flags);
	}

	if(s_ssl_check <= 0) {
		unsigned long s_ssl_error;

		for(;;) { /* make sure the OpenSSL error queue is empty */
			s_ssl_error = ERR_get_error();
			if(s_ssl_error == 0UL) {
				break;
			}

			(void)fprintf(stderr, "SSL_connect failed ! (\"%s\")\n", ERR_error_string(s_ssl_error, NULL));
		}

		SSL_free(s_ssl);
		errno = s_errno;
		return((SSL *)0);
	}

	return(s_ssl);
}

int SSL_inspection_connect(SSL_CTX *s_ssl_ctx, SSL **s_ssl_ptr, int s_socket, const void *s_sockaddr_ptr, socklen_t s_socklen, int s_timeout_msec)
{
	int s_flags;
	int s_check;
	int s_errno;
		
	if(s_ssl_ptr != ((SSL **)0)) {
		*s_ssl_ptr = (SSL *)0;
	}

	s_flags = 0;
	if(s_timeout_msec >= 0) {
		s_flags = fcntl(s_socket, F_GETFL, 0);
		if(s_flags != (-1)) {
			(void)fcntl(s_socket, F_SETFL, s_flags | O_NONBLOCK);
		}
	}

	s_check = connect(s_socket, (const struct sockaddr *)s_sockaddr_ptr, s_socklen);
	s_errno = errno;

	if(s_timeout_msec >= 0) {
		if(s_flags != (-1)) {
			(void)fcntl(s_socket, F_SETFL, s_flags);
		}
	}

	if(s_check == 0) { /* connected */
l_connected:;		
		errno = 0;

		if(s_ssl_ctx == ((SSL_CTX *)0)) { /* TCP connected */
			return(0);
		}

		if(s_ssl_ptr == ((SSL **)0)) {
			errno = EINVAL;
			return(-1);
		}

		/* SSL connect */
		*s_ssl_ptr = __SSL_inspection_ssl_connect(s_ssl_ctx, s_socket, s_timeout_msec);
		if(*s_ssl_ptr == ((SSL *)0)) {
			return(-1);
		}

		return(0);
	}

	if(s_check != (-1)) { /* what happen ? */
		errno = EINVAL;
		return(-1);
	}

	if(s_timeout_msec <= 0) {
		errno = s_errno;
		return(-1);
	}

	s_check = (-1);

#if defined(ENETUNREACH)
	if(s_errno == ENETUNREACH) { /* Network is unreachable */
		/* maybe not assigned any ip */
		errno = s_errno;
		return(-1);
	}
#endif

	if(s_errno == EINPROGRESS) { /* Linux */
		s_check = 0;
	}
	if(s_errno == EAGAIN) {
		s_check = 0;
	}

	if(s_check == 0) {
		fd_set s_fd_set_rx;
		fd_set s_fd_set_tx;
		fd_set s_fd_set_ex;

		struct timeval s_timeval_local;
		struct timeval *s_timeval;

		FD_ZERO(&s_fd_set_rx);
		FD_ZERO(&s_fd_set_tx);
		FD_ZERO(&s_fd_set_ex);

		FD_SET(s_socket, &s_fd_set_rx);
		FD_SET(s_socket, &s_fd_set_tx);
		FD_SET(s_socket, &s_fd_set_ex);

		if(s_timeout_msec < 0) {
			s_timeval = (struct timeval *)0;
		}
		else {
			s_timeval = (struct timeval *)(&s_timeval_local);
			s_timeval->tv_sec = s_timeout_msec / 1000;
			s_timeval->tv_usec = (s_timeout_msec % 1000) * 1000;
		}

		s_check = select(s_socket + 1, (fd_set *)(&s_fd_set_rx), (fd_set *)(&s_fd_set_tx), (fd_set *)(&s_fd_set_ex), s_timeval);
		if(s_check == (-1)) {
			s_errno = errno;
		}
		else if((s_check > 0) && ((FD_ISSET(s_socket, &s_fd_set_rx)) || (FD_ISSET(s_socket, &s_fd_set_tx)) || (FD_ISSET(s_socket, &s_fd_set_ex)))) {
			socklen_t s_sockerr_size;
			int s_sockerr;

			s_sockerr = 0;
			s_sockerr_size = (socklen_t)sizeof(s_sockerr);
			s_check = getsockopt(s_socket, SOL_SOCKET, SO_ERROR, (void *)(&s_sockerr), (socklen_t *)(&s_sockerr_size));
			if(s_check == (-1)) {
				s_errno = errno;
			}
			else if((s_check == 0) && (s_sockerr == 0)) {
				/* connected */
				goto l_connected;
			}
			else {
				s_errno = s_sockerr;
			}
		}
		else { /* timeout */
			s_errno = ETIMEDOUT;
		}
	}

	errno = s_errno;

	return(-1);
}

int SSL_inspection_simple_connect(SSL_CTX *s_ssl_ctx, SSL **s_ssl_ptr, const char *s_address, int s_port, int s_timeout_msec)
{
	struct sockaddr_storage s_sockaddr_remote;
	socklen_t s_socklen_remote;
	struct sockaddr_storage s_sockaddr_bind;
	socklen_t s_socklen_bind;

	int s_socket;

	int s_check;
		
	if(s_ssl_ptr != ((SSL **)0)) {
		*s_ssl_ptr = (SSL *)0;
	}

	s_socklen_remote = (socklen_t)sizeof(s_sockaddr_remote);
	s_check = SSL_inspection_string_to_sockaddr(
		AF_UNSPEC /* detect address family */,
		s_address,
		s_port,
		(void *)(&s_sockaddr_remote),
		(socklen_t *)(&s_socklen_remote)
	);
	if(s_check == (-1)) {
		return(-1);
	}
	
	s_socklen_bind = (socklen_t)sizeof(s_sockaddr_bind);
	s_check = SSL_inspection_string_to_sockaddr(
		s_sockaddr_remote.ss_family /* by remote */,
		(const char *)0 /* any address */,
		0 /* any port */,
		(void *)(&s_sockaddr_bind),
		(socklen_t *)(&s_socklen_bind)
	);
	if(s_check == (-1)) {
		return(-1);
	}

	if(s_sockaddr_remote.ss_family == AF_INET) {
		s_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); 
	}
	else if(s_sockaddr_remote.ss_family == AF_INET6) {
		s_socket = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP); 
	}
	else {
		errno = EINVAL;
		s_socket = (-1);
	}
	if(s_socket == (-1)) {
		return(-1);
	}

	s_check = bind(
		s_socket, 
		(struct sockaddr *)(&s_sockaddr_bind),
		s_socklen_bind
	);
	if(s_check == (-1)) {
		int s_errno;

		s_errno = errno;
		do {
			s_check = close(s_socket);
		}while((s_check == (-1)) && (errno == EINTR));
		errno = s_errno;

		return(-1);
	}

	s_check = SSL_inspection_connect(s_ssl_ctx, s_ssl_ptr, s_socket, (const void *)(&s_sockaddr_remote), s_socklen_remote, s_timeout_msec);
	if(s_check == (-1)) {
		int s_errno;

		s_errno = errno;
		do {
			s_check = close(s_socket);
		}while((s_check == (-1)) && (errno == EINTR));
		errno = s_errno;

		return(-1);
	}

	return(s_socket);
}

ssize_t SSL_inspection_encrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_plaintext, size_t s_plaintext_size, const void *s_aad, size_t s_aad_size, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_ciphertext, void *s_tag)
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
		(ENGINE *)0 /* engine */,
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
		EVP_CTRL_GCM_SET_IVLEN,
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
		(ENGINE *)0 /* engine */,
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
		EVP_CTRL_GCM_GET_TAG,
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

ssize_t SSL_inspection_decrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_ciphertext, size_t s_ciphertext_size, const void *s_aad, size_t s_aad_size, const void *s_tag, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_plaintext)
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
		(ENGINE *)0 /* engine */,
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
		EVP_CTRL_GCM_SET_IVLEN,
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
		(ENGINE *)0 /* engine */,
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
		(void)fprintf(stderr, "EVP_DecryptUpdate failed !\n");
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
		(void)fprintf(stderr, "EVP_DecryptUpdate failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}
	s_plaintext_size = (ssize_t)s_size;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	s_union_ptr.m_const_ptr = s_tag;
	s_check = EVP_CIPHER_CTX_ctrl(
		s_evp_cipher_ctx,
		EVP_CTRL_GCM_SET_TAG,
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

int SSL_inspection_dump_crypto_info(const char *s_title, const void *s_crypto_info_ptr)
{
	const struct tls_crypto_info *s_tls_crypto_info;

	if(s_crypto_info_ptr == ((const void *)0)) {
		errno = EINVAL;
		return(-1);
	}

	s_tls_crypto_info = (const struct tls_crypto_info *)s_crypto_info_ptr;

	if((s_tls_crypto_info->version == TLS_1_2_VERSION) && (s_tls_crypto_info->cipher_type == TLS_CIPHER_AES_GCM_128)) {
		const struct tls12_crypto_info_aes_gcm_128 *s_crypto_info; /* in kernel header "linux/tls.h" */

		s_crypto_info = (const struct tls12_crypto_info_aes_gcm_128 *)s_crypto_info_ptr;

		(void)fprintf(
			stdout,
			"Dump crypto_info - %s\n",
			(s_title == ((const char *)0)) ? "struct tls12_crypto_info_aes_gcm_128" : s_title 
		);
		(void)fprintf(stdout, "  - version : %08lXH\n", (unsigned long)s_crypto_info->info.version);
		(void)fprintf(stdout, "  - cipher_type : %lu\n", (unsigned long)s_crypto_info->info.cipher_type);
		(void)fprintf(stdout, "  - iv (%lu bytes)\n", (unsigned long)sizeof(s_crypto_info->iv));
		(void)SSL_inspection_hexdump("    ", (const void *)(&s_crypto_info->iv[0]), sizeof(s_crypto_info->iv));
		(void)fprintf(stdout, "  - key (%lu bytes)\n", (unsigned long)sizeof(s_crypto_info->key));
		(void)SSL_inspection_hexdump("    ", (const void *)(&s_crypto_info->key[0]), sizeof(s_crypto_info->key));
		(void)fprintf(stdout, "  - salt (%lu bytes)\n", (unsigned long)sizeof(s_crypto_info->salt));
		(void)SSL_inspection_hexdump("    ", (const void *)(&s_crypto_info->salt[0]), sizeof(s_crypto_info->salt));
		(void)fprintf(stdout, "  - rec_seq (%lu bytes)\n", (unsigned long)sizeof(s_crypto_info->rec_seq));
		(void)SSL_inspection_hexdump("    ", (const void *)(&s_crypto_info->rec_seq[0]), sizeof(s_crypto_info->rec_seq));

		return(0);
	}

	errno = ENOMSG;

	return(-1);
}

int SSL_inspection_set_ulp(int s_socket, const void *s_name, size_t s_name_size)
{
	if(s_socket == (-1)) {
		errno = EINVAL;
		return(-1);
	}

#if defined(SOL_TCP) && defined(TCP_ULP)
	return(
		setsockopt(
			s_socket,
			SOL_TCP,
			TCP_ULP,
			s_name,
			(socklen_t)s_name_size
		)
	);
#else
	errno = EPROTONOSUPPORT;
	return(-1);
#endif
}

int SSL_inspection_set_ulp_tls(int s_socket)
{
	static const char cg_tls_name[] = {"tls"};

	/* ULP/TLS 설정은 ESTABLISHED 된 TCP 연결 socket 에 대해서만 설정 가능합니다. */
	return(
		SSL_inspection_set_ulp(
			s_socket,
			(const void *)(&cg_tls_name[0]),
			sizeof(cg_tls_name) /* 4(3 + 1) bytes */
		)
	);
}

void *SSL_inspection_get_crypto_info(int s_socket, int s_is_encrypt, size_t *s_size_ptr)
{
	if(s_size_ptr != ((size_t *)0)) {
		*s_size_ptr = (size_t)0u;
	}

	if(s_socket == (-1)) {
		errno = EINVAL;
		return((void *)0);
	}

#if defined(SOL_TLS)
# if defined(TLS_RX)
	if(s_is_encrypt == 0) {
		socklen_t s_socklen;
		unsigned char s_buffer[ 16 << 10 ];
		const struct tls_crypto_info *s_tls_crypto_info;
		void *s_crypto_info_ptr;
		int s_check;

		/* step 1 */
		s_socklen = (socklen_t)sizeof(*s_tls_crypto_info);
		s_check = getsockopt(
			s_socket,
			SOL_TLS,
			TLS_RX,
			(void *)(&s_buffer[0]),
			(socklen_t *)(&s_socklen)
		);
		if(s_check == (-1)) {
			return((void *)0);
		}

		if(s_socklen < ((socklen_t)sizeof(*s_tls_crypto_info))) {
			errno = EBADMSG;
			return((void *)0);
		}

		/* step 2 */
		s_tls_crypto_info = (const struct tls_crypto_info *)(&s_buffer[0]);
		if((s_tls_crypto_info->version == TLS_1_2_VERSION) && (s_tls_crypto_info->cipher_type == TLS_CIPHER_AES_GCM_128)) {
			s_socklen = (socklen_t)sizeof(struct tls12_crypto_info_aes_gcm_128);
			s_check = getsockopt(
				s_socket,
				SOL_TLS,
				TLS_RX,
				(void *)(&s_buffer[0]),
				(socklen_t *)(&s_socklen)
			);
			if(s_check == (-1)) {
				return((void *)0);
			}
		
			if(s_socklen < ((socklen_t)sizeof(struct tls12_crypto_info_aes_gcm_128))) {
				errno = EBADMSG;
				return((void *)0);
			}
		}
		else {
			errno = ENOMSG;
			return((void *)0);
		}

		s_crypto_info_ptr = malloc((size_t)s_socklen);
		if(s_crypto_info_ptr == ((void *)0)) {
			errno = ENOMEM;
			return((void *)0);
		}

		if(s_size_ptr != ((size_t *)0)) {
			*s_size_ptr = (size_t)s_socklen;
		}
		
		return(s_crypto_info_ptr);
	}
# endif
# if defined(TLS_TX)
	if(s_is_encrypt != 0) {
		socklen_t s_socklen;
		unsigned char s_buffer[ 16 << 10 ];
		const struct tls_crypto_info *s_tls_crypto_info;
		void *s_crypto_info_ptr;
		int s_check;

		/* step 1 */
		s_socklen = (socklen_t)sizeof(*s_tls_crypto_info);
		s_check = getsockopt(
			s_socket,
			SOL_TLS,
			TLS_TX,
			(void *)(&s_buffer[0]),
			(socklen_t *)(&s_socklen)
		);
		if(s_check == (-1)) {
			return((void *)0);
		}
		
		if(s_socklen < ((socklen_t)sizeof(*s_tls_crypto_info))) {
			errno = EBADMSG;
			return((void *)0);
		}
		
		/* step 2 */
		s_tls_crypto_info = (const struct tls_crypto_info *)(&s_buffer[0]);
		if((s_tls_crypto_info->version == TLS_1_2_VERSION) && (s_tls_crypto_info->cipher_type == TLS_CIPHER_AES_GCM_128)) {
			s_socklen = (socklen_t)sizeof(struct tls12_crypto_info_aes_gcm_128);
			s_check = getsockopt(
				s_socket,
				SOL_TLS,
				TLS_TX,
				(void *)(&s_buffer[0]),
				(socklen_t *)(&s_socklen)
			);
			if(s_check == (-1)) {
				return((void *)0);
			}
		
			if(s_socklen < ((socklen_t)sizeof(struct tls12_crypto_info_aes_gcm_128))) {
				errno = EBADMSG;
				return((void *)0);
			}
		}
		else {
			errno = ENOMSG;
			return((void *)0);
		}
		
		s_crypto_info_ptr = malloc((size_t)s_socklen);
		if(s_crypto_info_ptr == ((void *)0)) {
			errno = ENOMEM;
			return((void *)0);
		}
		(void)memcpy(s_crypto_info_ptr, (const void *)(&s_buffer[0]), (size_t)s_socklen);
		if(s_size_ptr != ((size_t *)0)) {
			*s_size_ptr = (size_t)s_socklen;
		}

		return(s_crypto_info_ptr);
	}
# endif
#endif

	errno = EPROTONOSUPPORT;
	return((void *)0);
}

int SSL_inspection_set_crypto_info(int s_socket, int s_is_encrypt, const void *s_crypto_info_ptr, size_t s_crypto_info_size)
{
	if(s_socket == (-1)) {
		errno = EINVAL;
		return(-1);
	}

#if defined(SOL_TLS)
# if defined(TLS_RX)
	if(s_is_encrypt == 0) {
		return(
			setsockopt(
				s_socket,
				SOL_TLS,
				TLS_RX,
				s_crypto_info_ptr,
				(socklen_t)s_crypto_info_size
			)
		);
	}
# endif
# if defined(TLS_TX)
	if(s_is_encrypt != 0) {
		return(
			setsockopt(
				s_socket,
				SOL_TLS,
				TLS_TX,
				s_crypto_info_ptr,
				(socklen_t)s_crypto_info_size
			)
		);
	}
# endif
#endif

	errno = EPROTONOSUPPORT;
	return(-1);
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
# if defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wredundant-decls"
#  pragma GCC diagnostic ignored "-Wunused-parameter"
# endif
#if 0L /* deprecated */
/* for SSL->enc_read/write_ctx */
# include "ssl_locl.h"
#else
# include "ssl_local.h"
#endif
#endif
void *SSL_inspection_build_crypto_info(SSL *s_ssl, int s_is_encrypt, size_t *s_size_ptr)
{
	EVP_CIPHER_CTX *s_evp_cipher_ctx;

	const SSL_CIPHER *s_ssl_cipher;
	int s_version;
	const char *s_version_string;
	const char *s_cipher_name;
	void *s_cipher_data;

	const EVP_CIPHER *s_evp_cipher;

	int s_type; /* NID_xxx_yyy_zzz */
	int s_block_size; /* bytes */
	int s_key_size; /* bytes */
	int s_iv_size; /* bytes */
	unsigned long s_mode; /* EVP_CIPH_xxx_MODE */
	
	size_t s_crypto_info_size;
	void *s_crypto_info_ptr;

	if(s_size_ptr != ((size_t *)0)) {
		*s_size_ptr = (size_t)0u;
	}

	if(s_ssl == ((SSL *)0)) {
		errno = EINVAL;
		return((void *)0);
	}

	if(s_is_encrypt == 0) {
		s_evp_cipher_ctx = s_ssl->enc_read_ctx;
	}
	else {
		s_evp_cipher_ctx = s_ssl->enc_write_ctx;
	}
	if(s_evp_cipher_ctx == ((const EVP_CIPHER_CTX *)0)) {
		errno = EINVAL;
		return((void *)0);
	}

	s_ssl_cipher = SSL_get_current_cipher(s_ssl);
	s_version = SSL_version(s_ssl);
	s_version_string = SSL_CIPHER_get_version(s_ssl_cipher);
	s_cipher_name = SSL_CIPHER_get_name(s_ssl_cipher);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	s_cipher_data = EVP_CIPHER_CTX_get_cipher_data(s_evp_cipher_ctx);
#else
	s_cipher_data = s_evp_cipher_ctx->cipher_data;
#endif

	(void)s_version_string;
	(void)s_cipher_name;

#if 1L
	s_evp_cipher = EVP_CIPHER_CTX_cipher(s_evp_cipher_ctx);
#else
	s_evp_cipher = EVP_get_cipherbyname(s_cipher_name);
#endif
	s_type = EVP_CIPHER_type(s_evp_cipher);
	s_block_size = EVP_CIPHER_block_size(s_evp_cipher);
	s_key_size = EVP_CIPHER_key_length(s_evp_cipher);
	s_iv_size = EVP_CIPHER_iv_length(s_evp_cipher);
	s_mode = EVP_CIPHER_mode(s_evp_cipher);
	
#if 0L /* DEBUG: Master secret ... */
	do {
		const SSL_SESSION *s_session;

		size_t s_client_random_size;
		unsigned char s_client_random[SSL3_RANDOM_SIZE];
		size_t s_server_random_size;
		unsigned char s_server_random[SSL3_RANDOM_SIZE];
		size_t s_master_key_size;
		unsigned char s_master_key[SSL_MAX_MASTER_KEY_LENGTH];

		s_session = SSL_get_session(s_ssl);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		s_client_random_size = SSL_get_client_random(
			s_ssl,
			(unsigned char *)(&s_client_random[0]),
			sizeof(s_client_random)
		);
		s_server_random_size = SSL_get_server_random(
			s_ssl,
			(unsigned char *)(&s_server_random[0]),
			sizeof(s_server_random)
		);
		s_master_key_size = SSL_SESSION_get_master_key(
			s_session,
			(unsigned char *)(&s_master_key[0]),
			sizeof(s_master_key)
		);
#else
		if((s_ssl->s3 != ((struct ssl3_state_st *)0)) && (s_session->master_key_length > 0)) {
			s_client_random_size = sizeof(s_client_random);
			(void)memcpy((void *)(&s_client_random[0]), (const void *)s_ssl->s3->client_random, s_client_random_size);
			s_server_random_size = sizeof(s_server_random);
			(void)memcpy((void *)(&s_server_random[0]), (const void *)s_ssl->s3->server_random, s_server_random_size);
			s_master_key_size = (size_t)s_session->master_key_length;
			(void)memcpy((void *)(&s_master_key[0]), (const void *)s_session->master_key, (size_t)s_session->master_key_length);
		}
		else {
			s_client_random_size = (size_t)0u;
			s_server_random_size = (size_t)0u;
			s_master_key_size = (size_t)0u;
		}
#endif

		(void)fprintf(stdout, "Client-Random (%lu/%lu bytes)\n", (unsigned long)s_client_random_size, (unsigned long)sizeof(s_client_random));
		SSL_inspection_hexdump("  ", (const void *)(&s_client_random[0]), s_client_random_size);
		(void)fprintf(stdout, "Server-Random (%lu/%lu bytes)\n", (unsigned long)s_server_random_size, (unsigned long)sizeof(s_server_random));
		SSL_inspection_hexdump("  ", (const void *)(&s_server_random[0]), s_server_random_size);
		(void)fprintf(stdout, "Master-Key(Master-Secret) (%lu/%lu bytes)\n", (unsigned long)s_master_key_size, (unsigned long)sizeof(s_master_key));
		SSL_inspection_hexdump("  ", (const void *)(&s_master_key[0]), s_master_key_size);

		do { /* dump key-block */
			static const char cg_label[] = {"key expansion"};

			/* Key-Block size : (mac_secret_size + key_size + iv_size) * 2 */
			/* AES128-GCM case : mac_secret_size=0, key_size=16, iv_size=12 */
			uint8_t s_key_block[ (/* s_mac_secret_size + */ s_key_size + s_iv_size) * 2 ];
			uint8_t s_seed[ s_server_random_size + s_client_random_size];

			(void)fprintf(stdout, "Key-Block (label=\"%s\", %lu bytes)\n", (const char *)(&cg_label[0]), (unsigned long)sizeof(s_key_block));

			(void)memcpy((void *)(&s_seed[0]), (const void *)(&s_server_random[0]), s_server_random_size);
			(void)memcpy((void *)(&s_seed[s_server_random_size]), (const void *)(&s_client_random[0]), s_client_random_size);
			(void)hwport_pseudo_random_function_tlsv1_2_sha256(
				(const void *)(&s_master_key[0]),
				s_master_key_size,
				(const void *)(&cg_label[0]),
				strlen((const char *)(&cg_label[0])),
				(const void *)(&s_seed[0]),
				sizeof(s_seed),
				(void *)(&s_key_block[0]),
				sizeof(s_key_block)
			);
			(void)SSL_inspection_hexdump(
				"  ",
				(const void *)(&s_key_block[0]),
				sizeof(s_key_block)
			);
		}while(0);
	}while(0);
#endif

	if(((s_version == TLS1_2_VERSION) /* || (strcmp(s_version_string, "TLSv1.2") == 0) || (strcmp(s_version_string, "TLSv1/SSLv3") == 0) */) &&
		(s_type == NID_aes_128_gcm) &&
		(s_block_size >= 1) &&
		(s_key_size == 16 /* TLS_CIPHER_AES_GCM_128_KEY_SIZE */) &&
		(s_iv_size == 12 /* TLS_CIPHER_AES_GCM_128_IV_SIZE - TLS_CIPHER_AES_GCM_128_SALT_SIZE */) &&
		(s_mode == EVP_CIPH_GCM_MODE)) {
		struct tls12_crypto_info_aes_gcm_128 *s_crypto_info; /* in kernel header "linux/tls.h" */

		const EVP_AES_GCM_CTX *s_evp_aes_gcm_ctx; /* in OpenSSL source "crypto/evp/e_aes.c" */

		const unsigned char *s_key;
		const unsigned char *s_working_iv;
		const unsigned char *s_record_sequence;

		s_crypto_info_size = sizeof(struct tls12_crypto_info_aes_gcm_128);
		s_crypto_info_ptr = malloc(s_crypto_info_size);
		if(s_crypto_info_ptr == ((void *)0)) {
			errno = ENOMEM;
			return((void *)0);
		}

		s_crypto_info = (struct tls12_crypto_info_aes_gcm_128 *)memset(
			s_crypto_info_ptr,
			0,
			s_crypto_info_size
		);

		s_evp_aes_gcm_ctx = (const EVP_AES_GCM_CTX *)s_cipher_data;
		s_key = (const unsigned char *)s_evp_aes_gcm_ctx->gcm.key;
		s_working_iv = (const unsigned char *)s_evp_aes_gcm_ctx->iv;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		do {
			static const unsigned char cg_record_sequence[ /* TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE 8 */ ] = {
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
			};

			s_record_sequence = (const unsigned char *)(&cg_record_sequence[0]);
		}while(0);
#elif 1L /* <= OpenSSL v1.0.1p (not good idea) */
		if(s_is_encrypt == 0) {
			s_record_sequence = (const unsigned char *)(&s_ssl->s3->read_sequence[0]);
		}
		else {
			s_record_sequence = (const unsigned char *)(&s_ssl->s3->write_sequence[0]);
		}
#else /* always begin 1 */
		do {
			static const unsigned char cg_record_sequence[ /* TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE 8 */ ] = {
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
			};

			s_record_sequence = (const unsigned char *)(&cg_record_sequence[0]);
		}while(0);
#endif

		s_crypto_info->info.version = TLS_1_2_VERSION;
		s_crypto_info->info.cipher_type = TLS_CIPHER_AES_GCM_128 /* 51 */;

		(void)memcpy((void *)(&s_crypto_info->iv[0]), (const void *)(&s_working_iv[4]), TLS_CIPHER_AES_GCM_128_IV_SIZE /* 8 */);
		(void)memcpy((void *)(&s_crypto_info->key[0]), (const void *)(&s_key[0]), TLS_CIPHER_AES_GCM_128_KEY_SIZE /* 16 */);
		(void)memcpy((void *)(&s_crypto_info->salt[0]), (const void *)(&s_working_iv[0]), TLS_CIPHER_AES_GCM_128_SALT_SIZE /* 4 */);
		(void)memcpy((void *)(&s_crypto_info->rec_seq[0]), (const void *)(&s_record_sequence[0]), TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE /* 8 */);
		/* TLS_CIPHER_AES_GCM_128_TAG_SIZE 16 */
	}
	else {
#if 0L /* DEBUG */
		(void)fprintf(
			stdout,
			"Not supported kTLS's crypto info (version=\"%s\"(%d), name=\"%s\", type=%d, block_size=%d, key_size=%d, iv_size=%d, mode=%lu)\n",
			s_version_string,
			s_version,
			s_cipher_name,
			s_type,
			s_block_size,
			s_key_size,
			s_iv_size,
			s_mode
		);
#endif

		errno = ENOMSG;
		return((void *)0);
	}

	if(s_size_ptr != ((size_t *)0)) {
		*s_size_ptr = s_crypto_info_size;
	}

	errno = 0;

	return(s_crypto_info_ptr);
}

void *SSL_inspection_pseudo_encrypt(SSL *s_ssl, int s_socket, const void *s_plaintext_ptr, size_t s_plaintext_size, size_t *s_tls_payload_size_ptr)
{
	int s_errno;

	size_t s_tls_payload_size;
	void *s_tls_payload_ptr;

	size_t s_crypto_info_size;
	void *s_crypto_info_ptr;

	const struct tls_crypto_info *s_tls_crypto_info;

	if(s_tls_payload_size_ptr != ((size_t *)0)) {
		*s_tls_payload_size_ptr = (size_t)0u;
	}

	if(s_plaintext_size > ((size_t)(1u << 14))) { /* need fragmentation */
		errno = EOVERFLOW;
		return((void *)0);
	}

	if(s_ssl == ((SSL *)0)) {
		s_crypto_info_ptr = SSL_inspection_get_crypto_info(
			s_socket,
			1 /* is_encrypt */,
			(size_t *)(&s_crypto_info_size)
		);
	}
	else {
		s_crypto_info_ptr = SSL_inspection_build_crypto_info(
			s_ssl,
			1 /* is_encrypt */,
			(size_t *)(&s_crypto_info_size)
		);
	}
	if(s_crypto_info_ptr == ((void *)0)) {
		return((void *)0);
	}

	s_errno = EPROTONOSUPPORT;
	s_tls_payload_size = (size_t)0u;
	s_tls_payload_ptr = (void *)0;

	s_tls_crypto_info = (const struct tls_crypto_info *)s_crypto_info_ptr;
	if((s_tls_crypto_info->version == TLS_1_2_VERSION) && (s_tls_crypto_info->cipher_type == TLS_CIPHER_AES_GCM_128)) {
		size_t s_record_sequence_size;
		size_t s_record_type_size;
		size_t s_record_version_size;
		size_t s_record_length_size;
		size_t s_key_size;
		size_t s_salt_size;
		size_t s_iv_size;
		size_t s_aad_size;
		size_t s_tls_header_size;
		size_t s_ciphertext_size;
		size_t s_tag_size;
	
		/* pre calc size */
		s_record_sequence_size = (size_t)8u;
		s_record_type_size = (size_t)1u;
		s_record_version_size = (size_t)2u;
		s_record_length_size = (size_t)2u;
		s_key_size = (size_t)16u;
		(void)s_key_size;
		s_salt_size = (size_t)4u;
		s_iv_size = (size_t)8u;
		s_aad_size = s_record_sequence_size + s_record_type_size + s_record_version_size + s_record_length_size;
		s_tls_header_size = s_aad_size - s_record_sequence_size;
		s_ciphertext_size = s_plaintext_size;
		s_tag_size = (size_t)16u;

		/* allocate payload */
		s_tls_payload_size = s_tls_header_size + s_iv_size + s_ciphertext_size + s_tag_size;
		s_tls_payload_ptr = malloc(s_tls_payload_size);
		if(s_tls_payload_ptr == ((void *)0)) {
			s_errno = ENOMEM;
		}
		else {
			const struct tls12_crypto_info_aes_gcm_128 *s_crypto_info;

			const void *s_key_ptr;
			uint8_t s_iv_local[ 4 /* salt */ + 8 /* IV */ ];
			void *s_salt_iv_ptr;

			size_t s_offset;
		
			uint8_t s_aad_local[ s_aad_size ];
			void *s_aad_ptr;
			void *s_ciphertext_ptr;
			void *s_tag_ptr;

			ssize_t s_process_size;

			s_crypto_info = (const struct tls12_crypto_info_aes_gcm_128 *)s_crypto_info_ptr;
			
			/* key load */
			s_key_ptr = (const void *)(&s_crypto_info->key[0]);
			s_salt_iv_ptr = (void *)(&s_iv_local[0]);
			(void)memcpy(
				(void *)(((uint8_t *)s_salt_iv_ptr) + ((size_t)0u)),
				(const void *)(&s_crypto_info->salt[0]),
				s_salt_size
			);
			(void)memcpy(
				(void *)(((uint8_t *)s_salt_iv_ptr) + s_salt_size),
				(const void *)(&s_crypto_info->iv[0]),
				s_iv_size
			);
		
			/* build AAD */
			s_aad_ptr = (void *)(&s_aad_local[0]);
			s_offset = (size_t)0u;
			(void)memcpy(
				(void *)(((uint8_t *)s_aad_ptr) + s_offset),
				(const void *)(&s_crypto_info->rec_seq[0]),
				s_record_sequence_size
			);
			s_offset += s_record_sequence_size;
			*((uint8_t *)(((uint8_t *)s_aad_ptr) + s_offset)) = (uint8_t)0x17u;
			s_offset += s_record_type_size;
			*((uint16_t *)(((uint8_t *)s_aad_ptr) + s_offset)) = (uint16_t)htons(0x0303);
			s_offset += s_record_version_size;
			*((uint16_t *)(((uint8_t *)s_aad_ptr) + s_offset)) = (uint16_t)htons((uint16_t)(s_plaintext_size /* !! */));
			s_offset += s_record_length_size;

			/* mapping tls payload */
			s_offset = (size_t)0u;
			(void)memcpy(
				(void *)(((uint8_t *)s_tls_payload_ptr) + s_offset),
				(const void *)(((const uint8_t *)s_aad_ptr) + s_record_sequence_size),
				s_tls_header_size
			);
			*((uint16_t *)(((uint8_t *)s_tls_payload_ptr) + s_record_type_size + s_record_version_size)) = (uint16_t)htons((uint16_t)(s_iv_size + s_ciphertext_size + s_tag_size)); /* !! update TLS record length */
			s_offset += s_tls_header_size;
			(void)memcpy(
				(void *)(((uint8_t *)s_tls_payload_ptr) + s_offset),
				(const void *)(&s_crypto_info->iv[0]),
				s_iv_size
			);
			s_offset += s_iv_size;
			s_ciphertext_ptr = (void *)(((uint8_t *)s_tls_payload_ptr) + s_offset),
			s_offset += s_ciphertext_size;
			s_tag_ptr = (void *)(((uint8_t *)s_tls_payload_ptr) + s_offset),
			s_offset += s_tag_size;
		
			/* do encrypt */
			s_process_size = SSL_inspection_encrypt_AES_GCM(
				EVP_aes_128_gcm(),
				s_plaintext_ptr,
				s_plaintext_size,
				s_aad_ptr,
				s_aad_size,
				s_key_ptr,
				s_salt_iv_ptr,
				s_salt_size + s_iv_size,
				s_ciphertext_ptr,
				s_tag_ptr
			);
			if(s_process_size == ((ssize_t)(-1))) {
				s_errno = errno;
				
				free(s_tls_payload_ptr);
				s_tls_payload_ptr = (void *)0;
			}
		}
	}

	free(s_crypto_info_ptr);

	if(s_tls_payload_ptr == ((void *)0)) {
		errno = s_errno;
		return((void *)0);
	}

	if(s_tls_payload_size_ptr != ((size_t *)0)) {
		*s_tls_payload_size_ptr = s_tls_payload_size;
	}

	return(s_tls_payload_ptr);
}

#if !defined(__NR_ktls_forward )
# define __NR_ktls_forward 314
#endif
int SSL_inspection_pseudo_set_ktls_forward(int s_socket_client, int s_socket_server, unsigned int s_flags)
{
	return((int)syscall(__NR_ktls_forward, s_socket_client, s_socket_server, s_flags));
}

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
