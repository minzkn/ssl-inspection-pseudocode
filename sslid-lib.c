/*
	Copyright (C) MINZKN.COM
	All rights reserved.
	Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_sslid_lib_c__)
# define __def_sslid_source_sslid_lib_c__ "sslid-lib.c"

#include "sslid-lib.h"

#include <sys/syscall.h>

#include <execinfo.h>

/* Secure memory clearing function - immune to compiler optimization */
void SSL_inspection_secure_memzero(void *ptr, size_t size);

int SSL_inspection_ratelimited_message_check(void);
void SSL_inspection_perror(const char *s_prefix_message);
int SSL_inspection_fprintf(FILE *s_stream, const char *s_format, ...) SSL_inspection_vsprintf_varg_check(2,3);

char *SSL_inspection_cpuset_to_string(char *s_string, size_t s_limit_size, cpu_set_t *s_cpuset);

unsigned long long SSL_inspection_get_time_stamp_msec(void);
int SSL_inspection_msleep(int s_timeout_msec);

void *SSL_inspection_increment_be_block(void *s_bigint_ptr, size_t s_size);
void *SSL_inspection_xor_block(void *s_to_ptr, const void *s_from_ptr, size_t s_size);
void *SSL_inspection_right_shift_block(void *s_block_ptr, size_t s_size);

int SSL_inspection_is_printable_ascii(int s_charactor, int s_is_level);
void *SSL_inspection_convert_printable_ascii(void *s_to, const void *s_from, size_t s_size);
const void *SSL_inspection_hexdump(const char *s_prefix, const void *s_data, size_t s_size);

void SSL_inspection_dump_backtrace(void);

int SSL_inspection_string_to_sockaddr(int s_family, const char *s_address, int s_port, void *s_sockaddr_ptr, socklen_t *s_socklen_ptr);

int SSL_inspection_set_keepalive_socket(int s_socket, int s_is_enable, int s_keepidle_sec, int s_keepintvl_sec);
int SSL_inspection_set_linger_socket(int s_socket, int s_is_enable, int s_sec);
int SSL_inspection_set_reuse_address_socket(int s_socket, int s_is_enable);
int SSL_inspection_set_reuse_port_socket(int s_socket, int s_is_enable);
int SSL_inspection_set_naggle_socket(int s_socket, int s_is_enable);
int SSL_inspection_set_transparent_socket(int s_socket, int s_is_enable);
int SSL_inspection_set_freebind_socket(int s_socket, int s_is_enable);
int SSL_inspection_set_tx_socket_buffer_size(int s_socket, size_t s_size);
int SSL_inspection_set_rx_socket_buffer_size(int s_socket, size_t s_size);

int SSL_inspection_closefd(int s_fd);
int SSL_inspection_closesocket(int s_socket);

ssize_t SSL_inspection_encrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_plaintext, size_t s_plaintext_size, const void *s_aad, size_t s_aad_size, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_ciphertext, void *s_tag);
ssize_t SSL_inspection_decrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_ciphertext, size_t s_ciphertext_size, const void *s_aad, size_t s_aad_size, const void *s_tag, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_plaintext);

/*
 * Secure memory clearing function - immune to compiler optimization
 * Uses OPENSSL_cleanse if available, otherwise explicit_bzero or manual volatile write
 */
void SSL_inspection_secure_memzero(void *ptr, size_t size)
{
	if (ptr == NULL || size == 0) {
		return;
	}

	/* OPENSSL_cleanse is a function (not a macro), always available here */
	OPENSSL_cleanse(ptr, size);
}

int SSL_inspection_ratelimited_message_check(void)
{
	static unsigned long long sg_consume_per_sec = 512ull; /* CONFIG */

	static pthread_mutex_t sg_lock = PTHREAD_MUTEX_INITIALIZER;
	static unsigned long long sg_prev_time_stamp_msec = 0ull;
	static unsigned long long sg_consume_count = 0ull;
	static unsigned long long sg_limited_count = 0ull;
	unsigned long long s_time_stamp_msec;

	int s_limited;
	int s_errno;

	s_errno = errno;

	(void)pthread_mutex_lock((pthread_mutex_t *)(&sg_lock));
	s_time_stamp_msec = SSL_inspection_get_time_stamp_msec();
	if((sg_prev_time_stamp_msec == 0ull) || ((s_time_stamp_msec - sg_prev_time_stamp_msec) >= 1000ull)) {
		sg_consume_count += sg_consume_per_sec;
		if(sg_consume_count > sg_consume_per_sec) {
			sg_consume_count = sg_consume_per_sec;
		}

		if(SSL_inspection_unlikely(sg_limited_count > 0ull)) {
			(void)fprintf(stderr, "\n" def_hwport_color_magenta "*** RATELIMITED " def_hwport_color_white "%llu" def_hwport_color_magenta " MESSAGES ***" def_hwport_color_normal "\n\n", sg_limited_count);
			sg_limited_count = 0ull;
		}

		sg_prev_time_stamp_msec = s_time_stamp_msec;
	}

	if(sg_consume_count > 0ull) {
		--sg_consume_count;
		s_limited = 0;
	}
	else {
		++sg_limited_count;
		s_limited = 1;
	}
	(void)pthread_mutex_unlock((pthread_mutex_t *)(&sg_lock));

	errno = s_errno;

	return(s_limited);
}

void SSL_inspection_perror(const char *s_prefix_message)
{
	if(SSL_inspection_unlikely(SSL_inspection_ratelimited_message_check() != 0)) { /* 과도한 출력 통제 */
		return;
	}

	perror(s_prefix_message);
}

int SSL_inspection_fprintf(FILE *s_stream, const char *s_format, ...)
{
	int s_result;
	va_list s_var;

	if(SSL_inspection_unlikely(s_stream == ((FILE *)(NULL)))) {
		s_stream = stdout;
	}
	if(SSL_inspection_unlikely(s_format == ((const char *)(NULL)))) {
		(void)fflush(s_stream);
		return(0);
	}

	if(SSL_inspection_unlikely(SSL_inspection_ratelimited_message_check() != 0)) { /* 과도한 출력 통제 */
		return(0);
	}

	va_start(s_var, s_format);
	s_result = vfprintf(s_stream, s_format, s_var);
	va_end(s_var);

	return(s_result);
}

char *SSL_inspection_cpuset_to_string(char *s_string, size_t s_limit_size, cpu_set_t *s_cpuset)
{
	int s_cpu;
	int s_offset;

	if(SSL_inspection_unlikely((s_string == ((char *)(NULL))) || (s_limit_size <= ((size_t)0u)))) {
		return((char *)(NULL));
	}

	s_offset = 0;
	s_string[s_offset] = '\0';
	for (s_cpu = 0;(s_cpu < CPU_SETSIZE) && (((size_t)s_offset) < s_limit_size);s_cpu++) {
		if(CPU_ISSET(s_cpu, s_cpuset)) {
			s_offset += snprintf((char *)(&s_string[s_offset]), s_limit_size - ((size_t)s_offset), "[%d]", s_cpu);
		}
	}

	return(s_string);
}

unsigned long long SSL_inspection_get_time_stamp_msec(void)
{
	struct timespec s_timespec;
	unsigned long long s_time_stamp_msec;

	if(SSL_inspection_unlikely(clock_gettime(CLOCK_MONOTONIC, (struct timespec *)(&s_timespec)) != 0)) {
		return((unsigned long long)0u);
	}

	s_time_stamp_msec = ((unsigned long long)s_timespec.tv_sec) * ((unsigned long long)1000u); /* sec to msec */
	s_time_stamp_msec += ((unsigned long long)s_timespec.tv_nsec) / ((unsigned long long)1000000u); /* nanosec to msec */

	return(s_time_stamp_msec);
}

int SSL_inspection_msleep(int s_timeout_msec)
{
	struct timeval s_timeval_local;
	int s_check;

	if(s_timeout_msec < 0) {
		s_timeout_msec = 0;
	}
	s_timeval_local.tv_sec = s_timeout_msec / 1000;
	s_timeval_local.tv_usec = (s_timeout_msec % 1000) * 1000;

	s_check = select(0, (fd_set *)(NULL), (fd_set *)(NULL), (fd_set *)(NULL), (struct timeval *)(&s_timeval_local));
	if(SSL_inspection_unlikely(s_check == (-1))) {
		SSL_inspection_perror("msleep");
	}

	return(s_check);
}

void *SSL_inspection_increment_be_block(void *s_bigint_ptr, size_t s_size)
{
	if(SSL_inspection_unlikely(s_size <= ((size_t)0u))) {
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
	if(SSL_inspection_unlikely(s_size <= ((size_t)0u))) {
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

	if(SSL_inspection_unlikely(s_size <= ((size_t)0u))) {
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

	if(s_to == ((void *)(NULL))) {
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
	char s_m[ 64 ];
	int s_mo;

	if(SSL_inspection_unlikely(s_data == ((const void *)(NULL))))return((void *)(NULL));

	s_b[sizeof(s_b) - 1] = (unsigned char)'\0';
	for(s_o = (size_t)0;s_o < s_size;s_o += (size_t)16) {
		s_w = ((s_size - s_o) <= ((size_t)16)) ? (s_size - s_o) : ((size_t)16);
		s_mo = 0;
		s_m[0] = '\0';
		for(s_lo = (size_t)0;s_lo < s_w;s_lo++) {
			if(s_lo == ((size_t)(16 >> 1)))s_mo += snprintf((char *)(&s_m[s_mo]), sizeof(s_m) - s_mo, " | ");
			else s_mo += snprintf((char *)(&s_m[s_mo]), sizeof(s_m) - s_mo, " ");
			s_b[s_lo] = *(((const unsigned char *)s_data) + (s_o + s_lo));
			s_mo += snprintf((char *)(&s_m[s_mo]), sizeof(s_m) - s_mo, "%02X", (int)s_b[s_lo]);
			if(SSL_inspection_is_printable_ascii((int)s_b[s_lo], 0) == 0) {
				s_b[s_lo] = (unsigned char)'.';
			}
		}
		while(s_lo < ((size_t)16)) {
			if(s_lo == ((size_t)(16 >> 1)))s_mo += snprintf((char *)(&s_m[s_mo]), sizeof(s_m) - s_mo, "     ");
			else s_mo += snprintf((char *)(&s_m[s_mo]), sizeof(s_m) - s_mo, "   ");
			s_b[s_lo] = (unsigned char)' '; s_lo++;
		}
		(void)SSL_inspection_fprintf(
			stdout,
		       	"%s%08lX%s [%s]\n",
		       	(s_prefix == ((const char *)(NULL))) ? "" : s_prefix,
		       	(unsigned long)s_o,
		       	(const char *)(&s_m[0]),
		       	(char *)(&s_b[0])
		);
	}
	(void)fflush(stdout);

	return(s_data);
#endif
}

void SSL_inspection_dump_backtrace(void)
{
	/* gcc options: -fno-omit-frame-pointer, optionally -rdynamic */
	void *s_backtrace_buffer[16];
	int s_backtrace_size;
	static const char s_hdr[] = "backtrace:\n";

	s_backtrace_size = backtrace(
		(void **)(&s_backtrace_buffer[0]),
		(int)(sizeof(s_backtrace_buffer) / sizeof(void *))
	);
	{ ssize_t s_wr_ = write(STDERR_FILENO, s_hdr, sizeof(s_hdr) - 1); (void)s_wr_; }
	if(s_backtrace_size > 0) {
		backtrace_symbols_fd(
			(void * const *)(&s_backtrace_buffer[0]),
			s_backtrace_size,
			STDERR_FILENO
		);
	}
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

	if(s_socklen_ptr == ((socklen_t *)(NULL))) {
		s_socklen = (socklen_t)0;
	}
	else {
		s_socklen = *s_socklen_ptr;
	}

	if(s_address != ((const char *)(NULL))) {
		if(strlen(s_address) <= ((size_t)0u)) {
			s_address = (const char *)(NULL);
		}
	}

	if(s_family == AF_INET) {
		struct in_addr s_in_addr;
		struct sockaddr_in *s_sockaddr_in;

		if(SSL_inspection_unlikely((s_socklen > ((socklen_t)0)) && (s_socklen < sizeof(struct sockaddr_in)))) {
			/* not enough socklen */
			errno = EINVAL;
			return(-1);
		}

		if(SSL_inspection_unlikely(s_port > 65535)) {
			errno = EINVAL;
			return(-1);
		}
		if(s_port < 0) {
			s_port = 0;
		}

		if(s_address == ((const char *)(NULL))) {
			s_in_addr.s_addr = htonl(INADDR_ANY);
		}
		else {
			for(s_offset = (size_t)0u;s_address[s_offset] != '\0';s_offset++) {
				if(SSL_inspection_unlikely((isdigit(s_address[s_offset]) == 0) &&
					(s_address[s_offset] != '.'))) {
					errno = EINVAL;
					return(-1);
				}
			}

			/* IPv4 address string validation check */
			if(SSL_inspection_unlikely(inet_pton(s_family, s_address, (void *)(&s_in_addr)) <= 0)) {
				return(-1);
			}
		}

		s_socklen = (socklen_t)sizeof(struct sockaddr_in);
		if(s_socklen_ptr != ((socklen_t *)(NULL))) {
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

		if(SSL_inspection_unlikely((s_socklen > ((socklen_t)0)) && (s_socklen < sizeof(struct sockaddr_in6)))) {
			/* not enough socklen */
			errno = EINVAL;
			return(-1);
		}

		if(SSL_inspection_unlikely(s_port > 65535)) {
			errno = EINVAL;
			return(-1);
		}
		if(s_port < 0) {
			s_port = 0;
		}

		if(s_address == ((const char *)(NULL))) {
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
			if(SSL_inspection_unlikely(inet_pton(s_family, s_address, (void *)(&s_in6_addr)) <= 0)) {
				return(-1);
			}
		}

		s_socklen = (socklen_t)sizeof(struct sockaddr_in6);
		if(s_socklen_ptr != ((socklen_t *)(NULL))) {
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

		if(SSL_inspection_unlikely((s_socklen > ((socklen_t)0)) && (s_socklen < sizeof(struct sockaddr_un)))) {
			/* not enough socklen */
			errno = EINVAL;
			return(-1);
		}

		/* sun-path string validation check */
		if(s_address == ((const char *)(NULL))) { /* "" (unnamed path) */
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

			if(SSL_inspection_unlikely(s_is_valid_sun_path == 0)) {
				errno = EINVAL;
				return(-1);
			}
		}

		s_socklen = (socklen_t)sizeof(struct sockaddr_un);
		if(s_socklen_ptr != ((socklen_t *)(NULL))) {
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

int SSL_inspection_set_keepalive_socket(int s_socket, int s_is_enable, int s_keepidle_sec, int s_keepintvl_sec)
{
	int s_value;

	s_value = (s_is_enable == 0) ? 0 : 1;

	if(SSL_inspection_unlikely(setsockopt(
		s_socket,
		(int)(SOL_SOCKET),
		(int)(SO_KEEPALIVE),
		(const void *)(&s_value),
		(socklen_t)sizeof(s_value)) == (-1))) {
		return(-1);
	}

	if(s_is_enable <= 0) {
		return(0);
	}

#if defined(TCP_KEEPIDLE)
	if(s_keepidle_sec < 0) {
		s_keepidle_sec = 60 /* default */;
	}
	if(SSL_inspection_unlikely(setsockopt(
		s_socket,
		(int)(IPPROTO_TCP),
		(int)(TCP_KEEPIDLE),
		(const void *)(&s_keepidle_sec),
		(socklen_t)sizeof(s_keepidle_sec)) == (-1))) {
		return(-1);
	}
#else
	(void)s_keepidle_sec;
#endif
#if defined(TCP_KEEPINTVL)
	if(s_keepintvl_sec <= 0) {
		s_keepintvl_sec = 30 /* default */;
	}
	if(SSL_inspection_unlikely(setsockopt(
		s_socket,
		(int)(IPPROTO_TCP),
		(int)(TCP_KEEPINTVL),
		(const void *)(&s_keepintvl_sec),
		(socklen_t)sizeof(s_keepintvl_sec)) == (-1))) {
		return(-1);
	}
#else
	(void)s_keepintvl_sec;
#endif

	return(0);
}

int SSL_inspection_set_linger_socket(int s_socket, int s_is_enable, int s_sec)
{
	struct linger s_value;
	int s_optname;

	if(s_is_enable == 0) {
#if defined(SO_DONTLINGER)
		s_optname = SO_DONTLINGER;
#else
		s_optname = SO_LINGER;
#endif
		s_value.l_onoff = 0;
		s_value.l_linger = 0;
	}
	else {
		s_optname = SO_LINGER;
		s_value.l_onoff = 1;
		s_value.l_linger = s_sec;
	}

	return(setsockopt(s_socket, SOL_SOCKET, s_optname, (const void *)(&s_value), (socklen_t)sizeof(s_value)));
}

int SSL_inspection_set_reuse_address_socket(int s_socket, int s_is_enable)
{
	int s_value;

	s_value = (s_is_enable == 0) ? 0 : 1;

	return(setsockopt(s_socket, SOL_SOCKET, SO_REUSEADDR, (const void *)(&s_value), (socklen_t)sizeof(s_value)));
}

int SSL_inspection_set_reuse_port_socket(int s_socket, int s_is_enable)
{
	int s_value;

	s_value = (s_is_enable == 0) ? 0 : 1;

	return(setsockopt(s_socket, SOL_SOCKET, SO_REUSEPORT, (const void *)(&s_value), (socklen_t)sizeof(s_value)));
}

int SSL_inspection_set_naggle_socket(int s_socket, int s_is_enable)
{
    int s_value;

    s_value = (s_is_enable == 0) ? 1 /* TCP_NODELAY on: Nagle disabled */ : 0 /* TCP_NODELAY off: Nagle enabled */;
    
    return(setsockopt(s_socket, IPPROTO_TCP, (int)(TCP_NODELAY), (const void *)(&s_value), (socklen_t)sizeof(s_value)));
}

int SSL_inspection_set_transparent_socket(int s_socket, int s_is_enable)
{
	int s_value;
	struct sockaddr_storage s_sockaddr_storage;
	socklen_t s_socklen;

	s_value = (s_is_enable == 0) ? 0 : 1;

	s_socklen = (socklen_t)sizeof(s_sockaddr_storage);
	if(getsockname(s_socket, (struct sockaddr *)(&s_sockaddr_storage), (socklen_t *)(&s_socklen)) == 0) {
		if(s_sockaddr_storage.ss_family == AF_INET6) {
			return(setsockopt(s_socket, SOL_IPV6, IPV6_TRANSPARENT, (const void *)(&s_value), (socklen_t)sizeof(s_value)));
		}
	}

	return(setsockopt(s_socket, SOL_IP, IP_TRANSPARENT, (const void *)(&s_value), (socklen_t)sizeof(s_value)));
}

int SSL_inspection_set_freebind_socket(int s_socket, int s_is_enable)
{
	int s_value;
	struct sockaddr_storage s_sockaddr_storage;
	socklen_t s_socklen;

	s_value = (s_is_enable == 0) ? 0 : 1;

	s_socklen = (socklen_t)sizeof(s_sockaddr_storage);
	if(getsockname(s_socket, (struct sockaddr *)(&s_sockaddr_storage), (socklen_t *)(&s_socklen)) == 0) {
		if(s_sockaddr_storage.ss_family == AF_INET6) {
			return(setsockopt(s_socket, IPPROTO_IPV6, IPV6_FREEBIND, (const void *)(&s_value), (socklen_t)sizeof(s_value)));
		}
	}

	return(setsockopt(s_socket, IPPROTO_IP, IP_FREEBIND, (const void *)(&s_value), (socklen_t)sizeof(s_value)));
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

int SSL_inspection_closefd(int s_fd)
{
	int s_check;

	do {
		s_check = close(s_fd);
	}while((s_check == (-1)) && (errno == EINTR));

	return(s_check);
}

int SSL_inspection_closesocket(int s_socket)
{
	int s_check;

	do {
		s_check = close(s_socket);
	}while((s_check == (-1)) && (errno == EINTR));

	return(s_check);
}
ssize_t SSL_inspection_encrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_plaintext, size_t s_plaintext_size, const void *s_aad, size_t s_aad_size, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_ciphertext, void *s_tag)
{
	EVP_CIPHER_CTX *s_evp_cipher_ctx;
	int s_check;
	int s_size;
	ssize_t s_ciphertext_size;

	s_evp_cipher_ctx = EVP_CIPHER_CTX_new();
	if(SSL_inspection_unlikely(s_evp_cipher_ctx == ((EVP_CIPHER_CTX *)(NULL)))) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_CIPHER_CTX_new failed !\n");
		errno = ENOMEM;
		return((ssize_t)(-1));
	}

	if(s_cipher == ((const EVP_CIPHER *)(NULL))) {
		s_cipher = EVP_aes_256_gcm();
	}
	s_check = EVP_EncryptInit_ex(
		s_evp_cipher_ctx /* ctx */,
		s_cipher /* cipher */,
		(ENGINE *)(NULL) /* engine */,
		(const unsigned char *)(NULL) /* key */,
		(const unsigned char *)(NULL) /* iv */
	);
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_EncryptInit_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	s_check = EVP_CIPHER_CTX_ctrl(
		s_evp_cipher_ctx,
		EVP_CTRL_GCM_SET_IVLEN,
		(int)s_iv_size,
		(void *)(NULL)
	);
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Initialise key and IV */
	s_check = EVP_EncryptInit_ex(
		s_evp_cipher_ctx /* ctx */,
		(const EVP_CIPHER *)(NULL) /* cipher */,
		(ENGINE *)(NULL) /* engine */,
		(const unsigned char *)s_key /* key */,
		(const unsigned char *)s_iv /* iv */
	);
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_EncryptInit_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	if((s_aad == ((const void *)(NULL))) || (s_aad_size <= ((size_t)0u))) {
		static const uint8_t cg_empty[1] = {0};
		s_aad = (const void *)(&cg_empty[0]);
	}
	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	{
		/* Use a separate variable so the AAD-phase output length does not
		 * overwrite s_size, which is used for the plaintext phase below. */
		int s_aad_out_len = 0;
		s_check = EVP_EncryptUpdate(
			s_evp_cipher_ctx,
			(unsigned char *)(NULL),
			&s_aad_out_len,
			(const unsigned char *)s_aad,
			(int)s_aad_size
		);
	}
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_EncryptUpdate failed !\n");
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
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_EncryptUpdate failed !\n");
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
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_EncryptFinal_ex failed !\n");
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
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

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
	if(SSL_inspection_unlikely(s_evp_cipher_ctx == ((EVP_CIPHER_CTX *)(NULL)))) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_CIPHER_CTX_new failed !\n");
		errno = ENOMEM;
		return((ssize_t)(-1));
	}

	if(s_cipher == ((const EVP_CIPHER *)(NULL))) {
		s_cipher = EVP_aes_256_gcm();
	}
	s_check = EVP_DecryptInit_ex(
		s_evp_cipher_ctx /* ctx */,
		s_cipher /* cipher */,
		(ENGINE *)(NULL) /* engine */,
		(const unsigned char *)(NULL) /* key */,
		(const unsigned char *)(NULL) /* iv */
	);
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_DecryptInit_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	s_check = EVP_CIPHER_CTX_ctrl(
		s_evp_cipher_ctx,
		EVP_CTRL_GCM_SET_IVLEN,
		(int)s_iv_size,
		(void *)(NULL)
	);
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	/* Initialise key and IV */
	s_check = EVP_DecryptInit_ex(
		s_evp_cipher_ctx /* ctx */,
		(const EVP_CIPHER *)(NULL) /* cipher */,
		(ENGINE *)(NULL) /* engine */,
		(const unsigned char *)s_key /* key */,
		(const unsigned char *)s_iv /* iv */
	);
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_DecryptInit_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	if((s_aad == ((const void *)(NULL))) || (s_aad_size <= ((size_t)0u))) {
		static const uint8_t cg_empty[1] = {0};
		s_aad = (const void *)(&cg_empty[0]);
	}
	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	{
		/* Use a separate variable so the AAD-phase output length does not
		 * overwrite s_size, which is used for the ciphertext phase below. */
		int s_aad_out_len = 0;
		s_check = EVP_DecryptUpdate(
			s_evp_cipher_ctx,
			(unsigned char *)(NULL),
			&s_aad_out_len,
			(const unsigned char *)s_aad,
			(int)s_aad_size
		);
	}
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_DecryptUpdate failed !\n");
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
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_DecryptUpdate failed !\n");
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
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed !\n");
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
	if(SSL_inspection_unlikely(s_check <= 0)) { /* Verify failed */
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "EVP_DecryptFinal_ex failed !\n");
		EVP_CIPHER_CTX_free(s_evp_cipher_ctx);
		errno = EINVAL;
		return((ssize_t)(-1));
	}
	else {
		s_plaintext_size += (ssize_t)s_size;
	}

	EVP_CIPHER_CTX_free(s_evp_cipher_ctx);

	return(s_plaintext_size);
}

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
