/*
	Copyright (C) MINZKN.COM
	All rights reserved.
	Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_main_c__)
# define __def_sslid_source_main_c__ "main.c"

#include "sslid-lib.h"

#include <getopt.h>

static void *SSL_inspection_accept_handler(void *s_context_ptr);

#if 0L /* ALPN */
static int SSL_inspection_apln_select_callback_handler(SSL *s_ssl, const unsigned char **s_out, unsigned char *s_outlen, const unsigned char *s_in, unsigned int s_inlen, void *s_argument);
#endif

int main(int s_argc, char **s_argv);

static void *SSL_inspection_accept_handler(void *s_context_ptr)
{
	SSL_inspection_context_t *s_context = s_context_ptr;

	char s_accept_address_string[ INET6_ADDRSTRLEN ];

	SSL *s_accept_ssl = (SSL *)0;

	int s_is_accept_ssl_established = 0;
	int s_is_connect_ssl_established = 0;

	int s_is_accept_ktls_rx_supported = 0;
	int s_is_accept_ktls_tx_supported = 0;
	int s_is_connect_ktls_rx_supported = 0;
	int s_is_connect_ktls_tx_supported = 0;
	int s_is_ktls_forward_supported = 0;
	
	int s_check;

	SSL_CTX *s_connect_ssl_ctx = (SSL_CTX *)0;
	SSL *s_connect_ssl = (SSL *)0;
	int s_connect_socket = (-1);

	int s_splice_pipe[2] = { /* [0]=read, [1]=write */
		(-1), (-1)
	};

	off_t s_forward_transfer_size = (off_t)0;
	off_t s_backward_transfer_size = (off_t)0;

	(void)inet_ntop(
		s_context->m_sockaddr_storage.ss_family,
		(const void *)(&s_context->m_sockaddr_storage),
		(char *)memset((void *)(&s_accept_address_string[0]), 0, sizeof(s_accept_address_string)),
		(socklen_t)sizeof(s_accept_address_string)
	);
	if(s_context->m_is_verbose >= 0) {
		(void)fprintf(
			stdout,
			"Accepted (fd=%d, accept-from=\"%s\")\n",
			s_context->m_accept_socket,
			(char *)(&s_accept_address_string[0])
		);
	}

#if def_SSL_inspection_socket_buffer_tx > 0
	s_check = SSL_inspection_set_tx_socket_buffer_size(s_context->m_accept_socket, (size_t)def_SSL_inspection_socket_buffer_tx);
	if(s_check == (-1)) {
		perror("SSL_inspection_set_tx_socket_buffer_size (accept)");
	}
#endif
#if def_SSL_inspection_socket_buffer_rx > 0
	s_check = SSL_inspection_set_rx_socket_buffer_size(s_context->m_accept_socket, (size_t)def_SSL_inspection_socket_buffer_rx);
	if(s_check == (-1)) {
		perror("SSL_inspection_set_rx_socket_buffer_size (accept)");
	}
#endif

	if(s_context->m_ssl_ctx == ((SSL_CTX *)0)) {
		(void)fprintf(
			stderr,
			"For accept SSL_CTX is null ! (fd=%d, accept-from=\"%s\")\n",
			s_context->m_accept_socket,
			(char *)(&s_accept_address_string[0])
		);
		goto l_ssl_clean;
	}
	else {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		unsigned long s_connect_options = 0UL;
#else
		long s_connect_options = 0L;
#endif
		const SSL_METHOD *s_connect_ssl_method;

		/* connect side SSL */
		s_connect_options |= SSL_OP_ALL;
		if(s_context->m_use_ktls != 0u) {
			s_connect_options |= SSL_OP_NO_COMPRESSION;
			s_connect_options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
		}
		/* s_connect_options |= SSL_OP_TLS_ROLLBACK_BUG; */
		/* s_connect_options |= SSL_OP_SINGLE_DH_USE; */
		/* s_connect_options |= SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION; */
		/* s_connect_options |= SSL_OP_NO_TICKET; */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		s_connect_ssl_method = TLS_client_method();
#elif 1L /* TLS v1.2 */
		s_connect_ssl_method = TLSv1_2_client_method();
		/* s_connect_options |= SSL_OP_NO_SSLv2; */
		/* s_connect_options |= SSL_OP_NO_SSLv3; */
		/* s_connect_options |= SSL_OP_NO_TLSv1; */
		/* s_connect_options |= SSL_OP_NO_TLSv1_1; */
#elif 0L /* TLS v1.1 */
		s_connect_ssl_method = TLSv1_1_client_method();
		/* s_connect_options |= SSL_OP_NO_SSLv2; */
		/* s_connect_options |= SSL_OP_NO_SSLv3; */
		/* s_connect_options |= SSL_OP_NO_TLSv1; */
#elif 0L /* TLS v1.0 */
		s_connect_ssl_method = TLSv1_client_method();
		/* s_connect_options |= SSL_OP_NO_SSLv2; */
		/* s_connect_options |= SSL_OP_NO_SSLv3; */
#else /* SSL v3 */
		s_connect_ssl_method = SSLv23_client_method();
#endif
		if(s_connect_ssl_method == ((const SSL_METHOD *)0)) {
			(void)fprintf(
				stderr,
				"not supported method ! (connect, accept-from=\"%s\", connect-to=\"%s\")\n",
				(char *)(&s_accept_address_string[0]),
				s_context->m_connect_address
			);
			goto l_ssl_clean;
		}

		s_connect_ssl_ctx = SSL_CTX_new(s_connect_ssl_method);
		if(s_connect_ssl_ctx == ((SSL_CTX *)0)) {
			ERR_print_errors_fp(stderr);
			(void)fprintf(stderr, "SSL_CTX_new failed ! (connect)\n");
			goto l_ssl_clean;
		}
		
		(void)SSL_CTX_set_options(s_connect_ssl_ctx, s_connect_options);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		do {
			long s_min_proto_version;
			long s_max_proto_version;

			s_min_proto_version = TLS1_2_VERSION;
			if(s_context->m_use_ktls != 0u) {
				s_max_proto_version = TLS1_2_VERSION;
			}
			else {
				s_max_proto_version = TLS1_3_VERSION;
			}

			s_check = (int)SSL_CTX_set_min_proto_version(s_connect_ssl_ctx, s_min_proto_version);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_set_min_proto_version failed ! (connect, min_proto_version=%ld)\n", (long)s_min_proto_version);
				goto l_ssl_clean;
			}

			s_check = (int)SSL_CTX_set_max_proto_version(s_connect_ssl_ctx, s_max_proto_version);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_set_max_proto_version failed ! (connect, max_proto_version=%ld)\n", (long)s_max_proto_version);
				goto l_ssl_clean;
			}
		}while(0);
#endif
	
		if(s_context->m_cipher_list != ((const char *)0)) {
			s_check = SSL_CTX_set_cipher_list(s_connect_ssl_ctx, s_context->m_cipher_list);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_set_cipher_list failed ! (connect, \"%s\")\n", s_context->m_cipher_list);
				goto l_ssl_clean;
			}
		}

#if 0L /* ALPN */
		do { /* set alpn protos */
			static const unsigned char s_alpn[] = {
				0x06, 's', 'p', 'd', 'y', '/', '1',
				0x02, 'h', '2',
				0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
			};

			s_check = SSL_CTX_set_alpn_protos(
				s_connect_ssl_ctx,
				(const unsigned char *)(&s_alpn[0]),
				(unsigned int)sizeof(s_alpn)
			);
			if(s_check != 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_set_alpn_protos failed ! (connect)\n");
				goto l_ssl_clean;
			}
		}while(0);
#endif
	}

	if(s_context->m_is_verbose >= 0) {
		(void)fprintf(
			stdout,
			"%s connecting. (for fd=%d, \"[%s]:%d\")\n",
			(s_connect_ssl_ctx == ((SSL_CTX *)0)) ? "TCP" : "SSL",
			s_context->m_accept_socket,
			s_context->m_connect_address,
			s_context->m_connect_port
		);
	}
	s_connect_socket = SSL_inspection_simple_connect(
		s_connect_ssl_ctx,
		(SSL **)(&s_connect_ssl),
		s_context->m_connect_address,
		s_context->m_connect_port,
		60000
	);
	if(s_connect_socket == (-1)) {
		perror("SSL_inspection_simple_connect");
		goto l_ssl_clean;
	}
	if(s_context->m_is_verbose >= 0) {
		(void)fprintf(
			stdout,
			"%s connected. (fd=%d, for fd=%d, \"[%s]:%d\")\n",
			(s_connect_ssl == ((SSL *)0)) ? "TCP" : "SSL",
			s_connect_socket,
			s_context->m_accept_socket,
			s_context->m_connect_address,
			s_context->m_connect_port
		);
	}
	s_is_connect_ssl_established = 1;
	
#if def_SSL_inspection_socket_buffer_tx > 0
	s_check = SSL_inspection_set_tx_socket_buffer_size(s_connect_socket, (size_t)def_SSL_inspection_socket_buffer_tx);
	if(s_check == (-1)) {
		perror("SSL_inspection_set_tx_socket_buffer_size (connect)");
	}
#endif
#if def_SSL_inspection_socket_buffer_rx > 0
	s_check = SSL_inspection_set_rx_socket_buffer_size(s_connect_socket, (size_t)def_SSL_inspection_socket_buffer_rx);
	if(s_check == (-1)) {
		perror("SSL_inspection_set_rx_socket_buffer_size (connect)");
	}
#endif
	
	if(s_context->m_is_verbose >= 1) {
		const SSL_CIPHER *s_connect_cipher;

		s_connect_cipher = SSL_get_current_cipher(s_connect_ssl);
		if(s_connect_cipher != ((const SSL_CIPHER *)0)) {
			(void)fprintf(
				stdout,
				"current connect-side cipher info (fd=%d, \"%s\")\n",
				s_connect_socket,
				SSL_state_string_long(s_connect_ssl)
			);
			(void)fprintf(
				stdout,
				"  - vesion : \"%s\"\n",
				SSL_CIPHER_get_version(s_connect_cipher)
			);
			(void)fprintf(
				stdout,
				"  - bits : %d\n",
				SSL_CIPHER_get_bits(s_connect_cipher, (int *)0)
			);
			(void)fprintf(
				stdout,
				"  - name : \"%s\"\n",
				SSL_CIPHER_get_name(s_connect_cipher)
			);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
			(void)fprintf(
				stdout,
				"  - id : %lu\n"
				"  - kx_nid : %d\n"
				"  - auth_nid : %d\n"
				"  - Is AEAD : %d\n",
				(unsigned long)SSL_CIPHER_get_id(s_connect_cipher),
				SSL_CIPHER_get_kx_nid(s_connect_cipher),
				SSL_CIPHER_get_auth_nid(s_connect_cipher),
				SSL_CIPHER_is_aead(s_connect_cipher)
			);
#endif
		}
	
		if(s_context->m_is_verbose >= 4) {
			(void)SSL_SESSION_print_fp(stdout, SSL_get_session(s_connect_ssl));
		}
	}

	if(s_context->m_ssl_ctx != ((SSL_CTX *)0)) {
		/* accept side SSL */
		s_accept_ssl = SSL_new(s_context->m_ssl_ctx);
		if(s_accept_ssl == ((SSL *)0)) {
			(void)fprintf(stderr, "SSL_new failed ! (accept)\n");
			goto l_ssl_clean;
		}

		s_check = SSL_set_fd(s_accept_ssl, s_context->m_accept_socket);
		if(s_check <= 0) {
			(void)fprintf(stderr, "SSL_set_fd failed ! (accept, fd=%d)\n", s_context->m_accept_socket);
			goto l_ssl_clean;
		}

		/* service side SSL accept */
		do { /* blocking SSL accept */
			int s_ssl_error;
			unsigned long s_error_code;

			for(;;) {
				s_check = SSL_accept(s_accept_ssl);
				if(s_check == 1) { /* accepted */
					if(s_context->m_is_verbose >= 0) {
						(void)fprintf(stdout, "SSL Accepted (fd=%d)\n", s_context->m_accept_socket);
					}
					s_is_accept_ssl_established = 1;
					break;
				}

				s_ssl_error = SSL_get_error(s_accept_ssl, s_check);
				if(s_ssl_error == SSL_ERROR_WANT_READ) {
					continue;
				}
				if(s_ssl_error == SSL_ERROR_WANT_WRITE) {
					continue;
				}

				/* not established */

				(void)fprintf(
					stderr,
					"SSL accept failed ! (fd=%d)\n",
					s_context->m_accept_socket
				);

				for(;;) {
					s_error_code = ERR_get_error();
					if(s_error_code == 0UL) {
						break;
					}

					(void)fprintf(
						stderr,
						"  - SSL accept error info (fd=%d) : %lu, \"%s\"\n",
						s_context->m_accept_socket,
						s_error_code,
						ERR_error_string(s_error_code, NULL)
					);
				}

				goto l_ssl_clean;
			}
		}while(0);
			
		if(s_context->m_is_verbose >= 1) {
			const SSL_CIPHER *s_accept_cipher;

			s_accept_cipher = SSL_get_current_cipher(s_accept_ssl);
			if(s_accept_cipher != ((const SSL_CIPHER *)0)) {
				(void)fprintf(
					stdout,
					"current accept-side cipher info (fd=%d, \"%s\")\n",
					s_context->m_accept_socket,
					SSL_state_string_long(s_accept_ssl)
				);
				(void)fprintf(
					stdout,
					"  - version  : \"%s\"\n",
					SSL_CIPHER_get_version(s_accept_cipher)
				);
				(void)fprintf(
					stdout,
					"  - bits : %d\n",
					SSL_CIPHER_get_bits(s_accept_cipher, (int *)0)
				);
				(void)fprintf(
					stdout,
					"  - name : \"%s\"\n",
					SSL_CIPHER_get_name(s_accept_cipher)
				);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
				(void)fprintf(
					stdout,
					"  - id : %lu\n"
					"  - kx_nid : %d\n"
					"  - auth_nid : %d\n"
					"  - Is AEAD : %d\n",
					(unsigned long)SSL_CIPHER_get_id(s_accept_cipher),
					SSL_CIPHER_get_kx_nid(s_accept_cipher),
					SSL_CIPHER_get_auth_nid(s_accept_cipher),
					SSL_CIPHER_is_aead(s_accept_cipher)
				);
#endif
			}

			if(s_context->m_is_verbose >= 4) {
				(void)SSL_SESSION_print_fp(stdout, SSL_get_session(s_accept_ssl));
			}
		}
	}

	/* 양단 TLS handshake 가 완료된 시점 */

#if 0L /* ALPN */
	do {
		const unsigned char *s_alpn;
		unsigned int s_alpn_size;
	
		s_alpn = (const unsigned char *)0;
		s_alpn_size = (unsigned int)0u;
		SSL_get0_next_proto_negotiated(
			s_accept_ssl,
			(const unsigned char **)(&s_alpn),
			(unsigned int *)(&s_alpn_size)
		);
		if(s_alpn == ((const unsigned char *)0)) {
			SSL_get0_alpn_selected(
				s_accept_ssl,
				(const unsigned char **)(&s_alpn),
				(unsigned int *)(&s_alpn_size)
			);
		}
		if((s_alpn != ((const unsigned char *)0)) && (s_alpn_size > ((unsigned int)0u))) {
			if(s_context->m_is_verbose >= 0) {
				SSL_inspection_hexdump(
					"ALPN(accept) SEL ",
					(const void *)s_alpn,
					(size_t)s_alpn_size
				);
			}
		}

		s_alpn = (const unsigned char *)0;
		s_alpn_size = (unsigned int)0u;
		SSL_get0_next_proto_negotiated(
			s_connect_ssl,
			(const unsigned char **)(&s_alpn),
			(unsigned int *)(&s_alpn_size)
		);
		if(s_alpn == ((const unsigned char *)0)) {
			SSL_get0_alpn_selected(
				s_connect_ssl,
				(const unsigned char **)(&s_alpn),
				(unsigned int *)(&s_alpn_size)
			);
		}
		if((s_alpn != ((const unsigned char *)0)) && (s_alpn_size > ((unsigned int)0u))) {
			if(s_context->m_is_verbose >= 0) {
				SSL_inspection_hexdump(
					"ALPN(connect) SEL ",
					(const void *)s_alpn,
					(size_t)s_alpn_size
				);
			}
		}
	}while(0);
#endif

	/* keep-alive setting */
#if 1L
	do { /* 선택사항 : TCP 연결을 임의로 timeout 에 의해서 한쪽이 끊는 것을 방지하기 위해서 SO_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPINTVL 설정 */
		int s_value = 1;

		s_check = setsockopt(
			s_context->m_accept_socket,
			(int)(SOL_SOCKET),
			(int)(SO_KEEPALIVE),
			(const void *)(&s_value),
			(socklen_t)sizeof(s_value)
		);
		if(s_check == (-1)) {
			perror("SO_KEEPALIVE");
		}
		else {
#if defined(TCP_KEEPIDLE)
			s_value = 60 /* sec */;
			s_check = setsockopt(
				s_context->m_accept_socket,
				(int)(IPPROTO_TCP),
				(int)(TCP_KEEPIDLE),
				(const void *)(&s_value),
				(socklen_t)sizeof(s_value)
			);
			if(s_check == (-1)) {
				perror("TCP_KEEPIDLE");
			}
#endif
#if defined(TCP_KEEPINTVL)
			s_value = 30 /* sec */;
			s_check = setsockopt(
				s_context->m_accept_socket,
				(int)(IPPROTO_TCP),
				(int)(TCP_KEEPINTVL),
				(const void *)(&s_value),
				(socklen_t)sizeof(s_value)
			);
			if(s_check == (-1)) {
				perror("TCP_KEEPINTVL");
			}
#endif
		}
	}while(0);
#endif

	if((s_context->m_use_ktls & (def_SSL_inspection_use_ktls_rx | def_SSL_inspection_use_ktls_tx)) != def_SSL_inspection_use_ktls_none) { /* setup kTLS */
		if(s_accept_ssl != ((SSL *)0)) {
			s_check = SSL_inspection_set_ulp_tls(
				s_context->m_accept_socket
			);
			if((s_check == (-1)) && (errno != EEXIST)) {
				(void)fprintf(
					stderr,
					"SOL_TCP/TCP_ULP(accept) : %s (fd=%d)\n",
					strerror(errno),
					s_context->m_accept_socket
				);
				s_is_accept_ktls_rx_supported = 0;
				s_is_accept_ktls_tx_supported = 0;
			}
			else {
				size_t s_crypto_info_size;
				void *s_crypto_info_ptr;

				if((s_context->m_use_ktls & def_SSL_inspection_use_ktls_rx) != def_SSL_inspection_use_ktls_none) {
					s_crypto_info_ptr = SSL_inspection_build_crypto_info(s_accept_ssl, 0 /* is_encrypt */, (size_t *)(&s_crypto_info_size));
					if(s_crypto_info_ptr == ((void *)0)) {
						s_check = (-1);
					}
					else {
						if(s_context->m_is_verbose >= 1) {
							(void)SSL_inspection_dump_crypto_info("accept, for decrypt", (const void *)s_crypto_info_ptr);
						}
						s_check = SSL_inspection_set_crypto_info(
							s_context->m_accept_socket,
							0 /* is_encrypt */,
							s_crypto_info_ptr,
							s_crypto_info_size
						);
						free(s_crypto_info_ptr);
					}
					if(s_check == (-1)) {
						(void)fprintf(stdout, "SSL_inspection_set_crypto_info failed ! (accept, for decrypt, fd=%d)\n", s_context->m_accept_socket);
					}
					else {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(stdout, "SOL_TCP/TCP_ULP(accept, for decrypt) supported. (fd=%d)\n", s_context->m_accept_socket);
						}
						s_is_accept_ktls_rx_supported = 1;
					}
				}

				if((s_context->m_use_ktls & def_SSL_inspection_use_ktls_tx) != def_SSL_inspection_use_ktls_none) {
					s_crypto_info_ptr = SSL_inspection_build_crypto_info(s_accept_ssl, 1 /* is_encrypt */, (size_t *)(&s_crypto_info_size));
					if(s_crypto_info_ptr == ((void *)0)) {
						s_check = (-1);
					}
					else {
						if(s_context->m_is_verbose >= 1) {
							(void)SSL_inspection_dump_crypto_info("accept, for encrypt", (const void *)s_crypto_info_ptr);
						}
						s_check = SSL_inspection_set_crypto_info(
							s_context->m_accept_socket,
							1 /* is_encrypt */,
							s_crypto_info_ptr,
							s_crypto_info_size
						);
						free(s_crypto_info_ptr);
					}
					if(s_check == (-1)) {
						(void)fprintf(stdout, "SSL_inspection_set_crypto_info failed ! (accept, for encrypt, fd=%d)\n", s_context->m_accept_socket);
					}
					else {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(stdout, "SOL_TCP/TCP_ULP(accept, for encrypt) supported. (fd=%d)\n", s_context->m_accept_socket);
						}
						s_is_accept_ktls_tx_supported = 1;
					}
				}
			}
		}

		if(s_connect_ssl != ((SSL *)0)) {
			s_check = SSL_inspection_set_ulp_tls(
				s_connect_socket
			);
			if((s_check == (-1)) && (errno != EEXIST)) {
				(void)fprintf(
					stderr,
					"SOL_TCP/TCP_ULP(connect) : %s (fd=%d)\n",
					strerror(errno),
					s_connect_socket
				);
				s_is_connect_ktls_rx_supported = 0;
				s_is_connect_ktls_tx_supported = 0;
			}
			else {
				size_t s_crypto_info_size;
				void *s_crypto_info_ptr;

				if((s_context->m_use_ktls & def_SSL_inspection_use_ktls_rx) != def_SSL_inspection_use_ktls_none) {
					s_crypto_info_ptr = SSL_inspection_build_crypto_info(s_connect_ssl, 0 /* is_encrypt */, (size_t *)(&s_crypto_info_size));
					if(s_crypto_info_ptr == ((void *)0)) {
						s_check = (-1);
					}
					else {
						if(s_context->m_is_verbose >= 1) {
							(void)SSL_inspection_dump_crypto_info("connect, for decrypt", (const void *)s_crypto_info_ptr);
						}
						s_check = SSL_inspection_set_crypto_info(
							s_connect_socket,
							0 /* is_encrypt */,
							s_crypto_info_ptr,
							s_crypto_info_size
						);
						free(s_crypto_info_ptr);
					}
					if(s_check == (-1)) {
						(void)fprintf(stdout, "SSL_inspection_set_crypto_info failed ! (connect, for decrypt, fd=%d)\n", s_connect_socket);
					}
					else {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(stdout, "SOL_TCP/TCP_ULP(connect, for decrypt) supported. (fd=%d)\n", s_connect_socket);
						}
						s_is_connect_ktls_rx_supported = 1;
					}
				}

				if((s_context->m_use_ktls & def_SSL_inspection_use_ktls_tx) != def_SSL_inspection_use_ktls_none) {
					s_crypto_info_ptr = SSL_inspection_build_crypto_info(s_connect_ssl, 1 /* is_encrypt */, (size_t *)(&s_crypto_info_size));
					if(s_crypto_info_ptr == ((void *)0)) {
						s_check = (-1);
					}
					else {
						if(s_context->m_is_verbose >= 1) {
							(void)SSL_inspection_dump_crypto_info("connect, for encrypt", (const void *)s_crypto_info_ptr);
						}
						s_check = SSL_inspection_set_crypto_info(
							s_connect_socket,
							1 /* is_encrypt */,
							s_crypto_info_ptr,
							s_crypto_info_size
						);
						free(s_crypto_info_ptr);
					}
					if(s_check == (-1)) {
						(void)fprintf(stdout, "SSL_inspection_set_crypto_info failed ! (connect, for encrypt, fd=%d)\n", s_connect_socket);
					}
					else {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(stdout, "SOL_TCP/TCP_ULP(connect, for encrypt) supported. (fd=%d)\n", s_connect_socket);
						}
						s_is_connect_ktls_tx_supported = 1;
					}
				}
			}
		}
	}
	
	if((s_context->m_use_ktls & def_SSL_inspection_use_ktls_forward) != def_SSL_inspection_use_ktls_none) { /* setup kTLS forward (Extension for accelator) */
		unsigned int s_ktls_forward_flags = 0x00000000u;

		s_check = SSL_inspection_pseudo_set_ktls_forward(
			s_context->m_accept_socket,
			s_connect_socket,
			s_ktls_forward_flags
		);
		if(s_check == (-1)) {
			s_is_ktls_forward_supported = 0;
			
			(void)fprintf(
				stderr,
				def_hwport_color_red "kTLS forward syscall failed ! " def_hwport_color_normal "(accept-fd=%d, connect-fd=%d, kTLS-forward-flags=%08XH)\n",
				s_context->m_accept_socket,
				s_connect_socket,
				s_ktls_forward_flags
			);
		}
		else {
			s_is_ktls_forward_supported = 1;

			(void)fprintf(
				stdout,
				def_hwport_color_green "kTLS forward enabled." def_hwport_color_normal " (accept-fd=%d, connect-fd=%d, kTLS-forward-flags=%08XH)\n",
				s_context->m_accept_socket,
				s_connect_socket,
				s_ktls_forward_flags
			);
		}

		/* 일단 이 변수는 사용되지 않으나 추후 고려될지 모르는 상황 */
		(void)s_is_ktls_forward_supported;
	}
	
	if((s_context->m_use_splice != 0) &&
		(s_is_accept_ktls_rx_supported != 0) &&	
		(s_is_accept_ktls_tx_supported != 0) &&	
		(s_is_connect_ktls_rx_supported != 0) &&	
		(s_is_connect_ktls_tx_supported != 0)) { /* make pipe for splice */
		s_check = pipe((int *)(&s_splice_pipe[0]));
		if(s_check == (-1)) {
			perror("pipe for splice");
			s_splice_pipe[0] = (-1);
			s_splice_pipe[1] = (-1);
		}
		else {
			if(s_context->m_is_verbose >= 0) {
				(void)fprintf(
					stdout,
					def_hwport_color_green "pipe created for splice." def_hwport_color_normal " (accept-fd=%d, connect-fd=%d, R[0]=%d, W[1]=%d)\n",
					s_context->m_accept_socket,
					s_connect_socket,
					s_splice_pipe[0],
					s_splice_pipe[1]
				);
			}
		}
	}

	while(SSL_inspection_is_break_main_loop() == 0) {
		fd_set s_fd_set_rx;
		int s_max_fd;
		struct timeval s_timeval;
		int s_select_check;

		if((s_context->m_debug_flags & def_SSL_inspection_debug_flag_first_recv) != def_SSL_inspection_debug_flag_none) {
			if(s_forward_transfer_size == ((off_t)0)) {
				FD_ZERO(&s_fd_set_rx);
				s_select_check = 0;

				(void)fprintf(
					stdout,
					def_hwport_color_cyan "DEBUG" def_hwport_color_normal "(%08XH/%08XH): first recv trying...\n",
					def_SSL_inspection_debug_flag_first_recv,
					s_context->m_debug_flags
				);
				goto l_recv_from_accept;
			}
		}

		FD_ZERO(&s_fd_set_rx);
		
		s_max_fd = 0;
		FD_SET(s_context->m_accept_socket, &s_fd_set_rx);
		if(s_context->m_accept_socket > s_max_fd) {
			s_max_fd = s_context->m_accept_socket;
		}
		FD_SET(s_connect_socket, &s_fd_set_rx);
		if(s_connect_socket > s_max_fd) {
			s_max_fd = s_connect_socket;
		}

		s_timeval.tv_sec = 10;
		s_timeval.tv_usec = 0;
		s_select_check = select(
			s_max_fd + 1,
			(fd_set *)(&s_fd_set_rx),
			(fd_set *)0,
			(fd_set *)0,
			(struct timeval *)(&s_timeval)
		);
		if(s_select_check == (-1)) {
			perror("select");
			break;
		}
		else if(s_select_check == 0) { /* timeout */
			if(s_context->m_is_verbose >= 0) {
				(void)fprintf(stdout, "IDLE: wait event (accept-fd=%d, connect-fd=%d)\n", s_context->m_accept_socket, s_connect_socket);
			}
		}
		else {
			ssize_t s_recv_bytes;
			ssize_t s_send_bytes;

			if((s_select_check > 0) && (FD_ISSET(s_context->m_accept_socket, &s_fd_set_rx) != 0)) { /* from accept side */
				--s_select_check;

l_recv_from_accept:;
				if((s_splice_pipe[1] != (-1)) && (s_splice_pipe[0] != (-1))) {
					s_recv_bytes = splice(
						s_context->m_accept_socket,
						(loff_t *)0,
						s_splice_pipe[1],
						(loff_t *)0,
						(size_t)def_SSL_inspection_splice_rx_size,
						SPLICE_F_MOVE
					);
					if(s_recv_bytes == ((ssize_t)(-1))) {
						(void)fprintf(
							stderr,
							"splice rx failed ! (accept) : %s (fd=%d, %s)\n",
							strerror(errno),
							s_context->m_accept_socket,
							"ULP/kTLS/splice"
						);

						s_is_accept_ssl_established = 0;
					}
					else if(s_recv_bytes == ((ssize_t)0)) {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(
								stderr,
								"splice rx disconnected ! (accept, fd=%d, %s)\n",
								s_context->m_accept_socket,
								"ULP/kTLS/splice"
							);
						}
						
						s_is_accept_ssl_established = 0;
					}
					else {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(
								stdout,
								"From accept rx (fd=%d) %lld + %ld bytes%s\n",
								s_context->m_accept_socket,
								(long long)s_forward_transfer_size,
								(long)s_recv_bytes,
								def_hwport_color_green " (with kTLS/splice)" def_hwport_color_normal
							);
						}
					
						s_send_bytes = splice(
							s_splice_pipe[0],
							(loff_t *)0,
							s_connect_socket,
							(loff_t *)0,
							(size_t)s_recv_bytes,
							SPLICE_F_MOVE
						);
						if(s_send_bytes == ((ssize_t)(-1))) {
							(void)fprintf(
								stderr,
								"splice tx failed ! (connect) : %s (fd=%d, %s)\n",
								strerror(errno),
								s_connect_socket,
								"ULP/kTLS/splice"
							);

							s_is_connect_ssl_established = 0;
						}
						else if(s_send_bytes != s_recv_bytes) {
							(void)fprintf(
								stderr,
								def_hwport_color_red "splice tx/rx failed !" def_hwport_color_normal " (connect) : %s (fd=%d, %ld/%ld, %s)\n",
								strerror(errno),
								s_connect_socket,
								(long)s_send_bytes,
								(long)s_recv_bytes,
								"ULP/kTLS/splice"
							);
							
							s_forward_transfer_size += (off_t)s_send_bytes;
						}
						else {
							if(s_context->m_is_verbose >= 0) {
								(void)fprintf(
									stdout,
									"To connect tx (fd=%d) %lld + %ld/%ld bytes%s\n",
									s_connect_socket,
									(long long)s_forward_transfer_size,
									(long)s_send_bytes,
									(long)s_recv_bytes,
									def_hwport_color_green " (with kTLS/splice)" def_hwport_color_normal
								);
							}

							s_forward_transfer_size += (off_t)s_send_bytes;
						}
					}
				}
				else {
					s_recv_bytes = SSL_inspection_recv(
						(s_is_accept_ktls_rx_supported == 0) ? s_accept_ssl : ((SSL *)0),
						s_context->m_accept_socket,
						s_context->m_buffer,
						s_context->m_buffer_size,
						(-1)
					);
					if(s_recv_bytes == ((ssize_t)(-1))) {
						(void)fprintf(
							stderr,
							"SSL_inspection_recv failed ! (accept) : %s (fd=%d, %s)\n",
							strerror(errno),
							s_context->m_accept_socket,
							(s_is_accept_ktls_rx_supported == 0) ? "SSL" : "ULP"
						);

						s_is_accept_ssl_established = 0;
					}
					else if(s_recv_bytes == ((ssize_t)0)) {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(
								stderr,
								"SSL_inspection_recv disconnected ! (accept, fd=%d, %s)\n",
								s_context->m_accept_socket,
								(s_is_accept_ktls_rx_supported == 0) ? "SSL" : "ULP"
							);
						}

						s_is_accept_ssl_established = 0;
					}
					else {
						if(s_context->m_is_verbose >= 3) { /* 전체 데이터를 hexa dump */
							(void)fprintf(
								stdout,
								"From accept rx (fd=%d) %lld + %ld bytes%s\n",
								s_context->m_accept_socket,
								(long long)s_forward_transfer_size,
								(long)s_recv_bytes,
								(s_is_accept_ktls_rx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
							);
							(void)SSL_inspection_hexdump("  ", s_context->m_buffer, (size_t)s_recv_bytes);
						}
						else if(s_context->m_is_verbose >= 2) { /* 전체 데이터를 printable 한 평문으로 출력 */
							(void)fprintf(
								stdout,
								"From accept rx (fd=%d) {\n%.*s} %lld + %ld bytes%s\n",
								s_context->m_accept_socket,
								(int)s_recv_bytes,
								(char *)SSL_inspection_convert_printable_ascii(s_context->m_dup_buffer, s_context->m_buffer, (size_t)s_recv_bytes),
								(long long)s_forward_transfer_size,
								(long)s_recv_bytes,
								(s_is_accept_ktls_rx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
							);
						}
						else if(s_context->m_is_verbose >= 1) { /* 너무 많이 나오니까 앞에 16 bytes 까지만 출력 */
							(void)fprintf(
								stdout,
								"From accept rx (fd=%d) %lld + %ld bytes%s\n",
								s_context->m_accept_socket,
								(long long)s_forward_transfer_size,
								(long)s_recv_bytes,
								(s_is_accept_ktls_rx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
							);
							(void)SSL_inspection_hexdump("  ", s_context->m_buffer, (s_recv_bytes >= ((ssize_t)16)) ? ((size_t)16u) : ((size_t)s_recv_bytes));
						}
						else if(s_context->m_is_verbose >= 0) {
							(void)fprintf(
								stdout,
								"From accept rx (fd=%d) %lld + %ld bytes%s\n",
								s_context->m_accept_socket,
								(long long)s_forward_transfer_size,
								(long)s_recv_bytes,
								(s_is_accept_ktls_rx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
							);
						}

						/* encrypt pseudo try */
						if(s_context->m_is_verbose >= 1) {
							size_t s_tls_payload_size;
							void *s_tls_payload_ptr;

							s_tls_payload_ptr = SSL_inspection_pseudo_encrypt(
								(s_is_connect_ktls_tx_supported == 0) ? s_connect_ssl : ((SSL *)0),
								s_connect_socket,
								s_context->m_buffer,
								(size_t)s_recv_bytes,
								(size_t *)(&s_tls_payload_size)
							);
							if(s_tls_payload_ptr == ((void *)0)) {
								perror("SSL_inspection_pseudo_encrypt (connect)");
							}
							else {
								(void)fprintf(
									stdout,
									def_hwport_color_magenta "Pseudo-Encrypt" def_hwport_color_normal " for forward (fd=%d, tls-payloaod-size=%lu, plaintext-size=%lu) ***\n",
									s_connect_socket,
									(unsigned long)s_tls_payload_size,
									(unsigned long)s_recv_bytes
								);
								(void)SSL_inspection_hexdump(
									"  " def_hwport_color_cyan "[PSEUDO-EN]" def_hwport_color_normal " ",
									s_tls_payload_ptr,
									s_tls_payload_size
								);

								free(s_tls_payload_ptr);
							}
						}

						s_send_bytes = SSL_inspection_send_fill(
							(s_is_connect_ktls_tx_supported == 0) ? s_connect_ssl : ((SSL *)0),
							s_connect_socket,
							s_context->m_buffer,
							(size_t)s_recv_bytes,
							(-1)
						);
						if(s_send_bytes == ((ssize_t)(-1))) {
							(void)fprintf(
								stderr,
								"SSL_inspection_send_fill failed ! (connect) : %s (fd=%d, %s)\n",
								strerror(errno),
								s_connect_socket,
								(s_is_connect_ktls_tx_supported == 0) ? "SSL" : "ULP"
							);

							s_is_connect_ssl_established = 0;
						}
						else {
							if(s_context->m_is_verbose >= 3) { /* 전체 데이터를 hexa dump */
								(void)fprintf(
									stdout,
									"To connect tx (fd=%d) %lld + %ld bytes%s\n",
									s_connect_socket,
									(long long)s_forward_transfer_size,
									(long)s_send_bytes,
									(s_is_connect_ktls_tx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
								);
								(void)SSL_inspection_hexdump("  ", s_context->m_buffer, (size_t)s_send_bytes);
							}
							else if(s_context->m_is_verbose >= 2) { /* 전체 데이터를 printable 한 평문으로 출력 */
								(void)fprintf(
									stdout,
									"To connect tx (fd=%d) {\n%.*s} %lld + %ld bytes%s\n",
									s_connect_socket,
									(int)s_send_bytes,
									(char *)SSL_inspection_convert_printable_ascii(s_context->m_dup_buffer, s_context->m_buffer, (size_t)s_send_bytes),
									(long long)s_forward_transfer_size,
									(long)s_send_bytes,
									(s_is_connect_ktls_tx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
								);
							}
							else if(s_context->m_is_verbose >= 1) { /* 너무 많이 나오니까 앞에 16 bytes 까지만 출력 */
								(void)fprintf(
									stdout,
									"To connect tx (fd=%d) %lld + %ld bytes%s\n",
									s_connect_socket,
									(long long)s_forward_transfer_size,
									(long)s_send_bytes,
									(s_is_connect_ktls_tx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
								);
								(void)SSL_inspection_hexdump("  ", s_context->m_buffer, (s_send_bytes >= ((ssize_t)16)) ? ((size_t)16u) : ((size_t)s_send_bytes));
							}
							else if(s_context->m_is_verbose >= 0) {
								(void)fprintf(
									stdout,
									"To connect tx (fd=%d) %lld + %ld bytes%s\n",
									s_connect_socket,
									(long long)s_forward_transfer_size,
									(long)s_send_bytes,
									(s_is_connect_ktls_tx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
								);
							}

							s_forward_transfer_size += (off_t)s_send_bytes;
		
							if((s_context->m_debug_flags & def_SSL_inspection_debug_flag_send_delay) != def_SSL_inspection_debug_flag_none) {
								usleep(1 /* msec */ * 1000);
							}
						}
					}
				}
			}
		
			if((s_is_accept_ssl_established == 0) || (s_is_connect_ssl_established == 0)) {
				break;
			}
			
			if((s_select_check > 0) && (FD_ISSET(s_connect_socket, &s_fd_set_rx) != 0)) { /* from connect side */
				--s_select_check;

				if((s_splice_pipe[1] != (-1)) && (s_splice_pipe[0] != (-1))) {
					s_recv_bytes = splice(
						s_connect_socket,
						(loff_t *)0,
						s_splice_pipe[1],
						(loff_t *)0,
						(size_t)def_SSL_inspection_splice_rx_size,
						SPLICE_F_MOVE
					);
					if(s_recv_bytes == ((ssize_t)(-1))) {
						(void)fprintf(
							stderr,
							"splice rx failed ! (connect) : %s (fd=%d, %s)\n",
							strerror(errno),
							s_connect_socket,
							"ULP/kTLS/splice"
						);

						s_is_connect_ssl_established = 0;
					}
					else if(s_recv_bytes == ((ssize_t)0)) {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(
								stderr,
								"splice rx disconnected ! (connect, fd=%d, %s)\n",
								s_connect_socket,
								"ULP/kTLS/splice"
							);
						}
						
						s_is_connect_ssl_established = 0;
					}
					else {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(
								stdout,
								"From connect rx (fd=%d) %lld + %ld bytes%s\n",
								s_connect_socket,
								(long long)s_backward_transfer_size,
								(long)s_recv_bytes,
								def_hwport_color_green " (with kTLS/splice)" def_hwport_color_normal
							);
						}
					
						s_send_bytes = splice(
							s_splice_pipe[0],
							(loff_t *)0,
							s_context->m_accept_socket,
							(loff_t *)0,
							(size_t)s_recv_bytes,
							SPLICE_F_MOVE
						);
						if(s_send_bytes == ((ssize_t)(-1))) {
							(void)fprintf(
								stderr,
								"splice tx failed ! (accept) : %s (fd=%d, %s)\n",
								strerror(errno),
								s_context->m_accept_socket,
								"ULP/kTLS/splice"
							);

							s_is_accept_ssl_established = 0;
						}
						else if(s_send_bytes != s_recv_bytes) {
							(void)fprintf(
								stderr,
								def_hwport_color_red "splice tx/rx failed !" def_hwport_color_normal " (accept) : %s (fd=%d, %ld/%ld, %s)\n",
								strerror(errno),
								s_context->m_accept_socket,
								(long)s_send_bytes,
								(long)s_recv_bytes,
								"ULP/kTLS/splice"
							);
							
							s_forward_transfer_size += (off_t)s_send_bytes;
						}
						else {
							if(s_context->m_is_verbose >= 0) {
								(void)fprintf(
									stdout,
									"To accept tx (fd=%d) %lld + %ld/%ld bytes%s\n",
									s_context->m_accept_socket,
									(long long)s_backward_transfer_size,
									(long)s_send_bytes,
									(long)s_recv_bytes,
									def_hwport_color_green " (with kTLS/splice)" def_hwport_color_normal
								);
							}

							s_backward_transfer_size += (off_t)s_send_bytes;
						}
					}
				}
				else {
					s_recv_bytes = SSL_inspection_recv(
						(s_is_connect_ktls_rx_supported == 0) ? s_connect_ssl : ((SSL *)0),
						s_connect_socket,
						s_context->m_buffer,
						s_context->m_buffer_size,
						(-1)
					);
					if(s_recv_bytes == ((ssize_t)(-1))) {
						(void)fprintf(
							stderr,
							"SSL_inspection_recv failed ! (connect) : %s (fd=%d, %s)\n",
							strerror(errno),
							s_connect_socket,
							(s_is_connect_ktls_rx_supported == 0) ? "SSL" : "ULP"
						);

						s_is_connect_ssl_established = 0;
					}
					else if(s_recv_bytes == ((ssize_t)0)) {
						if(s_context->m_is_verbose >= 0) {
							(void)fprintf(
								stderr,
								"SSL_inspection_recv disconnected ! (connect, fd=%d, %s)\n",
								s_connect_socket,
								(s_is_connect_ktls_rx_supported == 0) ? "SSL" : "ULP"
							);
						}

						s_is_connect_ssl_established = 0;
					}
					else {
						if(s_context->m_is_verbose >= 3) { /* 전체 데이터를 hexa dump */
							(void)fprintf(
								stdout,
								"From connect rx (fd=%d) %lld + %ld bytes%s\n",
								s_connect_socket,
								(long long)s_backward_transfer_size,
								(long)s_recv_bytes,
								(s_is_connect_ktls_rx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
							);
							(void)SSL_inspection_hexdump("  ", s_context->m_buffer, (size_t)s_recv_bytes);
						}
						else if(s_context->m_is_verbose >= 2) { /* 전체 데이터를 printable 한 평문으로 출력 */
							(void)fprintf(
								stdout,
								"From connect rx (fd=%d) {\n%.*s} %lld + %ld bytes%s\n",
								s_connect_socket,
								(int)s_recv_bytes,
								(char *)SSL_inspection_convert_printable_ascii(s_context->m_dup_buffer, s_context->m_buffer, (size_t)s_recv_bytes),
								(long long)s_backward_transfer_size,
								(long)s_recv_bytes,
								(s_is_connect_ktls_rx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
							);
						}
						else if(s_context->m_is_verbose >= 1) { /* 너무 많이 나오니까 앞에 16 bytes 까지만 출력 */
							(void)fprintf(
								stdout,
								"From connect rx (fd=%d) %lld + %ld bytes%s\n",
								s_connect_socket,
								(long long)s_backward_transfer_size,
								(long)s_recv_bytes,
								(s_is_connect_ktls_rx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
							);
							(void)SSL_inspection_hexdump("  ", s_context->m_buffer, (s_recv_bytes >= ((ssize_t)16)) ? ((size_t)16u) : ((size_t)s_recv_bytes));
						}
						else if(s_context->m_is_verbose >= 0) {
							(void)fprintf(
								stdout,
								"From connect rx (fd=%d) %lld + %ld bytes%s\n",
								s_connect_socket,
								(long long)s_backward_transfer_size,
								(long)s_recv_bytes,
								(s_is_connect_ktls_rx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
							);
						}

						/* encrypt pseudo try */
						if(s_context->m_is_verbose >= 1) {
							size_t s_tls_payload_size;
							void *s_tls_payload_ptr;

							s_tls_payload_ptr = SSL_inspection_pseudo_encrypt(
								(s_is_accept_ktls_tx_supported == 0) ? s_accept_ssl : ((SSL *)0),
								s_context->m_accept_socket,
								s_context->m_buffer,
								(size_t)s_recv_bytes,
								(size_t *)(&s_tls_payload_size)
							);
							if(s_tls_payload_ptr == ((void *)0)) {
								perror("SSL_inspection_pseudo_encrypt (accept)");
							}
							else {
								(void)fprintf(
									stdout,
									def_hwport_color_magenta "Pseudo-Encrypt" def_hwport_color_normal " for backward (fd=%d, tls-payloaod-size=%lu, plaintext-size=%lu) ***\n",
									s_context->m_accept_socket,
									(unsigned long)s_tls_payload_size,
									(unsigned long)s_recv_bytes
								);
								(void)SSL_inspection_hexdump(
									"  " def_hwport_color_cyan "[PSEUDO-EN]" def_hwport_color_normal " ",
									s_tls_payload_ptr,
									s_tls_payload_size
								);

								free(s_tls_payload_ptr);
							}
						}

						s_send_bytes = SSL_inspection_send_fill(
							(s_is_accept_ktls_tx_supported == 0) ? s_accept_ssl : ((SSL *)0),
							s_context->m_accept_socket,
							s_context->m_buffer,
							(size_t)s_recv_bytes,
							(-1)
						);
						if(s_send_bytes == ((ssize_t)(-1))) {
							(void)fprintf(
								stderr,
								"SSL_inspection_send_fill failed ! (accept) : %s (fd=%d, %s)\n",
								strerror(errno),
								s_context->m_accept_socket,
								(s_is_accept_ktls_tx_supported == 0) ? "SSL" : "ULP"
							);

							s_is_accept_ssl_established = 0;
						}
						else {
							if(s_context->m_is_verbose >= 3) { /* 전체 데이터를 hexa dump */
								(void)fprintf(
									stdout,
									"To accept tx (fd=%d) %lld + %ld bytes%s\n",
									s_context->m_accept_socket,
									(long long)s_backward_transfer_size,
									(long)s_send_bytes,
									(s_is_accept_ktls_tx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
								);
								(void)SSL_inspection_hexdump("  ", s_context->m_buffer, (size_t)s_send_bytes);
							}
							else if(s_context->m_is_verbose >= 2) { /* 전체 데이터를 printable 한 평문으로 출력 */
								(void)fprintf(
									stdout,
									"To accept tx (fd=%d) {\n%.*s} %lld + %ld bytes%s\n",
									s_context->m_accept_socket,
									(int)s_send_bytes,
									(char *)SSL_inspection_convert_printable_ascii(s_context->m_dup_buffer, s_context->m_buffer, (size_t)s_send_bytes),
									(long long)s_backward_transfer_size,
									(long)s_send_bytes,
									(s_is_accept_ktls_tx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
								);
							}
							else if(s_context->m_is_verbose >= 1) { /* 너무 많이 나오니까 앞에 16 bytes 까지만 출력 */
								(void)fprintf(
									stdout,
									"To accept tx (fd=%d) %lld + %ld bytes%s\n",
									s_context->m_accept_socket,
									(long long)s_backward_transfer_size,
									(long)s_send_bytes,
									(s_is_accept_ktls_tx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
								);
								(void)SSL_inspection_hexdump("  ", s_context->m_buffer, (s_send_bytes >= ((ssize_t)16)) ? ((size_t)16u) : ((size_t)s_send_bytes));
							}
							else if(s_context->m_is_verbose >= 0) {
								(void)fprintf(
									stdout,
									"To accept tx (fd=%d) %lld + %ld bytes%s\n",
									s_context->m_accept_socket,
									(long long)s_backward_transfer_size,
									(long)s_send_bytes,
									(s_is_accept_ktls_tx_supported == 0) ? " (with OpenSSL)" : def_hwport_color_green " (with kTLS)" def_hwport_color_normal
								);
							}

							s_backward_transfer_size += (off_t)s_send_bytes;
							
							if((s_context->m_debug_flags & def_SSL_inspection_debug_flag_send_delay) != def_SSL_inspection_debug_flag_none) {
								usleep(1 /* msec */ * 1000);
							}
						}
					}
				}
			}
		
			if((s_is_accept_ssl_established == 0) || (s_is_connect_ssl_established == 0)) {
				break;
			}
		}
	}

l_ssl_clean:;
	/* pipe */
	if(s_splice_pipe[1] != (-1)) {
		do {
			s_check = close(s_splice_pipe[1]);
		}while((s_check == (-1)) && (errno == EINTR));
		if(s_check == (-1)) {
			(void)fprintf(
				stderr,
				"close pipe[1] ! : %s (for write, fd=%d)\n",
				strerror(errno),
				s_splice_pipe[1]
			);
		}

		s_splice_pipe[1] = (-1);
	}
	if(s_splice_pipe[0] != (-1)) {
		do {
			s_check = close(s_splice_pipe[0]);
		}while((s_check == (-1)) && (errno == EINTR));
		if(s_check == (-1)) {
			(void)fprintf(
				stderr,
				"close pipe[0] ! : %s (for read, fd=%d)\n",
				strerror(errno),
				s_splice_pipe[0]
			);
		}

		s_splice_pipe[0] = (-1);
	}

	/* accept side */
	if(s_accept_ssl != ((SSL *)0)) {
		if((s_is_accept_ssl_established > 0) && ((s_is_accept_ktls_rx_supported == 0) && (s_is_accept_ktls_tx_supported == 0))) {
			if(s_context->m_is_verbose >= 0) {
				(void)fprintf(stdout, "SSL shutdown (fd=%d)\n", s_context->m_accept_socket);
			}
			SSL_shutdown(s_accept_ssl);
		}
		else { /* 연결이 끊어졌거나 ktls 설정된 경우 */
			SSL_set_quiet_shutdown(s_accept_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN /* mode */);
			SSL_set_shutdown(s_accept_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN /* mode */);
			s_check = SSL_set_fd(s_accept_ssl, (-1));
			if(s_check <= 0) {
				(void)fprintf(stderr, "unregister fd failed ! (accept, fd=%d)\n", s_context->m_accept_socket);
			}
		}
		SSL_free(s_accept_ssl);
		s_accept_ssl = (SSL *)0;

		if(s_context->m_is_verbose >= 0) {
			(void)fprintf(stdout, "SSL free (fd=%d)\n", s_context->m_accept_socket);
		}
	}

	if(s_context->m_is_verbose >= 0) {
		(void)fprintf(stdout, "Disconnecting (accept, fd=%d)\n", s_context->m_accept_socket);
	}

	if(s_is_accept_ssl_established > 0) { /* 권장사항 : disconnection wait - 상대방이 먼저 연결을 끊는 상태를 유도하여 감지 (TIMEWAIT 상태가 서버측에 누적되는 것을 완화 하는 목적) */
		s_check = shutdown(s_context->m_accept_socket, SHUT_RDWR);
		if(s_check == (-1)) {
			(void)fprintf(
				stderr,
				"shutdown ! (accept) : %s (fd=%d)\n",
				strerror(errno),
				s_context->m_accept_socket
			);
		}
		else { /* waiting */
			s_check = SSL_inspection_is_readable(s_context->m_accept_socket, 4000);
			if(s_check == (-1)) {
				(void)fprintf(
					stderr,
					"disconnection wait ! (accept) : %s (fd=%d)\n",
					strerror(errno),
					s_context->m_accept_socket
				);
			}
		}
	}

	do {
		s_check = close(s_context->m_accept_socket);
	}while((s_check == (-1)) && (errno == EINTR));
	if(s_check == (-1)) {
		(void)fprintf(
			stderr,
			"close accept socket ! : %s (fd=%d)\n",
			strerror(errno),
			s_context->m_accept_socket
		);
	}
	
	/* connect side */
	if(s_connect_ssl != ((SSL *)0)) {
		if((s_is_connect_ssl_established > 0) && ((s_is_connect_ktls_rx_supported == 0) && (s_is_connect_ktls_tx_supported == 0))) {
			if(s_context->m_is_verbose >= 0) {
				(void)fprintf(stdout, "SSL shutdown (connect, fd=%d)\n", s_connect_socket);
			}
			SSL_shutdown(s_connect_ssl);
		}
		else { /* 연결이 끊어졌거나 ktls 설정된 경우 */
			SSL_set_quiet_shutdown(s_connect_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN /* mode */);
			SSL_set_shutdown(s_connect_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN /* mode */);
			s_check = SSL_set_fd(s_connect_ssl, (-1));
			if(s_check <= 0) {
				(void)fprintf(stderr, "unregister fd failed ! (connect, fd=%d)\n", s_connect_socket);
			}
		}
		SSL_free(s_connect_ssl);
		s_connect_ssl = (SSL *)0;

		if(s_context->m_is_verbose >= 0) {
			(void)fprintf(stdout, "SSL free (connect, fd=%d)\n", s_connect_socket);
		}
	}

	if(s_connect_ssl_ctx != ((SSL_CTX *)0)) {
		SSL_CTX_free(s_connect_ssl_ctx);
		s_connect_ssl_ctx = (SSL_CTX *)0;
	}
	
	if(s_connect_socket != (-1)) {
		if(s_context->m_is_verbose >= 0) {
			(void)fprintf(stdout, "Disconnecting (connect, fd=%d)\n", s_context->m_accept_socket);
		}

		do {
			s_check = close(s_connect_socket);
		}while((s_check == (-1)) && (errno == EINTR));
		if(s_check == (-1)) {
			(void)fprintf(
				stderr,
				"close connect sockekt ! : %s (fd=%d)\n",
				strerror(errno),
				s_connect_socket
			);
		}
	}
	
	free((void *)s_context);

	return((void *)0);
}

#if 0L /* ALPN */
static int SSL_inspection_apln_select_callback_handler(SSL *s_ssl, const unsigned char **s_out, unsigned char *s_outlen, const unsigned char *s_in, unsigned int s_inlen, void *s_argument)
{
	int s_is_verbose = *((int *)s_argument);

	(void)s_ssl;

	if(s_out == ((const unsigned char **)0)) {
		return(SSL_TLSEXT_ERR_NOACK);
	}
	if(s_outlen == ((unsigned char *)0)) {
		return(SSL_TLSEXT_ERR_NOACK);
	}

	if((s_in == ((const unsigned char *)0)) || (s_inlen <= 0u)) { /* no REQ */
		*s_out = (const unsigned char *)0;
		*s_outlen = (unsigned char)0u;
		return(SSL_TLSEXT_ERR_NOACK);
	}

	if(s_is_verbose >= 0) {
		(void)SSL_inspection_hexdump(
			"ALPN(accept) REQ ",
			(const void *)s_in,
			(size_t)s_inlen
		);
	}

	*s_out = s_in;
	*s_outlen = (unsigned char)s_inlen;

	return(SSL_TLSEXT_ERR_OK);
}
#endif

int main(int s_argc, char **s_argv)
{
	const char *c_program_name = def_SSL_inspection_default_program_name;
	int s_is_help = 0;
	int s_is_verbose = 0;
	unsigned int s_debug_flags = def_SSL_inspection_debug_flag_none;
	const char *c_bind_address = def_SSL_inspection_listen_address;
	int s_bind_port = def_SSL_inspection_listen_port;
	static const char *c_cipher_list = def_SSL_inspection_cipher_list;
	const char *c_certificate_pathname = def_SSL_inspection_default_certificate_pathname;
	const char *c_privatekey_pathname = def_SSL_inspection_default_privatekey_pathname;
	unsigned int s_use_ktls = def_SSL_inspection_use_ktls_none;
	int s_use_splice = 0;
	const char *c_connect_address = def_SSL_inspection_connect_address;
	int s_connect_port = def_SSL_inspection_connect_port;
	size_t s_buffer_size = (size_t)def_SSL_inspection_buffer_size;

	int s_exit_code;

	/* 관리 변수 */
	int s_check;
	int s_listen_socket;
	struct sockaddr_storage s_sockaddr_storage_bind;
	socklen_t s_sockaddr_storage_len;

	const SSL_METHOD *s_ssl_method = (const SSL_METHOD *)0;
	SSL_CTX *s_ssl_ctx = (SSL_CTX *)0;

	/* setup signal handler */
	(void)SSL_inspection_install_signal_handler();

	/* argument */
	do {
		static const struct option sg_options[] = {
			{"help", no_argument, (int *)0, 'h'},
			{"quiet", no_argument, (int *)0, 'q'},
			{"verbose", no_argument, (int *)0, 'v'},
			{"debug", no_argument, (int *)0, 'd'},
			{"bind", required_argument, (int *)0, 'b'},
			{"port", required_argument, (int *)0, 'p'},
			{"cipher-list", required_argument, (int *)0, 'l'},
			{"cert", required_argument, (int *)0, 'c'},
			{"key", required_argument, (int *)0, 'k'},
			{"ktls-rx", no_argument, (int *)0, 'R'},
			{"ktls-tx", no_argument, (int *)0, 'T'},
			{"ktls", no_argument, (int *)0, 't'},
			{"ktls-forward", no_argument, (int *)0, 'f'},
			{"splice", no_argument, (int *)0, 's'},
			{"connect", no_argument, (int *)0, 'B'},
			{"connect-port", no_argument, (int *)0, 'P'},
			{"buffer-size", required_argument, (int *)0, 0},
			{(char *)0, 0, (int *)0, 0}
		};
		int s_option_index;

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
			s_check = getopt_long(
				s_argc,
				s_argv,
				"hqvd:b:p:l:c:k:tsB:P:",
				sg_options,
				&s_option_index
			);
			if(s_check == (-1)) {
				break;
			}

			switch(s_check) {
				case 0:
					if(strcmp(sg_options[s_option_index].name, "buffer-size") == 0) {
						s_buffer_size = (size_t)atoi(optarg);
					}
					else { /* unknown option (unlikely) */
						(void)fprintf(stderr, "unknown option \"%s\" !\n", sg_options[s_option_index].name);
						s_is_help = 1;
					}
					break;  
				case '?':
				case 'h': s_is_help = 1; break;  
				case 'q': s_is_verbose = (-1); break;  
				case 'v': ++s_is_verbose; break;  
				case 'd': (void)sscanf(optarg, "%i", &s_debug_flags); break;
				case 'b': c_bind_address = optarg; break;
				case 'p': s_bind_port = atoi(optarg); break;
				case 'l': c_cipher_list = optarg; break;
				case 'c': c_certificate_pathname = optarg; break;
				case 'k': c_privatekey_pathname = optarg; break;
				case 'R': s_use_ktls |= def_SSL_inspection_use_ktls_rx; break;  
				case 'T': s_use_ktls |= def_SSL_inspection_use_ktls_tx; break;  
				case 't': s_use_ktls |= def_SSL_inspection_use_ktls_rx | def_SSL_inspection_use_ktls_tx; break;  
				case 'f': s_use_ktls |= def_SSL_inspection_use_ktls_rx | def_SSL_inspection_use_ktls_tx | def_SSL_inspection_use_ktls_forward; break;  
				case 's': s_use_splice = 1; s_use_ktls |= def_SSL_inspection_use_ktls_rx | def_SSL_inspection_use_ktls_tx; break;  
				case 'B': c_connect_address = optarg; break;
				case 'P': s_connect_port = atoi(optarg); break;
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
				"\t-q, --quiet                 : quiet\n"
				"\t-v, --verbose               : verbose (-v, -vv, -vvv, -vvvv, ...)\n"
				"\t-d, --debug=<flags>         : debug options (bits mask)\n"
				"\t                              0x00000001u = first recv\n"
				"\t                              0x00000002u = send delay\n"
				"\t-b, --bind=<address>        : bind address\n"
				"\t-p, --port=<port>           : bind port\n"
				"\t-l, --cipher-list=<string>  : cipher suite list (ex: \"ECDHE-RSA-AES128-GCM-SHA256\")\n"
				"\t-c, --cert=<filename>       : certificate filename\n"
				"\t-k, --key=<filename>        : private key filename\n"
				"\t-R, --ktls-rx               : using TCP_ULP+kTLS for RX(Decrypt)\n"
				"\t-T, --ktls-tx               : using TCP_ULP+kTLS for TX(Encrypt)\n"
				"\t-t, --ktls                  : using TCP_ULP+kTLS for RX/TX(Decrypt/Encrypt)\n"
				"\t-f, --ktls-forward          : using TCP_ULP+kTLS+Forward (Accelator)\n"
				"\t-s, --splice                : using splice (with --ktls option)\n"
				"\t-B, --connect=<address>     : connect address\n"
				"\t-P, --connect-port=<port>   : connect port\n"
				"\t    --buffer-size=<bytes>   : record buffer size\n"
				"\n",
				c_program_name,
				__DATE__,
				__TIME__,
				c_program_name
			);

			return(EXIT_FAILURE);
		}
	}while(0);
	
	(void)fprintf(
		stdout,
		def_hwport_color_green "Initializing SSL-Inspection%s%s%s" def_hwport_color_normal " ... (debug_flags=%08XH, bind=\"[%s]:%d\", connect=\"[%s]:%d\", buffer-size=%lu)\n"
		"\n",
		((s_use_ktls & (def_SSL_inspection_use_ktls_rx | def_SSL_inspection_use_ktls_tx)) == def_SSL_inspection_use_ktls_none) ? " with OpenSSL" : " with kTLS",
		((s_use_ktls & def_SSL_inspection_use_ktls_forward) == def_SSL_inspection_use_ktls_none) ? "" : " (Forward)",
		(s_use_splice == 0) ? "" : "/splice",
		s_debug_flags,
		c_bind_address,
		s_bind_port,
		c_connect_address,
		s_connect_port,
		(unsigned long)s_buffer_size
	);

	/* SSL library 초기화 */
	do {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		unsigned long s_options = 0UL;
#else
		long s_options = 0L;
#endif

		if(SSL_library_init() <= 0) {
			/* Could not initialize the OpenSSL library ! */
			(void)fprintf(stderr, "SSL_library_init failed !\n");
			s_exit_code = EXIT_FAILURE;
			goto l_return;
		}

		OPENSSL_load_builtin_modules();
		ENGINE_load_dynamic();
		ENGINE_load_builtin_engines();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		/* OpenSSL 1.1.0+ takes care of initialization itself */
#else
		/* Lets get nice error messages */
		SSL_load_error_strings();

		ERR_load_crypto_strings();
		ERR_load_BIO_strings();
		ERR_load_ERR_strings();

		/* Init the global ciphers and digests */
		s_check = SSLeay_add_ssl_algorithms();
		if(s_check <= 0) {
			(void)fprintf(stderr, "SSLeay_add_ssl_algorithms failed !\n");
			s_exit_code = EXIT_FAILURE;
			goto l_ssl_cleanup;
		}

		/* Load all digest and cipher algorithms */
		OpenSSL_add_ssl_algorithms();
#endif

		/* TEST vector */
		if(s_is_verbose >= 0) {
			(void)SSL_inspection_sha256_test0(s_is_verbose);
			(void)SSL_inspection_hmac_sha256_test0(s_is_verbose);
			(void)SSL_inspection_hmac_sha256_test1(s_is_verbose);
			(void)SSL_inspection_pseudo_random_function_tlsv1_2_sha256_test0(s_is_verbose);
			(void)SSL_inspection_evp_test0(s_is_verbose);
			(void)SSL_inspection_evp_test1(s_is_verbose);
			(void)SSL_inspection_internal_impl_test0(s_is_verbose);
		}

		/* ---- SSL_CTX 생성 ---- */

		s_options |= SSL_OP_ALL;
		if(s_use_ktls != 0u) {
			s_options |= SSL_OP_NO_COMPRESSION;
			s_options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
		}
		/* s_options |= SSL_OP_TLS_ROLLBACK_BUG; */
		/* s_options |= SSL_OP_SINGLE_DH_USE; */
		/* s_options |= SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION; */
		/* s_options |= SSL_OP_NO_TICKET; */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		s_ssl_method = TLS_server_method();
#elif 1L /* TLS v1.2 */
		s_ssl_method = TLSv1_2_server_method();
		/* s_options |= SSL_OP_NO_SSLv2; */
		/* s_options |= SSL_OP_NO_SSLv3; */
		/* s_options |= SSL_OP_NO_TLSv1; */
		/* s_options |= SSL_OP_NO_TLSv1_1; */
#elif 0L /* TLS v1.1 */
		s_ssl_method = TLSv1_1_server_method();
		/* s_options |= SSL_OP_NO_SSLv2; */
		/* s_options |= SSL_OP_NO_SSLv3; */
		/* s_options |= SSL_OP_NO_TLSv1; */
#elif 0L /* TLS v1.0 */
		s_ssl_method = TLSv1_server_method();
		/* s_options |= SSL_OP_NO_SSLv2; */
		/* s_options |= SSL_OP_NO_SSLv3; */
#else /* SSL v3 */
		s_ssl_method = SSLv23_server_method();
#endif
		if(s_ssl_method == ((const SSL_METHOD *)0)) {
			(void)fprintf(stderr, "not supported method !\n");
			s_exit_code = EXIT_FAILURE;
			goto l_ssl_cleanup;
		}

		s_ssl_ctx = SSL_CTX_new(s_ssl_method);
		if(s_ssl_ctx == ((SSL_CTX *)0)) {
			ERR_print_errors_fp(stderr);
			(void)fprintf(stderr, "SSL_CTX_new failed !\n");
			s_exit_code = EXIT_FAILURE;
			goto l_ssl_cleanup;
		}

		(void)SSL_CTX_set_options(s_ssl_ctx, s_options);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		do {
			long s_min_proto_version;
			long s_max_proto_version;

			s_min_proto_version = TLS1_2_VERSION;
			if(s_use_ktls != 0u) {
				s_max_proto_version = TLS1_2_VERSION;
			}
			else {
				s_max_proto_version = TLS1_3_VERSION;
			}

			s_check = (int)SSL_CTX_set_min_proto_version(s_ssl_ctx, s_min_proto_version);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_set_min_proto_version failed ! (min_proto_version=%ld)\n", (long)s_min_proto_version);
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}

			s_check = (int)SSL_CTX_set_max_proto_version(s_ssl_ctx, s_max_proto_version);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_set_max_proto_version failed ! (max_proto_version=%ld)\n", (long)s_max_proto_version);
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}
		}while(0);
#endif

		if(c_cipher_list != ((const char *)0)) {
			s_check = SSL_CTX_set_cipher_list((SSL_CTX *)s_ssl_ctx, c_cipher_list);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_set_cipher_list failed ! (\"%s\")\n", c_cipher_list);
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}

			if(s_is_verbose >= 0) {
				(void)fprintf(stdout, "Cipher suite list set : \"%s\"\n", c_cipher_list);
			}
		}
		
#if 0L /* ALPN */
		/* set alpn select callback handler */
		SSL_CTX_set_alpn_select_cb(
			s_ssl_ctx,
			SSL_inspection_apln_select_callback_handler,
			(void *)(&s_is_verbose)
		);
#endif

		s_check = SSL_CTX_set_default_verify_paths((SSL_CTX *)s_ssl_ctx);
		if(s_check <= 0) {
			ERR_print_errors_fp(stderr);
			(void)fprintf(stderr, "SSL_CTX_set_default_verify_paths failed !\n");
			s_exit_code = EXIT_FAILURE;
			goto l_ssl_cleanup;
		}

		if(c_certificate_pathname != ((const char *)0)) {
			if(access(c_certificate_pathname, F_OK) != 0) {
				c_certificate_pathname = (const char *)0;
			}
		}
		if(c_privatekey_pathname != ((const char *)0)) {
			if(access(c_privatekey_pathname, F_OK) != 0) {
				c_privatekey_pathname = (const char *)0;
			}
		}
		if((c_certificate_pathname != ((const char *)0)) && (c_privatekey_pathname != ((const char *)0))) { /* set */
			if(s_is_verbose >= 0) {
				(void)fprintf(stdout, "Using RSA certificate file ... (\"%s\")\n", c_certificate_pathname);
			}

			s_check = SSL_CTX_use_certificate_file(s_ssl_ctx, c_certificate_pathname, SSL_FILETYPE_PEM);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_use_certificate_file failed !\n");
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}

			if(s_is_verbose >= 0) {
				(void)fprintf(stdout, "Using RSA private key file ... (\"%s\")\n", c_privatekey_pathname);
			}

			s_check = SSL_CTX_use_PrivateKey_file (s_ssl_ctx, c_privatekey_pathname, SSL_FILETYPE_PEM);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_use_PrivateKey_file failed !\n");
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}

			s_check = SSL_CTX_check_private_key(s_ssl_ctx);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_check_private_key failed !\n");
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}
		}
		else { /* generate or read x509 */
			EVP_PKEY *s_evp_pkey;
			X509 *s_x509;
			RSA *s_rsa;
			
			s_evp_pkey = EVP_PKEY_new();
			if(s_evp_pkey == ((EVP_PKEY *)0)) {
				(void)fprintf(stderr, "EVP_PKEY_new failed !\n");
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}
			
			s_x509 = X509_new();
			if(s_x509 == ((X509 *)0)) {
				(void)fprintf(stderr, "X509_new failed !\n");
				EVP_PKEY_free(s_evp_pkey);
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}

			if(c_privatekey_pathname == ((const char *)0)) { /* generate */
				const int c_rsa_keysize_bits = 2048;

				if(s_is_verbose >= 0) {
					(void)fprintf(stdout, "Generating RSA private key ...\n");
				}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
				do {
					BIGNUM *s_bignum;
					
					s_rsa = RSA_new();
					if(s_rsa == ((RSA *)0)) {
						(void)fprintf(stderr, "RSA_new failed !\n");
						X509_free(s_x509);
						EVP_PKEY_free(s_evp_pkey);
						s_exit_code = EXIT_FAILURE;
						goto l_ssl_cleanup;
					}
					
					s_bignum = BN_new();
					if(s_bignum == ((BIGNUM *)0)) {
						(void)fprintf(stderr, "BN_new failed !\n");
						RSA_free(s_rsa);
						X509_free(s_x509);
						EVP_PKEY_free(s_evp_pkey);
						s_exit_code = EXIT_FAILURE;
						goto l_ssl_cleanup;
					}
					BN_dec2bn(&s_bignum, "3");
					
					s_check = RSA_generate_key_ex(s_rsa, c_rsa_keysize_bits, s_bignum, NULL);
					BN_free(s_bignum);
					if(s_check != 1) {
						(void)fprintf(stderr, "RSA_generate_key_ex failed !\n");
						RSA_free(s_rsa);
						X509_free(s_x509);
						EVP_PKEY_free(s_evp_pkey);
						s_exit_code = EXIT_FAILURE;
						goto l_ssl_cleanup;
					}
				}while(0);
#else
				/* RSA *RSA_generate_key(int bits, unsigned long e,void (*callback)(int,int,void *),void *cb_arg); */
				s_rsa = RSA_generate_key(c_rsa_keysize_bits, RSA_3 /* or RSA_F4 */, (void (*)(int,int,void *))0 /* callback */, (void *)0);
				if(s_rsa == ((RSA *)0)) {
					(void)fprintf(stderr, "RSA_generate_key failed !\n");
					X509_free(s_x509);
					EVP_PKEY_free(s_evp_pkey);
					s_exit_code = EXIT_FAILURE;
					goto l_ssl_cleanup;
				}
#endif
			}
			else { /* read */
				FILE *s_fp;
				
				if(s_is_verbose >= 0) {
					(void)fprintf(stdout, "Loading RSA private key file ...\n");
				}

				s_fp = fopen(c_privatekey_pathname, "rb");
				if(s_fp == ((FILE *)0)) {
					(void)fprintf(stderr, "privatekey file open failed !\n");
					X509_free(s_x509);
					EVP_PKEY_free(s_evp_pkey);
					s_exit_code = EXIT_FAILURE;
					goto l_ssl_cleanup;
				}

				s_rsa = PEM_read_RSAPrivateKey(s_fp, NULL, NULL, NULL);
				if(s_rsa == ((RSA *)0)) {
					(void)fprintf(stderr, "PEM_read_RSAPrivateKey failed !\n");
					s_check = fclose(s_fp);
					X509_free(s_x509);
					EVP_PKEY_free(s_evp_pkey);
					s_exit_code = EXIT_FAILURE;
					goto l_ssl_cleanup;
				}

				s_check = fclose(s_fp);
			}

			s_check = EVP_PKEY_assign_RSA(s_evp_pkey, s_rsa);
			if(s_check == 0) {
				(void)fprintf(stderr, "EVP_PKEY_assign_RSA failed !\n");
				RSA_free(s_rsa);
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}
			s_rsa = (RSA *)0; /* s_rsa to EVP assigned */
	
			X509_set_version(s_x509, 0x02);
			
			do {
				const int c_x509_serial = 0;
				
				ASN1_INTEGER_set(X509_get_serialNumber(s_x509), c_x509_serial);
			}while(0);
			
			do {
				/*
					CN: CommonName
					SN: Surname
					C: CountryName
					L: Locality
					S or ST: StateOrProvinceName
					STREET: Street Address
					O: Organization
					OU: OrganizationalUnit
					T or TITLE: Title
					G or GIVENNAME: Given name
					I or INITIALS: Initials
					DC: Domain Component
					E: emailAddress
				*/
				
				X509_NAME *s_x509_subject_name;
				X509_NAME *s_x509_issuer_name;

				s_x509_subject_name = X509_get_subject_name(s_x509);
				s_x509_issuer_name = X509_get_issuer_name(s_x509);

				/*
				 * This function creates and adds the entry, working out the
				 * correct string type and performing checks on its length.
				 * Normally we'd check the return value for errors...
				 */
				
				/* 발급 대상 */
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "CN", MBSTRING_ASC, (const unsigned char *)"www.hwport.com", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "SN", MBSTRING_ASC, (const unsigned char *)"*.hwport.com,*.hwport.co.kr", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "C", MBSTRING_ASC, (const unsigned char *)"KR", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "L", MBSTRING_ASC, (const unsigned char *)"Bundang-gu, Seongnam-si", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "S", MBSTRING_ASC, (const unsigned char *)"Gyeonggi-do", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "STREET", MBSTRING_ASC, (const unsigned char *)"Pangyo-ro 228beon-gil", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "O", MBSTRING_ASC, (const unsigned char *)"TEST-COMPANY Co., Ltd.", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "OU", MBSTRING_ASC, (const unsigned char *)"R&D Dept. FW 1 Team", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "T", MBSTRING_ASC, (const unsigned char *)"Principal Researcher", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_subject_name, "G", MBSTRING_ASC, (const unsigned char *)"TEST-G", -1, -1, 0);
				
				/* 발급자 */
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "CN", MBSTRING_ASC, (const unsigned char *)"www.minzkn.com", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "SN", MBSTRING_ASC, (const unsigned char *)"*.minzkn.com", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "C", MBSTRING_ASC, (const unsigned char *)"KR", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "L", MBSTRING_ASC, (const unsigned char *)"gunposi", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "S", MBSTRING_ASC, (const unsigned char *)"Gyeonggi-do", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "STREET", MBSTRING_ASC, (const unsigned char *)"geumdanglo", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "O", MBSTRING_ASC, (const unsigned char *)"MINZKN.COM", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "OU", MBSTRING_ASC, (const unsigned char *)"Dev part", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "T", MBSTRING_ASC, (const unsigned char *)"Principal Researcher", -1, -1, 0);
				X509_NAME_add_entry_by_txt(s_x509_issuer_name, "G", MBSTRING_ASC, (const unsigned char *)"MINZKN", -1, -1, 0);
				
				X509_set_subject_name(s_x509, s_x509_subject_name);
				X509_set_issuer_name(s_x509, s_x509_issuer_name);
			}while(0);

#if 0L /* 직접 유효기간 설정 */
			do {
				const long c_duration_days = 3650L;
				const long c_backward_duration_days = 30L;
				
				time_t s_time_sec = time((time_t *)0);
				
				ASN1_TIME *s_asn1_time;

				s_time_sec -= (time_t)(c_backward_duration_days * 86400L);

				s_asn1_time = X509_time_adj(X509_get_notBefore(s_x509), 0, &s_time_sec);
				if(s_asn1_time == ((ASN1_TIME *)0)) {
					(void)fprintf(stderr, "X509_time_adj/X509_get_notBefore failed !\n");
				}

				s_asn1_time = X509_time_adj(X509_get_notAfter(s_x509), (c_backward_duration_days + c_duration_days) * 86400L, &s_time_sec);
				if(s_asn1_time == ((ASN1_TIME *)0)) {
					(void)fprintf(stderr, "X509_time_adj/X509_get_notAfter failed !\n");
				}
			}while(0);
#else /* 상대적 유효기간 설정 */
			do {
				ASN1_TIME *s_asn1_time;

				s_asn1_time = X509_gmtime_adj(X509_get_notBefore(s_x509), (long)(-60*60*24)); /* 24 시간 전부터 */
				if(s_asn1_time == ((ASN1_TIME *)0)) {
					(void)fprintf(stderr, "X509_gmtime_adj/X509_get_notBefore failed !\n");
				}

				s_asn1_time = X509_gmtime_adj(X509_get_notAfter(s_x509), (long)(60*60*24*364)); /* 364일 까지 */
				if(s_asn1_time == ((ASN1_TIME *)0)) {
					(void)fprintf(stderr, "X509_gmtime_adj/X509_get_notAfter failed !\n");
				}
			}while(0);
#endif

			X509_set_pubkey(s_x509, s_evp_pkey);

			/* Add extension using V3 code: we can set the config file as NULL
			 * because we wont reference any other sections. We can also set
			 * the context to NULL because none of these extensions below will need
			 * to access it.
			 */
#if 0L
			do {
				static char g_value[] = {"server"};

				X509_EXTENSION *s_x509_extension;

				s_x509_extension = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, (char *)(&g_value[0]));
				s_check = X509_add_ext(s_x509, s_x509_extension, -1);
				X509_EXTENSION_free(s_x509_extension);
			}while(0);
#endif

#if 0L
			do {
				static char g_value[] = {"example comment extension"};

				X509_EXTENSION *s_x509_extension;

				s_x509_extension = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment, (char *)(&g_value[0]));
				s_check = X509_add_ext(s_x509, s_x509_extension, -1);
				X509_EXTENSION_free(s_x509_extension);
			}while(0);
#endif

#if 0L
			do {
				static char g_value[] = {"www.openssl.org"};

				X509_EXTENSION *s_x509_extension;

				s_x509_extension = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_ssl_server_name, (char *)(&g_value[0]));
				s_check = X509_add_ext(s_x509, s_x509_extension, -1);
				X509_EXTENSION_free(s_x509_extension);
			}while(0);
#endif

			s_check = X509_sign(s_x509, s_evp_pkey, EVP_sha256() /* or EVP_sha1 or EVP_md5 */);
			if(s_check == 0) {
				(void)fprintf(stderr, "X509_sign failed !\n");
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}

			s_check = SSL_CTX_use_certificate(s_ssl_ctx, s_x509);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_use_certificate_file failed !\n");
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}

			s_check = SSL_CTX_use_PrivateKey(s_ssl_ctx, s_evp_pkey);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_use_PrivateKey_file failed !\n");
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}
			
			s_check = SSL_CTX_check_private_key(s_ssl_ctx);
			if(s_check <= 0) {
				ERR_print_errors_fp(stderr);
				(void)fprintf(stderr, "SSL_CTX_check_private_key failed !\n");
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				s_exit_code = EXIT_FAILURE;
				goto l_ssl_cleanup;
			}

			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
		}
	}while(0);
	
	/* setup bind structure */
	s_sockaddr_storage_len = (socklen_t)sizeof(s_sockaddr_storage_bind);
	s_check = SSL_inspection_string_to_sockaddr(
		AF_UNSPEC /* detect address family */,
		c_bind_address,
		s_bind_port,
		(void *)(&s_sockaddr_storage_bind),
		(socklen_t *)(&s_sockaddr_storage_len)
	);
	if(s_check == (-1)) {
		perror("SSL_inspection_string_to_sockaddr");
		s_exit_code = EXIT_FAILURE;
		goto l_ssl_cleanup;
	}

	/* listen socket 생성 */
	if(s_sockaddr_storage_bind.ss_family == AF_INET) { /* IPv4 only */
		s_listen_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(s_listen_socket == (-1)) {
			perror("socket");
			s_exit_code = EXIT_FAILURE;
			goto l_ssl_cleanup;
		}
	
		if(s_is_verbose >= 0) {
			(void)fprintf(stdout, "IPv4 socket opened.\n");
		}
	}
	else if(s_sockaddr_storage_bind.ss_family == AF_INET6) { /* IPv6 (+ IPv4 dual stack) */
		s_listen_socket = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if(s_listen_socket == (-1)) {
			perror("socket");
			s_exit_code = EXIT_FAILURE;
			goto l_ssl_cleanup;
		}
		
		if(s_is_verbose >= 0) {
			(void)fprintf(stdout, "IPv6 socket opened.\n");
		}

#if /* defined(IPPROTO_IPV6) && */ defined(IPV6_V6ONLY)
		/* make dual stack */
		do {
			int s_value = 0;

			s_check = setsockopt(
				s_listen_socket,
				(int)(IPPROTO_IPV6),
				(int)(IPV6_V6ONLY),
				(const void *)(&s_value),
				(socklen_t)sizeof(s_value)
			);
			if(s_check == (-1)) {
				perror("IPv6 + IPv4 dual stack");
			}
			else {
				if(s_is_verbose >= 0) {
					(void)fprintf(stdout, "IPv6 + IPv4 dual stack supported\n");
				}
			}
		}while(0);
#endif  
	}
	else {
		(void)fprintf(stderr, "not supported bind address\n");
		s_exit_code = EXIT_FAILURE;
		goto l_ssl_cleanup;
	}

	/*
		reuse setting
		선택사항 : binding socket 의 연결이 있는 상태에서 강제 종료되는 경우 다시 binding 할 수 없는 상태를 방지하기 위함
	*/
	s_check = SSL_inspection_set_reuse_socket(s_listen_socket, 1 /* enable */);
	if(s_check == (-1)) {
		perror("reuse socket");
	}

	/* binding */
	s_check = bind(
		s_listen_socket,
		(struct sockaddr *)(&s_sockaddr_storage_bind),
		s_sockaddr_storage_len
	);
	if(s_check == (-1)) {
		perror("bind");
		s_exit_code = EXIT_FAILURE;
		goto l_close_socket;
	}

	/* listen */
	s_check = listen(s_listen_socket, SOMAXCONN /* 최대 backlog 설정 */);
	if(s_check == (-1)) {
		perror("listen");
		s_exit_code = EXIT_FAILURE;
		goto l_close_socket;
	}

	if(s_is_verbose >= 0) {
		(void)fprintf(stdout,
			def_hwport_color_green "Ready SSL-Inspection%s%s%s" def_hwport_color_normal " ... (\"[%s]:%d\")\n"
			"\n",
			((s_use_ktls & (def_SSL_inspection_use_ktls_rx | def_SSL_inspection_use_ktls_tx)) == def_SSL_inspection_use_ktls_none) ? " with OpenSSL" : " with kTLS",
			((s_use_ktls & def_SSL_inspection_use_ktls_forward) == def_SSL_inspection_use_ktls_none) ? "" : " (Forward)",
			(s_use_splice == 0) ? "" : "/splice",
			c_bind_address,
			s_bind_port
		);
	}
	s_exit_code = EXIT_SUCCESS;
	
	/* main accept loop */
	while(SSL_inspection_is_break_main_loop() == 0) {
		SSL_inspection_context_t *s_context;

		s_check = SSL_inspection_is_readable(
			s_listen_socket,
			(-1)
		);
		if(s_check == (-1)) {
			perror("incoming connection check");
			continue;
		}
			
		s_context = (SSL_inspection_context_t *)malloc(sizeof(SSL_inspection_context_t) + (s_buffer_size << 1));
		if(s_context == ((SSL_inspection_context_t *)0)) {
			perror("malloc context");
			continue;
		}
		s_context->m_debug_flags = s_debug_flags;
		s_context->m_is_verbose = s_is_verbose;
		s_context->m_cipher_list = c_cipher_list;
		s_context->m_use_ktls = s_use_ktls;
		s_context->m_use_splice = s_use_splice;
		s_context->m_connect_address = c_connect_address;
		s_context->m_connect_port = s_connect_port;

		s_context->m_ssl_ctx = s_ssl_ctx;

		s_context->m_buffer_size = s_buffer_size;
		s_context->m_buffer = (void *)(((uint8_t *)(&s_context[1])) + ((size_t)0u));
		s_context->m_dup_buffer = (void *)(((uint8_t *)(&s_context[1])) + s_buffer_size);

		do {
			s_context->m_socklen = (socklen_t)sizeof(s_context->m_sockaddr_storage);
			s_context->m_accept_socket = accept(
				s_listen_socket,
				(struct sockaddr *)(&s_context->m_sockaddr_storage),
				(socklen_t *)(&s_context->m_socklen)
			);
		}while((SSL_inspection_is_break_main_loop() == 0) && (s_context->m_accept_socket == (-1)) && (errno == EINTR));
		/* check accept-socket */
		if(s_context->m_accept_socket == (-1)) {
			perror("accept");
			free((void *)s_context);
			continue;
		}

#if 1L /* thread model */
		do {
			pthread_t s_pthread;

			/* process handler make thread */
			s_check = pthread_create(
					(pthread_t *)(&s_pthread),
					(const pthread_attr_t *)0,
					SSL_inspection_accept_handler,
					(void *)s_context
					);
			if(s_check == 0) { /* detach thread handler */
				s_check = pthread_detach(s_pthread);
			}
			else { /* direct call handler (pthread failover) */
				(void)fprintf(stderr, "pthread_create failed !\n");

				(void)SSL_inspection_accept_handler(s_context);
			}
		}while(0);
#else /* non-thread model */
		(void)SSL_inspection_accept_handler(s_context);
#endif
	}

	(void)fprintf(stdout,
		"\nEnd of SSL-Inspection%s%s.\n\n",
		((s_use_ktls & (def_SSL_inspection_use_ktls_rx | def_SSL_inspection_use_ktls_tx)) == def_SSL_inspection_use_ktls_none) ? " with OpenSSL" : " with kTLS",
		(s_use_splice == 0) ? "" : "/splice"
	);

l_close_socket:;
	/* close listen socket */
	do {
		s_check = close(s_listen_socket);
	}while((s_check == (-1)) && (errno == EINTR));
	if(s_check == (-1)) {
		perror("close listen socket");
		s_exit_code = EXIT_FAILURE;
	}

l_ssl_cleanup:;
	if(s_ssl_ctx != ((SSL_CTX *)0)) {
		SSL_CTX_free(s_ssl_ctx);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		/* OpenSSL 1.1 deprecates all these cleanup functions and turns them into no-ops in OpenSSL 1.0 compatibility mode */
#else
		/* Free ciphers and digests lists */
		EVP_cleanup();

		/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
		CRYPTO_cleanup_all_ex_data();

		/* Free engine list */
		ENGINE_cleanup();

		/* Free OpenSSL error strings */
		ERR_free_strings();

		/* Free thread local error state, destroying hash upon zero refcount */
		ERR_remove_thread_state(NULL);

		/* Free all memory allocated by all configuration modules */
		CONF_modules_free();

		SSL_COMP_free_compression_methods();
#endif
	}
	if(s_ssl_method != ((const SSL_METHOD *)0)) {
		s_ssl_method = (const SSL_METHOD *)0;
	}

l_return:;

	return(s_exit_code);
}

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
