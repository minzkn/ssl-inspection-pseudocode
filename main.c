/*
	Copyright (C) MINZKN.COM
	All rights reserved.
	Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_main_c__)
# define __def_sslid_source_main_c__ "main.c"

#include "sslid-lib.h"

#include <getopt.h>

#if defined(def_sslid_use_dpdk_lcore)
# include <rte_lcore.h>
#endif

SSL_inspection_session_t *SSL_inspection_new_and_accept_session(SSL_inspection_main_context_t *s_main_context, int s_listen_socket);
SSL_inspection_session_t *SSL_inspection_free_session(SSL_inspection_session_t *s_session);
SSL_inspection_session_t *SSL_inspection_free_session_list(SSL_inspection_session_t *s_session_list);

size_t SSL_inspection_enqueue_session_list(SSL_inspection_main_context_t *s_main_context, SSL_inspection_session_t *s_session_list);
size_t SSL_inspection_dequeue_session_list(SSL_inspection_main_context_t *s_main_context, size_t s_request_session_count, SSL_inspection_session_t **s_session_head_ptr, SSL_inspection_session_t **s_session_tail_ptr, int s_timeout_msec);

#if 0L /* ALPN */
static int __SSL_inspection_apln_select_callback_handler(SSL *s_ssl, const unsigned char **s_out, unsigned char *s_outlen, const unsigned char *s_in, unsigned int s_inlen, void *s_argument);
#endif
SSL_CTX *SSL_inspection_new_SSL_CTX(SSL_inspection_main_context_t *s_main_context, int s_is_server_side);

size_t SSL_inspection_checkout_worker_session(SSL_inspection_worker_context_t *s_worker_context, size_t s_request_session_count, int s_timeout_msec);

int SSL_inspection_add_worker(SSL_inspection_main_context_t *s_main_context, unsigned int s_worker_index, unsigned int s_flags);
SSL_inspection_worker_context_t *SSL_inspection_free_worker(SSL_inspection_worker_context_t *s_worker_context);

int SSL_inspection_do_session_event(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session, struct epoll_event *s_epoll_event, int s_epoll_session_type);
void *SSL_inspection_worker_handler(void *s_context_ptr);

int main(int s_argc, char **s_argv);

SSL_inspection_session_t *SSL_inspection_new_and_accept_session(SSL_inspection_main_context_t *s_main_context, int s_listen_socket)
{
	SSL_inspection_session_t *s_session;

	/* Allocate session with inline buffers (buffer + dup_buffer) */
	s_session = malloc(sizeof(SSL_inspection_session_t) + (s_main_context->m_buffer_size * 2));
	if (SSL_inspection_unlikely(s_session == NULL)) {
		SSL_inspection_perror("malloc session");
		return NULL;
	}

	*s_session = (SSL_inspection_session_t) {
		.m_next = NULL,
		.m_main_context = s_main_context,
		.m_flags = def_SSL_inspection_session_flag_none,
		.m_accept_socket = -1,
		.m_accept_socket_flags = -1,
		.m_sockaddr_accept.ss_family = AF_UNSPEC,
		.m_socklen_accept = (socklen_t)sizeof(s_session->m_sockaddr_accept),
		.m_accept_address_string = {0},
		.m_connect_ssl_ctx = NULL,
		.m_connect_socket = -1,
		.m_connect_socket_flags = -1,
		.m_accept_ssl = NULL,
		.m_connect_ssl = NULL,
		.m_forward_transfer_size = 0,
		.m_backward_transfer_size = 0,
		.m_buffer_size = s_main_context->m_buffer_size,
		/* Inline buffers follow the session structure */
		.m_buffer = (uint8_t *)(&s_session[1]),
		.m_dup_buffer = (uint8_t *)(&s_session[1]) + s_main_context->m_buffer_size,
	};

	/* do accept */
	s_session->m_accept_socket = accept(
		s_listen_socket,
		(struct sockaddr *)&s_session->m_sockaddr_accept,
		&s_session->m_socklen_accept
	);
	if (SSL_inspection_unlikely(s_session->m_accept_socket == -1)) {
		SSL_inspection_perror("accept");
		return SSL_inspection_free_session(s_session);
	}
	s_session->m_flags |= def_SSL_inspection_session_flag_accepted;

	return s_session;
}

SSL_inspection_session_t *SSL_inspection_free_session(SSL_inspection_session_t *s_session)
{
	SSL_inspection_main_context_t *s_main_context;
	int s_check;

	if (SSL_inspection_unlikely(s_session == NULL)) {
		errno = EINVAL;
		SSL_inspection_perror("null session");
		return NULL;
	}
	s_main_context = s_session->m_main_context;

	/* accept side */
	if(s_session->m_accept_ssl != ((SSL *)(NULL))) {
		if((s_session->m_flags & def_SSL_inspection_session_flag_ssl_accepted) != def_SSL_inspection_session_flag_none) {
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stdout, "SSL shutdown (fd=%d)\n", s_session->m_accept_socket);
			}
			s_check = SSL_inspection_shutdown(s_session->m_accept_ssl);
		}
		else { /* 연결이 끊어진 경우 */
			SSL_set_quiet_shutdown(s_session->m_accept_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN /* mode */);
			SSL_set_shutdown(s_session->m_accept_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN /* mode */);
			s_check = SSL_set_fd(s_session->m_accept_ssl, (-1));
			if(SSL_inspection_unlikely(s_check <= 0)) {
				(void)SSL_inspection_fprintf(stderr, "unregister fd failed ! (accept, fd=%d)\n", s_session->m_accept_socket);
			}
		}
		SSL_free(s_session->m_accept_ssl);
		s_session->m_accept_ssl = (SSL *)(NULL);
		s_session->m_flags &= (~def_SSL_inspection_session_flag_ssl_accepted);

		if(s_main_context->m_is_verbose >= 2) {
			(void)SSL_inspection_fprintf(stdout, "SSL free (fd=%d)\n", s_session->m_accept_socket);
		}
	}

	if(s_session->m_accept_socket != (-1)) {
		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout, "Disconnecting (accept, fd=%d)\n", s_session->m_accept_socket);
		}

#if 1L /* graceful shutdown */
		if((s_session->m_flags & def_SSL_inspection_session_flag_accepted) != def_SSL_inspection_session_flag_none) {
			/* 권장사항 : disconnection wait - 상대방이 먼저 연결을 끊는 상태를 유도하여 감지 (TIMEWAIT 상태가 서버측에 누적되는 것을 완화 하는 목적) */
			s_check = shutdown(s_session->m_accept_socket, SHUT_RDWR);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				(void)SSL_inspection_fprintf(
					stderr,
					"shutdown ! (accept) : %s (fd=%d)\n",
					strerror(errno),
					s_session->m_accept_socket
				);
			}
			else { /* waiting */
				s_check = SSL_inspection_is_readable(s_session->m_accept_socket, 4000);
				if(SSL_inspection_unlikely(s_check == (-1))) {
					(void)SSL_inspection_fprintf(
						stderr,
						"disconnection wait ! (accept) : %s (fd=%d)\n",
						strerror(errno),
						s_session->m_accept_socket
					);
				}
			}
		}
#endif

		s_check = SSL_inspection_closesocket(s_session->m_accept_socket);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			(void)SSL_inspection_fprintf(
				stderr,
				"close accept socket ! : %s (fd=%d)\n",
				strerror(errno),
				s_session->m_accept_socket
			);
		}
		s_session->m_accept_socket = (-1);
		s_session->m_flags &= (~def_SSL_inspection_session_flag_accepted);
	}

	/* connect side */
	if(s_session->m_connect_ssl != ((SSL *)(NULL))) {
		if((s_session->m_flags & def_SSL_inspection_session_flag_ssl_connected) != def_SSL_inspection_session_flag_none) {
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stdout, "SSL shutdown (connect, fd=%d)\n", s_session->m_connect_socket);
			}
			s_check = SSL_inspection_shutdown(s_session->m_connect_ssl);
		}
		else { /* 연결이 끊어진 경우 */
			SSL_set_quiet_shutdown(s_session->m_connect_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN /* mode */);
			SSL_set_shutdown(s_session->m_connect_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN /* mode */);
			s_check = SSL_set_fd(s_session->m_connect_ssl, (-1));
			if(SSL_inspection_unlikely(s_check <= 0)) {
				(void)SSL_inspection_fprintf(stderr, "unregister fd failed ! (connect, fd=%d)\n", s_session->m_connect_socket);
			}
		}
		SSL_free(s_session->m_connect_ssl);
		s_session->m_connect_ssl = (SSL *)(NULL);
		s_session->m_flags &= (~def_SSL_inspection_session_flag_ssl_connected);

		if(s_main_context->m_is_verbose >= 2) {
			(void)SSL_inspection_fprintf(stdout, "SSL free (connect, fd=%d)\n", s_session->m_connect_socket);
		}
	}

	if(s_session->m_connect_socket != (-1)) {
		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout, "Disconnecting (connect, fd=%d)\n", s_session->m_connect_socket);
		}

#if 1L /* graceful shutdown */
		if((s_session->m_flags & def_SSL_inspection_session_flag_connected) != def_SSL_inspection_session_flag_none) {
			/* 권장사항 : disconnection wait - 상대방이 먼저 연결을 끊는 상태를 유도하여 감지 (TIMEWAIT 상태가 서버측에 누적되는 것을 완화 하는 목적) */
			s_check = shutdown(s_session->m_connect_socket, SHUT_RDWR);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				(void)SSL_inspection_fprintf(
					stderr,
					"shutdown ! (connect) : %s (fd=%d)\n",
					strerror(errno),
					s_session->m_connect_socket
				);
			}
			else { /* waiting */
				s_check = SSL_inspection_is_readable(s_session->m_connect_socket, 4000);
				if(SSL_inspection_unlikely(s_check == (-1))) {
					(void)SSL_inspection_fprintf(
						stderr,
						"disconnection wait ! (connect) : %s (fd=%d)\n",
						strerror(errno),
						s_session->m_connect_socket
					);
				}
			}
		}
#endif

		s_check = SSL_inspection_closesocket(s_session->m_connect_socket);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			(void)SSL_inspection_fprintf(
				stderr,
				"close connect sockekt ! : %s (fd=%d)\n",
				strerror(errno),
				s_session->m_connect_socket
			);
		}
		s_session->m_connect_socket = (-1);
		s_session->m_flags &= (~def_SSL_inspection_session_flag_connected);
	}

	if(s_session->m_connect_ssl_ctx != ((SSL_CTX *)(NULL))) {
		SSL_CTX_free(s_session->m_connect_ssl_ctx);
		s_session->m_connect_ssl_ctx = (SSL_CTX *)(NULL);
	}

	free((void *)s_session);

	return((SSL_inspection_session_t *)(NULL));
}

SSL_inspection_session_t *SSL_inspection_free_session_list(SSL_inspection_session_t *s_session_list)
{
	SSL_inspection_session_t *s_session;

	while(s_session_list != ((SSL_inspection_session_t *)(NULL))) {
		s_session = s_session_list;
		s_session_list = s_session_list->m_next;
		s_session->m_next = (SSL_inspection_session_t *)(NULL);

		(void)SSL_inspection_free_session(s_session);
	}

	return(s_session_list);
}

size_t SSL_inspection_enqueue_session_list(SSL_inspection_main_context_t *s_main_context, SSL_inspection_session_t *s_session_list)
{
	size_t s_enqueued_session_count = 0;
	SSL_inspection_session_t *s_session;
	int s_mutex_result;

#if 1L /* BYPASS MUTEX with atomic check */
	/* Use atomic load to check enqueued state without mutex */
#if SSL_INSPECTION_HAS_C11_ATOMICS
	if (s_session_list == NULL && atomic_load(&s_main_context->m_is_enqueued) == 0) {
		return 0;
	}
#else
	/* Fallback: volatile read with memory barrier */
	SSL_inspection_barrier();
	if (s_session_list == NULL && s_main_context->m_is_enqueued == 0) {
		return 0;
	}
#endif
#endif

	s_mutex_result = pthread_mutex_lock(&s_main_context->m_session_queue_lock);
	if (SSL_inspection_unlikely(s_mutex_result != 0)) {
		(void)SSL_inspection_fprintf(stderr, "CRITICAL: enqueue pthread_mutex_lock failed (error=%d)\n", s_mutex_result);
		/* Return early on mutex failure to prevent data race */
		return 0;
	}

	while (s_session_list != NULL) {
		s_session = s_session_list;
		s_session_list = s_session_list->m_next;
		s_session->m_next = NULL;

		if (s_main_context->m_session_queue_tail == NULL) {
			s_main_context->m_session_queue_head = s_main_context->m_session_queue_tail = s_session;
		}
		else {
			s_main_context->m_session_queue_tail->m_next = s_session;
			s_main_context->m_session_queue_tail = s_session;
		}
		++s_enqueued_session_count;
	}
	s_main_context->m_enqueued_session_count += s_enqueued_session_count;
	s_main_context->m_session_queue_count += s_enqueued_session_count;
	s_enqueued_session_count = s_main_context->m_session_queue_count;

	if (s_enqueued_session_count > 0) { /* wakeup */
#if 1L /* BYPASS MUTEX with atomic store */
#if SSL_INSPECTION_HAS_C11_ATOMICS
		atomic_store(&s_main_context->m_is_enqueued, 1);
#else
		s_main_context->m_is_enqueued = 1;
		SSL_inspection_barrier();
#endif
#endif
		(void)pthread_cond_signal(&s_main_context->m_session_queue_cond);
	}

	s_mutex_result = pthread_mutex_unlock(&s_main_context->m_session_queue_lock);
	if (SSL_inspection_unlikely(s_mutex_result != 0)) {
		(void)SSL_inspection_fprintf(stderr, "CRITICAL: enqueue pthread_mutex_unlock failed (error=%d)\n", s_mutex_result);
	}

	return s_enqueued_session_count;
}

size_t SSL_inspection_dequeue_session_list(SSL_inspection_main_context_t *s_main_context, size_t s_request_session_count, SSL_inspection_session_t **s_session_head_ptr, SSL_inspection_session_t **s_session_tail_ptr, int s_timeout_msec)
{
	size_t s_session_dequeued_count;
	int s_mutex_result;

	SSL_inspection_session_t *s_session_head;
	SSL_inspection_session_t *s_session_tail;
	SSL_inspection_session_t *s_session;

#if 1L /* BYPASS MUTEX with atomic check */
	/* Use atomic load to check enqueued state without mutex */
#if SSL_INSPECTION_HAS_C11_ATOMICS
	if (s_timeout_msec == 0 && atomic_load(&s_main_context->m_is_enqueued) == 0) {
#else
	SSL_inspection_barrier();
	if (s_timeout_msec == 0 && s_main_context->m_is_enqueued == 0) {
#endif
		if (s_session_head_ptr != NULL) {
			*s_session_head_ptr = NULL;
		}
		if (s_session_tail_ptr != NULL) {
			*s_session_tail_ptr = NULL;
		}
		return 0;
	}
#endif

	s_mutex_result = pthread_mutex_lock(&s_main_context->m_session_queue_lock);
	if (SSL_inspection_unlikely(s_mutex_result != 0)) {
		(void)SSL_inspection_fprintf(stderr, "CRITICAL: dequeue pthread_mutex_lock failed (error=%d)\n", s_mutex_result);
		/* Return early on mutex failure */
		if (s_session_head_ptr != NULL) {
			*s_session_head_ptr = NULL;
		}
		if (s_session_tail_ptr != NULL) {
			*s_session_tail_ptr = NULL;
		}
		return 0;
	}
	if((s_timeout_msec != 0) && (s_main_context->m_session_queue_head == ((SSL_inspection_session_t *)(NULL)))) {
		if(s_timeout_msec > 0) { /* timed wait for enqueue */
			struct timespec s_timespec;

			if(clock_gettime(CLOCK_REALTIME, (struct timespec *)(&s_timespec)) == 0) {
				s_timespec.tv_sec += s_timeout_msec / 1000;
				s_timespec.tv_nsec += (s_timeout_msec % 1000) * 1000000;

				(void)pthread_cond_timedwait((pthread_cond_t *)(&s_main_context->m_session_queue_cond), (pthread_mutex_t *)(&s_main_context->m_session_queue_lock), (const struct timespec *)(&s_timespec));
			}
		}
		else { /* wait for enqueue */
			(void)pthread_cond_wait((pthread_cond_t *)(&s_main_context->m_session_queue_cond), (pthread_mutex_t *)(&s_main_context->m_session_queue_lock));
		}
	}

	if((s_request_session_count == ((size_t)0u)) || (s_request_session_count <= s_main_context->m_session_queue_count)) { /* all */
		s_session_head = s_main_context->m_session_queue_head;
		s_session_tail = s_main_context->m_session_queue_tail;
		s_session_dequeued_count = s_main_context->m_session_queue_count;

		s_main_context->m_session_queue_head = s_main_context->m_session_queue_tail = (SSL_inspection_session_t *)(NULL);
		s_main_context->m_session_queue_count = (size_t)0u;
	}
	else {
		s_session_dequeued_count = (size_t)0u;
		s_session_head = (SSL_inspection_session_t *)(NULL);
		s_session_tail = (SSL_inspection_session_t *)(NULL);
		while((s_session_dequeued_count < s_request_session_count) && (s_main_context->m_session_queue_head != ((SSL_inspection_session_t *)(NULL)))) {
			/* dequeue from main */
			s_session = s_main_context->m_session_queue_head;
			s_main_context->m_session_queue_head = s_main_context->m_session_queue_head->m_next;
			if(s_main_context->m_session_queue_head == ((SSL_inspection_session_t *)(NULL))) {
				s_main_context->m_session_queue_tail = (SSL_inspection_session_t *)(NULL);
			}
			s_session->m_next = (SSL_inspection_session_t *)(NULL);

			/* enqueue local */
			if(s_session_tail == ((SSL_inspection_session_t *)(NULL))) {
				s_session_head = s_session_tail = s_session;
			}
			else {
				s_session_tail->m_next = s_session;
				s_session_tail = s_session;
			}

			++s_session_dequeued_count;
		}
		s_main_context->m_session_queue_count -= s_session_dequeued_count;
	}
	s_main_context->m_dequeued_session_count += s_session_dequeued_count;

	if (s_main_context->m_session_queue_count > 0) { /* more queued, wakeup */
		(void)pthread_cond_signal(&s_main_context->m_session_queue_cond);
	}
#if 1L /* BYPASS MUTEX with atomic store */
	else {
#if SSL_INSPECTION_HAS_C11_ATOMICS
		atomic_store(&s_main_context->m_is_enqueued, 0);
#else
		s_main_context->m_is_enqueued = 0;
		SSL_inspection_barrier();
#endif
	}
#endif

	s_mutex_result = pthread_mutex_unlock(&s_main_context->m_session_queue_lock);
	if (SSL_inspection_unlikely(s_mutex_result != 0)) {
		(void)SSL_inspection_fprintf(stderr, "CRITICAL: dequeue pthread_mutex_unlock failed (error=%d)\n", s_mutex_result);
	}

	if(s_session_head_ptr != ((SSL_inspection_session_t **)(NULL))) {
		*s_session_head_ptr = s_session_head;
	}
	else if(s_session_tail_ptr == ((SSL_inspection_session_t **)(NULL))) {
		/* dequeued cleanup session */
		s_session_head = s_session_tail = SSL_inspection_free_session_list(s_session_head);
		s_session_dequeued_count = (size_t)0u;
	}
	if(s_session_tail_ptr != ((SSL_inspection_session_t **)(NULL))) {
		if((s_session_head_ptr == ((SSL_inspection_session_t **)(NULL))) && (s_session_head != s_session_tail)) {
			(void)SSL_inspection_fprintf(stderr, "BUG: memory leak s_session_head[%p] != s_session_tail[%p]\n", s_session_head, s_session_tail);
			/* dequeued cleanup session */
			s_session_head = s_session_tail = SSL_inspection_free_session_list(s_session_head);
			if(s_session_head_ptr != ((SSL_inspection_session_t **)(NULL))) {
				*s_session_head_ptr = s_session_head;
			}
			s_session_dequeued_count = (size_t)0u;
		}
		*s_session_tail_ptr = s_session_tail;
	}

	return(s_session_dequeued_count);
}

#if 0L /* ALPN */
static int __SSL_inspection_apln_select_callback_handler(SSL *s_ssl, const unsigned char **s_out, unsigned char *s_outlen, const unsigned char *s_in, unsigned int s_inlen, void *s_argument)
{
	SSL_inspection_main_context_t *s_main_context = (SSL_inspection_main_context_t *)s_argument;

	(void)s_ssl;

	if(s_out == ((const unsigned char **)(NULL))) {
		return(SSL_TLSEXT_ERR_NOACK);
	}
	if(s_outlen == ((unsigned char *)(NULL))) {
		return(SSL_TLSEXT_ERR_NOACK);
	}

	if((s_in == ((const unsigned char *)(NULL))) || (s_inlen <= 0u)) { /* no REQ */
		*s_out = (const unsigned char *)(NULL);
		*s_outlen = (unsigned char)0u;
		return(SSL_TLSEXT_ERR_NOACK);
	}

	if(SSL_inspection_unlikely((s_main_context == ((SSL_inspection_main_context_t *)(NULL))) || (s_main_context->m_magic_code_begin != 0x12345678u) || (s_main_context->m_magic_code_end != 0x87654321u))) {
		(void)SSL_inspection_fprintf(stderr, "BUG: detected main context broken ! (ALPN callback handler, main_context=%p)\n", s_main_context);
	}
	else if(s_main_context->m_is_verbose >= 2) {
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

SSL_CTX *SSL_inspection_new_SSL_CTX(SSL_inspection_main_context_t *s_main_context, int s_is_server_side)
{
	SSL_CTX *s_ssl_ctx;
	int s_check;

	s_ssl_ctx = SSL_CTX_new((s_is_server_side <= 0) ? s_main_context->m_client_ssl_method : s_main_context->m_server_ssl_method);
	if(SSL_inspection_unlikely(s_ssl_ctx == ((SSL_CTX *)(NULL)))) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "SSL_CTX_new failed ! (%s)\n", (s_is_server_side <= 0) ? "client side" : "server side");
		return((SSL_CTX *)(NULL));
	}

	if(s_main_context->m_use_async > 0) {
		if(SSL_inspection_unlikely(SSL_CTX_set_mode(s_ssl_ctx, SSL_MODE_ASYNC) <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_set_mode SSL_MODE_ASYNC failed ! (%s)\n", (s_is_server_side <= 0) ? "client side" : "server side");
		}
	}
#if 1L
	if(SSL_inspection_unlikely(SSL_CTX_set_mode(s_ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE) <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "SSL_CTX_set_mode SSL_MODE_ENABLE_PARTIAL_WRITE failed ! (%s)\n", (s_is_server_side <= 0) ? "client side" : "server side");
	}	
#endif
	(void)SSL_CTX_set_options(s_ssl_ctx, s_main_context->m_ssl_options);
#if 1L
	if(SSL_inspection_unlikely(SSL_CTX_set_ecdh_auto(s_ssl_ctx, 1) <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "SSL_CTX_set_ecdh_auto failed ! (%s)\n", (s_is_server_side <= 0) ? "client side" : "server side");
	}	
#endif
#if 1L
	if(SSL_inspection_unlikely(SSL_CTX_set_dh_auto(s_ssl_ctx, 1) <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "SSL_CTX_set_dh_auto failed ! (%s)\n", (s_is_server_side <= 0) ? "client side" : "server side");
	}	
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	do {
		long s_min_proto_version;
		long s_max_proto_version;

#if 0L /* TLS v1.2 ~ v1.3 */
		s_min_proto_version = TLS1_2_VERSION;
		s_max_proto_version = TLS1_3_VERSION;
#else /* TLS v1.2 only */
		s_min_proto_version = TLS1_2_VERSION;
		s_max_proto_version = TLS1_2_VERSION;
#endif

		s_check = (int)SSL_CTX_set_min_proto_version(s_ssl_ctx, s_min_proto_version);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_set_min_proto_version failed ! (%s, min_proto_version=%ld)\n", (s_is_server_side <= 0) ? "client side" : "server side", (long)s_min_proto_version);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		s_check = (int)SSL_CTX_set_max_proto_version(s_ssl_ctx, s_max_proto_version);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_set_max_proto_version failed ! (%s, max_proto_version=%ld)\n", (s_is_server_side <= 0) ? "client side" : "server side", (long)s_max_proto_version);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}
	}while(0);
#endif

	if(s_main_context->m_cipher_list != ((const char *)(NULL))) {
		s_check = SSL_CTX_set_cipher_list(s_ssl_ctx, s_main_context->m_cipher_list);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_set_cipher_list failed ! (%s, \"%s\")\n", (s_is_server_side <= 0) ? "client side" : "server side", s_main_context->m_cipher_list);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout, "Cipher suite list set : \"%s\" (%s)\n", s_main_context->m_cipher_list, (s_is_server_side <= 0) ? "client side" : "server side");
		}
	}

	if (s_is_server_side <= 0) {
		/* client side */

#if 0L /* ALPN */
		/* set alpn select callback handler */
		SSL_CTX_set_alpn_select_cb(
			s_ssl_ctx,
			__SSL_inspection_apln_select_callback_handler,
			(void *)(&s_main_context)
		);
#endif

#if 1L /* Server certificate verification - SECURITY: Enable in production */
		/*
		 * SSL_VERIFY_PEER: Verify server certificate
		 * Note: For SSL inspection proxy, you may want to disable this
		 * as the proxy acts as a client to arbitrary servers.
		 * Set verify depth to reasonable value for certificate chain.
		 */
		s_check = SSL_CTX_set_default_verify_paths(s_ssl_ctx);
		if (SSL_inspection_unlikely(s_check <= 0)) {
			if (s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stderr, "WARNING: SSL_CTX_set_default_verify_paths failed (client side)\n");
			}
		}
		/* For proxy use case: verify but don't fail on certificate errors
		 * In production, consider SSL_VERIFY_PEER for stricter checking */
		SSL_CTX_set_verify(s_ssl_ctx, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_verify_depth(s_ssl_ctx, 4);
#endif
		return s_ssl_ctx;
	}

	s_check = SSL_CTX_set_default_verify_paths(s_ssl_ctx);
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "SSL_CTX_set_default_verify_paths failed !\n");
		SSL_CTX_free(s_ssl_ctx);
		return((SSL_CTX *)(NULL));
	}

	if(s_main_context->m_certificate_pathname != ((const char *)(NULL))) {
		if(access(s_main_context->m_certificate_pathname, F_OK) != 0) {
			s_main_context->m_certificate_pathname = (const char *)(NULL);
		}
	}
	if(s_main_context->m_privatekey_pathname != ((const char *)(NULL))) {
		if(access(s_main_context->m_privatekey_pathname, F_OK) != 0) {
			s_main_context->m_privatekey_pathname = (const char *)(NULL);
		}
	}
	if((s_main_context->m_certificate_pathname != ((const char *)(NULL))) && (s_main_context->m_privatekey_pathname != ((const char *)(NULL)))) { /* set */
		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout, "Using RSA certificate file ... (\"%s\")\n", s_main_context->m_certificate_pathname);
		}

		s_check = SSL_CTX_use_certificate_file(s_ssl_ctx, s_main_context->m_certificate_pathname, SSL_FILETYPE_PEM);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_use_certificate_file failed !\n");
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout, "Using RSA private key file ... (\"%s\")\n", s_main_context->m_privatekey_pathname);
		}

		s_check = SSL_CTX_use_PrivateKey_file (s_ssl_ctx, s_main_context->m_privatekey_pathname, SSL_FILETYPE_PEM);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_use_PrivateKey_file failed !\n");
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		s_check = SSL_CTX_check_private_key(s_ssl_ctx);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_check_private_key failed !\n");
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}
	}
	else { /* generate or read x509 */
		const int c_rsa_keysize_bits = 2048;
		EVP_PKEY *s_evp_pkey;
		X509 *s_x509;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#else
		RSA *s_rsa;
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
		s_evp_pkey = EVP_RSA_gen(c_rsa_keysize_bits);
#else
		s_evp_pkey = EVP_PKEY_new();
#endif
		if(SSL_inspection_unlikely(s_evp_pkey == ((EVP_PKEY *)(NULL)))) {
			(void)SSL_inspection_fprintf(stderr, "EVP_PKEY_new failed !\n");
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}
		
		s_x509 = X509_new();
		if(SSL_inspection_unlikely(s_x509 == ((X509 *)(NULL)))) {
			(void)SSL_inspection_fprintf(stderr, "X509_new failed !\n");
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#else
		if(s_main_context->m_privatekey_pathname == ((const char *)(NULL))) { /* generate */
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stdout, "Generating RSA private key ...\n");
			}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
			do {
				BIGNUM *s_bignum;
				
				s_rsa = RSA_new();
				if(SSL_inspection_unlikely(s_rsa == ((RSA *)(NULL)))) {
					(void)SSL_inspection_fprintf(stderr, "RSA_new failed !\n");
					X509_free(s_x509);
					EVP_PKEY_free(s_evp_pkey);
					SSL_CTX_free(s_ssl_ctx);
					return((SSL_CTX *)(NULL));
				}
				
				s_bignum = BN_new();
				if(SSL_inspection_unlikely(s_bignum == ((BIGNUM *)(NULL)))) {
					(void)SSL_inspection_fprintf(stderr, "BN_new failed !\n");
					RSA_free(s_rsa);
					X509_free(s_x509);
					EVP_PKEY_free(s_evp_pkey);
					SSL_CTX_free(s_ssl_ctx);
					return((SSL_CTX *)(NULL));
				}
				BN_dec2bn(&s_bignum, "3");
				
				s_check = RSA_generate_key_ex(s_rsa, c_rsa_keysize_bits, s_bignum, NULL);
				BN_free(s_bignum);
				if(SSL_inspection_unlikely(s_check != 1)) {
					(void)SSL_inspection_fprintf(stderr, "RSA_generate_key_ex failed !\n");
					RSA_free(s_rsa);
					X509_free(s_x509);
					EVP_PKEY_free(s_evp_pkey);
					SSL_CTX_free(s_ssl_ctx);
					return((SSL_CTX *)(NULL));
				}
			}while(0);
#else
			/* RSA *RSA_generate_key(int bits, unsigned long e,void (*callback)(int,int,void *),void *cb_arg); */
			s_rsa = RSA_generate_key(c_rsa_keysize_bits, RSA_3 /* or RSA_F4 */, (void (*)(int,int,void *))0 /* callback */, (void *)(NULL));
			if(SSL_inspection_unlikely(s_rsa == ((RSA *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "RSA_generate_key failed !\n");
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
#endif
		}
		else { /* read */
			FILE *s_fp;
			
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stdout, "Loading RSA private key file ...\n");
			}

			s_fp = fopen(s_main_context->m_privatekey_pathname, "rb");
			if(SSL_inspection_unlikely(s_fp == ((FILE *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "privatekey file open failed !\n");
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}

			s_rsa = PEM_read_RSAPrivateKey(s_fp, NULL, NULL, NULL);
			if(SSL_inspection_unlikely(s_rsa == ((RSA *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "PEM_read_RSAPrivateKey failed !\n");
				s_check = fclose(s_fp);
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}

			s_check = fclose(s_fp);
		}

		s_check = EVP_PKEY_assign_RSA(s_evp_pkey, s_rsa);
		if(SSL_inspection_unlikely(s_check == 0)) {
			(void)SSL_inspection_fprintf(stderr, "EVP_PKEY_assign_RSA failed !\n");
			RSA_free(s_rsa);
			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}
		s_rsa = (RSA *)(NULL); /* s_rsa to EVP assigned */
#endif

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
			
			time_t s_time_sec = time((time_t *)(NULL));
			
			ASN1_TIME *s_asn1_time;

			s_time_sec -= (time_t)(c_backward_duration_days * 86400L);

			s_asn1_time = X509_time_adj(X509_get_notBefore(s_x509), 0, &s_time_sec);
			if(SSL_inspection_unlikely(s_asn1_time == ((ASN1_TIME *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "X509_time_adj/X509_get_notBefore failed !\n");
			}

			s_asn1_time = X509_time_adj(X509_get_notAfter(s_x509), (c_backward_duration_days + c_duration_days) * 86400L, &s_time_sec);
			if(SSL_inspection_unlikely(s_asn1_time == ((ASN1_TIME *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "X509_time_adj/X509_get_notAfter failed !\n");
			}
		}while(0);
#else /* 상대적 유효기간 설정 */
		do {
			ASN1_TIME *s_asn1_time;

			s_asn1_time = X509_gmtime_adj(X509_get_notBefore(s_x509), (long)(-60*60*24)); /* 24 시간 전부터 */
			if(SSL_inspection_unlikely(s_asn1_time == ((ASN1_TIME *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "X509_gmtime_adj/X509_get_notBefore failed !\n");
			}

			s_asn1_time = X509_gmtime_adj(X509_get_notAfter(s_x509), (long)(60*60*24*364)); /* 364일 까지 */
			if(SSL_inspection_unlikely(s_asn1_time == ((ASN1_TIME *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "X509_gmtime_adj/X509_get_notAfter failed !\n");
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
		if(SSL_inspection_unlikely(s_check == 0)) {
			(void)SSL_inspection_fprintf(stderr, "X509_sign failed !\n");
			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		s_check = SSL_CTX_use_certificate(s_ssl_ctx, s_x509);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_use_certificate_file failed !\n");
			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		s_check = SSL_CTX_use_PrivateKey(s_ssl_ctx, s_evp_pkey);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_use_PrivateKey_file failed !\n");
			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}
		
		s_check = SSL_CTX_check_private_key(s_ssl_ctx);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_check_private_key failed !\n");
			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		X509_free(s_x509);
		EVP_PKEY_free(s_evp_pkey);
	}

	return(s_ssl_ctx);		
}

size_t SSL_inspection_checkout_worker_session(SSL_inspection_worker_context_t *s_worker_context, size_t s_request_session_count, int s_timeout_msec)
{
	SSL_inspection_main_context_t *s_main_context = (SSL_inspection_main_context_t *)s_worker_context->m_main_context;

	int s_check;

	size_t s_session_dequeued_count;

	SSL_inspection_session_t *s_session_head;
	SSL_inspection_session_t *s_session_tail;
	SSL_inspection_session_t *s_session_prev;
	SSL_inspection_session_t *s_session_next;
	SSL_inspection_session_t *s_session;

	int s_prepare_remove_condition;

	s_session_dequeued_count = SSL_inspection_dequeue_session_list(
		s_main_context,
		(size_t)s_request_session_count,
		(SSL_inspection_session_t **)(&s_session_head),
		(SSL_inspection_session_t **)(&s_session_tail),
		s_timeout_msec
	);
	if(s_session_dequeued_count == ((size_t)0u)) {
		return((size_t)0u);
	}

	/* 새로 dequeue된 session 에 대한 prepare */
	for(s_session_prev = (SSL_inspection_session_t *)(NULL), s_session = s_session_head;s_session != ((SSL_inspection_session_t *)(NULL));s_session = s_session_next) {
		s_session_next = s_session->m_next;

		s_prepare_remove_condition = 0;
		
		errno = 0;
		s_session->m_accept_socket_flags = fcntl(s_session->m_accept_socket, F_GETFL, 0);
		if(s_session->m_accept_socket_flags == (-1)) {
			SSL_inspection_perror("F_GETFL (accept)");
		}
		else if((s_session->m_accept_socket_flags & O_NONBLOCK) != O_NONBLOCK) {
			(void)fcntl(s_session->m_accept_socket, F_SETFL, s_session->m_accept_socket_flags | (O_NONBLOCK));
			s_session->m_accept_socket_flags = fcntl(s_session->m_accept_socket, F_GETFL, 0);
		}

		if(s_main_context->m_is_verbose >= 1) {
#if defined(def_sslid_use_dpdk_lcore)
			(void)SSL_inspection_fprintf(
				stdout,
				"Accepted (fd=%d, socket_flags=0x%x%s, accept-from=\"%s\", worker_index=%u, lcore_id=%u)\n",
				s_session->m_accept_socket,
				s_session->m_accept_socket_flags,
				((s_session->m_accept_socket_flags != (-1)) && ((s_session->m_accept_socket_flags & O_NONBLOCK) == O_NONBLOCK)) ? "[NONBLOCK]" : "[BLOCK]",
				(char *)(&s_session->m_accept_address_string[0]),
				(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) ? 0u : s_worker_context->m_worker_index,
				(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) ? 0u : s_worker_context->m_lcore_id
			);
#else
			(void)SSL_inspection_fprintf(
				stdout,
				"Accepted (fd=%d, accept-from=\"%s\", worker_index=%u)\n",
				s_session->m_accept_socket,
				(char *)(&s_session->m_accept_address_string[0]),
				(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) ? 0u : s_worker_context->m_worker_index
			);
#endif
		}

		if(SSL_inspection_unlikely(SSL_inspection_set_linger_socket(s_session->m_accept_socket, 1 /* on */, 0 /* sec */) == (-1))) {
			SSL_inspection_perror("SSL_inspection_set_linger_socket (accept)");
		}
		if(SSL_inspection_unlikely(SSL_inspection_set_keepalive_socket(s_session->m_accept_socket, 1, (-1) /* keepidle_sec */, (-1) /* keepintvl_sec */) == (-1))) {
			SSL_inspection_perror("SSL_inspection_set_keepalive_socket (accept)");
		}
#if defined(def_SSL_inspection_socket_buffer_tx) && (def_SSL_inspection_socket_buffer_tx > 0)
		if(SSL_inspection_unlikely(SSL_inspection_set_tx_socket_buffer_size(s_session->m_accept_socket, (size_t)def_SSL_inspection_socket_buffer_tx) == (-1))) {
			SSL_inspection_perror("SSL_inspection_set_tx_socket_buffer_size (accept)");
		}
#endif
#if defined(def_SSL_inspection_socket_buffer_rx) && (def_SSL_inspection_socket_buffer_rx > 0)
		if(SSL_inspection_unlikely(SSL_inspection_set_rx_socket_buffer_size(s_session->m_accept_socket, (size_t)def_SSL_inspection_socket_buffer_rx) == (-1))) {
			SSL_inspection_perror("SSL_inspection_set_rx_socket_buffer_size (accept)");
		}
#endif

		/* PREPARE SESSION (ACCEPT) */
		if(s_session->m_sockaddr_accept.ss_family == AF_INET) {
			struct sockaddr_in *s_sockaddr_in = (struct sockaddr_in *)(&s_session->m_sockaddr_accept);

			(void)inet_ntop(
				s_session->m_sockaddr_accept.ss_family,
				(const void *)(&s_sockaddr_in->sin_addr),
				(char *)(&s_session->m_accept_address_string[0]),
				(socklen_t)sizeof(s_session->m_accept_address_string)
			);
		}
		else if(s_session->m_sockaddr_accept.ss_family == AF_INET6) {
			struct sockaddr_in6 *s_sockaddr_in6 = (struct sockaddr_in6 *)(&s_session->m_sockaddr_accept);

			(void)inet_ntop(
				s_session->m_sockaddr_accept.ss_family,
				(const void *)(&s_sockaddr_in6->sin6_addr),
				(char *)(&s_session->m_accept_address_string[0]),
				(socklen_t)sizeof(s_session->m_accept_address_string)
			);
		}
		else {
			(void)SSL_inspection_fprintf(stderr, "BUG: invalid accept address family ! (family=%u)\n", (unsigned int)s_session->m_sockaddr_accept.ss_family);
			s_prepare_remove_condition = 1;
		}

		/* ADD EPOLL EVENT (ACCEPT) */
		if(s_prepare_remove_condition == 0) {
			s_worker_context->m_epoll_event = (struct epoll_event) {
				.events = EPOLLIN,
				.data.fd = s_session->m_accept_socket,
			};
			s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_ADD, s_session->m_accept_socket, (struct epoll_event *)(&s_worker_context->m_epoll_event));
			if(SSL_inspection_unlikely(s_check != 0)) {
				if(errno == EEXIST) {
					s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_MOD, s_session->m_accept_socket, (struct epoll_event *)(&s_worker_context->m_epoll_event));
					if(SSL_inspection_unlikely(s_check != 0)) {
						SSL_inspection_perror("epoll_ctl (EPOLL_CTL_MOD, accept socket)");
						s_prepare_remove_condition = 1;
					}
				}
				else {
					SSL_inspection_perror("epoll_ctl (EPOLL_CTL_ADD, accept socket)");
					s_prepare_remove_condition = 1;
				}
			}
		}
	
		/* PREPARE SSL CTX (CONNECT) */	
		if(s_prepare_remove_condition == 0) {
			if(s_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) {
				s_session->m_connect_ssl_ctx = SSL_inspection_new_SSL_CTX(s_main_context, 0 /* client side */);
				if(SSL_inspection_unlikely(s_session->m_connect_ssl_ctx == ((SSL_CTX *)(NULL)))) {
					ERR_print_errors_fp(stderr);
					(void)SSL_inspection_fprintf(stderr, "SSL_CTX_new failed ! (connect)\n");
					s_prepare_remove_condition = 1;
				}
			}
		}

		/* PREPARE SESSION (CONNECT) */
		if(s_prepare_remove_condition == 0) {
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(
					stdout,
					"%s connecting. (for fd=%d, \"[%s]:%d\")\n",
					(s_session->m_connect_ssl_ctx == ((SSL_CTX *)(NULL))) ? "TCP" : "SSL",
					s_session->m_accept_socket,
					s_main_context->m_connect_address,
					s_main_context->m_connect_port
				);
			}
			s_session->m_connect_socket = socket(s_main_context->m_sockaddr_connect.ss_family, SOCK_STREAM, IPPROTO_TCP);
			if(SSL_inspection_unlikely(s_session->m_connect_socket == (-1))) {
				SSL_inspection_perror("connect socket");
				s_prepare_remove_condition = 1;
				goto l_prepare_connection_break;
			}

			if(SSL_inspection_unlikely(SSL_inspection_set_linger_socket(s_session->m_connect_socket, 1 /* on */, 0 /* sec */) == (-1))) {
				SSL_inspection_perror("SSL_inspection_set_linger_socket (connect)");
			}
			if(SSL_inspection_unlikely(SSL_inspection_set_keepalive_socket(s_session->m_connect_socket, 1, (-1) /* keepidle_sec */, (-1) /* keepintvl_sec */) == (-1))) {
				SSL_inspection_perror("SSL_inspection_set_keepalive_socket (accept)");
			}
			if(SSL_inspection_unlikely(SSL_inspection_set_freebind_socket(s_session->m_connect_socket, 1) == (-1))) {
				SSL_inspection_perror("SSL_inspection_set_freebind_socket (connect)");
			}
#if defined(def_SSL_inspection_socket_buffer_tx) && (def_SSL_inspection_socket_buffer_tx > 0)
			if(SSL_inspection_unlikely(SSL_inspection_set_tx_socket_buffer_size(s_session->m_connect_socket, (size_t)def_SSL_inspection_socket_buffer_tx) == (-1))) {
				SSL_inspection_perror("SSL_inspection_set_tx_socket_buffer_size (connect)");
			}
#endif
#if defined(def_SSL_inspection_socket_buffer_rx) && (def_SSL_inspection_socket_buffer_rx > 0)
			if(SSL_inspection_unlikely(SSL_inspection_set_rx_socket_buffer_size(s_session->m_connect_socket, (size_t)def_SSL_inspection_socket_buffer_rx) == (-1))) {
				SSL_inspection_perror("SSL_inspection_set_rx_socket_buffer_size (connect)");
			}
#endif

			s_check = bind(s_session->m_connect_socket, (struct sockaddr *)(&s_main_context->m_sockaddr_connect_bind), s_main_context->m_socklen_connect_bind);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				SSL_inspection_perror("connect bind");
				s_prepare_remove_condition = 1;
				goto l_prepare_connection_break;
			}

			errno = 0;
			s_session->m_connect_socket_flags = fcntl(s_session->m_connect_socket, F_GETFL, 0);
			if(s_session->m_connect_socket_flags == (-1)) {
				SSL_inspection_perror("F_GETFL (connect)");
			}
			else if((s_session->m_connect_socket_flags & O_NONBLOCK) != O_NONBLOCK) {
				(void)fcntl(s_session->m_connect_socket, F_SETFL, s_session->m_connect_socket_flags | (O_NONBLOCK));
				s_session->m_connect_socket_flags = fcntl(s_session->m_connect_socket, F_GETFL, 0);
			}

			s_check = SSL_inspection_connect(s_session->m_connect_socket, (const void *)(&s_main_context->m_sockaddr_connect), s_main_context->m_socklen_connect, 60000 /* msec */);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				SSL_inspection_perror("connect");
				s_prepare_remove_condition = 1;
				goto l_prepare_connection_break;
			}
			s_session->m_flags |= def_SSL_inspection_session_flag_connected;

			/* ADD EPOLL EVENT (CONNECT) */
			s_worker_context->m_epoll_event = (struct epoll_event) {
				.events = EPOLLIN,
				.data.fd = s_session->m_connect_socket,
			};
			s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_ADD, s_session->m_connect_socket, (struct epoll_event *)(&s_worker_context->m_epoll_event));
			if(SSL_inspection_unlikely(s_check != 0)) {
				if(errno == EEXIST) {
					s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_MOD, s_session->m_connect_socket, (struct epoll_event *)(&s_worker_context->m_epoll_event));
					if(SSL_inspection_unlikely(s_check != 0)) {
						SSL_inspection_perror("epoll_ctl (EPOLL_CTL_MOD, connect socket)");
						s_prepare_remove_condition = 1;
						goto l_prepare_connection_break;
					}
				}
				else {
					SSL_inspection_perror("epoll_ctl (EPOLL_CTL_ADD, connect socket)");
					s_prepare_remove_condition = 1;
					goto l_prepare_connection_break;
				}
			}

			if(s_session->m_connect_ssl_ctx != ((SSL_CTX *)(NULL))) { /* SSL handshake (connect) */
				if(s_main_context->m_use_serialize_lock != 0) {
					if(SSL_inspection_unlikely(pthread_mutex_lock((pthread_mutex_t *)(&s_main_context->m_serialize_lock)) != 0)) {
						(void)SSL_inspection_fprintf(stderr, "serialize: pthread_mutex_lock (connect)\n");
					}
				}
				s_session->m_connect_ssl = SSL_inspection_ssl_do_handshake(s_session->m_connect_ssl_ctx, s_session->m_connect_socket, (-1), 0 /* connect */);
				if(s_main_context->m_use_serialize_lock != 0) {
					if(SSL_inspection_unlikely(pthread_mutex_unlock((pthread_mutex_t *)(&s_main_context->m_serialize_lock)) != 0)) {
						(void)SSL_inspection_fprintf(stderr, "serialize: pthread_mutex_unlock (connect)\n");
					}
				}
				if(s_session->m_connect_ssl == ((SSL *)(NULL))) {
					SSL_inspection_perror("connect handshake");
					s_prepare_remove_condition = 1;
					goto l_prepare_connection_break;
				}
				s_session->m_flags |= def_SSL_inspection_session_flag_ssl_connected;
			
#if 0L /* ALPN */
				do {
					const unsigned char *s_alpn;
					unsigned int s_alpn_size;
				
					s_alpn = (const unsigned char *)(NULL);
					s_alpn_size = (unsigned int)0u;
					SSL_get0_next_proto_negotiated(
						s_session->m_connect_ssl,
						(const unsigned char **)(&s_alpn),
						(unsigned int *)(&s_alpn_size)
					);
					if(s_alpn == ((const unsigned char *)(NULL))) {
						SSL_get0_alpn_selected(
							s_session->m_connect_ssl,
							(const unsigned char **)(&s_alpn),
							(unsigned int *)(&s_alpn_size)
						);
					}
					if((s_alpn != ((const unsigned char *)(NULL))) && (s_alpn_size > ((unsigned int)0u))) {
						if(s_main_context->m_is_verbose >= 2) {
							SSL_inspection_hexdump(
								"ALPN(connect) SEL ",
								(const void *)s_alpn,
								(size_t)s_alpn_size
							);
						}
					}
				}while(0);
#endif

				if(s_main_context->m_is_verbose >= 2) {
					const SSL_CIPHER *s_connect_cipher;

					s_connect_cipher = SSL_get_current_cipher(s_session->m_connect_ssl);
					if(s_connect_cipher != ((const SSL_CIPHER *)(NULL))) {
						(void)SSL_inspection_fprintf(
							stdout,
							"current connect-side cipher info (fd=%d, \"%s\")\n",
							s_session->m_connect_socket,
							SSL_state_string_long(s_session->m_connect_ssl)
						);
						(void)SSL_inspection_fprintf(
							stdout,
							"  - vesion : \"%s\"\n",
							SSL_CIPHER_get_version(s_connect_cipher)
						);
						(void)SSL_inspection_fprintf(
							stdout,
							"  - bits : %d\n",
							SSL_CIPHER_get_bits(s_connect_cipher, (int *)(NULL))
						);
						(void)SSL_inspection_fprintf(
							stdout,
							"  - name : \"%s\"\n",
							SSL_CIPHER_get_name(s_connect_cipher)
						);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
						(void)SSL_inspection_fprintf(
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
				
					if(s_main_context->m_is_verbose >= 4) {
						(void)SSL_SESSION_print_fp(stdout, SSL_get_session(s_session->m_connect_ssl));
					}
				}

			}
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(
					stdout,
					"%s connected. (fd=%d, socket_flags=0x%x%s, for fd=%d, \"[%s]:%d\")\n",
					(s_session->m_connect_ssl == ((SSL *)(NULL))) ? "TCP" : "SSL",
					s_session->m_connect_socket,
					s_session->m_connect_socket_flags,
					((s_session->m_connect_socket_flags != (-1)) && ((s_session->m_connect_socket_flags & O_NONBLOCK) == O_NONBLOCK)) ? "[NONBLOCK]" : "[BLOCK]",
					s_session->m_accept_socket,
					s_main_context->m_connect_address,
					s_main_context->m_connect_port
				);
			}
			
			if(s_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) { /* SSL handshake (accept) */
				if(s_main_context->m_use_serialize_lock != 0) {
					if(SSL_inspection_unlikely(pthread_mutex_lock((pthread_mutex_t *)(&s_main_context->m_serialize_lock)) != 0)) {
						(void)SSL_inspection_fprintf(stderr, "serialize: pthread_mutex_lock (accept)\n");
					}
				}
				s_session->m_accept_ssl = SSL_inspection_ssl_do_handshake(s_main_context->m_ssl_ctx, s_session->m_accept_socket, (-1) /* msec */, 1 /* accept */);
				if(s_main_context->m_use_serialize_lock != 0) {
					if(SSL_inspection_unlikely(pthread_mutex_unlock((pthread_mutex_t *)(&s_main_context->m_serialize_lock)) != 0)) {
						(void)SSL_inspection_fprintf(stderr, "serialize: pthread_mutex_unlock (accept)\n");
					}
				}
				if(SSL_inspection_unlikely(s_session->m_accept_ssl == ((SSL *)(NULL)))) {
					(void)SSL_inspection_fprintf(stderr, "SSL_inspection_ssl_do_handshake failed ! (accept)\n");
					s_prepare_remove_condition = 1;
					goto l_prepare_connection_break;
				}
				if(s_main_context->m_is_verbose >= 1) {
					(void)SSL_inspection_fprintf(stdout, "SSL Accepted (fd=%d, socket_flags=0x%x%s)\n",
						s_session->m_accept_socket,
						s_session->m_accept_socket_flags,
						((s_session->m_accept_socket_flags != (-1)) && ((s_session->m_accept_socket_flags & O_NONBLOCK) == O_NONBLOCK)) ? "[NONBLOCK]" : "[BLOCK]"
					);
				}
				s_session->m_flags |= def_SSL_inspection_session_flag_ssl_accepted;

				/* ALPN */
				do {
					const unsigned char *s_alpn;
					unsigned int s_alpn_size;
				
					s_alpn = (const unsigned char *)(NULL);
					s_alpn_size = (unsigned int)0u;
					SSL_get0_next_proto_negotiated(
						s_session->m_accept_ssl,
						(const unsigned char **)(&s_alpn),
						(unsigned int *)(&s_alpn_size)
					);
					if(s_alpn == ((const unsigned char *)(NULL))) {
						SSL_get0_alpn_selected(
							s_session->m_accept_ssl,
							(const unsigned char **)(&s_alpn),
							(unsigned int *)(&s_alpn_size)
						);
					}
					if((s_alpn != ((const unsigned char *)(NULL))) && (s_alpn_size > ((unsigned int)0u))) {
						if(s_main_context->m_is_verbose >= 2) {
							SSL_inspection_hexdump(
								"ALPN(accept) SEL ",
								(const void *)s_alpn,
								(size_t)s_alpn_size
							);
						}
					}
				}while(0);

				if(s_main_context->m_is_verbose >= 2) {
					const SSL_CIPHER *s_accept_cipher;

					s_accept_cipher = SSL_get_current_cipher(s_session->m_accept_ssl);
					if(s_accept_cipher != ((const SSL_CIPHER *)(NULL))) {
						(void)SSL_inspection_fprintf(
							stdout,
							"current accept-side cipher info (fd=%d, \"%s\")\n",
							s_session->m_accept_socket,
							SSL_state_string_long(s_session->m_accept_ssl)
						);
						(void)SSL_inspection_fprintf(
							stdout,
							"  - version  : \"%s\"\n",
							SSL_CIPHER_get_version(s_accept_cipher)
						);
						(void)SSL_inspection_fprintf(
							stdout,
							"  - bits : %d\n",
							SSL_CIPHER_get_bits(s_accept_cipher, (int *)(NULL))
						);
						(void)SSL_inspection_fprintf(
							stdout,
							"  - name : \"%s\"\n",
							SSL_CIPHER_get_name(s_accept_cipher)
						);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
						(void)SSL_inspection_fprintf(
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

					if(s_main_context->m_is_verbose >= 4) {
						(void)SSL_SESSION_print_fp(stdout, SSL_get_session(s_session->m_accept_ssl));
					}
				}
			}

l_prepare_connection_break:;
		}

		if(SSL_inspection_unlikely(s_prepare_remove_condition != 0)) {
			/* REMOVE DEQUEUE SESSION */
			if(s_session_prev == ((SSL_inspection_session_t *)(NULL))) {
				s_session_head = s_session_next;
			}
			else {
				s_session_prev->m_next = s_session_next;
			}
			s_session->m_next = (SSL_inspection_session_t *)(NULL);
			if(s_session_next == ((SSL_inspection_session_t *)(NULL))) {
				s_session_tail = s_session_prev;
			}
			--s_session_dequeued_count;

			if(s_session->m_accept_socket != (-1)) {
				s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_DEL, s_session->m_accept_socket, (struct epoll_event *)(NULL));
				if(SSL_inspection_unlikely(s_check == (-1))) {
					if(errno != ENOENT) {
						SSL_inspection_perror("remove epoll (accept)");
					}
				}
			}
			if(s_session->m_connect_socket != (-1)) {
				s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_DEL, s_session->m_connect_socket, (struct epoll_event *)(NULL));
				if(SSL_inspection_unlikely(s_check == (-1))) {
					if(errno != ENOENT) {
						SSL_inspection_perror("remove epoll (connect)");
					}
				}
			}

			(void)SSL_inspection_free_session(s_session);
			continue;
		}

		s_session_prev = s_session;
	}

	if(s_session_head != ((SSL_inspection_session_t *)(NULL))) {
#if 0L /* DEBUG */
		do {
			size_t s_debug_session_dequeued_count;

			if(SSL_inspection_unlikely(s_session_tail == ((SSL_inspection_session_t *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "BUG[%u]: s_session_head = %p, s_session_tail = %p\n", s_worker_context->m_worker_index, s_session_head, s_session_tail);
			}
			for(s_debug_session_dequeued_count = (size_t)0u, s_session = s_session_head;s_session != ((SSL_inspection_session_t *)(NULL));s_session = s_session->m_next) {
				++s_debug_session_dequeued_count;
				if(s_session == s_session_tail) {
					if(SSL_inspection_unlikely(s_session_tail->m_next != ((SSL_inspection_session_t *)(NULL)))) {
						(void)SSL_inspection_fprintf(stderr, "BUG[%u]: s_session_tail->m_next = %p\n", s_worker_context->m_worker_index, s_session_tail->m_next);
					}
					break;
				}
			}
			if(SSL_inspection_unlikely(s_session_dequeued_count != s_debug_session_dequeued_count)) {
				(void)SSL_inspection_fprintf(stderr, "BUG[%u]: dequeued - s_session_dequeued_count = %lu, s_debug_session_dequeued_count = %lu\n", s_worker_context->m_worker_index, (unsigned long)s_session_dequeued_count, (unsigned long)s_debug_session_dequeued_count);
			}

			if(SSL_inspection_unlikely(s_worker_context->m_session_queue_head != ((SSL_inspection_session_t *)(NULL)))) {
				if(SSL_inspection_unlikely(s_worker_context->m_session_queue_tail == ((SSL_inspection_session_t *)(NULL)))) {
					(void)SSL_inspection_fprintf(stderr, "BUG[%u]: BEFORE - s_worker_context->m_session_queue_head = %p, s_worker_context->m_session_queue_tail = %p\n", s_worker_context->m_worker_index, s_worker_context->m_session_queue_head, s_worker_context->m_session_queue_tail);
				}
				for(s_debug_session_dequeued_count = (size_t)0u, s_session = s_worker_context->m_session_queue_head;s_session != ((SSL_inspection_session_t *)(NULL));s_session = s_session->m_next) {
					++s_debug_session_dequeued_count;
					if(SSL_inspection_unlikely(s_session == s_worker_context->m_session_queue_tail)) {
						if(s_worker_context->m_session_queue_tail->m_next != ((SSL_inspection_session_t *)(NULL))) {
							(void)SSL_inspection_fprintf(stderr, "BUG[%u]: BEFORE - s_worker_context->m_session_queue_tail->m_next = %p\n", s_worker_context->m_worker_index, s_worker_context->m_session_queue_tail->m_next);
						}
						break;
					}
				}
				if(SSL_inspection_unlikely(s_worker_context->m_session_queue_count != s_debug_session_dequeued_count)) {
					(void)SSL_inspection_fprintf(stderr, "BUG[%u]: BEFORE - worker queue - s_worker_context->m_session_queue_count = %lu, s_debug_session_dequeued_count = %lu\n", s_worker_context->m_worker_index, (unsigned long)s_worker_context->m_session_queue_count, (unsigned long)s_debug_session_dequeued_count);
				}
			}
			else if(SSL_inspection_unlikely(s_worker_context->m_session_queue_count > ((size_t)0u))) {
				(void)SSL_inspection_fprintf(stderr, "BUG[%u]: BEFORE - s_worker_context->m_session_queue_count = %lu\n", s_worker_context->m_worker_index, (unsigned long)s_worker_context->m_session_queue_count);
			}
		}while(0);
#endif
		/* MERGE DEQUEUE WITH WORKER SESSION */
		if(s_worker_context->m_session_queue_head == ((SSL_inspection_session_t *)(NULL))) {
			s_worker_context->m_session_queue_head = s_session_head;
		}
		else {
			s_worker_context->m_session_queue_tail->m_next = s_session_head;
		}
		s_worker_context->m_session_queue_tail = s_session_tail;
		s_worker_context->m_session_queue_count += s_session_dequeued_count;

#if 0L /* DEBUG */
		do {
			size_t s_debug_session_dequeued_count;

			if(SSL_inspection_unlikely(s_worker_context->m_session_queue_tail == ((SSL_inspection_session_t *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "BUG[%u]: AFTER - s_worker_context->m_session_queue_head = %p, s_worker_context->m_session_queue_tail = %p\n", s_worker_context->m_worker_index, s_worker_context->m_session_queue_head, s_worker_context->m_session_queue_tail);
			}
			for(s_debug_session_dequeued_count = (size_t)0u, s_session = s_worker_context->m_session_queue_head;s_session != ((SSL_inspection_session_t *)(NULL));s_session = s_session->m_next) {
				++s_debug_session_dequeued_count;
				if(SSL_inspection_unlikely(s_session == s_worker_context->m_session_queue_tail)) {
					if(s_worker_context->m_session_queue_tail->m_next != ((SSL_inspection_session_t *)(NULL))) {
						(void)SSL_inspection_fprintf(stderr, "BUG[%u]: AFTER - s_worker_context->m_session_queue_tail->m_next = %p\n", s_worker_context->m_worker_index, s_worker_context->m_session_queue_tail->m_next);
					}
					break;
				}
			}
			if(SSL_inspection_unlikely(s_worker_context->m_session_queue_count != s_debug_session_dequeued_count)) {
				(void)SSL_inspection_fprintf(stderr, "BUG[%u]: AFTER - worker queue - s_worker_context->m_session_queue_count = %lu, s_debug_session_dequeued_count = %lu\n", s_worker_context->m_worker_index, (unsigned long)s_worker_context->m_session_queue_count, (unsigned long)s_debug_session_dequeued_count);
			}
		}while(0);
#endif
	}
	else if(SSL_inspection_unlikely(s_session_dequeued_count > ((size_t)0u))) {
		(void)SSL_inspection_fprintf(stderr, "BUG[%u]: s_session_dequeued_count = %lu\n", s_worker_context->m_worker_index, (unsigned long)s_session_dequeued_count);
	}

	return(s_session_dequeued_count);
}

int SSL_inspection_add_worker(SSL_inspection_main_context_t *s_main_context, unsigned int s_worker_index, unsigned int s_flags)
{
	const int s_max_worker_epoll_events = def_SSL_inspection_max_worker_epoll_events;
	SSL_inspection_worker_context_t *s_worker_context;

	for(s_worker_context = s_main_context->m_worker_context_head;s_worker_context != ((SSL_inspection_worker_context_t *)(NULL));s_worker_context = s_worker_context->m_next) {
		if(SSL_inspection_unlikely(s_worker_context->m_worker_index == s_worker_index)) {
			errno = EEXIST;
			SSL_inspection_perror("BUG: duplicated worker");
			return(-1);
		}
	}

	s_worker_context = (SSL_inspection_worker_context_t *)malloc(sizeof(SSL_inspection_worker_context_t) + (sizeof(struct epoll_event) * ((size_t)s_max_worker_epoll_events)));
	if(SSL_inspection_unlikely(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL)))) {
		SSL_inspection_perror("alloc worker");
		return(-1);
	}

	*s_worker_context = (SSL_inspection_worker_context_t) {
		.m_next = s_main_context->m_worker_context_head,
		.m_flags = s_flags,
		.m_worker_index = s_worker_index,
#if defined(def_sslid_use_dpdk_lcore)
		.m_lcore_id = LCORE_ID_ANY,
#endif
		.m_running = (-1),
		.m_main_context = s_main_context,
		.m_session_queue_head = (SSL_inspection_session_t *)(NULL),
		.m_session_queue_tail = (SSL_inspection_session_t *)(NULL),
		.m_session_queue_count = (size_t)0u,
		.m_max_epoll_events = s_max_worker_epoll_events,
		.m_epoll_fd = epoll_create(s_max_worker_epoll_events),
		.m_epoll_event = {},
		.m_epoll_events = (struct epoll_event *)memset((void *)(&s_worker_context[1]), 0, (sizeof(struct epoll_event) * ((size_t)s_max_worker_epoll_events))),
		.m_listen_socket = (-1),
		.m_sockaddr_listen_bind = {},
		.m_socklen_listen_bind = (socklen_t)sizeof(s_worker_context->m_sockaddr_listen_bind),
		.m_forward_transfer_size = 0ull,
		.m_backward_transfer_size = 0ull,
	};
	if(SSL_inspection_unlikely(s_worker_context->m_epoll_fd == (-1))) {
		SSL_inspection_perror("worker epoll_create");
		free((void *)s_worker_context);
		return(-1);
	}

	if(s_worker_index == 0u /* main process */) {
#if defined(def_sslid_use_dpdk_lcore)
		s_worker_context->m_lcore_id = rte_lcore_id();
#endif

		/* add worker list to main_context */
		s_main_context->m_worker_context_head = s_worker_context;
		s_main_context->m_worker_context_main = s_worker_context;
		return(0);
	}

	if(pthread_attr_init((pthread_attr_t *)(&s_worker_context->m_pthread_attr)) == 0) {
#if 0L /* NOT USE */
		/* detached thread */
		(void)pthread_attr_setdetachstate((pthread_attr_t *)(&s_worker_context->m_pthread_attr), PTHREAD_CREATE_DETACHED);
#endif

		(void)pthread_attr_setscope((pthread_attr_t *)(&s_worker_context->m_pthread_attr), PTHREAD_SCOPE_SYSTEM /* OR PTHREAD_SCOPE_PROCESS */);
#if 1L /* single core assign */
		do {
			cpu_set_t s_cpuset;
			int s_select_cpu;

			if(s_main_context->m_cpu_count >= 2) {
				s_select_cpu = (int)(((s_worker_index - 1u) % (((unsigned int)s_main_context->m_cpu_count) - 1u)) + 1u);
			}
			else {
				s_select_cpu = 0;
			}
			CPU_ZERO(&s_cpuset);
			CPU_SET(s_select_cpu, &s_cpuset);
			(void)pthread_attr_setaffinity_np((pthread_attr_t *)(&s_worker_context->m_pthread_attr), sizeof(s_cpuset), &s_cpuset);
		}while(0);
#endif
	}

	/* process handler make thread */
	if(SSL_inspection_unlikely(pthread_create(
			(pthread_t *)(&s_worker_context->m_pthread),
			(const pthread_attr_t *)(&s_worker_context->m_pthread_attr),
			SSL_inspection_worker_handler,
			(void *)s_worker_context) != 0)) {
		(void)SSL_inspection_fprintf(stderr, "pthread_create failed !\n");

		(void)SSL_inspection_closefd(s_worker_context->m_epoll_fd);
		(void)free((void *)s_worker_context);
		return(-1);
	}

	++s_main_context->m_max_thread_pool;

	/* add worker list to main_context */
	s_main_context->m_worker_context_head = s_worker_context;

	/* waiting worker thread */
	while((SSL_inspection_is_break_main_loop() == 0) && ((*((volatile int *)(&s_worker_context->m_running))) == (-1))) {
		SSL_inspection_msleep(10);
	}

	return(0);
}

SSL_inspection_worker_context_t *SSL_inspection_free_worker(SSL_inspection_worker_context_t *s_worker_context)
{
	if(SSL_inspection_unlikely(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL)))) {
		errno = EINVAL;
		return((SSL_inspection_worker_context_t *)(NULL));
	}

	/* worker thread 의 종료를 기다립니다. */
	if((s_worker_context->m_worker_index > 0u) && ((*((volatile int *)(&s_worker_context->m_running))) != (-1))) {
		(void)pthread_join(s_worker_context->m_pthread, (void **)(NULL));
	}

	/* cleanup session */
	s_worker_context->m_session_queue_head = s_worker_context->m_session_queue_tail = SSL_inspection_free_session_list(
		s_worker_context->m_session_queue_head
	);
	s_worker_context->m_session_queue_count = (size_t)0u;

	if(s_worker_context->m_epoll_fd != (-1)) {
		(void)SSL_inspection_closefd(s_worker_context->m_epoll_fd);
		s_worker_context->m_epoll_fd = (-1);
	}
       	
	/* close listen socket */
	if(s_worker_context->m_listen_socket != (-1)) {
		if(SSL_inspection_unlikely(SSL_inspection_closesocket(s_worker_context->m_listen_socket) == (-1))) {
			SSL_inspection_perror("close listen socket");
		}
		s_worker_context->m_listen_socket = (-1);
	}

	*((volatile int *)(&s_worker_context->m_running)) = (-1);

	free((void *)s_worker_context);

	return((SSL_inspection_worker_context_t *)(NULL));
}

int SSL_inspection_do_session_event(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session, struct epoll_event *s_epoll_event, int s_epoll_session_type)
{
	SSL_inspection_main_context_t *s_main_context = s_worker_context->m_main_context;

	ssize_t s_recv_bytes;
	ssize_t s_send_bytes;
	
	if(s_epoll_session_type == 0 /* accept event */) {
		if((s_epoll_event->events & EPOLLIN) == EPOLLIN) {
			if(s_session->m_accept_ssl == ((SSL *)(NULL))) {
				s_recv_bytes = recv(s_session->m_accept_socket, s_session->m_buffer, s_session->m_buffer_size, def_SSL_inspection_recv_flags); 
			}
			else {
				int s_ssl_read_bytes;

l_retry_accept:;
				s_ssl_read_bytes = SSL_read(s_session->m_accept_ssl, s_session->m_buffer, (int)s_session->m_buffer_size);
				if(s_ssl_read_bytes > 0) {
					s_recv_bytes = (ssize_t)s_ssl_read_bytes;
				}
				else if(s_ssl_read_bytes == 0) {
					s_recv_bytes = (ssize_t)0;
				}
				else {
					int s_ssl_error;

					s_ssl_error = SSL_get_error(s_session->m_accept_ssl, s_ssl_read_bytes);
					if(s_ssl_error == SSL_ERROR_WANT_ASYNC) {
						SSL_inspection_wait_for_async(s_session->m_accept_ssl);
						goto l_retry_accept;
					}
					else if(s_ssl_error == SSL_ERROR_WANT_READ) {
						return(0); /* NEXT TIME */
					}
					else if(s_ssl_error == SSL_ERROR_WANT_WRITE) {
						(void)SSL_inspection_is_writable(s_session->m_accept_socket, (-1));
						goto l_retry_accept;
					}
					else if(s_ssl_error == SSL_ERROR_ZERO_RETURN) { /* disconnected */
						s_recv_bytes = (ssize_t)0;
					}
#if 0L
					else if(s_ssl_error == SSL_ERROR_SYSCALL) {
						s_recv_bytes = (ssize_t)(-1);
					}
					else if(s_ssl_error == SSL_ERROR_SSL) {
						s_recv_bytes = (ssize_t)(-1);
					}
#endif
					else {
						unsigned long s_error_code;

						for(;;) {
							s_error_code = ERR_get_error();
							if(s_error_code == 0UL) {
								break;
							}
							
							(void)SSL_inspection_fprintf(
								stderr,
								"SSL_recv failed ! (%lu: \"%s\")\n",
								s_error_code,
								ERR_error_string(s_error_code, NULL)
							);
						}

						s_recv_bytes = (ssize_t)(-1);
					}
				}
			}
			if(SSL_inspection_unlikely(s_recv_bytes == ((ssize_t)(-1)))) {
				(void)SSL_inspection_fprintf(
					stderr,
					"SSL_inspection_recv failed ! (accept) : %s (fd=%d, %s)\n",
					strerror(errno),
					s_session->m_accept_socket,
					(s_session->m_accept_ssl == ((SSL *)(NULL))) ? "TCP" : "SSL"
				);

				s_session->m_flags &= (~(def_SSL_inspection_session_flag_accepted | def_SSL_inspection_session_flag_ssl_accepted));

				return(-1);
			}
			if(s_recv_bytes == ((ssize_t)0)) {
				if(s_main_context->m_is_verbose >= 1) {
					(void)SSL_inspection_fprintf(
						stderr,
						"SSL_inspection_recv disconnected ! (accept, fd=%d, %s)\n",
						s_session->m_accept_socket,
						(s_session->m_accept_ssl == ((SSL *)(NULL))) ? "TCP" : "SSL"
					);
				}

				s_session->m_flags &= (~(def_SSL_inspection_session_flag_accepted | def_SSL_inspection_session_flag_ssl_accepted));

				return(-1);
			}

			if(s_main_context->m_is_verbose >= 4) { /* 전체 데이터를 hexa dump */
				(void)SSL_inspection_fprintf(
					stdout,
					"From accept rx (fd=%d) %llu + %ld bytes\n",
					s_session->m_accept_socket,
					(unsigned long long)s_session->m_forward_transfer_size,
					(long)s_recv_bytes
				);
				(void)SSL_inspection_hexdump("  ", s_session->m_buffer, (size_t)s_recv_bytes);
			}
			else if(s_main_context->m_is_verbose >= 3) { /* 전체 데이터를 printable 한 평문으로 출력 */
				(void)SSL_inspection_fprintf(
					stdout,
					"From accept rx (fd=%d) {\n%.*s} %llu + %ld bytes\n",
					s_session->m_accept_socket,
					(int)s_recv_bytes,
					(char *)SSL_inspection_convert_printable_ascii(s_session->m_dup_buffer, s_session->m_buffer, (size_t)s_recv_bytes),
					(unsigned long long)s_session->m_forward_transfer_size,
					(long)s_recv_bytes
				);
			}
			else if(s_main_context->m_is_verbose >= 2) { /* 너무 많이 나오니까 앞에 16 bytes 까지만 출력 */
				(void)SSL_inspection_fprintf(
					stdout,
					"From accept rx (fd=%d) %llu + %ld bytes\n",
					s_session->m_accept_socket,
					(unsigned long long)s_session->m_forward_transfer_size,
					(long)s_recv_bytes
				);
				(void)SSL_inspection_hexdump("  ", s_session->m_buffer, (s_recv_bytes >= ((ssize_t)16)) ? ((size_t)16u) : ((size_t)s_recv_bytes));
			}
			else if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(
					stdout,
					"From accept rx (fd=%d) %llu + %ld bytes\n",
					s_session->m_accept_socket,
					(unsigned long long)s_session->m_forward_transfer_size,
					(long)s_recv_bytes
				);
			}

			s_send_bytes = SSL_inspection_send_fill(
				s_session->m_connect_ssl,
				s_session->m_connect_socket,
				s_session->m_buffer,
				(size_t)s_recv_bytes,
				(-1)
			);
			if(SSL_inspection_unlikely(s_send_bytes == ((ssize_t)(-1)))) {
				(void)SSL_inspection_fprintf(
					stderr,
					"SSL_inspection_send_fill failed ! (connect) : %s (fd=%d, %s)\n",
					strerror(errno),
					s_session->m_connect_socket,
					(s_session->m_connect_ssl == ((SSL *)(NULL))) ? "TCP" : "SSL"
				);

				s_session->m_flags &= (~(def_SSL_inspection_session_flag_connected | def_SSL_inspection_session_flag_ssl_connected));

				return(-1);
			}

			if(s_main_context->m_is_verbose >= 4) { /* 전체 데이터를 hexa dump */
				(void)SSL_inspection_fprintf(
					stdout,
					"To connect tx (fd=%d) %llu + %ld bytes\n",
					s_session->m_connect_socket,
					(unsigned long long)s_session->m_forward_transfer_size,
					(long)s_send_bytes
				);
				(void)SSL_inspection_hexdump("  ", s_session->m_buffer, (size_t)s_send_bytes);
			}
			else if(s_main_context->m_is_verbose >= 3) { /* 전체 데이터를 printable 한 평문으로 출력 */
				(void)SSL_inspection_fprintf(
					stdout,
					"To connect tx (fd=%d) {\n%.*s} %llu + %ld bytes\n",
					s_session->m_connect_socket,
					(int)s_send_bytes,
					(char *)SSL_inspection_convert_printable_ascii(s_session->m_dup_buffer, s_session->m_buffer, (size_t)s_send_bytes),
					(unsigned long long)s_session->m_forward_transfer_size,
					(long)s_send_bytes
				);
			}
			else if(s_main_context->m_is_verbose >= 2) { /* 너무 많이 나오니까 앞에 16 bytes 까지만 출력 */
				(void)SSL_inspection_fprintf(
					stdout,
					"To connect tx (fd=%d) %llu + %ld bytes\n",
					s_session->m_connect_socket,
					(unsigned long long)s_session->m_forward_transfer_size,
					(long)s_send_bytes
				);
				(void)SSL_inspection_hexdump("  ", s_session->m_buffer, (s_send_bytes >= ((ssize_t)16)) ? ((size_t)16u) : ((size_t)s_send_bytes));
			}
			else if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(
					stdout,
					"To connect tx (fd=%d) %llu + %ld bytes\n",
					s_session->m_connect_socket,
					(unsigned long long)s_session->m_forward_transfer_size,
					(long)s_send_bytes
				);
			}

			s_session->m_forward_transfer_size += (unsigned long long)s_send_bytes;
			s_worker_context->m_forward_transfer_size += (unsigned long long)s_send_bytes;
		}
		else {
			(void)SSL_inspection_fprintf(stderr, "unknown accept epoll events 0x%lx\n", (unsigned long)s_epoll_event->events);
			return(0);
		}
	}
	else if(s_epoll_session_type == 1 /* connect event */) {
		if((s_epoll_event->events & EPOLLIN) == EPOLLIN) {
			if(s_session->m_connect_ssl == ((SSL *)(NULL))) {
				s_recv_bytes = recv(s_session->m_connect_socket, s_session->m_buffer, s_session->m_buffer_size, def_SSL_inspection_recv_flags); 
			}
			else {
				int s_ssl_read_bytes;

l_retry_connect:;				
				s_ssl_read_bytes = SSL_read(s_session->m_connect_ssl, s_session->m_buffer, (int)s_session->m_buffer_size);
				if(s_ssl_read_bytes > 0) {
					s_recv_bytes = (ssize_t)s_ssl_read_bytes;
				}
				else if(s_ssl_read_bytes == 0) {
					s_recv_bytes = (ssize_t)0;
				}
				else {
					int s_ssl_error;

					s_ssl_error = SSL_get_error(s_session->m_connect_ssl, s_ssl_read_bytes);
					if(s_ssl_error == SSL_ERROR_WANT_ASYNC) {
						SSL_inspection_wait_for_async(s_session->m_connect_ssl);
						goto l_retry_connect;
					}
					else if(s_ssl_error == SSL_ERROR_WANT_READ) {
						return(0); /* NEXT TIME */
					}
					else if(s_ssl_error == SSL_ERROR_WANT_WRITE) {
						(void)SSL_inspection_is_writable(s_session->m_connect_socket, (-1));
						goto l_retry_connect;
					}
					else if(s_ssl_error == SSL_ERROR_ZERO_RETURN) { /* disconnected */
						s_recv_bytes = (ssize_t)0;
					}
#if 0L
					else if(s_ssl_error == SSL_ERROR_SYSCALL) {
						s_recv_bytes = (ssize_t)(-1);
					}
					else if(s_ssl_error == SSL_ERROR_SSL) {
						s_recv_bytes = (ssize_t)(-1);
					}
#endif
					else {
						unsigned long s_error_code;

						for(;;) {
							s_error_code = ERR_get_error();
							if(s_error_code == 0UL) {
								break;
							}
							
							(void)SSL_inspection_fprintf(
								stderr,
								"SSL_recv failed ! (%lu: \"%s\")\n",
								s_error_code,
								ERR_error_string(s_error_code, NULL)
							);
						}

						s_recv_bytes = (ssize_t)(-1);
					}
				}
			}
			if(SSL_inspection_unlikely(s_recv_bytes == ((ssize_t)(-1)))) {
				(void)SSL_inspection_fprintf(
					stderr,
					"SSL_inspection_recv failed ! (connect) : %s (fd=%d, %s)\n",
					strerror(errno),
					s_session->m_connect_socket,
					(s_session->m_connect_ssl == ((SSL *)(NULL))) ? "TCP" : "SSL"
				);

				s_session->m_flags &= (~(def_SSL_inspection_session_flag_connected | def_SSL_inspection_session_flag_ssl_connected));

				return(-1);
			}
			if(s_recv_bytes == ((ssize_t)0)) {
				if(s_main_context->m_is_verbose >= 1) {
					(void)SSL_inspection_fprintf(
						stderr,
						"SSL_inspection_recv disconnected ! (connect, fd=%d, %s)\n",
						s_session->m_connect_socket,
						(s_session->m_connect_ssl == ((SSL *)(NULL))) ? "TCP" : "SSL"
					);
				}

				s_session->m_flags &= (~(def_SSL_inspection_session_flag_connected | def_SSL_inspection_session_flag_ssl_connected));

				return(-1);
			}

			if(s_main_context->m_is_verbose >= 4) { /* 전체 데이터를 hexa dump */
				(void)SSL_inspection_fprintf(
					stdout,
					"From connect rx (fd=%d) %llu + %ld bytes\n",
					s_session->m_connect_socket,
					(unsigned long long)s_session->m_backward_transfer_size,
					(long)s_recv_bytes
				);
				(void)SSL_inspection_hexdump("  ", s_session->m_buffer, (size_t)s_recv_bytes);
			}
			else if(s_main_context->m_is_verbose >= 3) { /* 전체 데이터를 printable 한 평문으로 출력 */
				(void)SSL_inspection_fprintf(
					stdout,
					"From connect rx (fd=%d) {\n%.*s} %llu + %ld bytes\n",
					s_session->m_connect_socket,
					(int)s_recv_bytes,
					(char *)SSL_inspection_convert_printable_ascii(s_session->m_dup_buffer, s_session->m_buffer, (size_t)s_recv_bytes),
					(unsigned long long)s_session->m_backward_transfer_size,
					(long)s_recv_bytes
				);
			}
			else if(s_main_context->m_is_verbose >= 2) { /* 너무 많이 나오니까 앞에 16 bytes 까지만 출력 */
				(void)SSL_inspection_fprintf(
					stdout,
					"From connect rx (fd=%d) %llu + %ld bytes\n",
					s_session->m_connect_socket,
					(unsigned long long)s_session->m_backward_transfer_size,
					(long)s_recv_bytes
				);
				(void)SSL_inspection_hexdump("  ", s_session->m_buffer, (s_recv_bytes >= ((ssize_t)16)) ? ((size_t)16u) : ((size_t)s_recv_bytes));
			}
			else if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(
					stdout,
					"From connect rx (fd=%d) %llu + %ld bytes\n",
					s_session->m_connect_socket,
					(unsigned long long)s_session->m_backward_transfer_size,
					(long)s_recv_bytes
				);
			}

			s_send_bytes = SSL_inspection_send_fill(
				s_session->m_accept_ssl,
				s_session->m_accept_socket,
				s_session->m_buffer,
				(size_t)s_recv_bytes,
				(-1)
			);
			if(SSL_inspection_unlikely(s_send_bytes == ((ssize_t)(-1)))) {
				(void)SSL_inspection_fprintf(
					stderr,
					"SSL_inspection_send_fill failed ! (accept) : %s (fd=%d, %s)\n",
					strerror(errno),
					s_session->m_accept_socket,
					(s_session->m_accept_ssl == ((SSL *)(NULL))) ? "TCP" : "SSL"
				);

				s_session->m_flags &= (~(def_SSL_inspection_session_flag_accepted | def_SSL_inspection_session_flag_ssl_accepted));

				return(-1);
			}

			if(s_main_context->m_is_verbose >= 4) { /* 전체 데이터를 hexa dump */
				(void)SSL_inspection_fprintf(
					stdout,
					"To accept tx (fd=%d) %llu + %ld bytes\n",
					s_session->m_accept_socket,
					(unsigned long long)s_session->m_backward_transfer_size,
					(long)s_send_bytes
				);
				(void)SSL_inspection_hexdump("  ", s_session->m_buffer, (size_t)s_send_bytes);
			}
			else if(s_main_context->m_is_verbose >= 3) { /* 전체 데이터를 printable 한 평문으로 출력 */
				(void)SSL_inspection_fprintf(
					stdout,
					"To accept tx (fd=%d) {\n%.*s} %llu + %ld bytes\n",
					s_session->m_accept_socket,
					(int)s_send_bytes,
					(char *)SSL_inspection_convert_printable_ascii(s_session->m_dup_buffer, s_session->m_buffer, (size_t)s_send_bytes),
					(unsigned long long)s_session->m_backward_transfer_size,
					(long)s_send_bytes
				);
			}
			else if(s_main_context->m_is_verbose >= 2) { /* 너무 많이 나오니까 앞에 16 bytes 까지만 출력 */
				(void)SSL_inspection_fprintf(
					stdout,
					"To accept tx (fd=%d) %llu + %ld bytes\n",
					s_session->m_accept_socket,
					(unsigned long long)s_session->m_backward_transfer_size,
					(long)s_send_bytes
				);
				(void)SSL_inspection_hexdump("  ", s_session->m_buffer, (s_send_bytes >= ((ssize_t)16)) ? ((size_t)16u) : ((size_t)s_send_bytes));
			}
			else if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(
					stdout,
					"To accept tx (fd=%d) %llu + %ld bytes\n",
					s_session->m_accept_socket,
					(unsigned long long)s_session->m_backward_transfer_size,
					(long)s_send_bytes
				);
			}

			s_session->m_backward_transfer_size += (unsigned long long)s_send_bytes;
			s_worker_context->m_backward_transfer_size += (unsigned long long)s_send_bytes;
		}
		else {
			(void)SSL_inspection_fprintf(stderr, "unknown connect epoll events 0x%lx\n", (unsigned long)s_epoll_event->events);
			return(0);
		}
	}
	else { /* NONE/other event */
		return(-1);
	}

	return(0);
}

void *SSL_inspection_worker_handler(void *s_worker_context_ptr)
{
	SSL_inspection_worker_context_t *s_worker_context = (SSL_inspection_worker_context_t *)s_worker_context_ptr;
	SSL_inspection_main_context_t *s_main_context = s_worker_context->m_main_context;

	int s_check;

	unsigned long long s_prev_time_stamp_msec = SSL_inspection_get_time_stamp_msec(), s_time_stamp_msec, s_delta_time_stamp_msec;
	unsigned long long s_prev_enqueued_session_count = 0ull;
	unsigned long long s_prev_dequeued_session_count = 0ull;
	unsigned long long s_prev_forward_transfer_size = 0ull;
	unsigned long long s_prev_backward_transfer_size = 0ull;

	SSL_inspection_session_t *s_session_prev;
	SSL_inspection_session_t *s_session_next;
	SSL_inspection_session_t *s_session;

	int s_epoll_check;

#if defined(def_sslid_use_dpdk_lcore)
	if(s_worker_context->m_worker_index > 0u) {
		(void)rte_thread_register();
	}
	s_worker_context->m_lcore_id = rte_lcore_id();
	if(s_main_context->m_is_verbose >= 1) {
		(void)SSL_inspection_fprintf(stdout, "Starting worker thread[%u] (lcore_id=%u)\n", s_worker_context->m_worker_index, s_worker_context->m_lcore_id);
	}
#else
	if(s_main_context->m_is_verbose >= 1) {
		(void)SSL_inspection_fprintf(stdout, "Starting worker thread[%u]\n", s_worker_context->m_worker_index);
	}
#endif

       	/* PREPARE LISTENER */
	if((s_main_context->m_use_multi_listen != 0) || (s_worker_context->m_worker_index == 0u)) {
		/* setup bind structure */
		s_check = SSL_inspection_string_to_sockaddr(
			AF_UNSPEC /* detect address family */,
			s_main_context->m_bind_address,
			s_main_context->m_bind_port + ((int)s_worker_context->m_worker_index), /* MULTI PORT LISTENER PER WORKER */
			(void *)(&s_worker_context->m_sockaddr_listen_bind),
			(socklen_t *)(&s_worker_context->m_socklen_listen_bind)
		);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			SSL_inspection_perror("SSL_inspection_string_to_sockaddr (listen bind)");
			goto l_return;
		}

		/* listen socket 생성 */
		if(s_worker_context->m_sockaddr_listen_bind.ss_family == AF_INET) { /* IPv4 only */
			s_worker_context->m_listen_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(SSL_inspection_unlikely(s_worker_context->m_listen_socket == (-1))) {
				SSL_inspection_perror("socket");
				goto l_return;
			}
		
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stdout, "IPv4 socket opened.\n");
			}
		}
		else if(s_worker_context->m_sockaddr_listen_bind.ss_family == AF_INET6) { /* IPv6 (+ IPv4 dual stack) */
			s_worker_context->m_listen_socket = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if(SSL_inspection_unlikely(s_worker_context->m_listen_socket == (-1))) {
				SSL_inspection_perror("socket");
				goto l_return;
			}
			
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stdout, "IPv6 socket opened.\n");
			}

#if /* defined(IPPROTO_IPV6) && */ defined(IPV6_V6ONLY)
			/* make dual stack */
			do {
				int s_value = 0;

				s_check = setsockopt(
					s_worker_context->m_listen_socket,
					(int)(IPPROTO_IPV6),
					(int)(IPV6_V6ONLY),
					(const void *)(&s_value),
					(socklen_t)sizeof(s_value)
				);
				if(SSL_inspection_unlikely(s_check == (-1))) {
					SSL_inspection_perror("IPv6 + IPv4 dual stack");
				}
				else {
					if(s_main_context->m_is_verbose >= 1) {
						(void)SSL_inspection_fprintf(stdout, "IPv6 + IPv4 dual stack supported\n");
					}
				}
			}while(0);
#endif  
		}
		else {
			(void)SSL_inspection_fprintf(stderr, "not supported bind address\n");
			goto l_return;
		}

#if 0L
		if(SSL_inspection_unlikely(SSL_inspection_set_transparent_socket(s_worker_context->m_listen_socket, 1) == (-1))) {
			SSL_inspection_perror("SSL_inspection_set_transparent_socket (listen)");
		}
#else
		(void)SSL_inspection_set_transparent_socket(s_worker_context->m_listen_socket, 1);
#endif

		/*
			reuse setting
			선택사항 : binding socket 의 연결이 있는 상태에서 강제 종료되는 경우 다시 binding 할 수 없는 상태를 방지하기 위함
		*/
		s_check = SSL_inspection_set_reuse_address_socket(s_worker_context->m_listen_socket, 1 /* enable */);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			SSL_inspection_perror("reuse socket");
		}
#if 0L /* FOR SINGLE PORT MULTI LISTENER */
		s_check = SSL_inspection_set_reuse_port_socket(s_worker_context->m_listen_socket, 1 /* enable */);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			SSL_inspection_perror("reuse socket");
		}
#endif

		/* binding */
		s_check = bind(
			s_worker_context->m_listen_socket,
			(struct sockaddr *)(&s_worker_context->m_sockaddr_listen_bind),
			s_worker_context->m_socklen_listen_bind
		);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			SSL_inspection_perror("bind");
			goto l_return;
		}

		/* listen */
		s_check = listen(s_worker_context->m_listen_socket, def_SSL_inspection_backlog /* 최대 backlog 설정 */);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			SSL_inspection_perror("listen");
			goto l_return;
		}

		/* int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event); */
		s_worker_context->m_epoll_event = (struct epoll_event) {
			.events = EPOLLIN,
			.data.fd = s_worker_context->m_listen_socket,
		};
		s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_ADD, s_worker_context->m_listen_socket, (struct epoll_event *)(&s_worker_context->m_epoll_event));
		if(SSL_inspection_unlikely(s_check != 0)) {
			if(errno == EEXIST) {
				s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_MOD, s_worker_context->m_listen_socket, (struct epoll_event *)(&s_worker_context->m_epoll_event));
				if(SSL_inspection_unlikely(s_check != 0)) {
					SSL_inspection_perror("epoll_ctl (EPOLL_CTL_MOD, listen socket)");
					goto l_return;
				}
			}
			else {
				SSL_inspection_perror("epoll_ctl (EPOLL_CTL_ADD, listen socket)");
				goto l_return;
			}
		}
	}

	*((volatile int *)(&s_worker_context->m_running)) = 1;

	while(SSL_inspection_is_break_main_loop() == 0) {
		/* WORKER TIMER */
		s_time_stamp_msec = SSL_inspection_get_time_stamp_msec();
		s_delta_time_stamp_msec = s_time_stamp_msec - s_prev_time_stamp_msec;
		if(s_delta_time_stamp_msec >= 1000ull) {
			if(s_main_context->m_is_verbose >= 0) {
				/* MONITOR */
				if(s_worker_context->m_worker_index == 0u) {
					unsigned long long s_enqueued_session_count;
					unsigned long long s_dequeued_session_count;
					unsigned long long s_forward_transfer_size;
					unsigned long long s_backward_transfer_size;
					unsigned long long s_enqueued_delta;
					unsigned long long s_dequeued_delta;
					unsigned long long s_forward_transfer_delta;
					unsigned long long s_backward_transfer_delta;
					unsigned long long s_enqueued_cps;
					unsigned long long s_dequeued_cps;
					unsigned long long s_forward_transfer_bps;
					unsigned long long s_backward_transfer_bps;
					int s_forward_transfer_unit;
					int s_backward_transfer_unit;

					size_t s_progress_session;
					SSL_inspection_worker_context_t *s_worker_context_trace;

#if 0L
					if(SSL_inspection_unlikely(pthread_mutex_lock((pthread_mutex_t *)(&s_main_context->m_session_queue_lock)) != 0)) {
						(void)SSL_inspection_fprintf(stderr, "enqueue: pthread_mutex_lock\n");
					}
#endif
					s_enqueued_session_count = s_main_context->m_enqueued_session_count;
					s_dequeued_session_count = s_main_context->m_dequeued_session_count;
#if 0L
					if(SSL_inspection_unlikely(pthread_mutex_unlock((pthread_mutex_t *)(&s_main_context->m_session_queue_lock)) != 0)) {
						(void)SSL_inspection_fprintf(stderr, "enqueue: pthread_mutex_unlock\n");
					}
#endif
					s_enqueued_delta = s_enqueued_session_count - s_prev_enqueued_session_count;
					s_dequeued_delta = s_dequeued_session_count - s_prev_dequeued_session_count;
					s_enqueued_cps = (s_enqueued_delta * 1000ull) / s_delta_time_stamp_msec;
					if((s_enqueued_cps == 0ull) && (s_enqueued_delta > 0ull)) {
						s_enqueued_cps = 1ull;
					}
					s_dequeued_cps = (s_dequeued_delta * 1000ull) / s_delta_time_stamp_msec;
					if((s_dequeued_cps == 0ull) && (s_dequeued_delta > 0ull)) {
						s_dequeued_cps = 1ull;
					}

					/* 원자적 접근은 무시하고 대략적인 수치 접근확인정도 */
					s_forward_transfer_size = 0ull;
					s_backward_transfer_size = 0ull;
					s_progress_session = 0ull;
					for(s_worker_context_trace = s_main_context->m_worker_context_head;s_worker_context_trace != ((SSL_inspection_worker_context_t *)(NULL));s_worker_context_trace = s_worker_context_trace->m_next) {
						size_t s_session_queue_count_temp = s_worker_context_trace->m_session_queue_count;

						s_forward_transfer_size += s_worker_context_trace->m_forward_transfer_size;
						s_backward_transfer_size += s_worker_context_trace->m_backward_transfer_size;

						s_progress_session += s_session_queue_count_temp;
					}
					s_forward_transfer_delta = s_forward_transfer_size - s_prev_forward_transfer_size;
					s_backward_transfer_delta = s_backward_transfer_size - s_prev_backward_transfer_size;
					s_forward_transfer_bps = (s_forward_transfer_delta * 8ull * 1000ull) / s_delta_time_stamp_msec;
					if((s_forward_transfer_bps == 0ull) && (s_forward_transfer_delta > 0ull)) {
						s_forward_transfer_bps = 1ull;
					}
					s_forward_transfer_unit = 'K';
					if(s_forward_transfer_bps >= 1000000ull) {
						s_forward_transfer_bps /= 1000ull;
						s_forward_transfer_unit = 'M';
						if(s_forward_transfer_bps >= 1000000ull) {
							s_forward_transfer_bps /= 1000ull;
							s_forward_transfer_unit = 'G';
							if(s_forward_transfer_bps >= 1000000ull) {
								s_forward_transfer_bps /= 1000ull;
								s_forward_transfer_unit = 'T';
							}
						}
					}
					s_backward_transfer_bps = (s_backward_transfer_delta * 8ull * 1000ull) / s_delta_time_stamp_msec;
					if((s_backward_transfer_bps == 0ull) && (s_backward_transfer_delta > 0ull)) {
						s_backward_transfer_bps = 1ull;
					}
					s_backward_transfer_unit = 'K';
					if(s_backward_transfer_bps >= 1000000ull) {
						s_backward_transfer_bps /= 1000ull;
						s_backward_transfer_unit = 'M';
						if(s_backward_transfer_bps >= 1000000ull) {
							s_backward_transfer_bps /= 1000ull;
							s_backward_transfer_unit = 'G';
							if(s_backward_transfer_bps >= 1000000ull) {
								s_backward_transfer_bps /= 1000ull;
								s_backward_transfer_unit = 'T';
							}
						}
					}

					(void)SSL_inspection_fprintf(
						stdout,
						def_hwport_color_magenta "MON" def_hwport_color_normal ": "
						"EQ/DQ " def_hwport_color_white "%5llu" def_hwport_color_normal "/" def_hwport_color_yellow "%5llu" def_hwport_color_normal " CPS, "
						"FW/BW " def_hwport_color_white "%4llu.%03llu" def_hwport_color_normal "%c/" def_hwport_color_white "%4llu.%03llu" def_hwport_color_normal "%c bps, "
						"PROGRESS=" def_hwport_color_white "%4lu" def_hwport_color_normal "\n",
						s_enqueued_cps,
						s_dequeued_cps,
						s_forward_transfer_bps / 1000ull,
						s_forward_transfer_bps % 1000ull,
						s_forward_transfer_unit,
						s_backward_transfer_bps / 1000ull,
						s_backward_transfer_bps % 1000ull,
						s_backward_transfer_unit,
						(unsigned long)s_progress_session
					);

					s_prev_enqueued_session_count = s_enqueued_session_count;
					s_prev_dequeued_session_count = s_dequeued_session_count;
					s_prev_forward_transfer_size = s_forward_transfer_size;
					s_prev_backward_transfer_size = s_backward_transfer_size;
				}
			}

			s_prev_time_stamp_msec = s_time_stamp_msec;
		}

		if(s_worker_context->m_listen_socket != (-1)) { /* LISTEN WORKER */
			if((s_worker_context->m_worker_index == 0u) && (s_main_context->m_max_thread_pool > 0u)) {
#if 0L /* OPTIONAL: 매우 극악의 Worker 사용률일 때 MAIN worker 도 세션처리에 가담 - 보통 이 상태에서 MAIN worker 도 LISTEN 처리로 바쁠 수 있음 */
				size_t s_enqueued_session_count;

				s_enqueued_session_count = SSL_inspection_enqueue_session_list(s_main_context, (SSL_inspection_session_t *)(NULL));
				if(s_enqueued_session_count > ((size_t)128u)) {
					(void)SSL_inspection_checkout_worker_session(s_worker_context, (size_t)1u, 0 /* msec */);
				}
#endif
			}
			else {
				(void)SSL_inspection_checkout_worker_session(s_worker_context, (size_t)128u, 0 /* msec */);
			}
		}
		else { /* SESSION WORKER (NO LISTEN) */
			if(s_worker_context->m_session_queue_count == ((size_t)0u)) {
				(void)SSL_inspection_checkout_worker_session(s_worker_context, (size_t)128u, (-1) /* msec */);
			}
			else {
				(void)SSL_inspection_checkout_worker_session(s_worker_context, (size_t)128u, 0 /* msec */);
			}

			if(s_worker_context->m_session_queue_count == ((size_t)0u)) {
				/* NO EVENT */
				continue;
			}
		}

		/* WAIT EVENTS */
		s_epoll_check = epoll_wait(
			s_worker_context->m_epoll_fd,
		       	(struct epoll_event *)(&s_worker_context->m_epoll_events[0]),
		       	s_worker_context->m_max_epoll_events,
		       	100 /* msec */
		);
		if(SSL_inspection_unlikely(s_epoll_check == (-1))) {
			if(errno != EINTR) {
				SSL_inspection_perror("epoll_wait");
				(void)SSL_inspection_msleep(10);
			}
		}
		else if(s_epoll_check == 0) {
			continue;
		}
		else {
			int s_epoll_index;
			int s_epoll_session_type; /* (-1)=NONE, 0=accept, 1=connect, 2=other */

			/* MULTIPLEXING */
			for(s_epoll_index = 0;s_epoll_index < s_epoll_check;s_epoll_index++) {
				if((s_worker_context->m_listen_socket != (-1)) && (s_worker_context->m_epoll_events[s_epoll_index].data.fd == s_worker_context->m_listen_socket)) {
					if((s_worker_context->m_epoll_events[s_epoll_index].events & EPOLLIN) == EPOLLIN) {
						/* new session */
						s_session = SSL_inspection_new_and_accept_session(s_main_context, s_worker_context->m_listen_socket);
						if(s_session != ((SSL_inspection_session_t *)(NULL))) {
							/* enqueue session */
							(void)SSL_inspection_enqueue_session_list(s_main_context, s_session);
						}
					}
					else if((s_worker_context->m_epoll_events[s_epoll_index].events & EPOLLERR) == EPOLLERR) {
						(void)SSL_inspection_fprintf(stderr, "listen poll error ! (fd=%d)\n", s_worker_context->m_listen_socket);
					}

					continue;
				}

				/* CHECK SESSION EVENT */
				for(s_session_prev = (SSL_inspection_session_t *)(NULL), s_session = s_worker_context->m_session_queue_head;s_session != ((SSL_inspection_session_t *)(NULL));s_session = s_session_next) {
					s_session_next = s_session->m_next;

					if((s_session->m_accept_socket != (-1)) && (s_worker_context->m_epoll_events[s_epoll_index].data.fd == s_session->m_accept_socket)) {
						s_epoll_session_type = 0; /* accept event */
					}
					else if((s_session->m_connect_socket != (-1)) && (s_worker_context->m_epoll_events[s_epoll_index].data.fd == s_session->m_connect_socket)) {
						s_epoll_session_type = 1; /* connect event */
					}
					else {
						s_epoll_session_type = (-1); /* NONE event */
					}

					if(s_epoll_session_type != (-1)) {
						s_check = SSL_inspection_do_session_event(s_worker_context, s_session, (struct epoll_event *)(&s_worker_context->m_epoll_events[s_epoll_index]), s_epoll_session_type);
						if(s_check == (-1)) {
							/* REMOVE WORKER SESSION */
							if(s_session_prev == ((SSL_inspection_session_t *)(NULL))) {
								s_worker_context->m_session_queue_head = s_session_next;
							}
							else {
								s_session_prev->m_next = s_session_next;
							}
							s_session->m_next = (SSL_inspection_session_t *)(NULL);
							if(s_session_next == ((SSL_inspection_session_t *)(NULL))) {
								s_worker_context->m_session_queue_tail = s_session_prev;
							}

							--s_worker_context->m_session_queue_count;

							if(s_session->m_accept_socket != (-1)) {
								s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_DEL, s_session->m_accept_socket, (struct epoll_event *)(NULL));
								if(SSL_inspection_unlikely(s_check == (-1))) {
									if(errno != ENOENT) {
										SSL_inspection_perror("remove epoll (accept)");
									}
								}
							}
							if(s_session->m_connect_socket != (-1)) {
								s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_DEL, s_session->m_connect_socket, (struct epoll_event *)(NULL));
								if(SSL_inspection_unlikely(s_check == (-1))) {
									if(errno != ENOENT) {
										SSL_inspection_perror("remove epoll (accept)");
									}
								}
							}

							(void)SSL_inspection_free_session(s_session);
						}

						break;
					}

					s_session_prev = s_session;
				}
			}
		}
	}

l_return:;
	/* CLEANUP SESSION */
	if(s_main_context->m_is_verbose >= 0) {
		if((s_worker_context->m_session_queue_count != ((size_t)0u)) || (s_worker_context->m_session_queue_head != ((SSL_inspection_session_t *)(NULL))) || (s_worker_context->m_session_queue_tail != ((SSL_inspection_session_t *)(NULL)))) {
			(void)SSL_inspection_fprintf(stdout, "WORKER[%u] Flushing session... (remain session=%lu, %p)\n", s_worker_context->m_worker_index, (unsigned long)s_worker_context->m_session_queue_count, s_worker_context->m_session_queue_head);
		}
	}
	while(s_worker_context->m_session_queue_head != ((SSL_inspection_session_t *)(NULL))) {
		s_session = s_worker_context->m_session_queue_head;
		s_worker_context->m_session_queue_head = s_worker_context->m_session_queue_head->m_next;
		if(s_worker_context->m_session_queue_head == ((SSL_inspection_session_t *)(NULL))) {
			s_worker_context->m_session_queue_tail = (SSL_inspection_session_t *)(NULL);
		}
		s_session->m_next = (SSL_inspection_session_t *)(NULL);
		--s_worker_context->m_session_queue_count;

		if(s_session->m_accept_socket != (-1)) {
			s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_DEL, s_session->m_accept_socket, (struct epoll_event *)(NULL));
			if(SSL_inspection_unlikely(s_check == (-1))) {
				if(errno != ENOENT) {
					SSL_inspection_perror("remove epoll (accept)");
				}
			}
		}
		if(s_session->m_connect_socket != (-1)) {
			s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_DEL, s_session->m_connect_socket, (struct epoll_event *)(NULL));
			if(SSL_inspection_unlikely(s_check == (-1))) {
				if(errno != ENOENT) {
					SSL_inspection_perror("remove epoll (accept)");
				}
			}
		}

		(void)SSL_inspection_free_session(s_session);
	}
#if 1L /* DEBUG */
	if(SSL_inspection_unlikely((s_worker_context->m_session_queue_count != ((size_t)0u)) || (s_worker_context->m_session_queue_head != ((SSL_inspection_session_t *)(NULL))) || (s_worker_context->m_session_queue_tail != ((SSL_inspection_session_t *)(NULL))))) {
		(void)SSL_inspection_fprintf(stderr, "BUG[%u]: s_worker_context->m_session_queue_count = %lu, s_worker_context->m_session_queue_head=%p, s_worker_context->m_session_queue_tail=%p)\n", s_worker_context->m_worker_index, (unsigned long)s_worker_context->m_session_queue_count, s_worker_context->m_session_queue_head, s_worker_context->m_session_queue_tail);
	}
#endif

	/* close listen socket */
	if(s_worker_context->m_listen_socket != (-1)) {
		s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_DEL, s_worker_context->m_listen_socket, (struct epoll_event *)(NULL));
		if(SSL_inspection_unlikely(s_check != 0)) {
			if(errno != ENOENT) {
				SSL_inspection_perror("epoll_ctl (EPOLL_CTL_DEL, listen socket)");
			}
		}

		if(SSL_inspection_unlikely(SSL_inspection_closesocket(s_worker_context->m_listen_socket) == (-1))) {
			SSL_inspection_perror("close listen socket");
		}
		s_worker_context->m_listen_socket = (-1);
	}

	*((volatile int *)(&s_worker_context->m_running)) = 0;

#if defined(def_sslid_use_dpdk_lcore)
	if(s_main_context->m_is_verbose >= 1) {
		(void)SSL_inspection_fprintf(stdout, "Stopping worker thread[%u] (lcore_id=%u)\n", s_worker_context->m_worker_index, s_worker_context->m_lcore_id);
	}
	if(s_worker_context->m_worker_index > 0u) {
		(void)rte_thread_unregister();
	}
#else
	if(s_main_context->m_is_verbose >= 1) {
		(void)SSL_inspection_fprintf(stdout, "Stopping worker thread[%u]\n", s_worker_context->m_worker_index);
	}
#endif

	return((void *)(NULL));
}

int main(int s_argc, char **s_argv)
{
	static SSL_inspection_main_context_t sg_main_context_local;
	SSL_inspection_main_context_t *s_main_context;

	int s_check;

	/* initialize main context */
	s_main_context = (SSL_inspection_main_context_t *)(&sg_main_context_local);
	*s_main_context = (SSL_inspection_main_context_t){
		.m_magic_code_begin = 0x12345678u,
		.m_program_name = def_SSL_inspection_default_program_name,
		.m_is_help = 0,
		.m_is_verbose = 0,
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
		.m_engine_name = (const char *)(NULL),
#endif
		.m_debug_flags = def_SSL_inspection_debug_flag_none,
		.m_bind_address = def_SSL_inspection_listen_address,
		.m_bind_port = def_SSL_inspection_listen_port,
		.m_use_multi_listen = 0,
		.m_cipher_list = def_SSL_inspection_cipher_list,
		.m_certificate_pathname = def_SSL_inspection_default_certificate_pathname,
		.m_privatekey_pathname = def_SSL_inspection_default_privatekey_pathname,
		.m_use_async = 0,
		.m_connect_address = def_SSL_inspection_connect_address,
		.m_connect_port = def_SSL_inspection_connect_port,
		.m_buffer_size = (size_t)def_SSL_inspection_buffer_size,
		.m_thread_model = 1,
		.m_max_thread_pool = 0u,
		.m_use_ssl = 1,
		.m_pid = getpid(),
#if defined(_SC_NPROCESSORS_ONLN)
		.m_cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN),
#endif
		.m_exit_code = EXIT_SUCCESS,
		.m_end_print = 0,
		.m_use_serialize_lock = 0,
		.m_serialize_lock = PTHREAD_MUTEX_INITIALIZER,
		.m_session_queue_cond = PTHREAD_COND_INITIALIZER,
		.m_session_queue_lock = PTHREAD_MUTEX_INITIALIZER,
		.m_session_queue_head = (SSL_inspection_session_t *)(NULL),
		.m_session_queue_tail = (SSL_inspection_session_t *)(NULL),
		.m_session_queue_count = (size_t)0u,
		.m_is_enqueued = 0,
		.m_enqueued_session_count = 0ull,
		.m_dequeued_session_count = 0ull,
		.m_worker_context_head = (SSL_inspection_worker_context_t *)(NULL),
		.m_worker_context_main = (SSL_inspection_worker_context_t *)(NULL),
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
		.m_engine = (ENGINE *)(NULL),
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		.m_ssl_options = 0UL,
#else
		.m_ssl_options = 0L,
#endif
		.m_server_ssl_method = (const SSL_METHOD *)(NULL),
		.m_client_ssl_method = (const SSL_METHOD *)(NULL),
		.m_ssl_ctx = (SSL_CTX *)(NULL),
		.m_sockaddr_connect_bind = {},
		.m_socklen_connect_bind = (socklen_t)sizeof(s_main_context->m_sockaddr_connect_bind),
		.m_sockaddr_connect = {},
		.m_socklen_connect = (socklen_t)sizeof(s_main_context->m_sockaddr_connect),
		.m_magic_code_end = 0x87654321u,
	};
	if(s_main_context->m_cpu_count <= 0) {
		cpu_set_t s_cpuset;

		CPU_ZERO(&s_cpuset);
		s_check = sched_getaffinity(s_main_context->m_pid, sizeof(s_cpuset), (cpu_set_t *)(&s_cpuset));
		if(s_check == 0) {
			s_main_context->m_cpu_count = CPU_COUNT(&s_cpuset);
		}

		if(SSL_inspection_unlikely(s_main_context->m_cpu_count <= 0)) {
			s_main_context->m_cpu_count = 1;
		}
	}

	/* setup signal handler */
	(void)SSL_inspection_install_signal_handler();

	/* argument */
	do {
		static const struct option sg_options[] = {
			{"help", no_argument, (int *)(NULL), 'h'},
			{"quiet", no_argument, (int *)(NULL), 'q'},
			{"verbose", no_argument, (int *)(NULL), 'v'},
			{"debug", no_argument, (int *)(NULL), 'd'},
			{"engine", required_argument, (int *)(NULL), 'e'},
			{"bind", required_argument, (int *)(NULL), 'b'},
			{"port", required_argument, (int *)(NULL), 'p'},
			{"multi-listen", no_argument, (int *)(NULL), 0},
			{"cipher-list", required_argument, (int *)(NULL), 'l'},
			{"cert", required_argument, (int *)(NULL), 'c'},
			{"key", required_argument, (int *)(NULL), 'k'},
			{"connect", no_argument, (int *)(NULL), 'B'},
			{"connect-port", no_argument, (int *)(NULL), 'P'},
			{"buffer-size", required_argument, (int *)(NULL), 0},
			{"no-thread", no_argument, (int *)(NULL), 'n'},
			{"serialize-lock", no_argument, (int *)(NULL), 0},
			{"thread-pool", required_argument, (int *)(NULL), 0},
			{"async", no_argument, (int *)(NULL), 'a'},
			{"nossl", no_argument, (int *)(NULL), 0},
			{(char *)(NULL), 0, (int *)(NULL), 0}
		};
		int s_option_index;

		if((s_argc >= 1) && (s_argv[0] != ((char *)(NULL)))) {
			s_main_context->m_program_name = strrchr(s_argv[0], '/');
			if(s_main_context->m_program_name != ((const char *)(NULL))) {
				s_main_context->m_program_name = (const char *)(&s_main_context->m_program_name[1]);
			}
			else {
				s_main_context->m_program_name = (const char *)s_argv[0];
			}
		}

		for(s_option_index = 0;s_main_context->m_is_help == 0;) {
			s_check = getopt_long(
				s_argc,
				s_argv,
				"hqvd:e:b:p:l:c:k:tsB:P:n",
				sg_options,
				&s_option_index
			);
			if(s_check == (-1)) {
				break;
			}

			switch(s_check) {
				case 0:
					if(strcmp(sg_options[s_option_index].name, "multi-listen") == 0) {
						s_main_context->m_use_multi_listen = 1;
					}
					else if(strcmp(sg_options[s_option_index].name, "buffer-size") == 0) {
						int s_value = atoi(optarg);
						if(s_value > 0) {
							s_main_context->m_buffer_size = (size_t)s_value;
						}
						else {
							(void)SSL_inspection_fprintf(stderr, "invalid option value \"%s\" !\n", sg_options[s_option_index].name);
							s_main_context->m_is_help = 1;
						}
					}
					else if(strcmp(sg_options[s_option_index].name, "serialize-lock") == 0) {
						s_main_context->m_use_serialize_lock = 1;
					}
					else if(strcmp(sg_options[s_option_index].name, "thread-pool") == 0) {
						int s_value = atoi(optarg);
						if(s_value > 0) {
							s_main_context->m_max_thread_pool = (unsigned int)s_value;
						}
						else {
							(void)SSL_inspection_fprintf(stderr, "invalid option value \"%s\" !\n", sg_options[s_option_index].name);
							s_main_context->m_is_help = 1;
						}
					}
					else if(strcmp(sg_options[s_option_index].name, "nossl") == 0) {
						s_main_context->m_use_ssl = 0;
					}
					else { /* unknown option (unlikely) */
						(void)SSL_inspection_fprintf(stderr, "unknown option \"%s\" !\n", sg_options[s_option_index].name);
						s_main_context->m_is_help = 1;
					}
					break;  
				case '?':
				case 'h': s_main_context->m_is_help = 1; break;  
				case 'q': s_main_context->m_is_verbose = (-1); break;  
				case 'v': ++s_main_context->m_is_verbose; break;  
				case 'd': (void)sscanf(optarg, "%i", &s_main_context->m_debug_flags); break;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
				case 'e': s_main_context->m_engine_name = optarg; break;
#endif
				case 'b': s_main_context->m_bind_address = optarg; break;
				case 'p': s_main_context->m_bind_port = atoi(optarg); break;
				case 'l': s_main_context->m_cipher_list = optarg; break;
				case 'c': s_main_context->m_certificate_pathname = optarg; break;
				case 'k': s_main_context->m_privatekey_pathname = optarg; break;
				case 'B': s_main_context->m_connect_address = optarg; break;
				case 'P': s_main_context->m_connect_port = atoi(optarg); break;
				case 'n': s_main_context->m_thread_model = 0; break;
				case 'a': s_main_context->m_use_async = 1; break;
				default: s_main_context->m_is_help = 1; break;
			}
		}

		if(s_main_context->m_is_help != 0) {
			(void)SSL_inspection_fprintf(
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
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
				"\t-e, --engine=<engine name>  : engine name (default: \"%s\")\n"
#endif
				"\t-b, --bind=<address>        : bind address\n"
				"\t-p, --port=<port>           : bind port\n"
				"\t    --multi-listen          : use multiple listen port (worker listen port = bind port + worker_index)\n"
				"\t-l, --cipher-list=<string>  : cipher suite list (default: \"%s\", ex: \"kRSA:ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA256\")\n"
				"\t-c, --cert=<filename>       : certificate filename\n"
				"\t-k, --key=<filename>        : private key filename\n"
				"\t-B, --connect=<address>     : connect address\n"
				"\t-P, --connect-port=<port>   : connect port\n"
				"\t    --buffer-size=<bytes>   : record buffer size\n"
				"\t-n, --no-thread             : non-thread model (single worker)\n"
				"\t    --serialize-lock        : use SSL handshake serialize lock\n"
				"\t    --thread-pool=<count>   : worker thread pool count\n"
				"\t-a, --async                 : use ASYNC mode\n"
				"\t    --nossl                 : TCP proxy mode (passthrough SSL)\n"
				"\n",
				s_main_context->m_program_name,
				__DATE__,
				__TIME__,
				s_main_context->m_program_name,
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
				(s_main_context->m_engine_name == ((const char *)(NULL))) ? "" : s_main_context->m_engine_name,
#endif
				(s_main_context->m_cipher_list == ((const char *)(NULL))) ? "" : s_main_context->m_cipher_list
			);

			return(EXIT_FAILURE);
		}
	}while(0);

	(void)SSL_inspection_fprintf(
		stdout,
		def_hwport_color_green "Initializing SSL-Inspection%s%s%s" def_hwport_color_normal " ... (pid=%d, cpu_count=%d, debug_flags=%08XH, bind=\"[%s]:%d\", connect=\"[%s]:%d\", buffer-size=%lu"
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
		", engine=\"%s\""
#endif
		"%s)\n"
		"\n",
		(s_main_context->m_use_ssl == 0) ? "" : " with OpenSSL",
		"",
		"",
		(int)s_main_context->m_pid,
		s_main_context->m_cpu_count,
		s_main_context->m_debug_flags,
		s_main_context->m_bind_address,
		s_main_context->m_bind_port,
		s_main_context->m_connect_address,
		s_main_context->m_connect_port,
		(unsigned long)s_main_context->m_buffer_size,
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
		(s_main_context->m_engine_name == ((const char *)(NULL))) ? "<default>" : s_main_context->m_engine_name,
#endif
		""
	);

	/* limit set */
	do {
		struct rlimit s_rlimit = {};

		s_check = getrlimit(RLIMIT_NOFILE, &s_rlimit);
		if(s_check == 0) {
			s_rlimit.rlim_max = 1 << 20;
			s_rlimit.rlim_cur = s_rlimit.rlim_max;
			s_check = setrlimit(RLIMIT_NOFILE, &s_rlimit);
			if(s_check == 0) {
				if(s_main_context->m_is_verbose >= 1) {
					(void)SSL_inspection_fprintf(stdout, "RLIMIT_NOFILE set. (max/cur=%llu/%llu)\n", (unsigned long long)s_rlimit.rlim_max, (unsigned long long)s_rlimit.rlim_cur);
				}
			}
		}

		errno = 0;
		s_check = nice(0 /* inc: -20=high, 0=normal, +19=low */);
		if(SSL_inspection_unlikely((s_check == (-1)) && (errno != 0))) {
			SSL_inspection_perror("nice");
		}
		else {
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stdout, "scheduling priority (nice=%d%s)\n", s_check, (s_check < 0) ? "[HIGH]" : "");
			}
		}
	}while(0);

	/* SSL library 초기화 */
	do {
#if defined(def_sslid_use_dpdk_lcore)
		/* main core affinity */
		do {
			cpu_set_t s_cpuset;

			/* CPU0 affinity */
			CPU_ZERO(&s_cpuset);
			CPU_SET(0, &s_cpuset);
			s_check = sched_setaffinity(s_main_context->m_pid, sizeof(s_cpuset), (cpu_set_t *)(&s_cpuset));
			if(SSL_inspection_unlikely(s_check == (-1))) {
				SSL_inspection_perror("CPU0 affinity");
			}
		}while(0);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		if(SSL_inspection_unlikely(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG
#if !defined(OPENSSL_NO_ENGINE)
	                    |OPENSSL_INIT_ENGINE_ALL_BUILTIN
#endif /* !OPENSSL_NO_ENGINE */
	                    , NULL) <= 0)) {
			/* Could not initialize the OpenSSL library ! */
			(void)SSL_inspection_fprintf(stderr, "OPENSSL_init_crypto failed !\n");
			s_main_context->m_exit_code = EXIT_FAILURE;
			goto l_return;
		}
		if(SSL_inspection_unlikely(OPENSSL_init_ssl(0, NULL) <= 0)) {
			/* Could not initialize the OpenSSL library ! */
			(void)SSL_inspection_fprintf(stderr, "OPENSSL_init_ssl failed !\n");
			s_main_context->m_exit_code = EXIT_FAILURE;
			goto l_return;
		}
#else
		if(SSL_inspection_unlikely(SSL_library_init() <= 0)) {
			/* Could not initialize the OpenSSL library ! */
			(void)SSL_inspection_fprintf(stderr, "SSL_library_init failed !\n");
			s_main_context->m_exit_code = EXIT_FAILURE;
			goto l_return;
		}
		OPENSSL_load_builtin_modules();
		ENGINE_load_dynamic();
		ENGINE_load_builtin_engines();
#endif

#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
		if((s_main_context->m_engine_name != ((const char *)(NULL))) && (s_main_context->m_engine_name[0] != '\0')) {
			if(s_main_context->m_is_verbose >= 0) {
				(void)SSL_inspection_fprintf(stdout, "Loading engine : \"%s\"\n", s_main_context->m_engine_name);
			}

			s_main_context->m_engine = ENGINE_by_id(s_main_context->m_engine_name);
			if(SSL_inspection_unlikely(s_main_context->m_engine == ((ENGINE *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "Not usable engine : \"%s\" ! (load failed)\n", s_main_context->m_engine_name);
			}
			else {
				if(s_main_context->m_is_verbose >= 0) {
					(void)SSL_inspection_fprintf(stdout, "Loaded engine : \"%s\"\n", s_main_context->m_engine_name);
				}

#if 0L
				if(s_main_context->m_is_verbose >= 0) {
					BIO *s_bio;

					s_bio = BIO_new_fp(stderr, BIO_NOCLOSE);

					ENGINE_ctrl(s_main_context->m_engine, ENGINE_CTRL_SET_LOGSTREAM, 0, s_bio, 0);
				       
					if(s_bio != ((BIO *)(NULL))) {
						BIO_free_all(s_bio);
					}
				}
#endif

				if(SSL_inspection_unlikely(ENGINE_init(s_main_context->m_engine) <= 0)) {
					(void)SSL_inspection_fprintf(stderr, "Not usable engine : \"%s\" ! (init failed)\n", s_main_context->m_engine_name);
				}
				else {
					if(s_main_context->m_is_verbose >= 0) {
						(void)SSL_inspection_fprintf(stdout, "Initialized engine : \"%s\"\n", s_main_context->m_engine_name);
					}

#if 1L
					if(SSL_inspection_unlikely(ENGINE_set_default(s_main_context->m_engine, ENGINE_METHOD_ALL) <= 0)) {
						(void)SSL_inspection_fprintf(stderr, "Not usable engine : \"%s\" ! (set default)\n", s_main_context->m_engine_name);
					}
#else
					if(SSL_inspection_unlikely(ENGINE_set_default_RSA(s_main_context->m_engine) <= 0)) {
						(void)SSL_inspection_fprintf(stderr, "Not usable engine : \"%s\" ! (set default RSA)\n", s_main_context->m_engine_name);
					}
#endif

					ENGINE_finish(s_main_context->m_engine);
				}
			}
		}
#endif

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
		if(SSL_inspection_unlikely(s_check <= 0)) {
			(void)SSL_inspection_fprintf(stderr, "SSLeay_add_ssl_algorithms failed !\n");
			s_main_context->m_exit_code = EXIT_FAILURE;
			goto l_return;
		}

		/* Load all digest and cipher algorithms */
		OpenSSL_add_ssl_algorithms();
#endif

#if defined(def_sslid_use_dpdk_lcore)
		if(rte_lcore_id() == LCORE_ID_ANY) { /* DPDK not activated */
			cpu_set_t s_cpuset;
			int s_cpu;

			/* CPU ALL affinity (DPDK환경이 아니므로)*/
			CPU_ZERO(&s_cpuset);
			for(s_cpu = 0;s_cpu < s_main_context->m_cpu_count;s_cpu++) {
				CPU_SET(s_cpu, &s_cpuset);
			}
			s_check = sched_setaffinity(s_main_context->m_pid, sizeof(s_cpuset), (cpu_set_t *)(&s_cpuset));
			if(SSL_inspection_unlikely(s_check == (-1))) {
				SSL_inspection_perror("CPU ALL affinity");
			}
		}
#endif

		/* TEST vector */
		if(s_main_context->m_is_verbose >= 0) {
#if defined(def_sslid_test_vector)
			(void)SSL_inspection_sha256_test0(s_main_context->m_is_verbose);
			(void)SSL_inspection_hmac_sha256_test0(s_main_context->m_is_verbose);
			(void)SSL_inspection_hmac_sha256_test1(s_main_context->m_is_verbose);
			(void)SSL_inspection_pseudo_random_function_tlsv1_2_sha256_test0(s_main_context->m_is_verbose);
			(void)SSL_inspection_evp_test0(s_main_context->m_is_verbose);
			(void)SSL_inspection_evp_test1(s_main_context->m_is_verbose);
			(void)SSL_inspection_internal_impl_test0(s_main_context->m_is_verbose);
#endif
		}

		/* ---- SSL_CTX 생성 ---- */

		s_main_context->m_ssl_options |= def_SSL_inspection_default_options;
		s_main_context->m_ssl_options |= SSL_OP_NO_COMPRESSION;
		s_main_context->m_ssl_options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
		/* s_main_context->m_ssl_options |= SSL_OP_CIPHER_SERVER_PREFERENCE; */
		/* s_main_context->m_ssl_options |= SSL_OP_TLS_ROLLBACK_BUG; */
		/* s_main_context->m_ssl_options |= SSL_OP_SINGLE_DH_USE; */
		/* s_main_context->m_ssl_options |= SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION; */
		/* s_main_context->m_ssl_options |= SSL_OP_NO_TICKET; */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		s_main_context->m_server_ssl_method = TLS_server_method();
		s_main_context->m_client_ssl_method = TLS_client_method();
#elif 1L /* TLS v1.2 */
		s_main_context->m_server_ssl_method = TLSv1_2_server_method();
		s_main_context->m_client_ssl_method = TLSv1_2_client_method();
		/* s_main_context->m_ssl_options |= SSL_OP_NO_SSLv2; */
		/* s_main_context->m_ssl_options |= SSL_OP_NO_SSLv3; */
		/* s_main_context->m_ssl_options |= SSL_OP_NO_TLSv1; */
		/* s_main_context->m_ssl_options |= SSL_OP_NO_TLSv1_1; */
#elif 0L /* TLS v1.1 */
		s_main_context->m_server_ssl_method = TLSv1_1_server_method();
		s_main_context->m_client_ssl_method = TLSv1_1_client_method();
		/* s_main_context->m_ssl_options |= SSL_OP_NO_SSLv2; */
		/* s_main_context->m_ssl_options |= SSL_OP_NO_SSLv3; */
		/* s_main_context->m_ssl_options |= SSL_OP_NO_TLSv1; */
#elif 0L /* TLS v1.0 */
		s_main_context->m_server_ssl_method = TLSv1_server_method();
		s_main_context->m_client_ssl_method = TLSv1_client_method();
		/* s_main_context->m_ssl_options |= SSL_OP_NO_SSLv2; */
		/* s_main_context->m_ssl_options |= SSL_OP_NO_SSLv3; */
#else /* SSL v3 */
		s_main_context->m_server_ssl_method = SSLv23_server_method();
		s_main_context->m_client_ssl_method = SSLv23_client_method();
#endif
		if(SSL_inspection_unlikely((s_main_context->m_server_ssl_method == ((const SSL_METHOD *)(NULL))) || (s_main_context->m_client_ssl_method == ((const SSL_METHOD *)(NULL))))) {
			(void)SSL_inspection_fprintf(stderr, "not supported method !\n");
			s_main_context->m_exit_code = EXIT_FAILURE;
			goto l_return;
		}

		if(s_main_context->m_use_ssl != 0) {
			s_main_context->m_ssl_ctx = SSL_inspection_new_SSL_CTX(s_main_context, 1 /* server side */);
			if(SSL_inspection_unlikely(s_main_context->m_ssl_ctx == ((SSL_CTX *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "SSL_inspection_new_SSL_CTX failed !\n");
				s_main_context->m_exit_code = EXIT_FAILURE;
				goto l_return;
			}
		}
	}while(0);
	
	/* setup bind structure */
	s_check = SSL_inspection_string_to_sockaddr(
		AF_UNSPEC /* detect address family */,
		s_main_context->m_connect_address,
		s_main_context->m_connect_port,
		(void *)(&s_main_context->m_sockaddr_connect),
		(socklen_t *)(&s_main_context->m_socklen_connect)
	);
	if(SSL_inspection_unlikely(s_check == (-1))) {
		SSL_inspection_perror("SSL_inspection_string_to_sockaddr (connect)");
		s_main_context->m_exit_code = EXIT_FAILURE;
		goto l_return;
	}
	s_check = SSL_inspection_string_to_sockaddr(
		s_main_context->m_sockaddr_connect.ss_family,
		(const char *)(NULL) /* any address */,
		0 /* any port */,
		(void *)(&s_main_context->m_sockaddr_connect_bind),
		(socklen_t *)(&s_main_context->m_socklen_connect_bind)
	);
	if(SSL_inspection_unlikely(s_check == (-1))) {
		SSL_inspection_perror("SSL_inspection_string_to_sockaddr (connect bind)");
		s_main_context->m_exit_code = EXIT_FAILURE;
		goto l_return;
	}

	/* create thread pool */
	do {
		unsigned int s_max_thread_pool;
		unsigned int s_worker_index;

		if(s_main_context->m_thread_model == 0) { /* thread model */
			s_max_thread_pool = 0u;
		}
		else if(s_main_context->m_max_thread_pool > 0u) {
			s_max_thread_pool = s_main_context->m_max_thread_pool;
		}
		else {
#if defined(def_sslid_use_dpdk_lcore)
			s_max_thread_pool = ((unsigned int)s_main_context->m_cpu_count) - 1u;
#else
			s_max_thread_pool = ((unsigned int)s_main_context->m_cpu_count) << 1;
#endif
		}
		s_main_context->m_max_thread_pool = 0u;
		for(s_worker_index = 0u;s_worker_index <= s_max_thread_pool;s_worker_index++) {
			s_check = SSL_inspection_add_worker(s_main_context, s_worker_index, def_SSL_inspection_worker_flag_none);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				SSL_inspection_perror("add worker");
				continue;
			}
		}
	}while(0);

	if(SSL_inspection_unlikely((s_main_context->m_magic_code_begin != 0x12345678u) || (s_main_context->m_magic_code_end != 0x87654321u))) {
		(void)SSL_inspection_fprintf(stderr, "BUG: detected main context broken ! (BEFORE MAIN LOOP), main_context=%p, magic_code_begin=0x%08x, magic_code_end=0x%08x)\n", s_main_context, (unsigned int)s_main_context->m_magic_code_begin, (unsigned int)s_main_context->m_magic_code_end);
		s_main_context->m_exit_code = EXIT_FAILURE;
		goto l_return;
	}

	if(s_main_context->m_is_verbose >= 0) {
		(void)SSL_inspection_fprintf(stdout,
			def_hwport_color_green "Ready SSL-Inspection%s%s%s" def_hwport_color_normal " ... (\"[%s]:%d\", backlog=%d, thread-pool=%u)\n"
			"\n",
			(s_main_context->m_use_ssl == 0) ? "" : " with OpenSSL",
			"",
			"",
			s_main_context->m_bind_address,
			s_main_context->m_bind_port,
			(int)def_SSL_inspection_backlog,
			(unsigned int)s_main_context->m_max_thread_pool
		);

		++s_main_context->m_end_print;

	}

	if(s_main_context->m_is_verbose >= 1) {
		cpu_set_t s_cpuset;

		CPU_ZERO(&s_cpuset);
		s_check = sched_getaffinity(s_main_context->m_pid, sizeof(s_cpuset), (cpu_set_t *)(&s_cpuset));
		if(SSL_inspection_unlikely(s_check == (-1))) {
			SSL_inspection_perror("get CPU affinity");
		}
		else {
			char s_cpu_affinity_string[ 1 << 10 ];

			(void)SSL_inspection_fprintf(stdout, "MAIN CPU AFFINITY : %s\n", SSL_inspection_cpuset_to_string((char *)(&s_cpu_affinity_string[0]), sizeof(s_cpu_affinity_string), (cpu_set_t *)(&s_cpuset)));
		}
	}

	/* MAIN WORKER */
	(void)SSL_inspection_worker_handler(s_main_context->m_worker_context_main);

l_return:;
	/* cleanup worker */
	if(s_main_context->m_worker_context_head != ((SSL_inspection_worker_context_t *)(NULL))) {
		SSL_inspection_worker_context_t *s_worker_context;

		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout, "Waiting worker thread...\n");
		}

		/* 모든 worker 들의 dequeue wait cond 상태를 깨우기 위해서 broadcast 합니다. */
		SSL_inspection_break_main_loop();
		if(SSL_inspection_unlikely(pthread_mutex_lock((pthread_mutex_t *)(&s_main_context->m_session_queue_lock)) != 0)) {
			(void)SSL_inspection_fprintf(stderr, "wakeup joinable threads: pthread_mutex_lock (%d)\n", s_check);
		}
		(void)pthread_cond_broadcast((pthread_cond_t *)(&s_main_context->m_session_queue_cond));
		if(SSL_inspection_unlikely(pthread_mutex_unlock((pthread_mutex_t *)(&s_main_context->m_session_queue_lock)) != 0)) {
			(void)SSL_inspection_fprintf(stderr, "wakeup joinable threads: pthread_mutex_unlock (%d)\n", s_check);
		}

		/* 모든 worker thread 의 종료를 기다립니다. 그리고 종료되면 worker context 를 파기합니다. */
		while(s_main_context->m_worker_context_head != ((SSL_inspection_worker_context_t *)(NULL))) {
			s_worker_context = s_main_context->m_worker_context_head;
			s_main_context->m_worker_context_head = s_main_context->m_worker_context_head->m_next;

			(void)SSL_inspection_free_worker(s_worker_context);
		}
		s_main_context->m_worker_context_head = s_main_context->m_worker_context_main = (SSL_inspection_worker_context_t *)(NULL);
		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout, "Stopped all worker thread.\n");
		}
	}

	/* cleanup all session */
	do {
		SSL_inspection_session_t *s_session_head;
		size_t s_session_dequeued_count;

	        s_session_dequeued_count = SSL_inspection_dequeue_session_list(
			s_main_context,
		       	(size_t)0u /* all */,
		       	(SSL_inspection_session_t **)(&s_session_head),
		       	(SSL_inspection_session_t **)(NULL),
		       	0 /* msec */
		);
		if(SSL_inspection_unlikely((s_session_dequeued_count > ((size_t)0u)) || (s_session_head != ((SSL_inspection_session_t *)(NULL))))) {
			if(s_main_context->m_is_verbose >= 0) {
				(void)SSL_inspection_fprintf(stdout, "CLEANUP: Flushing session... (remain session=%lu)\n", (unsigned long)s_session_dequeued_count);
			}
			(void)SSL_inspection_free_session_list(s_session_head);
		}
	}while(0);

	/* cleanup ssl */
	if(s_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) {
		if(s_main_context->m_is_verbose >= 0) {
			(void)SSL_inspection_fprintf(stdout, "Cleanup OpenSSL...\n");
		}

		SSL_CTX_free(s_main_context->m_ssl_ctx);
		s_main_context->m_ssl_ctx = (SSL_CTX *)(NULL);

#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
		if(s_main_context->m_engine != ((ENGINE *)(NULL))) {
			ENGINE_free(s_main_context->m_engine);
			s_main_context->m_engine = (ENGINE *)(NULL);
		}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		/* OpenSSL 1.1 deprecates all these cleanup functions and turns them into no-ops in OpenSSL 1.0 compatibility mode */
		OPENSSL_cleanup();
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
	}
	if(s_main_context->m_client_ssl_method != ((const SSL_METHOD *)(NULL))) {
		s_main_context->m_client_ssl_method = (const SSL_METHOD *)(NULL);
	}
	if(s_main_context->m_server_ssl_method != ((const SSL_METHOD *)(NULL))) {
		s_main_context->m_server_ssl_method = (const SSL_METHOD *)(NULL);
	}

	/* cleanup mutex */
	(void)pthread_mutex_destroy((pthread_mutex_t *)(&s_main_context->m_session_queue_lock));
	(void)pthread_cond_destroy((pthread_cond_t *)(&s_main_context->m_session_queue_cond));
	(void)pthread_mutex_destroy((pthread_mutex_t *)(&s_main_context->m_serialize_lock));

#if 1L /* DEBUG */
	if(SSL_inspection_unlikely(s_main_context->m_session_queue_count > ((size_t)0u))) {
		(void)SSL_inspection_fprintf(stderr, "BUG: s_main_context->m_session_queue_count = %lu\n", (unsigned long)s_main_context->m_session_queue_count);
	}
	if(SSL_inspection_unlikely(s_main_context->m_session_queue_head != ((SSL_inspection_session_t *)(NULL)))) {
		(void)SSL_inspection_fprintf(stderr, "BUG: s_main_context->m_session_queue_head = %p\n", s_main_context->m_session_queue_head);
	}
	if(SSL_inspection_unlikely(s_main_context->m_session_queue_tail != ((SSL_inspection_session_t *)(NULL)))) {
		(void)SSL_inspection_fprintf(stderr, "BUG: s_main_context->m_session_queue_tail = %p\n", s_main_context->m_session_queue_tail);
	}
	if(SSL_inspection_unlikely((s_main_context->m_magic_code_begin != 0x12345678u) || (s_main_context->m_magic_code_end != 0x87654321u))) {
		(void)SSL_inspection_fprintf(stderr, "BUG: s_main_context->m_magic_code_[begin/end] = 0x%08x/0x%08x\n", s_main_context->m_magic_code_begin, s_main_context->m_magic_code_end);
	}
#endif

	if(s_main_context->m_end_print > 0) {
		(void)SSL_inspection_fprintf(stdout,
			"\nEnd of SSL-Inspection%s%s.\n\n",
			(s_main_context->m_use_ssl == 0) ? "" : " with OpenSSL",
			""
		);
	}

	(void)fflush(stderr);
	(void)fflush(stdout);

	return(s_main_context->m_exit_code);
}

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
