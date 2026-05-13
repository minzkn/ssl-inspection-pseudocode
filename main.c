/*
	Copyright (C) MINZKN.COM
	All rights reserved.
	Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_main_c__)
# define __def_sslid_source_main_c__ "main.c"

#include "sslid-lib.h"

#include <execinfo.h>
#include <getopt.h>
#include <unistd.h>

#if defined(def_sslid_use_dpdk_lcore)
# include <rte_lcore.h>
#endif

#define def_SSL_inspection_epoll_session_base_events ((uint32_t)(EPOLLERR | EPOLLHUP | EPOLLRDHUP))

/* Runtime ANSI color strings — non-empty only when the target fd is a TTY.
   Initialized once in main() via isatty(). Empty strings produce no output. */
/* stdout colors */
static const char *sg_co_n = ""; /* reset/normal */
static const char *sg_co_c = ""; /* cyan    — [C-fd=N] session tag */
static const char *sg_co_y = ""; /* yellow  — S-fd=N, sni hostname */
static const char *sg_co_g = ""; /* green   — Accepted / connected / closed */
static const char *sg_co_m = ""; /* magenta — SSL Accepted / SSL Connected */
static const char *sg_co_w = ""; /* white   — numeric values */
/* stderr colors */
static const char *sg_ce_n = ""; /* reset/normal */
static const char *sg_ce_c = ""; /* cyan   — [C-fd=N] session tag */
static const char *sg_ce_r = ""; /* red    — error messages */
static const char *sg_ce_y = ""; /* yellow — sni / values in errors */

SSL_inspection_session_t *SSL_inspection_new_and_accept_session(SSL_inspection_main_context_t *s_main_context, int s_listen_socket);
SSL_inspection_session_t *SSL_inspection_free_session(SSL_inspection_session_t *s_session);
SSL_inspection_session_t *SSL_inspection_free_session_list(SSL_inspection_session_t *s_session_list);

size_t SSL_inspection_enqueue_session_list(SSL_inspection_main_context_t *s_main_context, SSL_inspection_session_t *s_session_list);
size_t SSL_inspection_dequeue_session_list(SSL_inspection_main_context_t *s_main_context, size_t s_request_session_count, SSL_inspection_session_t **s_session_head_ptr, SSL_inspection_session_t **s_session_tail_ptr, int s_timeout_msec);

#if 0L /* ALPN */
static int __SSL_inspection_apln_select_callback_handler(SSL *s_ssl, const unsigned char **s_out, unsigned char *s_outlen, const unsigned char *s_in, unsigned int s_inlen, void *s_argument);
#endif
SSL_CTX *SSL_inspection_new_SSL_CTX(SSL_inspection_main_context_t *s_main_context, int s_is_server_side, const char *s_hostname);
static int SSL_inspection_session_peek_sni(SSL_inspection_session_t *s_session);
static int SSL_inspection_session_initiate_connect(SSL_inspection_session_t *s_session);

int SSL_inspection_set_nonblock_socket(int s_socket);
int SSL_inspection_worker_set_epoll_interest(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_epoll_item_t *s_epoll_item, uint32_t s_events);
void SSL_inspection_worker_queue_job(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session);
SSL_inspection_session_t *SSL_inspection_worker_pop_job(SSL_inspection_worker_context_t *s_worker_context);
int SSL_inspection_worker_unlink_session(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session);
void SSL_inspection_worker_release_session_resources(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session);
void SSL_inspection_trace_transfer(SSL_inspection_main_context_t *s_main_context, int s_accept_fd, const char *s_title, int s_fd, unsigned long long s_transferred, const void *s_buffer, size_t s_size);
int SSL_inspection_prepare_session_async(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session);
int SSL_inspection_session_update_epoll(SSL_inspection_session_t *s_session);
void SSL_inspection_session_clear_async_wait(SSL_inspection_session_t *s_session, SSL_inspection_async_wait_t *s_async_wait);
int SSL_inspection_session_refresh_async_wait(SSL_inspection_session_t *s_session, SSL *s_ssl, SSL_inspection_async_wait_t *s_async_wait, unsigned int s_epoll_item_type);
int SSL_inspection_session_ensure_ssl(SSL_inspection_session_t *s_session, int s_is_accept_side);
static int SSL_inspection_session_poll_connect(SSL_inspection_session_t *s_session);
int SSL_inspection_session_drive_connect(SSL_inspection_session_t *s_session);
int SSL_inspection_session_drive_handshake(SSL_inspection_session_t *s_session, int s_is_accept_side);
ssize_t SSL_inspection_session_recv_nonblock(SSL_inspection_session_t *s_session, int s_is_accept_side, void *s_buffer, size_t s_buffer_size);
ssize_t SSL_inspection_session_send_nonblock(SSL_inspection_session_t *s_session, int s_is_accept_side, const void *s_buffer, size_t s_buffer_size);
int SSL_inspection_session_flush_buffer(SSL_inspection_session_t *s_session, int s_to_accept_side);
int SSL_inspection_session_fill_buffer(SSL_inspection_session_t *s_session, int s_from_accept_side);
int SSL_inspection_session_ktls_activate(SSL_inspection_session_t *s_session);
int SSL_inspection_session_splice_relay(SSL_inspection_session_t *s_session);
int SSL_inspection_session_drive(SSL_inspection_session_t *s_session);
void SSL_inspection_worker_attach_session_list(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session_head, SSL_inspection_session_t *s_session_tail, size_t s_session_count);
int SSL_inspection_worker_process_jobs(SSL_inspection_worker_context_t *s_worker_context, size_t s_max_job_count);

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
		.m_prev = NULL,
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
		.m_forward_transfer_count = 0,
		.m_backward_transfer_count = 0,
		.m_buffer_size = s_main_context->m_buffer_size,
		/* Inline buffers follow the session structure */
		.m_buffer = (uint8_t *)(&s_session[1]),
		.m_dup_buffer = (uint8_t *)(&s_session[1]) + s_main_context->m_buffer_size,
		.m_ktls_active = -1,
		.m_fwd_splice_pipe = {-1, -1},
		.m_bwd_splice_pipe = {-1, -1},
		.m_fwd_pipe_pending = (size_t)0u,
		.m_bwd_pipe_pending = (size_t)0u,
		.m_accept_ssl_ctx = NULL,
		.m_sni_hostname = {0},
		.m_auto_detect_result = def_SSL_inspection_auto_detect_unknown,
		.m_peek_start_ts = (uint64_t)0u,
		.m_transport = def_SSL_inspection_transport_tcp,
	};

	/* do accept: accept4 sets SOCK_NONBLOCK|SOCK_CLOEXEC atomically, saving 2 fcntl syscalls */
	s_session->m_accept_socket = accept4(
		s_listen_socket,
		(struct sockaddr *)&s_session->m_sockaddr_accept,
		&s_session->m_socklen_accept,
		SOCK_NONBLOCK | SOCK_CLOEXEC
	);
	if (SSL_inspection_unlikely(s_session->m_accept_socket == -1)) {
		if((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR)) {
			SSL_inspection_perror("accept");
		}
		return SSL_inspection_free_session(s_session);
	}
	s_session->m_flags |= def_SSL_inspection_session_flag_accepted;

	return s_session;
}

static void SSL_inspection_session_format_tuple(const SSL_inspection_session_t *s_session, char *out, size_t out_size)
{
	int s_src_port = 0;
	char s_dst_str[INET6_ADDRSTRLEN] = {0};
	int s_dst_port = 0;
	const SSL_inspection_main_context_t *s_main_context = s_session->m_main_context;

	if(s_session->m_sockaddr_accept.ss_family == AF_INET) {
		s_src_port = (int)ntohs(((const struct sockaddr_in *)(&s_session->m_sockaddr_accept))->sin_port);
	}
	else if(s_session->m_sockaddr_accept.ss_family == AF_INET6) {
		s_src_port = (int)ntohs(((const struct sockaddr_in6 *)(&s_session->m_sockaddr_accept))->sin6_port);
	}
	if(s_session->m_sockaddr_original_dst.ss_family == AF_INET) {
		(void)inet_ntop(AF_INET, &((const struct sockaddr_in *)(&s_session->m_sockaddr_original_dst))->sin_addr,
			s_dst_str, (socklen_t)sizeof(s_dst_str));
		s_dst_port = (int)ntohs(((const struct sockaddr_in *)(&s_session->m_sockaddr_original_dst))->sin_port);
	}
	else if(s_session->m_sockaddr_original_dst.ss_family == AF_INET6) {
		(void)inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)(&s_session->m_sockaddr_original_dst))->sin6_addr,
			s_dst_str, (socklen_t)sizeof(s_dst_str));
		s_dst_port = (int)ntohs(((const struct sockaddr_in6 *)(&s_session->m_sockaddr_original_dst))->sin6_port);
	}
	else if(s_main_context != ((const SSL_inspection_main_context_t *)(NULL))) {
		(void)snprintf(s_dst_str, sizeof(s_dst_str), "%s", s_main_context->m_connect_address);
		s_dst_port = s_main_context->m_connect_port;
	}
	(void)snprintf(out, out_size, "[%s]:%d -> [%s]:%d",
		s_session->m_accept_address_string, s_src_port, s_dst_str, s_dst_port);
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
	{
		int s_accept_fd = s_session->m_accept_socket; /* capture before cleanup zeroes it */

	if(s_main_context->m_is_verbose >= 1) {
		char s_tuple[128];
		SSL_inspection_session_format_tuple(s_session, s_tuple, sizeof(s_tuple));
		(void)SSL_inspection_fprintf(
			stdout,
			"%s[C-fd=%d]%s %sClosed%s %s (%sS-fd=%d%s): fwd %llu pkts / %llu bytes, bwd %llu pkts / %llu bytes\n",
			sg_co_c, s_accept_fd, sg_co_n,
			sg_co_g, sg_co_n,
			s_tuple,
			sg_co_y, s_session->m_connect_socket, sg_co_n,
			s_session->m_forward_transfer_count,
			s_session->m_forward_transfer_size,
			s_session->m_backward_transfer_count,
			s_session->m_backward_transfer_size
		);
	}

	/* accept side */
	if(s_session->m_accept_ssl != ((SSL *)(NULL))) {
		if(s_main_context->m_is_verbose >= 2) {
			(void)SSL_inspection_fprintf(stdout, "%s[C-fd=%d]%s SSL free (accept)\n", sg_co_c, s_accept_fd, sg_co_n);
		}
		SSL_set_quiet_shutdown(s_session->m_accept_ssl, 1);
		SSL_set_shutdown(s_session->m_accept_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
		(void)SSL_set_fd(s_session->m_accept_ssl, (-1));
		SSL_free(s_session->m_accept_ssl);
		s_session->m_accept_ssl = (SSL *)(NULL);
		s_session->m_flags &= (~def_SSL_inspection_session_flag_ssl_accepted);
	}

	if(s_session->m_accept_socket != (-1)) {
		if(s_main_context->m_is_verbose >= 2) {
			(void)SSL_inspection_fprintf(stdout, "%s[C-fd=%d]%s Disconnecting (accept)\n", sg_co_c, s_accept_fd, sg_co_n);
		}

		(void)shutdown(s_session->m_accept_socket, SHUT_RDWR);

		s_check = SSL_inspection_closesocket(s_session->m_accept_socket);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			(void)SSL_inspection_fprintf(stderr,
				"%s[C-fd=%d]%s %sclose accept socket failed%s: %s\n",
				sg_ce_c, s_accept_fd, sg_ce_n, sg_ce_r, sg_ce_n, strerror(errno));
		}
		s_session->m_accept_socket = (-1);
		s_session->m_flags &= (~def_SSL_inspection_session_flag_accepted);
	}

	/* connect side */
	if(s_session->m_connect_ssl != ((SSL *)(NULL))) {
		if(s_main_context->m_is_verbose >= 2) {
			(void)SSL_inspection_fprintf(stdout, "%s[C-fd=%d]%s SSL free (%sS-fd=%d%s)\n", sg_co_c, s_accept_fd, sg_co_n, sg_co_y, s_session->m_connect_socket, sg_co_n);
		}
		SSL_set_quiet_shutdown(s_session->m_connect_ssl, 1);
		SSL_set_shutdown(s_session->m_connect_ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
		(void)SSL_set_fd(s_session->m_connect_ssl, (-1));
		SSL_free(s_session->m_connect_ssl);
		s_session->m_connect_ssl = (SSL *)(NULL);
		s_session->m_flags &= (~def_SSL_inspection_session_flag_ssl_connected);
	}

	if(s_session->m_connect_socket != (-1)) {
		if(s_main_context->m_is_verbose >= 2) {
			(void)SSL_inspection_fprintf(stdout, "%s[C-fd=%d]%s Disconnecting (%sS-fd=%d%s)\n", sg_co_c, s_accept_fd, sg_co_n, sg_co_y, s_session->m_connect_socket, sg_co_n);
		}

		(void)shutdown(s_session->m_connect_socket, SHUT_RDWR);

		s_check = SSL_inspection_closesocket(s_session->m_connect_socket);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			(void)SSL_inspection_fprintf(stderr,
				"%s[C-fd=%d]%s %sclose %sS-fd=%d%s socket failed%s: %s\n",
				sg_ce_c, s_accept_fd, sg_ce_n, sg_ce_r, sg_ce_y, s_session->m_connect_socket, sg_ce_r, sg_ce_n, strerror(errno));
		}
		s_session->m_connect_socket = (-1);
		s_session->m_flags &= (~def_SSL_inspection_session_flag_connected);
	}

	if((s_session->m_connect_ssl_ctx != ((SSL_CTX *)(NULL))) &&
	   (s_session->m_connect_ssl_ctx != s_session->m_main_context->m_client_ssl_ctx)) {
		SSL_CTX_free(s_session->m_connect_ssl_ctx);
	}
	s_session->m_connect_ssl_ctx = (SSL_CTX *)(NULL);

	if((s_session->m_accept_ssl_ctx != ((SSL_CTX *)(NULL))) &&
	   (s_session->m_accept_ssl_ctx != s_session->m_main_context->m_ssl_ctx)) {
		SSL_CTX_free(s_session->m_accept_ssl_ctx);
	}
	s_session->m_accept_ssl_ctx = (SSL_CTX *)(NULL);

	if(s_session->m_accept_async_wait.m_epoll_items != ((SSL_inspection_epoll_item_t *)(NULL))) {
		if(s_session->m_accept_async_wait.m_epoll_items != s_session->m_accept_async_wait.m_inline_epoll_items) {
			free((void *)s_session->m_accept_async_wait.m_epoll_items);
		}
		s_session->m_accept_async_wait.m_epoll_items = (SSL_inspection_epoll_item_t *)(NULL);
	}
	if(s_session->m_accept_async_wait.m_fds != ((OSSL_ASYNC_FD *)(NULL))) {
		if(s_session->m_accept_async_wait.m_fds != s_session->m_accept_async_wait.m_inline_fds) {
			free((void *)s_session->m_accept_async_wait.m_fds);
		}
		s_session->m_accept_async_wait.m_fds = (OSSL_ASYNC_FD *)(NULL);
	}
	s_session->m_accept_async_wait.m_count = (size_t)0u;

	if(s_session->m_connect_async_wait.m_epoll_items != ((SSL_inspection_epoll_item_t *)(NULL))) {
		if(s_session->m_connect_async_wait.m_epoll_items != s_session->m_connect_async_wait.m_inline_epoll_items) {
			free((void *)s_session->m_connect_async_wait.m_epoll_items);
		}
		s_session->m_connect_async_wait.m_epoll_items = (SSL_inspection_epoll_item_t *)(NULL);
	}
	if(s_session->m_connect_async_wait.m_fds != ((OSSL_ASYNC_FD *)(NULL))) {
		if(s_session->m_connect_async_wait.m_fds != s_session->m_connect_async_wait.m_inline_fds) {
			free((void *)s_session->m_connect_async_wait.m_fds);
		}
		s_session->m_connect_async_wait.m_fds = (OSSL_ASYNC_FD *)(NULL);
	}
	s_session->m_connect_async_wait.m_count = (size_t)0u;

	/* close splice pipes if open */
	if(s_session->m_fwd_splice_pipe[0] != (-1)) {
		(void)close(s_session->m_fwd_splice_pipe[0]);
		s_session->m_fwd_splice_pipe[0] = (-1);
	}
	if(s_session->m_fwd_splice_pipe[1] != (-1)) {
		(void)close(s_session->m_fwd_splice_pipe[1]);
		s_session->m_fwd_splice_pipe[1] = (-1);
	}
	if(s_session->m_bwd_splice_pipe[0] != (-1)) {
		(void)close(s_session->m_bwd_splice_pipe[0]);
		s_session->m_bwd_splice_pipe[0] = (-1);
	}
	if(s_session->m_bwd_splice_pipe[1] != (-1)) {
		(void)close(s_session->m_bwd_splice_pipe[1]);
		s_session->m_bwd_splice_pipe[1] = (-1);
	}

	free((void *)s_session);

	} /* s_accept_fd scope */
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

	/* M-4: null guard unconditionally — nothing to enqueue regardless of queue state */
	if(s_session_list == ((SSL_inspection_session_t *)(NULL))) {
		return(0);
	}

	s_mutex_result = pthread_mutex_lock(&s_main_context->m_session_queue_lock);
	if (SSL_inspection_unlikely(s_mutex_result != 0)) {
		(void)SSL_inspection_fprintf(stderr, "CRITICAL: enqueue pthread_mutex_lock failed (error=%d)\n", s_mutex_result);
		/* M-1: free caller's list to prevent leak — mutex failure is unrecoverable */
		(void)SSL_inspection_free_session_list(s_session_list);
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
		(void)pthread_cond_broadcast(&s_main_context->m_session_queue_cond);
		/* M-1: store release right before unlock — symmetric with dequeue M-3 clear */
#if SSL_INSPECTION_HAS_C11_ATOMICS
		atomic_store_explicit(&s_main_context->m_is_enqueued, 1, memory_order_release);
#else
		s_main_context->m_is_enqueued = 1;
		SSL_inspection_barrier();
#endif
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
	/* N-3: recheck under lock closes TOCTOU window from atomic pre-check above */
	if((s_timeout_msec == 0) && (s_main_context->m_session_queue_count == (size_t)0u)) {
		/* M-2: clear stale fast-path flag before releasing lock */
#if SSL_INSPECTION_HAS_C11_ATOMICS
		atomic_store_explicit(&s_main_context->m_is_enqueued, 0, memory_order_release);
#else
		s_main_context->m_is_enqueued = 0;
		SSL_inspection_barrier();
#endif
		(void)pthread_mutex_unlock(&s_main_context->m_session_queue_lock);
		if(s_session_head_ptr != NULL) { *s_session_head_ptr = (SSL_inspection_session_t *)(NULL); }
		if(s_session_tail_ptr != NULL) { *s_session_tail_ptr = (SSL_inspection_session_t *)(NULL); }
		return 0;
	}
	if((s_timeout_msec != 0) && (s_main_context->m_session_queue_head == ((SSL_inspection_session_t *)(NULL)))) {
		if(s_timeout_msec > 0) { /* timed wait for enqueue */
			struct timespec s_timespec;

			if(clock_gettime(CLOCK_MONOTONIC, (struct timespec *)(&s_timespec)) == 0) {
				s_timespec.tv_sec += s_timeout_msec / 1000;
				s_timespec.tv_nsec += (s_timeout_msec % 1000) * 1000000L;
				if(s_timespec.tv_nsec >= 1000000000L) {
					s_timespec.tv_sec++;
					s_timespec.tv_nsec -= 1000000000L;
				}
				/* spurious wakeup 방지: queue가 실제로 비어 있는 동안만 대기 */
				while(s_main_context->m_session_queue_head == ((SSL_inspection_session_t *)(NULL))) {
					if(pthread_cond_timedwait((pthread_cond_t *)(&s_main_context->m_session_queue_cond), (pthread_mutex_t *)(&s_main_context->m_session_queue_lock), (const struct timespec *)(&s_timespec)) == ETIMEDOUT) {
						break;
					}
				}
			}
		}
		else { /* wait for enqueue */
			/* spurious wakeup 방지: queue가 실제로 비어 있는 동안만 대기 */
			while(s_main_context->m_session_queue_head == ((SSL_inspection_session_t *)(NULL))) {
				(void)pthread_cond_wait((pthread_cond_t *)(&s_main_context->m_session_queue_cond), (pthread_mutex_t *)(&s_main_context->m_session_queue_lock));
			}
		}
	}

	if((s_request_session_count == ((size_t)0u)) || (s_main_context->m_session_queue_count <= s_request_session_count)) { /* all available */
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
		(void)pthread_cond_broadcast(&s_main_context->m_session_queue_cond);
	}

	/* M-3: clear fast-path flag right before releasing lock so readers see consistent state */
#if SSL_INSPECTION_HAS_C11_ATOMICS
	if(s_main_context->m_session_queue_count == (size_t)0u) {
		atomic_store_explicit(&s_main_context->m_is_enqueued, 0, memory_order_release);
	}
#else
	if(s_main_context->m_session_queue_count == (size_t)0u) {
		s_main_context->m_is_enqueued = 0;
		SSL_inspection_barrier();
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

static int SSL_inspection_sni_is_loopback(const char *s_sni)
{
	struct in_addr  s_in4;
	struct in6_addr s_in6;
	size_t s_len;

	/* RFC 6066 §3: SNI HostName에 IP 주소는 허용되지 않음 (loopback 포함 모든 IP) */
	if(inet_pton(AF_INET,  s_sni, (void *)(&s_in4)) == 1) return(1);
	if(inet_pton(AF_INET6, s_sni, (void *)(&s_in6)) == 1) return(1);

	/* loopback 이름 */
	if(strcasecmp(s_sni, "localhost") == 0) return(1);

	s_len = strlen(s_sni);

	/* .localhost 접미사 (subdomain.localhost) */
	if((s_len > 10u) && (strcasecmp(s_sni + s_len - 10u, ".localhost") == 0)) return(1);

	/* .local — mDNS/Bonjour 로컬 도메인 (RFC 6762) */
	if((s_len > 6u) && (strcasecmp(s_sni + s_len - 6u, ".local") == 0)) return(1);

	/* 단일 레이블 (점 없음) — 로컬 머신 이름 (mybox, nas, router 등) */
	if(strchr(s_sni, '.') == ((const char *)(NULL))) return(1);

	return(0);
}

static int SSL_inspection_session_peek_sni(SSL_inspection_session_t *s_session)
{
	unsigned char s_buf[16384]; /* TLS record payload 최대 크기 (RFC 5246) — oversized ClientHello 대응 */
	ssize_t s_n;
	size_t s_pos, s_ext_end, s_type, s_len;

	s_session->m_sni_hostname[0] = '\0';
	s_n = recv(s_session->m_accept_socket, s_buf, sizeof(s_buf), MSG_PEEK | MSG_DONTWAIT);
	if(s_n <= 0) {
		if((s_n < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)))
			return(0); /* no data yet — wait */
		return(-1); /* peer closed or hard error */
	}

	/* TLS record header: [0]=0x16(Handshake) [1]=0x03(major) */
	if((size_t)s_n < 5u) return(0); /* 부분 도착 — 더 기다림 */
	if((s_buf[0] != 0x16u) || (s_buf[1] != 0x03u)) return(2); /* not TLS */
	/* Handshake msg: [5]=0x01 (ClientHello) */
	if((size_t)s_n < 9u) return(0);
	if(s_buf[5] != 0x01u) return(2); /* Alert/CCS 등 non-ClientHello → TCP relay */
	/* ClientHello fixed header ends at byte 43 (before session_id length) */
	if((size_t)s_n < 44u) return(0);

	s_pos = 43u;
	/* skip session_id */
	if(s_pos + 1u > (size_t)s_n) return(((size_t)s_n < sizeof(s_buf)) ? 0 : 1);
	s_pos += 1u + (size_t)s_buf[s_pos];
	/* skip cipher_suites */
	if(s_pos + 2u > (size_t)s_n) return(((size_t)s_n < sizeof(s_buf)) ? 0 : 1);
	s_pos += 2u + (((size_t)s_buf[s_pos] << 8) | (size_t)s_buf[s_pos + 1u]);
	/* skip compression_methods */
	if(s_pos + 1u > (size_t)s_n) return(((size_t)s_n < sizeof(s_buf)) ? 0 : 1);
	s_pos += 1u + (size_t)s_buf[s_pos];
	/* extensions length */
	if(s_pos + 2u > (size_t)s_n) return(((size_t)s_n < sizeof(s_buf)) ? 0 : 1); /* no extensions — proceed without SNI */
	s_ext_end = s_pos + 2u + (((size_t)s_buf[s_pos] << 8) | (size_t)s_buf[s_pos + 1u]);
	s_pos += 2u;
	if(s_ext_end > (size_t)s_n) s_ext_end = (size_t)s_n;

	while(s_pos + 4u <= s_ext_end) {
		s_type = ((size_t)s_buf[s_pos] << 8) | (size_t)s_buf[s_pos + 1u];
		s_len  = ((size_t)s_buf[s_pos + 2u] << 8) | (size_t)s_buf[s_pos + 3u];
		s_pos += 4u;
		if(s_pos + s_len > s_ext_end) break;
		if(s_type == 0x0000u) { /* server_name extension */
			if(s_len >= 5u) {
				const unsigned char *s_p = &s_buf[s_pos + 2u]; /* skip list_length (2 bytes) */
				if(s_p[0] == 0x00u) { /* name_type == host_name */
					size_t s_name_len = ((size_t)s_p[1] << 8) | (size_t)s_p[2];
					if((s_name_len > 0u) &&
					   (s_name_len < sizeof(s_session->m_sni_hostname)) &&
					   (&s_p[3] + s_name_len <= &s_buf[s_ext_end])) {
						(void)memcpy(s_session->m_sni_hostname, &s_p[3], s_name_len);
						s_session->m_sni_hostname[s_name_len] = '\0';
					}
				}
			}
			return(1);
		}
		s_pos += s_len;
	}
	return(1); /* no SNI extension found */
}

/* =========================================================================
 * 2-tier SNI certificate cache
 * =========================================================================
 *
 * Tier-1: per-worker local LRU (lock-free, max def_ssl_cert_cache_local_max_entries)
 * Tier-2: global hash-table + LRU protected by pthread_rwlock_t
 *           (max def_ssl_cert_cache_global_max_entries)
 *
 * Cache key  : normalized SNI (lowercase, trailing dot stripped)
 * Cache value: (X509 *, EVP_PKEY *) – OpenSSL-refcounted leaf cert + key
 *
 * Ref-counting contract
 * ---------------------
 *  Every handout from a lookup calls X509_up_ref / EVP_PKEY_up_ref.
 *  The caller is responsible for X509_free / EVP_PKEY_free when done.
 *  SSL_CTX_use_certificate / SSL_CTX_use_PrivateKey increment internally,
 *  so the caller's ref can be freed immediately after those calls.
 *  SSL_CTX_add_extra_chain_cert TAKES ownership; caller must up_ref first.
 *
 * Thundering-herd protection
 * --------------------------
 *  ssl_cert_cache_global_store() takes a write-lock and re-checks before
 *  inserting.  The winner's cert is returned via out_cert/out_pkey with an
 *  extra up_ref; the caller must free the candidate it generated.
 * ========================================================================= */

/* FNV-1a 32-bit hash */
static uint32_t ssl_cert_cache_fnv1a(const char *s)
{
	uint32_t h = 2166136261u;
	for (; *s; ++s) {
		h ^= (uint32_t)(unsigned char)*s;
		h *= 16777619u;
	}
	return h;
}

/* Normalize SNI: lowercase + strip single trailing dot.
 * Returns 0 on success, -1 if src is empty or too long. */
static int ssl_cert_cache_normalize_sni(char *dst, size_t dst_size, const char *src)
{
	size_t len;
	size_t i;

	if ((src == NULL) || (src[0] == '\0')) return -1;
	len = strlen(src);
	if (len == 0u || len >= dst_size) return -1;
	/* strip trailing dot (DNS FQDN) */
	if ((len > 1u) && (src[len - 1u] == '.')) --len;
	if (len == 0u || len >= dst_size) return -1;
	for (i = 0u; i < len; ++i)
		dst[i] = (char)tolower((unsigned char)src[i]);
	dst[len] = '\0';
	return 0;
}

/* --- LRU helpers (shared by local and global, different struct layouts) --- */

/* Global LRU unlink */
static void ssl_cert_cache_global_lru_unlink(ssl_cert_cache_global_t *g, ssl_cert_cache_entry_t *e)
{
	if (e->m_lru_prev != NULL) e->m_lru_prev->m_lru_next = e->m_lru_next;
	else                       g->m_lru_head              = e->m_lru_next;
	if (e->m_lru_next != NULL) e->m_lru_next->m_lru_prev = e->m_lru_prev;
	else                       g->m_lru_tail              = e->m_lru_prev;
	e->m_lru_prev = e->m_lru_next = NULL;
}

static void ssl_cert_cache_global_lru_push_front(ssl_cert_cache_global_t *g, ssl_cert_cache_entry_t *e)
{
	e->m_lru_prev = NULL;
	e->m_lru_next = g->m_lru_head;
	if (g->m_lru_head != NULL) g->m_lru_head->m_lru_prev = e;
	else                       g->m_lru_tail              = e;
	g->m_lru_head = e;
}

/* Local LRU unlink */
static void ssl_cert_cache_local_lru_unlink(ssl_cert_cache_local_t *l, ssl_cert_cache_entry_t *e)
{
	if (e->m_lru_prev != NULL) e->m_lru_prev->m_lru_next = e->m_lru_next;
	else                       l->m_lru_head              = e->m_lru_next;
	if (e->m_lru_next != NULL) e->m_lru_next->m_lru_prev = e->m_lru_prev;
	else                       l->m_lru_tail              = e->m_lru_prev;
	e->m_lru_prev = e->m_lru_next = NULL;
}

static void ssl_cert_cache_local_lru_push_front(ssl_cert_cache_local_t *l, ssl_cert_cache_entry_t *e)
{
	e->m_lru_prev = NULL;
	e->m_lru_next = l->m_lru_head;
	if (l->m_lru_head != NULL) l->m_lru_head->m_lru_prev = e;
	else                       l->m_lru_tail              = e;
	l->m_lru_head = e;
}

/* --- Entry alloc / free --- */

static ssl_cert_cache_entry_t *ssl_cert_cache_entry_new(
	const char *sni, uint32_t hash, X509 *cert, EVP_PKEY *pkey, time_t expiry)
{
	ssl_cert_cache_entry_t *e = (ssl_cert_cache_entry_t *)malloc(sizeof(ssl_cert_cache_entry_t));
	if (SSL_inspection_unlikely(e == NULL)) return NULL;
	(void)memset(e, 0, sizeof(*e));
	/* sni is already normalized and fits in m_sni (caller guarantees length < 256) */
	(void)memcpy(e->m_sni, sni, strlen(sni) + 1u);
	e->m_hash   = hash;
	e->m_expiry = expiry;
	/* Take ownership of one ref each */
	X509_up_ref(cert);
	EVP_PKEY_up_ref(pkey);
	e->m_cert = cert;
	e->m_pkey = pkey;
	return e;
}

static void ssl_cert_cache_entry_free(ssl_cert_cache_entry_t *e)
{
	if (e == NULL) return;
	if (e->m_cert != NULL) { X509_free(e->m_cert);     e->m_cert = NULL; }
	if (e->m_pkey != NULL) { EVP_PKEY_free(e->m_pkey); e->m_pkey = NULL; }
	free(e);
}

/* --- Global cache --- */

static ssl_cert_cache_global_t *ssl_cert_cache_global_create(size_t max_count)
{
	ssl_cert_cache_global_t *g = (ssl_cert_cache_global_t *)malloc(sizeof(ssl_cert_cache_global_t));
	if (SSL_inspection_unlikely(g == NULL)) return NULL;
	(void)memset(g, 0, sizeof(*g));
	g->m_max_count = max_count;
	if (SSL_inspection_unlikely(pthread_rwlock_init(&g->m_rwlock, NULL) != 0)) {
		free(g);
		return NULL;
	}
	return g;
}

static void ssl_cert_cache_global_destroy(ssl_cert_cache_global_t *g)
{
	ssl_cert_cache_entry_t *e, *next;
	if (g == NULL) return;
	/* No lock needed: called only after all workers have joined */
	for (e = g->m_lru_head; e != NULL; e = next) {
		next = e->m_lru_next;
		ssl_cert_cache_entry_free(e);
	}
	(void)pthread_rwlock_destroy(&g->m_rwlock);
	free(g);
}

/* Returns 1 and fills out_cert/out_pkey (each with an extra up_ref) on hit.
 * Returns 0 on miss.  Does NOT update LRU (avoids write on read path). */
static int ssl_cert_cache_global_lookup(
	ssl_cert_cache_global_t *g, const char *sni,
	X509 **out_cert, EVP_PKEY **out_pkey)
{
	uint32_t hash;
	uint32_t bucket;
	ssl_cert_cache_entry_t *e;
	time_t now;

	if (g == NULL) return 0;
	hash   = ssl_cert_cache_fnv1a(sni);
	bucket = hash & (def_ssl_cert_cache_global_bucket_count - 1u);
	now    = time(NULL);

	int s_expired_found = 0;
	(void)pthread_rwlock_rdlock(&g->m_rwlock);
	for (e = g->m_buckets[bucket]; e != NULL; e = e->m_hash_next) {
		if ((e->m_hash == hash) && (strcmp(e->m_sni, sni) == 0)) {
			if (e->m_expiry <= now) { s_expired_found = 1; break; }
			X509_up_ref(e->m_cert);
			EVP_PKEY_up_ref(e->m_pkey);
			*out_cert = e->m_cert;
			*out_pkey = e->m_pkey;
			(void)pthread_rwlock_unlock(&g->m_rwlock);
			return 1;
		}
	}
	(void)pthread_rwlock_unlock(&g->m_rwlock);

	/* Remove stale entry eagerly under write lock to prevent accumulation.
	 * Re-traverse to handle races: another thread may have refreshed it. */
	if (s_expired_found) {
		(void)pthread_rwlock_wrlock(&g->m_rwlock);
		for (e = g->m_buckets[bucket]; e != NULL; e = e->m_hash_next) {
			if ((e->m_hash == hash) && (strcmp(e->m_sni, sni) == 0) &&
			    e->m_expiry <= now) {
				if (e->m_hash_prev != NULL) e->m_hash_prev->m_hash_next = e->m_hash_next;
				else                        g->m_buckets[bucket]         = e->m_hash_next;
				if (e->m_hash_next != NULL) e->m_hash_next->m_hash_prev = e->m_hash_prev;
				ssl_cert_cache_global_lru_unlink(g, e);
				ssl_cert_cache_entry_free(e);
				--g->m_count;
				break;
			}
		}
		(void)pthread_rwlock_unlock(&g->m_rwlock);
	}
	return 0;
}

/* Insert (cert, pkey) for sni.
 *
 * Handles thundering herd: takes write-lock then re-checks.
 * If another worker already inserted:
 *   - discards (cert, pkey) passed by caller
 *   - fills out_cert/out_pkey with winner's cert (up_ref'd)
 * If this worker wins:
 *   - inserts entry (entry holds one ref via ssl_cert_cache_entry_new)
 *   - fills out_cert/out_pkey with another up_ref for caller to use
 * Evicts LRU tail if cache is full (expired entries evicted first).
 *
 * Returns 1 = winner (we inserted), 0 = loser (someone beat us).
 * In both cases *out_cert and *out_pkey are valid and caller must free them. */
static int ssl_cert_cache_global_store(
	ssl_cert_cache_global_t *g, const char *sni,
	X509 *cert, EVP_PKEY *pkey, time_t expiry,
	X509 **out_cert, EVP_PKEY **out_pkey)
{
	uint32_t hash;
	uint32_t bucket;
	ssl_cert_cache_entry_t *e, *evict;
	time_t now;

	if (g == NULL) {
		/* No cache: caller uses the cert they generated */
		X509_up_ref(cert); EVP_PKEY_up_ref(pkey);
		*out_cert = cert; *out_pkey = pkey;
		return 1;
	}

	hash   = ssl_cert_cache_fnv1a(sni);
	bucket = hash & (def_ssl_cert_cache_global_bucket_count - 1u);
	now    = time(NULL);

	(void)pthread_rwlock_wrlock(&g->m_rwlock);

	/* Re-check: another worker may have inserted while we were generating */
	for (e = g->m_buckets[bucket]; e != NULL; e = e->m_hash_next) {
		if ((e->m_hash == hash) && (strcmp(e->m_sni, sni) == 0)) {
			if (e->m_expiry > now) {
				/* Winner exists: return their cert, caller frees own cert */
				X509_up_ref(e->m_cert);
				EVP_PKEY_up_ref(e->m_pkey);
				*out_cert = e->m_cert;
				*out_pkey = e->m_pkey;
				(void)pthread_rwlock_unlock(&g->m_rwlock);
				return 0;
			}
			/* Expired entry for same SNI: remove it before inserting fresh one */
			if (e->m_hash_prev != NULL) e->m_hash_prev->m_hash_next = e->m_hash_next;
			else                        g->m_buckets[bucket]         = e->m_hash_next;
			if (e->m_hash_next != NULL) e->m_hash_next->m_hash_prev = e->m_hash_prev;
			ssl_cert_cache_global_lru_unlink(g, e);
			ssl_cert_cache_entry_free(e);
			--g->m_count;
			break;
		}
	}

	/* Evict LRU tail (prefer expired) if at capacity */
	if (g->m_count >= g->m_max_count) {
		/* First pass: prefer an expired entry anywhere in the tail half */
		evict = g->m_lru_tail;
		if (evict == NULL) evict = g->m_lru_head; /* should not happen */
		if (evict != NULL) {
			uint32_t evict_bucket = evict->m_hash & (def_ssl_cert_cache_global_bucket_count - 1u);
			if (evict->m_hash_prev != NULL) evict->m_hash_prev->m_hash_next = evict->m_hash_next;
			else                            g->m_buckets[evict_bucket]       = evict->m_hash_next;
			if (evict->m_hash_next != NULL) evict->m_hash_next->m_hash_prev = evict->m_hash_prev;
			ssl_cert_cache_global_lru_unlink(g, evict);
			ssl_cert_cache_entry_free(evict);
			--g->m_count;
		}
	}

	/* Insert new entry */
	e = ssl_cert_cache_entry_new(sni, hash, cert, pkey, expiry);
	if (SSL_inspection_unlikely(e == NULL)) {
		/* OOM: return caller's cert with extra up_ref */
		X509_up_ref(cert); EVP_PKEY_up_ref(pkey);
		*out_cert = cert; *out_pkey = pkey;
		(void)pthread_rwlock_unlock(&g->m_rwlock);
		return 1;
	}
	/* Link into bucket chain */
	e->m_hash_next = g->m_buckets[bucket];
	e->m_hash_prev = NULL;
	if (g->m_buckets[bucket] != NULL) g->m_buckets[bucket]->m_hash_prev = e;
	g->m_buckets[bucket] = e;
	ssl_cert_cache_global_lru_push_front(g, e);
	++g->m_count;

	/* Return cert to caller with an extra up_ref (entry already holds one) */
	X509_up_ref(cert); EVP_PKEY_up_ref(pkey);
	*out_cert = cert; *out_pkey = pkey;

	(void)pthread_rwlock_unlock(&g->m_rwlock);
	return 1;
}

/* --- Local (per-worker) cache --- */

static void ssl_cert_cache_local_init(ssl_cert_cache_local_t *l)
{
	(void)memset(l, 0, sizeof(*l));
}

static void ssl_cert_cache_local_destroy(ssl_cert_cache_local_t *l)
{
	ssl_cert_cache_entry_t *e, *next;
	if (l == NULL) return;
	for (e = l->m_lru_head; e != NULL; e = next) {
		next = e->m_lru_next;
		ssl_cert_cache_entry_free(e);
	}
	(void)memset(l, 0, sizeof(*l));
}

/* Returns 1 on hit (fills out_cert/out_pkey with up_ref'd pointers), 0 on miss. */
static int ssl_cert_cache_local_lookup(
	ssl_cert_cache_local_t *l, const char *sni,
	X509 **out_cert, EVP_PKEY **out_pkey)
{
	uint32_t hash;
	uint32_t bucket;
	ssl_cert_cache_entry_t *e;
	time_t now;

	hash   = ssl_cert_cache_fnv1a(sni);
	bucket = hash & (def_ssl_cert_cache_local_bucket_count - 1u);
	now    = time(NULL);

	for (e = l->m_buckets[bucket]; e != NULL; e = e->m_hash_next) {
		if ((e->m_hash == hash) && (strcmp(e->m_sni, sni) == 0)) {
			if (e->m_expiry <= now) {
				/* Expired: evict lazily */
				if (e->m_hash_prev != NULL) e->m_hash_prev->m_hash_next = e->m_hash_next;
				else                        l->m_buckets[bucket]         = e->m_hash_next;
				if (e->m_hash_next != NULL) e->m_hash_next->m_hash_prev = e->m_hash_prev;
				ssl_cert_cache_local_lru_unlink(l, e);
				ssl_cert_cache_entry_free(e);
				--l->m_count;
				return 0;
			}
			/* Promote to LRU front */
			ssl_cert_cache_local_lru_unlink(l, e);
			ssl_cert_cache_local_lru_push_front(l, e);
			X509_up_ref(e->m_cert);
			EVP_PKEY_up_ref(e->m_pkey);
			*out_cert = e->m_cert;
			*out_pkey = e->m_pkey;
			return 1;
		}
	}
	return 0;
}

static void ssl_cert_cache_local_store(
	ssl_cert_cache_local_t *l, const char *sni,
	X509 *cert, EVP_PKEY *pkey, time_t expiry)
{
	uint32_t hash;
	uint32_t bucket;
	ssl_cert_cache_entry_t *e;

	hash   = ssl_cert_cache_fnv1a(sni);
	bucket = hash & (def_ssl_cert_cache_local_bucket_count - 1u);

	/* Evict LRU tail if full */
	if (l->m_count >= def_ssl_cert_cache_local_max_entries) {
		ssl_cert_cache_entry_t *evict = l->m_lru_tail;
		if (evict != NULL) {
			uint32_t evict_bucket = evict->m_hash & (def_ssl_cert_cache_local_bucket_count - 1u);
			if (evict->m_hash_prev != NULL) evict->m_hash_prev->m_hash_next = evict->m_hash_next;
			else                            l->m_buckets[evict_bucket]       = evict->m_hash_next;
			if (evict->m_hash_next != NULL) evict->m_hash_next->m_hash_prev = evict->m_hash_prev;
			ssl_cert_cache_local_lru_unlink(l, evict);
			ssl_cert_cache_entry_free(evict);
			--l->m_count;
		}
	}

	e = ssl_cert_cache_entry_new(sni, hash, cert, pkey, expiry);
	if (SSL_inspection_unlikely(e == NULL)) return;

	e->m_hash_next = l->m_buckets[bucket];
	e->m_hash_prev = NULL;
	if (l->m_buckets[bucket] != NULL) l->m_buckets[bucket]->m_hash_prev = e;
	l->m_buckets[bucket] = e;
	ssl_cert_cache_local_lru_push_front(l, e);
	++l->m_count;
}

/* =========================================================================
 * CA setup and leaf certificate generation
 * =========================================================================
 *
 * ssl_inspection_setup_ca():
 *   Called once at startup (before SSL_inspection_new_SSL_CTX for m_ssl_ctx).
 *   Loads or generates the CA key, then builds a self-signed CA cert.
 *   Stores results in main_context->m_ca_pkey and m_ca_x509.
 *   Also allocates main_context->m_cert_cache.
 *
 * ssl_inspection_generate_leaf_cert():
 *   Generates a fresh ECDSA P-256 leaf key pair, builds an X.509 cert
 *   signed by the CA key.  Adds SubjectAltName DNS:<sni> for RFC 5280
 *   compliance.  Caller owns the returned (X509 *, EVP_PKEY *) references.
 *
 * ssl_inspection_get_or_create_sni_ssl_ctx():
 *   Cache-aware wrapper for per-SNI SSL_CTX creation.
 *   Local hit  → use cached cert directly.
 *   Global hit → promote to local, use cached cert.
 *   Miss       → generate, global-store (thundering-herd safe), local-store.
 * ========================================================================= */

static int ssl_inspection_setup_ca(SSL_inspection_main_context_t *s_main_context)
{
	EVP_PKEY *s_ca_pkey = NULL;
	X509     *s_ca_x509 = NULL;
	X509_NAME *s_name;
	X509_EXTENSION *s_ext;
	int s_check;

	/* --- Generate or load CA private key --- */
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	if (s_main_context->m_privatekey_pathname != NULL) {
		BIO *s_bio = BIO_new_file(s_main_context->m_privatekey_pathname, "rb");
		if (SSL_inspection_unlikely(s_bio == NULL)) {
			(void)SSL_inspection_fprintf(stderr, "CA: BIO_new_file failed (\"%s\")\n",
				s_main_context->m_privatekey_pathname);
			return -1;
		}
		s_ca_pkey = PEM_read_bio_PrivateKey(s_bio, NULL, NULL, NULL);
		BIO_free(s_bio);
	} else {
		s_ca_pkey = EVP_EC_gen(SN_X9_62_prime256v1);
	}
#else
	if (s_main_context->m_privatekey_pathname != NULL) {
		FILE *s_fp = fopen(s_main_context->m_privatekey_pathname, "rb");
		if (SSL_inspection_unlikely(s_fp == NULL)) {
			(void)SSL_inspection_fprintf(stderr, "CA: key file open failed (\"%s\")\n",
				s_main_context->m_privatekey_pathname);
			return -1;
		}
		s_ca_pkey = PEM_read_PrivateKey(s_fp, NULL, NULL, NULL);
		(void)fclose(s_fp);
	} else {
		EC_KEY *s_ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (SSL_inspection_unlikely(s_ec == NULL || EC_KEY_generate_key(s_ec) != 1)) {
			if (s_ec != NULL) EC_KEY_free(s_ec);
			(void)SSL_inspection_fprintf(stderr, "CA: EC key generation failed\n");
			return -1;
		}
		EC_KEY_set_asn1_flag(s_ec, OPENSSL_EC_NAMED_CURVE);
		s_ca_pkey = EVP_PKEY_new();
		if (SSL_inspection_unlikely(s_ca_pkey == NULL || EVP_PKEY_assign_EC_KEY(s_ca_pkey, s_ec) == 0)) {
			EC_KEY_free(s_ec);
			if (s_ca_pkey != NULL) { EVP_PKEY_free(s_ca_pkey); s_ca_pkey = NULL; }
			(void)SSL_inspection_fprintf(stderr, "CA: EVP_PKEY_assign_EC_KEY failed\n");
			return -1;
		}
	}
#endif
	if (SSL_inspection_unlikely(s_ca_pkey == NULL)) {
		(void)SSL_inspection_fprintf(stderr, "CA: private key load/generate failed\n");
		return -1;
	}

	/* --- Build self-signed CA certificate --- */
	s_ca_x509 = X509_new();
	if (SSL_inspection_unlikely(s_ca_x509 == NULL)) {
		(void)SSL_inspection_fprintf(stderr, "CA: X509_new failed\n");
		EVP_PKEY_free(s_ca_pkey);
		return -1;
	}

	/* Serial: random 128-bit positive integer */
	do {
		unsigned char s_buf[16];
		BIGNUM *s_bn;
		if (RAND_bytes(s_buf, (int)sizeof(s_buf)) != 1) {
			s_buf[0] = 0x01;
			(void)memset(s_buf + 1, 0xca, sizeof(s_buf) - 1);
		}
		s_buf[0] &= 0x7Fu;
		s_bn = BN_bin2bn(s_buf, (int)sizeof(s_buf), NULL);
		if (s_bn != NULL) {
			(void)BN_to_ASN1_INTEGER(s_bn, X509_get_serialNumber(s_ca_x509));
			BN_free(s_bn);
		}
	} while (0);

	(void)X509_set_version(s_ca_x509, 2L);  /* v3 */

	/* Validity: -24 h to +10 years */
	(void)X509_gmtime_adj(X509_get_notBefore(s_ca_x509), -86400L);
	(void)X509_gmtime_adj(X509_get_notAfter(s_ca_x509),  86400L * 3650L);

	/* Subject / Issuer (same for self-signed) */
	s_name = X509_get_subject_name(s_ca_x509);
	(void)X509_NAME_add_entry_by_txt(s_name, "CN", MBSTRING_ASC,
		(const unsigned char *)"SSL Inspection Proxy CA", -1, -1, 0);
	(void)X509_NAME_add_entry_by_txt(s_name, "O",  MBSTRING_ASC,
		(const unsigned char *)"SSL-Inspection", -1, -1, 0);
	(void)X509_set_issuer_name(s_ca_x509, s_name);

	/* Public key */
	(void)X509_set_pubkey(s_ca_x509, s_ca_pkey);

	/* BasicConstraints: critical, CA:true, pathLen:0 */
	s_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
		"critical,CA:true,pathlen:0");
	if (s_ext != NULL) {
		(void)X509_add_ext(s_ca_x509, s_ext, -1);
		X509_EXTENSION_free(s_ext);
	}

	/* KeyUsage: critical, keyCertSign, cRLSign */
	s_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
		"critical,keyCertSign,cRLSign");
	if (s_ext != NULL) {
		(void)X509_add_ext(s_ca_x509, s_ext, -1);
		X509_EXTENSION_free(s_ext);
	}

	/* SubjectKeyIdentifier */
	s_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_key_identifier, "hash");
	if (s_ext != NULL) {
		(void)X509_add_ext(s_ca_x509, s_ext, -1);
		X509_EXTENSION_free(s_ext);
	}

	/* Self-sign */
	s_check = X509_sign(s_ca_x509, s_ca_pkey, EVP_sha256());
	if (SSL_inspection_unlikely(s_check == 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "CA: X509_sign failed\n");
		X509_free(s_ca_x509);
		EVP_PKEY_free(s_ca_pkey);
		return -1;
	}

	/* --- Allocate global cert cache --- */
	s_main_context->m_cert_cache = ssl_cert_cache_global_create(
		(size_t)def_ssl_cert_cache_global_max_entries);
	if (SSL_inspection_unlikely(s_main_context->m_cert_cache == NULL)) {
		(void)SSL_inspection_fprintf(stderr, "CA: cert cache alloc failed\n");
		X509_free(s_ca_x509);
		EVP_PKEY_free(s_ca_pkey);
		return -1;
	}

	s_main_context->m_ca_pkey = s_ca_pkey;
	s_main_context->m_ca_x509 = s_ca_x509;

	if (s_main_context->m_is_verbose >= 1) {
		(void)SSL_inspection_fprintf(stdout,
			"CA: %s ECDSA P-256 key, cert cache ready (%u buckets)\n",
			(s_main_context->m_privatekey_pathname != NULL) ? "loaded" : "generated",
			(unsigned)def_ssl_cert_cache_global_max_entries);
	}
	return 0;
}

/* Generate a leaf cert for sni, signed by the CA.
 *
 * The leaf cert includes:
 *   - Subject CN = sni
 *   - SubjectAltName DNS:sni  (required by RFC 5280 / modern browsers)
 *   - Issuer copied from CA cert's subject
 *   - BasicConstraints CA:false (critical)
 *   - Signed by m_ca_pkey
 *
 * Returns 0 on success.  *out_cert and *out_pkey are caller-owned (refcount=1). */
static int ssl_inspection_generate_leaf_cert(
	SSL_inspection_main_context_t *s_main_context, const char *s_sni,
	X509 **out_cert, EVP_PKEY **out_pkey)
{
	EVP_PKEY *s_leaf_pkey = NULL;
	X509     *s_leaf_x509 = NULL;
	X509_NAME *s_subject;
	X509_EXTENSION *s_ext;
	char s_san_str[272]; /* "DNS:" + max 255-char SNI + NUL */
	int s_check;

	/* Generate fresh ECDSA P-256 leaf key */
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	s_leaf_pkey = EVP_EC_gen(SN_X9_62_prime256v1);
#else
	do {
		EC_KEY *s_ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (SSL_inspection_unlikely(s_ec == NULL)) break;
		EC_KEY_set_asn1_flag(s_ec, OPENSSL_EC_NAMED_CURVE);
		if (SSL_inspection_unlikely(EC_KEY_generate_key(s_ec) != 1)) { EC_KEY_free(s_ec); break; }
		s_leaf_pkey = EVP_PKEY_new();
		if (SSL_inspection_unlikely(s_leaf_pkey == NULL || EVP_PKEY_assign_EC_KEY(s_leaf_pkey, s_ec) == 0)) {
			EC_KEY_free(s_ec);
			if (s_leaf_pkey != NULL) { EVP_PKEY_free(s_leaf_pkey); s_leaf_pkey = NULL; }
		}
	} while (0);
#endif
	if (SSL_inspection_unlikely(s_leaf_pkey == NULL)) {
		(void)SSL_inspection_fprintf(stderr, "leaf cert: leaf key generation failed (sni=\"%s\")\n", s_sni);
		return -1;
	}

	s_leaf_x509 = X509_new();
	if (SSL_inspection_unlikely(s_leaf_x509 == NULL)) {
		(void)SSL_inspection_fprintf(stderr, "leaf cert: X509_new failed\n");
		EVP_PKEY_free(s_leaf_pkey);
		return -1;
	}

	(void)X509_set_version(s_leaf_x509, 2L); /* v3 */

	/* Random 128-bit positive serial */
	do {
		unsigned char s_buf[16];
		BIGNUM *s_bn;
		if (RAND_bytes(s_buf, (int)sizeof(s_buf)) != 1) {
			s_buf[0] = 0x01;
			(void)memset(s_buf + 1, 0xab, sizeof(s_buf) - 1);
		}
		s_buf[0] &= 0x7Fu;
		s_bn = BN_bin2bn(s_buf, (int)sizeof(s_buf), NULL);
		if (s_bn != NULL) {
			(void)BN_to_ASN1_INTEGER(s_bn, X509_get_serialNumber(s_leaf_x509));
			BN_free(s_bn);
		}
	} while (0);

	/* Validity: -24 h to +2 years */
	(void)X509_gmtime_adj(X509_get_notBefore(s_leaf_x509), -86400L);
	(void)X509_gmtime_adj(X509_get_notAfter(s_leaf_x509),
		(long)def_ssl_cert_cache_leaf_validity_secs);

	/* Subject: CN = sni */
	s_subject = X509_get_subject_name(s_leaf_x509);
	(void)X509_NAME_add_entry_by_txt(s_subject, "CN", MBSTRING_ASC,
		(const unsigned char *)s_sni, -1, -1, 0);

	/* Issuer: copy from CA cert's subject */
	(void)X509_set_issuer_name(s_leaf_x509,
		X509_get_subject_name(s_main_context->m_ca_x509));

	/* Public key = fresh leaf key */
	(void)X509_set_pubkey(s_leaf_x509, s_leaf_pkey);

	/* SubjectAltName DNS:<sni>  — required by RFC 5280 §4.2.1.6 */
	(void)snprintf(s_san_str, sizeof(s_san_str), "DNS:%s", s_sni);
	s_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, s_san_str);
	if (s_ext != NULL) {
		(void)X509_add_ext(s_leaf_x509, s_ext, -1);
		X509_EXTENSION_free(s_ext);
	}

	/* BasicConstraints: critical, CA:false */
	s_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:false");
	if (s_ext != NULL) {
		(void)X509_add_ext(s_leaf_x509, s_ext, -1);
		X509_EXTENSION_free(s_ext);
	}

	/* ExtendedKeyUsage: serverAuth */
	s_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "serverAuth");
	if (s_ext != NULL) {
		(void)X509_add_ext(s_leaf_x509, s_ext, -1);
		X509_EXTENSION_free(s_ext);
	}

	/* Sign with CA key — this is what makes it a real MITM cert */
	s_check = X509_sign(s_leaf_x509, s_main_context->m_ca_pkey, EVP_sha256());
	if (SSL_inspection_unlikely(s_check == 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "leaf cert: X509_sign failed (sni=\"%s\")\n", s_sni);
		X509_free(s_leaf_x509);
		EVP_PKEY_free(s_leaf_pkey);
		return -1;
	}

	*out_cert = s_leaf_x509;
	*out_pkey = s_leaf_pkey;
	return 0;
}

/* Create an SSL_CTX for the accept (server) side using a pre-built cert+key.
 * Applies the same options/ciphers/session-cache as SSL_inspection_new_SSL_CTX.
 * Adds m_ca_x509 as an extra chain cert so the client can build the trust chain.
 * Returns NULL on failure.  Caller must SSL_CTX_free() when done. */
static SSL_CTX *ssl_inspection_create_accept_ssl_ctx(
	SSL_inspection_main_context_t *s_main_context,
	X509 *s_cert, EVP_PKEY *s_pkey)
{
	SSL_CTX *s_ssl_ctx;
	int s_check;

	s_ssl_ctx = SSL_CTX_new(s_main_context->m_server_ssl_method);
	if (SSL_inspection_unlikely(s_ssl_ctx == NULL)) return NULL;

	if (s_main_context->m_use_async > 0)
		(void)SSL_CTX_set_mode(s_ssl_ctx, SSL_MODE_ASYNC);
	(void)SSL_CTX_set_mode(s_ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	(void)SSL_CTX_set_mode(s_ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	(void)SSL_CTX_set_options(s_ssl_ctx, s_main_context->m_ssl_options);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	if (s_main_context->m_use_ktls > 0)
		(void)SSL_CTX_set_options(s_ssl_ctx, SSL_OP_ENABLE_KTLS);
#endif
	(void)SSL_CTX_set_ecdh_auto(s_ssl_ctx, 1);
	(void)SSL_CTX_set_dh_auto(s_ssl_ctx, 1);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	(void)SSL_CTX_set_min_proto_version(s_ssl_ctx, TLS1_2_VERSION);
	(void)SSL_CTX_set_max_proto_version(s_ssl_ctx, TLS1_3_VERSION);
#endif

	if (s_main_context->m_cipher_list != NULL) {
		s_check = SSL_CTX_set_cipher_list(s_ssl_ctx, s_main_context->m_cipher_list);
		if (SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			SSL_CTX_free(s_ssl_ctx);
			return NULL;
		}
	}

	/* Leaf certificate */
	s_check = SSL_CTX_use_certificate(s_ssl_ctx, s_cert);
	if (SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "sni ctx: SSL_CTX_use_certificate failed\n");
		SSL_CTX_free(s_ssl_ctx);
		return NULL;
	}

	/* Leaf private key */
	s_check = SSL_CTX_use_PrivateKey(s_ssl_ctx, s_pkey);
	if (SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "sni ctx: SSL_CTX_use_PrivateKey failed\n");
		SSL_CTX_free(s_ssl_ctx);
		return NULL;
	}

	s_check = SSL_CTX_check_private_key(s_ssl_ctx);
	if (SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "sni ctx: SSL_CTX_check_private_key failed\n");
		SSL_CTX_free(s_ssl_ctx);
		return NULL;
	}

	/* Add CA cert to chain so clients can validate the leaf cert.
	 * SSL_CTX_add_extra_chain_cert takes ownership ONLY on success.
	 * On failure the ref we up_ref'd must be released explicitly. */
	if (s_main_context->m_ca_x509 != NULL) {
		X509_up_ref(s_main_context->m_ca_x509);
		s_check = (int)SSL_CTX_add_extra_chain_cert(s_ssl_ctx, s_main_context->m_ca_x509);
		if (SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			X509_free(s_main_context->m_ca_x509); /* release our ref — ownership not transferred */
		}
	}

	SSL_CTX_set_session_cache_mode(s_ssl_ctx, SSL_SESS_CACHE_SERVER);
	SSL_CTX_set_timeout(s_ssl_ctx, 3600L);

	return s_ssl_ctx;
}

/* Cache-aware per-SNI SSL_CTX factory.
 *
 * Order of operations:
 *  1. Normalize SNI
 *  2. Tier-1 local cache lookup (no lock, fast path)
 *  3. Tier-2 global cache lookup (rdlock)
 *  4. Miss: generate leaf cert, global-store with thundering-herd guard,
 *           local-store
 *  5. Create SSL_CTX with the resolved cert+key, free caller refs
 *
 * Returns a ready SSL_CTX or NULL on error. */
static SSL_CTX *ssl_inspection_get_or_create_sni_ssl_ctx(
	SSL_inspection_main_context_t *s_main_context,
	SSL_inspection_worker_context_t *s_worker_context,
	int s_accept_fd,
	const char *s_sni_raw)
{
	(void)s_accept_fd;
	char s_sni[256];
	X509     *s_cert = NULL;
	EVP_PKEY *s_pkey = NULL;
	SSL_CTX  *s_ssl_ctx;
	time_t s_expiry;
	int s_source; /* 0=local, 1=global, 2=generated */

	if (ssl_cert_cache_normalize_sni(s_sni, sizeof(s_sni), s_sni_raw) != 0) {
		/* Fallback: use raw SNI (truncated safely) */
		(void)strncpy(s_sni, s_sni_raw, sizeof(s_sni) - 1u);
		s_sni[sizeof(s_sni) - 1u] = '\0';
	}

	/* Tier-1: per-worker local cache (lock-free) */
	if ((s_worker_context != NULL) &&
	    ssl_cert_cache_local_lookup(&s_worker_context->m_cert_cache_local,
	                                s_sni, &s_cert, &s_pkey)) {
		s_source = 0;
		goto l_have_cert;
	}

	/* Tier-2: global cache (rdlock) */
	if ((s_main_context->m_cert_cache != NULL) &&
	    ssl_cert_cache_global_lookup(s_main_context->m_cert_cache,
	                                 s_sni, &s_cert, &s_pkey)) {
		s_source = 1;
		/* Promote to local cache (local_store takes its own up_ref) */
		s_expiry = time(NULL) + (time_t)def_ssl_cert_cache_ttl_secs;
		if (s_worker_context != NULL)
			ssl_cert_cache_local_store(&s_worker_context->m_cert_cache_local,
			                           s_sni, s_cert, s_pkey, s_expiry);
		goto l_have_cert;
	}

	/* Miss: generate a CA-signed leaf cert */
	if (SSL_inspection_unlikely(s_main_context->m_ca_pkey == NULL ||
	                             s_main_context->m_ca_x509 == NULL)) {
		(void)SSL_inspection_fprintf(stderr,
			"sni ctx: CA not initialized, cannot generate cert for \"%s\"\n", s_sni);
		return NULL;
	}
	if (SSL_inspection_unlikely(ssl_inspection_generate_leaf_cert(
	        s_main_context, s_sni, &s_cert, &s_pkey) != 0)) {
		return NULL;
	}
	s_source = 2;
	s_expiry  = time(NULL) + (time_t)def_ssl_cert_cache_ttl_secs;

	/* Global store with thundering-herd guard.
	 * out_cert/out_pkey receive the canonical cert (ours or winner's, up_ref'd).
	 * We then free our generated copies. */
	if (s_main_context->m_cert_cache != NULL) {
		X509     *s_out_cert = NULL;
		EVP_PKEY *s_out_pkey = NULL;
		(void)ssl_cert_cache_global_store(s_main_context->m_cert_cache,
		                                  s_sni, s_cert, s_pkey, s_expiry,
		                                  &s_out_cert, &s_out_pkey);
		/* Release our generated copies (global store holds its own ref) */
		X509_free(s_cert);
		EVP_PKEY_free(s_pkey);
		s_cert = s_out_cert;
		s_pkey = s_out_pkey;
	}

	/* Local store (takes its own up_ref internally) */
	if (s_worker_context != NULL)
		ssl_cert_cache_local_store(&s_worker_context->m_cert_cache_local,
		                           s_sni, s_cert, s_pkey, s_expiry);

l_have_cert:
	if (s_main_context->m_is_verbose >= 2) {
		static const char * const s_src_name[] = {"local-cache", "global-cache", "generated"};
		(void)SSL_inspection_fprintf(stdout,
			"sni ctx: \"%s\" [%s]\n", s_sni,
			s_src_name[(s_source < 3) ? s_source : 2]);
	}

	s_ssl_ctx = ssl_inspection_create_accept_ssl_ctx(s_main_context, s_cert, s_pkey);

	/* Release caller refs: SSL_CTX_use_certificate/PrivateKey already up_ref'd */
	X509_free(s_cert);
	EVP_PKEY_free(s_pkey);

	return s_ssl_ctx;
}

SSL_CTX *SSL_inspection_new_SSL_CTX(SSL_inspection_main_context_t *s_main_context, int s_is_server_side, const char *s_hostname)
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
	if(SSL_inspection_unlikely(SSL_CTX_set_mode(s_ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) <= 0)) {
		ERR_print_errors_fp(stderr);
		(void)SSL_inspection_fprintf(stderr, "SSL_CTX_set_mode SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER failed ! (%s)\n", (s_is_server_side <= 0) ? "client side" : "server side");
	}
#endif
	(void)SSL_CTX_set_options(s_ssl_ctx, s_main_context->m_ssl_options);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	if(s_main_context->m_use_ktls > 0) {
		(void)SSL_CTX_set_options(s_ssl_ctx, SSL_OP_ENABLE_KTLS);
	}
#endif
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

#if 1L /* TLS v1.2 ~ v1.3 */
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
			(void *)(s_main_context) /* N-3: pass pointer, not address-of-local-pointer */
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
		/* For proxy use case: verify but don't fail on certificate errors */
		SSL_CTX_set_verify(s_ssl_ctx, SSL_VERIFY_NONE, NULL);
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
			(void)SSL_inspection_fprintf(stdout, "Using certificate file ... (\"%s\")\n", s_main_context->m_certificate_pathname);
		}

		s_check = SSL_CTX_use_certificate_file(s_ssl_ctx, s_main_context->m_certificate_pathname, SSL_FILETYPE_PEM);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_use_certificate_file failed !\n");
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout, "Using private key file ... (\"%s\")\n", s_main_context->m_privatekey_pathname);
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
		EVP_PKEY *s_evp_pkey;
		X509 *s_x509;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#else
		EC_KEY *s_ec_key;
#endif

		/* Startup (hostname=NULL) with a pre-built CA: generate a default leaf cert
		 * (CN=localhost, SAN DNS:localhost) so the SSL_CTX presents a valid server cert.
		 * Per-SNI calls never reach here; they use ssl_inspection_get_or_create_sni_ssl_ctx(). */
		if ((s_is_server_side > 0) &&
		    (s_hostname == ((const char *)(NULL))) &&
		    (s_main_context->m_ca_pkey != ((EVP_PKEY *)(NULL))) &&
		    (s_main_context->m_ca_x509 != ((X509 *)(NULL)))) {
			X509     *s_leaf_cert = NULL;
			EVP_PKEY *s_leaf_pkey = NULL;
			int s_rc;
			if (SSL_inspection_unlikely(ssl_inspection_generate_leaf_cert(
			        s_main_context, "localhost", &s_leaf_cert, &s_leaf_pkey) != 0)) {
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
			s_rc = SSL_CTX_use_certificate(s_ssl_ctx, s_leaf_cert);
			if (SSL_inspection_unlikely(s_rc <= 0)) {
				ERR_print_errors_fp(stderr);
				(void)SSL_inspection_fprintf(stderr, "SSL_CTX_use_certificate (default leaf) failed\n");
				X509_free(s_leaf_cert);
				EVP_PKEY_free(s_leaf_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
			s_rc = SSL_CTX_use_PrivateKey(s_ssl_ctx, s_leaf_pkey);
			if (SSL_inspection_unlikely(s_rc <= 0)) {
				ERR_print_errors_fp(stderr);
				(void)SSL_inspection_fprintf(stderr, "SSL_CTX_use_PrivateKey (default leaf) failed\n");
				X509_free(s_leaf_cert);
				EVP_PKEY_free(s_leaf_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
			s_rc = SSL_CTX_check_private_key(s_ssl_ctx);
			if (SSL_inspection_unlikely(s_rc <= 0)) {
				ERR_print_errors_fp(stderr);
				(void)SSL_inspection_fprintf(stderr, "SSL_CTX_check_private_key (default leaf) failed\n");
				X509_free(s_leaf_cert);
				EVP_PKEY_free(s_leaf_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
			/* Add CA cert to chain so clients see the full chain */
			X509_up_ref(s_main_context->m_ca_x509);
			if (SSL_inspection_unlikely(SSL_CTX_add_extra_chain_cert(s_ssl_ctx, s_main_context->m_ca_x509) <= 0)) {
				X509_free(s_main_context->m_ca_x509);
			}
			X509_free(s_leaf_cert);
			EVP_PKEY_free(s_leaf_pkey);
			goto l_ssl_ctx_cert_done;
		}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
		if(s_main_context->m_privatekey_pathname != ((const char *)(NULL))) {
			BIO *s_bio_key = BIO_new_file(s_main_context->m_privatekey_pathname, "rb");
			if(SSL_inspection_unlikely(s_bio_key == ((BIO *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "privatekey BIO_new_file failed !\n");
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
			s_evp_pkey = PEM_read_bio_PrivateKey(s_bio_key, (EVP_PKEY **)(NULL), (pem_password_cb *)(NULL), (void *)(NULL));
			BIO_free(s_bio_key);
		}
		else {
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stdout, "Generating ECDSA P-256 private key ...\n");
			}
			s_evp_pkey = EVP_EC_gen(SN_X9_62_prime256v1);
		}
#else
		s_evp_pkey = EVP_PKEY_new();
#endif
		if(SSL_inspection_unlikely(s_evp_pkey == ((EVP_PKEY *)(NULL)))) {
			(void)SSL_inspection_fprintf(stderr, "EVP_PKEY load/generate failed !\n");
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
				(void)SSL_inspection_fprintf(stdout, "Generating ECDSA P-256 private key ...\n");
			}

			s_ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			if(SSL_inspection_unlikely(s_ec_key == ((EC_KEY *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "EC_KEY_new_by_curve_name failed !\n");
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
			EC_KEY_set_asn1_flag(s_ec_key, OPENSSL_EC_NAMED_CURVE);
			if(SSL_inspection_unlikely(EC_KEY_generate_key(s_ec_key) != 1)) {
				(void)SSL_inspection_fprintf(stderr, "EC_KEY_generate_key failed !\n");
				EC_KEY_free(s_ec_key);
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
			if(SSL_inspection_unlikely(EVP_PKEY_assign_EC_KEY(s_evp_pkey, s_ec_key) == 0)) {
				(void)SSL_inspection_fprintf(stderr, "EVP_PKEY_assign_EC_KEY failed !\n");
				EC_KEY_free(s_ec_key);
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
			s_ec_key = (EC_KEY *)(NULL); /* assigned to evp_pkey */
		}
		else { /* read */
			FILE *s_fp;

			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stdout, "Loading private key file ...\n");
			}

			s_fp = fopen(s_main_context->m_privatekey_pathname, "rb");
			if(SSL_inspection_unlikely(s_fp == ((FILE *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "privatekey file open failed !\n");
				X509_free(s_x509);
				EVP_PKEY_free(s_evp_pkey);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}

			/* Discard EVP_PKEY_new() placeholder; load key type-agnostically from file */
			EVP_PKEY_free(s_evp_pkey);
			s_evp_pkey = PEM_read_PrivateKey(s_fp, (EVP_PKEY **)(NULL), (pem_password_cb *)(NULL), (void *)(NULL));
			(void)fclose(s_fp);
			if(SSL_inspection_unlikely(s_evp_pkey == ((EVP_PKEY *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "PEM_read_PrivateKey failed !\n");
				X509_free(s_x509);
				SSL_CTX_free(s_ssl_ctx);
				return((SSL_CTX *)(NULL));
			}
		}
#endif

		/* N-1: X509_set_version returns int in OpenSSL 1.1+ */
		if(SSL_inspection_unlikely(X509_set_version(s_x509, 0x02) != 1)) {
			(void)SSL_inspection_fprintf(stderr, "X509_set_version failed !\n");
		}
		
		do {
			/* M-8: RFC 5280 requires a unique positive integer; use 128-bit random serial */
			unsigned char s_serial_buf[16];
			BIGNUM *s_serial_bn;
			/* M-3: check RAND_bytes — failure leaves buffer as stale stack data */
			if(SSL_inspection_unlikely(RAND_bytes(s_serial_buf, (int)sizeof(s_serial_buf)) != 1)) {
				(void)SSL_inspection_fprintf(stderr, "RAND_bytes failed !\n");
				(void)memset(s_serial_buf, 0, sizeof(s_serial_buf));
				s_serial_buf[sizeof(s_serial_buf) - 1] = 1u; /* fallback: serial=1, non-zero */
			}
			s_serial_buf[0] &= 0x7Fu; /* ensure positive (MSB=0) */
			s_serial_bn = BN_bin2bn(s_serial_buf, (int)sizeof(s_serial_buf), (BIGNUM *)(NULL));
			/* M-2: log BN_bin2bn failure — without this, cert gets serial=0 (RFC 5280 violation) */
			if(SSL_inspection_unlikely(s_serial_bn == ((BIGNUM *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "BN_bin2bn failed !\n");
			}
			else {
				ASN1_INTEGER *s_serial_asn1 = X509_get_serialNumber(s_x509);
				if(SSL_inspection_unlikely((s_serial_asn1 == ((ASN1_INTEGER *)(NULL))) ||
				   (BN_to_ASN1_INTEGER(s_serial_bn, s_serial_asn1) == ((ASN1_INTEGER *)(NULL))))) {
					(void)SSL_inspection_fprintf(stderr, "BN_to_ASN1_INTEGER failed !\n");
				}
				BN_free(s_serial_bn);
			}
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
			const char *s_cn;

			s_x509_subject_name = X509_get_subject_name(s_x509);
			s_x509_issuer_name = X509_get_issuer_name(s_x509);
			s_cn = ((s_hostname != ((const char *)(NULL))) && (s_hostname[0] != '\0')) ? s_hostname : "SSL Inspection Proxy";

			/* M-4: check each X509_NAME_add_entry_by_txt return value */
			/* 발급 대상 */
			if(SSL_inspection_unlikely(X509_NAME_add_entry_by_txt(s_x509_subject_name, "CN", MBSTRING_ASC, (const unsigned char *)s_cn, -1, -1, 0) != 1)) {
				(void)SSL_inspection_fprintf(stderr, "X509_NAME_add_entry_by_txt subject CN failed !\n");
			}
			if(SSL_inspection_unlikely(X509_NAME_add_entry_by_txt(s_x509_subject_name, "O", MBSTRING_ASC, (const unsigned char *)"SSL-Inspection", -1, -1, 0) != 1)) {
				(void)SSL_inspection_fprintf(stderr, "X509_NAME_add_entry_by_txt subject O failed !\n");
			}
			if(SSL_inspection_unlikely(X509_NAME_add_entry_by_txt(s_x509_subject_name, "OU", MBSTRING_ASC, (const unsigned char *)"Security", -1, -1, 0) != 1)) {
				(void)SSL_inspection_fprintf(stderr, "X509_NAME_add_entry_by_txt subject OU failed !\n");
			}

			/* 발급자 */
			if(SSL_inspection_unlikely(X509_NAME_add_entry_by_txt(s_x509_issuer_name, "CN", MBSTRING_ASC, (const unsigned char *)"SSL Inspection Proxy CA", -1, -1, 0) != 1)) {
				(void)SSL_inspection_fprintf(stderr, "X509_NAME_add_entry_by_txt issuer CN failed !\n");
			}
			if(SSL_inspection_unlikely(X509_NAME_add_entry_by_txt(s_x509_issuer_name, "O", MBSTRING_ASC, (const unsigned char *)"SSL-Inspection", -1, -1, 0) != 1)) {
				(void)SSL_inspection_fprintf(stderr, "X509_NAME_add_entry_by_txt issuer O failed !\n");
			}
			if(SSL_inspection_unlikely(X509_NAME_add_entry_by_txt(s_x509_issuer_name, "OU", MBSTRING_ASC, (const unsigned char *)"Security", -1, -1, 0) != 1)) {
				(void)SSL_inspection_fprintf(stderr, "X509_NAME_add_entry_by_txt issuer OU failed !\n");
			}
			/* N-3: X509_get_subject/issuer_name returns internal pointer; add_entry_by_txt
			 * already modifies it in-place. set_subject/issuer_name with the same pointer
			 * is a no-op (OpenSSL checks *xn == name). Removed. */
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

			s_asn1_time = X509_gmtime_adj(X509_get_notAfter(s_x509), (long)(60*60*24*3650)); /* M-10: 10 years */
			if(SSL_inspection_unlikely(s_asn1_time == ((ASN1_TIME *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "X509_gmtime_adj/X509_get_notAfter failed !\n");
			}
		}while(0);
#endif

		/* N-2: X509_set_pubkey returns int; failure means cert has no key — X509_sign will catch it */
		if(SSL_inspection_unlikely(X509_set_pubkey(s_x509, s_evp_pkey) != 1)) {
			(void)SSL_inspection_fprintf(stderr, "X509_set_pubkey failed !\n");
		}

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
			(void)SSL_inspection_fprintf(stderr, "X509_sign failed (hostname=\"%s\")\n", s_hostname ? s_hostname : "");
			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		s_check = SSL_CTX_use_certificate(s_ssl_ctx, s_x509);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_use_certificate failed (hostname=\"%s\")\n", s_hostname ? s_hostname : "");
			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		s_check = SSL_CTX_use_PrivateKey(s_ssl_ctx, s_evp_pkey);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_use_PrivateKey failed (hostname=\"%s\")\n", s_hostname ? s_hostname : "");
			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}
		
		s_check = SSL_CTX_check_private_key(s_ssl_ctx);
		if(SSL_inspection_unlikely(s_check <= 0)) {
			ERR_print_errors_fp(stderr);
			(void)SSL_inspection_fprintf(stderr, "SSL_CTX_check_private_key failed (hostname=\"%s\")\n", s_hostname ? s_hostname : "");
			X509_free(s_x509);
			EVP_PKEY_free(s_evp_pkey);
			SSL_CTX_free(s_ssl_ctx);
			return((SSL_CTX *)(NULL));
		}

		X509_free(s_x509);
		EVP_PKEY_free(s_evp_pkey);

l_ssl_ctx_cert_done:; /* reached by CA-fallback path via goto */
	}

	/* Server-side TLS session cache: clients resume sessions without a full handshake */
	SSL_CTX_set_session_cache_mode(s_ssl_ctx, SSL_SESS_CACHE_SERVER);
	SSL_CTX_set_timeout(s_ssl_ctx, 3600L); /* 1-hour session lifetime */

	return(s_ssl_ctx);
}

int SSL_inspection_set_nonblock_socket(int s_socket)
{
	int s_flags;

	if(SSL_inspection_unlikely(s_socket == (-1))) {
		errno = EINVAL;
		return(-1);
	}

	s_flags = fcntl(s_socket, F_GETFL, 0);
	if(SSL_inspection_unlikely(s_flags == (-1))) {
		return(-1);
	}
	if((s_flags & O_NONBLOCK) != O_NONBLOCK) {
		if(SSL_inspection_unlikely(fcntl(s_socket, F_SETFL, s_flags | O_NONBLOCK) == (-1))) {
			return(-1);
		}
		s_flags |= O_NONBLOCK;
	}

	return(s_flags);
}

int SSL_inspection_worker_set_epoll_interest(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_epoll_item_t *s_epoll_item, uint32_t s_events)
{
	struct epoll_event s_epoll_event;
	int s_fd;
	int s_op;
	int s_check;

	if(SSL_inspection_unlikely((s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) || (s_epoll_item == ((SSL_inspection_epoll_item_t *)(NULL))))) {
		errno = EINVAL;
		return(-1);
	}

	s_fd = (int)s_epoll_item->m_fd;
	if(s_fd < 0) {
		if(s_events == 0u) {
			s_epoll_item->m_events = 0u;
			s_epoll_item->m_is_registered = 0;
			return(0);
		}
		errno = EINVAL;
		return(-1);
	}

	if(s_events == 0u) {
		if(s_epoll_item->m_is_registered != 0) {
			s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_DEL, s_fd, (struct epoll_event *)(NULL));
			if((s_check == (-1)) && (errno != ENOENT) && (errno != EBADF)) {
				/* Unexpected DEL error: log and fall through to clear registration state.
				 * The fd will be closed by the caller, which removes it from epoll on Linux.
				 * Not clearing m_is_registered here would leave a stale pointer in epoll_item
				 * that could be dereferenced after the session is freed. */
				(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s %sepoll_ctl DEL unexpected error%s (fd=%d): %s\n",
					sg_ce_c, (s_epoll_item->m_session != ((SSL_inspection_session_t *)(NULL))) ? s_epoll_item->m_session->m_accept_socket : (-1), sg_ce_n,
					sg_ce_r, sg_ce_n,
					s_fd, strerror(errno));
			}
		}

		s_epoll_item->m_events = 0u;
		s_epoll_item->m_is_registered = 0;
		return(0);
	}

	if((s_epoll_item->m_is_registered != 0) && (s_epoll_item->m_events == s_events)) {
		return(0);
	}

	s_epoll_event = (struct epoll_event) {
		.events = s_events,
		.data.ptr = (void *)s_epoll_item,
	};
	s_op = (s_epoll_item->m_is_registered != 0) ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;

	s_check = epoll_ctl(s_worker_context->m_epoll_fd, s_op, s_fd, (struct epoll_event *)(&s_epoll_event));
	if(SSL_inspection_unlikely(s_check != 0)) {
		if((s_op == EPOLL_CTL_ADD) && (errno == EEXIST)) {
			s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_MOD, s_fd, (struct epoll_event *)(&s_epoll_event));
		}
		else if((s_op == EPOLL_CTL_MOD) && (errno == ENOENT)) {
			s_check = epoll_ctl(s_worker_context->m_epoll_fd, EPOLL_CTL_ADD, s_fd, (struct epoll_event *)(&s_epoll_event));
		}
	}
	if(SSL_inspection_unlikely(s_check != 0)) {
		return(-1);
	}

	s_epoll_item->m_events = s_events;
	s_epoll_item->m_is_registered = 1;

	return(0);
}

void SSL_inspection_worker_queue_job(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session)
{
	if((s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) || (s_session == ((SSL_inspection_session_t *)(NULL)))) {
		return;
	}

	if((s_session->m_job_flags & def_SSL_inspection_session_job_flag_enqueued) != def_SSL_inspection_session_job_flag_none) {
		return;
	}

	s_session->m_job_next = (SSL_inspection_session_t *)(NULL);
	s_session->m_job_flags |= def_SSL_inspection_session_job_flag_enqueued;

	if(s_worker_context->m_job_queue_tail == ((SSL_inspection_session_t *)(NULL))) {
		s_worker_context->m_job_queue_head = s_worker_context->m_job_queue_tail = s_session;
	}
	else {
		s_worker_context->m_job_queue_tail->m_job_next = s_session;
		s_worker_context->m_job_queue_tail = s_session;
	}
}

SSL_inspection_session_t *SSL_inspection_worker_pop_job(SSL_inspection_worker_context_t *s_worker_context)
{
	SSL_inspection_session_t *s_session;

	if(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) {
		return((SSL_inspection_session_t *)(NULL));
	}

	s_session = s_worker_context->m_job_queue_head;
	if(s_session == ((SSL_inspection_session_t *)(NULL))) {
		return((SSL_inspection_session_t *)(NULL));
	}

	s_worker_context->m_job_queue_head = s_session->m_job_next;
	if(s_worker_context->m_job_queue_head == ((SSL_inspection_session_t *)(NULL))) {
		s_worker_context->m_job_queue_tail = (SSL_inspection_session_t *)(NULL);
	}

	s_session->m_job_next = (SSL_inspection_session_t *)(NULL);
	s_session->m_job_flags &= (~def_SSL_inspection_session_job_flag_enqueued);

	return(s_session);
}

int SSL_inspection_worker_unlink_session(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session)
{
	if((s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) || (s_session == ((SSL_inspection_session_t *)(NULL)))) {
		errno = EINVAL;
		return(-1);
	}

	if(s_session->m_prev != ((SSL_inspection_session_t *)(NULL))) {
		s_session->m_prev->m_next = s_session->m_next;
	}
	else {
		s_worker_context->m_session_queue_head = s_session->m_next;
	}
	if(s_session->m_next != ((SSL_inspection_session_t *)(NULL))) {
		s_session->m_next->m_prev = s_session->m_prev;
	}
	else {
		s_worker_context->m_session_queue_tail = s_session->m_prev;
	}
	s_session->m_next = (SSL_inspection_session_t *)(NULL);
	s_session->m_prev = (SSL_inspection_session_t *)(NULL);
	if(s_worker_context->m_session_queue_count > ((size_t)0u)) {
		--s_worker_context->m_session_queue_count;
	}
	return(0);
}

void SSL_inspection_worker_release_session_resources(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session)
{
	(void)s_worker_context;

	if(s_session == ((SSL_inspection_session_t *)(NULL))) {
		return;
	}

	SSL_inspection_session_clear_async_wait(s_session, (SSL_inspection_async_wait_t *)(&s_session->m_accept_async_wait));
	SSL_inspection_session_clear_async_wait(s_session, (SSL_inspection_async_wait_t *)(&s_session->m_connect_async_wait));

	if(s_session->m_worker_context != ((SSL_inspection_worker_context_t *)(NULL))) {
		(void)SSL_inspection_worker_set_epoll_interest(s_session->m_worker_context, (SSL_inspection_epoll_item_t *)(&s_session->m_accept_epoll_item), 0u);
		(void)SSL_inspection_worker_set_epoll_interest(s_session->m_worker_context, (SSL_inspection_epoll_item_t *)(&s_session->m_connect_epoll_item), 0u);
	}
}

void SSL_inspection_trace_transfer(SSL_inspection_main_context_t *s_main_context, int s_accept_fd, const char *s_title, int s_fd, unsigned long long s_transferred, const void *s_buffer, size_t s_size)
{
	char *s_ascii;

	if((s_main_context == ((SSL_inspection_main_context_t *)(NULL))) || (s_title == ((const char *)(NULL))) || (s_buffer == ((const void *)(NULL))) || (s_size <= ((size_t)0u))) {
		return;
	}

	{
		const char *s_fd_label = (s_fd == s_accept_fd) ? "C-fd" : "S-fd";
		const char *s_fd_color = (s_fd == s_accept_fd) ? sg_co_c : sg_co_y;

		if(s_main_context->m_is_verbose >= 4) {
			(void)SSL_inspection_fprintf(stdout, "%s[C-fd=%d]%s %s (%s%s=%d%s) %llu + %lu bytes\n", sg_co_c, s_accept_fd, sg_co_n, s_title, s_fd_color, s_fd_label, s_fd, sg_co_n, s_transferred, (unsigned long)s_size);
			(void)SSL_inspection_hexdump("  ", s_buffer, s_size);
			return;
		}

		if(s_main_context->m_is_verbose >= 3) {
			s_ascii = (char *)malloc(s_size + ((size_t)1u));
			if(s_ascii != ((char *)(NULL))) {
				(void)SSL_inspection_convert_printable_ascii((void *)s_ascii, s_buffer, s_size);
				s_ascii[s_size] = '\0';
				(void)SSL_inspection_fprintf(stdout, "%s[C-fd=%d]%s %s (%s%s=%d%s) {\n%.*s} %llu + %lu bytes\n", sg_co_c, s_accept_fd, sg_co_n, s_title, s_fd_color, s_fd_label, s_fd, sg_co_n, (int)s_size, s_ascii, s_transferred, (unsigned long)s_size);
				free((void *)s_ascii);
				return;
			}
		}

		if(s_main_context->m_is_verbose >= 2) {
			(void)SSL_inspection_fprintf(stdout, "%s[C-fd=%d]%s %s (%s%s=%d%s) %llu + %lu bytes\n", sg_co_c, s_accept_fd, sg_co_n, s_title, s_fd_color, s_fd_label, s_fd, sg_co_n, s_transferred, (unsigned long)s_size);
			(void)SSL_inspection_hexdump("  ", s_buffer, (s_size >= ((size_t)16u)) ? ((size_t)16u) : s_size);
			return;
		}
	}

}

void SSL_inspection_session_clear_async_wait(SSL_inspection_session_t *s_session, SSL_inspection_async_wait_t *s_async_wait)
{
	size_t s_index;

	if((s_session == ((SSL_inspection_session_t *)(NULL))) || (s_async_wait == ((SSL_inspection_async_wait_t *)(NULL)))) {
		return;
	}

	if(s_async_wait->m_epoll_items != ((SSL_inspection_epoll_item_t *)(NULL))) {
		for(s_index = (size_t)0u;s_index < s_async_wait->m_count;s_index++) {
			if(s_session->m_worker_context != ((SSL_inspection_worker_context_t *)(NULL))) {
				(void)SSL_inspection_worker_set_epoll_interest(
					s_session->m_worker_context,
					(SSL_inspection_epoll_item_t *)(&s_async_wait->m_epoll_items[s_index]),
					0u
				);
			}
		}

		if(s_async_wait->m_epoll_items != s_async_wait->m_inline_epoll_items) {
			free((void *)s_async_wait->m_epoll_items);
		}
		s_async_wait->m_epoll_items = (SSL_inspection_epoll_item_t *)(NULL);
	}
	if(s_async_wait->m_fds != ((OSSL_ASYNC_FD *)(NULL))) {
		if(s_async_wait->m_fds != s_async_wait->m_inline_fds) {
			free((void *)s_async_wait->m_fds);
		}
		s_async_wait->m_fds = (OSSL_ASYNC_FD *)(NULL);
	}
	s_async_wait->m_count = (size_t)0u;
}

int SSL_inspection_session_refresh_async_wait(SSL_inspection_session_t *s_session, SSL *s_ssl, SSL_inspection_async_wait_t *s_async_wait, unsigned int s_epoll_item_type)
{
	SSL_inspection_epoll_item_t *s_epoll_items;
	OSSL_ASYNC_FD *s_fds;
	size_t s_count;
	size_t s_index;

	if((s_session == ((SSL_inspection_session_t *)(NULL))) || (s_async_wait == ((SSL_inspection_async_wait_t *)(NULL)))) {
		errno = EINVAL;
		return(-1);
	}

	SSL_inspection_session_clear_async_wait(s_session, s_async_wait);
	if(s_ssl == ((SSL *)(NULL))) {
		return(0);
	}

	s_count = (size_t)0u;
	if(SSL_inspection_unlikely(SSL_get_all_async_fds(s_ssl, (OSSL_ASYNC_FD *)(NULL), (size_t *)(&s_count)) == 0)) {
		return(0);
	}
	if(s_count == ((size_t)0u)) {
		return(0);
	}

	if(s_count <= (size_t)def_SSL_inspection_async_wait_inline_capacity) {
		/* use inline scratch to avoid heap allocation for the common case */
		(void)memset(s_async_wait->m_inline_epoll_items, 0, s_count * sizeof(SSL_inspection_epoll_item_t));
		(void)memset(s_async_wait->m_inline_fds, 0, s_count * sizeof(OSSL_ASYNC_FD));
		s_fds = s_async_wait->m_inline_fds;
		s_epoll_items = s_async_wait->m_inline_epoll_items;
	}
	else {
		s_fds = (OSSL_ASYNC_FD *)calloc(s_count, sizeof(OSSL_ASYNC_FD));
		s_epoll_items = (SSL_inspection_epoll_item_t *)calloc(s_count, sizeof(SSL_inspection_epoll_item_t));
		if((s_fds == ((OSSL_ASYNC_FD *)(NULL))) || (s_epoll_items == ((SSL_inspection_epoll_item_t *)(NULL)))) {
			free((void *)s_fds);
			free((void *)s_epoll_items);
			errno = ENOMEM;
			return(-1);
		}
	}

	if(SSL_inspection_unlikely(SSL_get_all_async_fds(s_ssl, (OSSL_ASYNC_FD *)s_fds, (size_t *)(&s_count)) == 0)) {
		if(s_fds != s_async_wait->m_inline_fds) {
			free((void *)s_fds);
			free((void *)s_epoll_items);
		}
		errno = EIO;
		return(-1);
	}

	s_async_wait->m_fds = s_fds;
	s_async_wait->m_epoll_items = s_epoll_items;
	s_async_wait->m_count = s_count;

	for(s_index = (size_t)0u;s_index < s_count;s_index++) {
		s_async_wait->m_epoll_items[s_index] = (SSL_inspection_epoll_item_t) {
			.m_worker_context = s_session->m_worker_context,
			.m_session = s_session,
			.m_fd = s_fds[s_index],
			.m_events = 0u,
			.m_type = s_epoll_item_type,
			.m_is_registered = 0,
		};

		if(SSL_inspection_unlikely(SSL_inspection_worker_set_epoll_interest(
			s_session->m_worker_context,
			(SSL_inspection_epoll_item_t *)(&s_async_wait->m_epoll_items[s_index]),
			def_SSL_inspection_epoll_session_base_events | (uint32_t)EPOLLIN
		) != 0)) {
			SSL_inspection_session_clear_async_wait(s_session, s_async_wait);
			return(-1);
		}
	}

	return(0);
}

int SSL_inspection_session_ensure_ssl(SSL_inspection_session_t *s_session, int s_is_accept_side)
{
	SSL *s_ssl;
	SSL_CTX *s_ssl_ctx;
	int s_socket;
	int s_check;

	if(s_session == ((SSL_inspection_session_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	if(s_is_accept_side != 0) {
		if(s_session->m_accept_ssl != ((SSL *)(NULL))) {
			return(0);
		}
		s_ssl_ctx = (s_session->m_accept_ssl_ctx != ((SSL_CTX *)(NULL)))
			? s_session->m_accept_ssl_ctx
			: s_session->m_main_context->m_ssl_ctx;
		s_socket = s_session->m_accept_socket;
	}
	else {
		if(s_session->m_connect_ssl != ((SSL *)(NULL))) {
			return(0);
		}
		s_ssl_ctx = s_session->m_connect_ssl_ctx;
		s_socket = s_session->m_connect_socket;
	}

	if((s_ssl_ctx == ((SSL_CTX *)(NULL))) || (s_socket == (-1))) {
		errno = EINVAL;
		return(-1);
	}

	s_ssl = SSL_new(s_ssl_ctx);
	if(SSL_inspection_unlikely(s_ssl == ((SSL *)(NULL)))) {
		ERR_print_errors_fp(stderr);
		errno = ENOMEM;
		return(-1);
	}

	if(s_is_accept_side == 0) {
		SSL_set_connect_state(s_ssl);
		if(s_session->m_sni_hostname[0] != '\0') {
			if(SSL_inspection_unlikely(SSL_set_tlsext_host_name(s_ssl, s_session->m_sni_hostname) != 1)) {
				(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s %sSSL_set_tlsext_host_name failed%s (sni=\"%s%s%s\")\n",
					sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n, sg_ce_y, s_session->m_sni_hostname, sg_ce_n);
			}
		}
	}
	else {
		SSL_set_accept_state(s_ssl);
	}
	s_check = SSL_set_fd(s_ssl, s_socket);
	if(SSL_inspection_unlikely(s_check <= 0)) {
		ERR_print_errors_fp(stderr);
		SSL_free(s_ssl);
		errno = EINVAL;
		return(-1);
	}

	if(s_is_accept_side != 0) {
		s_session->m_accept_ssl = s_ssl;
	}
	else {
		s_session->m_connect_ssl = s_ssl;
	}

	return(1);
}

/* connect 완료 여부만 확인 — 상태(m_state) 변경 없음.
 * drive_connect()와 auto_detect 핸들러가 공유하는 헬퍼. */
static int SSL_inspection_session_poll_connect(SSL_inspection_session_t *s_session)
{
	int s_sockerr;
	socklen_t s_sockerr_size;
	int s_check;

	if((s_session->m_flags & def_SSL_inspection_session_flag_connected) != 0)
		return(1); /* 이미 완료 */

	if((s_session->m_connect_ready_events & (EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) == 0u)
		return(0); /* 이벤트 없음 */

	s_sockerr = 0;
	s_sockerr_size = (socklen_t)sizeof(s_sockerr);
	s_check = getsockopt(s_session->m_connect_socket, SOL_SOCKET, SO_ERROR,
	                     (void *)(&s_sockerr), (socklen_t *)(&s_sockerr_size));
	if(SSL_inspection_unlikely(s_check == (-1))) return(-1);
	if(s_sockerr != 0) { errno = s_sockerr; return(-1); }

	s_session->m_flags |= def_SSL_inspection_session_flag_connected;
	return(1);
}

int SSL_inspection_session_drive_connect(SSL_inspection_session_t *s_session)
{
	SSL_inspection_main_context_t *s_main_context;
	int s_check;

	if(s_session == ((SSL_inspection_session_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	if((s_session->m_flags & def_SSL_inspection_session_flag_connected) != def_SSL_inspection_session_flag_none) {
		return(1);
	}
	if(s_session->m_state != def_SSL_inspection_session_state_connecting) {
		return(0);
	}

	s_check = SSL_inspection_session_poll_connect(s_session);
	if(s_check != 1) return(s_check);

	s_main_context = s_session->m_main_context;
	s_session->m_state = (s_session->m_connect_ssl_ctx == ((SSL_CTX *)(NULL))) ? def_SSL_inspection_session_state_stream : def_SSL_inspection_session_state_connect_ssl_handshake;

	if(s_main_context->m_is_verbose >= 1) {
		char s_tuple[128];
		SSL_inspection_session_format_tuple(s_session, s_tuple, sizeof(s_tuple));
		(void)SSL_inspection_fprintf(stdout,
			"%s[C-fd=%d]%s %s %sconnected%s%s %s (%sS-fd=%d%s)\n",
			sg_co_c, s_session->m_accept_socket, sg_co_n,
			(s_session->m_connect_ssl_ctx == ((SSL_CTX *)(NULL))) ? "TCP" : "SSL",
			sg_co_g, sg_co_n,
			(s_main_context->m_use_tproxy != 0) ? "[tproxy]" : "",
			s_tuple,
			sg_co_y, s_session->m_connect_socket, sg_co_n
		);
	}

	return(1);
}

static void SSL_inspection_pkey_algo_str(EVP_PKEY *s_pkey, char *s_buf, size_t s_buf_size)
{
	int s_type;
	int s_bits;

	if(s_pkey == ((EVP_PKEY *)(NULL))) {
		(void)snprintf(s_buf, s_buf_size, "(none)");
		return;
	}

	s_type = EVP_PKEY_base_id(s_pkey);
	s_bits = EVP_PKEY_bits(s_pkey);

	if(s_type == EVP_PKEY_EC) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
		char s_curve[64];
		size_t s_curve_len = 0u;
		if(EVP_PKEY_get_group_name(s_pkey, s_curve, sizeof(s_curve), &s_curve_len) == 1) {
			(void)snprintf(s_buf, s_buf_size, "ECDSA/%s", s_curve);
		}
		else {
			(void)snprintf(s_buf, s_buf_size, "ECDSA/%dbits", s_bits);
		}
#else
		const char *s_curve = "(unknown)";
		EC_KEY *s_ec_key = EVP_PKEY_get0_EC_KEY(s_pkey);
		if(s_ec_key != ((EC_KEY *)(NULL))) {
			const EC_GROUP *s_group = EC_KEY_get0_group(s_ec_key);
			if(s_group != ((const EC_GROUP *)(NULL))) {
				const char *s_sn = OBJ_nid2sn(EC_GROUP_get_curve_name(s_group));
				if(s_sn != ((const char *)(NULL))) {
					s_curve = s_sn;
				}
			}
		}
		(void)snprintf(s_buf, s_buf_size, "ECDSA/%s", s_curve);
#endif
	}
	else if(s_type == EVP_PKEY_RSA) {
		(void)snprintf(s_buf, s_buf_size, "RSA/%d", s_bits);
	}
	else {
		const char *s_name = OBJ_nid2sn(s_type);
		(void)snprintf(s_buf, s_buf_size, "%s/%d", (s_name != ((const char *)(NULL))) ? s_name : "?", s_bits);
	}
}

int SSL_inspection_session_drive_handshake(SSL_inspection_session_t *s_session, int s_is_accept_side)
{
	SSL_inspection_main_context_t *s_main_context;
	SSL_inspection_async_wait_t *s_async_wait;
	SSL *s_ssl;
	unsigned int s_done_flag;
	int s_state_done;
	int s_epoll_item_type;
	int s_check;
	int s_ssl_error;

	if(s_session == ((SSL_inspection_session_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	s_main_context = s_session->m_main_context;
	if(s_is_accept_side != 0) {
		s_async_wait = (SSL_inspection_async_wait_t *)(&s_session->m_accept_async_wait);
		s_ssl = s_session->m_accept_ssl;
		s_done_flag = def_SSL_inspection_session_flag_ssl_accepted;
		s_state_done = def_SSL_inspection_session_state_stream;
		s_epoll_item_type = def_SSL_inspection_epoll_item_type_accept_async;
	}
	else {
		s_async_wait = (SSL_inspection_async_wait_t *)(&s_session->m_connect_async_wait);
		s_ssl = s_session->m_connect_ssl;
		s_done_flag = def_SSL_inspection_session_flag_ssl_connected;
		/* accept-side SSL handshake가 필요한 경우: SSL inspection 모드이면서 TCP relay가 아닌 세션 */
		s_state_done = ((s_main_context->m_ssl_ctx == ((SSL_CTX *)(NULL))) ||
		                ((s_session->m_flags & def_SSL_inspection_session_flag_tcp_relay) != 0))
		    ? def_SSL_inspection_session_state_stream
		    : def_SSL_inspection_session_state_accept_ssl_handshake;
		s_epoll_item_type = def_SSL_inspection_epoll_item_type_connect_async;
	}

	s_check = SSL_inspection_session_ensure_ssl(s_session, s_is_accept_side);
	if(SSL_inspection_unlikely(s_check == (-1))) {
		return(-1);
	}
	if(s_is_accept_side != 0) {
		s_ssl = s_session->m_accept_ssl;
	}
	else {
		s_ssl = s_session->m_connect_ssl;
	}

	if(s_main_context->m_use_serialize_lock != 0) {
		if(SSL_inspection_unlikely(pthread_mutex_lock((pthread_mutex_t *)(&s_main_context->m_serialize_lock)) != 0)) {
			(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s serialize: pthread_mutex_lock (%s)\n", sg_ce_c, s_session->m_accept_socket, sg_ce_n, (s_is_accept_side != 0) ? "accept" : "connect");
		}
	}
	s_check = SSL_do_handshake(s_ssl);
	if(s_main_context->m_use_serialize_lock != 0) {
		if(SSL_inspection_unlikely(pthread_mutex_unlock((pthread_mutex_t *)(&s_main_context->m_serialize_lock)) != 0)) {
			(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s serialize: pthread_mutex_unlock (%s)\n", sg_ce_c, s_session->m_accept_socket, sg_ce_n, (s_is_accept_side != 0) ? "accept" : "connect");
		}
	}
	if(s_check == 1) {
		SSL_inspection_session_clear_async_wait(s_session, s_async_wait);
		s_session->m_flags |= s_done_flag;
		if(s_main_context->m_is_verbose >= 1) {
			const SSL_CIPHER *s_cipher = SSL_get_current_cipher(s_ssl);
			const char *s_tls_version = SSL_get_version(s_ssl);
			const char *s_cipher_name = (s_cipher != ((const SSL_CIPHER *)(NULL))) ? SSL_CIPHER_get_name(s_cipher) : "(none)";
			int s_cipher_bits = (s_cipher != ((const SSL_CIPHER *)(NULL))) ? SSL_CIPHER_get_bits(s_cipher, (int *)(NULL)) : 0;

			/* accept side: our private key type; connect side: peer cert public key type */
			char s_asym_algo[128];
			{
				EVP_PKEY *s_pkey;
				EVP_PKEY *s_pkey_to_free = (EVP_PKEY *)(NULL);

				if(s_is_accept_side != 0) {
					s_pkey = SSL_get_privatekey(s_ssl); /* borrowed */
				}
				else {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
					X509 *s_peer_cert = SSL_get1_peer_certificate(s_ssl);
#else
					X509 *s_peer_cert = SSL_get_peer_certificate(s_ssl);
#endif
					if(s_peer_cert != ((X509 *)(NULL))) {
						s_pkey = s_pkey_to_free = X509_get_pubkey(s_peer_cert);
						X509_free(s_peer_cert);
					}
					else {
						s_pkey = (EVP_PKEY *)(NULL);
					}
				}

				SSL_inspection_pkey_algo_str(s_pkey, s_asym_algo, sizeof(s_asym_algo));

				if(s_pkey_to_free != ((EVP_PKEY *)(NULL))) {
					EVP_PKEY_free(s_pkey_to_free);
				}
			}

			{
				char s_tuple[128];
				SSL_inspection_session_format_tuple(s_session, s_tuple, sizeof(s_tuple));
				if(s_is_accept_side != 0) {
					(void)SSL_inspection_fprintf(stdout,
						"%s[C-fd=%d]%s %sSSL Accepted%s %s sni=\"%s%s%s\", %s, %s, %dbits, asym=%s\n",
						sg_co_c, s_session->m_accept_socket, sg_co_n,
						sg_co_m, sg_co_n,
						s_tuple,
						sg_co_y, (s_session->m_sni_hostname[0] != '\0') ? s_session->m_sni_hostname : "(none)", sg_co_n,
						s_tls_version,
						s_cipher_name,
						s_cipher_bits,
						s_asym_algo
					);
				}
				else {
					(void)SSL_inspection_fprintf(stdout,
						"%s[C-fd=%d]%s %sSSL Connected%s %s sni=\"%s%s%s\", %s, %s, %dbits, asym=%s (%sS-fd=%d%s)\n",
						sg_co_c, s_session->m_accept_socket, sg_co_n,
						sg_co_m, sg_co_n,
						s_tuple,
						sg_co_y, (s_session->m_sni_hostname[0] != '\0') ? s_session->m_sni_hostname : "(none)", sg_co_n,
						s_tls_version,
						s_cipher_name,
						s_cipher_bits,
						s_asym_algo,
						sg_co_y, s_session->m_connect_socket, sg_co_n
					);
				}
			}
		}
		s_session->m_state = (unsigned int)s_state_done;
		return(1);
	}
	if(s_check == 0) {
		errno = ECONNRESET;
		return(-1);
	}

	s_ssl_error = SSL_get_error(s_ssl, s_check);
	if((s_ssl_error == SSL_ERROR_WANT_READ) || (s_ssl_error == SSL_ERROR_WANT_WRITE)) {
		SSL_inspection_session_clear_async_wait(s_session, s_async_wait);
		errno = EAGAIN;
		return(0);
	}
	if((s_ssl_error == SSL_ERROR_WANT_ASYNC) || (s_ssl_error == SSL_ERROR_WANT_ASYNC_JOB)) {
		if(SSL_inspection_unlikely(SSL_inspection_session_refresh_async_wait(s_session, s_ssl, s_async_wait, (unsigned int)s_epoll_item_type) != 0)) {
			return(-1);
		}
		errno = EAGAIN;
		return(0);
	}
	if(s_ssl_error == SSL_ERROR_ZERO_RETURN) {
		errno = ECONNRESET;
		return(-1);
	}
	if((s_ssl_error == SSL_ERROR_SYSCALL) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))) {
		errno = EAGAIN;
		return(0);
	}

	while((s_check = (int)ERR_get_error()) != 0) {
		(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s %sSSL_do_handshake failed%s (%s, \"%s\")\n", sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n, (s_is_accept_side != 0) ? "accept" : "connect", ERR_error_string((unsigned long)s_check, (char *)(NULL)));
	}
	errno = EIO;

	return(-1);
}

ssize_t SSL_inspection_session_recv_nonblock(SSL_inspection_session_t *s_session, int s_is_accept_side, void *s_buffer, size_t s_buffer_size)
{
	SSL_inspection_async_wait_t *s_async_wait;
	SSL *s_ssl;
	int s_socket;
	int s_check;
	int s_ssl_error;
	ssize_t s_result;

	if((s_session == ((SSL_inspection_session_t *)(NULL))) || (s_buffer == ((void *)(NULL))) || (s_buffer_size <= ((size_t)0u))) {
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	if(s_is_accept_side != 0) {
		s_async_wait = (SSL_inspection_async_wait_t *)(&s_session->m_accept_async_wait);
		s_ssl = s_session->m_accept_ssl;
		s_socket = s_session->m_accept_socket;
	}
	else {
		s_async_wait = (SSL_inspection_async_wait_t *)(&s_session->m_connect_async_wait);
		s_ssl = s_session->m_connect_ssl;
		s_socket = s_session->m_connect_socket;
	}

	if(s_ssl == ((SSL *)(NULL))) {
		s_result = recv(s_socket, s_buffer, s_buffer_size, def_SSL_inspection_recv_flags);
		if((s_result == ((ssize_t)(-1))) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))) {
			errno = EAGAIN;
		}
		return(s_result);
	}

	s_check = SSL_read(s_ssl, s_buffer, (int)s_buffer_size);
	if(s_check > 0) {
		SSL_inspection_session_clear_async_wait(s_session, s_async_wait);
		return((ssize_t)s_check);
	}
	if(s_check == 0) {
		s_ssl_error = SSL_get_error(s_ssl, 0);
		if(s_ssl_error != SSL_ERROR_ZERO_RETURN && s_ssl_error != SSL_ERROR_NONE) {
			(void)SSL_inspection_fprintf(stderr,
				"%s[C-fd=%d]%s %sSSL_read=0 non-clean close%s: SSL_get_error=%d (%s, fd=%d)\n",
				sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n, s_ssl_error,
				(s_is_accept_side != 0) ? "accept" : "connect", s_socket);
		}
		return((ssize_t)0);
	}

	s_ssl_error = SSL_get_error(s_ssl, s_check);
	if((s_ssl_error == SSL_ERROR_WANT_READ) || (s_ssl_error == SSL_ERROR_WANT_WRITE)) {
		SSL_inspection_session_clear_async_wait(s_session, s_async_wait);
		errno = EAGAIN;
		return((ssize_t)(-1));
	}
	if((s_ssl_error == SSL_ERROR_WANT_ASYNC) || (s_ssl_error == SSL_ERROR_WANT_ASYNC_JOB)) {
		if(SSL_inspection_unlikely(SSL_inspection_session_refresh_async_wait(
			s_session,
			s_ssl,
			s_async_wait,
			(unsigned int)((s_is_accept_side != 0) ? def_SSL_inspection_epoll_item_type_accept_async : def_SSL_inspection_epoll_item_type_connect_async)
		) != 0)) {
			return((ssize_t)(-1));
		}
		errno = EAGAIN;
		return((ssize_t)(-1));
	}
	if(s_ssl_error == SSL_ERROR_ZERO_RETURN) {
		return((ssize_t)0);
	}
	if((s_ssl_error == SSL_ERROR_SYSCALL) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))) {
		errno = EAGAIN;
		return((ssize_t)(-1));
	}

	while((s_check = (int)ERR_get_error()) != 0) {
		(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s %sSSL_recv failed%s (%s, \"%s\")\n", sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n, (s_is_accept_side != 0) ? "accept" : "connect", ERR_error_string((unsigned long)s_check, (char *)(NULL)));
	}
	errno = EIO;

	return((ssize_t)(-1));
}

ssize_t SSL_inspection_session_send_nonblock(SSL_inspection_session_t *s_session, int s_is_accept_side, const void *s_buffer, size_t s_buffer_size)
{
	SSL_inspection_async_wait_t *s_async_wait;
	SSL *s_ssl;
	int s_socket;
	int s_check;
	int s_ssl_error;
	ssize_t s_result;

	if((s_session == ((SSL_inspection_session_t *)(NULL))) || (s_buffer == ((const void *)(NULL))) || (s_buffer_size <= ((size_t)0u))) {
		errno = EINVAL;
		return((ssize_t)(-1));
	}

	if(s_is_accept_side != 0) {
		s_async_wait = (SSL_inspection_async_wait_t *)(&s_session->m_accept_async_wait);
		s_ssl = s_session->m_accept_ssl;
		s_socket = s_session->m_accept_socket;
	}
	else {
		s_async_wait = (SSL_inspection_async_wait_t *)(&s_session->m_connect_async_wait);
		s_ssl = s_session->m_connect_ssl;
		s_socket = s_session->m_connect_socket;
	}

	if(s_ssl == ((SSL *)(NULL))) {
		s_result = send(s_socket, s_buffer, s_buffer_size, def_SSL_inspection_send_flags);
		if((s_result == ((ssize_t)(-1))) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))) {
			errno = EAGAIN;
		}
		else if(s_result == ((ssize_t)0)) {
			errno = EAGAIN;
			s_result = (ssize_t)(-1);
		}
		return(s_result);
	}

	s_check = SSL_write(s_ssl, s_buffer, (int)s_buffer_size);
	if(s_check > 0) {
		SSL_inspection_session_clear_async_wait(s_session, s_async_wait);
		return((ssize_t)s_check);
	}

	s_ssl_error = SSL_get_error(s_ssl, s_check);
	if((s_ssl_error == SSL_ERROR_WANT_READ) || (s_ssl_error == SSL_ERROR_WANT_WRITE)) {
		SSL_inspection_session_clear_async_wait(s_session, s_async_wait);
		errno = EAGAIN;
		return((ssize_t)(-1));
	}
	if((s_ssl_error == SSL_ERROR_WANT_ASYNC) || (s_ssl_error == SSL_ERROR_WANT_ASYNC_JOB)) {
		if(SSL_inspection_unlikely(SSL_inspection_session_refresh_async_wait(
			s_session,
			s_ssl,
			s_async_wait,
			(unsigned int)((s_is_accept_side != 0) ? def_SSL_inspection_epoll_item_type_accept_async : def_SSL_inspection_epoll_item_type_connect_async)
		) != 0)) {
			return((ssize_t)(-1));
		}
		errno = EAGAIN;
		return((ssize_t)(-1));
	}
	if(s_ssl_error == SSL_ERROR_ZERO_RETURN) {
		errno = ECONNRESET;
		return((ssize_t)(-1));
	}
	if((s_ssl_error == SSL_ERROR_SYSCALL) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))) {
		errno = EAGAIN;
		return((ssize_t)(-1));
	}

	errno = EIO;
	return((ssize_t)(-1));
}

int SSL_inspection_session_flush_buffer(SSL_inspection_session_t *s_session, int s_to_accept_side)
{
	SSL_inspection_main_context_t *s_main_context;
	void *s_buffer;
	size_t *s_offset_ptr;
	size_t *s_size_ptr;
	ssize_t s_send_bytes;

	if(s_session == ((SSL_inspection_session_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	s_main_context = s_session->m_main_context;
	if(s_to_accept_side != 0) {
		s_buffer = s_session->m_dup_buffer;
		s_offset_ptr = (size_t *)(&s_session->m_backward_pending_offset);
		s_size_ptr = (size_t *)(&s_session->m_backward_pending_size);
	}
	else {
		s_buffer = s_session->m_buffer;
		s_offset_ptr = (size_t *)(&s_session->m_forward_pending_offset);
		s_size_ptr = (size_t *)(&s_session->m_forward_pending_size);
	}

	if(*s_size_ptr <= ((size_t)0u)) {
		return(0);
	}

	/* M-1: loop until all pending bytes are sent or socket blocks */
	while(*s_size_ptr > (size_t)0u) {
		s_send_bytes = SSL_inspection_session_send_nonblock(
			s_session,
			s_to_accept_side,
			(const void *)(((const uint8_t *)s_buffer) + *s_offset_ptr),
			*s_size_ptr
		);
		if(SSL_inspection_unlikely(s_send_bytes == ((ssize_t)(-1)))) {
			if(errno == EAGAIN) {
				return(0); /* socket full; remaining bytes stay in buffer */
			}

			(void)SSL_inspection_fprintf(
				stderr,
				"%s[C-fd=%d]%s %ssend failed%s (%s, fd=%d, %s): %s\n",
				sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n,
				(s_to_accept_side != 0) ? "accept" : "connect",
				(s_to_accept_side != 0) ? s_session->m_accept_socket : s_session->m_connect_socket,
				((s_to_accept_side != 0) ? s_session->m_accept_ssl : s_session->m_connect_ssl) == ((SSL *)(NULL)) ? "TCP" : "SSL",
				strerror(errno)
			);

			return(-1);
		}

		SSL_inspection_trace_transfer(
			s_main_context,
			s_session->m_accept_socket,
			(s_to_accept_side != 0) ? "To accept tx" : "To connect tx",
			(s_to_accept_side != 0) ? s_session->m_accept_socket : s_session->m_connect_socket,
			(s_to_accept_side != 0) ? s_session->m_backward_transfer_size : s_session->m_forward_transfer_size,
			(const void *)(((const uint8_t *)s_buffer) + *s_offset_ptr),
			(size_t)s_send_bytes
		);

		*s_offset_ptr += (size_t)s_send_bytes;
		*s_size_ptr -= (size_t)s_send_bytes;
		if(*s_size_ptr == ((size_t)0u)) {
			*s_offset_ptr = (size_t)0u;
		}

		if(s_to_accept_side != 0) {
			s_session->m_backward_transfer_size += (unsigned long long)s_send_bytes;
			s_session->m_backward_transfer_count++;
			if(s_session->m_worker_context != ((SSL_inspection_worker_context_t *)(NULL))) {
				s_session->m_worker_context->m_backward_transfer_size += (unsigned long long)s_send_bytes;
			}
		}
		else {
			s_session->m_forward_transfer_size += (unsigned long long)s_send_bytes;
			s_session->m_forward_transfer_count++;
			if(s_session->m_worker_context != ((SSL_inspection_worker_context_t *)(NULL))) {
				s_session->m_worker_context->m_forward_transfer_size += (unsigned long long)s_send_bytes;
			}
		}
	}

	return(1);
}

int SSL_inspection_session_fill_buffer(SSL_inspection_session_t *s_session, int s_from_accept_side)
{
	SSL_inspection_main_context_t *s_main_context;
	void *s_buffer;
	size_t *s_offset_ptr;
	size_t *s_size_ptr;
	ssize_t s_recv_bytes;

	if(s_session == ((SSL_inspection_session_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	s_main_context = s_session->m_main_context;
	if(s_from_accept_side != 0) {
		s_buffer = s_session->m_buffer;
		s_offset_ptr = (size_t *)(&s_session->m_forward_pending_offset);
		s_size_ptr = (size_t *)(&s_session->m_forward_pending_size);
	}
	else {
		s_buffer = s_session->m_dup_buffer;
		s_offset_ptr = (size_t *)(&s_session->m_backward_pending_offset);
		s_size_ptr = (size_t *)(&s_session->m_backward_pending_size);
	}

	if(*s_size_ptr > ((size_t)0u)) {
		return(0);
	}

	s_recv_bytes = SSL_inspection_session_recv_nonblock(
		s_session,
		s_from_accept_side,
		s_buffer,
		s_session->m_buffer_size
	);
	if(SSL_inspection_unlikely(s_recv_bytes == ((ssize_t)(-1)))) {
		if(errno == EAGAIN) {
			return(0);
		}

		(void)SSL_inspection_fprintf(
			stderr,
			"%s[C-fd=%d]%s %srecv failed%s (%s, fd=%d, %s): %s\n",
			sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n,
			(s_from_accept_side != 0) ? "accept" : "connect",
			(s_from_accept_side != 0) ? s_session->m_accept_socket : s_session->m_connect_socket,
			((s_from_accept_side != 0) ? s_session->m_accept_ssl : s_session->m_connect_ssl) == ((SSL *)(NULL)) ? "TCP" : "SSL",
			strerror(errno)
		);

		return(-1);
	}
	if(s_recv_bytes == ((ssize_t)0)) {
		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(
				stderr,
				"%s[C-fd=%d]%s disconnected (%s, fd=%d, %s)\n",
				sg_ce_c, s_session->m_accept_socket, sg_ce_n,
				(s_from_accept_side != 0) ? "accept" : "connect",
				(s_from_accept_side != 0) ? s_session->m_accept_socket : s_session->m_connect_socket,
				((s_from_accept_side != 0) ? s_session->m_accept_ssl : s_session->m_connect_ssl) == ((SSL *)(NULL)) ? "TCP" : "SSL"
			);
		}

		/* M-2: flush both buffer directions before tearing down on FIN */
		/* N-3: log flush failure so silent data loss is visible in verbose mode */
		if(SSL_inspection_unlikely(SSL_inspection_session_flush_buffer(s_session, 0) == (-1))) {
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s %sflush forward buffer failed on FIN%s\n",
					sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n);
			}
		}
		if(SSL_inspection_unlikely(SSL_inspection_session_flush_buffer(s_session, 1) == (-1))) {
			if(s_main_context->m_is_verbose >= 1) {
				(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s %sflush backward buffer failed on FIN%s\n",
					sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n);
			}
		}

		errno = ECONNRESET;
		return(-1);
	}

	*s_offset_ptr = (size_t)0u;
	*s_size_ptr = (size_t)s_recv_bytes;

	SSL_inspection_trace_transfer(
		s_main_context,
		s_session->m_accept_socket,
		(s_from_accept_side != 0) ? "From accept rx" : "From connect rx",
		(s_from_accept_side != 0) ? s_session->m_accept_socket : s_session->m_connect_socket,
		(s_from_accept_side != 0) ? s_session->m_forward_transfer_size : s_session->m_backward_transfer_size,
		s_buffer,
		(size_t)s_recv_bytes
	);

	return(1);
}

int SSL_inspection_session_update_epoll(SSL_inspection_session_t *s_session)
{
	SSL_inspection_worker_context_t *s_worker_context;
	uint32_t s_accept_events;
	uint32_t s_connect_events;

	if(s_session == ((SSL_inspection_session_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	s_worker_context = s_session->m_worker_context;
	if(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	s_accept_events = 0u;
	if(s_session->m_accept_socket != (-1)) {
		s_accept_events = def_SSL_inspection_epoll_session_base_events;
		if(s_session->m_state == def_SSL_inspection_session_state_auto_detect) {
			/* 감지 미결 시에만 EPOLLIN 등록: 감지 완료 후 connect 대기 중 level-triggered busy-loop 방지 */
			if(s_session->m_auto_detect_result == def_SSL_inspection_auto_detect_unknown) {
				s_accept_events |= (uint32_t)EPOLLIN;
			}
		}
		else if((s_session->m_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) &&
		        ((s_session->m_flags & def_SSL_inspection_session_flag_tcp_relay) == 0) &&
		        ((s_session->m_flags & def_SSL_inspection_session_flag_ssl_accepted) == def_SSL_inspection_session_flag_none)) {
			/* MSG_PEEK 후 ClientHello가 소켓 버퍼에 남아 있으므로 connecting/connect_ssl_handshake
			 * 구간에서는 EPOLLIN 등록을 생략한다 — level-triggered busy-loop 방지.
			 * peek 단계와 accept SSL 핸드쉐이크 단계에서만 EPOLLIN을 등록한다. */
			if((s_session->m_state == def_SSL_inspection_session_state_peek_client_hello) ||
			   (s_session->m_state == def_SSL_inspection_session_state_accept_ssl_handshake) ||
			   ((s_session->m_accept_ssl != ((SSL *)(NULL))) && (SSL_want_read(s_session->m_accept_ssl) != 0))) {
				s_accept_events |= (uint32_t)EPOLLIN;
			}
			if((s_session->m_accept_ssl != ((SSL *)(NULL))) && SSL_want_write(s_session->m_accept_ssl)) {
				s_accept_events |= (uint32_t)EPOLLOUT;
			}
		}
		else if(s_session->m_state == def_SSL_inspection_session_state_stream) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
			if((s_session->m_ktls_active > 0) && (s_session->m_fwd_splice_pipe[0] != (-1))) {
				/* splice mode: read accept when pipe empty, write accept when bwd pipe has data */
				if(s_session->m_fwd_pipe_pending == (size_t)0u) {
					s_accept_events |= (uint32_t)EPOLLIN;
				}
				if(s_session->m_bwd_pipe_pending > (size_t)0u) {
					s_accept_events |= (uint32_t)EPOLLOUT;
				}
			}
			else {
#endif
			if(s_session->m_forward_pending_size == ((size_t)0u)) {
				s_accept_events |= (uint32_t)EPOLLIN;
			}
			if(s_session->m_backward_pending_size > ((size_t)0u)) {
				s_accept_events |= (uint32_t)EPOLLOUT;
			}
			if(s_session->m_accept_ssl != ((SSL *)(NULL))) {
				if(SSL_want_read(s_session->m_accept_ssl)) {
					s_accept_events |= (uint32_t)EPOLLIN;
				}
				if(SSL_want_write(s_session->m_accept_ssl)) {
					s_accept_events |= (uint32_t)EPOLLOUT;
				}
			}
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
			}
#endif
		}
	}

	s_connect_events = 0u;
	if(s_session->m_connect_socket != (-1)) {
		s_connect_events = def_SSL_inspection_epoll_session_base_events;
		if(s_session->m_state == def_SSL_inspection_session_state_auto_detect) {
			if((s_session->m_flags & def_SSL_inspection_session_flag_connected) == 0) {
				/* connect 완료 대기 */
				s_connect_events |= (uint32_t)EPOLLOUT;
			}
			else if(s_session->m_auto_detect_result == def_SSL_inspection_auto_detect_unknown &&
			        s_session->m_backward_pending_size == 0u) {
				/* 서버 선행 데이터 수신 대기 */
				s_connect_events |= (uint32_t)EPOLLIN;
			}
			/* detect 완료 or backward buf 찬 경우: connect 이벤트 불필요 */
		}
		else if((s_session->m_flags & def_SSL_inspection_session_flag_connected) == def_SSL_inspection_session_flag_none) {
			s_connect_events |= (uint32_t)EPOLLOUT;
		}
		else if((s_session->m_connect_ssl_ctx != ((SSL_CTX *)(NULL))) && ((s_session->m_flags & def_SSL_inspection_session_flag_ssl_connected) == def_SSL_inspection_session_flag_none)) {
			s_connect_events |= (uint32_t)EPOLLIN;
			if((s_session->m_connect_ssl != ((SSL *)(NULL))) && SSL_want_write(s_session->m_connect_ssl)) {
				s_connect_events |= (uint32_t)EPOLLOUT;
			}
		}
		else if(s_session->m_state == def_SSL_inspection_session_state_stream) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
			if((s_session->m_ktls_active > 0) && (s_session->m_fwd_splice_pipe[0] != (-1))) {
				/* splice mode: read connect when pipe empty, write connect when fwd pipe has data */
				if(s_session->m_bwd_pipe_pending == (size_t)0u) {
					s_connect_events |= (uint32_t)EPOLLIN;
				}
				if(s_session->m_fwd_pipe_pending > (size_t)0u) {
					s_connect_events |= (uint32_t)EPOLLOUT;
				}
			}
			else {
#endif
			if(s_session->m_backward_pending_size == ((size_t)0u)) {
				s_connect_events |= (uint32_t)EPOLLIN;
			}
			if(s_session->m_forward_pending_size > ((size_t)0u)) {
				s_connect_events |= (uint32_t)EPOLLOUT;
			}
			if(s_session->m_connect_ssl != ((SSL *)(NULL))) {
				if(SSL_want_read(s_session->m_connect_ssl)) {
					s_connect_events |= (uint32_t)EPOLLIN;
				}
				if(SSL_want_write(s_session->m_connect_ssl)) {
					s_connect_events |= (uint32_t)EPOLLOUT;
				}
			}
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
			}
#endif
		}
	}

	s_session->m_accept_epoll_interest = s_accept_events;
	s_session->m_connect_epoll_interest = s_connect_events;

	if(SSL_inspection_unlikely(SSL_inspection_worker_set_epoll_interest(
		s_worker_context,
		(SSL_inspection_epoll_item_t *)(&s_session->m_accept_epoll_item),
		s_accept_events
	) != 0)) {
		return(-1);
	}
	if(SSL_inspection_unlikely(SSL_inspection_worker_set_epoll_interest(
		s_worker_context,
		(SSL_inspection_epoll_item_t *)(&s_session->m_connect_epoll_item),
		s_connect_events
	) != 0)) {
		return(-1);
	}

	return(0);
}

/* Returns 1 if original_dst resolves to our own listen address (self-loop or no-redirect). */
static int SSL_inspection_tproxy_is_self(
	const struct sockaddr_storage *s_original_dst,
	const struct sockaddr_storage *s_listen_bind)
{
	if(s_original_dst->ss_family != s_listen_bind->ss_family) return(0);
	if(s_original_dst->ss_family == AF_INET) {
		const struct sockaddr_in *s_dst    = (const struct sockaddr_in *)s_original_dst;
		const struct sockaddr_in *s_listen = (const struct sockaddr_in *)s_listen_bind;
		if(s_dst->sin_port != s_listen->sin_port) return(0);
		if(s_listen->sin_addr.s_addr == htonl(INADDR_ANY)) return(1); /* wildcard listen */
		return((s_dst->sin_addr.s_addr == s_listen->sin_addr.s_addr) ? 1 : 0);
	}
	if(s_original_dst->ss_family == AF_INET6) {
		const struct sockaddr_in6 *s_dst    = (const struct sockaddr_in6 *)s_original_dst;
		const struct sockaddr_in6 *s_listen = (const struct sockaddr_in6 *)s_listen_bind;
		if(s_dst->sin6_port != s_listen->sin6_port) return(0);
		if(memcmp(&s_listen->sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0) return(1); /* wildcard */
		return((memcmp(&s_dst->sin6_addr, &s_listen->sin6_addr, sizeof(struct in6_addr)) == 0) ? 1 : 0);
	}
	return(0);
}

int SSL_inspection_prepare_session_async(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session)
{
	SSL_inspection_main_context_t *s_main_context;

	if((s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) || (s_session == ((SSL_inspection_session_t *)(NULL)))) {
		errno = EINVAL;
		return(-1);
	}

	s_main_context = s_worker_context->m_main_context;
	s_session->m_worker_context = s_worker_context;
	if(s_main_context->m_use_auto_detect_tls != 0) {
		/* B 방안: accept 즉시 서버 TCP 연결 + 동시에 클라이언트 peek */
		s_session->m_state = def_SSL_inspection_session_state_auto_detect;
	}
	else if(s_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) {
		/* 기존 SSL 모드: peek 후 연결 */
		s_session->m_state = def_SSL_inspection_session_state_peek_client_hello;
	}
	else {
		/* 기존 TCP 모드: 즉시 연결 */
		s_session->m_state = def_SSL_inspection_session_state_connecting;
	}
	s_session->m_job_flags = def_SSL_inspection_session_job_flag_none;
	s_session->m_job_next = (SSL_inspection_session_t *)(NULL);
	s_session->m_forward_pending_offset = s_session->m_forward_pending_size = (size_t)0u;
	s_session->m_backward_pending_offset = s_session->m_backward_pending_size = (size_t)0u;
	s_session->m_accept_ready_events = s_session->m_connect_ready_events = 0u;
	s_session->m_accept_epoll_interest = s_session->m_connect_epoll_interest = 0u;

	/* accept4() already set NONBLOCK; just read flags for bookkeeping/verbose log */
	errno = 0;
	s_session->m_accept_socket_flags = fcntl(s_session->m_accept_socket, F_GETFL, 0);
	if(SSL_inspection_unlikely(s_session->m_accept_socket_flags == (-1))) {
		SSL_inspection_perror("F_GETFL (accept)");
		return(-1);
	}

	if(s_session->m_sockaddr_accept.ss_family == AF_INET) {
		struct sockaddr_in *s_sockaddr_in = (struct sockaddr_in *)(&s_session->m_sockaddr_accept);

		(void)inet_ntop(s_session->m_sockaddr_accept.ss_family, (const void *)(&s_sockaddr_in->sin_addr), (char *)(&s_session->m_accept_address_string[0]), (socklen_t)sizeof(s_session->m_accept_address_string));
	}
	else if(s_session->m_sockaddr_accept.ss_family == AF_INET6) {
		struct sockaddr_in6 *s_sockaddr_in6 = (struct sockaddr_in6 *)(&s_session->m_sockaddr_accept);

		(void)inet_ntop(s_session->m_sockaddr_accept.ss_family, (const void *)(&s_sockaddr_in6->sin6_addr), (char *)(&s_session->m_accept_address_string[0]), (socklen_t)sizeof(s_session->m_accept_address_string));
	}
	else {
		(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s %sBUG: invalid accept address family%s (family=%u)\n", sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n, (unsigned int)s_session->m_sockaddr_accept.ss_family);
		errno = EINVAL;
		return(-1);
	}

	/* TPROXY: get original destination from accepted socket via getsockname().
	 * In TPROXY mode the kernel preserves the original dst on the accepted fd.
	 * With --tproxy-fallback: if returned port == listen port (heuristic), fall
	 * back to -B/-P.  Caveat: misfires when redirect dst port == listen port. */
	if(s_main_context->m_use_tproxy != 0) {
		int  s_orig_port = 0;
		char s_orig_dst_str[INET6_ADDRSTRLEN] = {0};

		s_session->m_socklen_original_dst = (socklen_t)sizeof(s_session->m_sockaddr_original_dst);
		if(SSL_inspection_unlikely(getsockname(
				s_session->m_accept_socket,
				(struct sockaddr *)(&s_session->m_sockaddr_original_dst),
				&s_session->m_socklen_original_dst) == (-1))) {
			SSL_inspection_perror("getsockname (tproxy)");
			return(-1);
		}

		if(s_session->m_sockaddr_original_dst.ss_family == AF_INET) {
			s_orig_port = (int)ntohs(((struct sockaddr_in *)(&s_session->m_sockaddr_original_dst))->sin_port);
			(void)inet_ntop(AF_INET, &((struct sockaddr_in *)(&s_session->m_sockaddr_original_dst))->sin_addr,
				s_orig_dst_str, (socklen_t)sizeof(s_orig_dst_str));
		}
		else if(s_session->m_sockaddr_original_dst.ss_family == AF_INET6) {
			s_orig_port = (int)ntohs(((struct sockaddr_in6 *)(&s_session->m_sockaddr_original_dst))->sin6_port);
			(void)inet_ntop(AF_INET6, &((struct sockaddr_in6 *)(&s_session->m_sockaddr_original_dst))->sin6_addr,
				s_orig_dst_str, (socklen_t)sizeof(s_orig_dst_str));
		}

		/* Self-address check: original dst == our own listen address.
		 * Covers both "no TPROXY redirect rule" (traffic hits proxy directly)
		 * and genuine self-loop (misconfigured iptables rule). */
		if(SSL_inspection_tproxy_is_self(&s_session->m_sockaddr_original_dst, &s_worker_context->m_sockaddr_listen_bind)) {
			if(s_main_context->m_connect_address_explicit != 0) {
				/* -B given → fall back to explicit connect address; skip source spoofing */
				s_session->m_sockaddr_original_dst = s_main_context->m_sockaddr_connect;
				s_session->m_socklen_original_dst   = s_main_context->m_socklen_connect;
				s_session->m_flags |= def_SSL_inspection_session_flag_tproxy_no_spoof;
				if(s_main_context->m_is_verbose >= 1) {
					(void)SSL_inspection_fprintf(stderr,
						"%s[C-fd=%d]%s TPROXY: self-address \"[%s]:%d\", fallback to \"%s:%d\"\n",
						sg_ce_c, s_session->m_accept_socket, sg_ce_n, s_orig_dst_str, s_orig_port,
						s_main_context->m_connect_address, s_main_context->m_connect_port);
				}
			}
			else {
				/* No -B → routing misconfiguration, reject immediately */
				(void)SSL_inspection_fprintf(stderr,
					"%s[C-fd=%d]%s %sTPROXY: self-address \"[%s]:%d\", no -B fallback — closing%s\n",
					sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, s_orig_dst_str, s_orig_port, sg_ce_n);
				return(-1);
			}
		}
		else if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout,
				"%s[C-fd=%d]%s TPROXY: original dst \"[%s]:%d\"\n",
				sg_co_c, s_session->m_accept_socket, sg_co_n, s_orig_dst_str, s_orig_port);
		}
	}

	if(s_main_context->m_is_verbose >= 1) {
		char s_tuple[128];
		SSL_inspection_session_format_tuple(s_session, s_tuple, sizeof(s_tuple));
#if defined(def_sslid_use_dpdk_lcore)
		(void)SSL_inspection_fprintf(stdout,
			"%s[C-fd=%d]%s %sAccepted%s %s (worker_index=%u, lcore_id=%u)\n",
			sg_co_c, s_session->m_accept_socket, sg_co_n,
			sg_co_g, sg_co_n,
			s_tuple,
			s_worker_context->m_worker_index,
			s_worker_context->m_lcore_id
		);
#else
		(void)SSL_inspection_fprintf(stdout,
			"%s[C-fd=%d]%s %sAccepted%s %s (worker_index=%u)\n",
			sg_co_c, s_session->m_accept_socket, sg_co_n,
			sg_co_g, sg_co_n,
			s_tuple,
			s_worker_context->m_worker_index
		);
#endif
	}

	if(SSL_inspection_unlikely(SSL_inspection_set_linger_socket(s_session->m_accept_socket, 1, 0) == (-1))) {
		SSL_inspection_perror("SSL_inspection_set_linger_socket (accept)");
	}
	if(SSL_inspection_unlikely(SSL_inspection_set_keepalive_socket(s_session->m_accept_socket, 1, (-1), (-1)) == (-1))) {
		SSL_inspection_perror("SSL_inspection_set_keepalive_socket (accept)");
	}
	{
		int s_nodelay = 1;
		if(SSL_inspection_unlikely(setsockopt(s_session->m_accept_socket, IPPROTO_TCP, TCP_NODELAY, (void *)(&s_nodelay), (socklen_t)sizeof(s_nodelay)) == (-1))) {
			SSL_inspection_perror("TCP_NODELAY (accept)");
		}
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

	if((s_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) &&
	   (s_main_context->m_use_auto_detect_tls == 0) &&
	   ((s_session->m_flags & def_SSL_inspection_session_flag_tcp_relay) == 0)) {
		/* auto_detect 모드: m_connect_ssl_ctx는 TLS 확정 후 drive()에서 설정 */
		s_session->m_connect_ssl_ctx = s_main_context->m_client_ssl_ctx;
		if(SSL_inspection_unlikely(s_session->m_connect_ssl_ctx == ((SSL_CTX *)(NULL)))) {
			(void)SSL_inspection_fprintf(stderr, "%s[C-fd=%d]%s %sclient SSL_CTX not initialized (connect)%s\n", sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n);
			return(-1);
		}
	}

	s_session->m_accept_epoll_item = (SSL_inspection_epoll_item_t) {
		.m_worker_context = s_worker_context,
		.m_session = s_session,
		.m_fd = (OSSL_ASYNC_FD)s_session->m_accept_socket,
		.m_events = 0u,
		.m_type = def_SSL_inspection_epoll_item_type_accept_socket,
		.m_is_registered = 0,
	};
	/* connect fd not yet created — initiate_connect fills m_fd when called */
	s_session->m_connect_epoll_item = (SSL_inspection_epoll_item_t) {
		.m_worker_context = s_worker_context,
		.m_session = s_session,
		.m_fd = (OSSL_ASYNC_FD)(-1),
		.m_events = 0u,
		.m_type = def_SSL_inspection_epoll_item_type_connect_socket,
		.m_is_registered = 0,
	};

	if(s_main_context->m_use_auto_detect_tls != 0) {
		/* auto_detect: 서버 TCP 연결 즉시 시작 (SSL CTX 할당은 TLS 확정 후 drive()에서 수행) */
		s_session->m_auto_detect_result = def_SSL_inspection_auto_detect_unknown;
		s_session->m_peek_start_ts      = SSL_inspection_get_time_stamp_msec();
		if(SSL_inspection_unlikely(SSL_inspection_session_initiate_connect(s_session) != 0)) {
			return(-1);
		}
		/* initiate_connect()가 변경할 수 있는 state를 auto_detect로 복원 */
		s_session->m_state = def_SSL_inspection_session_state_auto_detect;
	}
	else if(s_main_context->m_ssl_ctx == ((SSL_CTX *)(NULL))) {
		/* TCP mode: no SNI peek needed — connect immediately */
		if(SSL_inspection_unlikely(SSL_inspection_session_initiate_connect(s_session) != 0)) {
			return(-1);
		}
	}
	else {
		/* peek_client_hello 모드: 타임아웃 추적을 위해 시작 시각 기록 */
		s_session->m_peek_start_ts = SSL_inspection_get_time_stamp_msec();
	}
	if(SSL_inspection_unlikely(SSL_inspection_session_update_epoll(s_session) != 0)) {
		return(-1);
	}

	return(0);
}

static int SSL_inspection_session_initiate_connect(SSL_inspection_session_t *s_session)
{
	SSL_inspection_main_context_t *s_main_context;
	int s_connect_check;

	s_main_context = s_session->m_main_context;

	if(s_main_context->m_is_verbose >= 1) {
		char s_tuple[128];
		SSL_inspection_session_format_tuple(s_session, s_tuple, sizeof(s_tuple));
		(void)SSL_inspection_fprintf(stdout,
			"%s[C-fd=%d]%s %s %sconnecting%s%s%s%s%s. %s\n",
			sg_co_c, s_session->m_accept_socket, sg_co_n,
			(s_session->m_connect_ssl_ctx == ((SSL_CTX *)(NULL))) ? "TCP" : "SSL",
			sg_co_g, sg_co_n,
			(s_main_context->m_use_tproxy != 0) ? "[tproxy]" : "",
			(s_session->m_sni_hostname[0] != '\0') ? " sni=\"" : "",
			(s_session->m_sni_hostname[0] != '\0') ? s_session->m_sni_hostname : "",
			(s_session->m_sni_hostname[0] != '\0') ? "\"" : "",
			s_tuple
		);
	}

	/* SOCK_NONBLOCK|SOCK_CLOEXEC set atomically, saving 2 fcntl syscalls per connection */
	/* TPROXY spoof: socket family must match client source; fallback uses connect address family */
	s_session->m_connect_socket = socket(
		((s_main_context->m_use_tproxy != 0) && ((s_session->m_flags & def_SSL_inspection_session_flag_tproxy_no_spoof) == def_SSL_inspection_session_flag_none))
			? s_session->m_sockaddr_accept.ss_family
			: s_main_context->m_sockaddr_connect.ss_family,
		SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
	if(SSL_inspection_unlikely(s_session->m_connect_socket == (-1))) {
		SSL_inspection_perror("connect socket");
		return(-1);
	}

	if(SSL_inspection_unlikely(SSL_inspection_set_linger_socket(s_session->m_connect_socket, 1, 0) == (-1))) {
		SSL_inspection_perror("SSL_inspection_set_linger_socket (connect)");
	}
	if(SSL_inspection_unlikely(SSL_inspection_set_keepalive_socket(s_session->m_connect_socket, 1, (-1), (-1)) == (-1))) {
		SSL_inspection_perror("SSL_inspection_set_keepalive_socket (connect)");
	}
	{
		int s_nodelay = 1;
		if(SSL_inspection_unlikely(setsockopt(s_session->m_connect_socket, IPPROTO_TCP, TCP_NODELAY, (void *)(&s_nodelay), (socklen_t)sizeof(s_nodelay)) == (-1))) {
			SSL_inspection_perror("TCP_NODELAY (connect)");
		}
	}
	if((s_main_context->m_use_tproxy != 0) &&
	   ((s_session->m_flags & def_SSL_inspection_session_flag_tproxy_no_spoof) == def_SSL_inspection_session_flag_none)) {
		/* Full TPROXY spoof path: IP_FREEBIND + IP_TRANSPARENT + bind to client source */
		if(SSL_inspection_unlikely(SSL_inspection_set_freebind_socket(s_session->m_connect_socket, 1) == (-1))) {
			SSL_inspection_perror("SSL_inspection_set_freebind_socket (connect, tproxy)");
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
		if(SSL_inspection_unlikely(SSL_inspection_set_transparent_socket(s_session->m_connect_socket, 1) == (-1))) {
			SSL_inspection_perror("SSL_inspection_set_transparent_socket (connect, tproxy)");
			return(-1);
		}
		{
			struct sockaddr_storage s_spoof_bind = s_session->m_sockaddr_accept;
			if(s_spoof_bind.ss_family == AF_INET) {
				((struct sockaddr_in *)(&s_spoof_bind))->sin_port = 0;
			}
			else if(s_spoof_bind.ss_family == AF_INET6) {
				((struct sockaddr_in6 *)(&s_spoof_bind))->sin6_port = 0;
			}
			if(SSL_inspection_unlikely(bind(s_session->m_connect_socket, (const struct sockaddr *)(&s_spoof_bind), s_session->m_socklen_accept) == (-1))) {
				SSL_inspection_perror("connect bind (tproxy spoof)");
				return(-1);
			}
		}
	}
	else {
		/* Normal path: no spoofing (non-TPROXY or TPROXY fallback to -B) */
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
		if(SSL_inspection_unlikely(bind(s_session->m_connect_socket, (struct sockaddr *)(&s_main_context->m_sockaddr_connect_bind), s_main_context->m_socklen_connect_bind) == (-1))) {
			SSL_inspection_perror("connect bind");
			return(-1);
		}
	}

	/* socket() already set NONBLOCK; just read flags for bookkeeping */
	s_session->m_connect_socket_flags = fcntl(s_session->m_connect_socket, F_GETFL, 0);
	if(SSL_inspection_unlikely(s_session->m_connect_socket_flags == (-1))) {
		SSL_inspection_perror("F_GETFL (connect)");
		return(-1);
	}

	/* update epoll item fd now that socket is created */
	s_session->m_connect_epoll_item.m_fd = (OSSL_ASYNC_FD)s_session->m_connect_socket;

	s_connect_check = connect(
		s_session->m_connect_socket,
		((s_main_context->m_use_tproxy != 0) && ((s_session->m_flags & def_SSL_inspection_session_flag_tproxy_no_spoof) == def_SSL_inspection_session_flag_none))
			? (const struct sockaddr *)(&s_session->m_sockaddr_original_dst)
			: (const struct sockaddr *)(&s_main_context->m_sockaddr_connect),
		((s_main_context->m_use_tproxy != 0) && ((s_session->m_flags & def_SSL_inspection_session_flag_tproxy_no_spoof) == def_SSL_inspection_session_flag_none))
			? s_session->m_socklen_original_dst
			: s_main_context->m_socklen_connect);
	if(s_connect_check == 0) {
		s_session->m_flags |= def_SSL_inspection_session_flag_connected;
		s_session->m_state = (s_session->m_connect_ssl_ctx == ((SSL_CTX *)(NULL))) ? def_SSL_inspection_session_state_stream : def_SSL_inspection_session_state_connect_ssl_handshake;
	}
	else if((errno == EINPROGRESS) || (errno == EALREADY) || (errno == EWOULDBLOCK)) {
		s_session->m_state = def_SSL_inspection_session_state_connecting;
	}
	else if(errno == EISCONN) {
		s_session->m_flags |= def_SSL_inspection_session_flag_connected;
		s_session->m_state = (s_session->m_connect_ssl_ctx == ((SSL_CTX *)(NULL))) ? def_SSL_inspection_session_state_stream : def_SSL_inspection_session_state_connect_ssl_handshake;
	}
	else {
		SSL_inspection_perror("connect");
		return(-1);
	}

	return(0);
}

/* Check whether kTLS is active on both SSL objects and optionally create splice pipes. */
int SSL_inspection_session_ktls_activate(SSL_inspection_session_t *s_session)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	SSL_inspection_main_context_t *s_main_context;
	int s_fwd_rx_ktls;
	int s_fwd_tx_ktls;
	int s_bwd_rx_ktls;
	int s_bwd_tx_ktls;
	int s_fwd_ktls;
	int s_bwd_ktls;

	s_main_context = s_session->m_main_context;

	if(s_main_context->m_use_ktls <= 0) {
		s_session->m_ktls_active = 0;
		return(0);
	}

	/* Evaluate each path individually: BIO_get_ktls_recv/send return flag bitmasks
	 * (BIO_FLAGS_KTLS_RX=0x4000, BIO_FLAGS_KTLS_TX=0x2000); bitwise & of different
	 * bit positions would give 0 even when both are active, so use logical && here. */
	/* fwd: accept_ssl rx (client→proxy), connect_ssl tx (proxy→server) */
	s_fwd_rx_ktls = (s_session->m_accept_ssl != ((SSL *)(NULL))) && BIO_get_ktls_recv(SSL_get_rbio(s_session->m_accept_ssl));
	s_fwd_tx_ktls = (s_session->m_connect_ssl != ((SSL *)(NULL))) && BIO_get_ktls_send(SSL_get_wbio(s_session->m_connect_ssl));
	/* bwd: connect_ssl rx (server→proxy), accept_ssl tx (proxy→client) */
	s_bwd_rx_ktls = (s_session->m_connect_ssl != ((SSL *)(NULL))) && BIO_get_ktls_recv(SSL_get_rbio(s_session->m_connect_ssl));
	s_bwd_tx_ktls = (s_session->m_accept_ssl != ((SSL *)(NULL))) && BIO_get_ktls_send(SSL_get_wbio(s_session->m_accept_ssl));
	s_fwd_ktls = s_fwd_rx_ktls && s_fwd_tx_ktls;
	s_bwd_ktls = s_bwd_rx_ktls && s_bwd_tx_ktls;

	if((s_fwd_ktls == 0) || (s_bwd_ktls == 0)) {
		/* kTLS not negotiated on all four paths — fall back to userspace relay */
		s_session->m_ktls_active = 0;
		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout,
				"%s[C-fd=%d]%s kTLS: fallback to userspace relay (%sS-fd=%d%s, fwd_rx=%s, fwd_tx=%s, bwd_rx=%s, bwd_tx=%s)\n",
				sg_co_c, s_session->m_accept_socket, sg_co_n,
				sg_co_y, s_session->m_connect_socket, sg_co_n,
				s_fwd_rx_ktls ? "on" : "off", s_fwd_tx_ktls ? "on" : "off",
				s_bwd_rx_ktls ? "on" : "off", s_bwd_tx_ktls ? "on" : "off"
			);
		}
		return(0);
	}

	s_session->m_ktls_active = 1;

	if(s_main_context->m_use_splice <= 0) {
		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout,
				"%s[C-fd=%d]%s kTLS: active (%sS-fd=%d%s), splice: off\n",
				sg_co_c, s_session->m_accept_socket, sg_co_n,
				sg_co_y, s_session->m_connect_socket, sg_co_n
			);
		}
		return(0); /* kTLS active, splice not requested */
	}

	/* create kernel pipes for zero-copy splice */
	if(pipe2(s_session->m_fwd_splice_pipe, O_NONBLOCK | O_CLOEXEC) != 0) {
		SSL_inspection_perror("pipe2 fwd_splice_pipe");
		s_session->m_ktls_active = 0; /* C-1: fall back to userspace relay; don't kill session */
		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout,
				"%s[C-fd=%d]%s kTLS: active (%sS-fd=%d%s), splice: pipe creation failed, fallback to userspace relay\n",
				sg_co_c, s_session->m_accept_socket, sg_co_n,
				sg_co_y, s_session->m_connect_socket, sg_co_n
			);
		}
		return(0);
	}
	/* N-4: log F_SETPIPE_SZ failure — pipe falls back to default (~64KB); splice still works */
	if(SSL_inspection_unlikely(fcntl(s_session->m_fwd_splice_pipe[0], F_SETPIPE_SZ, 256 * 1024) == (-1))) {
		SSL_inspection_perror("F_SETPIPE_SZ fwd_splice_pipe");
	}
	if(pipe2(s_session->m_bwd_splice_pipe, O_NONBLOCK | O_CLOEXEC) != 0) {
		SSL_inspection_perror("pipe2 bwd_splice_pipe");
		(void)close(s_session->m_fwd_splice_pipe[0]); s_session->m_fwd_splice_pipe[0] = (-1);
		(void)close(s_session->m_fwd_splice_pipe[1]); s_session->m_fwd_splice_pipe[1] = (-1);
		s_session->m_ktls_active = 0;
		if(s_main_context->m_is_verbose >= 1) {
			(void)SSL_inspection_fprintf(stdout,
				"%s[C-fd=%d]%s kTLS: active (%sS-fd=%d%s), splice: pipe creation failed, fallback to userspace relay\n",
				sg_co_c, s_session->m_accept_socket, sg_co_n,
				sg_co_y, s_session->m_connect_socket, sg_co_n
			);
		}
		return(0); /* M-4: fall back to userspace relay; m_ktls_active=0 disables splice path */
	}
	if(SSL_inspection_unlikely(fcntl(s_session->m_bwd_splice_pipe[0], F_SETPIPE_SZ, 256 * 1024) == (-1))) {
		SSL_inspection_perror("F_SETPIPE_SZ bwd_splice_pipe");
	}

	if(s_main_context->m_is_verbose >= 1) {
		(void)SSL_inspection_fprintf(stdout,
			"%s[C-fd=%d]%s kTLS: active (%sS-fd=%d%s), splice: active\n",
			sg_co_c, s_session->m_accept_socket, sg_co_n,
			sg_co_y, s_session->m_connect_socket, sg_co_n
		);
	}

	return(0);
#else
	(void)s_session;
	return(0);
#endif
}

/*
 * Splice-based zero-copy relay (requires kTLS on all four paths).
 * Moves data between accept_socket and connect_socket via kernel pipes.
 * The kernel kTLS layer transparently decrypts on read and re-encrypts on write.
 *
 * Returns: -1=error, 0=no progress, 1=made progress
 */
int SSL_inspection_session_splice_relay(SSL_inspection_session_t *s_session)
{
	int s_progress = 0;
	ssize_t s_n;
	size_t s_pipe_capacity = (size_t)(256u * 1024u); /* pipe capacity matches F_SETPIPE_SZ */

	/* forward: accept_socket → fwd_pipe → connect_socket */
	if(s_session->m_fwd_pipe_pending == (size_t)0u) {
		/* fill pipe from accept socket */
		s_n = splice(
			s_session->m_accept_socket,
			(loff_t *)(NULL),
			s_session->m_fwd_splice_pipe[1],
			(loff_t *)(NULL),
			s_pipe_capacity,
			SPLICE_F_NONBLOCK | SPLICE_F_MOVE
		);
		if(s_n > (ssize_t)0) {
			s_session->m_fwd_pipe_pending = (size_t)s_n;
			s_progress = 1;
		}
		else if(s_n == (ssize_t)0) {
			/* accept side FIN: fwd_pipe(client→server)는 비어 있지만(진입 조건),
			 * bwd_pipe(server→client)에 남아 있는 데이터는 클라이언트에 전달하고 종료.
			 * EAGAIN 시 POLLOUT로 단기 재시도하여 잔여 데이터 유실을 최소화한다. */
			while(s_session->m_bwd_pipe_pending > (size_t)0u) {
				ssize_t s_drained = splice(
					s_session->m_bwd_splice_pipe[0], (loff_t *)(NULL),
					s_session->m_accept_socket, (loff_t *)(NULL),
					s_session->m_bwd_pipe_pending,
					SPLICE_F_NONBLOCK | SPLICE_F_MOVE
				);
				if(s_drained > (ssize_t)0) {
					s_session->m_bwd_pipe_pending -= (size_t)s_drained;
				}
				else if((s_drained < (ssize_t)0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
					struct pollfd s_pfd;
					s_pfd.fd      = s_session->m_accept_socket;
					s_pfd.events  = POLLOUT;
					s_pfd.revents = 0;
					if(poll(&s_pfd, (nfds_t)1, 20) <= 0) break; /* 20ms 내 수신 불가 시 best-effort 포기 */
				}
				else {
					break; /* 에러 또는 FIN */
				}
			}
			return(-1);
		}
		else if((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR)) {
			return(-1);
		}
	}

	if(s_session->m_fwd_pipe_pending > (size_t)0u) {
		/* drain pipe to connect socket; SPLICE_F_MORE hints kernel to coalesce TCP segments */
		s_n = splice(
			s_session->m_fwd_splice_pipe[0],
			(loff_t *)(NULL),
			s_session->m_connect_socket,
			(loff_t *)(NULL),
			s_session->m_fwd_pipe_pending,
			SPLICE_F_NONBLOCK | SPLICE_F_MOVE | SPLICE_F_MORE
		);
		if(s_n > (ssize_t)0) {
			s_session->m_fwd_pipe_pending -= (size_t)s_n;
			s_session->m_forward_transfer_size += (unsigned long long)s_n;
			s_session->m_forward_transfer_count++;
			if(s_session->m_worker_context != ((SSL_inspection_worker_context_t *)(NULL))) {
				s_session->m_worker_context->m_forward_transfer_size += (unsigned long long)s_n;
			}
			s_progress = 1;
		}
		else if((s_n == (ssize_t)(-1)) && (errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR)) {
			return(-1);
		}
	}

	/* backward: connect_socket → bwd_pipe → accept_socket */
	if(s_session->m_bwd_pipe_pending == (size_t)0u) {
		s_n = splice(
			s_session->m_connect_socket,
			(loff_t *)(NULL),
			s_session->m_bwd_splice_pipe[1],
			(loff_t *)(NULL),
			s_pipe_capacity,
			SPLICE_F_NONBLOCK | SPLICE_F_MOVE
		);
		if(s_n > (ssize_t)0) {
			s_session->m_bwd_pipe_pending = (size_t)s_n;
			s_progress = 1;
		}
		else if(s_n == (ssize_t)0) {
			/* connect side FIN: bwd_pipe(server→client)는 비어 있지만(진입 조건),
			 * fwd_pipe(client→server)에 남아 있는 데이터는 서버에 전달하고 종료.
			 * EAGAIN 시 POLLOUT로 단기 재시도하여 잔여 데이터 유실을 최소화한다. */
			while(s_session->m_fwd_pipe_pending > (size_t)0u) {
				ssize_t s_drained = splice(
					s_session->m_fwd_splice_pipe[0], (loff_t *)(NULL),
					s_session->m_connect_socket, (loff_t *)(NULL),
					s_session->m_fwd_pipe_pending,
					SPLICE_F_NONBLOCK | SPLICE_F_MOVE
				);
				if(s_drained > (ssize_t)0) {
					s_session->m_fwd_pipe_pending -= (size_t)s_drained;
				}
				else if((s_drained < (ssize_t)0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
					struct pollfd s_pfd;
					s_pfd.fd      = s_session->m_connect_socket;
					s_pfd.events  = POLLOUT;
					s_pfd.revents = 0;
					if(poll(&s_pfd, (nfds_t)1, 20) <= 0) break; /* 20ms 내 수신 불가 시 best-effort 포기 */
				}
				else {
					break; /* 에러 또는 FIN */
				}
			}
			return(-1);
		}
		else if((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR)) {
			return(-1);
		}
	}

	if(s_session->m_bwd_pipe_pending > (size_t)0u) {
		/* drain pipe to accept socket; SPLICE_F_MORE hints kernel to coalesce TCP segments */
		s_n = splice(
			s_session->m_bwd_splice_pipe[0],
			(loff_t *)(NULL),
			s_session->m_accept_socket,
			(loff_t *)(NULL),
			s_session->m_bwd_pipe_pending,
			SPLICE_F_NONBLOCK | SPLICE_F_MOVE | SPLICE_F_MORE
		);
		if(s_n > (ssize_t)0) {
			s_session->m_bwd_pipe_pending -= (size_t)s_n;
			s_session->m_backward_transfer_size += (unsigned long long)s_n;
			s_session->m_backward_transfer_count++;
			if(s_session->m_worker_context != ((SSL_inspection_worker_context_t *)(NULL))) {
				s_session->m_worker_context->m_backward_transfer_size += (unsigned long long)s_n;
			}
			s_progress = 1;
		}
		else if((s_n == (ssize_t)(-1)) && (errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR)) {
			return(-1);
		}
	}

	return(s_progress);
}

int SSL_inspection_session_drive(SSL_inspection_session_t *s_session)
{
	SSL_inspection_main_context_t *s_main_context;
	SSL_inspection_worker_context_t *s_worker_context;
	int s_loop;
	int s_progress;
	int s_check;

	if(s_session == ((SSL_inspection_session_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	s_main_context = s_session->m_main_context;
	s_worker_context = s_session->m_worker_context;
	if(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	for(s_loop = 0;s_loop < 16;s_loop++) {
		s_progress = 0;

		/* ── auto_detect 상태: accept 즉시 서버 TCP connect + 동시 client peek ── */
		if(s_session->m_state == def_SSL_inspection_session_state_auto_detect) {

			/* 단계 1: connect 완료 확인 */
			if((s_session->m_flags & def_SSL_inspection_session_flag_connected) == 0) {
				s_check = SSL_inspection_session_poll_connect(s_session);
				if(SSL_inspection_unlikely(s_check == (-1))) return(-1);
				if(s_check > 0) {
					if(s_main_context->m_is_verbose >= 1) {
						(void)SSL_inspection_fprintf(stdout,
							"%s[C-fd=%d]%s auto-detect: server connected (%sS-fd=%d%s)\n",
							sg_co_c, s_session->m_accept_socket, sg_co_n,
							sg_co_y, s_session->m_connect_socket, sg_co_n);
					}
					s_progress = 1;
				}
			}

			/* 단계 2: 서버 선행 데이터 버퍼링 (connect 완료 후, detect 미결 상태에서만) */
			if((s_session->m_flags & def_SSL_inspection_session_flag_connected) != 0 &&
			   s_session->m_auto_detect_result == def_SSL_inspection_auto_detect_unknown &&
			   (s_session->m_connect_ready_events & EPOLLIN) != 0 &&
			   s_session->m_backward_pending_size == 0u) {
				ssize_t s_n = recv(s_session->m_connect_socket,
				                   s_session->m_dup_buffer,
				                   s_session->m_buffer_size,
				                   MSG_DONTWAIT);
				if(s_n > 0) {
					s_session->m_backward_pending_size   = (size_t)s_n;
					s_session->m_backward_pending_offset = 0u;
					if(s_main_context->m_is_verbose >= 1) {
						(void)SSL_inspection_fprintf(stdout,
							"%s[C-fd=%d]%s auto-detect: server banner buffered (%zd bytes, %sS-fd=%d%s)\n",
							sg_co_c, s_session->m_accept_socket, sg_co_n,
							s_n, sg_co_y, s_session->m_connect_socket, sg_co_n);
					}
					s_progress = 1;
				}
				else if(s_n == 0 ||
				        ((s_n < 0) && (errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR))) {
					return(-1);
				}
			}


			/* 단계 3: 클라이언트 프로토콜 감지 (peek)
			 * 단계 2b보다 먼저 실행: 서버 FIN과 클라이언트 TLS가 같은 epoll 사이클에 도착할 때
			 * TLS를 우선 감지해야 하므로 순서가 중요하다. */
			if(s_session->m_auto_detect_result == def_SSL_inspection_auto_detect_unknown) {
				s_check = SSL_inspection_session_peek_sni(s_session);
				if(SSL_inspection_unlikely(s_check < 0)) return(-1);

				if(s_check == 0) {
					/* 데이터 없음: 타임아웃 확인 */
					uint64_t s_elapsed = SSL_inspection_get_time_stamp_msec() - s_session->m_peek_start_ts;
					if(s_elapsed >= (uint64_t)s_main_context->m_peek_timeout_ms) {
						s_session->m_auto_detect_result = def_SSL_inspection_auto_detect_timeout;
						s_session->m_flags |= def_SSL_inspection_session_flag_tcp_relay;
						if(s_main_context->m_is_verbose >= 1) {
							(void)SSL_inspection_fprintf(stdout,
								"%s[C-fd=%d]%s auto-detect: peek timeout → TCP relay\n",
								sg_co_c, s_session->m_accept_socket, sg_co_n);
						}
						s_progress = 1;
					}
					/* else: EPOLLIN 대기 */
				}
				else if(s_check == 1) {
					/* TLS ClientHello 확정 */
					s_session->m_auto_detect_result = def_SSL_inspection_auto_detect_tls;

					/* backward 버퍼 초기화: TLS 서버는 ClientHello 수신 전 무송신이 정상.
					 * 비정상 서버가 데이터를 보냈더라도 SSL_connect로 새 핸드셰이크 시작. */
					if(s_session->m_backward_pending_size > 0u) {
						(void)SSL_inspection_fprintf(stderr,
							"%s[C-fd=%d]%s auto-detect: TLS detected — discarding %zu pre-handshake server bytes\n",
							sg_ce_c, s_session->m_accept_socket, sg_ce_n, s_session->m_backward_pending_size);
						s_session->m_backward_pending_size   = 0u;
						s_session->m_backward_pending_offset = 0u;
					}

					/* connect SSL ctx 지금 설정 (initiate_connect에서 미뤄둔 것) */
					s_session->m_connect_ssl_ctx = s_main_context->m_client_ssl_ctx;
					if(SSL_inspection_unlikely(s_session->m_connect_ssl_ctx == ((SSL_CTX *)(NULL)))) {
						(void)SSL_inspection_fprintf(stderr,
							"%s[C-fd=%d]%s %sauto-detect: client SSL_CTX not initialized !%s\n",
							sg_ce_c, s_session->m_accept_socket, sg_ce_n, sg_ce_r, sg_ce_n);
						return(-1);
					}

					/* SNI loopback 무시 */
					if((s_session->m_sni_hostname[0] != '\0') &&
					   SSL_inspection_unlikely(SSL_inspection_sni_is_loopback(s_session->m_sni_hostname) != 0)) {
						if(s_main_context->m_is_verbose >= 1) {
							(void)SSL_inspection_fprintf(stderr,
								"%s[C-fd=%d]%s auto-detect: SNI loopback ignored: \"%s%s%s\"\n",
								sg_ce_c, s_session->m_accept_socket, sg_ce_n,
								sg_ce_y, s_session->m_sni_hostname, sg_ce_n);
						}
						s_session->m_sni_hostname[0] = '\0';
					}

					/* per-SNI 인증서 생성 (2단 캐시 → CA 서명 leaf cert) */
					if((s_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) &&
					   (s_session->m_sni_hostname[0] != '\0')) {
						if(s_main_context->m_is_verbose >= 1) {
							(void)SSL_inspection_fprintf(stdout,
								"%s[C-fd=%d]%s auto-detect: TLS, sni=\"%s%s%s\" → per-session cert\n",
								sg_co_c, s_session->m_accept_socket, sg_co_n,
								sg_co_y, s_session->m_sni_hostname, sg_co_n);
						}
						s_session->m_accept_ssl_ctx = ssl_inspection_get_or_create_sni_ssl_ctx(
							s_main_context, s_session->m_worker_context, s_session->m_accept_socket, s_session->m_sni_hostname);
						if(SSL_inspection_unlikely(s_session->m_accept_ssl_ctx == ((SSL_CTX *)(NULL)))) return(-1);
					}
					else if(s_main_context->m_is_verbose >= 1) {
						(void)SSL_inspection_fprintf(stdout,
							"%s[C-fd=%d]%s auto-detect: TLS, no SNI → global cert\n",
							sg_co_c, s_session->m_accept_socket, sg_co_n);
					}
					s_progress = 1;
				}
				else { /* s_check == 2: non-TLS */
					s_session->m_auto_detect_result = def_SSL_inspection_auto_detect_tcp;
					s_session->m_flags |= def_SSL_inspection_session_flag_tcp_relay;
					if(s_main_context->m_is_verbose >= 1) {
						(void)SSL_inspection_fprintf(stdout,
							"%s[C-fd=%d]%s auto-detect: non-TLS → TCP relay\n",
							sg_co_c, s_session->m_accept_socket, sg_co_n);
					}
					s_progress = 1;
				}
			}

			/* 단계 2b: 배너 버퍼 완료 후 서버 FIN → 즉시 TCP relay 전환 (EPOLLRDHUP busy-loop 방지)
			 * 단계 3 이후에 실행: result가 이미 tls로 결정됐으면 이 블록은 건너뜀. */
			if((s_session->m_flags & def_SSL_inspection_session_flag_connected) != 0 &&
			   s_session->m_auto_detect_result == def_SSL_inspection_auto_detect_unknown &&
			   s_session->m_backward_pending_size > 0u &&
			   (s_session->m_connect_ready_events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) != 0) {
				s_session->m_auto_detect_result = def_SSL_inspection_auto_detect_timeout;
				s_session->m_flags |= def_SSL_inspection_session_flag_tcp_relay;
				if(s_main_context->m_is_verbose >= 1) {
					(void)SSL_inspection_fprintf(stdout,
						"%s[C-fd=%d]%s auto-detect: server FIN with buffered banner — TCP relay\n",
						sg_co_c, s_session->m_accept_socket, sg_co_n);
				}
				s_progress = 1;
			}

			/* 단계 4: detect 확정 + connect 완료 → 상태 전이 */
			if((s_session->m_auto_detect_result != def_SSL_inspection_auto_detect_unknown) &&
			   ((s_session->m_flags & def_SSL_inspection_session_flag_connected) != 0)) {
				if(s_session->m_auto_detect_result == def_SSL_inspection_auto_detect_tls) {
					s_session->m_state = def_SSL_inspection_session_state_connect_ssl_handshake;
					if(s_main_context->m_is_verbose >= 1) {
						(void)SSL_inspection_fprintf(stdout,
							"%s[C-fd=%d]%s auto-detect: → SSL inspection\n",
							sg_co_c, s_session->m_accept_socket, sg_co_n);
					}
				}
				else {
					s_session->m_state = def_SSL_inspection_session_state_stream;
					if(s_main_context->m_is_verbose >= 1) {
						(void)SSL_inspection_fprintf(stdout,
							"%s[C-fd=%d]%s auto-detect: → TCP relay stream (buffered=%zu bytes)\n",
							sg_co_c, s_session->m_accept_socket, sg_co_n, s_session->m_backward_pending_size);
					}
				}
				s_progress = 1;
			}

			if(s_progress == 0) break;
			continue;
		}

		/* ── peek_client_hello 상태: SNI 기반 per-cert 생성 후 연결 ── */
		if(s_session->m_state == def_SSL_inspection_session_state_peek_client_hello) {
			s_check = SSL_inspection_session_peek_sni(s_session);
			if(SSL_inspection_unlikely(s_check < 0)) return(-1);
			if(s_check == 0) {
				/* no data yet — wait for EPOLLIN, but check timeout */
				uint64_t s_elapsed = SSL_inspection_get_time_stamp_msec() - s_session->m_peek_start_ts;
				if(s_elapsed < (uint64_t)s_main_context->m_peek_timeout_ms) break;
				if(s_main_context->m_is_verbose >= 1) {
					(void)SSL_inspection_fprintf(stdout,
						"%s[C-fd=%d]%s SNI peek: timeout — connecting without SNI\n",
						sg_co_c, s_session->m_accept_socket, sg_co_n);
				}
				/* fall through: connect without SNI */
			}
			/* s_check==2(non-TLS)는 --auto-detect-tls 없이는 기존처럼 TLS MITM 시도 */

			/* loopback/any-address SNI는 유효한 origin 식별자가 아니므로 무시 */
			if((s_session->m_sni_hostname[0] != '\0') &&
			   (SSL_inspection_unlikely(SSL_inspection_sni_is_loopback(s_session->m_sni_hostname) != 0))) {
				if(s_main_context->m_is_verbose >= 1) {
					(void)SSL_inspection_fprintf(stderr,
						"%s[C-fd=%d]%s SNI loopback ignored: \"%s%s%s\"\n",
						sg_ce_c, s_session->m_accept_socket, sg_ce_n,
						sg_ce_y, s_session->m_sni_hostname, sg_ce_n);
				}
				s_session->m_sni_hostname[0] = '\0';
			}

			/* SNI가 있을 때만 세션별 인증서 생성 (2단 캐시 → CA 서명 leaf cert).
			 * SNI 없으면 m_accept_ssl_ctx = NULL → ensure_ssl에서 전역 m_ssl_ctx 사용. */
			if((s_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) &&
			   (s_session->m_sni_hostname[0] != '\0')) {
				if(s_main_context->m_is_verbose >= 1) {
					(void)SSL_inspection_fprintf(stdout,
						"%s[C-fd=%d]%s SNI peek: \"%s%s%s\" -> per-session CN\n",
						sg_co_c, s_session->m_accept_socket, sg_co_n,
						sg_co_y, s_session->m_sni_hostname, sg_co_n);
				}
				s_session->m_accept_ssl_ctx = ssl_inspection_get_or_create_sni_ssl_ctx(
					s_main_context, s_session->m_worker_context, s_session->m_accept_socket, s_session->m_sni_hostname);
				if(SSL_inspection_unlikely(s_session->m_accept_ssl_ctx == ((SSL_CTX *)(NULL)))) return(-1);
			}
			else if((s_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) && (s_main_context->m_is_verbose >= 1)) {
				(void)SSL_inspection_fprintf(stdout,
					"%s[C-fd=%d]%s SNI peek: (none) -> global cert\n",
					sg_co_c, s_session->m_accept_socket, sg_co_n);
			}
			/* initiate_connect()가 m_state를 connecting/connect_ssl_handshake로 전진시킴 */
			if(SSL_inspection_unlikely(SSL_inspection_session_initiate_connect(s_session) != 0)) return(-1);
			s_progress = 1;
			continue;
		}

		if((s_session->m_flags & def_SSL_inspection_session_flag_connected) == def_SSL_inspection_session_flag_none) {
			s_check = SSL_inspection_session_drive_connect(s_session);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				return(-1);
			}
			if(s_check > 0) {
				s_progress = 1;
			}
			else {
				break;
			}
		}

		if((s_session->m_connect_ssl_ctx != ((SSL_CTX *)(NULL))) && ((s_session->m_flags & def_SSL_inspection_session_flag_ssl_connected) == def_SSL_inspection_session_flag_none)) {
			s_check = SSL_inspection_session_drive_handshake(s_session, 0);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				return(-1);
			}
			if(s_check > 0) {
				s_progress = 1;
			}
			else {
				break;
			}
		}

		if((s_session->m_main_context->m_ssl_ctx != ((SSL_CTX *)(NULL))) &&
		   ((s_session->m_flags & def_SSL_inspection_session_flag_tcp_relay) == 0) &&
		   ((s_session->m_flags & def_SSL_inspection_session_flag_ssl_accepted) == def_SSL_inspection_session_flag_none)) {
			s_check = SSL_inspection_session_drive_handshake(s_session, 1);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				return(-1);
			}
			if(s_check > 0) {
				s_progress = 1;
			}
			else {
				break;
			}
		}

		s_session->m_state = def_SSL_inspection_session_state_stream;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
		/* one-shot kTLS activation: runs once per session after both handshakes complete */
		if(s_session->m_ktls_active < 0) {
			s_check = SSL_inspection_session_ktls_activate(s_session);
			if(SSL_inspection_unlikely(s_check != 0)) {
				return(-1);
			}
		}

		/* splice path: bypass userspace buffers entirely */
		if((s_session->m_ktls_active > 0) && (s_session->m_fwd_splice_pipe[0] != (-1))) {
			s_check = SSL_inspection_session_splice_relay(s_session);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				return(-1);
			}
			if(s_check > 0) {
				s_progress = 1;
			}
			if(s_progress == 0) {
				break;
			}
			continue;
		}
#endif

		s_check = SSL_inspection_session_flush_buffer(s_session, 0);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			return(-1);
		}
		if(s_check > 0) {
			s_progress = 1;
		}

		s_check = SSL_inspection_session_flush_buffer(s_session, 1);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			return(-1);
		}
		if(s_check > 0) {
			s_progress = 1;
		}

		if(s_session->m_forward_pending_size == ((size_t)0u)) {
			s_check = SSL_inspection_session_fill_buffer(s_session, 1);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				return(-1);
			}
			if(s_check > 0) {
				s_progress = 1;
				continue;
			}
		}

		if(s_session->m_backward_pending_size == ((size_t)0u)) {
			s_check = SSL_inspection_session_fill_buffer(s_session, 0);
			if(SSL_inspection_unlikely(s_check == (-1))) {
				return(-1);
			}
			if(s_check > 0) {
				s_progress = 1;
				continue;
			}
		}

		s_check = SSL_inspection_session_flush_buffer(s_session, 0);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			return(-1);
		}
		if(s_check > 0) {
			s_progress = 1;
		}

		s_check = SSL_inspection_session_flush_buffer(s_session, 1);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			return(-1);
		}
		if(s_check > 0) {
			s_progress = 1;
		}

		if((s_session->m_accept_ssl != ((SSL *)(NULL))) && (s_session->m_forward_pending_size == ((size_t)0u)) && (SSL_pending(s_session->m_accept_ssl) > 0)) {
			s_progress = 1;
			continue;
		}
		if((s_session->m_connect_ssl != ((SSL *)(NULL))) && (s_session->m_backward_pending_size == ((size_t)0u)) && (SSL_pending(s_session->m_connect_ssl) > 0)) {
			s_progress = 1;
			continue;
		}

		if(s_progress == 0) {
			break;
		}
	}

	s_session->m_accept_ready_events = 0u;
	s_session->m_connect_ready_events = 0u;

	if(SSL_inspection_unlikely(SSL_inspection_session_update_epoll(s_session) != 0)) {
		return(-1);
	}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	if((s_session->m_ktls_active > 0) && (s_session->m_fwd_splice_pipe[0] != (-1))) {
		/* splice mode: re-queue when either pipe has pending data */
		if((s_session->m_fwd_pipe_pending > (size_t)0u) || (s_session->m_bwd_pipe_pending > (size_t)0u)) {
			SSL_inspection_worker_queue_job(s_worker_context, s_session);
		}
	}
	else {
#endif
	if(
		(s_session->m_forward_pending_size > ((size_t)0u)) ||
		(s_session->m_backward_pending_size > ((size_t)0u)) ||
		((s_session->m_accept_ssl != ((SSL *)(NULL))) && (s_session->m_forward_pending_size == ((size_t)0u)) && (SSL_pending(s_session->m_accept_ssl) > 0)) ||
		((s_session->m_connect_ssl != ((SSL *)(NULL))) && (s_session->m_backward_pending_size == ((size_t)0u)) && (SSL_pending(s_session->m_connect_ssl) > 0))
	) {
		SSL_inspection_worker_queue_job(s_worker_context, s_session);
	}
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	}
#endif

	return(0);
}

void SSL_inspection_worker_attach_session_list(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session_head, SSL_inspection_session_t *s_session_tail, size_t s_session_count)
{
	SSL_inspection_session_t *s_session;
	SSL_inspection_session_t *s_session_next;

	(void)s_session_tail;
	(void)s_session_count;

	for(s_session = s_session_head;s_session != ((SSL_inspection_session_t *)(NULL));s_session = s_session_next) {
		s_session_next = s_session->m_next;
		s_session->m_next = (SSL_inspection_session_t *)(NULL);
		s_session->m_prev = (SSL_inspection_session_t *)(NULL);

		if(SSL_inspection_unlikely(SSL_inspection_prepare_session_async(s_worker_context, s_session) != 0)) {
			SSL_inspection_worker_release_session_resources(s_worker_context, s_session);
			(void)SSL_inspection_free_session(s_session);
			continue;
		}

		if(s_worker_context->m_session_queue_tail == ((SSL_inspection_session_t *)(NULL))) {
			s_worker_context->m_session_queue_head = s_worker_context->m_session_queue_tail = s_session;
		}
		else {
			s_session->m_prev = s_worker_context->m_session_queue_tail;
			s_worker_context->m_session_queue_tail->m_next = s_session;
			s_worker_context->m_session_queue_tail = s_session;
		}
		++s_worker_context->m_session_queue_count;

		SSL_inspection_worker_queue_job(s_worker_context, s_session);
	}
}

int SSL_inspection_worker_process_jobs(SSL_inspection_worker_context_t *s_worker_context, size_t s_max_job_count)
{
	SSL_inspection_session_t *s_session;
	size_t s_processed_count;

	if(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) {
		errno = EINVAL;
		return(-1);
	}

	for(s_processed_count = (size_t)0u;;) {
		if((s_max_job_count > ((size_t)0u)) && (s_processed_count >= s_max_job_count)) {
			break;
		}

		s_session = SSL_inspection_worker_pop_job(s_worker_context);
		if(s_session == ((SSL_inspection_session_t *)(NULL))) {
			break;
		}

		if(SSL_inspection_unlikely(SSL_inspection_session_drive(s_session) != 0)) {
			(void)SSL_inspection_worker_unlink_session(s_worker_context, s_session);
			SSL_inspection_worker_release_session_resources(s_worker_context, s_session);
			(void)SSL_inspection_free_session(s_session);
		}

		++s_processed_count;
	}

	return((int)s_processed_count);
}

size_t SSL_inspection_checkout_worker_session(SSL_inspection_worker_context_t *s_worker_context, size_t s_request_session_count, int s_timeout_msec)
{
	SSL_inspection_main_context_t *s_main_context = (SSL_inspection_main_context_t *)s_worker_context->m_main_context;
	SSL_inspection_session_t *s_session_head;
	SSL_inspection_session_t *s_session_tail;
	size_t s_prev_session_count;
	size_t s_session_dequeued_count;

	s_prev_session_count = s_worker_context->m_session_queue_count;
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

	SSL_inspection_worker_attach_session_list(s_worker_context, s_session_head, s_session_tail, s_session_dequeued_count);

	return(s_worker_context->m_session_queue_count - s_prev_session_count);
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
		.m_running = (-1), /* N-1: plain int init; ATOMIC_VAR_INIT deprecated in C17 */
		.m_thread_created = 0,
		.m_main_context = s_main_context,
		.m_session_queue_head = (SSL_inspection_session_t *)(NULL),
		.m_session_queue_tail = (SSL_inspection_session_t *)(NULL),
		.m_session_queue_count = (size_t)0u,
		.m_max_epoll_events = s_max_worker_epoll_events,
		.m_epoll_fd = epoll_create1(EPOLL_CLOEXEC),
		.m_epoll_event = {},
		.m_epoll_events = (struct epoll_event *)(&s_worker_context[1]),
		.m_listen_socket = (-1),
		.m_sockaddr_listen_bind = {},
		.m_socklen_listen_bind = (socklen_t)sizeof(s_worker_context->m_sockaddr_listen_bind),
		.m_forward_transfer_size = 0ull,
		.m_backward_transfer_size = 0ull,
	};
	ssl_cert_cache_local_init(&s_worker_context->m_cert_cache_local);
	(void)memset((void *)(&s_worker_context[1]), 0, sizeof(struct epoll_event) * (size_t)s_max_worker_epoll_events);
	if(SSL_inspection_unlikely(s_worker_context->m_epoll_fd == (-1))) {
		SSL_inspection_perror("worker epoll_create1");
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

	{
		int s_attr_ok = (pthread_attr_init((pthread_attr_t *)(&s_worker_context->m_pthread_attr)) == 0);
		if(s_attr_ok) {
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
				s_attr_ok ? (const pthread_attr_t *)(&s_worker_context->m_pthread_attr) : (const pthread_attr_t *)(NULL),
				SSL_inspection_worker_handler,
				(void *)s_worker_context) != 0)) {
			(void)SSL_inspection_fprintf(stderr, "pthread_create failed !\n");
			if(s_attr_ok) {
				(void)pthread_attr_destroy((pthread_attr_t *)(&s_worker_context->m_pthread_attr));
			}
			(void)SSL_inspection_closefd(s_worker_context->m_epoll_fd);
			(void)free((void *)s_worker_context);
			return(-1);
		}
		if(s_attr_ok) {
			(void)pthread_attr_destroy((pthread_attr_t *)(&s_worker_context->m_pthread_attr));
		}
		s_worker_context->m_thread_created = 1;
	}

	++s_main_context->m_max_thread_pool;

	/* add worker list to main_context */
	s_main_context->m_worker_context_head = s_worker_context;

	/* waiting worker thread */
#if SSL_INSPECTION_HAS_C11_ATOMICS
	while((SSL_inspection_is_break_main_loop() == 0) && (atomic_load_explicit(&s_worker_context->m_running, memory_order_acquire) == (-1))) {
		SSL_inspection_msleep(10);
	}
#else
	while((SSL_inspection_is_break_main_loop() == 0) && ((*((volatile int *)(&s_worker_context->m_running))) == (-1))) {
		SSL_inspection_msleep(10);
	}
#endif

	return(0);
}

SSL_inspection_worker_context_t *SSL_inspection_free_worker(SSL_inspection_worker_context_t *s_worker_context)
{
	if(SSL_inspection_unlikely(s_worker_context == ((SSL_inspection_worker_context_t *)(NULL)))) {
		errno = EINVAL;
		return((SSL_inspection_worker_context_t *)(NULL));
	}

	/* worker thread 의 종료를 기다립니다.
	 * m_thread_created guards pthread_join: if pthread_create never succeeded
	 * (e.g. break_main_loop fired before the spin loop in add_worker exited),
	 * joining an uninitialised pthread_t is UB.  Using m_thread_created instead
	 * of (m_running != -1) prevents the use-after-free that occurred when the
	 * thread was still running but m_running had not yet been updated. */
	if((s_worker_context->m_worker_index > 0u) && (s_worker_context->m_thread_created != 0)) {
		(void)pthread_join(s_worker_context->m_pthread, (void **)(NULL));
	}

	/* cleanup session: call release_session_resources() before free_session() for each
	 * remaining session so that epoll registrations are explicitly removed before the
	 * epoll fd itself is closed below.  The worker thread's l_return block normally
	 * drains this queue, so a non-empty queue here indicates an unexpected exit path. */
	{
		SSL_inspection_session_t *s_cleanup_session;
		SSL_inspection_session_t *s_cleanup_next;

		if(SSL_inspection_unlikely(s_worker_context->m_session_queue_head != ((SSL_inspection_session_t *)(NULL)))) {
			(void)SSL_inspection_fprintf(stderr, "BUG: free_worker[%u]: session queue not empty (count=%lu)\n",
				s_worker_context->m_worker_index, (unsigned long)s_worker_context->m_session_queue_count);
		}
		for(s_cleanup_session = s_worker_context->m_session_queue_head;
		    s_cleanup_session != ((SSL_inspection_session_t *)(NULL));
		    s_cleanup_session = s_cleanup_next) {
			s_cleanup_next = s_cleanup_session->m_next;
			s_cleanup_session->m_next = (SSL_inspection_session_t *)(NULL);
			s_cleanup_session->m_prev = (SSL_inspection_session_t *)(NULL);
			SSL_inspection_worker_release_session_resources(s_worker_context, s_cleanup_session);
			(void)SSL_inspection_free_session(s_cleanup_session);
		}
		s_worker_context->m_session_queue_head = (SSL_inspection_session_t *)(NULL);
		s_worker_context->m_session_queue_tail = (SSL_inspection_session_t *)(NULL);
		s_worker_context->m_session_queue_count = (size_t)0u;
	}

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

	/* Release per-worker cert cache (all sessions on this worker have been freed above) */
	ssl_cert_cache_local_destroy(&s_worker_context->m_cert_cache_local);

	free((void *)s_worker_context);

	return((SSL_inspection_worker_context_t *)(NULL));
}

int SSL_inspection_do_session_event(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session, struct epoll_event *s_epoll_event, int s_epoll_session_type)
{
	if((s_worker_context == ((SSL_inspection_worker_context_t *)(NULL))) || (s_session == ((SSL_inspection_session_t *)(NULL))) || (s_epoll_event == ((struct epoll_event *)(NULL)))) {
		errno = EINVAL;
		return(-1);
	}

	if(s_epoll_session_type == 0) {
		s_session->m_accept_ready_events |= s_epoll_event->events;
	}
	else if(s_epoll_session_type == 1) {
		s_session->m_connect_ready_events |= s_epoll_event->events;
	}
	else {
		errno = EINVAL;
		return(-1);
	}

	SSL_inspection_worker_queue_job(s_worker_context, s_session);

	return(0);
}

void *SSL_inspection_worker_handler(void *s_worker_context_ptr)
{
	SSL_inspection_worker_context_t *s_worker_context;
	SSL_inspection_main_context_t *s_main_context;
	int s_check;
	int s_epoll_check;
	unsigned long long s_prev_time_stamp_msec;
	unsigned long long s_time_stamp_msec;
	unsigned long long s_delta_time_stamp_msec;
	unsigned long long s_prev_enqueued_session_count = 0ull;
	unsigned long long s_prev_dequeued_session_count = 0ull;
	unsigned long long s_prev_forward_transfer_size = 0ull;
	unsigned long long s_prev_backward_transfer_size = 0ull;
	SSL_inspection_session_t *s_session;
	SSL_inspection_epoll_item_t *s_epoll_item;

	if(SSL_inspection_unlikely(s_worker_context_ptr == NULL)) {
		return(NULL);
	}
	s_worker_context = (SSL_inspection_worker_context_t *)s_worker_context_ptr;
	s_main_context = s_worker_context->m_main_context;
	s_prev_time_stamp_msec = SSL_inspection_get_time_stamp_msec();

#if defined(def_sslid_use_dpdk_lcore)
	if(s_worker_context->m_worker_index > 0u) {
		(void)rte_thread_register();
	}
	s_worker_context->m_lcore_id = rte_lcore_id();
	if(s_main_context->m_is_verbose >= 3) {
		(void)SSL_inspection_fprintf(stdout, "Starting worker thread[%u] (lcore_id=%u)\n", s_worker_context->m_worker_index, s_worker_context->m_lcore_id);
	}
#else
	if(s_main_context->m_is_verbose >= 3) {
		(void)SSL_inspection_fprintf(stdout, "Starting worker thread[%u]\n", s_worker_context->m_worker_index);
	}
#endif

       	/* PREPARE LISTENER */
	if((s_main_context->m_use_multi_listen != 0) || (s_worker_context->m_worker_index == 0u)) {
		/* setup bind structure */
		s_check = SSL_inspection_string_to_sockaddr(
			AF_UNSPEC /* detect address family */,
			s_main_context->m_bind_address,
			s_main_context->m_bind_port, /* SO_REUSEPORT: all workers share the same port */
			(void *)(&s_worker_context->m_sockaddr_listen_bind),
			(socklen_t *)(&s_worker_context->m_socklen_listen_bind)
		);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			SSL_inspection_perror("SSL_inspection_string_to_sockaddr (listen bind)");
			goto l_return;
		}

		/* listen socket 생성: SOCK_NONBLOCK|SOCK_CLOEXEC set atomically */
		if(s_worker_context->m_sockaddr_listen_bind.ss_family == AF_INET) { /* IPv4 only */
			s_worker_context->m_listen_socket = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
			if(SSL_inspection_unlikely(s_worker_context->m_listen_socket == (-1))) {
				SSL_inspection_perror("socket");
				goto l_return;
			}

			if(s_main_context->m_is_verbose >= 3) {
				(void)SSL_inspection_fprintf(stdout, "IPv4 socket opened.\n");
			}
		}
		else if(s_worker_context->m_sockaddr_listen_bind.ss_family == AF_INET6) { /* IPv6 (+ IPv4 dual stack) */
			s_worker_context->m_listen_socket = socket(PF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
			if(SSL_inspection_unlikely(s_worker_context->m_listen_socket == (-1))) {
				SSL_inspection_perror("socket");
				goto l_return;
			}

			if(s_main_context->m_is_verbose >= 3) {
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

		if(s_main_context->m_use_tproxy != 0) {
			if(SSL_inspection_unlikely(SSL_inspection_set_transparent_socket(s_worker_context->m_listen_socket, 1) == (-1))) {
				SSL_inspection_perror("SSL_inspection_set_transparent_socket (listen, tproxy) — requires CAP_NET_ADMIN");
				goto l_return;
			}
		}

		/*
			reuse setting
			선택사항 : binding socket 의 연결이 있는 상태에서 강제 종료되는 경우 다시 binding 할 수 없는 상태를 방지하기 위함
		*/
		s_check = SSL_inspection_set_reuse_address_socket(s_worker_context->m_listen_socket, 1 /* enable */);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			SSL_inspection_perror("reuse socket");
		}
#if 1L /* SO_REUSEPORT: kernel SYN load balancing across workers */
		s_check = SSL_inspection_set_reuse_port_socket(s_worker_context->m_listen_socket, 1 /* enable */);
		if(SSL_inspection_unlikely(s_check == (-1))) {
			SSL_inspection_perror("reuse port socket");
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

		/* socket() already set SOCK_NONBLOCK|SOCK_CLOEXEC atomically — no separate fcntl needed */

		s_worker_context->m_listen_epoll_item = (SSL_inspection_epoll_item_t) {
			.m_worker_context = s_worker_context,
			.m_session = (SSL_inspection_session_t *)(NULL),
			.m_fd = (OSSL_ASYNC_FD)s_worker_context->m_listen_socket,
			.m_events = 0u,
			.m_type = def_SSL_inspection_epoll_item_type_listen,
			.m_is_registered = 0,
		};
		if(SSL_inspection_unlikely(SSL_inspection_worker_set_epoll_interest(
			s_worker_context,
			(SSL_inspection_epoll_item_t *)(&s_worker_context->m_listen_epoll_item),
			def_SSL_inspection_epoll_session_base_events | (uint32_t)EPOLLIN
		) != 0)) {
			SSL_inspection_perror("epoll listen");
			goto l_return;
		}
	}

#if SSL_INSPECTION_HAS_C11_ATOMICS
	atomic_store_explicit(&s_worker_context->m_running, 1, memory_order_release);
#else
	*((volatile int *)(&s_worker_context->m_running)) = 1;
#endif

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
					s_progress_session = (size_t)0u;
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

		if(s_worker_context->m_job_queue_head != ((SSL_inspection_session_t *)(NULL))) {
			(void)SSL_inspection_worker_process_jobs(s_worker_context, (size_t)256u);
		}

		/* WAIT EVENTS */
		s_epoll_check = epoll_wait(
			s_worker_context->m_epoll_fd,
		       	(struct epoll_event *)(&s_worker_context->m_epoll_events[0]),
		       	s_worker_context->m_max_epoll_events,
		       	(s_worker_context->m_job_queue_head == ((SSL_inspection_session_t *)(NULL))) ? 100 : 0
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

			for(s_epoll_index = 0;s_epoll_index < s_epoll_check;s_epoll_index++) {
				s_epoll_item = (SSL_inspection_epoll_item_t *)s_worker_context->m_epoll_events[s_epoll_index].data.ptr;
				if(s_epoll_item == ((SSL_inspection_epoll_item_t *)(NULL))) {
					continue;
				}

				if(s_epoll_item->m_type == def_SSL_inspection_epoll_item_type_listen) {
					/* Check error conditions before attempting accept: a socket
					 * in EPOLLERR state should not accept new connections. */
					if((s_worker_context->m_epoll_events[s_epoll_index].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0u) {
						(void)SSL_inspection_fprintf(stderr, "listen poll error ! (fd=%d)\n", s_worker_context->m_listen_socket);
						goto l_return; /* M-5: fatal listen socket error — exit loop to avoid busy-spin */
					}
					if((s_worker_context->m_epoll_events[s_epoll_index].events & EPOLLIN) == EPOLLIN) {
						/* Batch accept: collect all pending connections, then enqueue once */
						SSL_inspection_session_t *s_batch_head = (SSL_inspection_session_t *)(NULL);
						SSL_inspection_session_t *s_batch_tail = (SSL_inspection_session_t *)(NULL);
						for(;;) {
							s_session = SSL_inspection_new_and_accept_session(s_main_context, s_worker_context->m_listen_socket);
							if(s_session == ((SSL_inspection_session_t *)(NULL))) {
								break;
							}
							s_session->m_next = (SSL_inspection_session_t *)(NULL);
							if(s_batch_head == ((SSL_inspection_session_t *)(NULL))) {
								s_batch_head = s_batch_tail = s_session;
							}
							else {
								s_batch_tail->m_next = s_session;
								s_batch_tail = s_session;
							}
						}
						if(s_batch_head != ((SSL_inspection_session_t *)(NULL))) {
							(void)SSL_inspection_enqueue_session_list(s_main_context, s_batch_head);
						}
					}
					continue;
				}

				s_session = s_epoll_item->m_session;
				if(s_session == ((SSL_inspection_session_t *)(NULL))) {
					continue;
				}

				switch(s_epoll_item->m_type) {
					case def_SSL_inspection_epoll_item_type_accept_socket:
						(void)SSL_inspection_do_session_event(s_worker_context, s_session, (struct epoll_event *)(&s_worker_context->m_epoll_events[s_epoll_index]), 0);
						break;
					case def_SSL_inspection_epoll_item_type_connect_socket:
						(void)SSL_inspection_do_session_event(s_worker_context, s_session, (struct epoll_event *)(&s_worker_context->m_epoll_events[s_epoll_index]), 1);
						break;
					case def_SSL_inspection_epoll_item_type_accept_async:
					case def_SSL_inspection_epoll_item_type_connect_async:
						SSL_inspection_worker_queue_job(s_worker_context, s_session);
						break;
					default:
						break;
				}
			}
		}

		/* auto_detect 세션 peek 타임아웃 스캔:
		 * 서버 선행 프로토콜(SMTP/IMAP 등)에서 클라이언트가 데이터를 보내지 않으면
		 * accept EPOLLIN이 발생하지 않으므로 epoll_wait 복귀마다 주기적으로 확인. */
		if(s_main_context->m_use_auto_detect_tls != 0) {
			uint64_t s_now = SSL_inspection_get_time_stamp_msec();
			SSL_inspection_session_t *s_scan = s_worker_context->m_session_queue_head;
			while(s_scan != ((SSL_inspection_session_t *)(NULL))) {
				SSL_inspection_session_t *s_scan_next = s_scan->m_next;
				if(((s_scan->m_state == def_SSL_inspection_session_state_auto_detect) ||
				    (s_scan->m_state == def_SSL_inspection_session_state_peek_client_hello)) &&
				   (s_scan->m_auto_detect_result == def_SSL_inspection_auto_detect_unknown) &&
				   ((s_now - s_scan->m_peek_start_ts) >= (uint64_t)s_main_context->m_peek_timeout_ms)) {
					SSL_inspection_worker_queue_job(s_worker_context, s_scan);
				}
				s_scan = s_scan_next;
			}
		}

		if(s_worker_context->m_job_queue_head != ((SSL_inspection_session_t *)(NULL))) {
			(void)SSL_inspection_worker_process_jobs(s_worker_context, (size_t)0u);
		}
	}

l_return:;
	s_worker_context->m_job_queue_head = s_worker_context->m_job_queue_tail = (SSL_inspection_session_t *)(NULL);
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
		else {
			s_worker_context->m_session_queue_head->m_prev = (SSL_inspection_session_t *)(NULL);
		}
		s_session->m_next = (SSL_inspection_session_t *)(NULL);
		s_session->m_prev = (SSL_inspection_session_t *)(NULL);
		--s_worker_context->m_session_queue_count;

		SSL_inspection_worker_release_session_resources(s_worker_context, s_session);
		(void)SSL_inspection_free_session(s_session);
	}
#if 1L /* DEBUG */
	if(SSL_inspection_unlikely((s_worker_context->m_session_queue_count != ((size_t)0u)) || (s_worker_context->m_session_queue_head != ((SSL_inspection_session_t *)(NULL))) || (s_worker_context->m_session_queue_tail != ((SSL_inspection_session_t *)(NULL))))) {
		(void)SSL_inspection_fprintf(stderr, "BUG[%u]: s_worker_context->m_session_queue_count = %lu, s_worker_context->m_session_queue_head=%p, s_worker_context->m_session_queue_tail=%p)\n", s_worker_context->m_worker_index, (unsigned long)s_worker_context->m_session_queue_count, s_worker_context->m_session_queue_head, s_worker_context->m_session_queue_tail);
	}
#endif

	/* close listen socket */
	if(s_worker_context->m_listen_socket != (-1)) {
		(void)SSL_inspection_worker_set_epoll_interest(s_worker_context, (SSL_inspection_epoll_item_t *)(&s_worker_context->m_listen_epoll_item), 0u);

		if(SSL_inspection_unlikely(SSL_inspection_closesocket(s_worker_context->m_listen_socket) == (-1))) {
			SSL_inspection_perror("close listen socket");
		}
		s_worker_context->m_listen_socket = (-1);
	}

#if SSL_INSPECTION_HAS_C11_ATOMICS
	atomic_store_explicit(&s_worker_context->m_running, 0, memory_order_release);
#else
	*((volatile int *)(&s_worker_context->m_running)) = 0;
#endif

#if defined(def_sslid_use_dpdk_lcore)
	if(s_main_context->m_is_verbose >= 3) {
		(void)SSL_inspection_fprintf(stdout, "Stopping worker thread[%u] (lcore_id=%u)\n", s_worker_context->m_worker_index, s_worker_context->m_lcore_id);
	}
	if(s_worker_context->m_worker_index > 0u) {
		(void)rte_thread_unregister();
	}
#else
	if(s_main_context->m_is_verbose >= 3) {
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
		.m_use_multi_listen = 1, /* SO_REUSEPORT: all workers share the same port for kernel-level load balancing */
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
		.m_use_ktls = 0,
		.m_use_splice = 0,
		.m_use_tproxy = 0,
		.m_connect_address_explicit = 0,
		.m_use_auto_detect_tls = 0,
		.m_peek_timeout_ms     = 3000,
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		.m_provider_count   = (size_t)0u,
		.m_provider_default = (OSSL_PROVIDER *)(NULL),
		.m_provider_props   = (const char *)(NULL),
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		.m_ssl_options = 0UL,
#else
		.m_ssl_options = 0L,
#endif
		.m_server_ssl_method = (const SSL_METHOD *)(NULL),
		.m_client_ssl_method = (const SSL_METHOD *)(NULL),
		.m_ssl_ctx = (SSL_CTX *)(NULL),
		.m_client_ssl_ctx = (SSL_CTX *)(NULL),
		.m_ca_pkey = (EVP_PKEY *)(NULL),
		.m_ca_x509 = (X509 *)(NULL),
		.m_cert_cache = (ssl_cert_cache_global_t *)(NULL),
		.m_sockaddr_connect_bind = {},
		.m_socklen_connect_bind = (socklen_t)sizeof(s_main_context->m_sockaddr_connect_bind),
		.m_sockaddr_connect = {},
		.m_socklen_connect = (socklen_t)sizeof(s_main_context->m_sockaddr_connect),
		.m_magic_code_end = 0x87654321u,
	};

	/* Initialize runtime color strings based on TTY detection */
	if(isatty(STDOUT_FILENO)) {
		sg_co_n = def_hwport_color_normal;
		sg_co_c = def_hwport_color_cyan;
		sg_co_y = def_hwport_color_yellow;
		sg_co_g = def_hwport_color_green;
		sg_co_m = def_hwport_color_magenta;
		sg_co_w = def_hwport_color_white;
	}
	if(isatty(STDERR_FILENO)) {
		sg_ce_n = def_hwport_color_normal;
		sg_ce_c = def_hwport_color_cyan;
		sg_ce_r = def_hwport_color_red;
		sg_ce_y = def_hwport_color_yellow;
	}

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

	/* M-2: reinit cond with CLOCK_MONOTONIC so NTP jumps don't cause drift */
	do {
		pthread_condattr_t s_condattr;
		(void)pthread_cond_destroy(&s_main_context->m_session_queue_cond);
		(void)pthread_condattr_init(&s_condattr);
		(void)pthread_condattr_setclock(&s_condattr, CLOCK_MONOTONIC);
		(void)pthread_cond_init(&s_main_context->m_session_queue_cond, &s_condattr);
		(void)pthread_condattr_destroy(&s_condattr);
	}while(0);

	/* Warmup backtrace() to force libgcc_s.so load before signal handler installation.
	 * glibc backtrace() lazily dlopen()s libgcc_s.so on first call — dlopen() is not
	 * async-signal-safe, so calling backtrace() for the first time inside a signal
	 * handler (e.g. on SIGSEGV) can deadlock.  One dummy call here forces the load
	 * while we are still in normal context. */
	{ void *s_bt[1]; (void)backtrace(s_bt, 1); }

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
			{"connect", required_argument, (int *)(NULL), 'B'},
			{"connect-port", required_argument, (int *)(NULL), 'P'},
			{"buffer-size", required_argument, (int *)(NULL), 0},
			{"no-thread", no_argument, (int *)(NULL), 'n'},
			{"serialize-lock", no_argument, (int *)(NULL), 0},
			{"thread-pool", required_argument, (int *)(NULL), 0},
			{"async", no_argument, (int *)(NULL), 'a'},
			{"nossl", no_argument, (int *)(NULL), 0},
			{"ktls", no_argument, (int *)(NULL), 0},
			{"splice", no_argument, (int *)(NULL), 0},
			{"tproxy", no_argument, (int *)(NULL), 0},
			{"auto-detect-tls", no_argument,       (int *)(NULL), 0},
			{"peek-timeout",    required_argument, (int *)(NULL), 0},
			{"provider",        required_argument, (int *)(NULL), 0},
			{"provider-props",  required_argument, (int *)(NULL), 0},
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
				"hqvd:e:b:p:l:c:k:B:P:na",
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
						char *s_endptr;
						long s_value;
						errno = 0;
						s_value = strtol(optarg, &s_endptr, 10);
						if((errno != 0) || (s_endptr == optarg) || (*s_endptr != '\0') || (s_value <= 0L) || ((size_t)s_value > (SIZE_MAX / 2u))) {
							(void)SSL_inspection_fprintf(stderr, "invalid option value \"%s\" !\n", sg_options[s_option_index].name);
							s_main_context->m_is_help = 1;
						}
						else {
							s_main_context->m_buffer_size = (size_t)s_value;
						}
					}
					else if(strcmp(sg_options[s_option_index].name, "serialize-lock") == 0) {
						s_main_context->m_use_serialize_lock = 1;
					}
					else if(strcmp(sg_options[s_option_index].name, "thread-pool") == 0) {
						char *s_endptr;
						long s_value;
						errno = 0;
						s_value = strtol(optarg, &s_endptr, 10);
						if((errno != 0) || (s_endptr == optarg) || (*s_endptr != '\0') || (s_value <= 0L) || (s_value > 4096L)) {
							(void)SSL_inspection_fprintf(stderr, "invalid option value \"%s\" !\n", sg_options[s_option_index].name);
							s_main_context->m_is_help = 1;
						}
						else {
							s_main_context->m_max_thread_pool = (unsigned int)s_value;
						}
					}
					else if(strcmp(sg_options[s_option_index].name, "nossl") == 0) {
						s_main_context->m_use_ssl = 0;
					}
					else if(strcmp(sg_options[s_option_index].name, "ktls") == 0) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
						s_main_context->m_use_ktls = 1;
#else
						(void)SSL_inspection_fprintf(stderr, "WARNING: --ktls requires OpenSSL 3.x+, ignored\n");
#endif
					}
					else if(strcmp(sg_options[s_option_index].name, "splice") == 0) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
						s_main_context->m_use_splice = 1;
						s_main_context->m_use_ktls = 1; /* --splice implies --ktls */
#else
						(void)SSL_inspection_fprintf(stderr, "WARNING: --splice requires OpenSSL 3.x+, ignored\n");
#endif
					}
					else if(strcmp(sg_options[s_option_index].name, "tproxy") == 0) {
						s_main_context->m_use_tproxy = 1;
					}
					else if(strcmp(sg_options[s_option_index].name, "auto-detect-tls") == 0) {
						s_main_context->m_use_auto_detect_tls = 1;
					}
					else if(strcmp(sg_options[s_option_index].name, "peek-timeout") == 0) {
						char *s_endptr;
						long s_value;
						errno = 0;
						s_value = strtol(optarg, &s_endptr, 10);
						if((errno != 0) || (s_endptr == optarg) || (*s_endptr != '\0') || (s_value <= 0L) || (s_value > 3600000L)) {
							(void)SSL_inspection_fprintf(stderr, "invalid option value \"%s\" !\n", sg_options[s_option_index].name);
							s_main_context->m_is_help = 1;
						}
						else {
							s_main_context->m_peek_timeout_ms = (uint32_t)s_value;
						}
					}
					else if(strcmp(sg_options[s_option_index].name, "provider") == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
						if(s_main_context->m_provider_count < (size_t)def_SSL_inspection_max_providers) {
							s_main_context->m_provider_names[s_main_context->m_provider_count++] = optarg;
						}
						else {
							(void)SSL_inspection_fprintf(stderr, "too many --provider options (max %d)\n", def_SSL_inspection_max_providers);
							s_main_context->m_is_help = 1;
						}
#else
						(void)SSL_inspection_fprintf(stderr, "WARNING: --provider requires OpenSSL 3.x+, ignored\n");
#endif
					}
					else if(strcmp(sg_options[s_option_index].name, "provider-props") == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
						s_main_context->m_provider_props = optarg;
#else
						(void)SSL_inspection_fprintf(stderr, "WARNING: --provider-props requires OpenSSL 3.x+, ignored\n");
#endif
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
				case 'd': s_main_context->m_debug_flags = (unsigned int)strtoul(optarg, (char **)(NULL), 0); break;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
				case 'e': s_main_context->m_engine_name = optarg; break;
#endif
				case 'b': s_main_context->m_bind_address = optarg; break;
				case 'p': {
					char *s_ep; long s_pv;
					errno = 0;
					s_pv = strtol(optarg, &s_ep, 10);
					if((errno != 0) || (s_ep == optarg) || (*s_ep != '\0') || (s_pv < 1L) || (s_pv > 65535L)) {
						(void)SSL_inspection_fprintf(stderr, "invalid port value \"%s\" !\n", optarg);
						s_main_context->m_is_help = 1;
					}
					else {
						s_main_context->m_bind_port = (int)s_pv;
					}
					break;
				}
				case 'l': s_main_context->m_cipher_list = optarg; break;
				case 'c': s_main_context->m_certificate_pathname = optarg; break;
				case 'k': s_main_context->m_privatekey_pathname = optarg; break;
				case 'B': s_main_context->m_connect_address = optarg; s_main_context->m_connect_address_explicit = 1; break;
				case 'P': {
					char *s_ep; long s_pv;
					errno = 0;
					s_pv = strtol(optarg, &s_ep, 10);
					if((errno != 0) || (s_ep == optarg) || (*s_ep != '\0') || (s_pv < 1L) || (s_pv > 65535L)) {
						(void)SSL_inspection_fprintf(stderr, "invalid port value \"%s\" !\n", optarg);
						s_main_context->m_is_help = 1;
					}
					else {
						s_main_context->m_connect_port = (int)s_pv;
					}
					break;
				}
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
				"\t    --multi-listen          : use SO_REUSEPORT so all workers share the same bind port (kernel-level SYN load balancing)\n"
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
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
				"\t    --ktls                  : kernel TLS offload (OpenSSL 3.x+, Linux 6.x+)\n"
				"\t    --splice                : zero-copy relay via splice (requires --ktls)\n"
#endif
				"\t    --tproxy                : transparent proxy mode — original dst obtained from\n"
				"\t                              accepted socket (requires CAP_NET_ADMIN,\n"
				"\t                              iptables TPROXY rule and policy routing)\n"
				"\t                              if -B is also given, self-address is detected\n"
				"\t                              and falls back to -B/-P automatically\n"
				"\t    --auto-detect-tls       : per-connection TLS/TCP auto detection;\n"
				"\t                              connect server immediately then peek client first bytes;\n"
				"\t                              TLS ClientHello → SSL MITM, otherwise → plain TCP relay\n"
				"\t    --peek-timeout=<ms>     : server-speaks-first fallback timeout (default: 3000ms)\n"
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
				"\t    --provider=<name>       : load OpenSSL 3.x provider (repeatable,\n"
				"\t                              e.g. --provider default --provider qatprovider)\n"
				"\t                              \"default\" is always loaded as SW fallback\n"
				"\t    --provider-props=<str>  : EVP property query string for operation routing\n"
				"\t                              (e.g. --provider-props '?provider=qatprovider')\n"
#endif
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

	/* --auto-detect-tls 옵션 검증 */
	if(s_main_context->m_use_auto_detect_tls != 0) {
		if(s_main_context->m_use_ssl == 0) {
			(void)SSL_inspection_fprintf(stderr,
				"ERROR: --auto-detect-tls requires SSL mode (do not use --nossl)\n");
			return(EXIT_FAILURE);
		}
	}

	(void)SSL_inspection_fprintf(
		stdout,
		def_hwport_color_green "Initializing SSL-Inspection%s%s%s%s" def_hwport_color_normal " ... (pid=%d, cpu_count=%d, debug_flags=%08XH, bind=\"[%s]:%d\", connect=\"[%s]:%d\", buffer-size=%lu, async=%s"
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
		", engine=\"%s\""
#endif
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
		", ktls=%s, splice=%s"
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		", providers=%zu, provider-props=\"%s\""
#endif
		", tproxy=%s"
		")\n"
		"\n",
		(s_main_context->m_use_ssl == 0) ? "" : " with OpenSSL",
		(s_main_context->m_use_ktls > 0) ? "+kTLS" : "",
		(s_main_context->m_use_splice > 0) ? "+splice" : "",
		(s_main_context->m_use_tproxy > 0) ? "+tproxy" : "",
		(int)s_main_context->m_pid,
		s_main_context->m_cpu_count,
		s_main_context->m_debug_flags,
		s_main_context->m_bind_address,
		s_main_context->m_bind_port,
		s_main_context->m_connect_address,
		s_main_context->m_connect_port,
		(unsigned long)s_main_context->m_buffer_size,
		(s_main_context->m_use_ssl == 0) ? "n/a" : ((s_main_context->m_use_async > 0) ? "on" : "off"),
#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
		(s_main_context->m_engine_name == ((const char *)(NULL))) ? "<default>" : s_main_context->m_engine_name,
#endif
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
		(s_main_context->m_use_ktls > 0) ? "on" : "off",
		(s_main_context->m_use_splice > 0) ? "on" : "off",
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		s_main_context->m_provider_count,
		(s_main_context->m_provider_props != NULL) ? s_main_context->m_provider_props : "",
#endif
		(s_main_context->m_use_tproxy > 0) ? "on" : "off"
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
			else {
				SSL_inspection_perror("setrlimit RLIMIT_NOFILE");
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

				/* M-6: ENGINE_finish() deferred to cleanup; releasing functional ref here
				 * would allow the engine to be unloaded while still in use by OpenSSL. */
				}
			}
		}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		if(s_main_context->m_provider_count > (size_t)0u) {
			size_t s_pi;

			/* Explicit provider loading disables implicit "default" activation.
			 * Always load "default" first so SW fallback (AES-GCM, SHA, RSA, …)
			 * remains available even when hardware providers take priority. */
			s_main_context->m_provider_default = OSSL_PROVIDER_load(NULL, "default");
			if(SSL_inspection_unlikely(s_main_context->m_provider_default == NULL)) {
				(void)fflush(stdout);
				(void)SSL_inspection_fprintf(stderr, "Failed to load provider: \"default\" (SW fallback)!\n");
				s_main_context->m_exit_code = EXIT_FAILURE;
				goto l_return;
			}
			if(s_main_context->m_is_verbose >= 0) {
				(void)SSL_inspection_fprintf(stdout, "Loaded provider: \"default\" (SW fallback)\n");
			}

			for(s_pi = (size_t)0u; s_pi < s_main_context->m_provider_count; s_pi++) {
				const char *s_pname = s_main_context->m_provider_names[s_pi];
				if(strcmp(s_pname, "default") == 0) {
					/* reuse the handle already loaded above */
					s_main_context->m_providers[s_pi] = s_main_context->m_provider_default;
					continue;
				}
				if(s_main_context->m_is_verbose >= 0) {
					(void)SSL_inspection_fprintf(stdout, "Loading provider: \"%s\"\n", s_pname);
					(void)fflush(stdout);
				}
				s_main_context->m_providers[s_pi] = OSSL_PROVIDER_load(NULL, s_pname);
				if(SSL_inspection_unlikely(s_main_context->m_providers[s_pi] == NULL)) {
					(void)SSL_inspection_fprintf(stderr, "Failed to load provider: \"%s\"!\n", s_pname);
					s_main_context->m_exit_code = EXIT_FAILURE;
					goto l_return;
				}
				if(s_main_context->m_is_verbose >= 0) {
					(void)SSL_inspection_fprintf(stdout, "Loaded provider: \"%s\"\n", s_pname);
				}
			}
		}

		if(s_main_context->m_provider_props != NULL) {
			if(SSL_inspection_unlikely(EVP_set_default_properties(NULL, s_main_context->m_provider_props) <= 0)) {
				(void)fflush(stdout);
				(void)SSL_inspection_fprintf(stderr, "EVP_set_default_properties(\"%s\") failed!\n", s_main_context->m_provider_props);
				s_main_context->m_exit_code = EXIT_FAILURE;
				goto l_return;
			}
			if(s_main_context->m_is_verbose >= 0) {
				(void)SSL_inspection_fprintf(stdout, "EVP default properties: \"%s\"\n", s_main_context->m_provider_props);
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
			/* Setup CA key+cert + global cert cache (must precede SSL_CTX creation) */
			if(SSL_inspection_unlikely(ssl_inspection_setup_ca(s_main_context) != 0)) {
				(void)SSL_inspection_fprintf(stderr, "CA setup failed !\n");
				s_main_context->m_exit_code = EXIT_FAILURE;
				goto l_return;
			}

			/* Global server SSL_CTX: uses CA cert as no-SNI fallback */
			s_main_context->m_ssl_ctx = SSL_inspection_new_SSL_CTX(s_main_context, 1 /* server side */, NULL);
			if(SSL_inspection_unlikely(s_main_context->m_ssl_ctx == ((SSL_CTX *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "SSL_inspection_new_SSL_CTX failed !\n");
				s_main_context->m_exit_code = EXIT_FAILURE;
				goto l_return;
			}
			s_main_context->m_client_ssl_ctx = SSL_inspection_new_SSL_CTX(s_main_context, 0 /* client side */, NULL);
			if(SSL_inspection_unlikely(s_main_context->m_client_ssl_ctx == ((SSL_CTX *)(NULL)))) {
				(void)SSL_inspection_fprintf(stderr, "SSL_inspection_new_SSL_CTX failed ! (client)\n");
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
	if(s_check == (-1)) {
		/* IP 변환 실패 → getaddrinfo 로 호스트명 해석 */
		struct addrinfo  s_hints;
		struct addrinfo *s_res;
		char             s_port_str[8];

		(void)memset(&s_hints, 0, sizeof(s_hints));
		s_hints.ai_family   = AF_UNSPEC;
		s_hints.ai_socktype = SOCK_STREAM;
		s_hints.ai_flags    = AI_ADDRCONFIG | AI_NUMERICSERV;
		(void)snprintf(s_port_str, sizeof(s_port_str), "%d", s_main_context->m_connect_port);
		s_check = getaddrinfo(s_main_context->m_connect_address, s_port_str, &s_hints, &s_res);
		if(SSL_inspection_unlikely(s_check != 0)) {
			(void)SSL_inspection_fprintf(stderr, "getaddrinfo \"%s\": %s\n",
				s_main_context->m_connect_address, gai_strerror(s_check));
			s_main_context->m_exit_code = EXIT_FAILURE;
			goto l_return;
		}
		(void)memcpy(&s_main_context->m_sockaddr_connect, s_res->ai_addr, s_res->ai_addrlen);
		s_main_context->m_socklen_connect = (socklen_t)s_res->ai_addrlen;
		freeaddrinfo(s_res);
		s_check = 0;
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
				if(s_worker_index == 0u) {
					goto l_return;
				}
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
			def_hwport_color_green "Ready SSL-Inspection%s%s%s%s" def_hwport_color_normal " ... (\"[%s]:%d\", backlog=%d, thread-pool=%u, async=%s"
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
			", ktls=%s, splice=%s"
#endif
			", tproxy=%s"
			")\n"
			"\n",
			(s_main_context->m_use_ssl == 0) ? "" : " with OpenSSL",
			(s_main_context->m_use_ktls > 0) ? "+kTLS" : "",
			(s_main_context->m_use_splice > 0) ? "+splice" : "",
			(s_main_context->m_use_tproxy > 0) ? "+tproxy" : "",
			s_main_context->m_bind_address,
			s_main_context->m_bind_port,
			(int)def_SSL_inspection_backlog,
			(unsigned int)s_main_context->m_max_thread_pool,
			(s_main_context->m_use_ssl == 0) ? "n/a" : ((s_main_context->m_use_async > 0) ? "on" : "off")
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
			,(s_main_context->m_use_ktls > 0) ? "on" : "off"
			,(s_main_context->m_use_splice > 0) ? "on" : "off"
#endif
			,(s_main_context->m_use_tproxy > 0) ? "on" : "off"
		);

		++s_main_context->m_end_print;

	}

	if((s_main_context->m_use_tproxy != 0) && (s_main_context->m_is_verbose >= 1)) {
		const char *s_tproxy_bind   = s_main_context->m_bind_address;
		int         s_tproxy_lport  = s_main_context->m_bind_port;
		const char *s_tproxy_dst    = s_main_context->m_connect_address;
		int         s_tproxy_dport  = s_main_context->m_connect_port;
		int         s_tproxy_is_ip6 = (strchr(s_tproxy_bind, ':') != ((char *)(NULL))) ? 1 : 0;
		const char *s_ipt           = s_tproxy_is_ip6 ? "ip6tables" : "iptables";
		const char *s_ip_rule       = s_tproxy_is_ip6 ? "ip -6 rule" : "ip rule";
		const char *s_ip_route      = s_tproxy_is_ip6 ? "ip -6 route" : "ip route";
		const char *s_ip_local      = s_tproxy_is_ip6 ? "::/0" : "0.0.0.0/0";
		const char *s_fw_family     = s_tproxy_is_ip6 ? "ipv6" : "ipv4";

		(void)SSL_inspection_fprintf(stdout,
			def_hwport_color_yellow "[TPROXY hint]" def_hwport_color_normal
			" Suggested mangle rules (bind=[%s]:%d, connect=[%s]:%d):\n"
			"\n"
			"  " def_hwport_color_white "# 1. Policy routing (one-time):" def_hwport_color_normal "\n"
			"  %s add fwmark 0x1/0x1 lookup 100\n"
			"  %s add local %s dev lo table 100\n"
			"\n"
			"  " def_hwport_color_white "# 2. iptables:" def_hwport_color_normal "\n",
			s_tproxy_bind, s_tproxy_lport,
			s_tproxy_dst, s_tproxy_dport,
			s_ip_rule, s_ip_route, s_ip_local
		);

		if(s_main_context->m_connect_address_explicit != 0) {
			(void)SSL_inspection_fprintf(stdout,
				"  %s -t mangle -A PREROUTING -p tcp -d %s --dport %d"
				" -j TPROXY --tproxy-mark 0x1/0x1 --on-port %d --on-ip %s\n",
				s_ipt, s_tproxy_dst, s_tproxy_dport, s_tproxy_lport, s_tproxy_bind
			);
		}
		else {
			(void)SSL_inspection_fprintf(stdout,
				"  %s -t mangle -A PREROUTING -p tcp --dport %d"
				" -j TPROXY --tproxy-mark 0x1/0x1 --on-port %d --on-ip %s\n",
				s_ipt, s_tproxy_dport, s_tproxy_lport, s_tproxy_bind
			);
		}

		(void)SSL_inspection_fprintf(stdout,
			"\n"
			"  " def_hwport_color_white "# 3. firewalld (--direct):" def_hwport_color_normal "\n"
			"  firewall-cmd --permanent --direct --add-rule %s mangle PREROUTING 0 \\\n",
			s_fw_family
		);

		if(s_main_context->m_connect_address_explicit != 0) {
			(void)SSL_inspection_fprintf(stdout,
				"    -p tcp -d %s --dport %d"
				" -j TPROXY --tproxy-mark 0x1/0x1 --on-port %d --on-ip %s\n"
				"  firewall-cmd --reload\n"
				"\n",
				s_tproxy_dst, s_tproxy_dport, s_tproxy_lport, s_tproxy_bind
			);
		}
		else {
			(void)SSL_inspection_fprintf(stdout,
				"    -p tcp --dport %d"
				" -j TPROXY --tproxy-mark 0x1/0x1 --on-port %d --on-ip %s\n"
				"  firewall-cmd --reload\n"
				"\n",
				s_tproxy_dport, s_tproxy_lport, s_tproxy_bind
			);
		}
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
		{
			int s_wakeup_result;
			s_wakeup_result = pthread_mutex_lock((pthread_mutex_t *)(&s_main_context->m_session_queue_lock));
			if(SSL_inspection_unlikely(s_wakeup_result != 0)) {
				(void)SSL_inspection_fprintf(stderr, "wakeup joinable threads: pthread_mutex_lock (%d)\n", s_wakeup_result);
			}
			(void)pthread_cond_broadcast((pthread_cond_t *)(&s_main_context->m_session_queue_cond));
			s_wakeup_result = pthread_mutex_unlock((pthread_mutex_t *)(&s_main_context->m_session_queue_lock));
			if(SSL_inspection_unlikely(s_wakeup_result != 0)) {
				(void)SSL_inspection_fprintf(stderr, "wakeup joinable threads: pthread_mutex_unlock (%d)\n", s_wakeup_result);
			}
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

		/* Global cert cache: destroy AFTER all workers have joined (and freed local caches).
		 * Any SSL_CTX created from cached certs has already been freed with its sessions. */
		if(s_main_context->m_cert_cache != ((ssl_cert_cache_global_t *)(NULL))) {
			ssl_cert_cache_global_destroy(s_main_context->m_cert_cache);
			s_main_context->m_cert_cache = (ssl_cert_cache_global_t *)(NULL);
		}
		if(s_main_context->m_ca_x509 != ((X509 *)(NULL))) {
			X509_free(s_main_context->m_ca_x509);
			s_main_context->m_ca_x509 = (X509 *)(NULL);
		}
		if(s_main_context->m_ca_pkey != ((EVP_PKEY *)(NULL))) {
			EVP_PKEY_free(s_main_context->m_ca_pkey);
			s_main_context->m_ca_pkey = (EVP_PKEY *)(NULL);
		}

		if(s_main_context->m_client_ssl_ctx != ((SSL_CTX *)(NULL))) {
			SSL_CTX_free(s_main_context->m_client_ssl_ctx);
			s_main_context->m_client_ssl_ctx = (SSL_CTX *)(NULL);
		}

		SSL_CTX_free(s_main_context->m_ssl_ctx);
		s_main_context->m_ssl_ctx = (SSL_CTX *)(NULL);

#if (OPENSSL_VERSION_NUMBER < 0x30000000L) && !defined(OPENSSL_NO_ENGINE)
		if(s_main_context->m_engine != ((ENGINE *)(NULL))) {
			ENGINE_finish(s_main_context->m_engine); /* M-6: release functional ref before structural */
			ENGINE_free(s_main_context->m_engine);
			s_main_context->m_engine = (ENGINE *)(NULL);
		}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		{
			size_t s_pi;
			for(s_pi = (size_t)0u; s_pi < s_main_context->m_provider_count; s_pi++) {
				if((s_main_context->m_providers[s_pi] != NULL) &&
				   (s_main_context->m_providers[s_pi] != s_main_context->m_provider_default)) {
					OSSL_PROVIDER_unload(s_main_context->m_providers[s_pi]);
					s_main_context->m_providers[s_pi] = (OSSL_PROVIDER *)(NULL);
				}
			}
			if(s_main_context->m_provider_default != NULL) {
				OSSL_PROVIDER_unload(s_main_context->m_provider_default);
				s_main_context->m_provider_default = (OSSL_PROVIDER *)(NULL);
			}
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
