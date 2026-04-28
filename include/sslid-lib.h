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

/* C11 atomic support for thread-safe operations */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)
# include <stdatomic.h>
# define SSL_INSPECTION_HAS_C11_ATOMICS 1
#else
# define SSL_INSPECTION_HAS_C11_ATOMICS 0
#endif

/* ---- */

/* 
   Header include 이전에 정의해야 하는 define 들은 여기에서 정의합니다.
*/

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
#include <sys/epoll.h>
#include <sys/resource.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sched.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <netdb.h>

/* kernel header */

/* library header */

#include <pthread.h>

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/modes.h>
#include <openssl/aes.h>

#include <openssl/md5.h>

#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
# include <openssl/provider.h>
#endif

/* ---- */

#if defined(__GNUC__) && __GNUC__ >= 3L
# define SSL_inspection_likely(m_expression) __builtin_expect((long)(m_expression),1L)
# define SSL_inspection_unlikely(m_expression) __builtin_expect((long)(m_expression),0L)
#else
# define SSL_inspection_likely(m_expression) m_expression
# define SSL_inspection_unlikely(m_expression) m_expression
#endif

#if defined(__GNUC__)
# define SSL_inspection_vsprintf_varg_check(m_format_index,m_varg_index) __attribute__((__format__(__printf__,m_format_index,m_varg_index)))
#else
# define SSL_inspection_vsprintf_varg_check(m_format_index,m_varg_index)
#endif

#define def_SSL_inspection_default_program_name "sslid"

#define def_SSL_inspection_listen_address "0.0.0.0" /* "0.0.0.0" or "::" */
#define def_SSL_inspection_listen_port 8443 /* listen port */

#define def_SSL_inspection_connect_address "1.0.0.1"
#define def_SSL_inspection_connect_port 443

/* Socket buffer sizes (1MB each)
 * Note: Large buffers increase memory usage per connection.
 * Consider reducing for high-connection-count deployments.
 * Set to -1 to use system defaults.
 */
#if 1L
#define def_SSL_inspection_socket_buffer_rx (1u << 20)
#define def_SSL_inspection_socket_buffer_tx (1u << 20)
#else
#define def_SSL_inspection_socket_buffer_rx (-1)
#define def_SSL_inspection_socket_buffer_tx (-1)
#endif

/* backlog: use system maximum or reasonable default
 * Note: actual value is limited by net.core.somaxconn (typically 4096 on modern Linux)
 */
#if 1L
#define def_SSL_inspection_backlog 4096
#else
#define def_SSL_inspection_backlog SOMAXCONN
#endif

#if 1L /* self-signed certificate generate */
# define def_SSL_inspection_default_certificate_pathname ((const char *)(NULL))
# define def_SSL_inspection_default_privatekey_pathname ((const char *)(NULL))
#else
# define def_SSL_inspection_default_certificate_pathname "./cert.pem"
# define def_SSL_inspection_default_privatekey_pathname "./key.pem"
#endif

#if 0L /* TLSv1.2 list */
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
	(const char *)(NULL)
#endif

/* SSL/TLS options: disable deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) */
#define def_SSL_inspection_default_options ( \
    SSL_OP_ALL | \
    SSL_OP_NO_ENCRYPT_THEN_MAC | \
    SSL_OP_NO_SSLv2 | \
    SSL_OP_NO_SSLv3 | \
    SSL_OP_NO_TLSv1 | \
    SSL_OP_NO_TLSv1_1 \
)

#define def_SSL_inspection_debug_flag_none 0x00000000u

#define def_SSL_inspection_buffer_size (1 << 14) /* limited 16KBytes : maximum TLS record size */

#define SSL_inspection_main_context_t __SSL_inspection_main_context_t
typedef struct SSL_inspection_main_context_ts __SSL_inspection_main_context_t;
#define SSL_inspection_session_t __SSL_inspection_session_t
typedef struct SSL_inspect_session_ts __SSL_inspection_session_t;
#define SSL_inspection_worker_context_t __SSL_inspection_worker_context_t
typedef struct SSL_inspection_worker_context_ts __SSL_inspection_worker_context_t;
#define SSL_inspection_epoll_item_t __SSL_inspection_epoll_item_t
typedef struct SSL_inspection_epoll_item_ts __SSL_inspection_epoll_item_t;
#define SSL_inspection_async_wait_t __SSL_inspection_async_wait_t
typedef struct SSL_inspection_async_wait_ts __SSL_inspection_async_wait_t;

#define def_SSL_inspection_session_flag_none 0u
#define def_SSL_inspection_session_flag_accepted (1u << 0) /* accept 유효 상태 */
#define def_SSL_inspection_session_flag_connected (1u << 1) /* connect 유효 상태 */
#define def_SSL_inspection_session_flag_ssl_accepted (1u << 2) /* SSL_accept 유효 상태 */
#define def_SSL_inspection_session_flag_ssl_connected (1u << 3) /* SSL_connect 유효 상태 */
#define def_SSL_inspection_session_flag_tproxy_no_spoof (1u << 4) /* TPROXY fallback 적용: connect 소켓 소스 스푸핑 생략 */

#define def_SSL_inspection_session_state_none 0u
#define def_SSL_inspection_session_state_connecting 1u
#define def_SSL_inspection_session_state_connect_ssl_handshake 2u
#define def_SSL_inspection_session_state_accept_ssl_handshake 3u
#define def_SSL_inspection_session_state_stream 4u
#define def_SSL_inspection_session_state_closing 5u
#define def_SSL_inspection_session_state_peek_client_hello 6u

#define def_SSL_inspection_session_job_flag_none 0u
#define def_SSL_inspection_session_job_flag_enqueued (1u << 0)

#define def_SSL_inspection_epoll_item_type_none 0u
#define def_SSL_inspection_epoll_item_type_listen 1u
#define def_SSL_inspection_epoll_item_type_accept_socket 2u
#define def_SSL_inspection_epoll_item_type_connect_socket 3u
#define def_SSL_inspection_epoll_item_type_accept_async 4u
#define def_SSL_inspection_epoll_item_type_connect_async 5u

#pragma pack(push,8)
struct SSL_inspection_epoll_item_ts {
	SSL_inspection_worker_context_t *m_worker_context;
	SSL_inspection_session_t *m_session;
	OSSL_ASYNC_FD m_fd;
	uint32_t m_events;
	unsigned int m_type;
	int m_is_registered;
};
#pragma pack(pop)

#define def_SSL_inspection_async_wait_inline_capacity 4

#pragma pack(push,8)
struct SSL_inspection_async_wait_ts {
	SSL_inspection_epoll_item_t *m_epoll_items;
	OSSL_ASYNC_FD *m_fds;
	size_t m_count;
	/* inline scratch avoids heap allocation when async FD count ≤ capacity */
	SSL_inspection_epoll_item_t m_inline_epoll_items[def_SSL_inspection_async_wait_inline_capacity];
	OSSL_ASYNC_FD m_inline_fds[def_SSL_inspection_async_wait_inline_capacity];
};
#pragma pack(pop)

#pragma pack(push,8)
struct SSL_inspect_session_ts {
	SSL_inspection_session_t *m_next;
	SSL_inspection_session_t *m_prev; /* doubly-linked for O(1) worker-queue unlink */
	SSL_inspection_session_t *m_job_next;

	SSL_inspection_main_context_t *m_main_context;
	SSL_inspection_worker_context_t *m_worker_context;

	unsigned int m_flags; /* def_SSL_inspection_session_flag_XXX */
	unsigned int m_state;
	unsigned int m_job_flags;

	uint32_t m_accept_ready_events;
	uint32_t m_connect_ready_events;
	uint32_t m_accept_epoll_interest;
	uint32_t m_connect_epoll_interest;

	SSL_inspection_epoll_item_t m_accept_epoll_item;
	SSL_inspection_epoll_item_t m_connect_epoll_item;
	SSL_inspection_async_wait_t m_accept_async_wait;
	SSL_inspection_async_wait_t m_connect_async_wait;

	int m_accept_socket;
	int m_accept_socket_flags;
	struct sockaddr_storage m_sockaddr_accept;
	socklen_t m_socklen_accept;
	char m_accept_address_string[ INET6_ADDRSTRLEN ];

	SSL_CTX *m_connect_ssl_ctx;
	int m_connect_socket;
	int m_connect_socket_flags;

	struct sockaddr_storage m_sockaddr_original_dst; /* TPROXY: original destination (getsockname on accepted fd) */
	socklen_t m_socklen_original_dst;

	SSL *m_accept_ssl;
	SSL *m_connect_ssl;

	unsigned long long m_forward_transfer_size;
	unsigned long long m_backward_transfer_size;

	size_t m_forward_pending_offset;
	size_t m_forward_pending_size;
	size_t m_backward_pending_offset;
	size_t m_backward_pending_size;

	size_t m_buffer_size;
	void *m_buffer;
	void *m_dup_buffer; /* for dump */

	/* kTLS offload and splice zero-copy relay */
	int m_ktls_active;             /* -1=not tried, 0=inactive, 1=active */
	int m_fwd_splice_pipe[2];      /* [0]=read [1]=write: accept(rx) → connect(tx) */
	int m_bwd_splice_pipe[2];      /* [0]=read [1]=write: connect(rx) → accept(tx) */
	size_t m_fwd_pipe_pending;     /* bytes in fwd pipe awaiting drain to connect */
	size_t m_bwd_pipe_pending;     /* bytes in bwd pipe awaiting drain to accept */

	SSL_CTX *m_accept_ssl_ctx;     /* per-session accept SSL_CTX (NULL = use global m_ssl_ctx) */
	char m_sni_hostname[256];      /* SNI from ClientHello peek; empty string = no SNI */
};
#pragma pack(pop)

#define def_SSL_inspection_worker_flag_none 0u

#define def_SSL_inspection_max_worker_epoll_events (1 << 10)

#pragma pack(push,8)
struct SSL_inspection_worker_context_ts {
	SSL_inspection_worker_context_t *m_next;

	unsigned int m_flags; /* def_SSL_inspection_worker_flag_XXX */

	unsigned int m_worker_index;
#if defined(def_sslid_use_dpdk_lcore)
	unsigned int m_lcore_id;
#endif
#if SSL_INSPECTION_HAS_C11_ATOMICS
	atomic_int m_running; /* for start sync up : (-1)=not-initial, 0=stopped, 1=started */
#else
	volatile int m_running; /* for start sync up : (-1)=not-initial, 0=stopped, 1=started */
#endif
	int m_thread_created; /* set to 1 after pthread_create succeeds; guards pthread_join in free_worker */

	SSL_inspection_main_context_t *m_main_context;
		
	pthread_attr_t m_pthread_attr;
	pthread_t m_pthread;

	SSL_inspection_session_t *m_session_queue_head; /* worker process session */
	SSL_inspection_session_t *m_session_queue_tail; /* worker process session */
	SSL_inspection_session_t *m_job_queue_head; /* worker ready job session */
	SSL_inspection_session_t *m_job_queue_tail; /* worker ready job session */
	size_t m_session_queue_count;

	int m_max_epoll_events;
	int m_epoll_fd;
	struct epoll_event m_epoll_event;
	struct epoll_event *m_epoll_events;
	
	int m_listen_socket;
	SSL_inspection_epoll_item_t m_listen_epoll_item;
	struct sockaddr_storage m_sockaddr_listen_bind;
	socklen_t m_socklen_listen_bind;

	unsigned long long m_forward_transfer_size;
	unsigned long long m_backward_transfer_size;
};
#pragma pack(pop)

#pragma pack(push,8)
struct SSL_inspection_main_context_ts {
	unsigned int m_magic_code_begin; /* main context 가 깨졌는지 확인 용 */

	const char *m_program_name;

	int m_is_help;
	int m_is_verbose;
	const char *m_engine_name;
	unsigned int m_debug_flags;
	const char *m_bind_address;
	int m_bind_port;
	int m_use_multi_listen;
	const char *m_cipher_list;
	const char *m_certificate_pathname;
	const char *m_privatekey_pathname;
	int m_use_async;
	const char *m_connect_address;
	int m_connect_port;
	size_t m_buffer_size;
	int m_thread_model;
	unsigned int m_max_thread_pool;
	int m_use_ssl;
	int m_use_ktls;   /* --ktls: kernel TLS offload (OpenSSL 3.x+, Linux 6.x+) */
	int m_use_splice; /* --splice: zero-copy relay via splice (requires --ktls) */
	int m_use_tproxy;             /* --tproxy: transparent proxy (iptables TPROXY rule + policy routing required) */
	int m_connect_address_explicit; /* -B was given explicitly: enables TPROXY fallback to -B/-P on self-address */

	pid_t m_pid;
	int m_cpu_count;
	int m_exit_code;
	int m_end_print;

	int m_use_serialize_lock;
	pthread_mutex_t m_serialize_lock;
	pthread_cond_t m_session_queue_cond;
	pthread_mutex_t m_session_queue_lock;
	SSL_inspection_session_t *m_session_queue_head;
	SSL_inspection_session_t *m_session_queue_tail;
	size_t m_session_queue_count;
#if SSL_INSPECTION_HAS_C11_ATOMICS
	atomic_int m_is_enqueued; /* atomic access for thread-safe check without mutex */
#else
	volatile int m_is_enqueued; /* fallback: volatile (not fully thread-safe) */
#endif
	unsigned long long m_enqueued_session_count;
	unsigned long long m_dequeued_session_count;
	
	SSL_inspection_worker_context_t *m_worker_context_head;
	SSL_inspection_worker_context_t *m_worker_context_main;

#if !defined(OPENSSL_NO_ENGINE)
	ENGINE *m_engine;
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	unsigned long m_ssl_options;
#else
	long m_ssl_options;
#endif
	const SSL_METHOD *m_server_ssl_method;
	const SSL_METHOD *m_client_ssl_method;
	SSL_CTX *m_ssl_ctx;
	SSL_CTX *m_client_ssl_ctx; /* shared client-side SSL_CTX, reused via SSL_new() per session */

	struct sockaddr_storage m_sockaddr_connect_bind;
	socklen_t m_socklen_connect_bind;
	struct sockaddr_storage m_sockaddr_connect;
	socklen_t m_socklen_connect;

	unsigned int m_magic_code_end; /* main context 가 깨졌는지 확인 용 */
};
#pragma pack(pop)

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

#if 0L
# define def_SSL_inspection_recv_flags 0
# define def_SSL_inspection_send_flags 0
#else
# define def_SSL_inspection_recv_flags MSG_NOSIGNAL
# define def_SSL_inspection_send_flags MSG_NOSIGNAL
#endif

#if !defined(__def_sslid_source_sslid_lib_c__)
/* Secure memory clearing - immune to compiler optimization */
extern void SSL_inspection_secure_memzero(void *ptr, size_t size);

extern int SSL_inspection_ratelimited_message_check(void);
extern void SSL_inspection_perror(const char *s_prefix_message);
extern int SSL_inspection_fprintf(FILE *s_stream, const char *s_format, ...) SSL_inspection_vsprintf_varg_check(2,3);

extern char *SSL_inspection_cpuset_to_string(char *s_string, size_t s_limit_size, cpu_set_t *s_cpuset);

extern unsigned long long SSL_inspection_get_time_stamp_msec(void);
extern int SSL_inspection_msleep(int s_timeout_msec);

extern void *SSL_inspection_increment_be_block(void *s_bigint_ptr, size_t s_size);
extern void *SSL_inspection_xor_block(void *s_to_ptr, const void *s_from_ptr, size_t s_size);
extern void *SSL_inspection_right_shift_block(void *s_block_ptr, size_t s_size);

extern int SSL_inspection_is_printable_ascii(int s_charactor, int s_is_level);
extern void *SSL_inspection_convert_printable_ascii(void *s_to, const void *s_from, size_t s_size);
extern const void *SSL_inspection_hexdump(const char *s_prefix, const void *s_data, size_t s_size);

extern void SSL_inspection_dump_backtrace(void);

extern int SSL_inspection_string_to_sockaddr(int s_family, const char *s_address, int s_port, void *s_sockaddr_ptr, socklen_t *s_socklen_ptr);

extern int SSL_inspection_set_keepalive_socket(int s_socket, int s_is_enable, int s_keepidle_sec, int s_keepintvl_sec);
extern int SSL_inspection_set_linger_socket(int s_socket, int s_is_enable, int s_sec);
extern int SSL_inspection_set_reuse_address_socket(int s_socket, int s_is_enable);
extern int SSL_inspection_set_reuse_port_socket(int s_socket, int s_is_enable);
extern int SSL_inspection_set_naggle_socket(int s_socket, int s_is_enable);
extern int SSL_inspection_set_transparent_socket(int s_socket, int s_is_enable);
extern int SSL_inspection_set_freebind_socket(int s_socket, int s_is_enable);
extern int SSL_inspection_set_tx_socket_buffer_size(int s_socket, size_t s_size);
extern int SSL_inspection_set_rx_socket_buffer_size(int s_socket, size_t s_size);

extern int SSL_inspection_is_readable(int s_socket, int s_timeout_msec);
extern int SSL_inspection_is_writable(int s_socket, int s_timeout_msec);
extern void SSL_inspection_wait_for_async(SSL *s_ssl);

extern int SSL_inspection_shutdown(SSL *s_ssl);

extern int SSL_inspection_closefd(int s_fd);
extern int SSL_inspection_closesocket(int s_socket);

extern ssize_t SSL_inspection_recv(SSL *s_ssl, int s_socket, void *s_data, size_t s_size, int s_timeout_msec);
extern ssize_t SSL_inspection_send(SSL *s_ssl, int s_socket, const void *s_data, size_t s_size, int s_timeout_msec);

extern ssize_t SSL_inspection_recv_fill(SSL *s_ssl, int s_socket, void *s_data, size_t s_size, int s_timeout_msec);
extern ssize_t SSL_inspection_send_fill(SSL *s_ssl, int s_socket, const void *s_data, size_t s_size, int s_timeout_msec);

extern SSL *SSL_inspection_ssl_do_handshake(SSL_CTX *s_ssl_ctx, int s_socket, int s_timeout_msec, int s_is_accept);
extern int SSL_inspection_connect(int s_socket, const void *s_sockaddr_ptr, socklen_t s_socklen, int s_timeout_msec);

extern ssize_t SSL_inspection_encrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_plaintext, size_t s_plaintext_size, const void *s_aad, size_t s_aad_size, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_ciphertext, void *s_tag);
extern ssize_t SSL_inspection_decrypt_AES_GCM(const EVP_CIPHER *s_cipher, const void *s_ciphertext, size_t s_ciphertext_size, const void *s_aad, size_t s_aad_size, const void *s_tag, const void *s_key, const void *s_iv, size_t s_iv_size, void *s_plaintext);
#endif

/* ---- */

#if !defined(__def_sslid_source_test_vector_c__)
# if defined(def_sslid_test_vector)
extern int SSL_inspection_sha256_test0(int s_is_verbose);

extern int SSL_inspection_hmac_sha256_test0(int s_is_verbose);
extern int SSL_inspection_hmac_sha256_test1(int s_is_verbose);

extern int SSL_inspection_pseudo_random_function_tlsv1_2_sha256_test0(int s_is_verbose);

extern int SSL_inspection_evp_test0(int s_is_verbose);
extern int SSL_inspection_evp_test1(int s_is_verbose);

extern int SSL_inspection_internal_impl_test0(int s_is_verbose);
# endif
#endif

/* ---- */

#if !defined(__def_sslid_source_signal_handler_c__)
extern void SSL_inspection_break_main_loop(void);
extern int SSL_inspection_is_break_main_loop(void);

extern int SSL_inspection_install_signal_handler(void);
#endif

/* ---- */

#if !defined(__def_sslid_source_main_c__)
extern SSL_inspection_session_t *SSL_inspection_new_and_accept_session(SSL_inspection_main_context_t *s_main_context, int s_listen_socket);
extern SSL_inspection_session_t *SSL_inspection_free_session(SSL_inspection_session_t *s_session);
extern SSL_inspection_session_t *SSL_inspection_free_session_list(SSL_inspection_session_t *s_session_list);

extern size_t SSL_inspection_enqueue_session_list(SSL_inspection_main_context_t *s_main_context, SSL_inspection_session_t *s_session_list);
extern size_t SSL_inspection_dequeue_session_list(SSL_inspection_main_context_t *s_main_context, size_t s_request_session_count, SSL_inspection_session_t **s_session_head_ptr, SSL_inspection_session_t **s_session_tail_ptr, int s_timeout_msec);

extern SSL_CTX *SSL_inspection_new_SSL_CTX(SSL_inspection_main_context_t *s_main_context, int s_is_server_side, const char *s_hostname);

extern size_t SSL_inspection_checkout_worker_session(SSL_inspection_worker_context_t *s_worker_context, size_t s_request_session_count, int s_timeout_msec);

extern int SSL_inspection_add_worker(SSL_inspection_main_context_t *s_main_context, unsigned int s_worker_index, unsigned int s_flags);
extern SSL_inspection_worker_context_t *SSL_inspection_free_worker(SSL_inspection_worker_context_t *s_worker_context);

extern int SSL_inspection_do_session_event(SSL_inspection_worker_context_t *s_worker_context, SSL_inspection_session_t *s_session, struct epoll_event *s_epoll_event, int s_epoll_session_type);
extern void *SSL_inspection_worker_handler(void *s_context_ptr);
#endif

/* ---- */

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
