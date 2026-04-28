/*
    Copyright (C) MINZKN.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_signal_handler_c__)
# define __def_sslid_source_signal_handler_c__ "signal-handler.c"

/* ---- */

#include "sslid-lib.h"

#include <signal.h>
#include <execinfo.h>

#if defined(def_sslid_use_dpdk_lcore)
# include <rte_lcore.h>
#endif

/* ---- */

void SSL_inspection_break_main_loop(void);
int SSL_inspection_is_break_main_loop(void);

static void SSL_inspection_signal_handler(int s_signo);

int SSL_inspection_install_signal_handler(void);

/* ---- */

static volatile int g_SSL_inspection_break = 0;
static volatile int g_SSL_inspection_critical = 0;

/* ---- */

void SSL_inspection_break_main_loop(void)
{
	*((volatile int *)(&g_SSL_inspection_break)) = 1;
}

int SSL_inspection_is_break_main_loop(void)
{
	return(*((volatile int *)(&g_SSL_inspection_break)));
}

/*
 * Signal-safe backtrace helper.
 * Uses only async-signal-safe functions: backtrace(), backtrace_symbols_fd(),
 * write().  Must NOT call backtrace_symbols() (malloc) or fprintf (stdio lock).
 */
static void SSL_inspection_signal_safe_backtrace(void)
{
	void *s_bt[16];
	int s_bt_size;
	static const char cg_bt_hdr[] = "backtrace:\n";

	s_bt_size = backtrace(s_bt, (int)(sizeof(s_bt) / sizeof(void *)));
	(void)write(STDERR_FILENO, cg_bt_hdr, sizeof(cg_bt_hdr) - 1);
	if (s_bt_size > 0) {
		backtrace_symbols_fd(s_bt, s_bt_size, STDERR_FILENO);
	}
}

static void SSL_inspection_signal_handler(int s_signo)
{
	static const char cg_signal_msg[] = "\nsignal: fatal signal received\n";
	static const char cg_quit_msg[]   = "\nsignal: quit/break requested\n";

	switch(s_signo) {
		case SIGSEGV:
		case SIGILL:
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
		case SIGABRT:
			(void)write(STDERR_FILENO, cg_signal_msg, sizeof(cg_signal_msg) - 1);
			if((*((volatile int *)(&g_SSL_inspection_critical))) != 0) {
				_exit(128 | s_signo);
			}
			*((volatile int *)(&g_SSL_inspection_critical)) = 1;
			SSL_inspection_signal_safe_backtrace();
			SSL_inspection_break_main_loop();
			_exit(128 | s_signo);
			break;
		case SIGQUIT: /* 강제 종료 */
		case SIGINT: /* Ctrl + C */
		case SIGTERM:
			(void)write(STDERR_FILENO, cg_quit_msg, sizeof(cg_quit_msg) - 1);
			if((*((volatile int *)(&g_SSL_inspection_critical))) != 0) {
				_exit(128 | s_signo);
			}
			if((s_signo == SIGQUIT) || (SSL_inspection_is_break_main_loop() != 0)) {
				SSL_inspection_signal_safe_backtrace();
			}
			SSL_inspection_break_main_loop();
			if(s_signo == SIGQUIT) {
				_exit(128 | s_signo);
			}
			break;
		case SIGHUP: /* reload */
		case SIGPIPE: /* broken pipe ! */
		default:
			break;
	}
	/* No signal() reinstall needed: sigaction(SA_RESTART) in install function
	 * keeps the handler persistent without SA_RESETHAND race. */
}

int SSL_inspection_install_signal_handler(void)
{
	struct sigaction sa;

	(void)memset((void *)(&sa), 0, sizeof(sa));
	sa.sa_handler = SSL_inspection_signal_handler;
	(void)sigemptyset(&sa.sa_mask);
	/* SA_RESTART: restart interrupted syscalls automatically.
	 * Omitting SA_RESETHAND: handler stays installed (no reinstall race). */
	sa.sa_flags = SA_RESTART;

	/* critical */
	(void)sigaction(SIGSEGV,  &sa, (struct sigaction *)(NULL));
	(void)sigaction(SIGILL,   &sa, (struct sigaction *)(NULL));
	(void)sigaction(SIGABRT,  &sa, (struct sigaction *)(NULL));
	(void)sigaction(SIGFPE,   &sa, (struct sigaction *)(NULL));
#if defined(SIGBUS)
	(void)sigaction(SIGBUS,   &sa, (struct sigaction *)(NULL));
#endif
#if defined(SIGSTKFLT)
	(void)sigaction(SIGSTKFLT, &sa, (struct sigaction *)(NULL));
#endif
#if defined(SIGPWR)
	(void)sigaction(SIGPWR,   &sa, (struct sigaction *)(NULL));
#endif
#if defined(SIGSYS)
	(void)sigaction(SIGSYS,   &sa, (struct sigaction *)(NULL));
#endif

	/* terminate */
	(void)sigaction(SIGQUIT,  &sa, (struct sigaction *)(NULL));
	(void)sigaction(SIGINT,   &sa, (struct sigaction *)(NULL));
	(void)sigaction(SIGTERM,  &sa, (struct sigaction *)(NULL));

	/* ignore */
	(void)sigaction(SIGHUP,   &sa, (struct sigaction *)(NULL));
	(void)sigaction(SIGPIPE,  &sa, (struct sigaction *)(NULL));

	return(0);
}

/* ---- */

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
