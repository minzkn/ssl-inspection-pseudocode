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

/* ---- */

void SSL_inspection_break_main_loop(void);
int SSL_inspection_is_break_main_loop(void);

static void SSL_inspection_signal_handler(int s_signo);

int SSL_inspection_install_signal_handler(void);

/* ---- */

static volatile int g_SSL_inspection_break = 0;

/* ---- */

void SSL_inspection_break_main_loop(void)
{
	*((volatile int *)(&g_SSL_inspection_break)) = 1;
}

int SSL_inspection_is_break_main_loop(void)
{
	return(*((volatile int *)(&g_SSL_inspection_break)));
}

static void SSL_inspection_signal_handler(int s_signo)
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
			(void)fprintf(stderr, def_hwport_color_normal "\n%s : Signal happened(%d) => ERROR\n", __func__, s_signo);
			SSL_inspection_dump_backtrace();
			SSL_inspection_break_main_loop();
			_exit(128 | s_signo);
			break;
		case SIGQUIT: /* 강제 종료 */
		case SIGINT: /* Ctrl + C */
		case SIGTERM:
			(void)fprintf(stderr, def_hwport_color_normal "\n%s : Signal happened(%d) => TERMINATE\n", __func__, s_signo);
			if(s_signo == SIGQUIT) {
				SSL_inspection_dump_backtrace();
			}
			SSL_inspection_break_main_loop();
			if(s_signo == SIGQUIT) {
				_exit(128 | s_signo);
			}
			break;
		case SIGHUP: /* reload */
		case SIGPIPE: /* broken pipe ! */
		default:
			/* 단순 발생유무만 확인하는 부분 */
			(void)fprintf(stderr, def_hwport_color_normal "\n%s : Signal happened(%d) => INFO\n", __func__, s_signo);
			SSL_inspection_dump_backtrace();
			break;
	}

	(void)signal(s_signo, SSL_inspection_signal_handler);
}

int SSL_inspection_install_signal_handler(void)
{
	/* critical */
	(void)signal(SIGSEGV, SSL_inspection_signal_handler);
	(void)signal(SIGILL, SSL_inspection_signal_handler);
	(void)signal(SIGABRT, SSL_inspection_signal_handler);
	(void)signal(SIGFPE, SSL_inspection_signal_handler);
#if defined(SIGBUS)
	(void)signal(SIGBUS, SSL_inspection_signal_handler);
#endif
#if defined(SIGSTKFLT)
	(void)signal(SIGSTKFLT, SSL_inspection_signal_handler);
#endif
#if defined(SIGPWR)
	(void)signal(SIGPWR, SSL_inspection_signal_handler);
#endif
#if defined(SIGSYS)
	(void)signal(SIGSYS, SSL_inspection_signal_handler);
#endif

	/* terminate */
	(void)signal(SIGQUIT, SSL_inspection_signal_handler);
	(void)signal(SIGINT, SSL_inspection_signal_handler);
	(void)signal(SIGTERM, SSL_inspection_signal_handler);

	/* ignore */
	(void)signal(SIGHUP, SSL_inspection_signal_handler);
	(void)signal(SIGPIPE, SSL_inspection_signal_handler);

	return(0);
}

/* ---- */

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
