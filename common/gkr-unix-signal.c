/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-unix-signal.c - integrate unix signals into the main loop

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-unix-signal.h"

#include <glib.h>

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------------
 * MAIN LOOP WAKEUP
 */

static int wakeup_fds[2] = { -1, -1 };
static guint wakeup_n = 0;
static GPollFD poll_fd;
static GMainContext *main_ctx;

static void
wakeup_register (GMainContext *ctx)
{
	if (wakeup_n++ == 0) {
		if (pipe (wakeup_fds))
			g_critical ("can't create wakeup pipe: %s", g_strerror (errno));

		/* Non blocking to prevent deadlock */
		fcntl (wakeup_fds[0], F_SETFL, fcntl (wakeup_fds[0], F_GETFL) | O_NONBLOCK);
		fcntl (wakeup_fds[1], F_SETFL, fcntl (wakeup_fds[1], F_GETFL) | O_NONBLOCK);

		/* Register poll fd with main context */
		poll_fd.fd = wakeup_fds[0];
		poll_fd.events = G_IO_IN;
		poll_fd.revents = 0;

		g_main_context_add_poll (ctx, &poll_fd, G_PRIORITY_HIGH_IDLE);
		main_ctx = ctx;
        }

        g_assert (wakeup_fds[0] >= 0);
}
static void

wakeup_unregister (void)
{
	if (--wakeup_n > 0)
		return;

	g_assert (wakeup_fds[0] >= 0);
	close (wakeup_fds[0]);
	wakeup_fds[0] = -1;

	g_assert (wakeup_fds[1] >= 0);
	close (wakeup_fds[1]);
	wakeup_fds[1] = -1;

	g_assert (main_ctx);
	g_main_context_remove_poll (main_ctx, &poll_fd);
	main_ctx = NULL;
}

static void
wakeup_now (void)
{
	#define SIG_MSG "couldn't write signal byte to pipe\n"
	guchar x = 0xAA;
	int res;

	if (wakeup_fds[1] < 0)
		return;

	/* Could be called from a signal handler, so try to not use library functions */
	if (write (wakeup_fds[1], &x, 1) != 1)
		res = write (2, SIG_MSG, strlen (SIG_MSG) - 1);
}

static void
wakeup_drain (void)
{
	guchar x;

	if (wakeup_fds[0] < 0)
		return;

	while (read (wakeup_fds[0], &x, 1) > 0);
}

/* ------------------------------------------------------------------------
 * SIGNAL STUFF
 */

#define MAX_SIGNAL 64
static gboolean handled_signals[MAX_SIGNAL] = { FALSE, };
static gboolean received_signals[MAX_SIGNAL] = { FALSE, };

static RETSIGTYPE
signal_handler (int sig)
{
	if (sig >= 0 && sig < MAX_SIGNAL) {
		received_signals[sig] = TRUE;
		wakeup_now ();
	}
}

typedef struct _SignalWatch {
	GSource source;
	guint signal;
} SignalWatch;

static gboolean
signal_events_prepare (GSource *source, gint *timeout)
{
	SignalWatch *sw = (SignalWatch*)source;
	*timeout = -1;
	wakeup_drain ();
	g_assert (sw->signal < MAX_SIGNAL); 
	return received_signals[sw->signal];
}

static gboolean
signal_events_check (GSource *source)
{
	SignalWatch *sw = (SignalWatch*)source;
	wakeup_drain ();
	g_assert (sw->signal < MAX_SIGNAL); 
	return received_signals[sw->signal];
}

static gboolean
signal_events_dispatch (GSource *source, GSourceFunc callback, gpointer user_data)
{
	SignalWatch *sw = (SignalWatch*)source;
	GkrUnixSignalHandler func = (GkrUnixSignalHandler)callback;

	wakeup_drain ();
	
	g_assert (sw->signal < MAX_SIGNAL); 
	g_assert (received_signals[sw->signal]);
	
	/* We've now delivered this signal */
	received_signals[sw->signal] = FALSE; 
	
	return (func) (sw->signal, user_data);
}

static void 
signal_events_finalize (GSource *source)
{
	SignalWatch *sw = (SignalWatch*)source;
	
	wakeup_unregister ();
	
	g_assert (sw->signal < MAX_SIGNAL);
	if (sw->signal > 0)
		signal (sw->signal, SIG_DFL);
		
	handled_signals[sw->signal] = FALSE;
}

static GSourceFuncs signal_events_functions = {
	signal_events_prepare,
	signal_events_check,
	signal_events_dispatch,
	signal_events_finalize
};

guint 
gkr_unix_signal_connect (GMainContext *ctx, guint sig, 
                         GkrUnixSignalHandler func, gpointer user_data)
{
	SignalWatch *sw;
	GSource *src;
	guint id;
	
	g_assert (sig < MAX_SIGNAL);
	g_assert (func);
	
	if (handled_signals[sig]) {
		g_critical ("registering a second handler for the same unix signal, only one will be called");
		return 0;
	}
	
    	src = g_source_new (&signal_events_functions, sizeof (SignalWatch));
	sw = (SignalWatch*)src;
	sw->signal = sig;

	wakeup_register (ctx);

	g_source_set_callback (src, (GSourceFunc)func, user_data, NULL);
	id = g_source_attach (src, ctx);
	g_source_unref (src);
	
	handled_signals[sig] = TRUE;
	
	/* The zero signal is an internal thread wakeup signal */
	if (sig > 0) {
		if (signal (sig, signal_handler) == SIG_ERR) {
			g_warning ("couldn't register signal handler for: %d: %s", 
			           sig, g_strerror (errno));
		}
	}
	
	return id;
}
