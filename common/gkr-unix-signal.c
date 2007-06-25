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
#include "gkr-wakeup.h"

#include <glib.h>

#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#define MAX_SIGNAL 64
static gboolean handled_signals[MAX_SIGNAL] = { FALSE, };
static gboolean received_signals[MAX_SIGNAL] = { FALSE, };

static RETSIGTYPE
signal_handler (int sig)
{
	if (sig >= 0 && sig < MAX_SIGNAL) {
		received_signals[sig] = TRUE;
		gkr_wakeup_now ();
	}
}

typedef struct _SignalWatch {
	GSource source;
	GPollFD poll;
	guint signal;
} SignalWatch;

static gboolean
signal_events_prepare (GSource *source, gint *timeout)
{
	SignalWatch *sw = (SignalWatch*)source;
	*timeout = -1;
	gkr_wakeup_drain (); 
	g_assert (sw->signal < MAX_SIGNAL); 
	return received_signals[sw->signal];
}

static gboolean
signal_events_check (GSource *source)
{
	SignalWatch *sw = (SignalWatch*)source;
	gkr_wakeup_drain (); 
	g_assert (sw->signal < MAX_SIGNAL); 
	return received_signals[sw->signal];
}

static gboolean
signal_events_dispatch (GSource *source, GSourceFunc callback, gpointer user_data)
{
	SignalWatch *sw = (SignalWatch*)source;
	GkrUnixSignalHandler func = (GkrUnixSignalHandler)callback;

	gkr_wakeup_drain (); 
	
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
	sw->poll.fd = -1;
	sw->poll.events = 0;
	gkr_wakeup_unregister ();
	
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
gkr_unix_signal_connect (guint sig, GkrUnixSignalHandler func, gpointer user_data)
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

	sw->poll.fd = gkr_wakeup_register ();
	sw->poll.events = G_IO_IN;
	g_source_add_poll (src, &sw->poll);

	g_source_set_callback (src, (GSourceFunc)func, user_data, NULL);
	id = g_source_attach (src, NULL);
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
