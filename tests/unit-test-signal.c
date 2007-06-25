/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-signal.c: Test unix signal handling

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <glib.h>

#include "run-base-test.h"

#include "common/gkr-unix-signal.h"

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void);
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void);
 * 
 * Tests be run in the order specified here.
 */
 
static GMainLoop *mainloop = NULL;

void unit_setup_signal_mainloop (void)
{
	mainloop = g_main_loop_new (NULL, FALSE);
}

static gboolean
quit_loop (gpointer unused)
{
	g_main_loop_quit (mainloop);
	return TRUE;	
}

static void
run_loop_for (int ms)
{
	guint id = g_timeout_add (ms, quit_loop, NULL);
	g_main_loop_run (mainloop);
	g_source_remove (id); 
}

static guint last_signal = 0;
static const gchar *test_arg = "data";

typedef struct _SignalParam {
	CuTest *cu;
	const gchar *argument;
} SignalParam;

static gboolean
handle_signal (guint sig, gpointer data)
{
	SignalParam *param = (SignalParam*)data;
	CuAssert(param->cu, "user data not passed properly", param->argument == test_arg);
	last_signal = sig;
	g_main_loop_quit (mainloop);
	return TRUE;
}

void unit_test_unix_signal (CuTest* cu)
{
	SignalParam param;
	
	param.cu = cu;
	param.argument = test_arg;
	
	gkr_unix_signal_connect (SIGHUP, handle_signal, &param);
	gkr_unix_signal_connect (SIGINT, handle_signal, &param);

	raise (SIGHUP);
	run_loop_for (2000);
	CuAssert (cu, "signal not handled", last_signal == SIGHUP);

	raise (SIGINT);
	run_loop_for (2000);
	CuAssert (cu, "signal not handled", last_signal == SIGINT);

	gkr_unix_signal_connect (SIGTERM, handle_signal, &param);
	raise (SIGTERM);
	run_loop_for (2000);
	CuAssert (cu, "signal not handled", last_signal == SIGTERM);
}		

void unit_test_unix_sig_remove (CuTest* cu)
{
	SignalParam param;
	guint id;

	param.cu = cu;
	param.argument = test_arg;
		
	id = gkr_unix_signal_connect (SIGCONT, handle_signal, &param);
	raise (SIGCONT);
	run_loop_for (2000);
	CuAssert (cu, "signal not handled", last_signal == SIGCONT);
	
	/* Remove the handler */
	last_signal = 0;	
	g_source_remove (id);
	
	/* Should be ignored */
	raise (SIGCONT);
	run_loop_for (2000);
	CuAssert (cu, "signal handler not removed properly", last_signal == 0);
}
