/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-async.c: Test low level worker and asynchronous thread capabilities

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include "run-auto-test.h"

#include "daemon/util/gkr-daemon-async.h"

DEFINE_SETUP(async_init)
{
	gkr_daemon_async_workers_init (test_mainloop_get ());
}
  
static gboolean 
cancel_worker (gpointer data)
{
	if (gkr_daemon_async_worker_is_valid ((GkrDaemonAsyncWorker*)data))
		gkr_daemon_async_worker_cancel ((GkrDaemonAsyncWorker*)data);
	/* Don't call again */
	return FALSE;
}

/* -----------------------------------------------------------------------------
 * SIMPLE WORKER TEST
 */
 
#define SIMPLE_N  5

typedef struct _SimpleParams {
	guint value;
} SimpleParams;

static gpointer
simple_thread (gpointer data)
{
	SimpleParams *params = (SimpleParams*)data;
	int i;
	
	for (i = 0; i < SIMPLE_N; ++i) {
		++params->value;
		gkr_daemon_async_usleep (G_USEC_PER_SEC / 5);
		g_printerr("+");
	}
	
	g_printerr("!\n");
	return &params->value;
}

static void 
simple_done (GkrDaemonAsyncWorker* worker, gpointer result, gpointer user_data)
{
	SimpleParams *params = (SimpleParams*)user_data;
	/* "result didn't get passed through" */
	g_assert (result == &params->value);
	test_mainloop_quit ();
}

DEFINE_TEST(worker_simple)
{
	GkrDaemonAsyncWorker *worker;
	SimpleParams params;
	
	memset (&params, 0, sizeof (params));
	
	worker = gkr_daemon_async_worker_start (simple_thread, simple_done, &params);
	g_assert (worker != NULL);
	 	
	/* Run the main loop */
	test_mainloop_run (20000);

	g_assert_cmpint (0, ==, gkr_daemon_async_workers_get_n ());
	g_assert_cmpint (SIMPLE_N, ==, params.value);
}

/* -----------------------------------------------------------------------------
 * CANCEL WORKER TEST
 */
 
typedef struct _CancelParams {
	guint value;
} CancelParams;

static gpointer
cancel_thread (gpointer data)
{
	CancelParams *params = (CancelParams*)data;

	while (!gkr_daemon_async_is_stopping ()) {
		++params->value;
		g_printerr("+");
		gkr_daemon_async_usleep (G_USEC_PER_SEC);
	}
	
	g_printerr("!\n");
	return data;
}

static void 
cancel_done (GkrDaemonAsyncWorker* worker, gpointer result, gpointer user_data)
{
	/* "result didn't get passed through" */
	g_assert (result == user_data);
	/* "completing worker is not valid" */
	g_assert (gkr_daemon_async_worker_is_valid (worker));
	test_mainloop_quit ();
}

DEFINE_TEST(worker_cancel)
{
	GkrDaemonAsyncWorker *worker;
	CancelParams params;
	
	memset (&params, 0, sizeof (params));

	worker = gkr_daemon_async_worker_start (cancel_thread, cancel_done, &params);
	g_assert (worker != NULL);
	/* "worker just started is not valid" */
	g_assert (gkr_daemon_async_worker_is_valid (worker));

	/* A less than two seconds later, cancel it */
	g_timeout_add (1600, cancel_worker, worker);
	 	
	/* Run the main loop */
	test_mainloop_run (20000);
	
	/* Two seconds should have elapsed in other thread */
	g_assert_cmpint (2, ==, params.value);
	g_assert_cmpint (0, ==, gkr_daemon_async_workers_get_n ());
	/* "worker is still valid after done" */
	g_assert (!gkr_daemon_async_worker_is_valid (worker));
}

/* -----------------------------------------------------------------------------
 * FIVE WORKER TEST
 */
 
typedef struct _FiveParams {
	guint number;
	guint value;
} FiveParams;

static gpointer
five_thread (gpointer data)
{
	FiveParams *params = (FiveParams*)data;

	while (gkr_daemon_async_yield ()) {
		++params->value;
		g_printerr("%d", params->number);
		gkr_daemon_async_sleep (1);
	}
	
	g_printerr("!\n");
	return data;
}

DEFINE_TEST(worker_five)
{
	GkrDaemonAsyncWorker *worker;
	FiveParams params[5];
	int i;
	
	memset (&params, 0, sizeof (params));
	
	for (i = 0; i < 5; ++i)
	{
		params[i].number = i;

		/* Make the last one cancel the main loop */
		worker = gkr_daemon_async_worker_start (five_thread, NULL, &params[i]);
		g_assert (worker != NULL);
		/* "worker just started is not valid" */
		g_assert (gkr_daemon_async_worker_is_valid (worker));

		/* Stop each in a little less than i seconds */	
		g_timeout_add ((1000 * i) - 200, cancel_worker, worker);
	}
	
	g_assert_cmpint (5, ==, gkr_daemon_async_workers_get_n ());
	 	
	/* Run the main loop */
	test_mainloop_run (1900); 

	/* "last worker should still be valid 2 seconds later" */
	g_assert (gkr_daemon_async_worker_is_valid (worker));
	gkr_daemon_async_worker_stop (worker);
	
	/* "all workers have somehow quit" */
	g_assert (gkr_daemon_async_workers_get_n () > 0);
	gkr_daemon_async_workers_stop_all ();
	
	g_assert_cmpint (0, ==, gkr_daemon_async_workers_get_n ());
	/* "last worker is still valid after exit" */
	g_assert (!gkr_daemon_async_worker_is_valid (worker));
}

