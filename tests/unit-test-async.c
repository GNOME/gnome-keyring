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

#include "unit-test-private.h"
#include "run-base-test.h"

#include "common/gkr-async.h"

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
 
void unit_setup_threading (void) 	 
{ 	 
	gkr_async_workers_init (test_mainloop_get ());
}
	 
static gboolean 
cancel_worker (gpointer data)
{
	if (gkr_async_worker_is_valid ((GkrAsyncWorker*)data))
		gkr_async_worker_cancel ((GkrAsyncWorker*)data);
	/* Don't call again */
	return FALSE;
}

/* -----------------------------------------------------------------------------
 * SIMPLE WORKER TEST
 */
 
#define SIMPLE_N  5

typedef struct _SimpleParams {
	CuTest *cu;
	guint value;
} SimpleParams;

static gpointer
simple_thread (gpointer data)
{
	SimpleParams *params = (SimpleParams*)data;
	int i;
	
	for (i = 0; i < SIMPLE_N; ++i) {
		++params->value;
		gkr_async_usleep (G_USEC_PER_SEC / 5);
		g_printerr("+");
	}
	
	g_printerr("!\n");
	return &params->value;
}

static void 
simple_done (GkrAsyncWorker* worker, gpointer result, gpointer user_data)
{
	SimpleParams *params = (SimpleParams*)user_data;
	CuAssert (params->cu, "result didn't get passed through", result == &params->value);
	test_mainloop_quit ();
}

void unit_test_worker_simple (CuTest* cu)
{
	GkrAsyncWorker *worker;
	SimpleParams params;
	
	memset (&params, 0, sizeof (params));
	params.cu = cu;
	
	worker = gkr_async_worker_start (simple_thread, simple_done, &params);
	CuAssertPtrNotNull (cu, worker);
	 	
	/* Run the main loop */
	test_mainloop_run (20000);
	
	CuAssertIntEquals (cu, 0, gkr_async_workers_get_n ());
	CuAssertIntEquals (cu, SIMPLE_N, params.value);	 
}

/* -----------------------------------------------------------------------------
 * CANCEL WORKER TEST
 */
 
typedef struct _CancelParams {
	CuTest *cu;
	guint value;
} CancelParams;

static gpointer
cancel_thread (gpointer data)
{
	CancelParams *params = (CancelParams*)data;

	while (!gkr_async_is_stopping ()) {
		++params->value;
		g_printerr("+");
		gkr_async_usleep (G_USEC_PER_SEC);
	}
	
	g_printerr("!\n");
	return data;
}

static void 
cancel_done (GkrAsyncWorker* worker, gpointer result, gpointer user_data)
{
	CancelParams *params = (CancelParams*)user_data;
	CuAssert (params->cu, "result didn't get passed through", result == user_data);	
	CuAssert (params->cu, "completing worker is not valid", gkr_async_worker_is_valid (worker));
	test_mainloop_quit ();
}

void unit_test_worker_cancel (CuTest* cu)
{
	GkrAsyncWorker *worker;
	CancelParams params;
	
	memset (&params, 0, sizeof (params));
	params.cu = cu;

	worker = gkr_async_worker_start (cancel_thread, cancel_done, &params);
	CuAssertPtrNotNull (cu, worker);
	CuAssert (cu, "worker just started is not valid", gkr_async_worker_is_valid (worker));

	/* A little less than two seconds later, cancel it */
	g_timeout_add (1800, cancel_worker, worker);
	 	
	/* Run the main loop */
	test_mainloop_run (20000);
	
	/* Two seconds should have elapsed in other thread */
	CuAssertIntEquals (cu, 2, params.value); 
	CuAssertIntEquals (cu, 0, gkr_async_workers_get_n ());
	CuAssert (cu, "worker is still valid after done", !gkr_async_worker_is_valid (worker));
}

/* -----------------------------------------------------------------------------
 * FIVE WORKER TEST
 */
 
typedef struct _FiveParams {
	CuTest *cu;
	guint number;
	guint value;
} FiveParams;

static gpointer
five_thread (gpointer data)
{
	FiveParams *params = (FiveParams*)data;

	while (gkr_async_yield ()) {
		++params->value;
		g_printerr("%d", params->number);
		gkr_async_sleep (1);
	}
	
	g_printerr("!\n");
	return data;
}

void unit_test_worker_five (CuTest* cu)
{
	GkrAsyncWorker *worker;
	FiveParams params[5];
	int i;
	
	memset (&params, 0, sizeof (params));
	
	for (i = 0; i < 5; ++i)
	{
		params[i].cu = cu;
		params[i].number = i;

		/* Make the last one cancel the main loop */
		worker = gkr_async_worker_start (five_thread, NULL, &params[i]);
		CuAssertPtrNotNull (cu, worker);
		CuAssert (cu, "worker just started is not valid", gkr_async_worker_is_valid (worker));

		/* Stop each in a little less than i seconds */	
		g_timeout_add ((1000 * i) - 200, cancel_worker, worker);
	}
	
	CuAssertIntEquals (cu, 5, gkr_async_workers_get_n ());
	 	
	/* Run the main loop */
	test_mainloop_run (1900); 

	CuAssert (cu, "last worker should still be valid 2 seconds later", gkr_async_worker_is_valid (worker));
	gkr_async_worker_stop (worker);
	
	CuAssert (cu, "all workers have somehow quit", gkr_async_workers_get_n () > 0);
	gkr_async_workers_stop_all ();
	
	CuAssertIntEquals (cu, 0, gkr_async_workers_get_n ());
	CuAssert (cu, "last worker is still valid after exit", !gkr_async_worker_is_valid (worker));
}

