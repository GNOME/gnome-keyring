/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-async.c - some daemon async functionality

   Copyright (C) 2007, Nate Nielsen

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

   Author: Nate Nielsen <nielsen@memberwebs.com>
*/


#include "gkr-async.h"
#include "gkr-wakeup.h"

#include <glib.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>


/* 
 * Private data for the async calls to be used on a worker thread, for making 
 * calls to the main thread. 
 * 
 * This will always be null for the main thread. 
 */
GStaticPrivate thread_private = G_STATIC_PRIVATE_INIT;

#define ASSERT_IS_MAIN() \
	g_assert (g_static_private_get (&thread_private) == NULL)
	
#define ASSERT_IS_WORKER() \
	g_assert (g_static_private_get (&thread_private) != NULL)


/* -----------------------------------------------------------------------------
 * ASYNC QUEUE MAIN LOOP INTEGRATION
 */

typedef gboolean (*GkrAsyncQueueFunc) (gpointer message, gpointer user_data);

typedef struct _AsyncQueueWatch {
	GSource source;
	GPollFD poll;
	GAsyncQueue *queue;
} AsyncQueueWatch;

static gboolean
thread_events_prepare (GSource *source, gint *timeout)
{
	AsyncQueueWatch *aqw = (AsyncQueueWatch*)source;
	*timeout = -1;
	return g_async_queue_length (aqw->queue) > 0;
}

static gboolean
thread_events_check (GSource *source)
{
	AsyncQueueWatch *aqw = (AsyncQueueWatch*)source;
	return g_async_queue_length (aqw->queue) > 0;
}

static gboolean
thread_events_dispatch (GSource *source, GSourceFunc callback, gpointer user_data)
{
	AsyncQueueWatch *aqw = (AsyncQueueWatch*)source;
	GkrAsyncQueueFunc func = (GkrAsyncQueueFunc)callback;
	gpointer message;
	gkr_wakeup_drain ();
	message = g_async_queue_pop (aqw->queue);
	return (func) (message, user_data);
}

static void 
thread_events_finalize (GSource *source)
{
	AsyncQueueWatch *aqw = (AsyncQueueWatch*)source;
	g_async_queue_unref (aqw->queue);
	aqw->queue = NULL;
	gkr_wakeup_unregister ();
}

static GSourceFuncs thread_events_functions = {
	thread_events_prepare,
	thread_events_check,
	thread_events_dispatch,
	thread_events_finalize
};

static guint 
async_queue_watch (GAsyncQueue *queue, GkrAsyncQueueFunc func, gpointer data)
{
	AsyncQueueWatch *aqw;
	GSource *src;
	guint id;
	
	ASSERT_IS_MAIN ();
	
	g_assert (queue);
	g_assert (func);

    	src = g_source_new (&thread_events_functions, sizeof(AsyncQueueWatch));
	aqw = (AsyncQueueWatch*)src;
	aqw->queue = queue;
	g_async_queue_ref (queue);
	
	aqw->poll.fd = gkr_wakeup_register ();
	aqw->poll.events = G_IO_IN;
	g_source_add_poll (src, &aqw->poll);

	g_source_set_callback (src, (GSourceFunc)func, data, NULL);
	id = g_source_attach (src, NULL);
	g_source_unref (src);
	
	return id;
}

static void
async_queue_unwatch (guint id)
{
	GSource* source;

	ASSERT_IS_MAIN ();

	if (!id)
		return;

	source = g_main_context_find_source_by_id (NULL, id);
	g_source_remove (id);
	if (source)
		g_source_destroy (source);
}

/* -------------------------------------------------------------------
 * ASYNC CALLS
 */

struct _GkrAsyncCalls {
	GAsyncQueue* queue;
	gint source;
};

struct _GkrAsyncCall {
	GMutex *mutex;
	GCond *ready;
	GkrAsyncFunc callback;
	gpointer input;
	gpointer output;
};

GkrAsyncCall*
gkr_async_call_send (GkrAsyncCalls* ctx, GkrAsyncFunc callback, gpointer data)
{
	GkrAsyncCall* call = g_slice_new0 (GkrAsyncCall);

	ASSERT_IS_WORKER ();

	call->mutex = g_mutex_new ();
	call->ready = g_cond_new ();
	call->callback = callback;
	call->input = data;
	call->output = NULL;

	g_async_queue_push (ctx->queue, call);
	gkr_wakeup_now ();

	return call;
}

gpointer
gkr_async_call_wait (GkrAsyncCall* call)
{
	gpointer data;
	g_assert (call);
	
	ASSERT_IS_WORKER ();

	gkr_wakeup_now ();

	g_mutex_lock (call->mutex);
	
		/* This unlocks reply->mutex while waiting */
		while (call->output == NULL)
			g_cond_wait (call->ready, call->mutex);
	
		data = call->output;
		call->output = NULL;
	
	g_mutex_unlock (call->mutex);
	
	g_mutex_free (call->mutex);
	g_cond_free (call->ready);
	g_slice_free (GkrAsyncCall, call);

	return data;
}

void
gkr_async_call_reply (GkrAsyncCall *call, gpointer data)
{
	g_assert(call);
	
	ASSERT_IS_MAIN ();
	
	/* And return the result */
	g_mutex_lock (call->mutex);
	
		g_assert (call->output == NULL);
		call->output = data;
	
	g_mutex_unlock (call->mutex);
	
	g_cond_signal (call->ready);
}	

static gboolean
process_call (gpointer message, gpointer user_data)
{
	GkrAsyncCall *call = (GkrAsyncCall*)message;
	GkrAsyncCalls *ctx = (GkrAsyncCalls*)user_data;
	GkrAsyncFunc func;
	gpointer input;

	g_assert (call);
	g_assert (ctx);
	
	ASSERT_IS_MAIN ();

	/* Get information about call */
	g_mutex_lock (call->mutex);

		g_assert (call->callback);
		g_assert (call->input);

		func = call->callback;
		input = call->input;

	g_mutex_unlock (call->mutex);

	/* Perform call outside of any locks */
	(func) (call, input);

	/* Don't remove this source */
	return TRUE;
}

GkrAsyncCalls*
gkr_async_calls_new (void)
{
	GkrAsyncCalls* ctx = g_new0 (GkrAsyncCalls, 1);
	
	ASSERT_IS_MAIN ();

	ctx->queue = g_async_queue_new ();
	ctx->source = async_queue_watch (ctx->queue, process_call, ctx);
	return ctx;
}

void
gkr_async_calls_free (GkrAsyncCalls* ctx)
{
	ASSERT_IS_MAIN ();

	async_queue_unwatch (ctx->source);

	if (ctx->queue)
		g_async_queue_unref (ctx->queue);
	g_free (ctx);
}

/* -----------------------------------------------------------------------------
 * ASYNC WORKER FUNCTIONS
 */
 
static GkrAsyncCalls *call_context = NULL;
static GAsyncQueue *done_queue = NULL;
static gint done_queue_source = 0;
static GHashTable *running_workers = NULL;
 
struct _GkrAsyncWorker {
	GThread *thread;
	
	GThreadFunc func;
	GkrAsyncWorkerCallback callback;
	
	/* The current status */
	gint cancelled;
	gint stopped;

	/* Arguments for callbacks and worker calls */
	gpointer user_data;
	GkrAsyncCalls *calls;
};

static gpointer 
async_worker_thread (gpointer data)
{
	GkrAsyncWorker *worker = (GkrAsyncWorker*)data; 	
	gpointer result;
	
	g_assert (worker);
	g_assert (worker->func);
	g_assert (worker->thread == g_thread_self ());

	/* The marks this as a worker thread, setup async calls to main thread */
	g_assert (g_static_private_get (&thread_private) == NULL);
	g_static_private_set (&thread_private, worker, NULL);
	
	ASSERT_IS_WORKER ();
	
	/* Call the actual thread function */
	result = (worker->func) (worker->user_data);
	
	g_static_private_set (&thread_private, NULL, NULL);
	
	g_atomic_int_inc (&worker->stopped);
	
	g_assert (done_queue);
	g_async_queue_push (done_queue, worker);

	gkr_wakeup_now ();
	
	g_thread_exit (result);
	return result;
}

static gboolean
cleanup_done_thread (gpointer message, gpointer data)
{
	GkrAsyncWorker *worker = (GkrAsyncWorker*)message;
	gpointer result;

	ASSERT_IS_MAIN ();
	
	g_assert (g_atomic_int_get (&worker->stopped));
		
	g_assert (worker->thread);
	result = g_thread_join (worker->thread);
		
	if (worker->callback)
		(worker->callback) (worker, result, worker->user_data);
			
	g_hash_table_remove (running_workers, worker); 
	g_free (worker);	
	
	/* Cleanup all related stuff */
	if (!g_hash_table_size (running_workers)) {
		g_async_queue_unref (done_queue);
		async_queue_unwatch (done_queue_source);
		done_queue = NULL;
		
		gkr_async_calls_free (call_context);
		call_context = NULL;
		
		g_hash_table_destroy (running_workers);
		running_workers = NULL;
		
		return FALSE;
	}
	
	return TRUE;
}

static void 
cleanup_done_threads ()
{
	gpointer message;
	
	ASSERT_IS_MAIN ();
	
	g_assert (done_queue);
	g_assert (running_workers);
	
	while (done_queue && g_async_queue_length (done_queue) > 0)
	{
		message = g_async_queue_pop (done_queue);
		g_assert (message);
		
		cleanup_done_thread (message, NULL);
	}
}

GkrAsyncWorker*    
gkr_async_worker_start (GThreadFunc func, GkrAsyncWorkerCallback callback, 
                        gpointer user_data)
{
	GkrAsyncWorker *worker;
	GError *err = NULL;
	
	ASSERT_IS_MAIN ();	
	
	if (!done_queue) {
		done_queue = g_async_queue_new ();
		done_queue_source = async_queue_watch (done_queue, cleanup_done_thread, NULL);
	}
	if (!call_context)
		call_context = gkr_async_calls_new ();
	if (!running_workers)
		running_workers = g_hash_table_new (g_direct_hash, g_direct_equal);
	
	worker = g_new0 (GkrAsyncWorker, 1);
	worker->func = func;
	worker->callback = callback;
	worker->user_data = user_data;
	worker->cancelled = 0;
	worker->stopped = 0;
	worker->calls = call_context;
	
	worker->thread = g_thread_create (async_worker_thread, worker, TRUE, &err);
	if (!worker->thread) {
		g_warning ("couldn't create new worker thread: %s", err->message);
		g_error_free (err);
		g_free (worker);
		return NULL;
	}

	g_hash_table_replace (running_workers, worker, worker);	
	return worker;
}

void
gkr_async_worker_cancel (GkrAsyncWorker *worker)
{
	g_assert (gkr_async_worker_is_valid (worker));
	g_atomic_int_inc (&worker->cancelled);
}

void
gkr_async_worker_stop (GkrAsyncWorker *worker)
{
	g_assert (gkr_async_worker_is_valid (worker));
	g_assert (worker);
	ASSERT_IS_MAIN ();
	
	gkr_async_worker_cancel (worker);
	
	while (!g_atomic_int_get (&worker->stopped)) {
		g_assert (running_workers && g_hash_table_size (running_workers) > 0);
		cleanup_done_threads ();
		g_thread_yield ();
	}

	cleanup_done_threads ();
}

gboolean
gkr_async_worker_is_valid (GkrAsyncWorker *worker)
{
	ASSERT_IS_MAIN ();
	
	return worker && running_workers && 
	       g_hash_table_lookup (running_workers, worker);	
}

guint
gkr_async_workers_get_n (void)
{
	ASSERT_IS_MAIN ();
	
	if (!running_workers)
		return 0;
	return g_hash_table_size (running_workers);	
}

static void 
cancel_each_worker (gpointer key, gpointer value, gpointer data)
{
	gkr_async_worker_cancel ((GkrAsyncWorker*)key);
}

void
gkr_async_workers_stop_all (void)
{
	ASSERT_IS_MAIN ();
	
	if (!running_workers)
		return;
	
	g_assert (done_queue);
	
	g_hash_table_foreach (running_workers, cancel_each_worker, NULL);
	
	while (running_workers) {
		g_assert (g_hash_table_size (running_workers) > 0);
		cleanup_done_threads ();
		g_thread_yield ();
	}
}

gboolean
gkr_async_worker_is_cancelled ()
{
	GkrAsyncWorker *worker;
	
	worker = (GkrAsyncWorker*)g_static_private_get (&thread_private);
	g_assert (worker);
	
	return g_atomic_int_get (&worker->cancelled) ? TRUE : FALSE;
}

gpointer
gkr_async_worker_call_main (GkrAsyncFunc callback, gpointer data)
{
	GkrAsyncCall *call;
	GkrAsyncWorker *worker;
	
	ASSERT_IS_WORKER ();
	
	worker = (GkrAsyncWorker*)g_static_private_get (&thread_private);
	g_assert (worker);
	g_assert (worker->calls);
	
	call = gkr_async_call_send (worker->calls, callback, data);
	g_assert (call);
	return gkr_async_call_wait (call);
}
