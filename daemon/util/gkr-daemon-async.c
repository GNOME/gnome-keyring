/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-daemon-async.c - some daemon async functionality

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


#include "gkr-daemon-async.h"

#include <glib.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#define DEBUG_LOCKS 0

/* 
 * See comments on async_poll_func() on the order of the various
 * gets and sets of waiting_on_* flags.
 */
#if DEBUG_LOCKS
#define DO_LOCK(mtx) G_STMT_START { \
		g_printerr ("%s LOCK %s\n", __func__, G_STRINGIFY(mtx));  \
		g_atomic_int_inc (&waiting_on_lock); \
		if (g_atomic_int_get (&waiting_on_poll)) g_main_context_wakeup (main_ctx); \
		g_mutex_lock (mtx);  \
		g_atomic_int_add (&waiting_on_lock, -1); \
        } G_STMT_END
#define DO_UNLOCK(mtx) G_STMT_START { \
		g_printerr ("%s UNLOCK %s\n", __func__, G_STRINGIFY(mtx));  \
		g_mutex_unlock (mtx);  \
        } G_STMT_END
#else
#define DO_LOCK(mtx) G_STMT_START { \
		g_atomic_int_inc (&waiting_on_lock); \
		if (g_atomic_int_get (&waiting_on_poll)) g_main_context_wakeup (main_ctx); \
		g_mutex_lock (mtx); \
		g_atomic_int_add (&waiting_on_lock, -1); \
	} G_STMT_END
#define DO_UNLOCK(mtx) \
	g_mutex_unlock (mtx)
#endif  
	
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


static GMainContext *main_ctx = NULL;		/* The main loop we're operating on */
static GMutex *async_mutex = NULL;		/* The mutex which is used for cooperative multitasking */
static GPollFunc orig_poll_func = NULL;		/* The system poll function, which we wrap */
static gint async_source_id = 0;              	/* Our GSource id for the main loop */
static GQueue *done_queue = NULL;		/* The queue of completed worker threads */ 
static GHashTable *running_workers = NULL;	/* A set of running worker threads */
static gint waiting_on_lock = 0;		/* Number of threads waiting on lock */ 
static gint waiting_on_poll = 0;		/* Whether we're waiting on the poll or not */

static void cleanup_done_threads (void);

/* -----------------------------------------------------------------------------
 * ASYNC MAINLOOP FUNCTIONS
 */

static gint
async_poll_func (GPollFD *ufds, guint nfsd, gint timeout)
{
	gint ret;
	
	g_assert (orig_poll_func);

	if (done_queue && !g_queue_is_empty (done_queue))
		cleanup_done_threads ();

	/* 
	 * These two atomic variables are interlocked in the 
	 * opposite order from those in DO_LOCK which prevents
	 * race conditions in the if statements.
	 */
	g_atomic_int_set (&waiting_on_poll, 1);
	if (g_atomic_int_get (&waiting_on_lock))
		timeout = 0;
 	
	ret = (orig_poll_func) (ufds, nfsd, timeout);

	g_atomic_int_set (&waiting_on_poll, 0);
	
 	return ret;
}

static gboolean
async_source_prepare(GSource* source, gint *timeout)
{
	gboolean have = g_atomic_int_get (&waiting_on_lock) > 0;
	*timeout = have ? 0 : -1;
	return have ? TRUE : FALSE;
}

static gboolean
async_source_check(GSource* source)
{
	return g_atomic_int_get (&waiting_on_lock) > 0;
}

static gboolean
async_source_dispatch(GSource* source, GSourceFunc callback, gpointer user_data)
{
	/* Let a worker run */
	DO_UNLOCK (async_mutex);
	g_thread_yield ();
	DO_LOCK (async_mutex);
	return TRUE;
}

static void
async_source_finalize(GSource* source)
{

}

static GSourceFuncs async_source_functions = {
	async_source_prepare,
	async_source_check,
	async_source_dispatch,
	async_source_finalize
};

void
gkr_daemon_async_workers_init (GMainLoop *mainloop)
{
	GSource *src;
	
	if (main_ctx)
		return;

	g_assert (mainloop);
	
	async_mutex = g_mutex_new ();

	g_assert (!main_ctx);
	main_ctx = g_main_loop_get_context (mainloop);
	g_assert (main_ctx);
	g_main_context_ref (main_ctx);
	
	/* Add our idle handler which processes other tasks */
	g_assert(!async_source_id);
	src = g_source_new (&async_source_functions, sizeof (GSource));
	async_source_id = g_source_attach (src, main_ctx);
	g_source_unref (src);

	/* Swap in our poll func */
 	orig_poll_func = g_main_context_get_poll_func (main_ctx);
 	g_assert (orig_poll_func);
 	g_main_context_set_poll_func (main_ctx, async_poll_func);

	/* 
	 * The mutex gets locked each time the main loop is waiting 
	 * for input. See lock_step_poll_func() 
	 */	
	DO_LOCK (async_mutex);
}

void 
gkr_daemon_async_workers_uninit (void)
{
	GSource* src;
	
	gkr_daemon_async_workers_stop_all ();

	DO_UNLOCK (async_mutex);
	
	/* Take out the source */
	g_assert (async_source_id);
	src = g_main_context_find_source_by_id(main_ctx, async_source_id);
	g_assert (src);
	g_source_destroy (src);
	async_source_id = 0;
		
	/* Swap back in original poll func */
	g_assert (orig_poll_func);
	g_main_context_set_poll_func (main_ctx, orig_poll_func);
		
	g_main_context_unref (main_ctx);
	main_ctx = NULL;
	
	if (async_mutex) {
		g_mutex_free (async_mutex);
		async_mutex = NULL;
	}
}

/* -----------------------------------------------------------------------------
 * ASYNC WORKER FUNCTIONS
 */


typedef struct _GkrCancelCallback {
	GDestroyNotify cancel_func;
	gpointer user_data;
} GkrCancelCallback;
 
struct _GkrDaemonAsyncWorker {
	GThread *thread;
	
	GThreadFunc func;
	GkrDaemonAsyncWorkerCallback callback;
	GQueue *cancel_funcs;
	
	/* The current status */
	gint cancelled;
	gint stopped;

	/* Arguments for callbacks and worker calls */
	gpointer user_data;
};

static gpointer 
async_worker_thread (gpointer data)
{
	GkrDaemonAsyncWorker *worker = (GkrDaemonAsyncWorker*)data;
	gpointer result;
	
	g_assert (worker);
	g_assert (worker->func);

	/* The marks this as a worker thread, setup async calls to main thread */
	g_assert (g_static_private_get (&thread_private) == NULL);
	g_static_private_set (&thread_private, worker, NULL);
	
	ASSERT_IS_WORKER ();
	
	/* 
	 * Call the actual thread function. This mutex is unlocked by workers
	 * when they yield, or by the main loop when it is waiting for input. 
	 */
	DO_LOCK (async_mutex);
	
		result = (worker->func) (worker->user_data);

		/* We're all done yay, let main thread know about it */
		g_atomic_int_inc (&worker->stopped);
		
		g_assert (done_queue);
		g_queue_push_tail (done_queue, worker);
		
	DO_UNLOCK (async_mutex);
	
	g_static_private_set (&thread_private, NULL, NULL);
	
	g_main_context_wakeup (main_ctx);
	
	g_thread_exit (result);
	return result;
}

static gboolean
cleanup_done_thread (gpointer message, gpointer data)
{
	GkrDaemonAsyncWorker *worker = (GkrDaemonAsyncWorker*)message;
	GkrCancelCallback *cb;
	gpointer result;

	ASSERT_IS_MAIN ();
	
	g_assert (g_atomic_int_get (&worker->stopped));
		
	/* This shouldn't block, because worker->stopped is set */
	g_assert (worker->thread);
	result = g_thread_join (worker->thread);
		
	if (worker->callback)
		(worker->callback) (worker, result, worker->user_data);

	/* Free all the cancel funcs */		
	for (;;) {
		cb = g_queue_pop_tail (worker->cancel_funcs);
		if (!cb)
			break;
		g_slice_free (GkrCancelCallback, cb);
	}
	g_queue_free (worker->cancel_funcs);
			
	g_hash_table_remove (running_workers, worker); 
	g_free (worker);	
	
	/* Cleanup all related stuff */
	if (!g_hash_table_size (running_workers)) {
		g_queue_free (done_queue);
		done_queue = NULL;
		
		g_hash_table_destroy (running_workers);
		running_workers = NULL;
		
		g_assert (main_ctx);
		return FALSE;
	}
	
	return TRUE;
}

static void 
cleanup_done_threads (void)
{
	gpointer message;
	
	while (done_queue && !g_queue_is_empty (done_queue))
	{
		message = g_queue_pop_head (done_queue);
		g_assert (message);
		
		cleanup_done_thread (message, NULL);
	}
}

GkrDaemonAsyncWorker*
gkr_daemon_async_worker_start (GThreadFunc func, GkrDaemonAsyncWorkerCallback callback, 
                               gpointer user_data)
{
	GkrDaemonAsyncWorker *worker;
	GError *err = NULL;
	
	ASSERT_IS_MAIN ();	
	
	if (!done_queue) {
		g_assert (main_ctx);
		
		done_queue = g_queue_new ();
		g_assert (!running_workers);
		running_workers = g_hash_table_new (g_direct_hash, g_direct_equal);
	}
	
	worker = g_new0 (GkrDaemonAsyncWorker, 1);
	worker->func = func;
	worker->callback = callback;
	worker->cancel_funcs = g_queue_new ();
	worker->user_data = user_data;
	worker->cancelled = 0;
	worker->stopped = 0;
	
	/* 
	 * Don't change this to a thread pool too lightly. Assumptions are made 
	 * that worker threads are not shared throughout the code.
	 */
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
gkr_daemon_async_worker_cancel (GkrDaemonAsyncWorker *worker)
{
	GkrCancelCallback *cb;
	
	g_assert (gkr_daemon_async_worker_is_valid (worker));
	g_atomic_int_inc (&worker->cancelled);
	
	for (;;) {
		cb = g_queue_pop_tail (worker->cancel_funcs);
		if (!cb)
			break;
		(cb->cancel_func) (cb->user_data);
		g_slice_free (GkrCancelCallback, cb);
	}
}

void
gkr_daemon_async_worker_stop (GkrDaemonAsyncWorker *worker)
{
	g_assert (gkr_daemon_async_worker_is_valid (worker));
	g_assert (worker);
	ASSERT_IS_MAIN ();
	
	gkr_daemon_async_worker_cancel (worker);
	
	while (!g_atomic_int_get (&worker->stopped)) {
		g_assert (running_workers && g_hash_table_size (running_workers) > 0);
		cleanup_done_threads ();
		gkr_daemon_async_yield ();
	}

	cleanup_done_threads ();
}

gboolean
gkr_daemon_async_worker_is_valid (GkrDaemonAsyncWorker *worker)
{
	ASSERT_IS_MAIN ();
	
	return worker && running_workers && 
	       g_hash_table_lookup (running_workers, worker);	
}

guint
gkr_daemon_async_workers_get_n (void)
{
	ASSERT_IS_MAIN ();
	
	if (!running_workers)
		return 0;
	return g_hash_table_size (running_workers);	
}

static void 
cancel_each_worker (gpointer key, gpointer value, gpointer data)
{
	gkr_daemon_async_worker_cancel ((GkrDaemonAsyncWorker*)key);
}

void
gkr_daemon_async_workers_stop_all (void)
{
	ASSERT_IS_MAIN ();
	
	if (!running_workers)
		return;
	
	g_assert (done_queue);
	
	g_hash_table_foreach (running_workers, cancel_each_worker, NULL);
	
	while (running_workers) {
		g_assert (g_hash_table_size (running_workers) > 0);
		cleanup_done_threads ();
		gkr_daemon_async_yield ();
	}
}

/* -----------------------------------------------------------------------------
 * ASYNC FUNCTIONS FOR ANY THREAD
 */

gboolean
gkr_daemon_async_yield (void)
{
	GkrDaemonAsyncWorker *worker;

	g_assert (async_mutex);
	
	worker = (GkrDaemonAsyncWorker*)g_static_private_get (&thread_private);
	if (worker && g_atomic_int_get (&worker->cancelled))
		return FALSE;

	/* Let another worker or the main loop run */
	DO_UNLOCK (async_mutex);
	g_thread_yield ();
	DO_LOCK (async_mutex);

	if (worker && g_atomic_int_get (&worker->cancelled))
		return FALSE;
		
	return TRUE;
}

gboolean
gkr_daemon_async_is_stopping (void)
{
	GkrDaemonAsyncWorker *worker;

	worker = (GkrDaemonAsyncWorker*)g_static_private_get (&thread_private);
	if (worker && g_atomic_int_get (&worker->cancelled))
		return TRUE;
	
	return FALSE;
}

void
gkr_daemon_async_begin_concurrent (void)
{
	g_assert (async_mutex);
	
	/* Let another worker or the main loop run */
	DO_UNLOCK (async_mutex);
}

void
gkr_daemon_async_end_concurrent (void)
{
	g_assert (async_mutex);
	
	/* Make sure only one thread is running */
	DO_LOCK (async_mutex);
}

void
gkr_daemon_async_register_cancel (GDestroyNotify cancel, gpointer data)
{
	GkrCancelCallback *cb;
	GkrDaemonAsyncWorker *worker;

	g_assert (cancel);
	
	worker = (GkrDaemonAsyncWorker*)g_static_private_get (&thread_private);
	
	/* We don't support cancellation funcs for main thread */	
	if (!worker)
		return;

	cb = g_slice_new (GkrCancelCallback);
	cb->cancel_func = cancel;
	cb->user_data = data;
	
	g_queue_push_tail (worker->cancel_funcs, cb);
}

static gint
match_cancel_func (gconstpointer a, gconstpointer b)
{
	return memcmp (a, b, sizeof (GkrCancelCallback));
}

void
gkr_daemon_async_unregister_cancel (GDestroyNotify cancel, gpointer data)
{
	GkrCancelCallback match;
	GkrDaemonAsyncWorker *worker;
	GList *l;
	
	g_assert (cancel);
	
	worker = (GkrDaemonAsyncWorker*)g_static_private_get (&thread_private);
	
	/* We don't support cancellation funcs for main thread */	
	if (!worker)
		return;
		
	match.cancel_func = cancel;
	match.user_data = data;
		
	l = g_queue_find_custom (worker->cancel_funcs, &match, match_cancel_func);
	if (l) {
		g_slice_free (GkrCancelCallback, l->data);
		g_queue_delete_link (worker->cancel_funcs, l);
	} 
}

/* -----------------------------------------------------------------------------
 * ASYNC WAITS
 */
 
GkrDaemonAsyncWait*
gkr_daemon_async_wait_new (void)
{
	return (GkrDaemonAsyncWait*)g_cond_new ();
}

void
gkr_daemon_async_wait_free (GkrDaemonAsyncWait *wait)
{
	if (!wait)
		return;
	g_cond_free ((GCond*)wait);
}

void
gkr_daemon_async_wait (GkrDaemonAsyncWait *wait)
{
	g_assert (wait);
	g_cond_wait ((GCond*)wait, async_mutex);
}

void
gkr_daemon_async_notify (GkrDaemonAsyncWait *wait)
{
	g_assert (wait);
	g_cond_signal ((GCond*)wait);
}

void
gkr_daemon_async_usleep (gulong microseconds)
{
	g_assert (async_mutex);
	
	/* Let another worker or the main loop run */
	DO_UNLOCK (async_mutex);
	
		g_usleep (microseconds);
		
	DO_LOCK (async_mutex);
}

void
gkr_daemon_async_sleep (glong seconds)
{
	g_assert (async_mutex);
	
	/* Let another worker or the main loop run */
	DO_UNLOCK (async_mutex);
	
		g_usleep (G_USEC_PER_SEC * seconds);
		
	DO_LOCK (async_mutex);
}
