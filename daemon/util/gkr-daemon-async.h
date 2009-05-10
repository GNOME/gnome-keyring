/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-daemon-async.h - some daemon async functionality

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

#ifndef __GKR_ASYNC_H__
#define __GKR_ASYNC_H__

#include <glib.h>

/* -----------------------------------------------------------------------------
 * ASYNC WAIT CONDITIONS
 */

struct _GkrDaemonAsyncWait;
typedef struct _GkrDaemonAsyncWait GkrDaemonAsyncWait;

/* 
 * Create a new wait condition. Use instead of GCond.
 */
GkrDaemonAsyncWait*  gkr_daemon_async_wait_new            (void);

/* 
 * Free a wait condition 
 */
void                 gkr_daemon_async_wait_free           (GkrDaemonAsyncWait *wait);

/* 
 * Wait on a condition, this should be done in a loop, as with GCond 
 */
void                 gkr_daemon_async_wait                (GkrDaemonAsyncWait *wait);

/* 
 * Notify that a condition has been satisfied 
 */
void                 gkr_daemon_async_notify              (GkrDaemonAsyncWait *wait);

/*
 * Per Async Worker Storage. This is currently exactly the same 
 * as GPrivate, however that may change in the future, so use this
 * API instead.
 */

typedef GPrivate GkrDaemonAsyncPrivate;
#define gkr_daemon_async_private_new(x) g_private_new (x)
#define gkr_daemon_async_private_get(x) g_private_get (x)
#define gkr_daemon_async_private_set(x, y) g_private_set (x, y)
#define gkr_daemon_async_private_free(x)

/* -----------------------------------------------------------------------------
 * GENERAL ASYNC CALLS
 */

/* 
 * Yield the current thread (main thread or worker). Returns FALSE
 * if the current thread is supposed to stop. 
 */
gboolean           gkr_daemon_async_yield               (void);

/* 
 * Enable concurrent execution of the current thread in the process 
 */
void               gkr_daemon_async_begin_concurrent    (void);

/* 
 * Put current thread back into cooperative execution 
 */
void               gkr_daemon_async_end_concurrent      (void);

/* 
 * See if current thread is supposed to stop 
 */
gboolean           gkr_daemon_async_is_stopping         (void);

/* 
 * Register a cancellation function which is called when the current
 * thread is supposed to stop. This is often used to close a socket
 * or satisfy some other condition that the thread is blocking on.
 * 
 * The GDestroyNotify function is run from an arbitary thread.
 */
void               gkr_daemon_async_register_cancel     (GDestroyNotify cancel, gpointer data);

/* 
 * Unregister a cancellation function.
 */
void               gkr_daemon_async_unregister_cancel   (GDestroyNotify cancel, gpointer data);

/*
 * The current thread should yield and sleep.
 */
void               gkr_daemon_async_usleep              (gulong microseconds);

/*
 * The current thread should yield and sleep.
 */
void               gkr_daemon_async_sleep               (glong seconds);

/* -----------------------------------------------------------------------------
 * WORKER THREADS
 */

struct _GkrDaemonAsyncWorker;
typedef struct _GkrDaemonAsyncWorker GkrDaemonAsyncWorker;

typedef void (*GkrDaemonAsyncWorkerCallback) (GkrDaemonAsyncWorker *worker, gpointer result, gpointer user_data);

/*
 * Called before using any async functionality or workers.
 */
void                   gkr_daemon_async_workers_init        (GMainLoop *mainloop);

/*
 * Called at end of application.
 */
void                   gkr_daemon_async_workers_uninit      (void);

/*
 * Stop all running workers and wait for them to finish.
 */
void                   gkr_daemon_async_workers_stop_all    (void);

/*
 * Get number of worker threads.
 */
guint                  gkr_daemon_async_workers_get_n       (void);

/*
 * Start a new worker thread. callback is run when the worker 
 * ends, whether cancelled or not. The returned pointer is 
 * only valid while worker is running.
 */
GkrDaemonAsyncWorker*  gkr_daemon_async_worker_start        (GThreadFunc worker,
                                                             GkrDaemonAsyncWorkerCallback callback,
                                                             gpointer user_data);

/*
 * Send a notification to a worker thread to stop. 
 */
void                   gkr_daemon_async_worker_cancel       (GkrDaemonAsyncWorker *worker);

/*
 * Send a notification to a worker thread to stop, and wait for 
 * it to finish.
 */
void                   gkr_daemon_async_worker_stop         (GkrDaemonAsyncWorker *worker);

/*
 * Check if a given worker pointer is still valid.
 */
gboolean               gkr_daemon_async_worker_is_valid     (GkrDaemonAsyncWorker *worker);

#endif /* __GKR_DAEMON_ASYNC_H__ */
