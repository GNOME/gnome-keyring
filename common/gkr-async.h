/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-async.h - some daemon async functionality

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
 * ASYNCHRONOUS CALLS
 */

struct _GkrAsyncCalls;
typedef struct _GkrAsyncCalls GkrAsyncCalls;

struct _GkrAsyncCall;
typedef struct _GkrAsyncCall GkrAsyncCall;

typedef void (*GkrAsyncFunc) (GkrAsyncCall* reply, gpointer message);

/* Called from a worker thread */

GkrAsyncCall*      gkr_async_call_send          (GkrAsyncCalls* calls, 
                                                 GkrAsyncFunc callback,
                                                 gpointer data);

gpointer           gkr_async_call_wait          (GkrAsyncCall* call);

/* Called on the main thread */

void               gkr_async_call_reply         (GkrAsyncCall* reply,
                                                 gpointer data);

GkrAsyncCalls*     gkr_async_calls_new          (void);

void               gkr_async_calls_free         (GkrAsyncCalls* calls);


/* -----------------------------------------------------------------------------
 * WORKER THREADS
 */  

struct _GkrAsyncWorker;
typedef struct _GkrAsyncWorker GkrAsyncWorker;

typedef void (*GkrAsyncWorkerCallback) (GkrAsyncWorker* worker, gpointer result, gpointer user_data);

/* Called on the main thread */

GkrAsyncWorker*    gkr_async_worker_start        (GThreadFunc worker,
                                                  GkrAsyncWorkerCallback callback,
                                                  gpointer user_data);

void               gkr_async_worker_cancel       (GkrAsyncWorker *worker);

void               gkr_async_worker_stop         (GkrAsyncWorker *worker);

gboolean           gkr_async_worker_is_valid     (GkrAsyncWorker *worker);

void               gkr_async_workers_stop_all    (void);

guint              gkr_async_workers_get_n       (void);

/* Called on the worker thread */

gboolean           gkr_async_worker_is_cancelled (void);


gpointer           gkr_async_worker_call_main    (GkrAsyncFunc callback,
                                                  gpointer data);

#endif /* __GKR_ASYNC_H__ */
