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

#include <glib.h>

#include "gkr-async.h"

/* -----------------------------------------------------------------------------
 * ASYNC QUEUE MAIN LOOP INTEGRATION
 */

typedef gboolean (*GkrAsyncQueueFunc) (gpointer message, gpointer user_data);

typedef struct _AsyncQueueWatch {
	GSource source;
	GAsyncQueue *queue;
	gpointer user_data;
} AsyncQueueWatch;

static gboolean
thread_events_prepare (GSource *source, gint *timeout)
{
	AsyncQueueWatch *aqw = (AsyncQueueWatch*)source;
	*timeout = -1;
	return g_async_queue_length(aqw->queue) > 0;
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
	
	message = g_async_queue_pop (aqw->queue);
	return (func) (message, user_data);
}

static void 
thread_events_finalize (GSource *source)
{
	AsyncQueueWatch *aqw = (AsyncQueueWatch*)source;
	g_async_queue_unref (aqw->queue);
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
	
	g_assert (queue);
	g_assert (func);

    	src = g_source_new (&thread_events_functions, sizeof(AsyncQueueWatch));
	aqw = (AsyncQueueWatch*)queue;
	aqw->queue = queue;
	g_async_queue_ref (queue);
	
	g_source_set_callback (src, (GSourceFunc)func, data, NULL);
	id = g_source_attach (src, NULL);
	g_source_unref (src);
	
	return id;
}

static void
async_queue_unwatch (guint id)
{
	GSource* source;

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

struct _GkrAsyncReply {
	GMutex *mutex;
	GCond *ready;
	GkrAsyncFunc callback;
	gpointer input;
	gpointer output;
};

gpointer
gkr_async_call (GkrAsyncCalls* ctx, GkrAsyncFunc callback, gpointer data)
{
	GkrAsyncReply* reply = gkr_async_call_send (ctx, callback, data);
	g_assert (reply);
	return gkr_async_call_wait (reply);
}

GkrAsyncReply*
gkr_async_call_send (GkrAsyncCalls* ctx, GkrAsyncFunc callback, gpointer data)
{
	GkrAsyncReply* reply = g_slice_new0 (GkrAsyncReply);

	reply->mutex = g_mutex_new ();
	reply->ready = g_cond_new ();
	reply->callback = callback;
	reply->input = data;
	reply->output = NULL;

	g_async_queue_push (ctx->queue, reply);

	return reply;
}

gpointer
gkr_async_call_wait (GkrAsyncReply* reply)
{
	gpointer data;
	g_assert (reply);
	
	g_mutex_lock (reply->mutex);
	
		/* This unlocks reply->mutex while waiting */
		while (reply->output == NULL)
			g_cond_wait (reply->ready, reply->mutex);
	
		data = reply->output;
		reply->output = NULL;
	
	g_mutex_unlock (reply->mutex);
	
	g_mutex_free (reply->mutex);
	g_cond_free (reply->ready);
	g_slice_free (GkrAsyncReply, reply);

	return data;
}

void
gkr_async_call_reply (GkrAsyncReply* reply, gpointer data)
{
	g_assert(reply);
	
	/* And return the result */
	g_mutex_lock (reply->mutex);
	
		g_assert (reply->output == NULL);
		reply->output = data;
	
	g_mutex_unlock (reply->mutex);
	
	g_cond_signal (reply->ready);
}	

static gboolean
process_call (gpointer message, gpointer user_data)
{
	GkrAsyncReply *reply = (GkrAsyncReply*)message;
	GkrAsyncCalls *ctx = (GkrAsyncCalls*)user_data;
	GkrAsyncFunc func;
	gpointer input;

	g_assert (reply);
	g_assert (ctx);

	/* Get information about call */
	g_mutex_lock (reply->mutex);

		g_assert (reply->callback);
		g_assert (reply->input);

		func = reply->callback;
		input = reply->input;

	g_mutex_unlock (reply->mutex);

	/* Perform call outside of any locks */
	(func) (reply, input);

	/* Don't remove this source */
	return TRUE;
}

GkrAsyncCalls*
gkr_async_call_new_context (void)
{
	GkrAsyncCalls* ctx = g_new0 (GkrAsyncCalls, 1);
	ctx->queue = g_async_queue_new ();
	ctx->source = async_queue_watch (ctx->queue, process_call, ctx);
	return ctx;
}

void
gkr_async_call_free_context (GkrAsyncCalls* ctx)
{
	async_queue_unwatch (ctx->source);

	if (ctx->queue)
		g_async_queue_unref (ctx->queue);
	g_free (ctx);
}

