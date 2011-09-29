/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gcr-callback-output-stream.h"
#define DEBUG_FLAG GCR_DEBUG_GNUPG
#include "gcr-debug.h"

#include <glib/gi18n.h>

struct _GcrCallbackOutputStream {
	GOutputStream parent;
	GcrCallbackOutputFunc callback;
	gpointer user_data;
	GDestroyNotify destroy_func;
};

struct _GcrCallbackOutputStreamClass {
	GOutputStreamClass parent_class;
};

G_DEFINE_TYPE (GcrCallbackOutputStream, _gcr_callback_output_stream, G_TYPE_OUTPUT_STREAM);

static void
_gcr_callback_output_stream_init (GcrCallbackOutputStream *self)
{

}

static gssize
_gcr_callback_output_stream_write (GOutputStream *stream,
                                   const void *buffer,
                                   gsize count,
                                   GCancellable *cancellable,
                                   GError **error)
{
	GcrCallbackOutputStream *self = GCR_CALLBACK_OUTPUT_STREAM (stream);

	if (g_cancellable_set_error_if_cancelled (cancellable, error)) {
		return -1;
	} else if (self->callback == NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_CLOSED,
		             _("The stream was closed"));
		return -1;
	}

	return (self->callback) (buffer, count, cancellable, self->user_data, error);
}

static gboolean
_gcr_callback_output_stream_close (GOutputStream *stream,
                                   GCancellable *cancellable,
                                   GError **error)
{
	GcrCallbackOutputStream *self = GCR_CALLBACK_OUTPUT_STREAM (stream);
	if (g_cancellable_set_error_if_cancelled (cancellable, error)) {
		return FALSE;
	} else if (self->callback == NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_CLOSED,
		             _("The stream was closed"));
		return FALSE;
	}

	if (self->destroy_func != NULL)
		(self->destroy_func) (self->user_data);
	self->destroy_func = NULL;
	self->user_data = NULL;
	self->callback = NULL;

	return TRUE;
}

static void
_gcr_callback_output_stream_dispose (GObject *obj)
{
	_gcr_callback_output_stream_close (G_OUTPUT_STREAM (obj), NULL, NULL);
	G_OBJECT_CLASS (_gcr_callback_output_stream_parent_class)->dispose (obj);
}

static void
_gcr_callback_output_stream_class_init (GcrCallbackOutputStreamClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GOutputStreamClass *output_class = G_OUTPUT_STREAM_CLASS (klass);

	gobject_class->dispose = _gcr_callback_output_stream_dispose;
	output_class->write_fn = _gcr_callback_output_stream_write;
	output_class->close_fn = _gcr_callback_output_stream_close;
}

/**
 * _gcr_callback_output_stream_new: (skip)
 *
 * Returns: (transfer full) (type Gcr.CallbackOutputStream): the new stream
 */
GOutputStream *
_gcr_callback_output_stream_new (GcrCallbackOutputFunc callback,
                                 gpointer user_data,
                                 GDestroyNotify destroy_func)
{
	GcrCallbackOutputStream *self;

	g_return_val_if_fail (callback, NULL);

	self = g_object_new (GCR_TYPE_CALLBACK_OUTPUT_STREAM, NULL);
	self->callback = callback;
	self->user_data = user_data;
	self->destroy_func = destroy_func;

	return G_OUTPUT_STREAM (self);
}
