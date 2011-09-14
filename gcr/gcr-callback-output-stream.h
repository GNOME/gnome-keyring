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

#ifndef GCR_CALLBACK_OUTPUT_STREAM_H
#define GCR_CALLBACK_OUTPUT_STREAM_H

#include "gcr-base.h"
#include "gcr-collection.h"

#include <glib-object.h>

G_BEGIN_DECLS

#define GCR_TYPE_CALLBACK_OUTPUT_STREAM               (_gcr_callback_output_stream_get_type ())
#define GCR_CALLBACK_OUTPUT_STREAM(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_CALLBACK_OUTPUT_STREAM, GcrCallbackOutputStream))
#define GCR_CALLBACK_OUTPUT_STREAM_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_CALLBACK_OUTPUT_STREAM, GcrCallbackOutputStreamClass))
#define GCR_IS_CALLBACK_OUTPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_CALLBACK_OUTPUT_STREAM))
#define GCR_IS_CALLBACK_OUTPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_CALLBACK_OUTPUT_STREAM))
#define GCR_CALLBACK_OUTPUT_STREAM_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_CALLBACK_OUTPUT_STREAM, GcrCallbackOutputStreamClass))

typedef struct _GcrCallbackOutputStream GcrCallbackOutputStream;
typedef struct _GcrCallbackOutputStreamClass GcrCallbackOutputStreamClass;

GType               _gcr_callback_output_stream_get_type   (void);

typedef gssize      (*GcrCallbackOutputFunc)               (gconstpointer buffer,
                                                            gsize count,
                                                            GCancellable *cancellable,
                                                            gpointer user_data,
                                                            GError **error);

GOutputStream *     _gcr_callback_output_stream_new        (GcrCallbackOutputFunc callback,
                                                            gpointer user_data,
                                                            GDestroyNotify destroy_func);

G_END_DECLS

#endif /* GCR_CALLBACK_OUTPUT_STREAM_H */
