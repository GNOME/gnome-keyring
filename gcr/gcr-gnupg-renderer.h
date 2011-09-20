/*
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

#if !defined (__GCR_H_INSIDE__) && !defined (GCR_COMPILATION)
#error "Only <gcr/gcr.h> can be included directly."
#endif

#ifndef __GCR_GNUPG_RENDERER_H__
#define __GCR_GNUPG_RENDERER_H__

#include <glib-object.h>
#include <gtk/gtk.h>

#include "gcr-record.h"

G_BEGIN_DECLS

#define GCR_TYPE_GNUPG_RENDERER               (_gcr_gnupg_renderer_get_type ())
#define GCR_GNUPG_RENDERER(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_GNUPG_RENDERER, GcrGnupgRenderer))
#define GCR_GNUPG_RENDERER_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_GNUPG_RENDERER, GcrGnupgRendererClass))
#define GCR_IS_GNUPG_RENDERER(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_GNUPG_RENDERER))
#define GCR_IS_GNUPG_RENDERER_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_GNUPG_RENDERER))
#define GCR_GNUPG_RENDERER_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_GNUPG_RENDERER, GcrGnupgRendererClass))

typedef struct _GcrGnupgRenderer GcrGnupgRenderer;
typedef struct _GcrGnupgRendererClass GcrGnupgRendererClass;
typedef struct _GcrGnupgRendererPrivate GcrGnupgRendererPrivate;

struct _GcrGnupgRenderer {
	GObject parent;

	/*< private >*/
	GcrGnupgRendererPrivate *pv;
};

struct _GcrGnupgRendererClass {
	GObjectClass parent_class;
};

GType                _gcr_gnupg_renderer_get_type           (void);

GcrGnupgRenderer *   _gcr_gnupg_renderer_new                (GPtrArray *records);

GcrGnupgRenderer *   _gcr_gnupg_renderer_new_for_attributes (const gchar *label,
                                                             GckAttributes *attrs);

GPtrArray *          _gcr_gnupg_renderer_get_records        (GcrGnupgRenderer *self);

void                 _gcr_gnupg_renderer_set_records        (GcrGnupgRenderer *self,
                                                             GPtrArray *records);

GckAttributes *      _gcr_gnupg_renderer_get_attributes     (GcrGnupgRenderer *self);

void                 _gcr_gnupg_renderer_set_attributes     (GcrGnupgRenderer *self,
                                                             GckAttributes *attrs);

G_END_DECLS

#endif /* __GCR_GNUPG_RENDERER_H__ */
