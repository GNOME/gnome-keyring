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

#if !defined (__GCR_INSIDE_HEADER__) && !defined (GCR_COMPILATION)
#error "Only <gcr/gcr.h> or <gcr/gcr-base.h> can be included directly."
#endif

#ifndef __GCR_UNLOCK_RENDERER_H__
#define __GCR_UNLOCK_RENDERER_H__

#include <glib-object.h>
#include <gtk/gtk.h>

#include "gcr-renderer.h"
#include "gcr-types.h"

G_BEGIN_DECLS

#define GCR_TYPE_UNLOCK_RENDERER               (_gcr_unlock_renderer_get_type ())
#define GCR_UNLOCK_RENDERER(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_UNLOCK_RENDERER, GcrUnlockRenderer))
#define GCR_UNLOCK_RENDERER_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_UNLOCK_RENDERER, GcrUnlockRendererClass))
#define GCR_IS_UNLOCK_RENDERER(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_UNLOCK_RENDERER))
#define GCR_IS_UNLOCK_RENDERER_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_UNLOCK_RENDERER))
#define GCR_UNLOCK_RENDERER_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_UNLOCK_RENDERER, GcrUnlockRendererClass))

typedef struct _GcrUnlockRenderer GcrUnlockRenderer;
typedef struct _GcrUnlockRendererClass GcrUnlockRendererClass;
typedef struct _GcrUnlockRendererPrivate GcrUnlockRendererPrivate;

struct _GcrUnlockRenderer {
	/*< private >*/
	GtkAlignment parent;
	GcrUnlockRendererPrivate *pv;
};

struct _GcrUnlockRendererClass {
	/*< private >*/
	GtkAlignmentClass parent_class;
};

GType                  _gcr_unlock_renderer_get_type          (void);

GcrUnlockRenderer *    _gcr_unlock_renderer_new               (const gchar *label,
                                                               gconstpointer locked_data,
                                                               gsize n_locked_data);

GcrUnlockRenderer *    _gcr_unlock_renderer_new_for_parsed    (GcrParser *parser);

G_END_DECLS

#endif /* __GCR_UNLOCK_RENDERER_H__ */
