/*
 * Copyright (C) 2008 Stefan Walter
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
 */

#include "config.h"

#include "gcr-display-scrolled.h"
#include "gcr-display-view.h"
#include "gcr-renderer.h"
#include "gcr-viewer.h"

/* -----------------------------------------------------------------------------
 * INTERFACE
 */

static void
gcr_viewer_base_init (gpointer gobject_iface)
{
	static gboolean initialized = FALSE;
	if (!initialized) {

		initialized = TRUE;
	}
}

GType
gcr_viewer_get_type (void)
{
	static GType type = 0;
	if (!type) {
		static const GTypeInfo info = {
			sizeof (GcrViewerIface),
			gcr_viewer_base_init,  /* base init */
			NULL,                  /* base finalize */
		};
		type = g_type_register_static (G_TYPE_INTERFACE, "GcrViewerIface", &info, 0);
		g_type_interface_add_prerequisite (type, GTK_TYPE_WIDGET);
	}

	return type;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GcrViewer*
gcr_viewer_new (void)
{
	return GCR_VIEWER (_gcr_display_view_new ());
}

GcrViewer*
gcr_viewer_new_scrolled (void)
{
	return GCR_VIEWER (_gcr_display_scrolled_new ());
}

void
gcr_viewer_add_renderer (GcrViewer *self, GcrRenderer *renderer)
{
	g_return_if_fail (GCR_IS_VIEWER (self));
	g_return_if_fail (GCR_IS_RENDERER (renderer));
	g_return_if_fail (GCR_VIEWER_GET_INTERFACE (self)->add_renderer);
	GCR_VIEWER_GET_INTERFACE (self)->add_renderer (self, renderer);
}

void
gcr_viewer_remove_renderer (GcrViewer *self, GcrRenderer *renderer)
{
	g_return_if_fail (GCR_IS_VIEWER (self));
	g_return_if_fail (GCR_IS_RENDERER (renderer));
	g_return_if_fail (GCR_VIEWER_GET_INTERFACE (self)->remove_renderer);
	GCR_VIEWER_GET_INTERFACE (self)->remove_renderer (self, renderer);
}

guint
gcr_viewer_count_renderers (GcrViewer *self)
{
	g_return_val_if_fail (GCR_IS_VIEWER (self), 0);
	g_return_val_if_fail (GCR_VIEWER_GET_INTERFACE (self)->count_renderers, 0);
	return GCR_VIEWER_GET_INTERFACE (self)->count_renderers (self);
}

GcrRenderer*
gcr_viewer_get_renderer (GcrViewer *self, guint index_)
{
	g_return_val_if_fail (GCR_IS_VIEWER (self), NULL);
	g_return_val_if_fail (GCR_VIEWER_GET_INTERFACE (self)->get_renderer, NULL);
	return GCR_VIEWER_GET_INTERFACE (self)->get_renderer (self, index_);
}
