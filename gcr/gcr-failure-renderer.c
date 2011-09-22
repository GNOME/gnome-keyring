/*
 * Copyright (C) 2010 Stefan Walter
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

#include "gcr-display-view.h"
#include "gcr-icons.h"
#include "gcr-parser.h"
#include "gcr-failure-renderer.h"

#include "egg/egg-entry-buffer.h"

#include <gdk/gdk.h>
#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_LABEL,
	PROP_ATTRIBUTES
};

struct _GcrFailureRendererPrivate {
	gchar *label;
	GError *error;
};

static void gcr_renderer_iface_init (GcrRendererIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrFailureRenderer, gcr_failure_renderer, G_TYPE_OBJECT,
	G_IMPLEMENT_INTERFACE (GCR_TYPE_RENDERER, gcr_renderer_iface_init);
);

static void
gcr_failure_renderer_init (GcrFailureRenderer *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_FAILURE_RENDERER,
	                                         GcrFailureRendererPrivate));
}

static void
gcr_failure_renderer_finalize (GObject *obj)
{
	GcrFailureRenderer *self = GCR_FAILURE_RENDERER (obj);

	g_error_free (self->pv->error);
	g_free (self->pv->label);

	G_OBJECT_CLASS (gcr_failure_renderer_parent_class)->finalize (obj);
}

static void
gcr_failure_renderer_set_property (GObject *obj,
                                   guint prop_id,
                                   const GValue *value,
                                   GParamSpec *pspec)
{
	GcrFailureRenderer *self = GCR_FAILURE_RENDERER (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_free (self->pv->label);
		self->pv->label = g_value_dup_string (value);
		g_object_notify (obj, "label");
		gcr_renderer_emit_data_changed (GCR_RENDERER (self));
		break;
	case PROP_ATTRIBUTES:
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_failure_renderer_get_property (GObject *obj,
                                   guint prop_id,
                                   GValue *value,
                                   GParamSpec *pspec)
{
	GcrFailureRenderer *self = GCR_FAILURE_RENDERER (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_take_string (value, self->pv->label);
		break;
	case PROP_ATTRIBUTES:
		g_value_set_boxed (value, NULL);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_failure_renderer_class_init (GcrFailureRendererClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (GcrFailureRendererPrivate));

	gobject_class->finalize = gcr_failure_renderer_finalize;
	gobject_class->set_property = gcr_failure_renderer_set_property;
	gobject_class->get_property = gcr_failure_renderer_get_property;

	g_object_class_install_property (gobject_class, PROP_LABEL,
	           g_param_spec_string ("label", "Label", "Failure Label",
	                                "", G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_ATTRIBUTES,
	           g_param_spec_boxed ("attributes", "Attributes", "Renderer attributes",
	                               GCK_TYPE_ATTRIBUTES, G_PARAM_READWRITE));
}

static void
gcr_failure_renderer_render (GcrRenderer *renderer,
                             GcrViewer *viewer)
{
	GcrFailureRenderer *self = GCR_FAILURE_RENDERER (renderer);
	GcrDisplayView *view;
	gchar *display;
	GIcon *icon;

	if (GCR_IS_DISPLAY_VIEW (viewer)) {
		view = GCR_DISPLAY_VIEW (viewer);

	} else {
		g_warning ("GcrFailureRenderer only works with internal specific "
		           "GcrViewer returned by gcr_viewer_new().");
		return;
	}

	_gcr_display_view_begin (view, renderer);

	if (g_error_matches (self->pv->error, GCR_DATA_ERROR, GCR_ERROR_UNRECOGNIZED))
		icon = g_themed_icon_new ("dialog-warning");
	else
		icon = g_themed_icon_new ("dialog-error");
	_gcr_display_view_set_icon (view, renderer, icon);
	g_object_unref (icon);

	_gcr_display_view_append_title (view, renderer, self->pv->label);

	if (self->pv->label)
		display = g_strdup_printf (_("Could not display '%s'"), self->pv->label);
	else
		display = g_strdup (_("Could not display file"));
	_gcr_display_view_append_content (view, renderer, display, NULL);
	g_free (display);

	if (self->pv->error->message)
		_gcr_display_view_append_value (view, renderer, _("Reason"),
		                                self->pv->error->message, FALSE);

	_gcr_display_view_end (view, renderer);
}

static void
gcr_renderer_iface_init (GcrRendererIface *iface)
{
	iface->render_view = gcr_failure_renderer_render;
}

GcrRenderer *
gcr_failure_renderer_new (const gchar *label,
                          GError *error)
{
	GcrFailureRenderer *renderer;

	renderer = g_object_new (GCR_TYPE_FAILURE_RENDERER,
	                         "label", label,
	                         NULL);

	renderer->pv->error = g_error_copy (error);
	return GCR_RENDERER (renderer);
}

GcrRenderer *
gcr_failure_renderer_new_unsupported (const gchar *label)
{
	GcrRenderer *renderer;
	GError *error;

	error = g_error_new (GCR_DATA_ERROR, GCR_ERROR_UNRECOGNIZED,
	                     _("Cannot display a file of this type."));

	renderer = gcr_failure_renderer_new (label, error);

	g_error_free (error);
	return renderer;
}
