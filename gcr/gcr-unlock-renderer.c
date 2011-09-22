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
#include "gcr-unlock-renderer.h"

#include "egg/egg-entry-buffer.h"

#include <gdk/gdk.h>
#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_LABEL,
	PROP_ATTRIBUTES
};

struct _GcrUnlockRendererPrivate {
	GtkEntry *entry;
	GtkLabel *warning;

	gpointer locked_data;
	gsize n_locked_data;
	gchar *label;
	gboolean unlocked;
	GList *renderers;
	guint unlock_tries;

	/* block widget destroys during render */
	gint no_destroy;
};

enum {
	UNLOCK_CLICKED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

static void gcr_renderer_iface_init (GcrRendererIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrUnlockRenderer, _gcr_unlock_renderer, GTK_TYPE_ALIGNMENT,
	G_IMPLEMENT_INTERFACE (GCR_TYPE_RENDERER, gcr_renderer_iface_init);
);

static gchar*
calculate_label (GcrUnlockRenderer *self)
{
	if (self->pv->label)
		return g_strdup_printf (_("Unlock: %s"), self->pv->label);

	return g_strdup (_("Unlock"));
}

void
_gcr_unlock_renderer_show_warning (GcrUnlockRenderer *self,
                                   const gchar *message)
{
	gchar *text;

	g_return_if_fail (GCR_UNLOCK_RENDERER (self));
	g_return_if_fail (message != NULL);

	text = g_strdup_printf ("<i>%s</i>", message);
	gtk_label_set_markup (self->pv->warning, text);
	g_free (text);

	gtk_widget_show (GTK_WIDGET (self->pv->warning));
}

static void
on_unlock_button_clicked (GtkButton *button,
                          gpointer user_data)
{
	GcrUnlockRenderer *self = GCR_UNLOCK_RENDERER (user_data);
	g_signal_emit (self, signals[UNLOCK_CLICKED], 0);
}

static void
on_entry_activated (GtkEntry *entry,
                    gpointer user_data)
{
	GtkButton *button = GTK_BUTTON (user_data);
	gtk_button_clicked (button);
}

static void
_gcr_unlock_renderer_init (GcrUnlockRenderer *self)
{
	GtkWidget *box, *vbox;
	GtkWidget *button;
	GtkEntryBuffer *buffer;

	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_UNLOCK_RENDERER,
	                                         GcrUnlockRendererPrivate));

	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);

	buffer = egg_entry_buffer_new ();
	self->pv->entry = GTK_ENTRY (gtk_entry_new_with_buffer (buffer));
	gtk_entry_set_visibility (self->pv->entry, FALSE);
	gtk_box_pack_start (GTK_BOX (box), GTK_WIDGET (self->pv->entry), TRUE, FALSE, 0);
	gtk_widget_show (GTK_WIDGET (self->pv->entry));
	g_object_unref (buffer);
#if GTK_CHECK_VERSION (3,1,1)
	gtk_entry_set_placeholder_text (self->pv->entry, _("Password"));
#endif

	button = gtk_button_new_with_label (_("Unlock"));
	gtk_box_pack_start (GTK_BOX (box), button, FALSE, FALSE, 0);
	g_signal_connect (button, "clicked", G_CALLBACK (on_unlock_button_clicked), self);
	g_signal_connect (self->pv->entry, "activate", G_CALLBACK (on_entry_activated), button);
	gtk_widget_show (button);

	vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	gtk_box_pack_start (GTK_BOX (vbox), box, FALSE, FALSE, 0);
	gtk_widget_show (box);

	self->pv->warning = GTK_LABEL (gtk_label_new (""));
	gtk_box_pack_start (GTK_BOX (vbox), GTK_WIDGET (self->pv->warning), FALSE, FALSE, 0);
	gtk_widget_hide (GTK_WIDGET (self->pv->warning));

	gtk_container_add (GTK_CONTAINER (self), vbox);
	gtk_widget_show (vbox);
}

static void
_gcr_unlock_renderer_finalize (GObject *obj)
{
	GcrUnlockRenderer *self = GCR_UNLOCK_RENDERER (obj);

	g_free (self->pv->locked_data);
	g_free (self->pv->label);
	g_list_free_full (self->pv->renderers, g_object_unref);

	G_OBJECT_CLASS (_gcr_unlock_renderer_parent_class)->finalize (obj);
}

static void
_gcr_unlock_renderer_set_property (GObject *obj,
                                   guint prop_id,
                                   const GValue *value,
                                   GParamSpec *pspec)
{
	GcrUnlockRenderer *self = GCR_UNLOCK_RENDERER (obj);

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
_gcr_unlock_renderer_get_property (GObject *obj,
                                   guint prop_id,
                                   GValue *value,
                                   GParamSpec *pspec)
{
	GcrUnlockRenderer *self = GCR_UNLOCK_RENDERER (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_take_string (value, calculate_label (self));
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
_gcr_unlock_renderer_class_init (GcrUnlockRendererClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (GcrUnlockRendererPrivate));

	gobject_class->finalize = _gcr_unlock_renderer_finalize;
	gobject_class->set_property = _gcr_unlock_renderer_set_property;
	gobject_class->get_property = _gcr_unlock_renderer_get_property;

	g_object_class_install_property (gobject_class, PROP_LABEL,
	           g_param_spec_string ("label", "Label", "Unlock Label",
	                                "", G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_ATTRIBUTES,
	           g_param_spec_boxed ("attributes", "Attributes", "Certificate pkcs11 attributes",
	                               GCK_TYPE_ATTRIBUTES, G_PARAM_READWRITE));

	signals[UNLOCK_CLICKED] = g_signal_new ("unlock-clicked", GCR_TYPE_UNLOCK_RENDERER, G_SIGNAL_RUN_LAST,
	                                        G_STRUCT_OFFSET (GcrUnlockRendererClass, unlock_clicked),
	                                        NULL, NULL, g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);
}

static void
gcr_unlock_renderer_render (GcrRenderer *renderer,
                            GcrViewer *viewer)
{
	GcrUnlockRenderer *self = GCR_UNLOCK_RENDERER (renderer);
	GcrDisplayView *view;
	gchar *display;
	GList *renderers;
	GIcon *icon;
	GList *l;

	if (GCR_IS_DISPLAY_VIEW (viewer)) {
		view = GCR_DISPLAY_VIEW (viewer);

	} else {
		g_warning ("GcrUnlockRenderer only works with internal specific "
		           "GcrViewer returned by gcr_viewer_new().");
		return;
	}

	/*
	 * If we were successfully unlocked, then this will contain a list of
	 * renderers to add to the viewer.
	 */
	if (self->pv->unlocked) {

		/* We used prepend above, so list is backwards */
		renderers = g_list_reverse (self->pv->renderers);
		self->pv->renderers = NULL;

		for (l = renderers; l != NULL; l = g_list_next (l))
			gcr_viewer_insert_renderer (viewer, l->data, renderer);
		g_list_free_full (renderers, g_object_unref);

		/* And finally remove ourselves from the viewer */
		gcr_viewer_remove_renderer (viewer, GCR_RENDERER (self));
	/*
	 * Not yet unlocked, display the unlock dialog.
	 */
	} else {

		_gcr_display_view_begin (view, renderer);

		icon = g_themed_icon_new ("emblem-readonly");
		_gcr_display_view_set_icon (view, renderer, icon);
		g_object_unref (icon);

		display = calculate_label (self);
		_gcr_display_view_append_title (view, renderer, display);
		g_free (display);

		if (self->pv->label)
			display = g_strdup_printf (_("The contents of '%s' are locked. In order to view the contents, enter the correct password."),
			                           self->pv->label);
		else
			display = g_strdup (_("The contents are locked. In order to view the contents, enter the correct password."));
		_gcr_display_view_append_content (view, renderer, display, NULL);
		g_free (display);

		_gcr_display_view_add_widget_area (view, renderer, GTK_WIDGET (self));
		gtk_widget_show (GTK_WIDGET (self));

		_gcr_display_view_end (view, renderer);
	}
}

static void
gcr_renderer_iface_init (GcrRendererIface *iface)
{
	iface->render_view = gcr_unlock_renderer_render;
}

GcrUnlockRenderer*
_gcr_unlock_renderer_new (const gchar *label,
                          gconstpointer locked_data,
                          gsize n_locked_data)
{
	GcrUnlockRenderer *renderer;

	renderer = g_object_new (GCR_TYPE_UNLOCK_RENDERER,
	                         "label", label,
	                         NULL);
	g_object_ref_sink (renderer);

	renderer->pv->locked_data = g_memdup (locked_data, n_locked_data);
	renderer->pv->n_locked_data = n_locked_data;

	return renderer;
}

GcrUnlockRenderer *
_gcr_unlock_renderer_new_for_parsed (GcrParser *parser)
{
	gconstpointer block;
	gsize n_block;

	g_return_val_if_fail (GCR_IS_PARSER (parser), NULL);

	block = gcr_parser_get_parsed_block (parser, &n_block);
	return _gcr_unlock_renderer_new (gcr_parser_get_parsed_label (parser),
	                                 block, n_block);
}

const gchar *
_gcr_unlock_renderer_get_password (GcrUnlockRenderer *self)
{
	g_return_val_if_fail (GCR_IS_UNLOCK_RENDERER (self), NULL);
	return gtk_entry_get_text (self->pv->entry);
}

gconstpointer
_gcr_unlock_renderer_get_locked_data (GcrUnlockRenderer *self,
                                      gsize *n_data)
{
	g_return_val_if_fail (GCR_IS_UNLOCK_RENDERER (self), NULL);
	g_return_val_if_fail (n_data != NULL, NULL);
	*n_data = self->pv->n_locked_data;
	return self->pv->locked_data;
}
