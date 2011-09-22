/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gcr-viewer-window.c: Window for viewer

   Copyright (C) 2011 Collabora Ltd.

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

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#include "config.h"

#include "gcr-viewer-window.h"

#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>

#include <locale.h>
#include <string.h>

struct _GcrViewerWindowPrivate {
	GcrViewerWidget *viewer;
	GcrImportButton *import;
};

G_DEFINE_TYPE (GcrViewerWindow, _gcr_viewer_window, GTK_TYPE_WINDOW);

static void
on_viewer_renderer_added (GcrViewerWidget *viewer,
                          GcrRenderer *renderer,
                          GcrParser *parser,
                          gpointer user_data)
{
	GcrViewerWindow *self = GCR_VIEWER_WINDOW (user_data);
	gcr_import_button_add_parsed (self->pv->import, parser);
}

static void
_gcr_viewer_window_init (GcrViewerWindow *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_VIEWER_WINDOW,
	                                        GcrViewerWindowPrivate);
}

static void
on_import_button_imported (GcrImportButton *button,
                           GcrImporter *importer,
                           GError *error,
                           gpointer user_data)
{
	GcrViewerWindow *self = GCR_VIEWER_WINDOW (user_data);
	GcrRenderer *renderer;

	if (error == NULL) {
		g_object_set (button, "label", _("Imported"), NULL);

	} else {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			renderer = gcr_failure_renderer_new (_("Import failed"), error);
			gcr_viewer_add_renderer (GCR_VIEWER (self->pv->viewer), renderer);
			g_object_unref (renderer);
		}
	}
}

static void
on_close_clicked (GtkButton *button,
                  gpointer user_data)
{
	GcrViewerWindow *self = GCR_VIEWER_WINDOW (user_data);
	gtk_widget_destroy (GTK_WIDGET (self));
}

static void
_gcr_viewer_window_constructed (GObject *obj)
{
	GcrViewerWindow *self = GCR_VIEWER_WINDOW (obj);
	GtkWidget *bbox;
	GtkWidget *box;
	GtkWidget *button;
	GtkWidget *align;

	G_OBJECT_CLASS (_gcr_viewer_window_parent_class)->constructed (obj);

	bbox = gtk_button_box_new (GTK_ORIENTATION_HORIZONTAL);
	gtk_box_set_spacing (GTK_BOX (bbox), 12);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
	gtk_widget_show (bbox);

	self->pv->import = gcr_import_button_new (_("Import"));
	g_signal_connect_object (self->pv->import, "imported",
	                         G_CALLBACK (on_import_button_imported),
	                         self, 0);
	gtk_widget_show (GTK_WIDGET (self->pv->import));

	button = gtk_button_new_from_stock (GTK_STOCK_CLOSE);
	g_signal_connect_object  (button, "clicked",
	                          G_CALLBACK (on_close_clicked),
	                          self, 0);
	gtk_widget_show (button);

	gtk_box_pack_start (GTK_BOX (bbox), button, FALSE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (bbox), GTK_WIDGET (self->pv->import), FALSE, TRUE, 0);

	align = gtk_alignment_new (0.5, 0.5, 1.0, 1.0);
	gtk_alignment_set_padding (GTK_ALIGNMENT (align), 0, 0, 0, 12);
	gtk_widget_show (align);
	gtk_container_add (GTK_CONTAINER (align), bbox);

	self->pv->viewer = gcr_viewer_widget_new ();
	g_signal_connect_object (self->pv->viewer, "added",
	                         G_CALLBACK (on_viewer_renderer_added),
	                         self, 0);
	gtk_widget_show (GTK_WIDGET (self->pv->viewer));

	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_widget_show (box);

	gtk_box_pack_start (GTK_BOX (box), GTK_WIDGET (self->pv->viewer), TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box), align, FALSE, FALSE, 6);

	gtk_container_add (GTK_CONTAINER (self), box);

	gtk_window_set_default_size (GTK_WINDOW (self), 250, 400);
}

static void
_gcr_viewer_window_class_init (GcrViewerWindowClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructed = _gcr_viewer_window_constructed;

	g_type_class_add_private (klass, sizeof (GcrViewerWindow));
}

GtkWindow *
_gcr_viewer_window_new (void)
{
	return g_object_new (GCR_TYPE_VIEWER_WINDOW, NULL);
}

void
_gcr_viewer_window_load (GcrViewerWindow *self,
                         GFile *file)
{
	g_return_if_fail (GCR_IS_VIEWER_WINDOW (self));
	g_return_if_fail (G_IS_FILE (file));

	return gcr_viewer_widget_load_file (self->pv->viewer, file);
}
