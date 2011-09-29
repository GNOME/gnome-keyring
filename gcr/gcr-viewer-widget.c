/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gcr-viewer-widget: Widget for viewer

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

#include "gcr-display-scrolled.h"
#include "gcr-failure-renderer.h"
#include "gcr-importer.h"
#include "gcr-marshal.h"
#include "gcr-parser.h"
#include "gcr-renderer.h"
#include "gcr-unlock-renderer.h"
#include "gcr-viewer-widget.h"
#include "gcr-viewer.h"

#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>

#include <locale.h>
#include <string.h>

/**
 * SECTION:gcr-viewer-widget
 * @title: GcrViewerWidget
 * @short_description: A widget which shows certificates or keys
 *
 * A viewer widget which can display certificates and keys that are
 * located in files.
 */

/**
 * GcrViewerWidget:
 *
 * A viewer widget object.
 */

/**
 * GcrViewerWidgetClass:
 *
 * Class for #GcrViewerWidget
 */

/*
 * Not yet figured out how to expose these without locking down our
 * implementation, the parent class we derive from.
 */

struct _GcrViewerWidget {
	/*< private >*/
	GcrDisplayScrolled parent;
	GcrViewerWidgetPrivate *pv;
};

struct _GcrViewerWidgetClass {
	GcrDisplayScrolledClass parent_class;

	void       (*added)        (GcrViewerWidget *widget,
	                            GcrRenderer *renderer,
	                            GcrParsed *parsed);
};

struct _GcrViewerWidgetPrivate {
	GQueue *files_to_load;
	GcrParser *parser;
	GCancellable *cancellable;
	GList *unlocks;
	gboolean loading;
	gchar *display_name;
};

enum {
	ADDED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0, };

static void viewer_load_next_file (GcrViewerWidget *self);
static void viewer_stop_loading_files (GcrViewerWidget *self);

G_DEFINE_TYPE (GcrViewerWidget, gcr_viewer_widget, GCR_TYPE_DISPLAY_SCROLLED);

static const gchar *
get_parsed_label_or_display_name (GcrViewerWidget *self,
                                  GcrParser *parser)
{
	const gchar *label;

	label = gcr_parser_get_parsed_label (parser);
	if (label == NULL)
		label = self->pv->display_name;

	return label;
}

static void
on_parser_parsed (GcrParser *parser,
                  gpointer user_data)
{
	GcrViewerWidget *self = GCR_VIEWER_WIDGET (user_data);
	GckAttributes *attrs;
	GcrRenderer *renderer;
	const gchar *label;
	gboolean actual = TRUE;

	label = get_parsed_label_or_display_name (self, parser);
	attrs = gcr_parser_get_parsed_attributes (parser);

	renderer = gcr_renderer_create (label, attrs);

	if (renderer == NULL) {
		renderer = gcr_failure_renderer_new_unsupported (label);
		actual = FALSE;
	}

	/* And show the data */
	gcr_viewer_add_renderer (GCR_VIEWER (self), renderer);

	/* Let callers know we're rendering data */
	if (actual == TRUE)
		g_signal_emit (self, signals[ADDED], 0, renderer,
		               gcr_parser_get_parsed (parser));

	g_object_unref (renderer);
}

static gboolean
on_parser_authenticate_for_unlock (GcrParser *parser,
                                   guint count,
                                   gpointer user_data)
{
	GcrUnlockRenderer *unlock = GCR_UNLOCK_RENDERER (user_data);
	const gchar *password;

	if (count == 0) {
		password = _gcr_unlock_renderer_get_password (unlock);
		gcr_parser_add_password (parser, password);
	}

	return TRUE;
}

static void
on_unlock_renderer_clicked (GcrUnlockRenderer *unlock,
                            gpointer user_data)
{
	GcrViewerWidget *self = GCR_VIEWER_WIDGET (user_data);
	GError *error = NULL;
	gconstpointer data;
	gsize n_data;
	gulong sig;

	/* Override our main authenticate signal handler */
	sig = g_signal_connect (self->pv->parser, "authenticate",
	                        G_CALLBACK (on_parser_authenticate_for_unlock), unlock);

	data = _gcr_unlock_renderer_get_locked_data (unlock, &n_data);
	if (gcr_parser_parse_data (self->pv->parser, data, n_data, &error)) {

		/* Done with this unlock renderer */
		gcr_viewer_remove_renderer (GCR_VIEWER (self), GCR_RENDERER (unlock));
		self->pv->unlocks = g_list_remove (self->pv->unlocks, unlock);
		g_object_unref (unlock);

	} else if (g_error_matches (error, GCR_DATA_ERROR, GCR_ERROR_LOCKED)){
		_gcr_unlock_renderer_show_warning (unlock,  _("The password was incorrect"));
		g_error_free (error);

	} else {
		_gcr_unlock_renderer_show_warning (unlock, error->message);
		g_error_free (error);
	}

	g_signal_handler_disconnect (self->pv->parser, sig);
}

static gboolean
on_parser_authenticate_for_data (GcrParser *parser,
                                 guint count,
                                 gpointer user_data)
{
	GcrViewerWidget *self = GCR_VIEWER_WIDGET (user_data);
	GcrUnlockRenderer *unlock;

	unlock = _gcr_unlock_renderer_new_for_parsed (parser);
	if (unlock != NULL) {
		g_object_set (unlock, "label", get_parsed_label_or_display_name (self, parser), NULL);
		gcr_viewer_add_renderer (GCR_VIEWER (self), GCR_RENDERER (unlock));
		g_signal_connect (unlock, "unlock-clicked", G_CALLBACK (on_unlock_renderer_clicked), self);
		self->pv->unlocks = g_list_prepend (self->pv->unlocks, unlock);
	}

	return TRUE;
}

static void
gcr_viewer_widget_init (GcrViewerWidget *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_VIEWER_WIDGET,
	                                        GcrViewerWidgetPrivate);

	self->pv->files_to_load = g_queue_new ();
	self->pv->parser = gcr_parser_new ();
	self->pv->cancellable = g_cancellable_new ();
	self->pv->unlocks = NULL;

	g_signal_connect (self->pv->parser, "parsed", G_CALLBACK (on_parser_parsed), self);
	g_signal_connect_after (self->pv->parser, "authenticate", G_CALLBACK (on_parser_authenticate_for_data), self);
}

static void
gcr_viewer_widget_dispose (GObject *obj)
{
	GcrViewerWidget *self = GCR_VIEWER_WIDGET (obj);
	GList *l;

	g_signal_handlers_disconnect_by_func (self->pv->parser, on_parser_parsed, self);

	for (l = self->pv->unlocks; l != NULL; l = g_list_next (l)) {
		g_signal_handlers_disconnect_by_func (l->data, on_unlock_renderer_clicked, self);
		g_object_unref (l->data);
	}
	g_list_free (self->pv->unlocks);
	self->pv->unlocks = NULL;

	while (!g_queue_is_empty (self->pv->files_to_load))
		g_object_unref (g_queue_pop_head (self->pv->files_to_load));

	g_cancellable_cancel (self->pv->cancellable);

	G_OBJECT_CLASS (gcr_viewer_widget_parent_class)->dispose (obj);
}

static void
gcr_viewer_widget_finalize (GObject *obj)
{
	GcrViewerWidget *self = GCR_VIEWER_WIDGET (obj);

	g_assert (g_queue_is_empty (self->pv->files_to_load));
	g_queue_free (self->pv->files_to_load);

	g_free (self->pv->display_name);
	g_object_unref (self->pv->cancellable);
	g_object_unref (self->pv->parser);

	G_OBJECT_CLASS (gcr_viewer_widget_parent_class)->finalize (obj);
}

static void
gcr_viewer_widget_class_init (GcrViewerWidgetClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->dispose = gcr_viewer_widget_dispose;
	gobject_class->finalize = gcr_viewer_widget_finalize;

	g_type_class_add_private (klass, sizeof (GcrViewerWidget));

	/**
	 * GcrViewerWidget::added:
	 * @self: the viewer widget
	 * @renderer: (type Gcr.Renderer): the renderer that was added
	 * @parsed: (type Gcr.Parsed): the parsed item that was added
	 *
	 * This signal is emitted when an item is added to the viewer widget.
	 */
	signals[ADDED] = g_signal_new ("added", GCR_TYPE_VIEWER_WIDGET, G_SIGNAL_RUN_LAST,
	                               G_STRUCT_OFFSET (GcrViewerWidgetClass, added),
	                               NULL, NULL, _gcr_marshal_VOID__OBJECT_BOXED,
	                               G_TYPE_NONE, 2, G_TYPE_OBJECT, GCR_TYPE_PARSED);
}

static void
on_parser_parse_stream_returned (GObject *source,
                                 GAsyncResult *result,
                                 gpointer user_data)
{
	GcrViewerWidget *self = GCR_VIEWER_WIDGET (user_data);
	GError *error = NULL;
	GcrRenderer *renderer;

	gcr_parser_parse_stream_finish (self->pv->parser, result, &error);

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) ||
	    g_error_matches (error, GCR_DATA_ERROR, GCR_ERROR_CANCELLED)) {
		viewer_stop_loading_files (self);

	} else if (g_error_matches (error, GCR_DATA_ERROR, GCR_ERROR_LOCKED)) {
		/* Just skip this one, an unlock renderer was added */

	} else if (error) {
		renderer = gcr_failure_renderer_new (self->pv->display_name, error);
		gcr_viewer_add_renderer (GCR_VIEWER (self), renderer);
		g_object_unref (renderer);
		g_error_free (error);
	}

	viewer_load_next_file (self);
}

static void
update_display_name (GcrViewerWidget *self,
                     GFile *file)
{
	gchar *basename;

	basename = g_file_get_basename (file);

	g_free (self->pv->display_name);
	self->pv->display_name = g_filename_display_name (basename);

	g_free (basename);
}

static void
on_file_read_returned (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GcrViewerWidget *self = GCR_VIEWER_WIDGET (user_data);
	GFile *file = G_FILE (source);
	GError *error = NULL;
	GFileInputStream *fis;
	GcrRenderer *renderer;

	fis = g_file_read_finish (file, result, &error);
	update_display_name (self, file);

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		viewer_stop_loading_files (self);

	} else if (error) {
		renderer = gcr_failure_renderer_new (self->pv->display_name, error);
		gcr_viewer_add_renderer (GCR_VIEWER (self), renderer);
		g_object_unref (renderer);
		g_error_free (error);

		viewer_load_next_file (self);

	} else {
		gcr_parser_parse_stream_async (self->pv->parser, G_INPUT_STREAM (fis),
		                               self->pv->cancellable, on_parser_parse_stream_returned,
		                               self);
		g_object_unref (fis);
	}
}

static void
viewer_stop_loading_files (GcrViewerWidget *self)
{
	self->pv->loading = FALSE;
}

static void
viewer_load_next_file (GcrViewerWidget *self)
{
	GFile* file;

	file = g_queue_pop_head (self->pv->files_to_load);
	if (file == NULL) {
		viewer_stop_loading_files (self);
		return;
	}

	g_file_read_async (file, G_PRIORITY_DEFAULT, self->pv->cancellable,
	                   on_file_read_returned, self);

	g_object_unref (file);
}

/**
 * gcr_viewer_widget_new:
 *
 * Create a new viewer widget.
 *
 * Returns: (transfer full): A new #GcrViewerWidget object
 */
GcrViewerWidget *
gcr_viewer_widget_new (void)
{
	return g_object_new (GCR_TYPE_VIEWER_WIDGET, NULL);
}

/**
 * gcr_viewer_widget_load_file:
 * @self: a viewer widget
 * @file: a file to load
 *
 * Display contents of a file in the viewer widget. Multiple files can
 * be loaded.
 */
void
gcr_viewer_widget_load_file (GcrViewerWidget *self,
                             GFile *file)
{
	g_return_if_fail (GCR_IS_VIEWER_WIDGET (self));
	g_return_if_fail (G_IS_FILE (file));

	g_queue_push_tail (self->pv->files_to_load, g_object_ref (file));

	if (!self->pv->loading)
		viewer_load_next_file (self);
}

/**
 * gcr_viewer_widget_load_data:
 * @self: a viewer widget
 * @display_name: label for the loaded data
 * @data: (array length=n_data): data to load
 * @n_data: length of data to load
 *
 * Parse and load some data to be displayed into the viewer widgets. The data
 * may contain multiple parseable items if the format can contain multiple
 * items.
 */
void
gcr_viewer_widget_load_data (GcrViewerWidget *self,
                             const gchar *display_name,
                             const guchar *data,
                             gsize n_data)
{
	GError *error = NULL;
	GcrRenderer *renderer;

	g_return_if_fail (GCR_IS_VIEWER_WIDGET (self));

	g_free (self->pv->display_name);
	self->pv->display_name = g_strdup (display_name);

	if (!gcr_parser_parse_data (self->pv->parser, data, n_data, &error)) {
		renderer = gcr_failure_renderer_new (display_name, error);
		gcr_viewer_add_renderer (GCR_VIEWER (self), renderer);
		g_object_unref (renderer);
		g_error_free (error);
	}
}
