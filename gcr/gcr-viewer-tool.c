/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gcr-viewer-tool.c: Command line utility

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

#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <locale.h>
#include <stdlib.h>
#include <string.h>

static gchar **remaining_args = NULL;

static gboolean
print_version_and_exit (const gchar *option_name, const gchar *value,
                        gpointer data, GError **error)
{
	g_print("%s -- %s\n", _("GCR Certificate and Key Viewer"), VERSION);
	exit (0);
	return TRUE;
}

static const GOptionEntry options[] = {
	{ "version", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
	  print_version_and_exit, N_("Show the application's version"), NULL},
	{ G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY,
	  &remaining_args, NULL, N_("[file...]") },
	{ NULL }
};

static gboolean
on_idle_load_files (gpointer user_data)
{
	GcrViewerWindow *window = GCR_VIEWER_WINDOW (user_data);
	GFile *file;
	gint i;

	if (remaining_args) {
		for (i = 0; remaining_args[i] != NULL; ++i) {
			file = g_file_new_for_commandline_arg (remaining_args[i]);
			gcr_viewer_window_load (window, file);
			g_object_unref (file);
		}

		g_strfreev (remaining_args);
		remaining_args = NULL;
	}

	return FALSE; /* Don't run this again */
}

static gboolean
on_window_delete_event (GtkWidget *widget, GdkEvent *event, gpointer unused)
{
	gtk_main_quit ();
	gtk_widget_hide (widget);
	return TRUE;
}

int
main (int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	GtkWindow *window;

	g_type_init ();
	g_thread_init (NULL);

#ifdef HAVE_LOCALE_H
	/* internationalisation */
	setlocale (LC_ALL, "");
#endif

#ifdef HAVE_GETTEXT
	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	textdomain (GETTEXT_PACKAGE);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
#endif

	context = g_option_context_new (N_("- View certificate and key files"));
	g_option_context_set_translation_domain (context, GETTEXT_PACKAGE);
	g_option_context_add_main_entries (context, options, GETTEXT_PACKAGE);

	g_option_context_add_group (context, gtk_get_option_group (TRUE));

	if (! g_option_context_parse (context, &argc, &argv, &error)) {
		g_critical ("Failed to parse arguments: %s", error->message);
		g_error_free (error);
		g_option_context_free (context);
		return 1;
	}

	g_option_context_free (context);
	g_set_application_name (_("Certificate Viewer"));

	gtk_init (&argc, &argv);

	window = gcr_viewer_window_new ();
	gtk_widget_show (GTK_WIDGET (window));

	g_idle_add (on_idle_load_files, window);
	g_signal_connect (window, "delete-event", G_CALLBACK (on_window_delete_event), NULL);
	gtk_main ();

	gtk_widget_destroy (GTK_WIDGET (window));
	return 0;
}
