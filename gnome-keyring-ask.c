/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-ask.c - Handles graphical authentication for the keyring daemon.

   Copyright (C) 2003 Red Hat, Inc

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Alexander Larsson <alexl@redhat.com>
*/

#include "config.h"

#include <stdio.h>
#include <string.h>

#include <gtk/gtk.h>

#include "gnome-keyring-private.h"

#ifdef ENABLE_NLS
#  include <libintl.h>
#  define _(String) gettext (String)
#  ifdef gettext_noop
#    define N_(String) gettext_noop (String)
#  else
#    define N_(String) (String)
#  endif
#else
#  define _(String)
#  define N_(String) (String)
#endif

int
main (int argc, char *argv[])
{
	const char *app_display_name;
	const char *app_pathname;
	const char *keyring_name;
	const char *item_name;
	GtkWidget *dialog;
	GtkLabel *message_widget;
	char *message;
	GtkWidget *entry;
	gint response;
	gboolean keyring;
	gboolean new_keyring;
	gboolean default_keyring;
	char *title;

	app_display_name = g_getenv ("KEYRING_APP_NAME");
	app_pathname = g_getenv ("KEYRING_APP_PATH");
	keyring_name = g_getenv ("KEYRING_NAME");
	item_name = g_getenv ("ITEM_NAME");

	gtk_init (&argc, &argv);


	keyring = FALSE;
	new_keyring = FALSE;
	default_keyring = FALSE;
	if (argc >= 2 &&
	    strcmp (argv[1], "-k") == 0) {
		keyring = TRUE;
	}
	if (argc >= 2 &&
	    strcmp (argv[1], "-n") == 0) {
		keyring = TRUE;
		new_keyring = TRUE;
	}
	if (argc >= 2 &&
	    strcmp (argv[1], "-d") == 0) {
		keyring = TRUE;
		default_keyring = TRUE;
	}
	
	if (keyring) {
		if (new_keyring) {
			title = _("New keyring password");
		} else if (default_keyring) {
			title = _("Create default keyring");
		} else {
			title = _("Unlock keyring");
		}
		
		dialog = gtk_dialog_new_with_buttons (title , NULL, 0,
						      "_Deny", GTK_RESPONSE_CANCEL,
						      GTK_STOCK_OK, GTK_RESPONSE_OK,
						      NULL);
		
		gtk_window_set_default_size (GTK_WINDOW (dialog), 300, -1);

		if (new_keyring) {
			message = g_strdup_printf (_("Enter password for new keyring %s"), keyring_name ? keyring_name : "unknown");
		} else if (default_keyring) {
			message = g_strdup_printf (_("There is no default keyring, and one is needed. Please enter the password for the new default keyring."));
		} else {
			message = g_strdup_printf (_("Enter password to unlock keyring %s"), keyring_name ? keyring_name : "unknown");
		}
		message_widget = GTK_LABEL (gtk_label_new (message));
		g_free (message);
		gtk_label_set_line_wrap (message_widget, TRUE);
		gtk_label_set_justify (message_widget,
				       GTK_JUSTIFY_LEFT);
		gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				    GTK_WIDGET (message_widget),
				    TRUE, TRUE, 6);
		
		entry = gtk_entry_new ();
		gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				    entry,
				    TRUE, TRUE, 6);
		
		gtk_widget_show_all (dialog);
		
		response = gtk_dialog_run (GTK_DIALOG (dialog));

		if (response == GTK_RESPONSE_OK) {
			response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
		} else {
			response = GNOME_KEYRING_ASK_RESPONSE_DENY;
		}
		
		printf ("%d\n%s\n", response, gtk_entry_get_text (GTK_ENTRY (entry)));

	} else {
		dialog = gtk_dialog_new_with_buttons (_("Allow access") , NULL, 0,
						      "_Deny", GTK_RESPONSE_CANCEL,
						      "_Allow Once", 1,
						      "_Allow Forever", 2,
						      NULL);
		
		gtk_window_set_default_size (GTK_WINDOW (dialog), 300, -1);
		
		message = g_strdup_printf (_("Allow app %s to access item %s"),
					   app_display_name, item_name);
		message_widget = GTK_LABEL (gtk_label_new (message));
		g_free (message);
		gtk_label_set_line_wrap (message_widget, TRUE);
		gtk_label_set_justify (message_widget,
				       GTK_JUSTIFY_LEFT);
		gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				    GTK_WIDGET (message_widget),
				    TRUE, TRUE, 6);
		
		gtk_widget_show_all (dialog);
		
		response = gtk_dialog_run (GTK_DIALOG (dialog));
		
		if (response == 1) {
			response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
		} else if (response == 2) {
			response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_FOREVER;
		} else {
			response = GNOME_KEYRING_ASK_RESPONSE_DENY;
		}
		printf ("%d\n", response);
	}

	
	return 0;
}
