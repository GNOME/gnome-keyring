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

const char *env_app_display_name;
const char *env_app_pathname;
const char *env_keyring_name;
const char *env_item_name;

static char *
create_markup (const char *primary, const char *secondary)
{
	return g_strconcat ("<span weight=\"bold\" size=\"larger\">", primary, "</span>\n\n", secondary, NULL);
}

static gint
run_dialog (const char *title,
	    const char *primary,
	    const char *secondary,
	    gboolean include_password,
	    char **password_out,
	    guint default_response,
	    const gchar *first_button_text,
	    ...)
{
	GtkWidget *dialog;
	GtkLabel *message_widget;
	char *message;
	GtkWidget *entry;
	gint response;
	va_list args;
	const char *text;
	gint response_id;
	GtkWidget *hbox;
	GtkWidget *vbox;
	GtkWidget *image;
	const char *password;

	dialog = gtk_dialog_new_with_buttons (title , NULL, 0, NULL);
	gtk_dialog_set_has_separator (GTK_DIALOG (dialog), FALSE);
 	gtk_container_set_border_width (GTK_CONTAINER (dialog), 6);
	gtk_window_set_default_size (GTK_WINDOW (dialog), 300, -1);
	gtk_box_set_spacing (GTK_BOX (GTK_DIALOG (dialog)->vbox), 12);
 	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);

	va_start (args, first_button_text);
	
	text = first_button_text;
	response_id = va_arg (args, gint);

	while (text != NULL) {
		gtk_dialog_add_button (GTK_DIALOG (dialog), text, response_id);
			
		text = va_arg (args, char*);
		if (text == NULL) {
			break;
		}
		response_id = va_arg (args, int);
	}
	
	va_end (args);

	gtk_dialog_set_default_response (GTK_DIALOG (dialog), default_response);

	hbox = gtk_hbox_new (FALSE, 12);
	gtk_container_set_border_width (GTK_CONTAINER (hbox), 5);
	
	gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox), hbox, 
	                    FALSE, FALSE, 0);

	image = gtk_image_new_from_stock (GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_DIALOG);
	gtk_misc_set_alignment (GTK_MISC (image), 0.5, 0.0);

	gtk_box_pack_start (GTK_BOX (hbox), image, 
	                    FALSE, FALSE, 0);

	vbox = gtk_vbox_new (FALSE, 12);
	gtk_box_pack_start (GTK_BOX (hbox),
			    GTK_WIDGET (vbox),
			    FALSE, FALSE, 0);
	
	message = create_markup (primary, secondary);
	message_widget = GTK_LABEL (gtk_label_new (message));
	g_free (message);
	gtk_label_set_use_markup (message_widget, TRUE);
	gtk_misc_set_alignment (GTK_MISC (message_widget), 0.0, 0.5);
	gtk_label_set_line_wrap (message_widget, TRUE);
	gtk_label_set_justify (message_widget,
			       GTK_JUSTIFY_LEFT);
	gtk_box_pack_start (GTK_BOX (vbox),
			    GTK_WIDGET (message_widget),
			    FALSE, FALSE, 0);

	entry = NULL;
	if (include_password) {
		entry = gtk_entry_new ();
		gtk_entry_set_visibility (GTK_ENTRY (entry), FALSE);
		g_signal_connect_swapped (entry,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_box_pack_start (GTK_BOX (vbox),
				    entry,
				    FALSE, FALSE, 0);
	}

 retry:
	gtk_widget_show_all (dialog);
	response = gtk_dialog_run (GTK_DIALOG (dialog));

	if (include_password && entry != NULL) {
		password = gtk_entry_get_text (GTK_ENTRY (entry));
		if (response == GTK_RESPONSE_OK && *password == 0) {
			goto retry;
		}
		*password_out = g_strdup (password);
	}

	gtk_widget_destroy (dialog);
	
	return response;
}


static char *
get_app_string (void)
{
	if (env_app_display_name != NULL) {
		if (env_app_pathname != NULL) {
			return g_strdup_printf (_("The application '%s' (%s)"), env_app_display_name, env_app_pathname);
		}
		return g_strdup_printf (_("The application '%s'"), env_app_display_name);
	}
	if (env_app_pathname != NULL) {
		return g_strdup_printf (_("The application %s"), env_app_pathname);
	}
	return g_strdup ("An unknown application");
}

static char *
get_keyring_string (void)
{
	if (env_keyring_name != NULL) {
		if (strcmp (env_keyring_name, "default") == 0) {
			return g_strdup (_("the default keyring"));
		} else {
			return g_strdup_printf (_("the keyring '%s'"), env_keyring_name);
		}
	}
	return g_strdup (_("an unknown keyring"));
}

static void
ask_for_keyring_password (void)
{
	char *message;
	gint response;
	char *app;
	char *keyring;
	char *password;
	char *primary;
	
	app = get_app_string ();
	keyring = get_keyring_string ();

	message = g_strdup_printf (_("%s wants access to %s, but it is locked."), app, keyring);
	g_free(app);
	g_free(keyring);

	if (env_keyring_name == NULL ||
	    strcmp (env_keyring_name, "default") == 0) {
		primary = g_strdup (_("Enter password for default keyring to unlock"));
	} else {
		primary = g_strdup_printf (_("Enter password for keyring '%s' to unlock"), env_keyring_name);
	}

	response = run_dialog (_("Unlock Keyring"),
			       primary,
			       message,
			       TRUE, &password,
			       GTK_RESPONSE_OK,
			       "_Deny", GTK_RESPONSE_CANCEL,
			       GTK_STOCK_OK, GTK_RESPONSE_OK,
			       NULL);
	g_free (message);
	g_free (primary);
		    
	if (response == GTK_RESPONSE_OK) {
		response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
	} else {
		response = GNOME_KEYRING_ASK_RESPONSE_DENY;
	}
	
	printf ("%d\n%s\n", response, password);
	g_free (password);
}

static void
ask_for_new_keyring_password (void)
{
	char *message;
	gint response;
	char *app;
	const char *keyring;
	char *password;
	
	app = get_app_string ();
	keyring = env_keyring_name;
	if (keyring == NULL) {
		keyring = "";
	}

	message = g_strdup_printf (_("%s wants to create a new keyring called '%s'. "
				     "You have to choose the password you want to use for it."),
				   app, keyring);
	g_free(app);

	response = run_dialog (_("New Keyring Password"),
			       _("Choose password for new keyring"),
			       message,
			       TRUE, &password,
			       GTK_RESPONSE_OK,
			       "_Deny", GTK_RESPONSE_CANCEL,
			       GTK_STOCK_OK, GTK_RESPONSE_OK,
			       NULL);
	g_free (message);
	
	if (response == GTK_RESPONSE_OK) {
		response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
	} else {
		response = GNOME_KEYRING_ASK_RESPONSE_DENY;
	}
	
	printf ("%d\n%s\n", response, password);
	g_free (password);
}

static void
ask_for_default_keyring (void)
{
	char *message;
	gint response;
	char *app;
	char *password;
	
	app = get_app_string ();

	message = g_strdup_printf (_("%s wants to store a password, but there is no default keyring. "
				     "To create one, you need to choose the password you wish to use for it."),
				   app);
	g_free(app);

	response = run_dialog (_("Create Default Keyring"),
			       _("Choose password for default keyring"),
			       message,
			       TRUE, &password,
			       GTK_RESPONSE_OK,
			       "_Deny", GTK_RESPONSE_CANCEL,
			       GTK_STOCK_OK, GTK_RESPONSE_OK,
			       NULL);
	g_free (message);

	if (response == GTK_RESPONSE_OK) {
		response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
	} else {
		response = GNOME_KEYRING_ASK_RESPONSE_DENY;
	}
	
	printf ("%d\n%s\n", response, password);
	g_free (password);
}


static void
ask_for_item_read_write_acccess (void)
{
	char *app;
	char *keyring;
	char *primary;
	char *secondary;
	const char *item;
	gint response;
	
	app = get_app_string ();
	keyring = get_keyring_string ();
	item = env_item_name;
	if (item == NULL) {
		item = "";
	}
	
	primary = _("Allow application access to keyring?");
	secondary = g_strdup_printf (_("%s wants to access the password for '%s' in %s."),
				     app, item, keyring);
	g_free(app);
	g_free(keyring);

	response = run_dialog (_("Allow access"),
			       primary, secondary,
			       FALSE, NULL,
			       2,
			       "_Deny", GTK_RESPONSE_CANCEL,
			       "Allow _Once", 1,
			       "_Always Allow", 2,
			       NULL);
	g_free (secondary);
	
	
	if (response == 1) {
		response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
	} else if (response == 2) {
		response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_FOREVER;
	} else {
		response = GNOME_KEYRING_ASK_RESPONSE_DENY;
	}
	
	printf ("%d\n", response);
}



int
main (int argc, char *argv[])
{

	env_app_display_name = g_getenv ("KEYRING_APP_NAME");
	env_app_pathname = g_getenv ("KEYRING_APP_PATH");
	env_keyring_name = g_getenv ("KEYRING_NAME");
	env_item_name = g_getenv ("ITEM_NAME");

	gtk_init (&argc, &argv);
#ifdef HAVE_LOCALE_H
	/* internationalisation */
	setlocale (LC_ALL, "");
#endif

#ifdef HAVE_GETTEXT
	bindtextdomain (GETTEXT_PACKAGE, GNOMELOCALEDIR);
	textdomain (GETTEXT_PACKAGE);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
#endif

	if (argc < 2) {
		g_print (_("You must specify the type of request to run\n"));
		return 1;
	}

	if (strcmp (argv[1], "-k") == 0) {
		ask_for_keyring_password ();
	} else if (strcmp (argv[1], "-n") == 0) {
		ask_for_new_keyring_password ();
	} else if (strcmp (argv[1], "-i") == 0) {
		ask_for_item_read_write_acccess ();
	} else if (strcmp (argv[1], "-d") == 0) {
		ask_for_default_keyring ();
	} else {
		g_print (_("Unknown request type\n"));
	}
	
	return 0;
}
