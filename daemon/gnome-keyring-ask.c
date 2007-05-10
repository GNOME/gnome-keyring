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
#include <locale.h>

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
#  define _(String) (String)
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

static char *
create_notice (const char *text)
{
	return g_strconcat ("<span style=\"italic\" >", text, "</span>", NULL);
}

enum {
	KEYRING_NAME_NORMAL,
	KEYRING_NAME_DEFAULT,
	KEYRING_NAME_UNKNOWN
};

enum {
	APPLICATION_NAME_DISPLAY_AND_PATH,
	APPLICATION_NAME_DISPLAY_ONLY,
	APPLICATION_NAME_PATH_ONLY,
	APPLICATION_NAME_UNKNOWN
};

static void
on_password_changed (GtkEditable     *editable,
		     gpointer         user_data)
{
	const char *password;
	int length;
	int i;
	int upper, lower, digit, misc;
	gdouble pwstrength;

	password = gtk_entry_get_text (GTK_ENTRY (editable));

	/*
	 * This code is based on the Master Password dialog in Firefox
	 * (pref-masterpass.js)
	 * Original code triple-licensed under the MPL, GPL, and LGPL
	 * so is license-compatible with this file
	 */

	length = strlen (password);
	upper = 0;
	lower = 0;
	digit = 0;
	misc = 0;

	for ( i = 0; i < length ; i++) {
		if (g_ascii_isdigit (password[i])) {
			digit++;
		} else if (g_ascii_islower (password[i])) {
			lower++;
		} else if (g_ascii_isupper (password[i])) {
			upper++;
		} else {
			misc++;
		}
	}

	if (length > 5) {
		length = 5;
	}
	
	if (digit > 3) {
		digit = 3;
	}
	
	if (upper > 3) {
		upper = 3;
	}
	
	if (misc > 3) {
		misc = 3;
	}
	
	pwstrength = ((length*0.1)-0.2) + (digit*0.1) + (misc*0.15) + (upper*0.1);

	if (pwstrength < 0.0) {
		pwstrength = 0.0;
	}

	if (pwstrength > 1.0) {
		pwstrength = 1.0;
	}

	gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (user_data), pwstrength);
}

static gint
run_dialog (const char *title,
	    const char *primary,
	    const char *secondary,
	    gboolean include_password,
	    gboolean include_confirm,
	    gboolean include_original,
	    char **password_out,
	    char **original_out,
	    guint default_response,
	    const gchar *first_button_text,
	    ...)
{
	GtkWidget *dialog;
	GtkLabel *message_widget;
	GtkLabel *notice;
	char *message;
	char *notice_text;
	GtkWidget *old;
	GtkWidget *entry;
	GtkWidget *confirm;
	GtkWidget *label_old;
	GtkWidget *label_entry;
	GtkWidget *label_confirm;
	gint response;
	va_list args;
	const char *text;
	gint response_id;
	GtkWidget *table;
	GtkWidget *image;
	GtkWidget *strength_bar;
	GtkWidget *strength_bar_text;
	const char *password;
	const char *confirmation;
	const char *original;
	int row;

	dialog = gtk_dialog_new_with_buttons (title , NULL, 0, NULL, NULL);
	gtk_window_set_icon_name(GTK_WINDOW(dialog), "stock_lock");
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

	table = gtk_table_new (3, 2, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE (table), 12);
	gtk_table_set_col_spacings (GTK_TABLE (table), 12);
	gtk_container_set_border_width (GTK_CONTAINER (table), 5);
	
	gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox), table, 
	                    FALSE, FALSE, 0);

	image = gtk_image_new_from_stock (GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_DIALOG);
	gtk_misc_set_alignment (GTK_MISC (image), 0.5, 0.0);

	gtk_table_attach_defaults (GTK_TABLE (table), image, 
	                    0, 1, 0 ,1);
	
	message = create_markup (primary, secondary);
	message_widget = GTK_LABEL (gtk_label_new (message));
	g_free (message);
	gtk_label_set_use_markup (message_widget, TRUE);
	gtk_misc_set_alignment (GTK_MISC (message_widget), 0.0, 0.5);
	gtk_label_set_line_wrap (message_widget, TRUE);
	gtk_label_set_justify (message_widget,
			       GTK_JUSTIFY_LEFT);
	gtk_table_attach_defaults (GTK_TABLE (table), 
				   GTK_WIDGET (message_widget),
				   1, 2, 0, 1);

	notice = GTK_LABEL (gtk_label_new (NULL));
	gtk_table_attach_defaults (GTK_TABLE (table), 
			    GTK_WIDGET (notice),
			    0, 2, 1, 2);

	row = 2;

	old = NULL;
	if (include_original) {
		label_old = gtk_label_new_with_mnemonic (_("_Old password:"));
		old = gtk_entry_new ();
		gtk_entry_set_visibility (GTK_ENTRY (old), FALSE);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label_old), 
					       old);
		g_signal_connect_swapped (old,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_table_attach_defaults (GTK_TABLE (table), 
					   label_old,
					   0, 1, row, row+1);
		gtk_misc_set_alignment (GTK_MISC (label_old), 0.0, 0.5);
		gtk_table_attach_defaults (GTK_TABLE (table), 
					   old,
					   1, 2, row, row+1);
		row++;
	}
	
	entry = NULL;
	if (include_password) {
		label_entry = gtk_label_new_with_mnemonic (_("_Password:"));
		entry = gtk_entry_new ();
		gtk_entry_set_visibility (GTK_ENTRY (entry), FALSE);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label_entry), 
					       entry);
		g_signal_connect_swapped (entry,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_table_attach_defaults (GTK_TABLE (table), 
					   label_entry,
					   0, 1, row, row+1);
		gtk_misc_set_alignment (GTK_MISC (label_entry), 0.0, 0.5);
		gtk_table_attach_defaults (GTK_TABLE (table), 
					   entry,
					   1, 2, row, row+1);
		row++;
	}

	confirm = NULL;
	if (include_confirm) {
		gtk_table_resize (GTK_TABLE (table),4,2);
		label_confirm = gtk_label_new_with_mnemonic (_("_Confirm new password:"));
		confirm = gtk_entry_new ();
		gtk_entry_set_visibility (GTK_ENTRY (confirm), FALSE);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label_confirm), confirm);
		g_signal_connect_swapped (confirm,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_table_attach_defaults (GTK_TABLE (table), 
					   label_confirm,
					   0, 1, row, row+1);
		gtk_misc_set_alignment (GTK_MISC (label_confirm), 0.0, 0.5);
		gtk_table_attach_defaults (GTK_TABLE (table), 
					   confirm,
					   1, 2, row, row+1);
		row++;

		/* Strength bar: */
		
		message = g_strconcat ("<span weight=\"bold\">",
				       _("Password strength meter:"),
				       "</span>",
				       NULL);
		strength_bar_text = gtk_label_new (message);
		g_free (message);
		gtk_label_set_use_markup (GTK_LABEL (strength_bar_text), TRUE);
		gtk_misc_set_alignment (GTK_MISC (strength_bar_text), 0.0, 0.5);
		gtk_label_set_justify (GTK_LABEL (strength_bar_text),
				       GTK_JUSTIFY_LEFT);
		gtk_table_attach_defaults (GTK_TABLE (table), 
					   strength_bar_text,
					   0, 1, row, row+1);
		
		strength_bar = gtk_progress_bar_new ();
		g_signal_connect ((gpointer) entry, "changed",
				  G_CALLBACK (on_password_changed),
				  strength_bar);
		gtk_table_attach_defaults (GTK_TABLE (table), 
					   strength_bar,
					   1, 2, row, row+1);
		row++;
	}

 retry:
	gtk_widget_show_all (dialog);
	response = gtk_dialog_run (GTK_DIALOG (dialog));
	
	if (include_original && old !=NULL && response == GTK_RESPONSE_OK) {
		original = gtk_entry_get_text (GTK_ENTRY (old));
		if (*original == 0) {
			notice_text = create_notice (_("Old password cannot be blank."));
			gtk_label_set_markup (notice,  notice_text);
			g_free (notice_text);			
			goto retry;
		}
		*original_out = g_strdup (original);
	}

	if (include_password && entry != NULL && response == GTK_RESPONSE_OK) {
		password = gtk_entry_get_text (GTK_ENTRY (entry));
		if (*password == 0) {
			notice_text = create_notice (_("Password cannot be blank."));
			gtk_label_set_markup (notice,  notice_text);
			g_free (notice_text);			
			goto retry;
		}
		if (include_confirm && confirm != NULL) {
			confirmation = gtk_entry_get_text (GTK_ENTRY (confirm));
			if (strcmp(password, confirmation) != 0) {
				notice_text = create_notice (_("Passwords do not match."));
				gtk_label_set_markup (notice,  notice_text);
				g_free (notice_text);			
				goto retry;
			}
		}
		*password_out = g_strdup (password);
	}

	gtk_widget_destroy (dialog);
	
	return response;
}


static int
get_app_information (void)
{
	if (env_app_display_name != NULL) {
		if (env_app_pathname != NULL) {
			return APPLICATION_NAME_DISPLAY_AND_PATH;
		}
		return APPLICATION_NAME_DISPLAY_ONLY;
	}
	if (env_app_pathname != NULL) {
		return APPLICATION_NAME_PATH_ONLY;
	}
	return APPLICATION_NAME_UNKNOWN;
}

static int
get_keyring_information (void)
{
	if (env_keyring_name != NULL) {
		if (strcmp (env_keyring_name, "default") == 0) {
			return KEYRING_NAME_DEFAULT;
		} else {
			return KEYRING_NAME_NORMAL;
		}
	}

	return KEYRING_NAME_UNKNOWN;
}

static void
ask_for_keyring_password (void)
{
	char *message;
	gint response;
	char *password;
	char *primary;
	int app;
	int keyring;
	
	app = get_app_information ();
	keyring = get_keyring_information ();

	if (app == APPLICATION_NAME_DISPLAY_AND_PATH) {
		if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("The application '%s' (%s) wants access to "
						     "the default keyring, but it is locked"),
						   env_app_display_name, env_app_pathname);
		} else if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("The application '%s' (%s) wants access to "
						     "the keyring '%s', but it is locked"),
						   env_app_display_name, env_app_pathname,
						   env_keyring_name);
		} else /* keyring == KEYRING_NAME_UNKNOWN */ {
			message = g_strdup_printf (_("The application '%s' (%s) wants access to "
						     "an unknown keyring, but it is locked"), 
						   env_app_display_name, env_app_pathname);
		}
	} else if (app == APPLICATION_NAME_DISPLAY_ONLY) {
		if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("The application '%s' wants access to the "
						     "default keyring, but it is locked"),
						   env_app_display_name);
		} else if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("The application '%s' wants access to the "
						     "keyring '%s', but it is locked"),
						   env_app_display_name, env_keyring_name);
		} else /* keyring == KEYRING_NAME_UNKNOWN */ {
			message = g_strdup_printf (_("The application '%s' wants access to an "
						     "unknown keyring, but it is locked"),
						   env_app_display_name);
		}
	} else if (app == APPLICATION_NAME_PATH_ONLY) {
		if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("The application '%s' wants access to the "
						     "default keyring, but it is locked"),
						   env_app_pathname);
		}
		else if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("The application '%s' wants access to the "
						     "keyring '%s', but it is locked"),
						   env_app_pathname, env_keyring_name);
		}
		else /* keyring == KEYRING_NAME_UNKNOWN */ {
			message = g_strdup_printf (_("The application '%s' wants access to an "
						     "unknown keyring, but it is locked"),
						   env_app_pathname);
		}
	} else { /* app == APPLICATION_NAME_UNKNOWN) */
		if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("An unknown application wants access to the "
						     "default keyring, but it is locked"));
		}
		else if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("An unknown application wants access to the "
						     "keyring '%s', but it is locked"),
						   env_keyring_name);
		}
		else /* keyring == KEYRING_NAME_UNKNOWN */ {
			message = g_strdup_printf (_("An unknown application wants access to an "
						     "unknown keyring, but it is locked"));
		}
	}

	if (env_keyring_name == NULL ||
	    strcmp (env_keyring_name, "default") == 0) {
		primary = g_strdup (_("Enter password for default keyring to unlock"));
	} else {
		primary = g_strdup_printf (_("Enter password for keyring '%s' to unlock"), env_keyring_name);
	}

	password = NULL;
	response = run_dialog (_("Unlock Keyring"),
			       primary,
			       message,
			       TRUE, FALSE, FALSE, &password, NULL,
			       GTK_RESPONSE_OK,
			       _("_Deny"), GTK_RESPONSE_CANCEL,
			       GTK_STOCK_OK, GTK_RESPONSE_OK,
			       NULL);
	g_free (message);
	g_free (primary);
		    
	if (response == GTK_RESPONSE_OK) {
		response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
	} else {
		response = GNOME_KEYRING_ASK_RESPONSE_DENY;
	}
	
	if (password) {
		printf ("%d\n%s\n", response, password);
		g_free (password);
	} else 
		printf ("%d\n\n", response);
}

static void
ask_for_new_keyring_password (void)
{
	char *message;
	gint response;
	int app;
	int keyring;
	char *password;
	
	app = get_app_information ();
	if (env_keyring_name == NULL) {
		env_keyring_name = "";
	}
	keyring = get_keyring_information ();
	g_assert (keyring != KEYRING_NAME_UNKNOWN);
	
	message = NULL;
	if (app == APPLICATION_NAME_DISPLAY_AND_PATH) {
		if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("The application '%s' (%s) wants to create a new keyring called '%s'. "
						     "You have to choose the password you want to use for it."),
						   env_app_display_name, env_app_pathname, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("The application '%s' (%s) wants to create a new default keyring. "
						     "You have to choose the password you want to use for it."),
						   env_app_display_name, env_app_pathname);
		} 
	} else if (app == APPLICATION_NAME_DISPLAY_ONLY) {
		if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("The application '%s' wants to create a new keyring called '%s'. "
						     "You have to choose the password you want to use for it."),
						   env_app_display_name, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("The application '%s' wants to create a new default keyring. "
						     "You have to choose the password you want to use for it."),
						   env_app_display_name);
		} 
	} else if (app == APPLICATION_NAME_PATH_ONLY) {
		if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("The application '%s' wants to create a new keyring called '%s'. "
						     "You have to choose the password you want to use for it."),
						   env_app_pathname, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("The application '%s' wants to create a new default keyring. "
						     "You have to choose the password you want to use for it."),
						   env_app_pathname);
		} 
	} else /* app == APPLICATION_NAME_UNKNOWN */ {
		if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("An unknown application wants to create a new keyring called '%s'. "
						     "You have to choose the password you want to use for it."),
						   env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("An unknown application wants to create a new default keyring. "
						     "You have to choose the password you want to use for it."));
		} 
	}

	
	password = NULL;
	response = run_dialog (_("New Keyring Password"),
			       _("Choose password for new keyring"),
			       message,
			       TRUE, TRUE, FALSE, &password, NULL,
			       GTK_RESPONSE_OK,
			       _("_Deny"), GTK_RESPONSE_CANCEL,
			       GTK_STOCK_OK, GTK_RESPONSE_OK,
			       NULL);
	g_free (message);
	
	if (response == GTK_RESPONSE_OK) {
		response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
	} else {
		response = GNOME_KEYRING_ASK_RESPONSE_DENY;
	}
	
	if (password) {
		printf ("%d\n%s\n", response, password);
		g_free (password);
	} else 
		printf ("%d\n\n", response);
}

static void
ask_for_change_keyring_password (gboolean need_original)
{
	char *message;
	char *title;
	gint response;
	int app;
	int keyring;
	char *password;
	char *original;
	
	app = get_app_information ();
	if (env_keyring_name == NULL) {
		env_keyring_name = "";
	}
	keyring = get_keyring_information ();
	g_assert (keyring != KEYRING_NAME_UNKNOWN);
	
	message = NULL;
	if (app == APPLICATION_NAME_DISPLAY_AND_PATH) {
		if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("The application '%s' (%s) wants to change the password for the '%s' keyring. "
						     "You have to choose the password you want to use for it."),
						   env_app_display_name, env_app_pathname, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("The application '%s' (%s) wants to change the password for the default keyring. "
						     "You have to choose the password you want to use for it."),
						   env_app_display_name, env_app_pathname);
		} 
	} else if (app == APPLICATION_NAME_DISPLAY_ONLY) {
		if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("The application '%s' wants to change the password for the '%s' keyring. "
						     "You have to choose the password you want to use for it."),
						   env_app_display_name, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("The application '%s' wants to change the password for the default keyring. "
						     "You have to choose the password you want to use for it."),
						   env_app_display_name);
		} 
	} else if (app == APPLICATION_NAME_PATH_ONLY) {
		if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("The application '%s' wants to change the password for the '%s' keyring. "
						     "You have to choose the password you want to use for it."),
						   env_app_pathname, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("The application '%s' wants to change the password for the default keyring. "
						     "You have to choose the password you want to use for it."),
						   env_app_pathname);
		} 
	} else /* app == APPLICATION_NAME_UNKNOWN */ {
		if (keyring == KEYRING_NAME_NORMAL) {
			message = g_strdup_printf (_("An unknown application wants to change the password for the '%s' keyring. "
						     "You have to choose the password you want to use for it."),
						   env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			message = g_strdup_printf (_("An unknown application wants to change the password for the default keyring. "
						     "You have to choose the password you want to use for it."));
		} 
	}
	
	title = NULL;
	if (keyring == KEYRING_NAME_NORMAL) {
		title = g_strdup_printf (_("Choose a new password for the '%s' keyring. "), env_keyring_name);
	} else if (keyring == KEYRING_NAME_DEFAULT) {
		title = g_strdup_printf (_("Choose a new password for the default keyring. "));
	}

	original = NULL;	
	password = NULL;	
	response = run_dialog (_("Change Keyring Password"),
			       _(title),
			       message,
			       TRUE, TRUE, need_original, &password, &original,
			       GTK_RESPONSE_OK,
			       _("_Deny"), GTK_RESPONSE_CANCEL,
			       GTK_STOCK_OK, GTK_RESPONSE_OK,
			       NULL);
	g_free (message);
	
	if (response == GTK_RESPONSE_OK) {
		response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
	} else {
		response = GNOME_KEYRING_ASK_RESPONSE_DENY;
	}
	
	if (password && original) {
		printf ("%d\n%s\n%s\n", response, original, password);
		g_free (original);
		g_free (password);
	} else if (password) {
		printf ("%d\n%s\n", response, password);
		g_free (password);
	} else {
		printf ("%d\n\n", response);
	}
}

static void
ask_for_default_keyring (void)
{
	char *message;
	gint response;
	int app;
	char *password;
	
	app = get_app_information ();
 
	if (app == APPLICATION_NAME_DISPLAY_AND_PATH) {
		message = g_strdup_printf (_("The application '%s' (%s) wants to store a password, but there is no default keyring. "
					     "To create one, you need to choose the password you wish to use for it."),
					   env_app_display_name, env_app_pathname);
	} else if (app == APPLICATION_NAME_DISPLAY_ONLY) {
		message = g_strdup_printf (_("The application '%s' wants to store a password, but there is no default keyring. "
					     "To create one, you need to choose the password you wish to use for it."),
					   env_app_display_name);
	} else if (app == APPLICATION_NAME_PATH_ONLY) {
		message = g_strdup_printf (_("The application '%s' wants to store a password, but there is no default keyring. "
					     "To create one, you need to choose the password you wish to use for it."),
					   env_app_pathname);
	} else /* app == APPLICATION_NAME_UNKNOWN */ {
		message = g_strdup_printf (_("An unknown application wants to store a password, but there is no default keyring. "
					     "To create one, you need to choose the password you wish to use for it."));
	}

	password = NULL;
	response = run_dialog (_("Create Default Keyring"),
			       _("Choose password for default keyring"),
			       message,
			       TRUE, TRUE, FALSE, &password, NULL,
			       GTK_RESPONSE_OK,
			       _("_Deny"), GTK_RESPONSE_CANCEL,
			       GTK_STOCK_OK, GTK_RESPONSE_OK,
			       NULL);
	g_free (message);

	if (response == GTK_RESPONSE_OK) {
		response = GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE;
	} else {
		response = GNOME_KEYRING_ASK_RESPONSE_DENY;
	}
	
	if (password) {
		printf ("%d\n%s\n", response, password);
		g_free (password);
	} else
		printf ("%d\n\n", response);
}


static void
ask_for_item_read_write_acccess (void)
{
	int app;
	int keyring;
	char *primary;
	char *secondary;
	const char *item;
	gint response;
	
	app = get_app_information ();
	keyring = get_keyring_information ();
	item = env_item_name;
	if (item == NULL) {
		item = "";
	}
	
	primary = _("Allow application access to keyring?");
	if (app == APPLICATION_NAME_DISPLAY_AND_PATH) {
		if (keyring == KEYRING_NAME_NORMAL) {
			secondary = g_strdup_printf (_("The application '%s' (%s) wants to access the password for '%s' in %s."),
						     env_app_display_name, env_app_pathname, item, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			secondary = g_strdup_printf (_("The application '%s' (%s) wants to access the password for '%s' in the default keyring."),
						     env_app_display_name, env_app_pathname, item);
		} else /* keyring == KEYRING_NAME_UNKNOWN */ {
			secondary = g_strdup_printf (_("The application '%s' (%s) wants to access the password for '%s' in an unknown keyring."),
						     env_app_display_name, env_app_pathname, item);
		}
	} else if (app == APPLICATION_NAME_DISPLAY_ONLY) {
		if (keyring == KEYRING_NAME_NORMAL) {
			secondary = g_strdup_printf (_("The application '%s' wants to access the password for '%s' in %s."),
						     env_app_display_name, item, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			secondary = g_strdup_printf (_("The application '%s' wants to access the password for '%s' in the default keyring."),
						     env_app_display_name, item);
		} else /* keyring == KEYRING_NAME_UNKNOWN */ {
			secondary = g_strdup_printf (_("The application '%s' wants to access the password for '%s' in an unknown keyring."),
						     env_app_display_name, item);
		}
	} else if (app == APPLICATION_NAME_PATH_ONLY) {
		if (keyring == KEYRING_NAME_NORMAL) {
			secondary = g_strdup_printf (_("The application '%s' wants to access the password for '%s' in %s."),
						     env_app_pathname, item, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			secondary = g_strdup_printf (_("The application '%s' wants to access the password for '%s' in the default keyring."),
						     env_app_pathname, item);
		} else /* keyring == KEYRING_NAME_UNKNOWN */ {
			secondary = g_strdup_printf (_("The application '%s' wants to access the password for '%s' in an unknown keyring."),
						     env_app_pathname, item);
		}
	} else /* app == APPLICATION_NAME_UNKNOWN */ {
		if (keyring == KEYRING_NAME_NORMAL) {
			secondary = g_strdup_printf (_("An unknown application wants to access the password for '%s' in %s."),
						     item, env_keyring_name);
		} else if (keyring == KEYRING_NAME_DEFAULT) {
			secondary = g_strdup_printf (_("An unknown application wants to access the password for '%s' in the default keyring."),
						     item);
		} else /* keyring == KEYRING_NAME_UNKNOWN */ {
			secondary = g_strdup_printf (_("An unknown application wants to access the password for '%s' in an unknown keyring."),
						     item);
		}
	}

	response = run_dialog (_("Allow access"),
			       primary, secondary,
			       FALSE, FALSE, FALSE, NULL, NULL,
			       2,
			       _("_Deny"), GTK_RESPONSE_CANCEL,
			       _("Allow _Once"), 1,
			       _("_Always Allow"), 2,
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
	} else if (strcmp (argv[1], "-c") == 0) {
		ask_for_change_keyring_password (FALSE);
	} else if (strcmp (argv[1], "-o") == 0) {
		ask_for_change_keyring_password (TRUE);
	} else if (strcmp (argv[1], "-i") == 0) {
		ask_for_item_read_write_acccess ();
	} else if (strcmp (argv[1], "-d") == 0) {
		ask_for_default_keyring ();
	} else {
		g_print (_("Unknown request type\n"));
	}
	
	return 0;
}
