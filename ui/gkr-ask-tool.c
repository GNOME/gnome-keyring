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
#include <stdlib.h>

#include <gtk/gtk.h>
#include <glib/gi18n.h>

#include "gkr-ask-request.h"

static const gchar *env_title = NULL;
static const gchar *env_primary = NULL;
static const gchar *env_secondary = NULL;
static guint env_flags = 0;

static gchar*
create_markup (const gchar *primary, const gchar *secondary)
{
	return g_markup_printf_escaped ("<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s", 
	                                primary, secondary);
}

static gchar*
create_notice (const gchar *text)
{
	return g_markup_printf_escaped ("<span style=\"italic\">%s</span>", text);
}

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
		
		message = g_markup_printf_escaped ("<span weight=\"bold\">%s</span>",
		                                   _("Password strength meter:"));
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
	
	if (include_original && old !=NULL && response >= GKR_ASK_RESPONSE_ALLOW) {
		original = gtk_entry_get_text (GTK_ENTRY (old));
		if (*original == 0) {
			notice_text = create_notice (_("Old password cannot be blank."));
			gtk_label_set_markup (notice,  notice_text);
			g_free (notice_text);			
			goto retry;
		}
		*original_out = g_strdup (original);
	}

	if (include_password && entry != NULL && response >= GKR_ASK_RESPONSE_ALLOW) {
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

static void 
prepare_dialog (void)
{
	gchar *password, *original;
	const gchar* buttons[6];
	guint resps[6];
	int i = 0;
	guint response;
	
	g_assert (env_title);
	g_assert (env_primary);
	
	memset (buttons, 0, sizeof (buttons));
	memset (resps, 0, sizeof (resps));
	
	password = original = NULL;
	
	if (!env_flags) 
		env_flags = GKR_ASK_REQUEST_OK_DENY_BUTTONS;
	
	/* In order of preference for default response */
	if (env_flags & GKR_ASK_REQUEST_DENY_BUTTON) {
		buttons[i] = _("Deny");
		resps[i++] = GKR_ASK_RESPONSE_DENY;
	}
	if (env_flags & GKR_ASK_REQUEST_CANCEL_BUTTON) {
		buttons[i] = GTK_STOCK_CANCEL;
		resps[i++] = GKR_ASK_RESPONSE_DENY;
	}
	if (env_flags & GKR_ASK_REQUEST_OK_BUTTON) {
		buttons[i] = GTK_STOCK_OK;
		resps[i++] = GKR_ASK_RESPONSE_ALLOW;
	}
	if (env_flags & GKR_ASK_REQUEST_ALLOW_BUTTON) {
		buttons[i] = _("Allow _Once");
		resps[i++] = GKR_ASK_RESPONSE_ALLOW;
	}
	if (env_flags & GKR_ASK_REQUEST_ALLOW_FOREVER_BUTTON) {
		buttons[i] = _("_Always Allow");
		resps[i++] = GKR_ASK_RESPONSE_ALLOW_FOREVER;
	}
	
	g_assert (i > 0);
	
	password = NULL;
	response = run_dialog (env_title, env_primary, env_secondary,
	                       env_flags & GKR_ASK_REQUEST_PASSWORD, 
	                       env_flags & GKR_ASK_REQUEST_CONFIRM_PASSWORD,
	                       env_flags & GKR_ASK_REQUEST_ORIGINAL_PASSWORD,
	                       &password, &original, 
	                       resps[i - 1], /* default response, last one added */
	                       buttons[0], resps[0],
	                       buttons[1], resps[1],
	                       buttons[2], resps[2],
	                       buttons[3], resps[3],
	                       buttons[4], resps[4],
	                       buttons[5], resps[5],
	                       NULL);
	
	if (response == GTK_RESPONSE_DELETE_EVENT) {
		response = GKR_ASK_RESPONSE_DENY;
	} else if (response <= 0) {
		g_warning ("invalid respnose returned from dialog: %d", response);
		response = GKR_ASK_RESPONSE_FAILURE;
	}
	
	/* Send back the response */
	printf ("%d\n", response);
	
	if (response >= GKR_ASK_RESPONSE_ALLOW) {
		
		/* Send back the password */
		if ((env_flags & GKR_ASK_REQUEST_PASSWORD) && password)
			printf ("%s\n", password);
	
		/* And the original */
		if ((env_flags & GKR_ASK_REQUEST_ORIGINAL_PASSWORD) && original)
			printf ("%s", original);
	}
}

int
main (int argc, char *argv[])
{
	const gchar *flags;
	
	env_title = g_getenv ("ASK_TITLE");
	env_primary = g_getenv ("ASK_PRIMARY");
	env_secondary = g_getenv ("ASK_SECONDARY");
	flags = g_getenv ("ASK_FLAGS");
	
	if (!env_title || !env_primary || !env_secondary || !flags) {
		g_printerr (_("Must be run from gnome-keyring\n"));
		return 1;
	}
	
	env_flags = atoi (flags);

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

	prepare_dialog ();
	
	return 0;
}

