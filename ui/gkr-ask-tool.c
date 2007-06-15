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
#include <errno.h>
#include <sys/mman.h>

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

static void
unlock_memory (void)
{
#ifdef HAVE_MLOCKALL
	munlockall ();
#endif
}

static void
lock_memory (void)
{
	int r = -1;

	/* 
	 * TODO: This is a copout, due to the fact that GTK, and the entry 
	 * control in particular are hard to lock into memory. 
	 * 
	 * Since this is short lived process, should work for now. In the future
	 * we need to make this more fine grained.
	 */
#ifdef HAVE_MLOCKALL
	r = mlockall (MCL_CURRENT);
#endif

	if (r < 0)
		g_warning ("couldn't lock process in memory: %s", strerror (errno));
	else
		g_atexit (unlock_memory);
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
	GtkWidget *old, *entry, *confirm;
	GtkWidget *vbox;
	gint response;
	va_list args;
	const char *text;
	gint response_id;
	GtkWidget *table, *ptable;
	GtkWidget *image;
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
	
	vbox = gtk_vbox_new (FALSE, 12);
	gtk_widget_show (vbox);
	gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox), vbox, TRUE, TRUE, 0);

	table = gtk_table_new (1, 2, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE (table), 12);
	gtk_table_set_col_spacings (GTK_TABLE (table), 12);
	gtk_container_set_border_width (GTK_CONTAINER (table), 5);
	gtk_box_pack_start (GTK_BOX (vbox), table, FALSE, TRUE, 0);

	image = gtk_image_new_from_stock (GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_DIALOG);
	gtk_misc_set_alignment (GTK_MISC (image), 0.5, 0.0);

	gtk_table_attach (GTK_TABLE (table), image, 
	                  0, 1, 0, 1, GTK_FILL, GTK_FILL, 0, 0);
	
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
	
	gtk_widget_show_all (table);
	
	/* The notice line, goes between the two tables */
	notice = GTK_LABEL (gtk_label_new (NULL));
	gtk_box_pack_start (GTK_BOX (vbox), GTK_WIDGET (notice), FALSE, TRUE, 0);
	
	row = 0;
			   
	/* A new table for the passwords so they don't make top look strange */
	ptable = gtk_table_new (0, 2, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE (ptable), 6);
	gtk_table_set_col_spacings (GTK_TABLE (ptable), 12);
	gtk_container_set_border_width (GTK_CONTAINER (ptable), 5);
	gtk_box_pack_start (GTK_BOX (vbox), ptable, FALSE, TRUE, 0);
	
	old = NULL;
	if (include_original) {
		GtkWidget *label_old;
	
		label_old = gtk_label_new_with_mnemonic (_("_Old password:"));
		old = gtk_entry_new ();
		gtk_entry_set_visibility (GTK_ENTRY (old), FALSE);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label_old), 
					       old);
		g_signal_connect_swapped (old,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_table_attach (GTK_TABLE (ptable), label_old,
				  0, 1, row, row+1,
				  GTK_FILL, GTK_SHRINK, 0, 6);
		gtk_misc_set_alignment (GTK_MISC (label_old), 0.0, 0.5);
		gtk_table_attach (GTK_TABLE (ptable), old,
				  1, 2, row, row+1, 
				  GTK_EXPAND | GTK_FILL, GTK_SHRINK, 0, 6);
		row++;
	}
	
	entry = NULL;
	if (include_password) {
		GtkWidget *label_entry;
		
		label_entry = gtk_label_new_with_mnemonic (_("_Password:"));
		entry = gtk_entry_new ();
		gtk_entry_set_visibility (GTK_ENTRY (entry), FALSE);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label_entry), 
					       entry);
		g_signal_connect_swapped (entry,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_table_attach (GTK_TABLE (ptable), label_entry,
				  0, 1, row, row+1,
				  GTK_FILL, GTK_SHRINK, 0, 0);
		gtk_misc_set_alignment (GTK_MISC (label_entry), 0.0, 0.5);
		gtk_table_attach_defaults (GTK_TABLE (ptable), 
					   entry,
					   1, 2, row, row+1);
		row++;
	}

	confirm = NULL;
	if (include_confirm) {
		GtkWidget *label_confirm;
		GtkWidget *strength_bar;
	
		gtk_table_resize (GTK_TABLE (ptable),4,2);
		label_confirm = gtk_label_new_with_mnemonic (_("_Confirm password:"));
		confirm = gtk_entry_new ();
		gtk_entry_set_visibility (GTK_ENTRY (confirm), FALSE);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label_confirm), confirm);
		g_signal_connect_swapped (confirm,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_table_attach (GTK_TABLE (ptable), label_confirm,
				  0, 1, row, row+1,
				  GTK_FILL, GTK_SHRINK, 0, 0);
		gtk_misc_set_alignment (GTK_MISC (label_confirm), 0.0, 0.5);
		gtk_table_attach_defaults (GTK_TABLE (ptable), 
					   confirm,
					   1, 2, row, row+1);
		row++;

		/* Strength bar: */
		strength_bar = gtk_progress_bar_new ();
		gtk_progress_bar_set_text (GTK_PROGRESS_BAR (strength_bar), _("New password strength"));
		g_signal_connect ((gpointer) entry, "changed",
				  G_CALLBACK (on_password_changed),
				  strength_bar);
		gtk_table_attach_defaults (GTK_TABLE (ptable), 
					   strength_bar,
					   1, 2, row, row+1);
		row++;
	}
	
	if (row > 0)
		gtk_widget_show_all (ptable);

	/*
	 * We do this as late as possible, so all the memory the process needs is 
	 * allocated in memory. This prevents mapping failures.
	 */
	lock_memory ();

 retry:
	gtk_widget_show (dialog);
	response = gtk_dialog_run (GTK_DIALOG (dialog));
	
	if (include_original && old !=NULL && response >= GKR_ASK_RESPONSE_ALLOW) {
		original = gtk_entry_get_text (GTK_ENTRY (old));
		if (*original == 0) {
			notice_text = create_notice (_("Old password cannot be blank."));
			gtk_label_set_markup (notice,  notice_text);
			gtk_widget_show (GTK_WIDGET (notice));
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
			gtk_widget_show (GTK_WIDGET (notice));
			g_free (notice_text);			
			goto retry;
		}
		if (include_confirm && confirm != NULL) {
			confirmation = gtk_entry_get_text (GTK_ENTRY (confirm));
			if (strcmp(password, confirmation) != 0) {
				notice_text = create_notice (_("Passwords do not match."));
				gtk_label_set_markup (notice,  notice_text);
				gtk_widget_show (GTK_WIDGET (notice));
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
	
	if (!(env_flags & GKR_ASK_REQUEST_BUTTONS_MASK)) 
		env_flags |= GKR_ASK_REQUEST_OK_DENY_BUTTONS;
	
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

