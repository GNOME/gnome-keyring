/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ask-tool.c - Handles graphical authentication for the keyring daemon.

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

#include "gkr-ask-tool.h"
#include "gkr-ask-request.h"

#include "egg/egg-secure-entry.h"
#include "egg/egg-secure-memory.h"

#include <gtk/gtk.h>
#include <glib/gi18n.h>

#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <syslog.h>

static GKeyFile *input_data = NULL;
static GKeyFile *output_data = NULL;
static gboolean grabbed = FALSE;

#define LOG_ERRORS 1

/* -----------------------------------------------------------------------------
 * MEMORY
 */

static gboolean do_warning = TRUE;
#define WARNING  "couldn't allocate secure memory to keep passwords " \
		 "and or keys from being written to the disk"
		 
#define ABORTMSG "The GNOME_KEYRING_PARANOID environment variable was set. " \
                 "Exiting..."

/* 
 * These are called from gkr-secure-memory.c to provide appropriate
 * locking for memory between threads
 */ 

void
egg_memory_lock (void)
{
	/* No threads used in ask tool, doesn't need locking */
}

void 
egg_memory_unlock (void)
{
	/* No threads used in ask tool, doesn't need locking */
}

void*
egg_memory_fallback (void *p, size_t sz)
{
	const gchar *env;
	
	/* We were asked to free memory */
	if (!sz) {
		g_free (p);
		return NULL;
	}
	
	/* We were asked to allocate */
	if (!p) {
		if (do_warning) {
			g_message (WARNING);
			do_warning = FALSE;
		}
		
		env = g_getenv ("GNOME_KEYRING_PARANOID");
		if (env && *env) 
			g_error (ABORTMSG);
			
		return g_malloc0 (sz);
	}
	
	/* 
	 * Reallocation is a bit of a gray area, as we can be asked 
	 * by external libraries (like libgcrypt) to reallocate a 
	 * non-secure block into secure memory. We cannot satisfy 
	 * this request (as we don't know the size of the original 
	 * block) so we just try our best here.
	 */
			 
	return g_realloc (p, sz);
}

/* -------------------------------------------------------------------------
 * HELPERS 
 */

/* Because Solaris doesn't have err() :( */
static void 
fatal (const char *msg1, const char *msg2)
{
	g_printerr ("%s: %s%s%s\n", 
	            g_get_prgname (),
	            msg1 ? msg1 : "", 
	            msg1 && msg2 ? ": " : "",
	            msg2 ? msg2 : "");
#if LOG_ERRORS
	syslog (LOG_AUTH | LOG_ERR, "%s%s%s\n", 
	         msg1 ? msg1 : "", 
	         msg1 && msg2 ? ": " : "",
	         msg2 ? msg2 : "");
#endif
	exit (1);
}

#if LOG_ERRORS

static void
log_handler (const gchar *log_domain, GLogLevelFlags log_level, 
             const gchar *message, gpointer user_data)
{
	int level;

	/* Note that crit and err are the other way around in syslog */
        
	switch (G_LOG_LEVEL_MASK & log_level) {
	case G_LOG_LEVEL_ERROR:
		level = LOG_CRIT;
		break;
	case G_LOG_LEVEL_CRITICAL:
		level = LOG_ERR;
		break;
	case G_LOG_LEVEL_WARNING:
		level = LOG_WARNING;
		break;
	case G_LOG_LEVEL_MESSAGE:
		level = LOG_NOTICE;
		break;
	case G_LOG_LEVEL_INFO:
		level = LOG_INFO;
		break;
	case G_LOG_LEVEL_DEBUG:
		level = LOG_DEBUG;
		break;
	default:
		level = LOG_ERR;
		break;
	}
    
	/* Log to syslog first */
	if (log_domain)
		syslog (level, "%s: %s", log_domain, message);
	else
		syslog (level, "%s", message);
 
    /* And then to default handler for aborting and stuff like that */
    g_log_default_handler (log_domain, log_level, message, user_data); 
}

#endif /* LOG_ERRORS */

static void
prepare_logging ()
{
	GLogLevelFlags flags = G_LOG_FLAG_FATAL | G_LOG_LEVEL_ERROR | 
	                       G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING | 
	                       G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO;
                
	openlog ("gnome-keyring-ask", 0, LOG_AUTH);
    
	g_log_set_handler (NULL, flags, log_handler, NULL);
	g_log_set_handler ("Glib", flags, log_handler, NULL);
	g_log_set_handler ("Gtk", flags, log_handler, NULL);
	g_log_set_handler ("Gnome", flags, log_handler, NULL);
	g_log_set_default_handler (log_handler, NULL);
}


static void
write_output (const gchar *data, gsize len)
{
	int res;
	
	while (len > 0) {
		res = write (1, data, len);
		if (res <= 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			g_warning ("couldn't write dialog response to output: %s",
			           g_strerror (errno));
			exit (1);
		} else  {
			len -= res;
			data += res;
		}
	}
}

/* ------------------------------------------------------------------------------ */

#if 0

/*
 * Some strings added before string freeze for the fixing of bug: 
 * http://bugzilla.gnome.org/show_bug.cgi?id=571423
 */

static void
grab_strings (void)
{
	_("<b><big>Could not grab your mouse.</big></b>"
		"\n\n"
		"A malicious client may be eavesdropping "
		"on your session or you may have just clicked "
		"a menu or some application just decided to get "
		"focus."
		"\n\n"
		"Try again.");
	
	_("<b><big>Could not grab your keyboard.</big></b>"
		"\n\n"
		"A malicious client may be eavesdropping "
		"on your session or you may have just clicked "
		"a menu or some application just decided to get "
		"focus."
		"\n\n"
		"Try again.");	
}

#endif

static gchar*
create_markup (const gchar *primary, const gchar *secondary)
{
	/* We're passed markup for both of these */
	return g_markup_printf_escaped ("<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s",
					primary, secondary ? secondary : "");

}

static gchar*
create_notice (const gchar *text)
{
	return g_markup_printf_escaped ("<span style=\"italic\">%s</span>", text);
}

static gboolean
confirm_blank_password (GtkWindow *parent)
{
	GtkWidget *dialog;
	gchar *markup;
	gint ret;
	
	dialog = gtk_message_dialog_new (parent, GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING,
	                                 GTK_BUTTONS_NONE, NULL);
	
	markup = create_markup (_("Store passwords unencrypted?"), 
	                        _("By choosing to use a blank password, your stored passwords will not be safely encrypted. "
	                          "They will be accessible by anyone with access to your files."));
	gtk_message_dialog_set_markup (GTK_MESSAGE_DIALOG (dialog), markup);
	g_free (markup);
	
	gtk_dialog_add_buttons (GTK_DIALOG (dialog), 
	                        GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
	                        _("Use Unsafe Storage"), GTK_RESPONSE_ACCEPT,
	                        NULL);
 
 	ret = gtk_dialog_run (GTK_DIALOG (dialog));
 	gtk_widget_destroy (dialog);
 	
 	return ret == GTK_RESPONSE_ACCEPT;
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

	password = egg_secure_entry_get_text (EGG_SECURE_ENTRY (editable));

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

static gboolean
grab_keyboard (GtkWidget *win, GdkEvent *event, gpointer data)
{
	GdkGrabStatus status;
	if (!grabbed) {
		status = gdk_keyboard_grab (win->window, FALSE, gdk_event_get_time (event));
		if (status == GDK_GRAB_SUCCESS)
			grabbed = TRUE;
		else
			g_message ("could not grab keyboard: %d", (int)status);
	}
	return FALSE;
}

static gboolean
ungrab_keyboard (GtkWidget *win, GdkEvent *event, gpointer data)
{
	if (grabbed)
		gdk_keyboard_ungrab (gdk_event_get_time (event));
	grabbed = FALSE;
	return FALSE;
}

static gboolean
window_state_changed (GtkWidget *win, GdkEventWindowState *event, gpointer data)
{
	GdkWindowState state = gdk_window_get_state (win->window);
	
	if (state & GDK_WINDOW_STATE_WITHDRAWN ||
	    state & GDK_WINDOW_STATE_ICONIFIED ||
	    state & GDK_WINDOW_STATE_FULLSCREEN ||
	    state & GDK_WINDOW_STATE_MAXIMIZED)
	    	ungrab_keyboard (win, (GdkEvent*)event, data);
	else
		grab_keyboard (win, (GdkEvent*)event, data);
		
	return FALSE;
}

static gint
run_dialog (gboolean include_password,
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
	char *message, *value, *value2;
	char *notice_text;
	GtkWidget *old, *entry, *confirm;
	GtkWidget *vbox, *label;
	gint response;
	va_list args;
	const char *text;
	gint response_id;
	GtkWidget *table, *ptable;
	GtkWidget *image, *check, *location;
	const char *password, *original, *confirmation;
	const char *env;
	int row;

	value = g_key_file_get_value (input_data, "general", "title", NULL);
	if (!value)
		fatal ("no 'title' field in input data", NULL);
	dialog = gtk_dialog_new_with_buttons (value, NULL, 0, NULL, NULL);
	g_free (value);
	
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
	
	value = g_key_file_get_value (input_data, "general", "primary", NULL);
	if (!value)
		fatal ("no 'primary' field in input data", NULL);
	value2 = g_key_file_get_value (input_data, "general", "secondary", NULL);

	message = create_markup (value, value2);
	g_free (value);
	g_free (value2);
	
	message_widget = GTK_LABEL (gtk_label_new (NULL));
	gtk_label_set_use_markup (message_widget, TRUE);
	gtk_label_set_markup (message_widget, message);
	g_free (message);
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

	location = gkr_ask_tool_create_location (input_data);
	if (location) {
		gtk_table_resize (GTK_TABLE (ptable), ++row, 2);
		label = gtk_label_new_with_mnemonic (_("_Location:"));
		gtk_label_set_mnemonic_widget (GTK_LABEL (label), location);
		gtk_table_attach (GTK_TABLE (ptable), label,
				  0, 1, row - 1, row,
				  GTK_FILL, GTK_SHRINK, 0, 0);
		gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
		gtk_table_attach_defaults (GTK_TABLE (ptable), location,
		                           1, 2, row - 1, row);
	}
		
	old = NULL;
	if (include_original) {
		gtk_table_resize (GTK_TABLE (ptable), ++row, 2);	
		label = gtk_label_new_with_mnemonic (_("_Old password:"));
		old = egg_secure_entry_new ();
		egg_secure_entry_set_visibility (EGG_SECURE_ENTRY (old), FALSE);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label), old);
		g_signal_connect_swapped (old,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_table_attach (GTK_TABLE (ptable), label,
				  0, 1, row - 1, row,
				  GTK_FILL, GTK_SHRINK, 0, 6);
		gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
		gtk_table_attach (GTK_TABLE (ptable), old,
				  1, 2, row - 1, row, 
				  GTK_EXPAND | GTK_FILL, GTK_SHRINK, 0, 6);
	}
	
	entry = NULL;
	if (include_password) {
		gtk_table_resize (GTK_TABLE (ptable), ++row, 2);	
		label = gtk_label_new_with_mnemonic (_("_Password:"));
		entry = egg_secure_entry_new ();
		egg_secure_entry_set_visibility (EGG_SECURE_ENTRY (entry), FALSE);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);
		g_signal_connect_swapped (entry,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_table_attach (GTK_TABLE (ptable), label,
				  0, 1, row - 1, row,
				  GTK_FILL, GTK_SHRINK, 0, 0);
		gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
		gtk_table_attach_defaults (GTK_TABLE (ptable), 
					   entry,
					   1, 2, row - 1, row);
	}

	confirm = NULL;
	if (include_confirm) {
		GtkWidget *strength_bar;
	
		gtk_table_resize (GTK_TABLE (ptable), ++row, 2);	
		label = gtk_label_new_with_mnemonic (_("_Confirm password:"));
		confirm = egg_secure_entry_new ();
		egg_secure_entry_set_visibility (EGG_SECURE_ENTRY (confirm), FALSE);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label), confirm);
		g_signal_connect_swapped (confirm,
					  "activate",
					  G_CALLBACK (gtk_window_activate_default),
					  dialog);
		gtk_table_attach (GTK_TABLE (ptable), label,
				  0, 1, row - 1, row,
				  GTK_FILL, GTK_SHRINK, 0, 0);
		gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
		gtk_table_attach_defaults (GTK_TABLE (ptable), 
					   confirm,
					   1, 2, row - 1, row);

		/* Strength bar: */
		if (entry) {
			gtk_table_resize (GTK_TABLE (ptable), ++row, 2);
			strength_bar = gtk_progress_bar_new ();
			gtk_progress_bar_set_text (GTK_PROGRESS_BAR (strength_bar), _("New password strength"));
			g_signal_connect ((gpointer) entry, "changed", G_CALLBACK (on_password_changed), strength_bar);
			gtk_table_attach_defaults (GTK_TABLE (ptable), strength_bar, 1, 2, row - 1, row);
		}
	}
	
	check = NULL;
	if (g_key_file_get_boolean (input_data, "check", "check-enable", NULL)) {
		value = g_key_file_get_value (input_data, "check", "check-text", NULL);
		if (!value)
			fatal ("'check-enable' set, but no 'check-text'", NULL);
		gtk_table_resize (GTK_TABLE (ptable), ++row, 2);
		check = gtk_check_button_new_with_mnemonic (value);
		gtk_table_attach_defaults (GTK_TABLE (ptable), check,  
		                           1, 2, row - 1, row);
		g_free (value);
	}
	
	if (row > 0)
		gtk_widget_show_all (ptable);

	/* 
	 * When passwords are involved we grab the keyboard so that people
	 * don't accidentally type their passwords in other windows.
	 */
	if (include_password || include_confirm || include_original) { 
		g_signal_connect (dialog, "map-event", G_CALLBACK (grab_keyboard), NULL);
		g_signal_connect (dialog, "unmap-event", G_CALLBACK (ungrab_keyboard), NULL);
		g_signal_connect (dialog, "window-state-event", G_CALLBACK (window_state_changed), NULL); 
	}

	/* 
	 * We do this to guarantee the dialog comes up on top. Since the code that
	 * that prompted this dialog is many processes away, we can't figure out 
	 * a window to be transient for. 
	 */
	gtk_window_set_keep_above (GTK_WINDOW (dialog), TRUE);
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);
	gtk_window_set_type_hint (GTK_WINDOW (dialog), GDK_WINDOW_TYPE_HINT_NORMAL);
	
 retry:
	gtk_widget_show (dialog);
	response = gtk_dialog_run (GTK_DIALOG (dialog));
	
	password = original = NULL;
	
	/* Get the original password */
	if (include_original && old != NULL && response >= GKR_ASK_RESPONSE_ALLOW) {
		original = egg_secure_entry_get_text (EGG_SECURE_ENTRY (old));
		*original_out = egg_secure_strdup (original);
	}

	/* Get the main password entry, and confirmation */
	if (include_password && entry != NULL && response >= GKR_ASK_RESPONSE_ALLOW) {
		password = egg_secure_entry_get_text (EGG_SECURE_ENTRY (entry));
		if (include_confirm && confirm != NULL) {
			confirmation = egg_secure_entry_get_text (EGG_SECURE_ENTRY (confirm));
			if (strcmp (password, confirmation) != 0) {
				notice_text = create_notice (_("Passwords do not match."));
				gtk_label_set_markup (notice,  notice_text);
				gtk_widget_show (GTK_WIDGET (notice));
				g_free (notice_text);			
				goto retry;
			}
		}
		*password_out = egg_secure_strdup (password);
	}
	
	/* When it's a new password and blank, double check */
	if (include_confirm && password && !password[0]) {
		
		/* Don't allow blank passwords if in paranoid mode */
		env = g_getenv ("GNOME_KEYRING_PARANOID");
		if (env && *env) {
			notice_text = create_notice (_("Password cannot be blank"));
			gtk_label_set_markup (notice, notice_text);
			gtk_widget_show (GTK_WIDGET (notice));
			g_free (notice_text);
			goto retry;
			
		/* Double check with the user */ 
		} else if (!confirm_blank_password (GTK_WINDOW (dialog))) {
			goto retry;
		}
	}
	
	if (check != NULL && response >= GKR_ASK_RESPONSE_ALLOW) {
		g_key_file_set_boolean (output_data, "check", "check-active", 
		                        gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));
	}
	
	if (location != NULL) {
		text = gkr_ask_tool_get_location (location);
		if (text != NULL)
			g_key_file_set_value (output_data, "location", "location-selected", text);
	}		                      

	gtk_widget_destroy (dialog);
	
	return response;
}

static void 
prepare_dialog (void)
{
	gchar *password = NULL;
	gchar *original = NULL;
	const gchar* buttons[6];
	guint resps[6];
	int i = 0;
	guint response;
	guint flags;
	
	memset (buttons, 0, sizeof (buttons));
	memset (resps, 0, sizeof (resps));
	
	password = original = NULL;
	
	flags = g_key_file_get_integer (input_data, "general", "flags", NULL);
	
	if (!(flags & GKR_ASK_REQUEST_BUTTONS_MASK)) 
		flags |= GKR_ASK_REQUEST_OK_DENY_BUTTONS;
	
	/* In order of preference for default response */
	if (flags & GKR_ASK_REQUEST_DENY_BUTTON) {
		buttons[i] = _("_Deny");
		resps[i++] = GKR_ASK_RESPONSE_DENY;
	}
	if (flags & GKR_ASK_REQUEST_CANCEL_BUTTON) {
		buttons[i] = GTK_STOCK_CANCEL;
		resps[i++] = GKR_ASK_RESPONSE_DENY;
	}
	if (flags & GKR_ASK_REQUEST_OK_BUTTON) {
		buttons[i] = GTK_STOCK_OK;
		resps[i++] = GKR_ASK_RESPONSE_ALLOW;
	}
	if (flags & GKR_ASK_REQUEST_CREATE_BUTTON) {
		buttons[i] = _("C_reate");
		resps[i++] = GKR_ASK_RESPONSE_ALLOW;
	}
	if (flags & GKR_ASK_REQUEST_CHANGE_BUTTON) {
		buttons[i] = _("C_hange");
		resps[i++] = GKR_ASK_RESPONSE_ALLOW;
	}
	if (flags & GKR_ASK_REQUEST_ALLOW_BUTTON) {
		buttons[i] = _("Allow _Once");
		resps[i++] = GKR_ASK_RESPONSE_ALLOW;
	}
	if (flags & GKR_ASK_REQUEST_ALLOW_FOREVER_BUTTON) {
		buttons[i] = _("_Always Allow");
		resps[i++] = GKR_ASK_RESPONSE_ALLOW_FOREVER;
	}
	
	g_assert (i > 0);
	
	password = NULL;
	response = run_dialog (flags & GKR_ASK_REQUEST_PASSWORD, 
	                       flags & GKR_ASK_REQUEST_CONFIRM_PASSWORD,
	                       flags & GKR_ASK_REQUEST_ORIGINAL_PASSWORD,
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
	
	if (!password)
		password = egg_secure_strdup ("");
	if (!original)
		original = egg_secure_strdup ("");

	/* First two lines of the response are always the passwords */
	if (response < GKR_ASK_RESPONSE_ALLOW || !(flags & GKR_ASK_REQUEST_PASSWORD))
		password[0] = 0;
	write_output (password, strlen (password));
	write_output ("\n", 1);
		
	if (response < GKR_ASK_RESPONSE_ALLOW || !(flags & GKR_ASK_REQUEST_ORIGINAL_PASSWORD))
		original[0] = 0;
	write_output (original, strlen (original));
	write_output ("\n", 1);
	
	/* Send back the response */
	g_key_file_set_integer (output_data, "general", "response", response);
	
	egg_secure_free (password);
	egg_secure_free (original);
}

static gchar*
read_all_input (void)
{
	GString *data = g_string_new ("");
	gchar buf[256];
	int r;

	for (;;) {
		r = read (0, buf, sizeof (buf));
		if (r < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			g_warning ("couldn't read auth dialog instructions from input: %s",
			           g_strerror (errno));
			exit (1);
		} 
		if (r == 0)
			break;
		g_string_append_len (data, buf, r);
	}
	
	return g_string_free (data, FALSE);
}

int
main (int argc, char *argv[])
{
	GError *err = NULL;
	gchar *data;
	gboolean ret;
	gsize length;
	
	prepare_logging ();
	
	input_data = g_key_file_new ();
	output_data = g_key_file_new ();
	
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

	data = read_all_input ();
	g_assert (data);
	
	if (!data[0])
		fatal ("no auth dialog instructions", NULL);	
	
	ret = g_key_file_load_from_data (input_data, data, strlen (data), G_KEY_FILE_NONE, &err);
	g_free (data);

	if (!ret)
		fatal ("couldn't parse auth dialog instructions", err ? err->message : "");

	prepare_dialog ();
	
	g_key_file_free (input_data);
	data = g_key_file_to_data (output_data, &length, &err);
	g_key_file_free (output_data);
	
	if (!data)
		fatal ("couldn't format auth dialog response: %s", err ? err->message : ""); 
	
	write_output (data, length);
	g_free (data);
	
	return 0;
}

