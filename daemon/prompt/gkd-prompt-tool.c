/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-prompt-tool.c - Handles gui authentication for the keyring daemon.

   Copyright (C) 2009 Stefan Walter

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkd-prompt-util.h"

#include "egg/egg-dh.h"
#include "egg/egg-secure-memory.h"

#include <gcrypt.h>

#include <glib/gi18n.h>

#include <gtk/gtk.h>

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static GKeyFile *input_data = NULL;
static GKeyFile *output_data = NULL;
static gboolean keyboard_grabbed = FALSE;

/* An encryption key for returning passwords */
static gpointer the_key = NULL;
static gsize n_the_key = 0;

#define LOG_ERRORS 1

/* ------------------------------------------------------------------------------ */

static gchar*
create_markup (const gchar *primary, const gchar *secondary)
{
	return g_markup_printf_escaped ("<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s",
					primary, secondary ? secondary : "");

}

static gboolean
grab_keyboard (GtkWidget *win, GdkEvent *event, gpointer data)
{
	GdkGrabStatus status;
	if (!keyboard_grabbed) {
		status = gdk_keyboard_grab (win->window, FALSE, gdk_event_get_time (event));
		if (status == GDK_GRAB_SUCCESS) {
			keyboard_grabbed = TRUE;
		} else {
			g_message ("could not grab keyboard: %d", (int)status);
		}
	}
	return FALSE;
}

static gboolean
ungrab_keyboard (GtkWidget *win, GdkEvent *event, gpointer data)
{
	if (keyboard_grabbed)
		gdk_keyboard_ungrab (gdk_event_get_time (event));
	keyboard_grabbed = FALSE;
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

static void
prepare_visibility (GtkBuilder *builder, GtkDialog *dialog)
{
	gchar **keys, **key;
	GObject *object;

	keys = g_key_file_get_keys (input_data, "visibility", NULL, NULL);
	g_return_if_fail (keys);

	for (key = keys; key && *key; ++key) {
		object = gtk_builder_get_object (builder, *key);
		if (!GTK_IS_WIDGET (object)) {
			g_warning ("can't set visibility on invalid builder object: %s", *key);
			continue;
		}
		if (g_key_file_get_boolean (input_data, "visibility", *key, NULL))
			gtk_widget_show (GTK_WIDGET (object));
		else
			gtk_widget_hide (GTK_WIDGET (object));
	}

	g_strfreev (keys);
}

static void
prepare_titlebar (GtkBuilder *builder, GtkDialog *dialog)
{
	gchar *title;

	title = g_key_file_get_value (input_data, "prompt", "title", NULL);
	if (title)
		gtk_window_set_title (GTK_WINDOW (dialog), title);
	gtk_window_set_icon_name(GTK_WINDOW(dialog), "stock_lock");
	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);

	gtk_window_set_keep_above (GTK_WINDOW (dialog), TRUE);
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);
	gtk_window_set_type_hint (GTK_WINDOW (dialog), GDK_WINDOW_TYPE_HINT_NORMAL);
}

static void
prepare_prompt (GtkBuilder *builder, GtkDialog *dialog)
{
	gchar *primary, *secondary, *markup;
	GtkLabel *label;

	primary = g_key_file_get_value (input_data, "prompt", "primary", NULL);
	g_return_if_fail (primary);
	secondary = g_key_file_get_value (input_data, "prompt", "secondary", NULL);

	markup = create_markup (primary, secondary);
	g_free (primary);
	g_free (secondary);

	label = GTK_LABEL (gtk_builder_get_object (builder, "prompt_label"));
	g_return_if_fail (label);

	gtk_label_set_markup (label, markup);
	g_free (markup);
}

static void
prepare_buttons (GtkBuilder *builder, GtkDialog *dialog)
{
	gchar *ok_text;
	gchar *cancel_text;
	gchar *other_text;

	ok_text = g_key_file_get_value (input_data, "buttons", "ok", NULL);
	cancel_text = g_key_file_get_value (input_data, "buttons", "cancel", NULL);
	other_text = g_key_file_get_value (input_data, "buttons", "other", NULL);

	if (other_text)
		gtk_dialog_add_button (dialog, other_text, GTK_RESPONSE_APPLY);
	gtk_dialog_add_button (dialog, cancel_text ? cancel_text : GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL);
	gtk_dialog_add_button (dialog, ok_text ? ok_text : GTK_STOCK_OK, GTK_RESPONSE_OK);

	gtk_dialog_set_default_response (dialog, GTK_RESPONSE_OK);

	g_free (ok_text);
	g_free (cancel_text);
	g_free (other_text);
}

static void
prepare_security (GtkBuilder *builder, GtkDialog *dialog)
{
	/*
	 * When passwords are involved we grab the keyboard so that people
	 * don't accidentally type their passwords in other windows.
	 */
	g_signal_connect (dialog, "map-event", G_CALLBACK (grab_keyboard), NULL);
	g_signal_connect (dialog, "unmap-event", G_CALLBACK (ungrab_keyboard), NULL);
	g_signal_connect (dialog, "window-state-event", G_CALLBACK (window_state_changed), NULL);
}

static GtkDialog*
prepare_dialog (GtkBuilder *builder)
{
	GError *error = NULL;
	GtkDialog *dialog;

	if (!gtk_builder_add_from_file (builder, UIDIR "gkd-prompt.ui", &error)) {
		g_warning ("couldn't load prompt ui file: %s",
		           error && error->message ? error->message : "");
		g_clear_error (&error);
		return NULL;
	}

	dialog = GTK_DIALOG (gtk_builder_get_object (builder, "prompt_dialog"));
	g_return_val_if_fail (GTK_IS_DIALOG (dialog), NULL);

	prepare_titlebar (builder, dialog);
	prepare_prompt (builder, dialog);
	prepare_visibility (builder, dialog);
	prepare_buttons (builder, dialog);
	prepare_security (builder, dialog);

	return dialog;
}

static gboolean
negotiate_transport_crypto (void)
{
	gcry_mpi_t base, prime, peer;
	gcry_mpi_t key, pub, secret;
	gboolean ret = FALSE;

	g_assert (!the_key);
	base = prime = peer = NULL;
	key = pub = secret = NULL;

	/* The DH stuff coming in from our caller */
	if (gkd_prompt_util_decode_mpi (input_data, "transport", "prime", &prime) &&
	    gkd_prompt_util_decode_mpi (input_data, "transport", "base", &base) &&
	    gkd_prompt_util_decode_mpi (input_data, "transport", "public", &peer)) {

		/* Generate our own public/secret, and then a key, send it back */
		if (egg_dh_gen_secret (prime, base, &pub, &secret) &&
		    egg_dh_gen_key (peer, secret, prime, &key)) {

			/* Build up a key we can use */
			gkd_prompt_util_encode_mpi (output_data, "transport", "public", pub);
			if (gkd_prompt_util_mpi_to_key (key, &the_key, &n_the_key))
				ret = TRUE;
		}
	}

	gcry_mpi_release (base);
	gcry_mpi_release (prime);
	gcry_mpi_release (peer);
	gcry_mpi_release (key);
	gcry_mpi_release (pub);
	gcry_mpi_release (secret);

	return ret;
}

static void
gather_password (GtkBuilder *builder, const gchar *password_type)
{
	GtkEntry *entry;
	gchar iv[16];
	gpointer data;
	gsize n_data;

	entry = GTK_ENTRY (gtk_builder_get_object (builder, "password_entry"));
	g_return_if_fail (GTK_IS_ENTRY (entry));

	/* A non-encrypted password: just send the value back */
	if (!g_key_file_has_group (input_data, "transport")) {
		g_key_file_set_boolean (output_data, password_type, "encrypted", FALSE);
		g_key_file_set_value (output_data, password_type, "value",
		                      gtk_entry_get_text (entry));
		return;
	}

	g_key_file_set_boolean (output_data, password_type, "encrypted", TRUE);
	if (!the_key && !negotiate_transport_crypto ()) {
		g_warning ("couldn't negotiate transport crypto for password");
		return;
	}

	gcry_create_nonce (iv, sizeof (iv));
	data = gkd_prompt_util_encrypt_text (the_key, n_the_key, iv, sizeof (iv),
	                                     gtk_entry_get_text (entry), &n_data);
	g_return_if_fail (data);

	gkd_prompt_util_encode_hex (output_data, password_type, "iv", iv, sizeof (iv));
	gkd_prompt_util_encode_hex (output_data, password_type, "value", data, n_data);

	g_free (data);
}

static void
gather_response (gint response)
{
	const gchar *value = NULL;

	switch (response) {
	case GTK_RESPONSE_OK:
		value = "ok";
		break;
	case GTK_RESPONSE_CANCEL:
		value = "no";
		break;
	case GTK_RESPONSE_DELETE_EVENT:
		value = "";
		break;
	case GTK_RESPONSE_APPLY:
		value = "other";
		break;
	default:
		g_return_if_reached ();
		break;
	}

	g_key_file_set_value (output_data, "prompt", "response", value);
}

static void
gather_dialog (GtkBuilder *builder, GtkDialog *dialog)
{
	gather_password (builder, "password");
}

static void
run_dialog (void)
{
	GtkBuilder *builder;
	GtkDialog *dialog;
	gint res;

	builder = gtk_builder_new ();
	dialog = prepare_dialog (builder);
	if (!dialog) {
		g_object_unref (builder);
		return;
	}

	for (;;) {
		gtk_widget_show (GTK_WIDGET (dialog));
		res = gtk_dialog_run (dialog);
		switch (res) {
		case GTK_RESPONSE_OK:
		case GTK_RESPONSE_APPLY:
			/* if (!validate_dialog (builder, dialog, res))
				continue; */
			gather_dialog (builder, dialog);
			break;
		case GTK_RESPONSE_CANCEL:
		case GTK_RESPONSE_DELETE_EVENT:
			break;
		default:
			g_return_if_reached ();
			break;
		}

		/* Break out of the loop by default */
		break;
	}

	gather_response (res);
	g_object_unref (builder);
}

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
	/* No threads used in prompt tool, doesn't need locking */
}

void
egg_memory_unlock (void)
{
	/* No threads used in prompt tool, doesn't need locking */
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

#if LOG_ERRORS
	/* Log to syslog first */
	if (log_domain)
		syslog (level, "%s: %s", log_domain, message);
	else
		syslog (level, "%s", message);
#endif /* LOG_ERRORS */

	/* And then to default handler for aborting and stuff like that */
	g_log_default_handler (log_domain, log_level, message, user_data);
}

static void
prepare_logging ()
{
	GLogLevelFlags flags = G_LOG_FLAG_FATAL | G_LOG_LEVEL_ERROR |
	                       G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING |
	                       G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO;

	openlog ("gnome-keyring-prompt", 0, LOG_AUTH);

	g_log_set_handler (NULL, flags, log_handler, NULL);
	g_log_set_handler ("Glib", flags, log_handler, NULL);
	g_log_set_handler ("Gtk", flags, log_handler, NULL);
	g_log_set_handler ("Gnome", flags, log_handler, NULL);
	g_log_set_default_handler (log_handler, NULL);
}

static void
write_all_output (const gchar *data, gsize len)
{
	int res;

	while (len > 0) {
		res = write (1, data, len);
		if (res <= 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			if (errno != EPIPE)
				g_warning ("couldn't write dialog response to output: %s",
				           g_strerror (errno));
			exit (1);
		} else  {
			len -= res;
			data += res;
		}
	}
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

static void
hup_handler (int sig)
{
	/*
	 * Exit due to being cancelled. No real need to do any
	 * cleanup or anything. All memory will be freed on process end.
	 **/
	_exit (0);
}

int
main (int argc, char *argv[])
{
	GError *err = NULL;
	gchar *data;
	gboolean ret;
	gsize length;

	/* Exit on HUP signal */
	signal(SIGINT,  hup_handler);

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

	run_dialog ();

	/* Cleanup after any key */
	if (the_key) {
		egg_secure_clear (the_key, n_the_key);
		egg_secure_free (the_key);
		the_key = NULL;
		n_the_key = 0;
	}

	g_key_file_free (input_data);
	data = g_key_file_to_data (output_data, &length, &err);
	g_key_file_free (output_data);

	if (!data)
		fatal ("couldn't format auth dialog response: %s", err ? err->message : "");

	write_all_output (data, length);
	g_free (data);

	return 0;
}
