/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus-session.c - daemon registering with the session

   Copyright (C) 2007, 2009, Stefan Walter

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkd-dbus-private.h"

#include "daemon/gkd-main.h"

#include <string.h>

#define SERVICE_SESSION_MANAGER	"org.gnome.SessionManager"
#define PATH_SESSION_MANAGER	"/org/gnome/SessionManager"
#define IFACE_SESSION_MANAGER   "org.gnome.SessionManager"
#define IFACE_SESSION_CLIENT    "org.gnome.SessionManager.Client"
#define IFACE_SESSION_PRIVATE   "org.gnome.SessionManager.ClientPrivate"

static gchar *client_session_path = NULL;
static guint  client_session_signal_id = 0;

static void
send_end_session_response (GDBusConnection *conn)
{
	const gchar *reason = "";
	gboolean is_ok = TRUE;
	GError *error = NULL;
	GVariant *res;

	g_return_if_fail (client_session_path);

	res = g_dbus_connection_call_sync (conn,
					   SERVICE_SESSION_MANAGER,
					   client_session_path,
					   IFACE_SESSION_PRIVATE,
					   "EndSessionResponse",
					   g_variant_new ("(bs)",
							  is_ok,
							  reason),
					   NULL,
					   G_DBUS_CALL_FLAGS_NONE, 1000,
					   NULL, &error);

	if (error != NULL) {
		g_message ("dbus failure responding to ending session: %s", error->message);
		g_error_free (error);
		return;
	}

	g_variant_unref (res);
}

static void
unregister_daemon_in_session (GDBusConnection *conn)
{
	GVariant *res;

	if (client_session_signal_id) {
		g_dbus_connection_signal_unsubscribe (conn, client_session_signal_id);
		client_session_signal_id = 0;
	}

	if (!client_session_path)
		return;

	res = g_dbus_connection_call_sync (conn,
					   SERVICE_SESSION_MANAGER,
					   PATH_SESSION_MANAGER,
					   IFACE_SESSION_MANAGER,
					   "UnregisterClient",
					   g_variant_new ("(o)", client_session_path),
					   NULL, G_DBUS_CALL_FLAGS_NONE,
					   -1, NULL, NULL);

	g_free (client_session_path);
	client_session_path = NULL;

	g_clear_pointer (&res, g_variant_unref);
}

static void
signal_filter (GDBusConnection *conn,
	       const gchar *sender_name,
	       const gchar *object_path,
	       const gchar *interface_name,
	       const gchar *signal_name,
	       GVariant *parameters,
	       gpointer user_data)
{
	/* Quit the daemon when the session is over */
	if (g_strcmp0 (signal_name, "Stop") == 0) {
		unregister_daemon_in_session (conn);
		gkd_main_quit ();
	} else if (g_strcmp0 (signal_name, "QueryEndSession") == 0) {
		send_end_session_response (conn);
	} else if (g_strcmp0 (signal_name, "EndSession") == 0) {
		send_end_session_response (conn);
		unregister_daemon_in_session (conn);
		gkd_main_quit ();
	} else if (g_strcmp0 (signal_name, "Disconnected") == 0) {
		gkd_main_quit ();
	}
}

void
gkd_dbus_session_cleanup (GDBusConnection *conn)
{
	g_free (client_session_path);
	client_session_path = NULL;
}

/*
 * Here we register our desktop autostart id gnome-session style
 * session manager via DBus.
 */
void
gkd_dbus_session_init (GDBusConnection *conn)
{
	const gchar *app_id = "gnome-keyring-daemon";
	const gchar *client_id;
	GError *error = NULL;
	GVariant *object_path_variant;

	client_id = g_getenv ("DESKTOP_AUTOSTART_ID");
	if (!client_id)
		return;

	object_path_variant = g_dbus_connection_call_sync (conn,
							   SERVICE_SESSION_MANAGER,
							   PATH_SESSION_MANAGER,
							   IFACE_SESSION_MANAGER,
							   "RegisterClient",
							   g_variant_new ("(ss)",
									  app_id,
									  client_id),
							   G_VARIANT_TYPE ("(o)"),
							   G_DBUS_CALL_FLAGS_NONE, 1000,
							   NULL, &error);

	if (error != NULL) {
		g_message ("couldn't register in session: %s", error->message);
		g_error_free (error);
		return;
	}

	g_variant_get (object_path_variant, "(o)", &client_session_path);
	g_variant_unref (object_path_variant);

	/*
	 * Unset DESKTOP_AUTOSTART_ID in order to avoid child processes to
	 * use the same client id.
	 */
	g_unsetenv ("DESKTOP_AUTOSTART_ID");

	/*
	 * Now we register for DBus signals on that client session path
	 * These are fired specifically for us.
	 */
	client_session_signal_id = g_dbus_connection_signal_subscribe (conn,
								       NULL,
								       "org.gnome.SessionManager.ClientPrivate", NULL,
								       client_session_path, NULL,
								       G_DBUS_SIGNAL_FLAGS_NONE,
								       signal_filter, NULL, NULL);
}
