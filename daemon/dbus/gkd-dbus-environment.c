/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus-session.c - daemon registering environment variables with session

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

#include "daemon/gkd-util.h"

#include <string.h>

#define SERVICE_SESSION_MANAGER	"org.gnome.SessionManager"
#define PATH_SESSION_MANAGER	"/org/gnome/SessionManager"
#define IFACE_SESSION_MANAGER   "org.gnome.SessionManager"

void
gkd_dbus_environment_cleanup (GDBusConnection *conn)
{
	/* Nothing to do here */
}

static void
setenv_request (GDBusConnection *conn, const gchar *env)
{
	const gchar *value;
	gchar *name;
	GVariant *res;
	GError *error = NULL;

	/* Find the value part of the environment variable */
	value = strchr (env, '=');
	if (!value)
		return;

	name = g_strndup (env, value - env);
	++value;

	/* Note: This call does not neccessarily need to be a sync call. However
	 *       under certain conditions the process will quit immediately
	 *       after emitting the call. This ensures that we wait long enough
	 *       for the message to be sent out (could also be done using
	 *       g_dbus_connection_flush() in the exit handler when called with
	 *       --start) and also ensures that gnome-session has processed the
	 *       DBus message before possibly thinking that the startup of
	 *       gnome-keyring has finished and continuing with forking the
	 *       shell. */
	res = g_dbus_connection_call_sync (conn,
					   SERVICE_SESSION_MANAGER,
					   PATH_SESSION_MANAGER,
					   IFACE_SESSION_MANAGER,
					   "Setenv",
					   g_variant_new ("(ss)",
							  name,
							  value),
					   NULL, G_DBUS_CALL_FLAGS_NONE,
					   -1, NULL, &error);

	if (error != NULL) {
		if (g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN))
			g_debug ("couldn't set environment variable in session: %s", error->message);
		else
			g_message ("couldn't set environment variable in session: %s", error->message);
		g_error_free (error);
	}

	g_free (name);
	g_clear_pointer (&res, g_variant_unref);
}

static void
on_watch_environment (gpointer data, gpointer user_data)
{
	GDBusConnection *conn = user_data;
	const gchar *env = data;
	setenv_request (conn, env);
}

void
gkd_dbus_environment_init (GDBusConnection *conn)
{
	const gchar **envp;

	/*
	 * The list of all environment variables registered by
	 * various components in the daemon.
	 */
	envp = gkd_util_get_environment ();

	for (; *envp; ++envp)
		setenv_request (conn, *envp);

	gkd_util_watch_environment (on_watch_environment, g_object_ref (conn),
				    (GDestroyNotify) g_object_unref);
}
