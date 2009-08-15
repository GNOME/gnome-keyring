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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkd-dbus-private.h"

#include "util/gkr-daemon-util.h"

#include <dbus/dbus.h>

#include <string.h>

#define SERVICE_SESSION_MANAGER	"org.gnome.SessionManager"
#define PATH_SESSION_MANAGER	"/org/gnome/SessionManager"
#define IFACE_SESSION_MANAGER   "org.gnome.SessionManager"

void
gkd_dbus_environment_cleanup (DBusConnection *conn)
{
	/* Nothing to do here */
}

void
gkd_dbus_environment_init (DBusConnection *conn)
{
	DBusMessageIter args;
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError derr = { 0 };
	const gchar **envp;
	const gchar *value;
	gchar *name;

	/*
	 * The list of all environment variables registered by
	 * various components in the daemon.
	 */
	envp = gkr_daemon_util_get_environment ();

	for (; *envp; ++envp) {

		/* Find the value part of the environment variable */
		value = strchr (*envp, '=');
		if (!value)
			continue;

		name = g_strndup (*envp, value - *envp);
		++value;

		msg = dbus_message_new_method_call (SERVICE_SESSION_MANAGER,
		                                    PATH_SESSION_MANAGER,
		                                    IFACE_SESSION_MANAGER,
		                                    "Setenv");
		g_return_if_fail (msg);

		dbus_message_iter_init_append (msg, &args);
		if (!dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &name) ||
		    !dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &value))
			g_return_if_reached ();

		g_free (name);
		value = name = NULL;

		/* Send message and get a handle for a reply */
		reply = dbus_connection_send_with_reply_and_block (conn, msg, 1000, &derr);
		dbus_message_unref (msg);

		if (!reply) {
			g_message ("couldn't set environment variable in session: %s", derr.message);
			dbus_error_free (&derr);
			return;
		}

		dbus_message_unref (reply);
	}
}
