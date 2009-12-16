/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus-service.c - gnome-keyring dbus service

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
#include "gkd-util.h"
#include "gkr-daemon.h"

#include <dbus/dbus.h>

#include <string.h>

static gboolean object_registered = FALSE;

#define GNOME_KEYRING_DAEMON_SERVICE    "org.gnome.keyring"
#define GNOME_KEYRING_DAEMON_PATH       "/org/gnome/keyring/daemon"
#define GNOME_KEYRING_DAEMON_INTERFACE  "org.gnome.keyring.Daemon"

static DBusHandlerResult
message_handler_cb (DBusConnection *conn, DBusMessage *message, void *user_data)
{
	/*
	 * Here we handle the requests to our own gnome-keyring DBus interfaces
	 */

	DBusMessageIter args;
	DBusMessage *reply = NULL;

	/* GetSocketPath */
	if (dbus_message_get_type (message) == DBUS_MESSAGE_TYPE_METHOD_CALL &&
	    dbus_message_is_method_call (message, GNOME_KEYRING_DAEMON_INTERFACE, "GetSocketPath") &&
	    g_str_equal (dbus_message_get_signature (message), "")) {

		const gchar *socket_path = gkr_daemon_io_get_socket_path ();
		g_return_val_if_fail (socket_path, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		/* Setup the result */
		reply = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply, &args);
		if (!dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &socket_path))
			g_return_val_if_reached (DBUS_HANDLER_RESULT_NEED_MEMORY);

	/* GetEnvironment */
	} else if (dbus_message_get_type (message) == DBUS_MESSAGE_TYPE_METHOD_CALL &&
	           dbus_message_is_method_call (message, GNOME_KEYRING_DAEMON_INTERFACE, "GetEnvironment") &&
	           g_str_equal (dbus_message_get_signature (message), "")) {

		const gchar **env;
		DBusMessageIter items, entry;
		gchar **parts;

		env = gkd_util_get_environment ();
		g_return_val_if_fail (env, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		/* Setup the result */
		reply = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply, &args);
		if (!dbus_message_iter_open_container (&args, DBUS_TYPE_ARRAY, "{ss}", &items))
			g_return_val_if_reached (DBUS_HANDLER_RESULT_NEED_MEMORY);
		while (*env) {
			parts = g_strsplit (*env, "=", 2);
			g_return_val_if_fail (parts && parts[0] && parts[1], DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
			if (!dbus_message_iter_open_container (&items, DBUS_TYPE_DICT_ENTRY, NULL, &entry) ||
			    !dbus_message_iter_append_basic (&entry, DBUS_TYPE_STRING, &parts[0]) ||
			    !dbus_message_iter_append_basic (&entry, DBUS_TYPE_STRING, &parts[1]) ||
			    !dbus_message_iter_close_container (&items, &entry))
				g_return_val_if_reached (DBUS_HANDLER_RESULT_NEED_MEMORY);
			++env;
		}
		if (!dbus_message_iter_close_container (&args, &items))
			g_return_val_if_reached (DBUS_HANDLER_RESULT_NEED_MEMORY);

	/* Unknown call */
	} else {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Send the reply */
	if (!dbus_connection_send (conn, reply, NULL))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NEED_MEMORY);
	dbus_connection_flush (conn);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusObjectPathVTable object_vtable  = {
	NULL,
	message_handler_cb,
	NULL,
};

void
gkd_dbus_service_init (DBusConnection *conn)
{
	dbus_uint32_t res = 0;
	DBusError derr = { 0 };

	dbus_error_init (&derr);

	/* Try and grab our name */
	res = dbus_bus_request_name (conn, GNOME_KEYRING_DAEMON_SERVICE, 0, &derr);
	if (dbus_error_is_set (&derr)) {
		g_message ("couldn't request name on session bus: %s", derr.message);
		dbus_error_free (&derr);
		return;
	}

	switch (res) {
	/* We acquired the service name */
	case DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER:
		break;
	/* We already acquired the service name. Odd */
	case DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER:
		g_return_if_reached ();
		break;
	/* Another daemon is running */
	case DBUS_REQUEST_NAME_REPLY_IN_QUEUE:
	case DBUS_REQUEST_NAME_REPLY_EXISTS:
		g_message ("another gnome-keyring-daemon is running");
		break;
	default:
		g_return_if_reached ();
		break;
	};

	/* Now register the object */
	if (dbus_connection_register_object_path (conn, GNOME_KEYRING_DAEMON_PATH, 
	                                          &object_vtable, NULL))
		object_registered = TRUE;
	else
		g_message ("couldn't register dbus object path");
}

void
gkd_dbus_service_cleanup (DBusConnection *conn)
{
	if (object_registered)
		dbus_connection_unregister_object_path (conn, GNOME_KEYRING_DAEMON_PATH);
	object_registered = FALSE;
}
