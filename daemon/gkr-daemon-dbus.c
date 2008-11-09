/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-daemon-dbus.c - daemon usage of dbus

   Copyright (C) 2007, Stefan Walter

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

#include "gkr-daemon.h"

#include "common/gkr-cleanup.h"
#include "common/gkr-dbus.h"
#include "common/gkr-daemon-util.h"

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-private.h"

#include <dbus/dbus.h>

#include <string.h>

/* Rule to send to DBus bus for which signals we're interested in */
#define SIGNAL_MATCH_RULE "type='signal',interface='org.gnome.SessionManager'"

static DBusConnection *dbus_conn = NULL;
static const char* socket_path = NULL;
static gboolean dbus_initialized = FALSE;

static DBusHandlerResult 
message_handler_cb (DBusConnection *conn, DBusMessage *message, void *user_data)
{
	DBusMessageIter args;
	DBusMessage *reply;

	if (dbus_message_get_type (message) != DBUS_MESSAGE_TYPE_METHOD_CALL ||
	    !dbus_message_is_method_call (message, GNOME_KEYRING_DAEMON_INTERFACE, "GetSocketPath") ||
	    !g_str_equal (dbus_message_get_signature (message), "")) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	g_return_val_if_fail (socket_path, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	/* Setup the result */ 
	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &args); 
	if (!dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &socket_path))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NEED_MEMORY);

	/* Send the reply */
	if (!dbus_connection_send (dbus_conn, reply, NULL))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NEED_MEMORY);
	dbus_connection_flush (dbus_conn);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
signal_filter (DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	/* Quit the daemon when the session is over */
	if (dbus_message_is_signal (msg, "org.gnome.SessionManager", "SessionOver")) {
		gkr_daemon_quit ();
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable object_vtable  = {
	NULL,
	message_handler_cb,
	NULL, 
};

static void 
daemon_dbus_cleanup (gpointer unused)
{
	if (dbus_conn) {
		dbus_bus_remove_match (dbus_conn, SIGNAL_MATCH_RULE, NULL);
		dbus_connection_unregister_object_path (dbus_conn, GNOME_KEYRING_DAEMON_PATH);
		gkr_dbus_disconnect_from_mainloop (dbus_conn, NULL);
		dbus_connection_unref (dbus_conn);
		dbus_conn = NULL;
	}
}

/* 
 * Here we register our environment variables with a gnome-session style
 * session manager via DBus. 
 */
static void 
register_environment_in_session (void)
{
	DBusMessageIter args;
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError derr = { 0 };
	const gchar **envp;
	const gchar *value;
	gchar *name;
	
	g_return_if_fail (dbus_conn);
	
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
		
		msg = dbus_message_new_method_call ("org.gnome.SessionManager",
		                                    "/org/gnome/SessionManager",
		                                    "org.gnome.SessionManager",
		                                    "Setenv");
		g_return_if_fail (msg);
		
		dbus_message_iter_init_append (msg, &args); 
		if (!dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &name) ||
		    !dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &value))
			g_return_if_reached ();
		
		g_free (name);
		value = name = NULL;
		
		/* Send message and get a handle for a reply */
		reply = dbus_connection_send_with_reply_and_block (dbus_conn, msg, 1000, &derr);
		dbus_message_unref (msg);
		
		if (!reply) {
			g_warning ("couldn't set environment variable in session: %s", derr.message);
			return;
		}
		
		dbus_message_unref (reply);
	}
}

/* 
 * Here we register our desktop autostart id gnome-session style
 * session manager via DBus. 
 */
static void 
register_daemon_in_session (void)
{
	DBusMessageIter args;
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError derr = { 0 };
	const gchar *app_id = "gnome-keyring-daemon";
	const gchar *client_id;
	
	client_id = g_getenv ("DESKTOP_AUTOSTART_ID");
	if(!client_id)
		return;
	
	g_return_if_fail (dbus_conn);
	
	msg = dbus_message_new_method_call ("org.gnome.SessionManager",
	                                    "/org/gnome/SessionManager",
	                                    "org.gnome.SessionManager",
	                                    "RegisterClient");
	g_return_if_fail (msg);
	
	dbus_message_iter_init_append (msg, &args); 
	if (!dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &app_id) ||
	    !dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &client_id))
		g_return_if_reached ();
	
	/* Send message and get a handle for a reply */
	reply = dbus_connection_send_with_reply_and_block (dbus_conn, msg, 1000, &derr);
	dbus_message_unref (msg);
	
	if (!reply) {
		g_warning ("couldn't register in session: %s", derr.message);
		return;
	}
	
	dbus_message_unref (reply);
	
	/* 
	 * Unset DESKTOP_AUTOSTART_ID in order to avoid child processes to
	 * use the same client id. 
	 */
	g_unsetenv ("DESKTOP_AUTOSTART_ID");
}

void 
gkr_daemon_dbus_setup (void)
{
	dbus_uint32_t res = 0;
	DBusError derr = { 0 };
	const gchar *env;
	
	/* 
	 * We may be launched before the DBUS session, (ie: via PAM) 
	 * and DBus tries to launch itself somehow, so double check 
	 * that it has really started.
	 */ 
	env = getenv ("DBUS_SESSION_BUS_ADDRESS");
	if (!env || !env[0])
		return;
	
	if (dbus_initialized)
		return;
	
#ifdef WITH_TESTS
	/* If running as a test, don't do DBUS stuff */
	env = g_getenv ("GNOME_KEYRING_TEST_PATH");
	if (env && env[0])
		return;
#endif

	socket_path = gkr_daemon_io_get_socket_path ();
	dbus_error_init (&derr); 

	/* Get the dbus bus and hook up */
	dbus_conn = dbus_bus_get (DBUS_BUS_SESSION, &derr);
	if (!dbus_conn) {
		g_warning ("couldn't connect to dbus session bus: %s", derr.message);
		dbus_error_free (&derr);
		return;
	}
	
	gkr_cleanup_register (daemon_dbus_cleanup, NULL);

	gkr_dbus_connect_with_mainloop (dbus_conn, NULL);

	/* Make sure dbus doesn't kill our app */
	dbus_connection_set_exit_on_disconnect (dbus_conn, FALSE);

	/* Try and grab our name */
	res = dbus_bus_request_name (dbus_conn, GNOME_KEYRING_DAEMON_SERVICE,
				     DBUS_NAME_FLAG_DO_NOT_QUEUE, &derr);
	if (dbus_error_is_set (&derr)) { 
		g_warning ("couldn't request name on session bus: %s", derr.message);
		dbus_error_free (&derr);
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
		return;
	default:
		g_return_if_reached ();
		break;
	};

	/* Now register the object */
	if (!dbus_connection_register_object_path (dbus_conn, GNOME_KEYRING_DAEMON_PATH, 
	                                           &object_vtable, NULL)) {
		g_warning ("couldn't register dbus object path");
		return;
	}
	
	/* Listen in to signals that tell us when the session will be over */
	dbus_bus_add_match (dbus_conn, SIGNAL_MATCH_RULE, NULL);
	dbus_connection_add_filter (dbus_conn, signal_filter, NULL, NULL);

	dbus_initialized = TRUE;
	
	register_environment_in_session ();
	register_daemon_in_session ();
}
