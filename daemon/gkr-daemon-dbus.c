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

#include "egg/egg-cleanup.h"
#include "egg/egg-dbus.h"

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-private.h"

#include "util/gkr-daemon-util.h"

#include <dbus/dbus.h>

#include <string.h>

#define SERVICE_SESSION_MANAGER	"org.gnome.SessionManager"
#define PATH_SESSION_MANAGER	"/org/gnome/SessionManager"
#define IFACE_SESSION_MANAGER   "org.gnome.SessionManager"
#define IFACE_SESSION_CLIENT    "org.gnome.SessionManager.Client"
#define IFACE_SESSION_PRIVATE   "org.gnome.SessionManager.ClientPrivate"

static DBusConnection *dbus_conn = NULL;
static gchar *client_session_path = NULL;
static gchar *client_session_rule = NULL;
static gboolean dbus_initialized = FALSE;

/* -----------------------------------------------------------------------------------
 * 
 */

static void
send_end_session_response ()
{
	DBusMessageIter args;
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError derr = { 0 };
	const gchar *reason = "";
	dbus_bool_t is_ok = TRUE;
	
	g_return_if_fail (client_session_path);
	g_return_if_fail (dbus_conn);
	
	msg = dbus_message_new_method_call (SERVICE_SESSION_MANAGER,
	                                    client_session_path,
	                                    IFACE_SESSION_PRIVATE,
	                                    "EndSessionResponse");
	g_return_if_fail (msg);
	
	dbus_message_iter_init_append (msg, &args); 
	if (!dbus_message_iter_append_basic (&args, DBUS_TYPE_BOOLEAN, &is_ok) ||
	    !dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &reason))
		g_return_if_reached ();
	
	reply = dbus_connection_send_with_reply_and_block (dbus_conn, msg, 1000, &derr);
	dbus_message_unref (msg);
	
	if (!reply) {
		g_message ("dbus failure responding to ending session: %s", derr.message);
		return;
	}

	dbus_message_unref (reply);
}

static void 
unregister_daemon_in_session (void)
{
	DBusMessageIter args;
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError derr = { 0 };

	g_return_if_fail (dbus_conn);

	if (client_session_rule) {
		dbus_bus_remove_match (dbus_conn, client_session_rule, NULL);
		g_free (client_session_rule);
		client_session_rule = NULL;
	}

	if (!client_session_path)
		return;
	
	msg = dbus_message_new_method_call (SERVICE_SESSION_MANAGER,
	                                    PATH_SESSION_MANAGER,
	                                    IFACE_SESSION_MANAGER,
	                                    "UnregisterClient");
	g_return_if_fail (msg);
	
	dbus_message_iter_init_append (msg, &args); 
	if (!dbus_message_iter_append_basic (&args, DBUS_TYPE_OBJECT_PATH, &client_session_path))
		g_return_if_reached ();
	
	reply = dbus_connection_send_with_reply_and_block (dbus_conn, msg, 1000, &derr);
	dbus_message_unref (msg);
	
	if (!reply) {
		g_message ("dbus failure unregistering from session: %s", derr.message);
		return;
	}
	
	dbus_message_unref (reply);
	
	g_free (client_session_path);
	client_session_path = NULL;
}

static DBusHandlerResult
signal_filter (DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	/* Quit the daemon when the session is over */
	if (dbus_message_is_signal (msg, IFACE_SESSION_PRIVATE, "Stop")) {
		unregister_daemon_in_session ();
		gkr_daemon_quit ();
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal (msg, IFACE_SESSION_PRIVATE, "QueryEndSession")) {
		send_end_session_response ();
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal (msg, IFACE_SESSION_PRIVATE, "EndSession")) {
		send_end_session_response ();
		unregister_daemon_in_session ();
		gkr_daemon_quit ();
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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
		reply = dbus_connection_send_with_reply_and_block (dbus_conn, msg, 1000, &derr);
		dbus_message_unref (msg);
		
		if (!reply) {
			g_message ("couldn't set environment variable in session: %s", derr.message);
			dbus_error_free (&derr);
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
	
	msg = dbus_message_new_method_call (SERVICE_SESSION_MANAGER,
	                                    PATH_SESSION_MANAGER,
	                                    IFACE_SESSION_MANAGER,
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
		g_message ("couldn't register in session: %s", derr.message);
		dbus_error_free (&derr);
		return;
	}
	
	/* Get out our client path */
	if (!dbus_message_iter_init (reply, &args) || 
	    dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_OBJECT_PATH) {
		g_message ("invalid register response from session");
	} else {
		dbus_message_iter_get_basic (&args, &client_session_path);
		client_session_path = g_strdup (client_session_path);
	}

	dbus_message_unref (reply);
	
	/* 
	 * Unset DESKTOP_AUTOSTART_ID in order to avoid child processes to
	 * use the same client id. 
	 */
	g_unsetenv ("DESKTOP_AUTOSTART_ID");
	
	/*
	 * Now we register for DBus signals on that client session path
	 * These are fired specifically for us.
	 */
	client_session_rule = g_strdup_printf("type='signal',"
	                                      "interface='org.gnome.SessionManager.ClientPrivate',"
	                                      "path='%s'", 
	                                      client_session_path);
	dbus_bus_add_match (dbus_conn, client_session_rule, &derr);
	
	if(dbus_error_is_set(&derr)) {
		g_message ("couldn't listen for signals in session: %s", derr.message);
		dbus_error_free (&derr);
		g_free (client_session_rule);
		client_session_rule = NULL;
		return;
	}

	dbus_connection_add_filter (dbus_conn, signal_filter, NULL, NULL);
}

/* -----------------------------------------------------------------------------------
 * GNOME-KEYRING DBUS INTERFACES
 */

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
		
		env = gkr_daemon_util_get_environment ();
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
	if (!dbus_connection_send (dbus_conn, reply, NULL))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NEED_MEMORY);
	dbus_connection_flush (dbus_conn);

	return DBUS_HANDLER_RESULT_HANDLED;
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
		unregister_daemon_in_session ();
		
		dbus_connection_unregister_object_path (dbus_conn, GNOME_KEYRING_DAEMON_PATH);
		egg_dbus_disconnect_from_mainloop (dbus_conn, NULL);
		dbus_connection_unref (dbus_conn);
		dbus_conn = NULL;
	}
	
	g_free (client_session_path);
	client_session_path = NULL;
	
	g_free (client_session_rule);
	client_session_rule = NULL;
}

void 
gkr_daemon_dbus_initialize (void)
{
	dbus_uint32_t res = 0;
	DBusError derr = { 0 };
	
	if (dbus_initialized)
		return;
	
#ifdef WITH_TESTS
	{
		/* If running as a test, don't do DBUS stuff */
		const gchar *env = g_getenv ("GNOME_KEYRING_TEST_PATH");
		if (env && env[0])
			return;
	}
#endif

	dbus_error_init (&derr); 

	/* Get the dbus bus and hook up */
	dbus_conn = dbus_bus_get (DBUS_BUS_SESSION, &derr);
	if (!dbus_conn) {
		g_message ("couldn't connect to dbus session bus: %s", derr.message);
		dbus_error_free (&derr);
		return;
	}
	
	egg_cleanup_register (daemon_dbus_cleanup, NULL);

	egg_dbus_connect_with_mainloop (dbus_conn, NULL);

	/* Make sure dbus doesn't kill our app */
	dbus_connection_set_exit_on_disconnect (dbus_conn, FALSE);

	/* Try and grab our name */
	res = dbus_bus_request_name (dbus_conn, GNOME_KEYRING_DAEMON_SERVICE,
				     DBUS_NAME_FLAG_DO_NOT_QUEUE, &derr);
	if (dbus_error_is_set (&derr)) { 
		g_message ("couldn't request name on session bus: %s", derr.message);
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
		break;
	default:
		g_return_if_reached ();
		break;
	};

	/* Now register the object */
	if (!dbus_connection_register_object_path (dbus_conn, GNOME_KEYRING_DAEMON_PATH, 
	                                           &object_vtable, NULL)) {
		g_message ("couldn't register dbus object path");
		return;
	}
	
	dbus_initialized = TRUE;

	/* Register with the session now that DBus is setup */
	register_environment_in_session ();
	register_daemon_in_session ();
}
