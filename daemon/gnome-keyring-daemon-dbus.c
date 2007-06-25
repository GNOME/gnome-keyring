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

#ifdef WITH_DBUS

#include "gnome-keyring.h"
#include "gnome-keyring-private.h"
#include "gnome-keyring-daemon.h"

#include "common/gkr-cleanup.h"

#include <dbus/dbus.h>

static DBusConnection *dbus_conn = NULL;
static const char* socket_path = NULL;

/* ------------------------------------------------------------------------
 * DBUS GLIB MAIN LOOP INTEGRATION
 * 
 * Copied from dbus-gmain.c due to API instabilities in dbus-glib bindings. :( 
 */

typedef struct {
  GSource source;             /* the parent GSource */
  DBusConnection *connection; /* the connection to dispatch */
} DBusGMessageQueue;

static gboolean
message_queue_prepare (GSource *source, gint *timeout)
{
	DBusConnection *connection = ((DBusGMessageQueue *)source)->connection;  
	*timeout = -1;
	return (dbus_connection_get_dispatch_status (connection) == DBUS_DISPATCH_DATA_REMAINS);  
}

static gboolean
message_queue_check (GSource *source)
{
	return FALSE;
}

static gboolean
message_queue_dispatch (GSource *source, GSourceFunc  callback, gpointer user_data)
{
	DBusConnection *connection = ((DBusGMessageQueue *)source)->connection;
	dbus_connection_ref (connection);

	/* Only dispatch once - we don't want to starve other GSource */
	dbus_connection_dispatch (connection);
	dbus_connection_unref (connection);
	return TRUE;
}

static const GSourceFuncs message_queue_funcs = {
	message_queue_prepare,
	message_queue_check,
	message_queue_dispatch,
	NULL
};

typedef struct {
  GMainContext *context;         /* the main context */
  GSList *ios;                   /* all IOHandler */
  GSList *timeouts;              /* all TimeoutHandler */
  DBusConnection *connection;    /* NULL if this is really for a server not a connection */
  GSource *message_queue_source; /* DBusGMessageQueue */
} ConnectionSetup;

static ConnectionSetup *the_setup = NULL;

typedef struct {
  ConnectionSetup *cs;
  GSource *source;
  DBusWatch *watch;
} IOHandler;

typedef struct {
  ConnectionSetup *cs;
  GSource *source;
  DBusTimeout *timeout;
} TimeoutHandler;

static ConnectionSetup*
connection_setup_new (GMainContext *context, DBusConnection *connection)
{
	ConnectionSetup *cs = g_new0 (ConnectionSetup, 1);
	g_assert (context != NULL);
  
	cs->context = context;
	g_main_context_ref (cs->context);  

	if (connection) {
		cs->connection = connection;
		cs->message_queue_source = g_source_new ((GSourceFuncs *) &message_queue_funcs,
		                                         sizeof (DBusGMessageQueue));
		((DBusGMessageQueue*)cs->message_queue_source)->connection = connection;
		g_source_attach (cs->message_queue_source, cs->context);
	}
  
	return cs;
}

static void
io_handler_source_finalized (gpointer data)
{
	IOHandler *handler = data;
	if (handler->watch)
		dbus_watch_set_data (handler->watch, NULL, NULL);
	g_free (handler);
}

static void
io_handler_destroy_source (void *data)
{
	IOHandler *handler = data;
	if (handler->source) {
		GSource *source = handler->source;
		handler->source = NULL;
		handler->cs->ios = g_slist_remove (handler->cs->ios, handler);
		g_source_destroy (source);
		g_source_unref (source);
	}
}

static void
io_handler_watch_freed (void *data)
{
	IOHandler *handler = data;
	handler->watch = NULL;
	io_handler_destroy_source (handler);
}

static gboolean
io_handler_dispatch (GIOChannel *source, GIOCondition condition, gpointer data)
{
	IOHandler *handler = data;
	guint dbus_condition = 0;
	DBusConnection *connection = handler->cs->connection;

	if (connection)
		dbus_connection_ref (connection);
  
	if (condition & G_IO_IN)
		dbus_condition |= DBUS_WATCH_READABLE;
	if (condition & G_IO_OUT)
		dbus_condition |= DBUS_WATCH_WRITABLE;
	if (condition & G_IO_ERR)
		dbus_condition |= DBUS_WATCH_ERROR;
	if (condition & G_IO_HUP)
		dbus_condition |= DBUS_WATCH_HANGUP;

	/* Note that we don't touch the handler after this, because
	 * dbus may have disabled the watch and thus killed the
	 * handler.
	 */
	dbus_watch_handle (handler->watch, dbus_condition);
	handler = NULL;

	if (connection)
		dbus_connection_unref (connection);
  
	return TRUE;
}

static void
connection_setup_add_watch (ConnectionSetup *cs, DBusWatch *watch)
{
	guint flags;
	GIOCondition condition;
	GIOChannel *channel;
	IOHandler *handler;
  
	if (!dbus_watch_get_enabled (watch))
		return;
  
	g_assert (dbus_watch_get_data (watch) == NULL);
  
	flags = dbus_watch_get_flags (watch);

	condition = G_IO_ERR | G_IO_HUP;
	if (flags & DBUS_WATCH_READABLE)
		condition |= G_IO_IN;
	if (flags & DBUS_WATCH_WRITABLE)
		condition |= G_IO_OUT;

	handler = g_new0 (IOHandler, 1);
	handler->cs = cs;
	handler->watch = watch;
  
	channel = g_io_channel_unix_new (dbus_watch_get_fd (watch));
  
	handler->source = g_io_create_watch (channel, condition);
	g_source_set_callback (handler->source, (GSourceFunc) io_handler_dispatch, handler,
	                       io_handler_source_finalized);
	g_source_attach (handler->source, cs->context);

	cs->ios = g_slist_prepend (cs->ios, handler);
  
	dbus_watch_set_data (watch, handler, io_handler_watch_freed);
	g_io_channel_unref (channel);
}

static void
connection_setup_remove_watch (ConnectionSetup *cs, DBusWatch *watch)
{
	IOHandler *handler = dbus_watch_get_data (watch);
	if (handler != NULL)
		io_handler_destroy_source (handler);
}

static void
timeout_handler_source_finalized (gpointer data)
{
	TimeoutHandler *handler = data;
	if (handler->timeout)
		dbus_timeout_set_data (handler->timeout, NULL, NULL);
	g_free (handler);
}

static void
timeout_handler_destroy_source (void *data)
{
	TimeoutHandler *handler = data;
	if (handler->source) {
		GSource *source = handler->source;
		handler->source = NULL;
		handler->cs->timeouts = g_slist_remove (handler->cs->timeouts, handler);
		g_source_destroy (source);
		g_source_unref (source);
	}
}

static void
timeout_handler_timeout_freed (void *data)
{
	TimeoutHandler *handler = data;
	handler->timeout = NULL;
	timeout_handler_destroy_source (handler);
}

static gboolean
timeout_handler_dispatch (gpointer      data)
{
	TimeoutHandler *handler = data;
	dbus_timeout_handle (handler->timeout);
	return TRUE;
}

static void
connection_setup_add_timeout (ConnectionSetup *cs,
                              DBusTimeout     *timeout)
{
	TimeoutHandler *handler;
	if (!dbus_timeout_get_enabled (timeout))
		return;
	g_assert (dbus_timeout_get_data (timeout) == NULL);

	handler = g_new0 (TimeoutHandler, 1);
	handler->cs = cs;
	handler->timeout = timeout;

	handler->source = g_timeout_source_new (dbus_timeout_get_interval (timeout));
	g_source_set_callback (handler->source, timeout_handler_dispatch, handler,
	                       timeout_handler_source_finalized);
	g_source_attach (handler->source, handler->cs->context);
	cs->timeouts = g_slist_prepend (cs->timeouts, handler);
	dbus_timeout_set_data (timeout, handler, timeout_handler_timeout_freed);
}

static void
connection_setup_remove_timeout (ConnectionSetup *cs, DBusTimeout *timeout)
{
	TimeoutHandler *handler = dbus_timeout_get_data (timeout);
	if (handler != NULL)
		timeout_handler_destroy_source (handler);
}

static void
connection_setup_free (ConnectionSetup *cs)
{
	while (cs->ios)
		io_handler_destroy_source (cs->ios->data);

	while (cs->timeouts)
		timeout_handler_destroy_source (cs->timeouts->data);

	if (cs->message_queue_source) {
		GSource *source = cs->message_queue_source;
		cs->message_queue_source = NULL;

		g_source_destroy (source);
		g_source_unref (source);
	}
  
	g_main_context_unref (cs->context);
	g_free (cs);
}

static dbus_bool_t
add_watch (DBusWatch *watch, gpointer data)
{
	ConnectionSetup *cs = data;
	connection_setup_add_watch (cs, watch);
	return TRUE;
}

static void
remove_watch (DBusWatch *watch, gpointer data)
{
	ConnectionSetup *cs = data;
	connection_setup_remove_watch (cs, watch);
}

static void
watch_toggled (DBusWatch *watch, void *data)
{
	if (dbus_watch_get_enabled (watch))
		add_watch (watch, data);
	else
		remove_watch (watch, data);
}

static dbus_bool_t
add_timeout (DBusTimeout *timeout, void *data)
{
	ConnectionSetup *cs = data;
	if (!dbus_timeout_get_enabled (timeout))
		return TRUE;
	connection_setup_add_timeout (cs, timeout);
	return TRUE;
}

static void
remove_timeout (DBusTimeout *timeout, void *data)
{
	ConnectionSetup *cs = data;
	connection_setup_remove_timeout (cs, timeout);
}

static void
timeout_toggled (DBusTimeout *timeout, void *data)
{
	if (dbus_timeout_get_enabled (timeout))
		add_timeout (timeout, data);
	else
		remove_timeout (timeout, data);
}

static void
wakeup_main (void *data)
{
	ConnectionSetup *cs = data;
	g_main_context_wakeup (cs->context);
}

static void
connect_dbus_with_glib (DBusConnection *connection, GMainContext *context)
{
	ConnectionSetup *cs;
  
	if (context == NULL)
		context = g_main_context_default ();
	cs = connection_setup_new (context, connection);
	the_setup = cs;
  
	if (!dbus_connection_set_watch_functions (connection, add_watch,
	                                          remove_watch, watch_toggled,
	                                          cs, NULL))
		goto nomem;

	if (!dbus_connection_set_timeout_functions (connection, add_timeout,
                                                  remove_timeout, timeout_toggled,
	                                            cs, NULL))
		goto nomem;
    
	dbus_connection_set_wakeup_main_function (connection, wakeup_main, cs, NULL);
      
	return;

nomem:
	g_error ("Not enough memory to set up DBusConnection for use with GLib");
}

static void 
disconnect_dbus_from_glib (DBusConnection *connection, GMainContext *context)
{
	ConnectionSetup *cs = the_setup;
	the_setup = NULL;

	if (cs)
		connection_setup_free (cs);		
}

/* 
 * END OF DBUS GLIB CODE 
 * ----------------------------------------------------------------------*/

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

static DBusObjectPathVTable object_vtable  = {
	NULL,
	message_handler_cb,
	NULL, 
};


static void 
daemon_dbus_cleanup (gpointer unused)
{
	if (dbus_conn) {
		dbus_connection_unregister_object_path (dbus_conn, GNOME_KEYRING_DAEMON_PATH);
		disconnect_dbus_from_glib (dbus_conn, NULL);
		dbus_connection_unref (dbus_conn);
		dbus_conn = NULL;
	}
}

void 
gnome_keyring_daemon_dbus_setup (GMainLoop *loop, const gchar *socket)
{
	dbus_uint32_t res = 0;
	DBusError derr = { 0 };
	
#ifdef WITH_TESTS
	/* If running as a test, don't do DBUS stuff */
	const gchar *env = g_getenv ("GNOME_KEYRING_TEST_PATH");
	if (env && *env) 
		return;
#endif

	socket_path = socket;
	dbus_error_init (&derr); 

	/* Get the dbus bus and hook up */
	dbus_conn = dbus_bus_get (DBUS_BUS_SESSION, &derr);
	if (!dbus_conn) {
		g_warning ("couldn't connect to dbus session bus: %s", derr.message);
		dbus_error_free (&derr);
		return;
	}
	
	gkr_cleanup_register (daemon_dbus_cleanup, NULL);

	connect_dbus_with_glib (dbus_conn, NULL);

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
}


#endif /* WITH_DBUS */
