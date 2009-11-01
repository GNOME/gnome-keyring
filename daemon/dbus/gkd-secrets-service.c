/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "gkd-dbus-util.h"
#include "gkd-secrets-objects.h"
#include "gkd-secrets-prompt.h"
#include "gkd-secrets-service.h"
#include "gkd-secrets-session.h"
#include "gkd-secrets-types.h"
#include "gkd-secrets-unlock.h"

#include "egg/egg-unix-credentials.h"

#include "gp11/gp11.h"

#include "pkcs11/pkcs11i.h"

#include <string.h>

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_PKCS11_SLOT,
#if 0
	/* Secrets Service Properties */
	PROP_COLLECTIONS,
	PROP_DEFAULT_COLLECTION
#endif
};

struct _GkdSecretsService {
	GObject parent;
	DBusConnection *connection;
	GHashTable *clients;
	gchar *match_rule;
	GkdSecretsObjects *objects;
#if 0
	gchar *default_collection;
#endif
};

#if 0
#define LOC_DEFAULT_FILE    (gkd_location_from_string ("LOCAL:/keyrings/default"))
#endif

typedef struct _ServiceClient {
	gchar *caller_peer;
	gchar *caller_exec;
	pid_t caller_pid;
	CK_G_APPLICATION app;
	GP11Session *pkcs11_session;
	GHashTable *sessions;
	GHashTable *prompts;
} ServiceClient;

/* Forward declaration */
static void service_dispatch_message (GkdSecretsService *, DBusMessage *);

G_DEFINE_TYPE (GkdSecretsService, gkd_secrets_service, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

#if 0
static void
update_default (GkdSecretsService *self)
{
	gchar *contents;

	if (gkd_location_read_file (LOC_DEFAULT_FILE, (guchar**)&contents, NULL, NULL)) {
		g_strstrip (contents);
		if (!contents[0]) {
			g_free (contents);
			contents = NULL;
		}
		g_free (self->pv->default_collection);
		self->pv->default_collection = contents;
	}
}
#endif

static gboolean
object_path_has_prefix (const gchar *path, const gchar *prefix)
{
	gsize len;

	g_assert (prefix);

	if (!path)
		return FALSE;

	len = strlen (prefix);
	return g_ascii_strncasecmp (path, prefix, len) == 0 &&
	       (path[len] == '\0' || path[len] == '/');
}

static void
dispose_and_unref (gpointer object)
{
	g_return_if_fail (G_IS_OBJECT (object));
	g_object_run_dispose (G_OBJECT (object));
	g_object_unref (object);
}

static void
free_client (gpointer data)
{
	ServiceClient *client = data;

	if (!client)
		return;

	/* Info about our client */
	g_free (client->caller_peer);
	g_free (client->caller_exec);

	/* The session we use for accessing as our client */
	if (client->pkcs11_session) {
#if 0
		gp11_session_close (client->pkcs11_session, NULL);
#endif
		g_object_unref (client->pkcs11_session);
	}

	/* The sessions and prompts the client has open */
	g_hash_table_destroy (client->sessions);
	g_hash_table_destroy (client->prompts);

	g_free (client);
}

typedef struct _on_get_connection_unix_process_id_args {
	GkdSecretsService *self;
	DBusMessage *message;
} on_get_connection_unix_process_id_args;

static void
free_on_get_connection_unix_process_id_args (gpointer data)
{
	on_get_connection_unix_process_id_args *args = data;
	if (args != NULL) {
		g_object_unref (args->self);
		dbus_message_unref (args->message);
		g_free (args);
	}
}

static void
on_get_connection_unix_process_id (DBusPendingCall *pending, gpointer user_data)
{
	on_get_connection_unix_process_id_args *args = user_data;
	DBusMessage *reply = NULL;
	DBusError error = DBUS_ERROR_INIT;
	dbus_uint32_t caller_pid = 0;
	GkdSecretsService *self;
	ServiceClient *client;
	const gchar *caller;

	g_return_if_fail (GKD_SECRETS_IS_SERVICE (args->self));
	self = args->self;

	/* Get the resulting process ID */
	reply = dbus_pending_call_steal_reply (pending);
	g_return_if_fail (reply);

	caller = dbus_message_get_sender (args->message);
	g_return_if_fail (caller);

	client = g_hash_table_lookup (self->clients, caller);
	if (client == NULL) {

		/* An error returned from GetConnectionUnixProcessID */
		if (dbus_set_error_from_message (&error, reply)) {
			g_message ("couldn't get the caller's unix process id: %s", error.message);
			caller_pid = 0;
			dbus_error_free (&error);

		/* A PID was returned from GetConnectionUnixProcessID */
		} else {
			if (!dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &caller_pid, DBUS_TYPE_INVALID))
				g_return_if_reached ();
		}

		/* Initialize the client object */
		client = g_new0 (ServiceClient, 1);
		client->caller_peer = g_strdup (caller);
		client->caller_pid = caller_pid;
		if (caller_pid != 0)
			client->caller_exec = egg_unix_credentials_executable (caller_pid);
		client->app.applicationData = client;
		client->sessions = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, dispose_and_unref);
		client->prompts = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, dispose_and_unref);

		g_hash_table_replace (self->clients, client->caller_peer, client);
	}

	dbus_message_unref (reply);

	/* Dispatch the original message again */
	service_dispatch_message (self, args->message);
}

static void
initialize_service_client (GkdSecretsService *self, DBusMessage *message)
{
	on_get_connection_unix_process_id_args *args;
	DBusMessage *request;
	DBusPendingCall *pending;
	const gchar *caller;

	g_assert (GKD_SECRETS_IS_SERVICE (self));
	g_assert (message);

	args = g_new0 (on_get_connection_unix_process_id_args, 1);
	args->self = g_object_ref (self);
	args->message = dbus_message_ref (message);

	caller = dbus_message_get_sender (message);
	g_return_if_fail (caller);

	/* Message org.freedesktop.DBus.GetConnectionUnixProcessID(IN String caller) */
	request = dbus_message_new_method_call ("org.freedesktop.DBus", "/org/freedesktop/DBus",
	                                        "org.freedesktop.DBus", "GetConnectionUnixProcessID");
	if (!request || !dbus_message_append_args (request, DBUS_TYPE_STRING, &caller, DBUS_TYPE_INVALID))
		g_return_if_reached ();

	/*
	 * Send of request for GetConnectionUnixProcessID, with lowish timeout.
	 * We're only talking to the session bus, so the reply should be fast.
	 * In addition we want to send off a reply to our caller, before it
	 * times out.
	 */
	if (!dbus_connection_send_with_reply (self->connection, request, &pending, 2000))
		g_return_if_reached ();
	dbus_message_unref (request);

	/* Track our new session object, on this call */
	dbus_pending_call_set_notify (pending, on_get_connection_unix_process_id, args,
	                              free_on_get_connection_unix_process_id_args);
	dbus_pending_call_unref (pending);
}

/* -----------------------------------------------------------------------------
 * DBUS
 */

static DBusMessage*
service_property_get (GkdSecretsService *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	const gchar *interface;
	const gchar *name;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface, 
	                            DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRETS_SERVICE_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED, 
		                                      "Object does not have properties on interface '%s'", 
		                                      interface);

	/* The "Collections" property */
	if (g_str_equal (name, "Collections")) {
		reply = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply, &iter);
		gkd_secrets_objects_append_collection_paths (self->objects, &iter, message);

	/* No such property */
	} else {
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Object does not have the '%s' property", name);
	}

	return reply;
}

static DBusMessage*
service_property_set (GkdSecretsService *self, DBusMessage *message)
{
	return NULL; /* TODO: Need to implement */
}

static DBusMessage*
service_property_getall (GkdSecretsService *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	DBusMessageIter array;
	DBusMessageIter dict;
	DBusMessageIter iter;
	const gchar *interface;
	const gchar *name;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRETS_SERVICE_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED, 
		                                      "Object does not have properties on interface '%s'", 
		                                      interface);

	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "{sv}", &array);

	name = "Collections";
	dbus_message_iter_open_container (&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
	dbus_message_iter_append_basic (&dict, DBUS_TYPE_STRING, &name);
	gkd_secrets_objects_append_collection_paths (self->objects, &dict, message);
	dbus_message_iter_close_container (&array, &dict);

	dbus_message_iter_close_container (&iter, &array);

	return reply;
}

static DBusMessage*
service_method_open_session (GkdSecretsService *self, DBusMessage *message)
{
	GkdSecretsSession *session;
	ServiceClient *client;
	DBusMessage *reply;
	const gchar *caller;
	const gchar *path;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID))
		return NULL;

	caller = dbus_message_get_sender (message);

	/* Now we can create a session with this information */
	session = g_object_new (GKD_SECRETS_TYPE_SESSION,
	                        "caller", caller,
	                        "service", self,
	                        NULL);

	/* Take ownership of the session */
	client = g_hash_table_lookup (self->clients, caller);
	g_return_val_if_fail (client, NULL);
	path = gkd_secrets_session_get_object_path (session);
	g_return_val_if_fail (!g_hash_table_lookup (client->sessions, path), NULL);
	g_hash_table_replace (client->sessions, (gpointer)path, session);

	/* Return the response */
	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);
	return reply;
}

static DBusMessage*
service_method_unlock (GkdSecretsService *self, DBusMessage *message)
{
	char **objpaths, **o;
	GkdSecretsUnlock *unlock;
	ServiceClient *client;
	DBusMessage *reply;
	const char *caller;
	const gchar *path;

	if (!dbus_message_get_args (message, NULL,
	                            DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &objpaths,
	                            DBUS_TYPE_INVALID))
		return NULL;

	caller = dbus_message_get_sender (message);
	unlock = gkd_secrets_unlock_new (self, caller);
	for (o = objpaths; o && *o; ++o)
		gkd_secrets_unlock_queue (unlock, *o);
	dbus_free_string_array (objpaths);

	/* So do we need to prompt? */
	if (gkd_secrets_unlock_have_queued (unlock)) {
		client = g_hash_table_lookup (self->clients, caller);
		g_return_val_if_fail (client, NULL);
		path = gkd_secrets_prompt_get_object_path (GKD_SECRETS_PROMPT (unlock));
		g_hash_table_replace (client->sessions, (gpointer)path, g_object_ref (unlock));

	/* No need to prompt */
	} else {
		path = "";
	}

	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply,
	                          DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, gkd_secrets_unlock_get_results (unlock),
	                          DBUS_TYPE_OBJECT_PATH, path,
	                          DBUS_TYPE_INVALID);

	gkd_secrets_unlock_reset_results (unlock);
	g_object_unref (unlock);

	return reply;
}

static DBusMessage*
service_message_handler (GkdSecretsService *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;

	g_return_val_if_fail (message, NULL);
	g_return_val_if_fail (GKD_SECRETS_IS_SERVICE (self), NULL);

	/* org.freedesktop.Secrets.Service.OpenSession() */
	if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "OpenSession"))
		reply = service_method_open_session (self, message);

	/* org.freedesktop.Secrets.Service.CreateCollection() */
	if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "CreateCollection"))
		g_return_val_if_reached (NULL); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Service.LockService() */
	if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "LockService"))
		g_return_val_if_reached (NULL); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Service.SearchItems() */
	if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "SearchItems"))
		return gkd_secrets_objects_handle_search_items (self->objects, message, NULL);

	/* org.freedesktop.Secrets.Service.Unlock() */
	if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "Unlock"))
		reply = service_method_unlock (self, message);

	/* org.freedesktop.Secrets.Service.CompleteAuthenticate() */
	if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "CompleteAuthenticate"))
		g_return_val_if_reached (NULL); /* TODO: Need to implement */

	/* org.freedesktop.DBus.Properties.Get() */
	if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Get"))
		return service_property_get (self, message);

	/* org.freedesktop.DBus.Properties.Set() */
	else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Set"))
		return service_property_set (self, message);

	/* org.freedesktop.DBus.Properties.GetAll() */
	else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "GetAll"))
		return service_property_getall (self, message);

	else if (dbus_message_has_interface (message, DBUS_INTERFACE_INTROSPECTABLE))
		return gkd_dbus_introspect_handle (message, "service");

	return reply;
}

static void
service_dispatch_message (GkdSecretsService *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	const gchar *caller;
	ServiceClient *client;
	const gchar *path;
	gpointer object;

	g_assert (GKD_SECRETS_IS_SERVICE (self));
	g_assert (message);

	/* The first thing we do is try to allocate a client context */
	caller = dbus_message_get_sender (message);
	if (caller == NULL) {
		reply = dbus_message_new_error (message, DBUS_ERROR_FAILED,
		                                "Could not not identify calling client application");
		dbus_connection_send (self->connection, reply, NULL);
		dbus_message_unref (reply);
		return;
	}

	client = g_hash_table_lookup (self->clients, caller);
	if (client == NULL) {
		initialize_service_client (self, message);
		return; /* This function called again, when client is initialized */
	}

	path = dbus_message_get_path (message);
	g_return_if_fail (path);

	/* Dispatched to a session, find a session in this client */
	if (object_path_has_prefix (path, SECRETS_SESSION_PREFIX)) {
		object = g_hash_table_lookup (client->sessions, path);
		if (object != NULL)
			reply = gkd_secrets_session_dispatch (object, message);

	/* Dispatched to a prompt, find a prompt in this client */
	} else if (object_path_has_prefix (path, SECRETS_PROMPT_PREFIX)) {
		object = g_hash_table_lookup (client->prompts, path);
		if (object != NULL)
			reply = gkd_secrets_prompt_dispatch (object, message);

	/* Dispatched to a collection, off it goes */
	} else if (object_path_has_prefix (path, SECRETS_COLLECTION_PREFIX)) {
		reply = gkd_secrets_objects_dispatch (self->objects, message);

	/* Addressed to the service */
	} else if (g_str_equal (path, SECRETS_SERVICE_PATH)) {
		reply = service_message_handler (self, message);
	}

	/* Should we send an error? */
	if (!reply && dbus_message_get_type (message) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		if (!dbus_message_get_no_reply (message) && !gkd_dbus_message_is_handled (message)) {
			reply = dbus_message_new_error_printf (message, DBUS_ERROR_UNKNOWN_METHOD, 
			                                       "Method \"%s\" with signature \"%s\" on interface \"%s\" doesn't exist\n",
			                                       dbus_message_get_member (message),
			                                       dbus_message_get_signature (message),
			                                       dbus_message_get_interface (message));
		}
	}

	if (reply) {
		dbus_connection_send (self->connection, reply, NULL);
		dbus_message_unref (reply);
	}
}

static DBusHandlerResult
gkd_secrets_service_filter_handler (DBusConnection *conn, DBusMessage *message, gpointer user_data)
{
	GkdSecretsService *self = user_data;
	const gchar *object_name;
	const gchar *old_owner;
	const gchar *new_owner;
	const gchar *path;
	const gchar *interface;

	g_return_val_if_fail (conn && message, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (GKD_SECRETS_IS_SERVICE (self), DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	/* org.freedesktop.DBus.NameOwnerChanged(STRING name, STRING old_owner, STRING new_owner) */
	if (dbus_message_is_signal (message, BUS_INTERFACE, "NameOwnerChanged") && 
	    dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &object_name, 
	                           DBUS_TYPE_STRING, &old_owner, DBUS_TYPE_STRING, &new_owner,
	                           DBUS_TYPE_INVALID)) {

		/*
		 * A peer is connecting or disconnecting from the bus,
		 * remove any client info, when client gone.
		 */

		g_return_val_if_fail (object_name && new_owner, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
		if (g_str_equal (new_owner, "") && object_name[0] == ':')
			g_hash_table_remove (self->clients, object_name);

		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/*
	 * If the path is a within our object tree, then we do our own dispatch.
	 */
	path = dbus_message_get_path (message);
	switch (dbus_message_get_type (message)) {

	/* Dispatch any method call on our interfaces, for our objects */
	case DBUS_MESSAGE_TYPE_METHOD_CALL:
		if (object_path_has_prefix (path, SECRETS_SERVICE_PATH)) {
			interface = dbus_message_get_interface (message);
			if (interface == NULL ||
			    g_str_has_prefix (interface, SECRETS_INTERFACE_PREFIX) ||
			    g_str_equal (interface, DBUS_INTERFACE_PROPERTIES) ||
			    g_str_equal (interface, DBUS_INTERFACE_INTROSPECTABLE)) {
				service_dispatch_message (self, message);
				return DBUS_HANDLER_RESULT_HANDLED;
			}
		}
		break;

	/* Dispatch any signal for one of our objects */
	case DBUS_MESSAGE_TYPE_SIGNAL:
		if (object_path_has_prefix (path, SECRETS_SERVICE_PATH)) {
			service_dispatch_message (self, message);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		break;

	default:
		break;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gkd_secrets_service_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (G_OBJECT_CLASS (gkd_secrets_service_parent_class)->constructor(type, n_props, props));
	DBusError error = DBUS_ERROR_INIT;
	GP11Slot *slot = NULL;
	guint i;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->connection, NULL);

	/* Find the pkcs11-slot parameter */
	for (i = 0; !slot && i < n_props; ++i) {
		if (g_str_equal (props[i].pspec->name, "pkcs11-slot"))
			slot = g_value_get_object (props[i].value);
	}

	/* Create our objects proxy */
	g_return_val_if_fail (GP11_IS_SLOT (slot), NULL);
	self->objects = g_object_new (GKD_SECRETS_TYPE_OBJECTS,
	                              "pkcs11-slot", slot, "service", self, NULL);

	/* Register for signals that let us know when clients leave the bus */
	self->match_rule = g_strdup_printf ("type='signal',member=NameOwnerChanged,"
	                                    "interface='" BUS_INTERFACE "'");
	dbus_bus_add_match (self->connection, self->match_rule, &error);
	if (dbus_error_is_set (&error)) {
		g_warning ("couldn't listen for NameOwnerChanged signal on session bus: %s", error.message);
		dbus_error_free (&error);
		g_free (self->match_rule);
		self->match_rule = NULL;
	}

	if (!dbus_connection_add_filter (self->connection, gkd_secrets_service_filter_handler, self, NULL))
		g_return_val_if_reached (NULL);

	return G_OBJECT (self);
}

static void
gkd_secrets_service_init (GkdSecretsService *self)
{
	self->clients = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, free_client);
}

static void
gkd_secrets_service_dispose (GObject *obj)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (obj);

	if (self->match_rule) {
		g_return_if_fail (self->connection);
		dbus_bus_remove_match (self->connection, self->match_rule, NULL);
		g_free (self->match_rule);
		self->match_rule = NULL;
	}

	/* Closes all the clients */
	g_hash_table_remove_all (self->clients);

	/* Hide all the objects */
	if (self->objects) {
		g_object_run_dispose (G_OBJECT (self->objects));
		g_object_unref (self->objects);
		self->objects = NULL;
	}

	if (self->connection) {
		dbus_connection_remove_filter (self->connection, gkd_secrets_service_filter_handler, self);
		dbus_connection_unref (self->connection);
		self->connection = NULL;
	}

	G_OBJECT_CLASS (gkd_secrets_service_parent_class)->dispose (obj);
}

static void
gkd_secrets_service_finalize (GObject *obj)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (obj);

	g_assert (g_hash_table_size (self->clients) == 0);
	g_hash_table_destroy (self->clients);
	self->clients = NULL;

#if 0
	g_free (self->pv->default_collection);
	self->pv->default_collection = NULL;
#endif

	G_OBJECT_CLASS (gkd_secrets_service_parent_class)->finalize (obj);
}

static void
gkd_secrets_service_set_property (GObject *obj, guint prop_id, const GValue *value,
                                  GParamSpec *pspec)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (obj);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_return_if_fail (!self->connection);
		self->connection = g_value_dup_boxed (value);
		g_return_if_fail (self->connection);
		break;
	case PROP_PKCS11_SLOT:
		g_return_if_fail (!self->objects);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secrets_service_get_property (GObject *obj, guint prop_id, GValue *value,
                                  GParamSpec *pspec)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (obj);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_boxed (value, gkd_secrets_service_get_connection (self));
		break;
	case PROP_PKCS11_SLOT:
		g_value_set_object (value, gkd_secrets_service_get_pkcs11_slot (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secrets_service_class_init (GkdSecretsServiceClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkd_secrets_service_constructor;
	gobject_class->dispose = gkd_secrets_service_dispose;
	gobject_class->finalize = gkd_secrets_service_finalize;
	gobject_class->set_property = gkd_secrets_service_set_property;
	gobject_class->get_property = gkd_secrets_service_get_property;

	g_object_class_install_property (gobject_class, PROP_CONNECTION,
		g_param_spec_boxed ("connection", "Connection", "DBus Connection",
		                    GKD_DBUS_TYPE_CONNECTION, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_PKCS11_SLOT,
	        g_param_spec_object ("pkcs11-slot", "Pkcs11 Slot", "PKCS#11 slot that we use for secrets",
	                             GP11_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

void
gkd_secrets_service_send (GkdSecretsService *self, DBusMessage *message)
{
	g_return_if_fail (GKD_SECRETS_IS_SERVICE (self));
	dbus_connection_send (self->connection, message, NULL);
}

GkdSecretsObjects*
gkd_secrets_service_get_objects (GkdSecretsService *self)
{
	g_return_val_if_fail (GKD_SECRETS_IS_SERVICE (self), NULL);
	return self->objects;
}

DBusConnection*
gkd_secrets_service_get_connection (GkdSecretsService *self)
{
	g_return_val_if_fail (GKD_SECRETS_IS_SERVICE (self), NULL);
	return self->connection;
}

GP11Slot*
gkd_secrets_service_get_pkcs11_slot (GkdSecretsService *self)
{
	g_return_val_if_fail (GKD_SECRETS_IS_SERVICE (self), NULL);
	return gkd_secrets_objects_get_pkcs11_slot (self->objects);
}

GP11Session*
gkd_secrets_service_get_pkcs11_session (GkdSecretsService *self, const gchar *caller)
{
	ServiceClient *client;
	GError *error = NULL;
	GP11Slot *slot;
	gulong flags;

	g_return_val_if_fail (GKD_SECRETS_IS_SERVICE (self), NULL);
	g_return_val_if_fail (caller, NULL);

	client = g_hash_table_lookup (self->clients, caller);
	g_return_val_if_fail (client, NULL);

	/* Open a new session if necessary */
	if (!client->pkcs11_session) {
		flags = CKF_RW_SESSION | CKF_G_APPLICATION_SESSION;
		slot = gkd_secrets_service_get_pkcs11_slot (self);
		client->pkcs11_session = gp11_slot_open_session_full (slot, flags, &client->app,
		                                                      NULL, NULL, &error);
		if (!client->pkcs11_session) {
			g_warning ("couldn't open pkcs11 session for secrets service: %s",
			           error->message);
			g_clear_error (&error);
			return NULL;
		}
	}

	return client->pkcs11_session;
}

void
gkd_secrets_service_close_session (GkdSecretsService *self, GkdSecretsSession *session)
{
	ServiceClient *client;
	const gchar *caller;
	const gchar *path;

	g_return_if_fail (GKD_SECRETS_IS_SERVICE (self));
	g_return_if_fail (GKD_SECRETS_IS_SESSION (session));

	caller = gkd_secrets_session_get_caller (session);
	client = g_hash_table_lookup (self->clients, caller);
	g_return_if_fail (client);

	path = gkd_secrets_session_get_object_path (session);
	g_hash_table_remove (client->sessions, path);
}

#if 0
GkdSecretsCollection*
gkd_secrets_service_get_default_collection (GkdSecretsService *self)
{
	GkdSecretsCollection *collection = NULL;

	g_return_val_if_fail (GKD_SECRETS_IS_SERVICE (self), NULL);

	if (!self->pv->default_collection)
		update_default (self);

	if (self->pv->default_collection != NULL)
		collection = gkd_secrets_service_get_collection (self, self->pv->default_collection);

	/*
	 * We prefer to make the 'login' keyring the default
	 * keyring when nothing else is setup.
	 */
	if (collection == NULL)
		collection = gkd_secrets_service_get_collection (self, "login");

	/*
	 * Otherwise fall back to the 'default' keyring setup
	 * if PAM integration is borked, and the user had to
	 * create a new keyring.
	 */
	if (collection == NULL)
		collection = gkd_secrets_service_get_collection (self, "default");

	return collection;
}

#endif
