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
#include "gkd-secrets-service.h"
#include "gkd-secrets-session.h"
#include "gkd-secrets-types.h"

#include "egg/egg-unix-credentials.h"

#include "gp11/gp11.h"

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
	GHashTable *sessions;
	gchar *match_rule;
	GP11Slot *pkcs11_slot;
#if 0
	gchar *default_collection;
#endif
};

#if 0
#define LOC_DEFAULT_FILE    (gkd_location_from_string ("LOCAL:/keyrings/default"))
#endif

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

static void
dispose_session (GkdSecretsSession *session)
{
	g_object_run_dispose (G_OBJECT (session));
	g_object_unref (session);
}

static void
take_session (GkdSecretsService *self, GkdSecretsSession *session)
{
	GPtrArray *sessions;
	const gchar *caller;

	g_assert (GKD_SECRETS_SERVICE (self));
	g_assert (GKD_SECRETS_SESSION (session));

	caller = gkd_secrets_session_get_caller (session);
	sessions = g_hash_table_lookup (self->sessions, caller);
	if (!sessions) {
		sessions = g_ptr_array_new ();
		g_hash_table_replace (self->sessions, g_strdup (caller), sessions);
	}

	g_ptr_array_add (sessions, session);
}

static void
remove_session (GkdSecretsService *self, GkdSecretsSession *session)
{
	GPtrArray *sessions;
	const gchar *caller;

	g_assert (GKD_SECRETS_SERVICE (self));
	g_assert (GKD_SECRETS_SESSION (session));

	caller = gkd_secrets_session_get_caller (session);
	sessions = g_hash_table_lookup (self->sessions, caller);
	g_return_if_fail (sessions);

	g_ptr_array_remove_fast (sessions, session);
	if (sessions->len == 0)
		g_hash_table_remove (self->sessions, caller);

	dispose_session (session);
}

static void
free_sessions (gpointer data)
{
	GPtrArray *sessions = data;
	guint i;

	for (i = 0; i < sessions->len; ++i)
		dispose_session (g_ptr_array_index (sessions, i));
	g_ptr_array_free (sessions, TRUE);
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
	gchar *caller_exec = NULL;
	dbus_uint32_t caller_pid = 0;
	GkdSecretsSession *session;
	GkdSecretsService *self;
	const gchar *caller;
	const gchar *path;

	g_return_if_fail (GKD_SECRETS_IS_SERVICE (args->self));
	self = args->self;

	caller = dbus_message_get_sender (args->message);
	g_return_if_fail (caller);

	/* Get the resulting process ID */
	reply = dbus_pending_call_steal_reply (pending);
	g_return_if_fail (reply);

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

	dbus_message_unref (reply);

	/* Dig out the process executable if possible */
	if (caller_pid != 0)
		caller_exec = egg_unix_credentials_executable (caller_pid);

	/* Now we can create a session with this information */
	session = g_object_new (GKD_SECRETS_TYPE_SESSION,
	                        "caller-executable", caller_exec,
	                        "caller", caller,
	                        "service", self,
	                        NULL);
	g_free (caller_exec);

	/* Take ownership of the session */
	take_session (self, session);

	path = gkd_secrets_session_get_object_path (session);
	reply = dbus_message_new_method_return (args->message);
	dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);
	dbus_connection_send (args->self->connection, reply, NULL);
	dbus_message_unref (reply);
}

/* -----------------------------------------------------------------------------
 * DBUS
 */

static DBusHandlerResult
gkd_secrets_service_open_session (GkdSecretsService *self, DBusConnection *conn, DBusMessage *message)
{
	on_get_connection_unix_process_id_args *args;
	DBusMessage *request, *reply;
	DBusPendingCall *pending;
	const gchar *caller;

	g_assert (GKD_SECRETS_IS_SERVICE (self));
	g_assert (conn && message);

	/* Who is the caller of this message? */
	caller = dbus_message_get_sender (message);
	if (caller == NULL) {
		reply = dbus_message_new_error (message, DBUS_ERROR_FAILED,
		                                "Could not not identify calling client application");
		dbus_connection_send (conn, reply, NULL);
		dbus_message_unref (reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Message org.freedesktop.DBus.GetConnectionUnixProcessID(IN String caller) */
	request = dbus_message_new_method_call ("org.freedesktop.DBus", "/org/freedesktop/DBus",
	                                        "org.freedesktop.DBus", "GetConnectionUnixProcessID");
	if (!request || !dbus_message_append_args (request, DBUS_TYPE_STRING, &caller, DBUS_TYPE_INVALID))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	/*
	 * Send of request for GetConnectionUnixProcessID, with lowish timeout.
	 * We're only talking to the session bus, so the reply should be fast.
	 * In addition we want to send off a reply to our caller, before it
	 * times out.
	 */
	if (!dbus_connection_send_with_reply (conn, request, &pending, 2000))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	dbus_message_unref (request);

	args = g_new0 (on_get_connection_unix_process_id_args, 1);
	args->self = g_object_ref (self);
	args->message = dbus_message_ref (message);

	/* Track our new session object, on this call */
	dbus_pending_call_set_notify (pending, on_get_connection_unix_process_id, args,
	                              free_on_get_connection_unix_process_id_args);
	dbus_pending_call_unref (pending);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
gkd_sercets_service_property_handler (DBusConnection *conn, DBusMessage *message, gpointer user_data)
{
	g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */
#if 0
	/* org.freedesktop.DBus.Properties.Get */
	if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Get") &&
	    dbus_message_has_signature (message, "ss")) {
		xxx;

	/* org.freedesktop.DBus.Properties.Set */
	} else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Set") &&
	           dbus_message_has_signature (message, "ssv")) {
		xxx;

	/* org.freedesktop.DBus.Properties.GetAll */
	} else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "GetAll") &&
	           dbus_message_has_signature (message, "s")) {
		xxx;
	}
#endif
}

static DBusHandlerResult
gkd_secrets_service_message_handler (DBusConnection *conn, DBusMessage *message, gpointer user_data)
{
	GkdSecretsService *self = user_data;

	g_return_val_if_fail (conn && message, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (GKD_SECRETS_IS_SERVICE (self), DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	/* Check if it's properties, and hand off to property handler. */
	if (dbus_message_has_interface (message, PROPERTIES_INTERFACE))
		return gkd_sercets_service_property_handler (conn, message, self);

	/* org.freedesktop.Secrets.Service.OpenSession() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "OpenSession"))
		return gkd_secrets_service_open_session (self, conn, message);

	/* org.freedesktop.Secrets.Service.CreateCollection() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "CreateCollection"))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Service.LockService() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "CreateCollection"))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Service.SearchItems() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "SearchItems"))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Service.RetrieveSecrets() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "RetrieveSecrets"))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
gkd_secrets_service_filter_handler (DBusConnection *conn, DBusMessage *message, gpointer user_data)
{
	GkdSecretsService *self = user_data;
	const gchar *object_name;
	const gchar *old_owner;
	const gchar *new_owner;

	g_return_val_if_fail (conn && message, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (GKD_SECRETS_IS_SERVICE (self), DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	/* org.freedesktop.DBus.NameOwnerChanged(STRING name, STRING old_owner, STRING new_owner) */
	if (!dbus_message_is_signal (message, BUS_INTERFACE, "NameOwnerChanged") || 
	    !dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &object_name, 
	                            DBUS_TYPE_STRING, &old_owner, DBUS_TYPE_STRING, &new_owner,
	                            DBUS_TYPE_INVALID))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	g_return_val_if_fail (object_name && new_owner, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	/* See if it's something that owns our sessions, close if so */
	if (g_str_equal (new_owner, "") && object_name[0] == ':')
		g_hash_table_remove (self->sessions, object_name);

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

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->connection, NULL);
	g_return_val_if_fail (self->pkcs11_slot, NULL);

	/* Now register the object */
	if (!dbus_connection_register_object_path (self->connection, SECRETS_SERVICE_PATH,
	                                           &GKD_SECRETS_SERVICE_GET_CLASS (self)->dbus_vtable, self))
		g_return_val_if_reached (NULL);

	/* Register for signals that let us know when clients leave the bus */
	self->match_rule = g_strdup_printf ("type='signal',member=NameOwnerChanged,"
	                                    "interface='" BUS_INTERFACE "'");
	dbus_bus_add_match (self->connection, self->match_rule, &error);
	if (dbus_error_is_set (&error)) {
		g_warning ("couldn't listen for NameOwnerChanged signal on session bus: %s", error.message);
		dbus_error_free (&error);
		g_free (self->match_rule);
		self->match_rule = NULL;
	} else {
		dbus_connection_add_filter (self->connection, gkd_secrets_service_filter_handler, self, NULL);
	}

	return G_OBJECT (self);
}

static void
gkd_secrets_service_init (GkdSecretsService *self)
{
	self->sessions = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, free_sessions);
}

static void
gkd_secrets_service_dispose (GObject *obj)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (obj);

	if (self->match_rule) {
		g_return_if_fail (self->connection);
		dbus_connection_remove_filter (self->connection, gkd_secrets_service_filter_handler, self);
		dbus_bus_remove_match (self->connection, self->match_rule, NULL);
		g_free (self->match_rule);
		self->match_rule = NULL;
	}

	/* Closes all the sessions */
	g_hash_table_remove_all (self->sessions);

	if (self->connection) {
		if (!dbus_connection_unregister_object_path (self->connection, SECRETS_SERVICE_PATH))
			g_return_if_reached ();
		dbus_connection_unref (self->connection);
		self->connection = NULL;
	}

	if (self->pkcs11_slot) {
		g_object_unref (self->pkcs11_slot);
		self->pkcs11_slot = NULL;
	}

	G_OBJECT_CLASS (gkd_secrets_service_parent_class)->dispose (obj);
}

static void
gkd_secrets_service_finalize (GObject *obj)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (obj);

	g_assert (g_hash_table_size (self->sessions) == 0);
	g_hash_table_destroy (self->sessions);
	self->sessions = NULL;

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
		g_return_if_fail (!self->pkcs11_slot);
		self->pkcs11_slot = g_value_dup_object (value);
		g_return_if_fail (self->pkcs11_slot);
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

	klass->dbus_vtable.message_function = gkd_secrets_service_message_handler;

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
	return self->pkcs11_slot;
}

void
gkd_secrets_service_close_session (GkdSecretsService *self, GkdSecretsSession *session)
{
	g_return_if_fail (GKD_SECRETS_IS_SERVICE (self));
	g_return_if_fail (GKD_SECRETS_IS_SESSION (session));

	remove_session (self, session);
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
