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

#include "egg/egg-unix-credentials.h"

enum {
	PROP_0,
	PROP_CONNECTION,
#if 0
	/* Secrets Service Properties */
	PROP_COLLECTIONS,
	PROP_DEFAULT_COLLECTION
#endif
};


struct _GkdSecretsService {
	GObject parent;
	DBusConnection *connection;
	GList *sessions;
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
	self->sessions = g_list_prepend (self->sessions, session);

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

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gkd_secrets_service_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (G_OBJECT_CLASS (gkd_secrets_service_parent_class)->constructor(type, n_props, props));

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->connection, NULL);

	/* Now register the object */
	if (!dbus_connection_register_object_path (self->connection, SECRETS_SERVICE_PATH,
	                                           &GKD_SECRETS_SERVICE_GET_CLASS (self)->dbus_vtable, self))
		g_return_val_if_reached (NULL);

	return G_OBJECT (self);
}

static void
gkd_secrets_service_init (GkdSecretsService *self)
{
	self->sessions = NULL;
}

static void
gkd_secrets_service_dispose (GObject *obj)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (obj);
	GList *l;

	for (l = self->sessions; l; l = g_list_next (l)) {
		g_object_run_dispose (G_OBJECT (l->data));
		g_object_unref (l->data);
	}
	g_list_free (self->sessions);
	self->sessions = NULL;

	if (self->connection) {
		if (!dbus_connection_unregister_object_path (self->connection, SECRETS_SERVICE_PATH))
			g_return_if_reached ();
		dbus_connection_unref (self->connection);
		self->connection = NULL;
	}

	G_OBJECT_CLASS (gkd_secrets_service_parent_class)->dispose (obj);
}

static void
gkd_secrets_service_finalize (GObject *obj)
{
	GkdSecretsService *self = GKD_SECRETS_SERVICE (obj);

	g_assert (!self->sessions);

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

void
gkd_secrets_service_close_session (GkdSecretsService *self, GkdSecretsSession *session)
{
	GList *l;

	g_return_if_fail (GKD_SECRETS_IS_SERVICE (self));
	g_return_if_fail (GKD_SECRETS_IS_SESSION (session));

	l = g_list_find (self->sessions, session);
	g_return_if_fail (l != NULL);
	self->sessions = g_list_delete_link (self->sessions, l);

	g_object_run_dispose (G_OBJECT (session));
	g_object_unref (session);
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
