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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkd-dbus-util.h"
#include "gkd-secret-change.h"
#include "gkd-secret-create.h"
#include "gkd-secret-dispatch.h"
#include "gkd-secret-error.h"
#include "gkd-secret-introspect.h"
#include "gkd-secret-lock.h"
#include "gkd-secret-objects.h"
#include "gkd-secret-prompt.h"
#include "gkd-secret-property.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"
#include "gkd-secret-unlock.h"
#include "gkd-secret-util.h"

#include "egg/egg-error.h"
#include "egg/egg-unix-credentials.h"

#include <gck/gck.h>

#include "pkcs11/pkcs11i.h"

#include <string.h>

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_PKCS11_SLOT,
};

struct _GkdSecretService {
	GObject parent;
	DBusConnection *connection;
	GHashTable *clients;
	gchar *match_rule;
	GkdSecretObjects *objects;
	GHashTable *aliases;
	GckSession *internal_session;
	gchar *alias_directory;
};

typedef struct _ServiceClient {
	gchar *caller_peer;
	gchar *caller_exec;
	pid_t caller_pid;
	CK_G_APPLICATION app;
	GckSession *pkcs11_session;
	GHashTable *dispatch;
} ServiceClient;

/* Forward declaration */
static void service_dispatch_message (GkdSecretService *, DBusMessage *);

G_DEFINE_TYPE (GkdSecretService, gkd_secret_service, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar*
default_path (GkdSecretService *self)
{
	gchar *old_directory;
	gchar *new_directory;

#if WITH_DEBUG
	if (self->alias_directory == NULL) {
		const gchar *path = g_getenv ("GNOME_KEYRING_TEST_PATH");
		if (path && path[0]) {
			self->alias_directory = g_strdup (path);
			g_debug ("Alias directory was overridden by tests: %s", path);
		}
	}
#endif

	if (self->alias_directory == NULL) {
		new_directory = g_build_filename (g_get_user_data_dir (), "keyrings", NULL);
		old_directory = g_build_filename (g_get_home_dir (), ".gnome2", "keyrings", NULL);

		if (!g_file_test (new_directory, G_FILE_TEST_IS_DIR) &&
		    g_file_test (old_directory, G_FILE_TEST_IS_DIR)) {
			self->alias_directory = old_directory;
			old_directory = NULL;
		} else {
			self->alias_directory = new_directory;
			new_directory = NULL;
		}

		g_free (old_directory);
		g_free (new_directory);
		g_debug ("keyring alias directory: %s", self->alias_directory);
	}

	return g_build_filename (self->alias_directory, "default", NULL);
}

static void
update_default (GkdSecretService *self, gboolean force)
{
	gchar *contents = NULL;
	const gchar *identifier;
	gchar *path;

	if (!force) {
		identifier = g_hash_table_lookup (self->aliases, "default");
		if (identifier)
			return;
	}

	path = default_path (self);
	if (g_file_get_contents (path, &contents, NULL, NULL)) {
		g_strstrip (contents);
		if (!contents[0]) {
			g_free (contents);
			contents = NULL;
		}
	}
	g_free (path);

	g_hash_table_replace (self->aliases, g_strdup ("default"), contents);
}

static void
store_default (GkdSecretService *self)
{
	GError *error = NULL;
	const gchar *identifier;
	gchar *path;

	identifier = g_hash_table_lookup (self->aliases, "default");
	if (!identifier)
		return;

	path = default_path (self);
	if (!g_file_set_contents (path, identifier, -1, &error))
		g_message ("couldn't store default keyring: %s", egg_error_message (error));
	g_free (path);
}

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
		gck_session_close (client->pkcs11_session, NULL);
#endif
		g_object_unref (client->pkcs11_session);
	}

	/* The sessions and prompts the client has open */
	g_hash_table_destroy (client->dispatch);

	g_free (client);
}

typedef struct _on_get_connection_unix_process_id_args {
	GkdSecretService *self;
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
	GkdSecretService *self;
	ServiceClient *client;
	const gchar *caller;

	g_return_if_fail (GKD_SECRET_IS_SERVICE (args->self));
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
		client->dispatch = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, dispose_and_unref);

		g_hash_table_replace (self->clients, client->caller_peer, client);

		/* Update default collection each time someone connects */
		update_default (self, TRUE);
	}

	dbus_message_unref (reply);

	/* Dispatch the original message again */
	service_dispatch_message (self, args->message);
}

static void
initialize_service_client (GkdSecretService *self, DBusMessage *message)
{
	on_get_connection_unix_process_id_args *args;
	DBusMessage *request;
	DBusPendingCall *pending;
	const gchar *caller;

	g_assert (GKD_SECRET_IS_SERVICE (self));
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
service_property_get (GkdSecretService *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	const gchar *interface;
	const gchar *name;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface,
	                            DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRET_SERVICE_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	/* The "Collections" property */
	if (g_str_equal (name, "Collections")) {
		reply = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply, &iter);
		gkd_secret_objects_append_collection_paths (self->objects, &iter, message);

	/* No such property */
	} else {
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Object does not have the '%s' property", name);
	}

	return reply;
}

static DBusMessage*
service_property_set (GkdSecretService *self, DBusMessage *message)
{
	return NULL; /* TODO: Need to implement */
}

static void
service_append_all_properties (GkdSecretService *self,
                               DBusMessageIter *iter)
{
	DBusMessageIter array;
	DBusMessageIter dict;
	const gchar *name;

	dbus_message_iter_open_container (iter, DBUS_TYPE_ARRAY, "{sv}", &array);

	name = "Collections";
	dbus_message_iter_open_container (&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
	dbus_message_iter_append_basic (&dict, DBUS_TYPE_STRING, &name);
	gkd_secret_objects_append_collection_paths (self->objects, &dict, NULL);
	dbus_message_iter_close_container (&array, &dict);

	dbus_message_iter_close_container (iter, &array);
}

static DBusMessage*
service_property_getall (GkdSecretService *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	const gchar *interface;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRET_SERVICE_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	service_append_all_properties (self, &iter);
	return reply;
}

static DBusMessage*
service_method_open_session (GkdSecretService *self, DBusMessage *message)
{
	GkdSecretSession *session;
	DBusMessage *reply = NULL;
	const gchar *caller;

	if (!dbus_message_has_signature (message, "sv"))
		return NULL;

	caller = dbus_message_get_sender (message);

	/* Now we can create a session with this information */
	session = gkd_secret_session_new (self, caller);
	reply = gkd_secret_session_handle_open (session, message);

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN)
		gkd_secret_service_publish_dispatch (self, caller,
		                                     GKD_SECRET_DISPATCH (session));

	g_object_unref (session);
	return reply;
}

static DBusMessage*
service_method_create_collection (GkdSecretService *self, DBusMessage *message)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	DBusMessageIter iter, array;
	GckAttributes *attrs;
	GkdSecretCreate *create;
	DBusMessage *reply;
	const gchar *path;
	const gchar *alias;
	const char *caller;
	const gchar *coll;

	/* Parse the incoming message */
	if (!dbus_message_has_signature (message, "a{sv}s"))
		return NULL;
	if (!dbus_message_iter_init (message, &iter))
		g_return_val_if_reached (NULL);
	dbus_message_iter_recurse (&iter, &array);
	if (!gkd_secret_property_parse_all (&array, SECRET_COLLECTION_INTERFACE, &builder)) {
		gck_builder_clear (&builder);
		return dbus_message_new_error_printf (message, DBUS_ERROR_INVALID_ARGS,
		                                      "Invalid properties");
	}
	if (!dbus_message_iter_next (&iter))
		g_return_val_if_reached (NULL);
	dbus_message_iter_get_basic (&iter, &alias);

	/* Empty alias is no alias */
	if (alias) {
		if (!alias[0]) {
			alias = NULL;
		} else if (!g_str_equal (alias, "default")) {
			gck_builder_clear (&builder);
			return dbus_message_new_error (message, DBUS_ERROR_NOT_SUPPORTED,
			                               "Only the 'default' alias is supported");
		}
	}

	gck_builder_add_boolean (&builder, CKA_TOKEN, TRUE);
	attrs = gck_attributes_ref_sink (gck_builder_end (&builder));

	/* Create the prompt object, for the password */
	caller = dbus_message_get_sender (message);
	create = gkd_secret_create_new (self, caller, attrs, alias);
	gck_attributes_unref (attrs);

	path = gkd_secret_dispatch_get_object_path (GKD_SECRET_DISPATCH (create));
	gkd_secret_service_publish_dispatch (self, caller,
	                                     GKD_SECRET_DISPATCH (create));

	coll = "/";
	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply,
	                          DBUS_TYPE_OBJECT_PATH, &coll,
	                          DBUS_TYPE_OBJECT_PATH, &path,
	                          DBUS_TYPE_INVALID);

	g_object_unref (create);
	return reply;
}

static DBusMessage*
service_method_lock_service (GkdSecretService *self, DBusMessage *message)
{
	DBusError derr = DBUS_ERROR_INIT;
	GckSession *session;
	const char *caller;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID))
		return NULL;

	caller = dbus_message_get_sender (message);
	session = gkd_secret_service_get_pkcs11_session (self, caller);
	g_return_val_if_fail (session != NULL, NULL);

	if (!gkd_secret_lock_all (session, &derr))
		return gkd_secret_error_to_reply (message, &derr);

	return dbus_message_new_method_return (message);
}

static DBusMessage*
service_method_unlock (GkdSecretService *self, DBusMessage *message)
{
	GkdSecretUnlock *unlock;
	DBusMessage *reply;
	const char *caller;
	const gchar *path;
	int n_objpaths, i;
	char **objpaths;

	if (!dbus_message_get_args (message, NULL,
	                            DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &objpaths, &n_objpaths,
	                            DBUS_TYPE_INVALID))
		return NULL;

	caller = dbus_message_get_sender (message);
	unlock = gkd_secret_unlock_new (self, caller, NULL);
	for (i = 0; i < n_objpaths; ++i)
		gkd_secret_unlock_queue (unlock, objpaths[i]);
	dbus_free_string_array (objpaths);

	/* So do we need to prompt? */
	if (gkd_secret_unlock_have_queued (unlock)) {
		gkd_secret_service_publish_dispatch (self, caller,
		                                     GKD_SECRET_DISPATCH (unlock));
		path = gkd_secret_dispatch_get_object_path (GKD_SECRET_DISPATCH (unlock));

	/* No need to prompt */
	} else {
		path = "/";
	}

	reply = dbus_message_new_method_return (message);
	objpaths = gkd_secret_unlock_get_results (unlock, &n_objpaths);
	dbus_message_append_args (reply,
	                          DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &objpaths, n_objpaths,
	                          DBUS_TYPE_OBJECT_PATH, &path,
	                          DBUS_TYPE_INVALID);

	gkd_secret_unlock_reset_results (unlock);
	g_object_unref (unlock);

	return reply;
}

static DBusMessage*
service_method_lock (GkdSecretService *self, DBusMessage *message)
{
	DBusMessage *reply;
	const char *caller;
	const gchar *prompt;
	GckObject *collection;
	int n_objpaths, i;
	char **objpaths;
	GPtrArray *array;

	if (!dbus_message_get_args (message, NULL,
	                            DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &objpaths, &n_objpaths,
	                            DBUS_TYPE_INVALID))
		return NULL;

	caller = dbus_message_get_sender (message);
	array = g_ptr_array_new ();
	for (i = 0; i < n_objpaths; ++i) {
		collection = gkd_secret_objects_lookup_collection (self->objects, caller, objpaths[i]);
		if (collection != NULL) {
			if (gkd_secret_lock (collection, NULL)) {
				g_ptr_array_add (array, objpaths[i]);
				gkd_secret_objects_emit_collection_locked (self->objects,
				                                           collection);
			}
			g_object_unref (collection);
		}
	}

	prompt = "/";
	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply,
	                          DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &array->pdata, array->len,
	                          DBUS_TYPE_OBJECT_PATH, &prompt,
	                          DBUS_TYPE_INVALID);

	dbus_free_string_array (objpaths);
	return reply;
}

static DBusMessage*
service_method_change_lock (GkdSecretService *self, DBusMessage *message)
{
	GkdSecretChange *change;
	DBusMessage *reply;
	const char *caller;
	const gchar *path;
	GckObject *collection;

	caller = dbus_message_get_sender (message);
	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
		return NULL;

	/* Make sure it exists */
	collection = gkd_secret_objects_lookup_collection (self->objects, caller, path);
	if (!collection)
		return dbus_message_new_error (message, SECRET_ERROR_NO_SUCH_OBJECT,
		                               "The collection does not exist");
	g_object_unref (collection);

	change = gkd_secret_change_new (self, caller, path);
	path = gkd_secret_dispatch_get_object_path (GKD_SECRET_DISPATCH (change));
	gkd_secret_service_publish_dispatch (self, caller,
	                                     GKD_SECRET_DISPATCH (change));

	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);

	g_object_unref (change);
	return reply;
}

static DBusMessage*
service_method_read_alias (GkdSecretService *self, DBusMessage *message)
{
	DBusMessage *reply;
	const char *alias;
	gchar *path = NULL;
	const gchar *identifier;
	GckObject  *collection = NULL;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &alias, DBUS_TYPE_INVALID))
		return NULL;

	identifier = gkd_secret_service_get_alias (self, alias);
	if (identifier)
		path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX, identifier, -1);

	/* Make sure it actually exists */
	if (path)
		collection = gkd_secret_objects_lookup_collection (self->objects,
		                                                   dbus_message_get_sender (message), path);
	if (collection == NULL) {
		g_free (path);
		path = NULL;
	} else {
		g_object_unref (collection);
	}

	reply = dbus_message_new_method_return (message);
	if (path == NULL)
		path = g_strdup ("/");
	dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);
	g_free (path);

	return reply;
}

static DBusMessage*
service_method_set_alias (GkdSecretService *self, DBusMessage *message)
{
	GckObject *collection;
	gchar *identifier;
	const char *alias;
	const char *path;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &alias,
	                            DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
		return NULL;

	g_return_val_if_fail (alias, NULL);
	g_return_val_if_fail (path, NULL);

	if (!g_str_equal (alias, "default"))
		return dbus_message_new_error (message, DBUS_ERROR_NOT_SUPPORTED,
		                               "Only the 'default' alias is supported");

	/* No default collection */
	if (g_str_equal (path, "/")) {
		identifier = g_strdup ("");

	/* Find a collection with that path */
	} else {
		if (!object_path_has_prefix (path, SECRET_COLLECTION_PREFIX) ||
		    !gkd_secret_util_parse_path (path, &identifier, NULL))
			return dbus_message_new_error (message, DBUS_ERROR_INVALID_ARGS,
						       "Invalid collection object path");

		collection = gkd_secret_objects_lookup_collection (self->objects,
								   dbus_message_get_sender (message), path);
		if (collection == NULL) {
			g_free (identifier);
			return dbus_message_new_error (message, SECRET_ERROR_NO_SUCH_OBJECT,
						       "No such collection exists");
		}

		g_object_unref (collection);
	}

	gkd_secret_service_set_alias (self, alias, identifier);
	g_free (identifier);

	return dbus_message_new_method_return (message);
}

static DBusMessage*
service_method_create_with_master_password (GkdSecretService *self, DBusMessage *message)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	DBusError derr = DBUS_ERROR_INIT;
	DBusMessageIter iter, array;
	DBusMessage *reply = NULL;
	GkdSecretSecret *secret = NULL;
	GckAttributes *attrs = NULL;
	GError *error = NULL;
	gchar *path;

	/* Parse the incoming message */
	if (!dbus_message_has_signature (message, "a{sv}(oayays)"))
		return NULL;
	if (!dbus_message_iter_init (message, &iter))
		g_return_val_if_reached (NULL);
	dbus_message_iter_recurse (&iter, &array);
	if (!gkd_secret_property_parse_all (&array, SECRET_COLLECTION_INTERFACE, &builder)) {
		gck_builder_clear (&builder);
		return dbus_message_new_error (message, DBUS_ERROR_INVALID_ARGS,
		                               "Invalid properties argument");
	}
	dbus_message_iter_next (&iter);
	secret = gkd_secret_secret_parse (self, message, &iter, &derr);
	if (secret == NULL) {
		gck_builder_clear (&builder);
		return gkd_secret_error_to_reply (message, &derr);
	}

	gck_builder_add_boolean (&builder, CKA_TOKEN, TRUE);
	attrs = gck_attributes_ref_sink (gck_builder_end (&builder));
	path = gkd_secret_create_with_secret (attrs, secret, &error);
	gck_attributes_unref (attrs);
	gkd_secret_secret_free (secret);

	if (path == NULL)
		return gkd_secret_propagate_error (message, "Couldn't create collection", error);

	/* Notify the callers that a collection was created */
	gkd_secret_service_emit_collection_created (self, path);

	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);
	g_free (path);

	return reply;
}

static DBusMessage*
service_method_change_with_master_password (GkdSecretService *self, DBusMessage *message)
{
	DBusError derr = DBUS_ERROR_INIT;
	GkdSecretSecret *original, *master;
	GckObject *collection;
	DBusMessageIter iter;
	DBusMessage *reply;
	GError *error = NULL;
	const gchar *path;

	/* Parse the incoming message */
	if (!dbus_message_has_signature (message, "o(oayays)(oayays)"))
		return NULL;
	if (!dbus_message_iter_init (message, &iter))
		g_return_val_if_reached (NULL);
	dbus_message_iter_get_basic (&iter, &path);
	dbus_message_iter_next (&iter);
	original = gkd_secret_secret_parse (self, message, &iter, &derr);
	if (original == NULL)
		return gkd_secret_error_to_reply (message, &derr);
	dbus_message_iter_next (&iter);
	master = gkd_secret_secret_parse (self, message, &iter, &derr);
	if (master == NULL) {
		gkd_secret_secret_free (original);
		return gkd_secret_error_to_reply (message, &derr);
	}

	/* Make sure we have such a collection */
	collection = gkd_secret_objects_lookup_collection (self->objects,
	                                                   dbus_message_get_sender (message),
	                                                   path);

	/* No such collection */
	if (collection == NULL)
		reply = dbus_message_new_error (message, SECRET_ERROR_NO_SUCH_OBJECT,
		                                "The collection does not exist");

	/* Success */
	else if (gkd_secret_change_with_secrets (collection, NULL, original, master, &error))
		reply = dbus_message_new_method_return (message);

	/* Failure */
	else
		reply = gkd_secret_propagate_error (message, "Couldn't change collection password", error);

	gkd_secret_secret_free (original);
	gkd_secret_secret_free (master);

	if (collection)
		g_object_unref (collection);

	return reply;
}

static DBusMessage*
service_method_unlock_with_master_password (GkdSecretService *self, DBusMessage *message)
{
	DBusError derr = DBUS_ERROR_INIT;
	GkdSecretSecret *master;
	GError *error = NULL;
	GckObject *collection;
	DBusMessageIter iter;
	DBusMessage *reply;
	const gchar *path;

	/* Parse the incoming message */
	if (!dbus_message_has_signature (message, "o(oayays)"))
		return NULL;
	if (!dbus_message_iter_init (message, &iter))
		g_return_val_if_reached (NULL);
	dbus_message_iter_get_basic (&iter, &path);
	dbus_message_iter_next (&iter);
	master = gkd_secret_secret_parse (self, message, &iter, &derr);
	if (master == NULL)
		return gkd_secret_error_to_reply (message, &derr);

	/* Make sure we have such a collection */
	collection = gkd_secret_objects_lookup_collection (self->objects,
	                                                   dbus_message_get_sender (message),
	                                                   path);

	/* No such collection */
	if (collection == NULL) {
		reply = dbus_message_new_error (message, SECRET_ERROR_NO_SUCH_OBJECT,
		                                "The collection does not exist");

	/* Success */
	} else if (gkd_secret_unlock_with_secret (collection, master, &error)) {
		reply = dbus_message_new_method_return (message);
		gkd_secret_objects_emit_collection_locked (self->objects, collection);

	/* Failure */
	} else {
		reply = gkd_secret_propagate_error (message, "Couldn't unlock collection", error);
	}

	gkd_secret_secret_free (master);

	if (collection)
		g_object_unref (collection);

	return reply;
}

static void
on_each_path_append_to_array (GkdSecretObjects *self,
                              const gchar *path,
                              GckObject *object,
                              gpointer user_data)
{
	GPtrArray *array = user_data;
	g_ptr_array_add (array, g_strdup (path));
}

static DBusMessage *
service_introspect (GkdSecretService *self,
                    DBusMessage *message)
{
	GPtrArray *names;
	DBusMessage *reply;
	ServiceClient *client;
	const gchar *caller;
	const gchar *path;
	GHashTableIter iter;

	names = g_ptr_array_new_with_free_func (g_free);
	gkd_secret_objects_foreach_collection (self->objects, message,
	                                       on_each_path_append_to_array,
	                                       names);

	/* Lookup all sessions and prompts for this client */
	caller = dbus_message_get_sender (message);
	if (caller != NULL) {
		client = g_hash_table_lookup (self->clients, caller);
		if (client != NULL) {
			g_hash_table_iter_init (&iter, client->dispatch);
			while (g_hash_table_iter_next (&iter, (gpointer *)&path, NULL))
				g_ptr_array_add (names, g_strdup (path));
		}
	}

	g_ptr_array_add (names, NULL);

	reply = gkd_dbus_introspect_handle (message, gkd_secret_introspect_service,
	                                    (const gchar **)names->pdata);

	g_ptr_array_unref (names);
	return reply;
}

static DBusMessage*
service_message_handler (GkdSecretService *self, DBusMessage *message)
{
	g_return_val_if_fail (message, NULL);
	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);

	/* org.freedesktop.Secret.Service.OpenSession() */
	if (dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "OpenSession"))
		return service_method_open_session (self, message);

	/* org.freedesktop.Secret.Service.CreateCollection() */
	if (dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "CreateCollection"))
		return service_method_create_collection (self, message);

	/* org.freedesktop.Secret.Service.LockService() */
	if (dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "LockService"))
		return service_method_lock_service (self, message);

	/* org.freedesktop.Secret.Service.SearchItems() */
	if (dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "SearchItems"))
		return gkd_secret_objects_handle_search_items (self->objects, message, NULL, TRUE);

	/* org.freedesktop.Secret.Service.GetSecrets() */
	if (dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "GetSecrets"))
		return gkd_secret_objects_handle_get_secrets (self->objects, message);

	/* org.freedesktop.Secret.Service.Unlock() */
	if (dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "Unlock"))
		return service_method_unlock (self, message);

	/* org.freedesktop.Secret.Service.Lock() */
	if (dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "Lock"))
		return service_method_lock (self, message);

	/* org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.ChangeWithPrompt() */
	if (dbus_message_is_method_call (message, INTERNAL_SERVICE_INTERFACE, "ChangeWithPrompt") ||
	    dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "ChangeLock"))
		return service_method_change_lock (self, message);

	/* org.freedesktop.Secret.Service.ReadAlias() */
	if (dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "ReadAlias"))
		return service_method_read_alias (self, message);

	/* org.freedesktop.Secret.Service.SetAlias() */
	if (dbus_message_is_method_call (message, SECRET_SERVICE_INTERFACE, "SetAlias"))
		return service_method_set_alias (self, message);

	/* org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.CreateWithMasterPassword */
	if (dbus_message_is_method_call (message, INTERNAL_SERVICE_INTERFACE, "CreateWithMasterPassword"))
		return service_method_create_with_master_password (self, message);

	/* org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.ChangeWithMasterPassword() */
	if (dbus_message_is_method_call (message, INTERNAL_SERVICE_INTERFACE, "ChangeWithMasterPassword"))
		return service_method_change_with_master_password (self, message);

	/* org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.UnlockWithMasterPassword() */
	if (dbus_message_is_method_call (message, INTERNAL_SERVICE_INTERFACE, "UnlockWithMasterPassword"))
		return service_method_unlock_with_master_password (self, message);

	/* org.freedesktop.DBus.Properties.Get() */
	if (dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "Get"))
		return service_property_get (self, message);

	/* org.freedesktop.DBus.Properties.Set() */
	else if (dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "Set"))
		return service_property_set (self, message);

	/* org.freedesktop.DBus.Properties.GetAll() */
	else if (dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "GetAll"))
		return service_property_getall (self, message);

	/* org.freedesktop.DBus.Introspectable.Introspect() */
	else if (dbus_message_has_interface (message, DBUS_INTERFACE_INTROSPECTABLE))
		return service_introspect (self, message);

	return NULL;
}

static gboolean
root_dispatch_message (GkdSecretService *self,
                       DBusMessage *message)
{
	DBusMessage *reply = NULL;

	if (dbus_message_has_interface (message, DBUS_INTERFACE_INTROSPECTABLE))
		reply = gkd_dbus_introspect_handle (message, gkd_secret_introspect_root, NULL);

	if (reply != NULL) {
		dbus_connection_send (self->connection, reply, NULL);
		dbus_message_unref (reply);
		return TRUE;
	}

	return FALSE;
}

static void
service_dispatch_message (GkdSecretService *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	const gchar *caller;
	ServiceClient *client;
	const gchar *path;
	gpointer object;

	g_assert (GKD_SECRET_IS_SERVICE (self));
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

	/* Dispatched to a session or prompt */
	if (object_path_has_prefix (path, SECRET_SESSION_PREFIX) ||
	    object_path_has_prefix (path, SECRET_PROMPT_PREFIX)) {
		object = g_hash_table_lookup (client->dispatch, path);
		if (object == NULL)
			reply = gkd_secret_error_no_such_object (message);
		else
			reply = gkd_secret_dispatch_message (GKD_SECRET_DISPATCH (object), message);

	/* Dispatched to a collection, off it goes */
	} else if (object_path_has_prefix (path, SECRET_COLLECTION_PREFIX) ||
	           object_path_has_prefix (path, SECRET_ALIAS_PREFIX)) {
		reply = gkd_secret_objects_dispatch (self->objects, message);

	/* Addressed to the service */
	} else if (g_str_equal (path, SECRET_SERVICE_PATH)) {
		reply = service_message_handler (self, message);
	}

	/* Should we send an error? */
	if (!reply && dbus_message_get_type (message) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		if (!dbus_message_get_no_reply (message)) {
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
gkd_secret_service_filter_handler (DBusConnection *conn, DBusMessage *message, gpointer user_data)
{
	GkdSecretService *self = user_data;
	const gchar *object_name;
	const gchar *old_owner;
	const gchar *new_owner;
	const gchar *path;
	const gchar *interface;

	g_return_val_if_fail (conn && message, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	/* org.freedesktop.DBus.NameOwnerChanged(STRING name, STRING old_owner, STRING new_owner) */
	if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged") &&
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
		if (path != NULL && g_str_equal (path, "/")) {
			if (root_dispatch_message (self, message))
				return DBUS_HANDLER_RESULT_HANDLED;
		}

		if (object_path_has_prefix (path, SECRET_SERVICE_PATH)) {
			interface = dbus_message_get_interface (message);
			if (interface == NULL ||
			    g_str_has_prefix (interface, SECRET_INTERFACE_PREFIX) ||
			    g_str_equal (interface, DBUS_INTERFACE_PROPERTIES) ||
			    g_str_equal (interface, INTERNAL_SERVICE_INTERFACE) ||
			    g_str_equal (interface, DBUS_INTERFACE_INTROSPECTABLE)) {
				service_dispatch_message (self, message);
				return DBUS_HANDLER_RESULT_HANDLED;
			}
		}
		break;

	/* Dispatch any signal for one of our objects */
	case DBUS_MESSAGE_TYPE_SIGNAL:
		if (object_path_has_prefix (path, SECRET_SERVICE_PATH)) {
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
gkd_secret_service_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkdSecretService *self = GKD_SECRET_SERVICE (G_OBJECT_CLASS (gkd_secret_service_parent_class)->constructor(type, n_props, props));
	DBusError error = DBUS_ERROR_INIT;
	GckSlot *slot = NULL;
	guint i;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->connection, NULL);

	/* Find the pkcs11-slot parameter */
	for (i = 0; !slot && i < n_props; ++i) {
		if (g_str_equal (props[i].pspec->name, "pkcs11-slot"))
			slot = g_value_get_object (props[i].value);
	}

	/* Create our objects proxy */
	g_return_val_if_fail (GCK_IS_SLOT (slot), NULL);
	self->objects = g_object_new (GKD_SECRET_TYPE_OBJECTS,
	                              "pkcs11-slot", slot, "service", self, NULL);

	/* Register for signals that let us know when clients leave the bus */
	self->match_rule = g_strdup_printf ("type='signal',member=NameOwnerChanged,"
	                                    "interface='" DBUS_INTERFACE_DBUS "'");
	dbus_bus_add_match (self->connection, self->match_rule, &error);
	if (dbus_error_is_set (&error)) {
		g_warning ("couldn't listen for NameOwnerChanged signal on session bus: %s", error.message);
		dbus_error_free (&error);
		g_free (self->match_rule);
		self->match_rule = NULL;
	}

	if (!dbus_connection_add_filter (self->connection, gkd_secret_service_filter_handler, self, NULL))
		g_return_val_if_reached (NULL);

	return G_OBJECT (self);
}

static void
gkd_secret_service_init (GkdSecretService *self)
{
	self->clients = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, free_client);
	self->aliases = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

static void
gkd_secret_service_dispose (GObject *obj)
{
	GkdSecretService *self = GKD_SECRET_SERVICE (obj);

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
		dbus_connection_remove_filter (self->connection, gkd_secret_service_filter_handler, self);
		dbus_connection_unref (self->connection);
		self->connection = NULL;
	}

	if (self->internal_session) {
		dispose_and_unref (self->internal_session);
		self->internal_session = NULL;
	}

	G_OBJECT_CLASS (gkd_secret_service_parent_class)->dispose (obj);
}

static void
gkd_secret_service_finalize (GObject *obj)
{
	GkdSecretService *self = GKD_SECRET_SERVICE (obj);

	g_assert (g_hash_table_size (self->clients) == 0);
	g_hash_table_destroy (self->clients);
	self->clients = NULL;

	g_hash_table_destroy (self->aliases);
	self->aliases = NULL;

	G_OBJECT_CLASS (gkd_secret_service_parent_class)->finalize (obj);
}

static void
gkd_secret_service_set_property (GObject *obj, guint prop_id, const GValue *value,
                                 GParamSpec *pspec)
{
	GkdSecretService *self = GKD_SECRET_SERVICE (obj);

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
gkd_secret_service_get_property (GObject *obj, guint prop_id, GValue *value,
                                 GParamSpec *pspec)
{
	GkdSecretService *self = GKD_SECRET_SERVICE (obj);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_boxed (value, gkd_secret_service_get_connection (self));
		break;
	case PROP_PKCS11_SLOT:
		g_value_set_object (value, gkd_secret_service_get_pkcs11_slot (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_service_class_init (GkdSecretServiceClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkd_secret_service_constructor;
	gobject_class->dispose = gkd_secret_service_dispose;
	gobject_class->finalize = gkd_secret_service_finalize;
	gobject_class->set_property = gkd_secret_service_set_property;
	gobject_class->get_property = gkd_secret_service_get_property;

	g_object_class_install_property (gobject_class, PROP_CONNECTION,
		g_param_spec_boxed ("connection", "Connection", "DBus Connection",
		                    GKD_DBUS_TYPE_CONNECTION, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_PKCS11_SLOT,
	        g_param_spec_object ("pkcs11-slot", "Pkcs11 Slot", "PKCS#11 slot that we use for secrets",
	                             GCK_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

void
gkd_secret_service_send (GkdSecretService *self, DBusMessage *message)
{
	g_return_if_fail (GKD_SECRET_IS_SERVICE (self));
	dbus_connection_send (self->connection, message, NULL);
}

GkdSecretObjects*
gkd_secret_service_get_objects (GkdSecretService *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);
	return self->objects;
}

DBusConnection*
gkd_secret_service_get_connection (GkdSecretService *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);
	return self->connection;
}

GckSlot*
gkd_secret_service_get_pkcs11_slot (GkdSecretService *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);
	return gkd_secret_objects_get_pkcs11_slot (self->objects);
}

static gboolean
log_into_pkcs11_session (GckSession *session, GError **error)
{
	GckSessionInfo *sess;
	GckTokenInfo *info;
	GckSlot *slot;
	gboolean login;

	/* Perform the necessary 'user' login to secrets token. Doesn't unlock anything */
	slot = gck_session_get_slot (session);
	info = gck_slot_get_token_info (slot);
	login = info && (info->flags & CKF_LOGIN_REQUIRED);
	gck_token_info_free (info);
	g_object_unref (slot);

	if (login) {
		sess = gck_session_get_info (session);
		if (sess->state == CKS_RO_USER_FUNCTIONS ||
		    sess->state == CKS_RW_USER_FUNCTIONS)
			login = FALSE;
		gck_session_info_free (sess);
	}

	if (login && !gck_session_login (session, CKU_USER, NULL, 0, NULL, error))
		return FALSE;

	return TRUE;
}

GckSession*
gkd_secret_service_get_pkcs11_session (GkdSecretService *self, const gchar *caller)
{
	ServiceClient *client;
	GError *error = NULL;
	GckSlot *slot;

	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (caller, NULL);

	client = g_hash_table_lookup (self->clients, caller);
	g_return_val_if_fail (client, NULL);

	/* Open a new session if necessary */
	if (!client->pkcs11_session) {
		slot = gkd_secret_service_get_pkcs11_slot (self);
		client->pkcs11_session = gck_slot_open_session_full (slot, GCK_SESSION_READ_WRITE,
		                                                     CKF_G_APPLICATION_SESSION, &client->app,
		                                                     NULL, NULL, &error);
		if (!client->pkcs11_session) {
			g_warning ("couldn't open pkcs11 session for secret service: %s",
			           egg_error_message (error));
			g_clear_error (&error);
			return NULL;
		}

		if (!log_into_pkcs11_session (client->pkcs11_session, &error)) {
			g_warning ("couldn't log in to pkcs11 session for secret service: %s",
			           egg_error_message (error));
			g_clear_error (&error);
			g_object_unref (client->pkcs11_session);
			client->pkcs11_session = NULL;
			return NULL;
		}
	}

	return client->pkcs11_session;
}

GckSession*
gkd_secret_service_internal_pkcs11_session (GkdSecretService *self)
{
	GError *error = NULL;
	GckSlot *slot;

	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);

	if (self->internal_session)
		return self->internal_session;

	slot = gkd_secret_service_get_pkcs11_slot (self);
	self->internal_session = gck_slot_open_session_full (slot, GCK_SESSION_READ_WRITE,
	                                                     0, NULL, NULL, NULL, &error);
	if (!self->internal_session) {
		g_warning ("couldn't open pkcs11 session for secret service: %s",
		           egg_error_message (error));
		g_clear_error (&error);
		return NULL;
	}

	if (!log_into_pkcs11_session (self->internal_session, &error)) {
		g_warning ("couldn't log in to pkcs11 session for secret service: %s",
		           egg_error_message (error));
		g_clear_error (&error);
		g_object_unref (self->internal_session);
		self->internal_session = NULL;
		return NULL;
	}

	return self->internal_session;
}

GkdSecretSession*
gkd_secret_service_lookup_session (GkdSecretService *self, const gchar *path,
                                   const gchar *caller)
{
	ServiceClient *client;
	gpointer object;

	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (path, NULL);
	g_return_val_if_fail (caller, NULL);

	client = g_hash_table_lookup (self->clients, caller);
	g_return_val_if_fail (client, NULL);

	object = g_hash_table_lookup (client->dispatch, path);
	if (object == NULL || !GKD_SECRET_IS_SESSION (object))
		return NULL;

	return GKD_SECRET_SESSION (object);
}

void
gkd_secret_service_close_session (GkdSecretService *self, GkdSecretSession *session)
{
	ServiceClient *client;
	const gchar *caller;
	const gchar *path;

	g_return_if_fail (GKD_SECRET_IS_SERVICE (self));
	g_return_if_fail (GKD_SECRET_IS_SESSION (session));

	caller = gkd_secret_session_get_caller (session);
	client = g_hash_table_lookup (self->clients, caller);
	g_return_if_fail (client);

	path = gkd_secret_dispatch_get_object_path (GKD_SECRET_DISPATCH (session));
	g_hash_table_remove (client->dispatch, path);
}

const gchar*
gkd_secret_service_get_alias (GkdSecretService *self, const gchar *alias)
{
	const gchar *identifier;

	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (alias != NULL, NULL);

	identifier =  g_hash_table_lookup (self->aliases, alias);
	if (!identifier) {
		if (g_str_equal (alias, "default")) {
			update_default (self, TRUE);
			identifier = g_hash_table_lookup (self->aliases, alias);

			/* Default to to 'login' if no default keyring */
			if (identifier == NULL) {
				identifier = "login";
				g_hash_table_replace (self->aliases, g_strdup (alias),
				                      g_strdup (identifier));
			}

		} else if (g_str_equal (alias, "session")) {
			identifier = "session";
			g_hash_table_replace (self->aliases, g_strdup (alias),
			                      g_strdup (identifier));

		/* TODO: We should be using CKA_G_LOGIN_COLLECTION */
		} else if (g_str_equal (alias, "login")) {
			identifier = "login";
			g_hash_table_replace (self->aliases, g_strdup (alias),
			                      g_strdup (identifier));
		}
	}

	return identifier;
}

void
gkd_secret_service_set_alias (GkdSecretService *self, const gchar *alias,
                              const gchar *identifier)
{
	g_return_if_fail (GKD_SECRET_IS_SERVICE (self));
	g_return_if_fail (alias);

	g_hash_table_replace (self->aliases, g_strdup (alias), g_strdup (identifier));

	if (g_str_equal (alias, "default"))
		store_default (self);
}

void
gkd_secret_service_publish_dispatch (GkdSecretService *self, const gchar *caller,
                                     GkdSecretDispatch *object)
{
	ServiceClient *client;
	const gchar *path;

	g_return_if_fail (GKD_SECRET_IS_SERVICE (self));
	g_return_if_fail (caller);
	g_return_if_fail (GKD_SECRET_IS_DISPATCH (object));

	/* Take ownership of the session */
	client = g_hash_table_lookup (self->clients, caller);
	g_return_if_fail (client);
	path = gkd_secret_dispatch_get_object_path (object);
	g_return_if_fail (!g_hash_table_lookup (client->dispatch, path));
	g_hash_table_replace (client->dispatch, (gpointer)path, g_object_ref (object));
}

static void
emit_collections_properties_changed (GkdSecretService *self)
{
	const gchar *iface = SECRET_SERVICE_INTERFACE;
	DBusMessage *message;
	DBusMessageIter array;
	DBusMessageIter iter;

	message = dbus_message_new_signal (SECRET_SERVICE_PATH,
	                                   DBUS_INTERFACE_PROPERTIES,
	                                   "PropertiesChanged");

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &iface);
	service_append_all_properties (self, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "s", &array);
	dbus_message_iter_close_container (&iter, &array);

	if (!dbus_connection_send (self->connection, message, NULL))
		g_return_if_reached ();
	dbus_message_unref (message);
}

void
gkd_secret_service_emit_collection_created (GkdSecretService *self,
                                            const gchar *collection_path)
{
	DBusMessage *message;

	g_return_if_fail (GKD_SECRET_IS_SERVICE (self));
	g_return_if_fail (collection_path != NULL);

	message = dbus_message_new_signal (SECRET_SERVICE_PATH,
	                                   SECRET_SERVICE_INTERFACE,
	                                   "CollectionCreated");
	dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &collection_path,
	                          DBUS_TYPE_INVALID);

	if (!dbus_connection_send (self->connection, message, NULL))
		g_return_if_reached ();
	dbus_message_unref (message);

	emit_collections_properties_changed (self);
}

void
gkd_secret_service_emit_collection_deleted (GkdSecretService *self,
                                            const gchar *collection_path)
{
	DBusMessage *message;

	g_return_if_fail (GKD_SECRET_IS_SERVICE (self));
	g_return_if_fail (collection_path != NULL);

	message = dbus_message_new_signal (SECRET_SERVICE_PATH,
	                                   SECRET_SERVICE_INTERFACE,
	                                   "CollectionDeleted");
	dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &collection_path,
	                          DBUS_TYPE_INVALID);

	if (!dbus_connection_send (self->connection, message, NULL))
		g_return_if_reached ();
	dbus_message_unref (message);

	emit_collections_properties_changed (self);
}
