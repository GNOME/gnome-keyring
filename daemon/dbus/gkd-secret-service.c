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

#include "gkd-secret-change.h"
#include "gkd-secret-create.h"
#include "gkd-secret-dispatch.h"
#include "gkd-secret-error.h"
#include "gkd-secret-lock.h"
#include "gkd-secret-objects.h"
#include "gkd-secret-portal.h"
#include "gkd-secret-prompt.h"
#include "gkd-secret-property.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"
#include "gkd-secret-unlock.h"
#include "gkd-secret-util.h"

#include "gkd-internal-generated.h"
#include "gkd-secrets-generated.h"

#include "egg/egg-error.h"
#include "egg/egg-unix-credentials.h"

#include <gck/gck.h>
#include <gcrypt.h>

#include "pkcs11/pkcs11i.h"

#include <string.h>

/* -----------------------------------------------------------------------------
 * SKELETON
 */
typedef struct {
	GkdExportedServiceSkeleton parent;
	GkdSecretService *service;
} GkdSecretServiceSkeleton;
typedef struct {
	GkdExportedServiceSkeletonClass parent_class;
} GkdSecretServiceSkeletonClass;

GType gkd_secret_service_skeleton_get_type (void);
G_DEFINE_TYPE (GkdSecretServiceSkeleton, gkd_secret_service_skeleton, GKD_TYPE_EXPORTED_SERVICE_SKELETON)

enum {
	PROP_COLLECTIONS = 1
};

static void
gkd_secret_service_skeleton_get_property (GObject *object,
					  guint prop_id,
					  GValue *value,
					  GParamSpec *pspec)
{
	GkdSecretServiceSkeleton *skeleton = (GkdSecretServiceSkeleton *) object;

	switch (prop_id) {
	case PROP_COLLECTIONS:
		g_value_take_boxed (value, gkd_secret_service_get_collections (skeleton->service));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_service_skeleton_set_property (GObject *object,
					  guint prop_id,
					  const GValue *value,
					  GParamSpec *pspec)
{
	G_OBJECT_CLASS (gkd_secret_service_skeleton_parent_class)->set_property (object, prop_id, value, pspec);
}

static void
gkd_secret_service_skeleton_class_init (GkdSecretServiceSkeletonClass *klass)
{
	GObjectClass *oclass = G_OBJECT_CLASS (klass);
	oclass->get_property = gkd_secret_service_skeleton_get_property;
	oclass->set_property = gkd_secret_service_skeleton_set_property;
	gkd_exported_service_override_properties (oclass, PROP_COLLECTIONS);
}

static void
gkd_secret_service_skeleton_init (GkdSecretServiceSkeleton *self)
{
}

static GkdExportedService *
gkd_secret_service_skeleton_new (GkdSecretService *service)
{
	GkdExportedService *skeleton = g_object_new (gkd_secret_service_skeleton_get_type (), NULL);
	((GkdSecretServiceSkeleton *) skeleton)->service = service;
	return skeleton;
}

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_PKCS11_SLOT,
};

struct _GkdSecretService {
	GObject parent;

	GDBusConnection *connection;
	GkdExportedService *skeleton;
	GkdExportedInternal *internal_skeleton;
	GkdSecretPortal *portal;
	guint name_owner_id;
	guint filter_id;

	GHashTable *clients;
	GkdSecretObjects *objects;
	GHashTable *aliases;
	GckSession *internal_session;
	gchar *default_path;
};

typedef struct _ServiceClient {
	gchar *caller_peer;
	CK_G_APPLICATION app;
	GckSession *pkcs11_session;
	GHashTable *dispatch;
} ServiceClient;

G_DEFINE_TYPE (GkdSecretService, gkd_secret_service, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar*
get_default_path (void)
{
	gchar *old_directory;
	gchar *new_directory;
	g_autofree gchar *alias_directory = NULL;

#if WITH_DEBUG
	const gchar *path = g_getenv ("GNOME_KEYRING_TEST_PATH");
	if (path && path[0]) {
		alias_directory = g_strdup (path);
		g_debug ("Alias directory was overridden by tests: %s", path);
	}
#endif

	if (alias_directory == NULL) {
		new_directory = g_build_filename (g_get_user_data_dir (), "keyrings", NULL);
		old_directory = g_build_filename (g_get_home_dir (), ".gnome2", "keyrings", NULL);

		if (!g_file_test (new_directory, G_FILE_TEST_IS_DIR) &&
		    g_file_test (old_directory, G_FILE_TEST_IS_DIR)) {
			alias_directory = old_directory;
			old_directory = NULL;
		} else {
			alias_directory = new_directory;
			new_directory = NULL;
		}

		g_free (old_directory);
		g_free (new_directory);
		g_debug ("keyring alias directory: %s", alias_directory);
	}

	return g_build_filename (alias_directory, "default", NULL);
}

static void
update_default (GkdSecretService *self)
{
	gchar *contents = NULL;

	if (g_file_get_contents (self->default_path, &contents, NULL, NULL)) {
		g_strstrip (contents);
		if (!contents[0]) {
			g_free (contents);
			contents = NULL;
		}
	}

	/* Default to to 'login' if no default keyring */
	if (contents == NULL)
		contents = g_strdup ("login");
	g_hash_table_replace (self->aliases, g_strdup ("default"), contents);
}

static void
store_default (GkdSecretService *self)
{
	GError *error = NULL;
	const gchar *identifier;

	identifier = g_hash_table_lookup (self->aliases, "default");
	if (!identifier)
		return;

	if (!g_file_set_contents (self->default_path, identifier, -1, &error))
		g_message ("couldn't store default keyring: %s", egg_error_message (error));
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

static void
initialize_service_client (GkdSecretService *self,
			   const gchar *caller)
{
	ServiceClient *client;

	g_assert (GKD_SECRET_IS_SERVICE (self));
	g_assert (caller);

	/* Initialize the client object */
	client = g_new0 (ServiceClient, 1);
	client->caller_peer = g_strdup (caller);
	client->app.applicationData = client;
	client->dispatch = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, dispose_and_unref);

	g_hash_table_replace (self->clients, client->caller_peer, client);

	/* Update default collection each time someone connects */
	update_default (self);
}

static void
gkd_secret_service_ensure_client (GkdSecretService *self,
				  const gchar *caller)
{
	ServiceClient *client;

	client = g_hash_table_lookup (self->clients, caller);
	if (client == NULL) {
		initialize_service_client (self, caller);
	}
}

typedef struct {
	GkdSecretService *service;
	GDBusMessage *message;
} MessageFilterData;

static gboolean
ensure_client_for_sender (gpointer user_data)
{
	MessageFilterData *data = user_data;
	const gchar *sender;

	/* Ensure clients for our incoming connections */
	sender = g_dbus_message_get_sender (data->message);
	gkd_secret_service_ensure_client (data->service, sender);

	g_clear_object (&data->service);
	g_clear_object (&data->message);
	g_slice_free (MessageFilterData, data);

	return FALSE;
}

static GDBusMessage *
rewrite_default_alias (GkdSecretService *self,
                       GDBusMessage *message)
{
	const char *path = g_dbus_message_get_path (message);
	const char *replace;
	char *collection = NULL, *item = NULL;
	char *collection_path, *item_path;
	GDBusMessage *rewritten;
	GError *error = NULL;

	if (path == NULL)
		return message;

	if (!g_str_has_prefix (path, SECRET_ALIAS_PREFIX))
		return message;

	if (!gkd_secret_util_parse_path (path, &collection, &item))
		return message;

	replace = gkd_secret_service_get_alias (self, collection);
	if (!replace) {
		g_free (item);
		g_free (collection);
		return message;
	}

	rewritten = g_dbus_message_copy (message, &error);
	if (error != NULL) {
		g_error_free (error);
		return message;
	}

	collection_path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX,
						      replace, -1);

	if (item != NULL) {
		item_path = gkd_secret_util_build_path (collection_path,
							item, -1);
		g_dbus_message_set_path (rewritten, item_path);
		g_free (item_path);
	} else {
		g_dbus_message_set_path (rewritten, collection_path);
	}

	g_free (collection_path);
	g_free (item);
	g_free (collection);
	g_object_unref (message);

	return rewritten;
}

static GDBusMessage *
service_message_filter (GDBusConnection *connection,
			GDBusMessage *message,
			gboolean incoming,
			gpointer user_data)
{
	GkdSecretService *self = user_data;
	MessageFilterData *data;
	GDBusMessage *filtered;

	if (!incoming)
		return message;

	filtered = rewrite_default_alias (self, message);

	data = g_slice_new0 (MessageFilterData);
	data->service = g_object_ref (self);
	data->message = g_object_ref (filtered);

	/* We use G_PRIORITY_HIGH to make sure this timeout is
	 * scheduled before the actual method call.
	 */
	g_idle_add_full (G_PRIORITY_HIGH, ensure_client_for_sender,
			 data, NULL);

	return filtered;
}

/* -----------------------------------------------------------------------------
 * DBUS
 */

static gboolean
service_method_open_session (GkdExportedService *skeleton,
			     GDBusMethodInvocation *invocation,
			     gchar *algorithm,
			     GVariant *input,
			     GkdSecretService *self)
{
	GkdSecretSession *session;
	GVariant *output = NULL;
	gchar *result = NULL;
	GError *error = NULL;
	const gchar *caller;
	GVariant *input_payload;

	caller = g_dbus_method_invocation_get_sender (invocation);

	/* Now we can create a session with this information */
	session = gkd_secret_session_new (self, caller);
	input_payload = g_variant_get_variant (input);
	gkd_secret_session_handle_open (session, algorithm, input_payload,
					&output, &result,
					&error);
	g_variant_unref (input_payload);

	if (error != NULL) {
		g_dbus_method_invocation_take_error (invocation, error);
	} else {
		gkd_secret_service_publish_dispatch (self, caller,
						     GKD_SECRET_DISPATCH (session));
		gkd_exported_service_complete_open_session (skeleton, invocation, output, result);
		g_free (result);
	}

	g_object_unref (session);
	return TRUE;
}

static gboolean
service_method_search_items (GkdExportedService *skeleton,
			     GDBusMethodInvocation *invocation,
			     GVariant *attributes,
			     GkdSecretService *self)
{
	return gkd_secret_objects_handle_search_items (self->objects, invocation,
						       attributes, NULL, TRUE);
}

static gboolean
service_method_get_secrets (GkdExportedService *skeleton,
			    GDBusMethodInvocation *invocation,
			    gchar **items,
			    gchar *session,
			    GkdSecretService *self)
{
	return gkd_secret_objects_handle_get_secrets (self->objects, invocation,
						      (const gchar **) items, session);
}

static gboolean
service_method_create_collection (GkdExportedService *skeleton,
				  GDBusMethodInvocation *invocation,
				  GVariant *properties,
				  gchar *alias,
				  GkdSecretService *self)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckAttributes *attrs;
	GkdSecretCreate *create;
	const gchar *path;
	const char *caller;

	if (!gkd_secret_property_parse_all (properties, SECRET_COLLECTION_INTERFACE, &builder)) {
		gck_builder_clear (&builder);
		g_dbus_method_invocation_return_error_literal (invocation, G_DBUS_ERROR,
							       G_DBUS_ERROR_INVALID_ARGS,
							       "Invalid properties");
		return TRUE;
	}

	/* Empty alias is no alias */
	if (alias) {
		if (!alias[0]) {
			alias = NULL;
		} else if (!g_str_equal (alias, "default")) {
			gck_builder_clear (&builder);
			g_dbus_method_invocation_return_error_literal (invocation, G_DBUS_ERROR,
								       G_DBUS_ERROR_NOT_SUPPORTED,
								       "Only the 'default' alias is supported");
			return TRUE;
		}
	}

	gck_builder_add_boolean (&builder, CKA_TOKEN, TRUE);
	attrs = gck_attributes_ref_sink (gck_builder_end (&builder));

	/* Create the prompt object, for the password */
	caller = g_dbus_method_invocation_get_sender (invocation);
	create = gkd_secret_create_new (self, caller, attrs, alias);
	gck_attributes_unref (attrs);

	path = gkd_secret_dispatch_get_object_path (GKD_SECRET_DISPATCH (create));
	gkd_secret_service_publish_dispatch (self, caller,
					     GKD_SECRET_DISPATCH (create));

	gkd_exported_service_complete_create_collection (skeleton, invocation,
							 "/", path);
	return TRUE;
}

static gboolean
service_method_lock_service (GkdExportedService *skeleton,
			     GDBusMethodInvocation *invocation,
			     GkdSecretService *self)
{
	GError *error = NULL;
	GckSession *session;
	const char *caller;

	caller = g_dbus_method_invocation_get_sender (invocation);
	session = gkd_secret_service_get_pkcs11_session (self, caller);
	g_return_val_if_fail (session != NULL, FALSE);

	if (!gkd_secret_lock_all (session, &error))
		g_dbus_method_invocation_take_error (invocation, error);
	else
		gkd_exported_service_complete_lock_service (skeleton, invocation);

	return TRUE;
}

static gboolean
service_method_unlock (GkdExportedService *skeleton,
		       GDBusMethodInvocation *invocation,
		       gchar **objpaths,
		       GkdSecretService *self)
{
	GkdSecretUnlock *unlock;
	const char *caller;
	const gchar *path;
	int i, n_unlocked;
	gchar **unlocked;

	caller = g_dbus_method_invocation_get_sender (invocation);
	unlock = gkd_secret_unlock_new (self, caller, NULL);
	for (i = 0; objpaths[i] != NULL; ++i)
		gkd_secret_unlock_queue (unlock, objpaths[i]);

	/* So do we need to prompt? */
	if (gkd_secret_unlock_have_queued (unlock)) {
		gkd_secret_service_publish_dispatch (self, caller,
						     GKD_SECRET_DISPATCH (unlock));
		path = gkd_secret_dispatch_get_object_path (GKD_SECRET_DISPATCH (unlock));

	/* No need to prompt */
	} else {
		path = "/";
	}

	unlocked = gkd_secret_unlock_get_results (unlock, &n_unlocked);
	gkd_exported_service_complete_unlock (skeleton, invocation,
					      (const gchar **) unlocked, path);

	gkd_secret_unlock_reset_results (unlock);
	g_object_unref (unlock);

	return TRUE;
}

static gboolean
service_method_lock (GkdExportedService *skeleton,
		     GDBusMethodInvocation *invocation,
		     gchar **objpaths,
		     GkdSecretService *self)
{
	const char *caller;
	GckObject *collection;
	int i;
	char **locked;
	GPtrArray *array;

	caller = g_dbus_method_invocation_get_sender (invocation);
	array = g_ptr_array_new ();
	for (i = 0; objpaths[i] != NULL; ++i) {
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

	g_ptr_array_add (array, NULL);

	locked = (gchar **) g_ptr_array_free (array, FALSE);
	gkd_exported_service_complete_lock (skeleton, invocation,
					    (const gchar **) locked, "/");
	g_free (locked);

	return TRUE;
}

static gboolean
method_change_lock_internal (GkdSecretService *self,
			     GDBusMethodInvocation *invocation,
			     const gchar *collection_path)
{
	GkdSecretChange *change;
	const char *caller;
	const gchar *path;
	GckObject *collection;

	caller = g_dbus_method_invocation_get_sender (invocation);

	/* Make sure it exists */
	collection = gkd_secret_objects_lookup_collection (self->objects, caller, collection_path);
	if (!collection) {
		g_dbus_method_invocation_return_error_literal (invocation, GKD_SECRET_ERROR,
							       GKD_SECRET_ERROR_NO_SUCH_OBJECT,
							       "The collection does not exist");
		return TRUE;
	}

	g_object_unref (collection);

	change = gkd_secret_change_new (self, caller, collection_path);
	path = gkd_secret_dispatch_get_object_path (GKD_SECRET_DISPATCH (change));
	gkd_secret_service_publish_dispatch (self, caller,
					     GKD_SECRET_DISPATCH (change));

	g_dbus_method_invocation_return_value (invocation, g_variant_new ("(o)", path));
	g_object_unref (change);

	return TRUE;
}

static gboolean
service_method_change_lock (GkdExportedService *skeleton,
			    GDBusMethodInvocation *invocation,
			    gchar *collection_path,
			    GkdSecretService *self)
{
	return method_change_lock_internal (self, invocation, collection_path);
}

static gboolean
service_method_change_with_prompt (GkdExportedInternal *skeleton,
				   GDBusMethodInvocation *invocation,
				   gchar *collection_path,
				   GkdSecretService *self)
{
	return method_change_lock_internal (self, invocation, collection_path);
}

static gboolean
service_method_read_alias (GkdExportedService *skeleton,
			   GDBusMethodInvocation *invocation,
			   gchar *alias,
			   GkdSecretService *self)
{
	gchar *path = NULL;
	const gchar *identifier;
	GckObject  *collection = NULL;

	identifier = gkd_secret_service_get_alias (self, alias);
	if (identifier)
		path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX, identifier, -1);

	/* Make sure it actually exists */
	if (path)
		collection = gkd_secret_objects_lookup_collection (self->objects,
								   g_dbus_method_invocation_get_sender (invocation),
								   path);
	if (collection == NULL) {
		g_free (path);
		path = NULL;
	} else {
		g_object_unref (collection);
	}

	if (path == NULL)
		path = g_strdup ("/");

	gkd_exported_service_complete_read_alias (skeleton, invocation, path);
	g_free (path);

	return TRUE;
}

static gboolean
service_method_set_alias (GkdExportedService *skeleton,
			  GDBusMethodInvocation *invocation,
			  gchar *alias,
			  gchar *path,
			  GkdSecretService *self)
{
	GckObject *collection;
	gchar *identifier;

	if (!g_str_equal (alias, "default")) {
		g_dbus_method_invocation_return_error_literal (invocation, G_DBUS_ERROR,
							       G_DBUS_ERROR_NOT_SUPPORTED,
							       "Only the 'default' alias is supported");
		return TRUE;
	}

	/* No default collection */
	if (g_str_equal (path, "/")) {
		identifier = g_strdup ("");

	/* Find a collection with that path */
	} else {
		if (!object_path_has_prefix (path, SECRET_COLLECTION_PREFIX) ||
		    !gkd_secret_util_parse_path (path, &identifier, NULL)) {
			g_dbus_method_invocation_return_error_literal (invocation, G_DBUS_ERROR,
								       G_DBUS_ERROR_INVALID_ARGS,
								       "Invalid collection object path");
			return TRUE;
		}

		collection = gkd_secret_objects_lookup_collection (self->objects,
								   g_dbus_method_invocation_get_sender (invocation),
								   path);
		if (collection == NULL) {
			g_free (identifier);
			g_dbus_method_invocation_return_error_literal (invocation, GKD_SECRET_ERROR,
								       GKD_SECRET_ERROR_NO_SUCH_OBJECT,
								       "The collection does not exist");
			return TRUE;
		}

		g_object_unref (collection);
	}

	gkd_secret_service_set_alias (self, alias, identifier);
	g_free (identifier);

	gkd_exported_service_complete_set_alias (skeleton, invocation);

	return TRUE;
}

static gboolean
service_method_create_with_master_password (GkdExportedInternal *skeleton,
					    GDBusMethodInvocation *invocation,
					    GVariant *attributes,
					    GVariant *master,
					    GkdSecretService *self)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GkdSecretSecret *secret = NULL;
	GckAttributes *attrs = NULL;
	GError *error = NULL;
	gchar *path;
	const gchar *caller;

	if (!gkd_secret_property_parse_all (attributes, SECRET_COLLECTION_INTERFACE, &builder)) {
		gck_builder_clear (&builder);
		g_dbus_method_invocation_return_error_literal (invocation, G_DBUS_ERROR,
							       G_DBUS_ERROR_INVALID_ARGS,
							       "Invalid properties argument");
		return TRUE;
	}

	caller = g_dbus_method_invocation_get_sender (invocation);
	secret = gkd_secret_secret_parse (self,
					  caller,
					  master, &error);
	if (secret == NULL) {
		gck_builder_clear (&builder);
		g_dbus_method_invocation_take_error (invocation, error);
		return TRUE;
	}

	gck_builder_add_boolean (&builder, CKA_TOKEN, TRUE);
	attrs = gck_attributes_ref_sink (gck_builder_end (&builder));
	path = gkd_secret_create_with_secret (attrs, secret, &error);
	gck_attributes_unref (attrs);
	gkd_secret_secret_free (secret);

	if (path == NULL) {
		gkd_secret_propagate_error (invocation, "Couldn't create collection", error);
		return TRUE;
	}

	/* Notify the callers that a collection was created */
        g_message ("emit collection_Created");
	gkd_secret_service_emit_collection_created (self, path);

	gkd_exported_internal_complete_create_with_master_password
		(skeleton, invocation, path);
	g_free (path);

	return TRUE;
}

static gboolean
service_method_change_with_master_password (GkdExportedInternal *skeleton,
					    GDBusMethodInvocation *invocation,
					    gchar *path,
					    GVariant *original_variant,
					    GVariant *master_variant,
					    GkdSecretService *self)
{
	GkdSecretSecret *original, *master;
	GckObject *collection;
	GError *error = NULL;
	const gchar *sender;

	sender = g_dbus_method_invocation_get_sender (invocation);

	/* Parse the incoming message */
	original = gkd_secret_secret_parse (self, sender,
					    original_variant, &error);
	if (original == NULL) {
		g_dbus_method_invocation_take_error (invocation, error);
		return TRUE;
	}

	master = gkd_secret_secret_parse (self, sender,
					  master_variant, &error);
	if (master == NULL) {
		g_dbus_method_invocation_take_error (invocation, error);
		return TRUE;
	}

	/* Make sure we have such a collection */
	collection = gkd_secret_objects_lookup_collection (self->objects, sender,
							   path);

	/* No such collection */
	if (collection == NULL) {
	  g_dbus_method_invocation_return_error_literal (invocation, GKD_SECRET_ERROR,
							 GKD_SECRET_ERROR_NO_SUCH_OBJECT,
							 "The collection does not exist");
	}

	/* Success */
	else if (gkd_secret_change_with_secrets (collection, NULL, original, master, &error))
		gkd_exported_internal_complete_change_with_master_password
			(skeleton, invocation);

	/* Failure */
	else
		gkd_secret_propagate_error (invocation, "Couldn't change collection password", error);

	gkd_secret_secret_free (original);
	gkd_secret_secret_free (master);

	if (collection)
		g_object_unref (collection);

	return TRUE;
}

static gboolean
service_method_unlock_with_master_password (GkdExportedInternal *skeleton,
					    GDBusMethodInvocation *invocation,
					    gchar *path,
					    GVariant *master_variant,
					    GkdSecretService *self)
{
	GkdSecretSecret *master;
	GError *error = NULL;
	GckObject *collection;
	const gchar *sender;

	sender = g_dbus_method_invocation_get_sender (invocation);

	/* Parse the incoming message */
	master = gkd_secret_secret_parse (self, sender, master_variant, &error);
	if (master == NULL) {
		g_dbus_method_invocation_take_error (invocation, error);
		return TRUE;
	}

	/* Make sure we have such a collection */
	collection = gkd_secret_objects_lookup_collection (self->objects, sender, path);

	/* No such collection */
	if (collection == NULL) {
		g_dbus_method_invocation_return_error_literal (invocation, GKD_SECRET_ERROR,
							       GKD_SECRET_ERROR_NO_SUCH_OBJECT,
							       "The collection does not exist");

	/* Success */
	} else if (gkd_secret_unlock_with_secret (collection, master, &error)) {
		gkd_secret_objects_emit_collection_locked (self->objects, collection);
		gkd_exported_internal_complete_unlock_with_master_password
			(skeleton, invocation);

	/* Failure */
	} else {
		gkd_secret_propagate_error (invocation, "Couldn't unlock collection", error);
	}

	gkd_secret_secret_free (master);

	if (collection)
		g_object_unref (collection);

	return TRUE;
}

static void
service_name_owner_changed (GDBusConnection *connection,
			    const gchar *sender_name,
			    const gchar *object_path,
			    const gchar *interface_name,
			    const gchar *signal_name,
			    GVariant *parameters,
			    gpointer user_data)
{
	const gchar *object_name;
	const gchar *old_owner;
	const gchar *new_owner;
	GkdSecretService *self = user_data;

	/* A peer is connecting or disconnecting from the bus,
	 * remove any client info, when client gone.
	 */
	g_variant_get (parameters, "(&s&s&s)", &object_name, &old_owner, &new_owner);

	if (g_str_equal (new_owner, "") && object_name[0] == ':')
		g_hash_table_remove (self->clients, object_name);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkd_secret_service_init_collections (GkdSecretService *self)
{
	gchar **collections = gkd_secret_service_get_collections (self);
	gint idx;

	for (idx = 0; collections[idx] != NULL; idx++)
		gkd_secret_objects_register_collection (self->objects, collections[idx]);

	g_strfreev (collections);
}

static void
gkd_secret_service_init_aliases (GkdSecretService *self)
{
	self->aliases = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_insert (self->aliases, g_strdup ("session"), g_strdup ("session"));
	/* TODO: We should be using CKA_G_LOGIN_COLLECTION */
	g_hash_table_insert (self->aliases, g_strdup ("login"), g_strdup ("login"));

	update_default (self);
}

static GObject*
gkd_secret_service_constructor (GType type,
				guint n_props,
				GObjectConstructParam *props)
{
	GkdSecretService *self = GKD_SECRET_SERVICE (G_OBJECT_CLASS (gkd_secret_service_parent_class)->constructor(type, n_props, props));
	GError *error = NULL;
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

	self->skeleton = gkd_secret_service_skeleton_new (self);
	g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (self->skeleton),
					  self->connection,
					  SECRET_SERVICE_PATH, &error);
	if (error != NULL) {
		g_warning ("could not register secret service on session bus: %s", error->message);
		g_clear_error (&error);
	}

	g_signal_connect (self->skeleton, "handle-change-lock",
			  G_CALLBACK (service_method_change_lock), self);
	g_signal_connect (self->skeleton, "handle-create-collection",
			  G_CALLBACK (service_method_create_collection), self);
	g_signal_connect (self->skeleton, "handle-get-secrets",
			  G_CALLBACK (service_method_get_secrets), self);
	g_signal_connect (self->skeleton, "handle-lock",
			  G_CALLBACK (service_method_lock), self);
	g_signal_connect (self->skeleton, "handle-lock-service",
			  G_CALLBACK (service_method_lock_service), self);
	g_signal_connect (self->skeleton, "handle-open-session",
			  G_CALLBACK (service_method_open_session), self);
	g_signal_connect (self->skeleton, "handle-read-alias",
			  G_CALLBACK (service_method_read_alias), self);
	g_signal_connect (self->skeleton, "handle-search-items",
			  G_CALLBACK (service_method_search_items), self);
	g_signal_connect (self->skeleton, "handle-set-alias",
			  G_CALLBACK (service_method_set_alias), self);
	g_signal_connect (self->skeleton, "handle-unlock",
			  G_CALLBACK (service_method_unlock), self);

	self->internal_skeleton = gkd_exported_internal_skeleton_new ();
	g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (self->internal_skeleton),
					  self->connection,
					  SECRET_SERVICE_PATH, &error);

	if (error != NULL) {
		g_warning ("could not register internal interface service on session bus: %s", error->message);
		g_clear_error (&error);
	}

	g_signal_connect (self->internal_skeleton, "handle-change-with-master-password",
			  G_CALLBACK (service_method_change_with_master_password), self);
	g_signal_connect (self->internal_skeleton, "handle-change-with-prompt",
			  G_CALLBACK (service_method_change_with_prompt), self);
	g_signal_connect (self->internal_skeleton, "handle-create-with-master-password",
			  G_CALLBACK (service_method_create_with_master_password), self);
	g_signal_connect (self->internal_skeleton, "handle-unlock-with-master-password",
			  G_CALLBACK (service_method_unlock_with_master_password), self);

	self->portal = g_object_new (GKD_SECRET_TYPE_PORTAL, "service", self, NULL);

	self->name_owner_id = g_dbus_connection_signal_subscribe (self->connection,
								  NULL,
								  "org.freedesktop.DBus",
								  "NameOwnerChanged",
								  NULL, NULL,
								  G_DBUS_SIGNAL_FLAGS_NONE,
								  service_name_owner_changed,
								  self, NULL);

	self->filter_id = g_dbus_connection_add_filter (self->connection,
							service_message_filter,
							self, NULL);

	gkd_secret_service_init_collections (self);

	return G_OBJECT (self);
}

static void
gkd_secret_service_init (GkdSecretService *self)
{
	self->clients = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, free_client);
	self->default_path = get_default_path ();
	gkd_secret_service_init_aliases (self);
}

static void
gkd_secret_service_dispose (GObject *obj)
{
	GkdSecretService *self = GKD_SECRET_SERVICE (obj);

	if (self->name_owner_id) {
		g_dbus_connection_signal_unsubscribe (self->connection, self->name_owner_id);
		self->name_owner_id = 0;
	}

	if (self->filter_id) {
		g_dbus_connection_remove_filter (self->connection, self->filter_id);
		self->filter_id = 0;
	}

	/* Closes all the clients */
	g_hash_table_remove_all (self->clients);

	/* Hide all the objects */
	if (self->objects) {
		g_object_run_dispose (G_OBJECT (self->objects));
		g_object_unref (self->objects);
		self->objects = NULL;
	}

	g_clear_object (&self->connection);

	if (self->internal_session) {
		dispose_and_unref (self->internal_session);
		self->internal_session = NULL;
	}

	g_clear_object (&self->portal);

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

	g_free (self->default_path);
	self->default_path = NULL;

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
		self->connection = g_value_dup_object (value);
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
		g_value_set_object (value, gkd_secret_service_get_connection (self));
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
		g_param_spec_object ("connection", "Connection", "DBus Connection",
				     G_TYPE_DBUS_CONNECTION, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_PKCS11_SLOT,
		g_param_spec_object ("pkcs11-slot", "Pkcs11 Slot", "PKCS#11 slot that we use for secrets",
				     GCK_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkdSecretObjects*
gkd_secret_service_get_objects (GkdSecretService *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);
	return self->objects;
}

GDBusConnection*
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
	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (alias != NULL, NULL);

	return g_hash_table_lookup (self->aliases, alias);
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

gchar **
gkd_secret_service_get_collections (GkdSecretService *self)
{
	GVariant *collections_variant;
	gchar **collections;

	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (self), NULL);

	collections_variant = gkd_secret_objects_append_collection_paths (self->objects, NULL);
	collections = g_variant_dup_objv (collections_variant, NULL);
	g_variant_unref (collections_variant);

	return collections;
}

void
gkd_secret_service_emit_collection_created (GkdSecretService *self,
					    const gchar *collection_path)
{
	gchar **collections;

	g_return_if_fail (GKD_SECRET_IS_SERVICE (self));
	g_return_if_fail (collection_path != NULL);

	gkd_secret_objects_register_collection (self->objects, collection_path);

	collections = gkd_secret_service_get_collections (self);
	gkd_exported_service_set_collections (self->skeleton, (const gchar **) collections);
	gkd_exported_service_emit_collection_created (self->skeleton, collection_path);

	g_strfreev (collections);
}

void
gkd_secret_service_emit_collection_deleted (GkdSecretService *self,
					    const gchar *collection_path)
{
	gchar **collections;

	g_return_if_fail (GKD_SECRET_IS_SERVICE (self));
	g_return_if_fail (collection_path != NULL);

	gkd_secret_objects_unregister_collection (self->objects, collection_path);

	collections = gkd_secret_service_get_collections (self);
	gkd_exported_service_set_collections (self->skeleton, (const gchar **) collections);
	gkd_exported_service_emit_collection_deleted (self->skeleton, collection_path);

	g_strfreev (collections);
}

void
gkd_secret_service_emit_collection_changed (GkdSecretService *self,
					    const gchar *collection_path)
{
	g_return_if_fail (GKD_SECRET_IS_SERVICE (self));
	g_return_if_fail (collection_path != NULL);

	gkd_exported_service_emit_collection_changed (self->skeleton, collection_path);
}
