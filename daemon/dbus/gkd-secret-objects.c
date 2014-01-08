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

#include "gkd-secret-error.h"
#include "gkd-secret-introspect.h"
#include "gkd-secret-objects.h"
#include "gkd-secret-property.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"
#include "gkd-secret-util.h"

#include "egg/egg-error.h"

#include "pkcs11/pkcs11i.h"

#include <string.h>

enum {
	PROP_0,
	PROP_PKCS11_SLOT,
	PROP_SERVICE
};

struct _GkdSecretObjects {
	GObject parent;
	GkdSecretService *service;
	GckSlot *pkcs11_slot;
};

static gchar *    object_path_for_item          (const gchar *base,
                                                 GckObject *item);

static gchar *    object_path_for_collection    (GckObject *collection);

static gchar *    collection_path_for_item      (GckObject *item);

G_DEFINE_TYPE (GkdSecretObjects, gkd_secret_objects, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gboolean
parse_object_path (GkdSecretObjects *self, const gchar *path, gchar **collection, gchar **item)
{
	const gchar *replace;

	g_assert (self);
	g_assert (path);
	g_assert (collection);

	if (!gkd_secret_util_parse_path (path, collection, item))
		return FALSE;

	if (g_str_has_prefix (path, SECRET_ALIAS_PREFIX)) {
		replace = gkd_secret_service_get_alias (self->service, *collection);
		if (!replace) {
			g_free (*collection);
			*collection = NULL;
			if (item) {
				g_free (*item);
				*item = NULL;
			}
			return FALSE;
		}
		g_free (*collection);
		*collection = g_strdup (replace);
	}

	return TRUE;
}

static DBusMessage*
object_property_get (GckObject *object, DBusMessage *message,
                     const gchar *prop_name)
{
	DBusMessageIter iter;
	GError *error = NULL;
	DBusMessage *reply;
	GckAttribute attr;
	gpointer value;
	gsize length;

	if (!gkd_secret_property_get_type (prop_name, &attr.type))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have the '%s' property", prop_name);

	/* Retrieve the actual attribute */
	attr.value = value = gck_object_get_data (object, attr.type, NULL, &length, &error);
	if (error != NULL) {
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Couldn't retrieve '%s' property: %s",
		                                       prop_name, egg_error_message (error));
		g_clear_error (&error);
		return reply;
	}

	/* Marshall the data back out */
	attr.length = length;
	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	gkd_secret_property_append_variant (&iter, &attr);
	g_free (value);
	return reply;
}

static DBusMessage*
object_property_set (GckObject *object,
                     DBusMessage *message,
                     DBusMessageIter *iter,
                     const gchar *prop_name)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	DBusMessage *reply;
	GError *error = NULL;
	gulong attr_type;

	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_VARIANT, NULL);

	/* What type of property is it? */
	if (!gkd_secret_property_get_type (prop_name, &attr_type))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have the '%s' property", prop_name);

	/* Retrieve the actual attribute value */
	if (!gkd_secret_property_parse_variant (iter, prop_name, &builder)) {
		gck_builder_clear (&builder);
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "The property type or value was invalid: %s", prop_name);
	}

	gck_object_set (object, gck_builder_end (&builder), NULL, &error);

	if (error != NULL) {
		if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN))
			reply = dbus_message_new_error (message, SECRET_ERROR_IS_LOCKED,
			                                "Cannot set property on a locked object");
		else
			reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
			                                       "Couldn't set '%s' property: %s",
			                                       prop_name, egg_error_message (error));
		g_clear_error (&error);
		return reply;
	}

	return dbus_message_new_method_return (message);
}

static DBusMessage*
item_property_get (GckObject *object, DBusMessage *message)
{
	const gchar *interface;
	const gchar *name;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface,
	                            DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRET_ITEM_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	return object_property_get (object, message, name);
}

static DBusMessage*
item_property_set (GkdSecretObjects *self,
                   GckObject *object,
                   DBusMessage *message)
{
	DBusMessageIter iter;
	const char *interface;
	const char *name;
	DBusMessage *reply;

	if (!dbus_message_has_signature (message, "ssv"))
		return NULL;

	dbus_message_iter_init (message, &iter);
	dbus_message_iter_get_basic (&iter, &interface);
	dbus_message_iter_next (&iter);
	dbus_message_iter_get_basic (&iter, &name);
	dbus_message_iter_next (&iter);

	if (!gkd_dbus_interface_match (SECRET_ITEM_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	reply = object_property_set (object, message, &iter, name);

	/* Notify everyone a property changed */
	if (reply && dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN)
		gkd_secret_objects_emit_item_changed (self, object, name, NULL);

	return reply;
}

static DBusMessage*
item_property_getall (GckObject *object, DBusMessage *message)
{
	GckAttributes *attrs;
	DBusMessageIter iter;
	DBusMessageIter array;
	GError *error = NULL;
	DBusMessage *reply;
	const gchar *interface;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRET_ITEM_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	attrs = gck_object_get (object, NULL, &error,
	                         CKA_LABEL,
	                         CKA_G_SCHEMA,
	                         CKA_G_LOCKED,
	                         CKA_G_CREATED,
	                         CKA_G_MODIFIED,
	                         CKA_G_FIELDS,
	                         GCK_INVALID);

	if (error != NULL)
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Couldn't retrieve properties: %s",
		                                      egg_error_message (error));

	reply = dbus_message_new_method_return (message);

	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "{sv}", &array);
	gkd_secret_property_append_all (&array, attrs);
	dbus_message_iter_close_container (&iter, &array);
	return reply;
}

static DBusMessage*
item_method_delete (GkdSecretObjects *self, GckObject *object, DBusMessage *message)
{
	GError *error = NULL;
	gchar *collection_path;
	gchar *item_path;
	DBusMessage *reply;
	const gchar *prompt;
	GckObject *collection;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID))
		return NULL;

	collection_path = collection_path_for_item (object);
	item_path = object_path_for_item (NULL, object);

	if (gck_object_destroy (object, NULL, &error)) {
		collection = gkd_secret_objects_lookup_collection (self, NULL, collection_path);
		if (collection != NULL) {
			gkd_secret_objects_emit_item_deleted (self, collection, item_path);
			g_object_unref (collection);
		}

		prompt = "/"; /* No prompt necessary */
		reply = dbus_message_new_method_return (message);
		dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &prompt, DBUS_TYPE_INVALID);

	} else {
		if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN))
			reply = dbus_message_new_error_printf (message, SECRET_ERROR_IS_LOCKED,
			                                       "Cannot delete a locked item");
		else
			reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
			                                       "Couldn't delete collection: %s",
			                                       egg_error_message (error));

		g_clear_error (&error);
	}

	g_free (collection_path);
	g_free (item_path);
	return reply;
}

static DBusMessage*
item_method_get_secret (GkdSecretObjects *self, GckObject *item, DBusMessage *message)
{
	DBusError derr = DBUS_ERROR_INIT;
	GkdSecretSession *session;
	GkdSecretSecret *secret;
	DBusMessage *reply;
	DBusMessageIter iter;
	const char *path;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
		return NULL;

	session = gkd_secret_service_lookup_session (self->service, path, dbus_message_get_sender (message));
	if (session == NULL)
		return dbus_message_new_error (message, SECRET_ERROR_NO_SESSION, "The session does not exist");

	secret = gkd_secret_session_get_item_secret (session, item, &derr);
	if (secret == NULL)
		return gkd_secret_error_to_reply (message, &derr);

	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	gkd_secret_secret_append (secret, &iter);
	gkd_secret_secret_free (secret);
	return reply;
}

static DBusMessage*
item_method_set_secret (GkdSecretObjects *self, GckObject *item, DBusMessage *message)
{
	DBusError derr = DBUS_ERROR_INIT;
	DBusMessageIter iter;
	GkdSecretSecret *secret;
	const char *caller;

	if (!dbus_message_has_signature (message, "(oayays)"))
		return NULL;
	dbus_message_iter_init (message, &iter);
	secret = gkd_secret_secret_parse (self->service, message, &iter, &derr);
	if (secret == NULL)
		return gkd_secret_error_to_reply (message, &derr);

	caller = dbus_message_get_sender (message);
	g_return_val_if_fail (caller, NULL);

	gkd_secret_session_set_item_secret (secret->session, item, secret, &derr);
	gkd_secret_secret_free (secret);

	if (dbus_error_is_set (&derr))
		return gkd_secret_error_to_reply (message, &derr);

	return dbus_message_new_method_return (message);
}

static DBusMessage*
item_message_handler (GkdSecretObjects *self, GckObject *object, DBusMessage *message)
{
	/* org.freedesktop.Secret.Item.Delete() */
	if (dbus_message_is_method_call (message, SECRET_ITEM_INTERFACE, "Delete"))
		return item_method_delete (self, object, message);

	/* org.freedesktop.Secret.Session.GetSecret() */
	else if (dbus_message_is_method_call (message, SECRET_ITEM_INTERFACE, "GetSecret"))
		return item_method_get_secret (self, object, message);

	/* org.freedesktop.Secret.Session.SetSecret() */
	else if (dbus_message_is_method_call (message, SECRET_ITEM_INTERFACE, "SetSecret"))
		return item_method_set_secret (self, object, message);

	/* org.freedesktop.DBus.Properties.Get */
	if (dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "Get"))
		return item_property_get (object, message);

	/* org.freedesktop.DBus.Properties.Set */
	else if (dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "Set"))
		return item_property_set (self, object, message);

	/* org.freedesktop.DBus.Properties.GetAll */
	else if (dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "GetAll"))
		return item_property_getall (object, message);

	else if (dbus_message_has_interface (message, DBUS_INTERFACE_INTROSPECTABLE))
		return gkd_dbus_introspect_handle (message, gkd_secret_introspect_item, NULL);

	return NULL;
}

static void
item_cleanup_search_results (GckSession *session, GList *items,
                             GList **locked, GList **unlocked)
{
	GError *error = NULL;
	gpointer value;
	gsize n_value;
	GList *l;

	*locked = NULL;
	*unlocked = NULL;

	for (l = items; l; l = g_list_next (l)) {
		value = gck_object_get_data (l->data, CKA_G_LOCKED, NULL, &n_value, &error);
		if (value == NULL) {
			if (!g_error_matches (error, GCK_ERROR, CKR_OBJECT_HANDLE_INVALID))
				g_warning ("couldn't check if item is locked: %s", egg_error_message (error));
			g_clear_error (&error);

		/* Is not locked */
		} if (n_value == 1 && *((CK_BBOOL*)value) == CK_FALSE) {
			*unlocked = g_list_prepend (*unlocked, l->data);

		/* Is locked */
		} else {
			*locked = g_list_prepend (*locked, l->data);
		}

		g_free (value);
	}

	*locked = g_list_reverse (*locked);
	*unlocked = g_list_reverse (*unlocked);
}

static DBusMessage*
collection_property_get (GkdSecretObjects *self, GckObject *object, DBusMessage *message)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	const gchar *interface;
	const gchar *name;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface,
	                            DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRET_COLLECTION_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	/* Special case, the Items property */
	if (g_str_equal (name, "Items")) {
		reply = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply, &iter);
		gkd_secret_objects_append_item_paths (self, dbus_message_get_path (message), &iter, message);
		return reply;
	}

	return object_property_get (object, message, name);
}

static DBusMessage*
collection_property_set (GkdSecretObjects *self, GckObject *object, DBusMessage *message)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	const char *interface;
	const char *name;

	if (!dbus_message_has_signature (message, "ssv"))
		return NULL;

	dbus_message_iter_init (message, &iter);
	dbus_message_iter_get_basic (&iter, &interface);
	dbus_message_iter_next (&iter);
	dbus_message_iter_get_basic (&iter, &name);
	dbus_message_iter_next (&iter);

	if (!gkd_dbus_interface_match (SECRET_COLLECTION_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	reply = object_property_set (object, message, &iter, name);

	/* Notify everyone a property changed */
	if (reply && dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_METHOD_RETURN)
		gkd_secret_objects_emit_collection_changed (self, object, name, NULL);

	return reply;
}

static DBusMessage*
collection_property_getall (GkdSecretObjects *self, GckObject *object, DBusMessage *message)
{
	GckAttributes *attrs;
	DBusMessageIter iter;
	DBusMessageIter array;
	DBusMessageIter dict;
	GError *error = NULL;
	DBusMessage *reply;
	const gchar *name;
	const gchar *interface;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRET_COLLECTION_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	attrs = gck_object_get (object, NULL, &error,
	                        CKA_LABEL,
	                        CKA_G_LOCKED,
	                        CKA_G_CREATED,
	                        CKA_G_MODIFIED,
	                        GCK_INVALID);

	if (error != NULL)
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Couldn't retrieve properties: %s",
		                                      egg_error_message (error));

	reply = dbus_message_new_method_return (message);

	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "{sv}", &array);

	/* Append all the usual properties */
	gkd_secret_property_append_all (&array, attrs);

	/* Append the Items property */
	dbus_message_iter_open_container (&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
	name = "Items";
	dbus_message_iter_append_basic (&dict, DBUS_TYPE_STRING, &name);
	gkd_secret_objects_append_item_paths (self, dbus_message_get_path (message), &dict, message);
	dbus_message_iter_close_container (&array, &dict);

	dbus_message_iter_close_container (&iter, &array);
	return reply;
}

static DBusMessage*
collection_method_search_items (GkdSecretObjects *self, GckObject *object, DBusMessage *message)
{
	return gkd_secret_objects_handle_search_items (self, message, dbus_message_get_path (message), FALSE);
}

static GckObject*
collection_find_matching_item (GkdSecretObjects *self,
                               GckSession *session,
                               const gchar *identifier,
                               const GckAttribute *fields)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckObject *result = NULL;
	GError *error = NULL;
	GckObject *search;
	gpointer data;
	gsize n_data;

	/* Find items matching the collection and fields */
	gck_builder_add_attribute (&builder, fields);
	gck_builder_add_string (&builder, CKA_G_COLLECTION, identifier);
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_SEARCH);
	gck_builder_add_boolean (&builder, CKA_TOKEN, FALSE);

	/* Create the search object */
	search = gck_session_create_object (session, gck_builder_end (&builder), NULL, &error);

	if (error != NULL) {
		g_warning ("couldn't search for matching item: %s", egg_error_message (error));
		g_clear_error (&error);
		return NULL;
	}

	/* Get the matched item handles, and delete the search object */
	data = gck_object_get_data (search, CKA_G_MATCHED, NULL, &n_data, NULL);
	gck_object_destroy (search, NULL, NULL);
	g_object_unref (search);

	if (n_data >= sizeof (CK_OBJECT_HANDLE))
		result = gck_object_from_handle (session, *((CK_OBJECT_HANDLE_PTR)data));

	g_free (data);
	return result;
}

static gchar *
object_path_for_item (const gchar *base,
                      GckObject *item)
{
	GError *error = NULL;
	gpointer identifier;
	gsize n_identifier;
	gchar *alloc = NULL;
	gchar *path = NULL;

	if (base == NULL)
		base = alloc = collection_path_for_item (item);

	identifier = gck_object_get_data (item, CKA_ID, NULL, &n_identifier, &error);
	if (identifier == NULL) {
		g_warning ("couldn't get item identifier: %s", egg_error_message (error));
		g_clear_error (&error);
		path = NULL;

	} else {
		path = gkd_secret_util_build_path (base, identifier, n_identifier);
		g_free (identifier);
	}

	g_free (alloc);
	return path;
}

static gchar *
collection_path_for_item (GckObject *item)
{
	GError *error = NULL;
	gpointer identifier;
	gsize n_identifier;
	gchar *path = NULL;

	identifier = gck_object_get_data (item, CKA_G_COLLECTION, NULL, &n_identifier, &error);
	if (!identifier) {
		g_warning ("couldn't get item collection identifier: %s", egg_error_message (error));
		g_clear_error (&error);
		return NULL;
	}

	path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX, identifier, n_identifier);
	g_free (identifier);
	return path;
}

static gchar *
object_path_for_collection (GckObject *collection)
{
	GError *error = NULL;
	gpointer identifier;
	gsize n_identifier;
	gchar *path = NULL;

	identifier = gck_object_get_data (collection, CKA_ID, NULL, &n_identifier, &error);
	if (identifier == NULL) {
		g_warning ("couldn't get collection identifier: %s", egg_error_message (error));
		g_clear_error (&error);
		path = NULL;

	} else {
		path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX, identifier, n_identifier);
		g_free (identifier);
	}

	return path;
}

static DBusMessage*
collection_method_create_item (GkdSecretObjects *self, GckObject *object, DBusMessage *message)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckSession *pkcs11_session = NULL;
	DBusError derr = DBUS_ERROR_INIT;
	GkdSecretSecret *secret = NULL;
	dbus_bool_t replace = FALSE;
	GckAttributes *attrs = NULL;
	const GckAttribute *fields;
	DBusMessageIter iter, array;
	GckObject *item = NULL;
	const gchar *prompt;
	const gchar *base;
	GError *error = NULL;
	DBusMessage *reply = NULL;
	gchar *path = NULL;
	gchar *identifier;
	gboolean created = FALSE;

	/* Parse the message */
	if (!dbus_message_has_signature (message, "a{sv}(oayays)b"))
		return NULL;
	if (!dbus_message_iter_init (message, &iter))
		g_return_val_if_reached (NULL);
	dbus_message_iter_recurse (&iter, &array);
	if (!gkd_secret_property_parse_all (&array, SECRET_ITEM_INTERFACE, &builder)) {
		reply = dbus_message_new_error (message, DBUS_ERROR_INVALID_ARGS,
		                                "Invalid properties argument");
		goto cleanup;
	}
	dbus_message_iter_next (&iter);
	secret = gkd_secret_secret_parse (self->service, message, &iter, &derr);
	if (secret == NULL) {
		reply = gkd_secret_error_to_reply (message, &derr);
		goto cleanup;
	}
	dbus_message_iter_next (&iter);
	dbus_message_iter_get_basic (&iter, &replace);

	base = dbus_message_get_path (message);
	if (!parse_object_path (self, base, &identifier, NULL))
		g_return_val_if_reached (NULL);
	g_return_val_if_fail (identifier, NULL);

	pkcs11_session = gck_object_get_session (object);
	g_return_val_if_fail (pkcs11_session, NULL);

	attrs = gck_attributes_ref_sink (gck_builder_end (&builder));

	if (replace) {
		fields = gck_attributes_find (attrs, CKA_G_FIELDS);
		if (fields)
			item = collection_find_matching_item (self, pkcs11_session, identifier, fields);
	}

	/* Replace the item */
	if (item) {
		if (!gck_object_set (item, attrs, NULL, &error))
			goto cleanup;

	/* Create a new item */
	} else {
		gck_builder_add_all (&builder, attrs);
		gck_builder_add_string (&builder, CKA_G_COLLECTION, identifier);
		gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
		item = gck_session_create_object (pkcs11_session, gck_builder_end (&builder), NULL, &error);
		if (item == NULL)
			goto cleanup;
		created = TRUE;
	}

	/* Set the secret */
	if (!gkd_secret_session_set_item_secret (secret->session, item, secret, &derr)) {
		if (created) /* If we created, then try to destroy on failure */
			gck_object_destroy (item, NULL, NULL);
		goto cleanup;
	}

	path = object_path_for_item (base, item);
	gkd_secret_objects_emit_item_created (self, object, item);

	/* Build up the item identifier */
	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_OBJECT_PATH, &path);
	prompt = "/";
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_OBJECT_PATH, &prompt);

cleanup:
	if (error) {
		if (!reply) {
			if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN))
				reply = dbus_message_new_error_printf (message, SECRET_ERROR_IS_LOCKED,
				                                       "Cannot create an item in a locked collection");
			else
				reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
				                                       "Couldn't create item: %s", egg_error_message (error));
		}
		g_clear_error (&error);
	}

	if (dbus_error_is_set (&derr)) {
		if (!reply)
			reply = dbus_message_new_error (message, derr.name, derr.message);
		dbus_error_free (&derr);
	}

	gkd_secret_secret_free (secret);
	gck_attributes_unref (attrs);
	if (item)
		g_object_unref (item);
	if (pkcs11_session)
		g_object_unref (pkcs11_session);
	g_free (path);

	return reply;
}

static DBusMessage*
collection_method_delete (GkdSecretObjects *self, GckObject *object, DBusMessage *message)
{
	GError *error = NULL;
	DBusMessage *reply;
	const gchar *prompt;
	gchar *path;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID))
		return NULL;

	path = object_path_for_collection (object);
	g_return_val_if_fail (path != NULL, NULL);

	if (!gck_object_destroy (object, NULL, &error)) {
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Couldn't delete collection: %s",
		                                       egg_error_message (error));
		g_clear_error (&error);
		g_free (path);
		return reply;
	}

	/* Notify the callers that a collection was deleted */
	gkd_secret_service_emit_collection_deleted (self->service, path);
	g_free (path);

	prompt = "/";
	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &prompt, DBUS_TYPE_INVALID);
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
collection_introspect (GkdSecretObjects *self,
                       GckObject *object,
                       DBusMessage *message)
{
	GPtrArray *names;
	DBusMessage *reply;

	names = g_ptr_array_new_with_free_func (g_free);
	gkd_secret_objects_foreach_item (self, message, dbus_message_get_path (message),
	                                 on_each_path_append_to_array, names);
	g_ptr_array_add (names, NULL);

	reply = gkd_dbus_introspect_handle (message, gkd_secret_introspect_collection,
	                                    (const gchar **)names->pdata);

	g_ptr_array_unref (names);
	return reply;
}

static DBusMessage*
collection_message_handler (GkdSecretObjects *self, GckObject *object, DBusMessage *message)
{
	/* org.freedesktop.Secret.Collection.Delete() */
	if (dbus_message_is_method_call (message, SECRET_COLLECTION_INTERFACE, "Delete"))
		return collection_method_delete (self, object, message);

	/* org.freedesktop.Secret.Collection.SearchItems() */
	if (dbus_message_is_method_call (message, SECRET_COLLECTION_INTERFACE, "SearchItems"))
		return collection_method_search_items (self, object, message);

	/* org.freedesktop.Secret.Collection.CreateItem() */
	if (dbus_message_is_method_call (message, SECRET_COLLECTION_INTERFACE, "CreateItem"))
		return collection_method_create_item (self, object, message);

	/* org.freedesktop.DBus.Properties.Get() */
	if (dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "Get"))
		return collection_property_get (self, object, message);

	/* org.freedesktop.DBus.Properties.Set() */
	else if (dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "Set"))
		return collection_property_set (self, object, message);

	/* org.freedesktop.DBus.Properties.GetAll() */
	else if (dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "GetAll"))
		return collection_property_getall (self, object, message);

	/* org.freedesktop.DBus.Introspectable.Introspect() */
	else if (dbus_message_has_interface (message, DBUS_INTERFACE_INTROSPECTABLE))
		return collection_introspect (self, object, message);

	return NULL;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gkd_secret_objects_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (G_OBJECT_CLASS (gkd_secret_objects_parent_class)->constructor(type, n_props, props));

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->pkcs11_slot, NULL);
	g_return_val_if_fail (self->service, NULL);

	return G_OBJECT (self);
}

static void
gkd_secret_objects_init (GkdSecretObjects *self)
{

}

static void
gkd_secret_objects_dispose (GObject *obj)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (obj);

	if (self->pkcs11_slot) {
		g_object_unref (self->pkcs11_slot);
		self->pkcs11_slot = NULL;
	}

	if (self->service) {
		g_object_remove_weak_pointer (G_OBJECT (self->service),
		                              (gpointer*)&(self->service));
		self->service = NULL;
	}

	G_OBJECT_CLASS (gkd_secret_objects_parent_class)->dispose (obj);
}

static void
gkd_secret_objects_finalize (GObject *obj)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (obj);

	g_assert (!self->pkcs11_slot);
	g_assert (!self->service);

	G_OBJECT_CLASS (gkd_secret_objects_parent_class)->finalize (obj);
}

static void
gkd_secret_objects_set_property (GObject *obj, guint prop_id, const GValue *value,
                                 GParamSpec *pspec)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (obj);

	switch (prop_id) {
	case PROP_PKCS11_SLOT:
		g_return_if_fail (!self->pkcs11_slot);
		self->pkcs11_slot = g_value_dup_object (value);
		g_return_if_fail (self->pkcs11_slot);
		break;
	case PROP_SERVICE:
		g_return_if_fail (!self->service);
		self->service = g_value_get_object (value);
		g_return_if_fail (self->service);
		g_object_add_weak_pointer (G_OBJECT (self->service),
		                           (gpointer*)&(self->service));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_objects_get_property (GObject *obj, guint prop_id, GValue *value,
                                     GParamSpec *pspec)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (obj);

	switch (prop_id) {
	case PROP_PKCS11_SLOT:
		g_value_set_object (value, gkd_secret_objects_get_pkcs11_slot (self));
		break;
	case PROP_SERVICE:
		g_value_set_object (value, self->service);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_objects_class_init (GkdSecretObjectsClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkd_secret_objects_constructor;
	gobject_class->dispose = gkd_secret_objects_dispose;
	gobject_class->finalize = gkd_secret_objects_finalize;
	gobject_class->set_property = gkd_secret_objects_set_property;
	gobject_class->get_property = gkd_secret_objects_get_property;

	g_object_class_install_property (gobject_class, PROP_PKCS11_SLOT,
	        g_param_spec_object ("pkcs11-slot", "Pkcs11 Slot", "PKCS#11 slot that we use for secrets",
	                             GCK_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Service which owns this objects",
		                     GKD_SECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GckSlot*
gkd_secret_objects_get_pkcs11_slot (GkdSecretObjects *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);
	return self->pkcs11_slot;
}

DBusMessage*
gkd_secret_objects_dispatch (GkdSecretObjects *self, DBusMessage *message)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	DBusMessage *reply = NULL;
	GError *error = NULL;
	GList *objects;
	GckSession *session;
	gchar *c_ident;
	gchar *i_ident;
	gboolean is_item;
	const char *path;

	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);
	g_return_val_if_fail (message, NULL);

	path = dbus_message_get_path (message);
	g_return_val_if_fail (path, NULL);

	if (!parse_object_path (self, path, &c_ident, &i_ident) || !c_ident)
		return gkd_secret_error_no_such_object (message);

	/* The session we're using to access the object */
	session = gkd_secret_service_get_pkcs11_session (self->service, dbus_message_get_sender (message));
	g_return_val_if_fail (session, NULL);

	if (i_ident) {
		is_item = TRUE;
		gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
		gck_builder_add_string (&builder, CKA_G_COLLECTION, c_ident);
		gck_builder_add_string (&builder, CKA_ID, i_ident);
	} else {
		is_item = FALSE;
		gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_COLLECTION);
		gck_builder_add_string (&builder, CKA_ID, c_ident);
	}

	objects = gck_session_find_objects (session, gck_builder_end (&builder), NULL, &error);

	g_free (c_ident);
	g_free (i_ident);

	if (error != NULL) {
		g_warning ("couldn't lookup object: %s: %s", path, egg_error_message (error));
		g_clear_error (&error);
	}

	if (!objects)
		return gkd_secret_error_no_such_object (message);

	if (is_item)
		reply = item_message_handler (self, objects->data, message);
	else
		reply = collection_message_handler (self, objects->data, message);

	gck_list_unref_free (objects);
	return reply;
}

GckObject*
gkd_secret_objects_lookup_collection (GkdSecretObjects *self, const gchar *caller,
                                      const gchar *path)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckObject *object = NULL;
	GError *error = NULL;
	GList *objects;
	GckSession *session;
	gchar *identifier;

	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);
	g_return_val_if_fail (path, NULL);

	if (!parse_object_path (self, path, &identifier, NULL))
		return NULL;

	/* The session we're using to access the object */
	if (caller == NULL)
		session = gkd_secret_service_internal_pkcs11_session (self->service);
	else
		session = gkd_secret_service_get_pkcs11_session (self->service, caller);
	g_return_val_if_fail (session, NULL);

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_COLLECTION);
	gck_builder_add_string (&builder, CKA_ID, identifier);

	objects = gck_session_find_objects (session, gck_builder_end (&builder), NULL, &error);

	g_free (identifier);

	if (error != NULL) {
		g_warning ("couldn't lookup collection: %s: %s", path, egg_error_message (error));
		g_clear_error (&error);
	}

	if (objects)
		object = g_object_ref (objects->data);

	gck_list_unref_free (objects);
	return object;
}

GckObject*
gkd_secret_objects_lookup_item (GkdSecretObjects *self, const gchar *caller,
                                const gchar *path)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckObject *object = NULL;
	GError *error = NULL;
	GList *objects;
	GckSession *session;
	gchar *collection;
	gchar *identifier;

	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);
	g_return_val_if_fail (caller, NULL);
	g_return_val_if_fail (path, NULL);

	if (!parse_object_path (self, path, &collection, &identifier))
		return NULL;

	/* The session we're using to access the object */
	session = gkd_secret_service_get_pkcs11_session (self->service, caller);
	g_return_val_if_fail (session, NULL);

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
	gck_builder_add_string (&builder, CKA_ID, identifier);
	gck_builder_add_string (&builder, CKA_G_COLLECTION, collection);

	objects = gck_session_find_objects (session, gck_builder_end (&builder), NULL, &error);

	g_free (identifier);
	g_free (collection);

	if (error != NULL) {
		g_warning ("couldn't lookup item: %s: %s", path, egg_error_message (error));
		g_clear_error (&error);
	}

	if (objects)
		object = g_object_ref (objects->data);

	gck_list_unref_free (objects);
	return object;
}

static void
objects_foreach_item (GkdSecretObjects *self,
                      GList *items,
                      const gchar *base,
                      GkdSecretObjectsForeach callback,
                      gpointer user_data)
{
	gchar *path;
	GList *l;

	for (l = items; l; l = g_list_next (l)) {
		path = object_path_for_item (base, l->data);
		(callback) (self, path, l->data, user_data);
		g_free (path);
	}
}

void
gkd_secret_objects_foreach_item (GkdSecretObjects *self,
                                 DBusMessage *message,
                                 const gchar *base,
                                 GkdSecretObjectsForeach callback,
                                 gpointer user_data)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckSession *session;
	GError *error = NULL;
	gchar *identifier;
	GList *items;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (base != NULL);
	g_return_if_fail (callback != NULL);

	/* The session we're using to access the object */
	if (message == NULL) {
		session = gkd_secret_service_internal_pkcs11_session (self->service);
	} else {
		session = gkd_secret_service_get_pkcs11_session (self->service,
		                                                 dbus_message_get_sender (message));
	}

	if (!parse_object_path (self, base, &identifier, NULL))
		g_return_if_reached ();

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
	gck_builder_add_string (&builder, CKA_G_COLLECTION, identifier);

	items = gck_session_find_objects (session, gck_builder_end (&builder), NULL, &error);

	if (error == NULL) {
		objects_foreach_item (self, items, base, callback, user_data);

	} else {
		g_warning ("couldn't lookup items in '%s' collection: %s", identifier, egg_error_message (error));
		g_clear_error (&error);
	}

	gck_list_unref_free (items);
	g_free (identifier);
}

static void
on_object_path_append_to_iter (GkdSecretObjects *self,
                               const gchar *path,
                               GckObject *object,
                               gpointer user_data)
{
	DBusMessageIter *array = user_data;
	dbus_message_iter_append_basic (array, DBUS_TYPE_OBJECT_PATH, &path);
}

void
gkd_secret_objects_append_item_paths (GkdSecretObjects *self,
                                      const gchar *base,
                                      DBusMessageIter *iter,
                                      DBusMessage *message)
{
	DBusMessageIter variant;
	DBusMessageIter array;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (base);
	g_return_if_fail (iter);


	dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, "ao", &variant);
	dbus_message_iter_open_container (&variant, DBUS_TYPE_ARRAY, "o", &array);

	gkd_secret_objects_foreach_item (self, message, base, on_object_path_append_to_iter, &array);

	dbus_message_iter_close_container (&variant, &array);
	dbus_message_iter_close_container (iter, &variant);
}

void
gkd_secret_objects_foreach_collection (GkdSecretObjects *self,
                                       DBusMessage *message,
                                       GkdSecretObjectsForeach callback,
                                       gpointer user_data)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckSession *session;
	GError *error = NULL;
	GList *collections, *l;
	gpointer identifier;
	gsize n_identifier;
	gchar *path;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (callback);

	/* The session we're using to access the object */
	if (message == NULL) {
		session = gkd_secret_service_internal_pkcs11_session (self->service);
	} else {
		session = gkd_secret_service_get_pkcs11_session (self->service,
		                                                 dbus_message_get_sender (message));
	}

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_COLLECTION);

	collections = gck_session_find_objects (session, gck_builder_end (&builder), NULL, &error);

	if (error != NULL) {
		g_warning ("couldn't lookup collections: %s", egg_error_message (error));
		g_clear_error (&error);
		return;
	}

	for (l = collections; l; l = g_list_next (l)) {

		identifier = gck_object_get_data (l->data, CKA_ID, NULL, &n_identifier, &error);
		if (identifier == NULL) {
			g_warning ("couldn't get collection identifier: %s", egg_error_message (error));
			g_clear_error (&error);
			continue;
		}

		path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX, identifier, n_identifier);
		g_free (identifier);

		(callback) (self, path, l->data, user_data);
		g_free (path);
	}

	gck_list_unref_free (collections);
}

void
gkd_secret_objects_append_collection_paths (GkdSecretObjects *self,
                                            DBusMessageIter *iter,
                                            DBusMessage *message)
{
	DBusMessageIter variant;
	DBusMessageIter array;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (iter != NULL);

	dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, "ao", &variant);
	dbus_message_iter_open_container (&variant, DBUS_TYPE_ARRAY, "o", &array);

	gkd_secret_objects_foreach_collection (self, message, on_object_path_append_to_iter, &array);

	dbus_message_iter_close_container (&variant, &array);
	dbus_message_iter_close_container (iter, &variant);
}

DBusMessage*
gkd_secret_objects_handle_search_items (GkdSecretObjects *self,
                                        DBusMessage *message,
                                        const gchar *base,
                                        gboolean separate_locked)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	DBusMessageIter iter;
	DBusMessageIter array;
	GckObject *search;
	GckSession *session;
	DBusMessage *reply;
	GError *error = NULL;
	gchar *identifier;
	gpointer data;
	gsize n_data;
	GList *locked, *unlocked;
	GList *items;

	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);
	g_return_val_if_fail (message, NULL);

	if (!dbus_message_has_signature (message, "a{ss}"))
		return NULL;

	dbus_message_iter_init (message, &iter);
	if (!gkd_secret_property_parse_fields (&iter, &builder)) {
		gck_builder_clear (&builder);
		return dbus_message_new_error (message, DBUS_ERROR_FAILED,
		                               "Invalid data in attributes argument");
	}

	if (base != NULL) {
		if (!parse_object_path (self, base, &identifier, NULL))
			g_return_val_if_reached (NULL);
		gck_builder_add_string (&builder, CKA_G_COLLECTION, identifier);
		g_free (identifier);
	}

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_SEARCH);
	gck_builder_add_boolean (&builder, CKA_TOKEN, FALSE);

	/* The session we're using to access the object */
	session = gkd_secret_service_get_pkcs11_session (self->service, dbus_message_get_sender (message));
	g_return_val_if_fail (session, NULL);

	/* Create the search object */
	search = gck_session_create_object (session, gck_builder_end (&builder), NULL, &error);

	if (error != NULL) {
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Couldn't search for items: %s",
		                                       egg_error_message (error));
		g_clear_error (&error);
		return reply;
	}

	/* Get the matched item handles, and delete the search object */
	data = gck_object_get_data (search, CKA_G_MATCHED, NULL, &n_data, &error);
	gck_object_destroy (search, NULL, NULL);
	g_object_unref (search);

	if (error != NULL) {
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Couldn't retrieve matched items: %s",
		                                       egg_error_message (error));
		g_clear_error (&error);
		return reply;
	}

	/* Build a list of object handles */
	items = gck_objects_from_handle_array (session, data, n_data / sizeof (CK_OBJECT_HANDLE));
	g_free (data);

	/* Prepare the reply message */
	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);

	/* Filter out the locked items */
	if (separate_locked) {
		item_cleanup_search_results (session, items, &locked, &unlocked);

		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "o", &array);
		objects_foreach_item (self, unlocked, NULL, on_object_path_append_to_iter, &array);
		dbus_message_iter_close_container (&iter, &array);

		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "o", &array);
		objects_foreach_item (self, locked, NULL, on_object_path_append_to_iter, &array);
		dbus_message_iter_close_container (&iter, &array);

		g_list_free (locked);
		g_list_free (unlocked);

	} else {
		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "o", &array);
		objects_foreach_item (self, items, NULL, on_object_path_append_to_iter, &array);
		dbus_message_iter_close_container (&iter, &array);
	}

	gck_list_unref_free (items);

	return reply;
}

DBusMessage*
gkd_secret_objects_handle_get_secrets (GkdSecretObjects *self, DBusMessage *message)
{
	DBusError derr = DBUS_ERROR_INIT;
	GkdSecretSession *session;
	GkdSecretSecret *secret;
	DBusMessage *reply;
	GckObject *item;
	DBusMessageIter iter, array, dict;
	const char *session_path;
	const char *caller;
	char **paths;
	int n_paths, i;

	if (!dbus_message_get_args (message, NULL,
	                            DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &paths, &n_paths,
	                            DBUS_TYPE_OBJECT_PATH, &session_path,
	                            DBUS_TYPE_INVALID))
		return NULL;

	caller = dbus_message_get_sender (message);
	g_return_val_if_fail (caller, NULL);

	session = gkd_secret_service_lookup_session (self->service, session_path,
	                                             dbus_message_get_sender (message));
	if (session == NULL)
		return dbus_message_new_error (message, SECRET_ERROR_NO_SESSION, "The session does not exist");

	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "{o(oayays)}", &array);

	for (i = 0; i < n_paths; ++i) {

		/* Try to find the item, if it doesn't exist, just ignore */
		item = gkd_secret_objects_lookup_item (self, caller, paths[i]);
		if (!item)
			continue;

		secret = gkd_secret_session_get_item_secret (session, item, &derr);
		g_object_unref (item);

		if (secret == NULL) {
			/* We ignore is locked, and just leave out from response */
			if (dbus_error_has_name (&derr, SECRET_ERROR_IS_LOCKED)) {
				dbus_error_free (&derr);
				continue;

			/* All other errors stop the operation */
			} else {
				dbus_message_unref (reply);
				reply = dbus_message_new_error (message, derr.name, derr.message);
				dbus_error_free (&derr);
				break;
			}
		}

		dbus_message_iter_open_container (&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
		dbus_message_iter_append_basic (&dict, DBUS_TYPE_OBJECT_PATH, &(paths[i]));
		gkd_secret_secret_append (secret, &dict);
		gkd_secret_secret_free (secret);
		dbus_message_iter_close_container (&array, &dict);
	}

	if (i == n_paths)
		dbus_message_iter_close_container (&iter, &array);
	dbus_free_string_array (paths);

	return reply;
}

static void
on_each_item_emit_locked (GkdSecretObjects *self,
                          const gchar *path,
                          GckObject *object,
                          gpointer user_data)
{
	gkd_secret_objects_emit_item_changed (self, object, "Locked", NULL);
}

void
gkd_secret_objects_emit_collection_locked (GkdSecretObjects *self,
                                           GckObject *collection)
{
	const gchar *collection_path;

	collection_path = object_path_for_collection (collection);
	gkd_secret_objects_foreach_item (self, NULL, collection_path,
	                                 on_each_item_emit_locked, NULL);

	gkd_secret_objects_emit_collection_changed (self, collection, "Locked", NULL);
}

static void
emit_object_properties_changed (GkdSecretObjects *self,
                                GckObject *object,
                                const gchar *path,
                                const gchar *iface,
                                va_list va)
{
	gchar *collection_path;
	const gchar *propname;
	DBusMessage *message;
	DBusMessageIter iter;
	DBusMessageIter array;
	DBusMessageIter dict;
	CK_ATTRIBUTE_TYPE type;
	GckAttributes *attrs;
	GError *error = NULL;
	gboolean items = FALSE;
	GArray *types;

	types = g_array_new (FALSE, FALSE, sizeof (CK_ATTRIBUTE_TYPE));
	while ((propname = va_arg (va, const gchar *)) != NULL) {

		/* Special case the Items property */
		if (g_str_equal (propname, "Items")) {
			items = TRUE;
			continue;
		}

		if (gkd_secret_property_get_type (propname, &type))
			g_array_append_val (types, type);
		else
			g_warning ("invalid property: %s", propname);
	}

	attrs = gck_object_get_full (object, (CK_ATTRIBUTE_TYPE *)types->data,
	                             types->len, NULL, &error);
	g_array_free (types, TRUE);

	if (error != NULL) {
		g_warning ("couldn't retrieve properties: %s", egg_error_message (error));
		return;
	}

	message = dbus_message_new_signal (path, DBUS_INTERFACE_PROPERTIES,
	                                   "PropertiesChanged");

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &iface);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "{sv}", &array);
	gkd_secret_property_append_all (&array, attrs);

	/* Append the Items property */
	if (items) {
		collection_path = object_path_for_collection (object);
		dbus_message_iter_open_container (&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
		propname = "Items";
		dbus_message_iter_append_basic (&dict, DBUS_TYPE_STRING, &propname);
		gkd_secret_objects_append_item_paths (self, collection_path, &dict, NULL);
		dbus_message_iter_close_container (&array, &dict);
		g_free (collection_path);
	}

	dbus_message_iter_close_container (&iter, &array);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "s", &array);
	dbus_message_iter_close_container (&iter, &array);

	if (!dbus_connection_send (gkd_secret_service_get_connection (self->service),
	                           message, NULL))
		g_return_if_reached ();
	dbus_message_unref (message);

	gck_attributes_unref (attrs);
}

void
gkd_secret_objects_emit_collection_changed (GkdSecretObjects *self,
                                            GckObject *collection,
                                            ...)
{
	DBusMessage *message;
	gchar *collection_path;
	va_list va;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (GCK_OBJECT (collection));

	collection_path = object_path_for_collection (collection);

	message = dbus_message_new_signal (SECRET_SERVICE_PATH,
	                                   SECRET_SERVICE_INTERFACE,
	                                   "CollectionChanged");
	dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &collection_path,
	                          DBUS_TYPE_INVALID);

	if (!dbus_connection_send (gkd_secret_service_get_connection (self->service),
	                           message, NULL))
		g_return_if_reached ();

	dbus_message_unref (message);

	va_start (va, collection);
	emit_object_properties_changed (self, collection, collection_path,
	                                SECRET_COLLECTION_INTERFACE, va);
	va_end (va);

	g_free (collection_path);
}

void
gkd_secret_objects_emit_item_created (GkdSecretObjects *self,
                                      GckObject *collection,
                                      GckObject *item)
{
	DBusMessage *message;
	gchar *collection_path;
	gchar *item_path;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (GCK_OBJECT (collection));
	g_return_if_fail (GCK_OBJECT (item));

	collection_path = object_path_for_collection (collection);
	item_path = object_path_for_item (collection_path, item);

	message = dbus_message_new_signal (collection_path,
	                                   SECRET_COLLECTION_INTERFACE,
	                                   "ItemCreated");
	dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &item_path,
	                          DBUS_TYPE_INVALID);

	if (!dbus_connection_send (gkd_secret_service_get_connection (self->service),
	                           message, NULL))
		g_return_if_reached ();

	dbus_message_unref (message);

	gkd_secret_objects_emit_collection_changed (self, collection, "Items", NULL);

	g_free (item_path);
	g_free (collection_path);
}

void
gkd_secret_objects_emit_item_changed (GkdSecretObjects *self,
                                      GckObject *item,
                                      ...)
{
	DBusMessage *message;
	gchar *collection_path;
	gchar *item_path;
	va_list va;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (GCK_OBJECT (item));

	collection_path = collection_path_for_item (item);
	item_path = object_path_for_item (collection_path, item);

	message = dbus_message_new_signal (collection_path,
	                                   SECRET_COLLECTION_INTERFACE,
	                                   "ItemChanged");
	dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &item_path,
	                          DBUS_TYPE_INVALID);

	if (!dbus_connection_send (gkd_secret_service_get_connection (self->service),
	                           message, NULL))
		g_return_if_reached ();

	dbus_message_unref (message);

	va_start (va, item);
	emit_object_properties_changed (self, item, item_path,
	                                SECRET_ITEM_INTERFACE, va);
	va_end (va);

	g_free (item_path);
	g_free (collection_path);
}

void
gkd_secret_objects_emit_item_deleted (GkdSecretObjects *self,
                                      GckObject *collection,
                                      const gchar *item_path)
{
	DBusMessage *message;
	gchar *collection_path;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (GCK_OBJECT (collection));
	g_return_if_fail (item_path != NULL);

	collection_path = object_path_for_collection (collection);

	message = dbus_message_new_signal (collection_path,
	                                   SECRET_COLLECTION_INTERFACE,
	                                   "ItemDeleted");
	dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &item_path,
	                          DBUS_TYPE_INVALID);

	if (!dbus_connection_send (gkd_secret_service_get_connection (self->service),
	                           message, NULL))
		g_return_if_reached ();

	dbus_message_unref (message);
	g_free (collection_path);

	gkd_secret_objects_emit_collection_changed (self, collection, "Items", NULL);
}
