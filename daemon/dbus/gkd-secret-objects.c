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

#include "gkd-secret-error.h"
#include "gkd-secret-objects.h"
#include "gkd-secret-property.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"
#include "gkd-secret-util.h"
#include "gkd-secrets-generated.h"

#include "egg/egg-error.h"

#include "pkcs11/pkcs11i.h"

#include <string.h>

struct _GkdSecretObjects {
	GObject parent;
	GkdSecretService *service;
	GckSlot *pkcs11_slot;
	GHashTable *collections_to_skeletons;
	GHashTable *items_to_skeletons;
};


/* -----------------------------------------------------------------------------
 * SKELETON
 */

typedef struct {
	GkdExportedCollectionSkeleton parent;
	GkdSecretObjects *objects;
} GkdSecretCollectionSkeleton;
typedef struct {
	GkdExportedCollectionSkeletonClass parent_class;
} GkdSecretCollectionSkeletonClass;
typedef struct {
	GkdExportedItemSkeleton parent;
	GkdSecretObjects *objects;
} GkdSecretItemSkeleton;
typedef struct {
	GkdExportedItemSkeletonClass parent_class;
} GkdSecretItemSkeletonClass;

static GckObject * secret_objects_lookup_gck_object_for_path (GkdSecretObjects *self,
							      const gchar *sender,
							      const gchar *path,
							      GError **error);

GType gkd_secret_collection_skeleton_get_type (void);
G_DEFINE_TYPE (GkdSecretCollectionSkeleton, gkd_secret_collection_skeleton, GKD_TYPE_EXPORTED_COLLECTION_SKELETON)
GType gkd_secret_item_skeleton_get_type (void);
G_DEFINE_TYPE (GkdSecretItemSkeleton, gkd_secret_item_skeleton, GKD_TYPE_EXPORTED_ITEM_SKELETON)

static void
on_object_path_append_to_builder (GkdSecretObjects *self,
				  const gchar *path,
				  GckObject *object,
				  gpointer user_data)
{
	GVariantBuilder *builder = user_data;
	g_variant_builder_add (builder, "o", path);
}

static GVariant *
gkd_secret_objects_append_item_paths (GkdSecretObjects *self,
				      const gchar *caller,
				      const gchar *base)
{
	GVariantBuilder builder;

	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);
	g_return_val_if_fail (base, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ao"));
	gkd_secret_objects_foreach_item (self, caller, base, on_object_path_append_to_builder, &builder);

	return g_variant_builder_end (&builder);
}

static gchar **
gkd_secret_objects_get_collection_items (GkdSecretObjects *self,
					 const gchar *collection_path)
{
	GVariant *items_variant;
	gchar **items;

	items_variant = gkd_secret_objects_append_item_paths (self, NULL, collection_path);
	items = g_variant_dup_objv (items_variant, NULL);
	g_variant_unref (items_variant);

	return items;
}

static gboolean
object_property_set (GkdSecretObjects *objects,
		     GckObject *object,
		     const gchar *prop_name,
		     GVariant *value,
		     GError **error_out)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GError *error = NULL;
	gulong attr_type;

	/* What type of property is it? */
	if (!gkd_secret_property_get_type (prop_name, &attr_type)) {
		g_set_error (error_out, G_DBUS_ERROR,
			     G_DBUS_ERROR_UNKNOWN_PROPERTY,
			     "Object does not have the '%s' property",
			     prop_name);
		return FALSE;
	}

	/* Retrieve the actual attribute value */
	if (!gkd_secret_property_parse_variant (value, prop_name, &builder)) {
		gck_builder_clear (&builder);
		g_set_error (error_out, G_DBUS_ERROR,
			     G_DBUS_ERROR_INVALID_ARGS,
			     "The property type or value was invalid: %s",
			     prop_name);
		return FALSE;
	}

	gck_object_set (object, gck_builder_end (&builder), NULL, &error);

	if (error != NULL) {
		if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN))
			g_set_error (error_out, GKD_SECRET_ERROR,
				     GKD_SECRET_ERROR_IS_LOCKED,
				     "Cannot set property on a locked object");
		else
			g_set_error (error_out, G_DBUS_ERROR,
				     G_DBUS_ERROR_FAILED,
				     "Couldn't set '%s' property: %s",
				     prop_name, egg_error_message (error));
		g_clear_error (&error);
		return FALSE;
	}

	return TRUE;
}

static GVariant *
object_property_get (GkdSecretObjects *objects,
		     GckObject *object,
		     const gchar *prop_name,
		     GError **error_out)
{
	GError *error = NULL;
	GckAttribute attr;
	gpointer value;
	gsize length;
	GVariant *res;

	if (!gkd_secret_property_get_type (prop_name, &attr.type)) {
		g_set_error (error_out, G_DBUS_ERROR,
			     G_DBUS_ERROR_UNKNOWN_PROPERTY,
			     "Object does not have the '%s' property",
			     prop_name);
		return NULL;
	}

	/* Retrieve the actual attribute */
	attr.value = value = gck_object_get_data (object, attr.type, NULL, &length, &error);
	if (error != NULL) {
		g_set_error (error_out, G_DBUS_ERROR,
			     G_DBUS_ERROR_FAILED,
			     "Couldn't retrieve '%s' property: %s",
			     prop_name, egg_error_message (error));
		g_clear_error (&error);
		return NULL;
	}

	/* Marshall the data back out */
	attr.length = length;
	res = gkd_secret_property_append_variant (&attr);
	g_free (value);

	return res;
}

static gboolean
gkd_secret_collection_skeleton_set_property_dbus (GDBusConnection *connection,
						  const gchar *sender,
						  const gchar *object_path,
						  const gchar *interface_name,
						  const gchar *property_name,
						  GVariant *value,
						  GError **error,
						  gpointer user_data)
{
	GkdSecretCollectionSkeleton *self = (GkdSecretCollectionSkeleton *) user_data;
	GckObject *object;

	object = secret_objects_lookup_gck_object_for_path (self->objects, sender, object_path, error);
	if (!object)
		return FALSE;

	if (!object_property_set (self->objects, object, property_name, value, error)) {
		g_object_unref (object);
		return FALSE;
	}

	if (g_strcmp0 (property_name, "Label") == 0) {
		gkd_exported_collection_set_label (GKD_EXPORTED_COLLECTION (self),
						   g_variant_get_string (value, NULL));
	}

	gkd_secret_service_emit_collection_changed (self->objects->service, object_path);
	g_object_unref (object);

	return TRUE;
}

static GVariant *
gkd_secret_collection_skeleton_get_property_dbus (GDBusConnection *connection,
						  const gchar *sender,
						  const gchar *object_path,
						  const gchar *interface_name,
						  const gchar *property_name,
						  GError **error,
						  gpointer user_data)
{
	GkdSecretCollectionSkeleton *self = (GkdSecretCollectionSkeleton *) user_data;
	GckObject *object;
	GVariant *variant;

	object = secret_objects_lookup_gck_object_for_path (self->objects, sender, object_path, error);
	if (!object)
		return FALSE;

	if (g_strcmp0 (property_name, "Items") == 0)
		variant = gkd_secret_objects_append_item_paths (self->objects, sender, object_path);
	else
		variant = object_property_get (self->objects, object, property_name, error);


	g_object_unref (object);
	return variant;
}

static GDBusInterfaceVTable *
gkd_secret_collection_skeleton_get_vtable (GDBusInterfaceSkeleton *skeleton)
{
	static GDBusInterfaceVTable vtable;
	GDBusInterfaceVTable *parent_vtable;

	parent_vtable = G_DBUS_INTERFACE_SKELETON_CLASS (gkd_secret_collection_skeleton_parent_class)->get_vtable (skeleton);

	(&vtable)->get_property = gkd_secret_collection_skeleton_get_property_dbus;
	(&vtable)->set_property = gkd_secret_collection_skeleton_set_property_dbus;
	(&vtable)->method_call = parent_vtable->method_call;

	return &vtable;
}

static void
gkd_secret_collection_skeleton_class_init (GkdSecretCollectionSkeletonClass *klass)
{
	GDBusInterfaceSkeletonClass *skclass = G_DBUS_INTERFACE_SKELETON_CLASS (klass);
	skclass->get_vtable = gkd_secret_collection_skeleton_get_vtable;
}

static void
gkd_secret_collection_skeleton_init (GkdSecretCollectionSkeleton *self)
{
}

static GkdExportedCollection *
gkd_secret_collection_skeleton_new (GkdSecretObjects *objects)
{
	GkdExportedCollection *self = g_object_new (gkd_secret_collection_skeleton_get_type (), NULL);
	((GkdSecretCollectionSkeleton *) self)->objects = objects;
	return self;
}

static gboolean
gkd_secret_item_skeleton_set_property_dbus (GDBusConnection *connection,
					    const gchar *sender,
					    const gchar *object_path,
					    const gchar *interface_name,
					    const gchar *property_name,
					    GVariant *value,
					    GError **error,
					    gpointer user_data)
{
	GkdSecretItemSkeleton *self = (GkdSecretItemSkeleton *) user_data;
	GckObject *object;

	object = secret_objects_lookup_gck_object_for_path (self->objects, sender, object_path, error);
	if (!object)
		return FALSE;

	if (!object_property_set (self->objects, object, property_name, value, error)) {
		g_object_unref (object);
		return FALSE;
	}

	if (g_strcmp0 (property_name, "Attributes") == 0) {
		gkd_exported_item_set_attributes (GKD_EXPORTED_ITEM (self),
						  g_variant_get_variant (value));
	} else if (g_strcmp0 (property_name, "Label") == 0) {
		gkd_exported_item_set_label (GKD_EXPORTED_ITEM (self),
					     g_variant_get_string (value, NULL));
	}

	gkd_secret_objects_emit_item_changed (self->objects, object);
	g_object_unref (object);

	return TRUE;
}

static GVariant *
gkd_secret_item_skeleton_get_property_dbus (GDBusConnection *connection,
					    const gchar *sender,
					    const gchar *object_path,
					    const gchar *interface_name,
					    const gchar *property_name,
					    GError **error,
					    gpointer user_data)
{
	GkdSecretItemSkeleton *self = (GkdSecretItemSkeleton *) user_data;
	GckObject *object;
	GVariant *variant;

	object = secret_objects_lookup_gck_object_for_path (self->objects, sender, object_path, error);
	if (!object)
		return NULL;

	variant = object_property_get (self->objects, object, property_name, error);
	g_object_unref (object);

	return variant;
}

static GDBusInterfaceVTable *
gkd_secret_item_skeleton_get_vtable (GDBusInterfaceSkeleton *skeleton)
{
	static GDBusInterfaceVTable vtable;
	GDBusInterfaceVTable *parent_vtable;

	parent_vtable = G_DBUS_INTERFACE_SKELETON_CLASS (gkd_secret_item_skeleton_parent_class)->get_vtable (skeleton);

	(&vtable)->get_property = gkd_secret_item_skeleton_get_property_dbus;
	(&vtable)->set_property = gkd_secret_item_skeleton_set_property_dbus;
	(&vtable)->method_call = parent_vtable->method_call;

	return &vtable;
}

static void
gkd_secret_item_skeleton_class_init (GkdSecretItemSkeletonClass *klass)
{
	GDBusInterfaceSkeletonClass *skclass = G_DBUS_INTERFACE_SKELETON_CLASS (klass);
	skclass->get_vtable = gkd_secret_item_skeleton_get_vtable;
}

static void
gkd_secret_item_skeleton_init (GkdSecretItemSkeleton *self)
{
}

static GkdExportedItem *
gkd_secret_item_skeleton_new (GkdSecretObjects *objects)
{
	GkdExportedItem *self = g_object_new (gkd_secret_item_skeleton_get_type (), NULL);
	((GkdSecretItemSkeleton *) self)->objects = objects;
	return self;
}

enum {
	PROP_0,
	PROP_PKCS11_SLOT,
	PROP_SERVICE
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

static GckObject *
secret_objects_lookup_gck_object_for_path (GkdSecretObjects *self,
					   const gchar *sender,
					   const gchar *path,
					   GError **error_out)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GList *objects;
	GckSession *session;
	gchar *c_ident;
	gchar *i_ident;
	GckObject *object = NULL;
	GError *error = NULL;

	g_return_val_if_fail (path, FALSE);

	if (!parse_object_path (self, path, &c_ident, &i_ident) || !c_ident)
		goto out;

	/* The session we're using to access the object */
	session = gkd_secret_service_get_pkcs11_session (self->service, sender);
	g_return_val_if_fail (session, FALSE);

	if (i_ident) {
		gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
		gck_builder_add_string (&builder, CKA_G_COLLECTION, c_ident);
		gck_builder_add_string (&builder, CKA_ID, i_ident);
	} else {
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
		goto out;

	object = g_object_ref (objects->data);
	gck_list_unref_free (objects);

 out:
	if (!object)
		g_set_error (error_out, GKD_SECRET_ERROR,
			     GKD_SECRET_ERROR_NO_SUCH_OBJECT,
			     "The '%s' object does not exist",
			     path);

	return object;
}

static GckObject *
secret_objects_lookup_gck_object_for_invocation (GkdSecretObjects *self,
						 GDBusMethodInvocation *invocation)
{
	GError *error = NULL;
	GckObject *object;

	object = secret_objects_lookup_gck_object_for_path (self,
							    g_dbus_method_invocation_get_sender (invocation),
							    g_dbus_method_invocation_get_object_path (invocation),
							    &error);

	if (!object)
		g_dbus_method_invocation_take_error (invocation, error);

	return object;
}

static gboolean
item_method_delete (GkdExportedItem *skeleton,
		    GDBusMethodInvocation *invocation,
		    GkdSecretObjects *self)
{
	GError *error = NULL;
	gchar *collection_path;
	gchar *item_path;
	GckObject *collection;
	GckObject *object;

	object = secret_objects_lookup_gck_object_for_invocation (self, invocation);
	if (!object) {
		return TRUE;
	}

	collection_path = collection_path_for_item (object);
	item_path = object_path_for_item (NULL, object);

	if (gck_object_destroy (object, NULL, &error)) {
		collection = gkd_secret_objects_lookup_collection (self, NULL, collection_path);
		if (collection != NULL) {
			gkd_secret_objects_emit_item_deleted (self, collection, item_path);
			g_object_unref (collection);
		}

		/* No prompt necessary */
		gkd_exported_item_complete_delete (skeleton, invocation, "/");

	} else {
		if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN))
			g_dbus_method_invocation_return_error_literal (invocation, GKD_SECRET_ERROR,
								       GKD_SECRET_ERROR_IS_LOCKED,
								       "Cannot delete a locked item");
		else
			g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
							       G_DBUS_ERROR_FAILED,
							       "Couldn't delete collection: %s",
							       egg_error_message (error));

		g_clear_error (&error);
	}

	g_free (collection_path);
	g_free (item_path);
	g_object_unref (object);

	return TRUE;
}

static gboolean
item_method_get_secret (GkdExportedItem *skeleton,
			GDBusMethodInvocation *invocation,
			gchar *path,
			GkdSecretObjects *self)
{
	GkdSecretSession *session;
	GkdSecretSecret *secret;
	GckObject *item;
	GError *error = NULL;

	item = secret_objects_lookup_gck_object_for_invocation (self, invocation);
	if (!item) {
		return TRUE;
	}

	session = gkd_secret_service_lookup_session (self->service, path,
						     g_dbus_method_invocation_get_sender (invocation));
	if (session == NULL) {
		g_dbus_method_invocation_return_error_literal (invocation, GKD_SECRET_ERROR,
							       GKD_SECRET_ERROR_NO_SESSION,
							       "The session does not exist");
		goto cleanup;
	}

	secret = gkd_secret_session_get_item_secret (session, item, &error);
	if (secret == NULL) {
		g_dbus_method_invocation_take_error (invocation, error);
		goto cleanup;
	}

	gkd_exported_item_complete_get_secret (skeleton, invocation,
					       gkd_secret_secret_append (secret));
	gkd_secret_secret_free (secret);

 cleanup:
	g_object_unref (item);
	return TRUE;
}

static gboolean
item_method_set_secret (GkdExportedItem *skeleton,
			GDBusMethodInvocation *invocation,
			GVariant *secret_variant,
			GkdSecretObjects *self)
{
	GkdSecretSecret *secret;
	const char *caller;
	GckObject *item;
	GError *error = NULL;

	item = secret_objects_lookup_gck_object_for_invocation (self, invocation);
	if (!item) {
		return TRUE;
	}

	caller = g_dbus_method_invocation_get_sender (invocation);
	secret = gkd_secret_secret_parse (self->service, caller, secret_variant, &error);
	if (error != NULL) {
		goto cleanup;
	}

	gkd_secret_session_set_item_secret (secret->session, item, secret, &error);
	gkd_secret_secret_free (secret);

	if (error != NULL) {
		goto cleanup;
	}

 cleanup:
	if (error != NULL) {
		g_dbus_method_invocation_take_error (invocation, error);
	} else {
		gkd_exported_item_complete_set_secret (skeleton, invocation);
	}

	g_object_unref (item);
	return TRUE;
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

static gboolean
collection_method_search_items (GkdExportedCollection *skeleton,
				GDBusMethodInvocation *invocation,
				GVariant *attributes,
				GkdSecretObjects *self)
{
	return gkd_secret_objects_handle_search_items (self, invocation, attributes,
						       g_dbus_method_invocation_get_object_path (invocation),
						       FALSE);
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

static gboolean
collection_method_create_item (GkdExportedCollection *skeleton,
			       GDBusMethodInvocation *invocation,
			       GVariant *properties,
			       GVariant *secret_variant,
			       gboolean replace,
			       GkdSecretObjects *self)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckSession *pkcs11_session = NULL;
	GkdSecretSecret *secret = NULL;
	GckAttributes *attrs = NULL;
	const GckAttribute *fields;
	GckObject *item = NULL;
	const gchar *base;
	GError *error = NULL;
	gchar *path = NULL;
	gchar *identifier;
	gboolean created = FALSE;
	GckObject *object;

	object = secret_objects_lookup_gck_object_for_invocation (self, invocation);
	if (!object) {
		return TRUE;
	}

	if (!gkd_secret_property_parse_all (properties, SECRET_ITEM_INTERFACE, &builder)) {
		g_dbus_method_invocation_return_error_literal (invocation, G_DBUS_ERROR,
							       G_DBUS_ERROR_INVALID_ARGS,
							       "Invalid properties argument");
		goto cleanup;
	}

	base = g_dbus_method_invocation_get_object_path (invocation);
	secret = gkd_secret_secret_parse (self->service, g_dbus_method_invocation_get_sender (invocation),
					  secret_variant, &error);

	if (secret == NULL) {
		g_dbus_method_invocation_take_error (invocation, error);
		error = NULL;
		goto cleanup;
	}

	if (!parse_object_path (self, base, &identifier, NULL))
		g_return_val_if_reached (FALSE);
	g_return_val_if_fail (identifier, FALSE);

	pkcs11_session = gck_object_get_session (object);
	g_return_val_if_fail (pkcs11_session, FALSE);

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
	if (!gkd_secret_session_set_item_secret (secret->session, item, secret, &error)) {
		if (created) /* If we created, then try to destroy on failure */
			gck_object_destroy (item, NULL, NULL);
		goto cleanup;
	}

	path = object_path_for_item (base, item);
	gkd_secret_objects_emit_item_created (self, object, path);

	gkd_exported_collection_complete_create_item (skeleton, invocation, path, "/");

cleanup:
	if (error) {
		if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN))
			g_dbus_method_invocation_return_error_literal (invocation, GKD_SECRET_ERROR,
								       GKD_SECRET_ERROR_IS_LOCKED,
								       "Cannot create an item in a locked collection");
		else
			g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
							       G_DBUS_ERROR_FAILED,
							       "Couldn't create item: %s",
							       egg_error_message (error));
		g_clear_error (&error);
	}

	gkd_secret_secret_free (secret);
	gck_attributes_unref (attrs);
	if (item)
		g_object_unref (item);
	if (pkcs11_session)
		g_object_unref (pkcs11_session);
	g_free (path);
	g_object_unref (object);

	return TRUE;
}

static gboolean
collection_method_delete (GkdExportedCollection *skeleton,
			  GDBusMethodInvocation *invocation,
			  GkdSecretObjects *self)
{
	GError *error = NULL;
	gchar *path;
	GckObject *object;

	object = secret_objects_lookup_gck_object_for_invocation (self, invocation);
	if (!object) {
		return TRUE;
	}

	path = object_path_for_collection (object);
	g_return_val_if_fail (path != NULL, FALSE);

	if (!gck_object_destroy (object, NULL, &error)) {
		g_dbus_method_invocation_return_error (invocation,
						       G_DBUS_ERROR,
						       G_DBUS_ERROR_FAILED,
						       "Couldn't delete collection: %s",
						       egg_error_message (error));
		g_clear_error (&error);
		goto cleanup;
	}

	/* Notify the callers that a collection was deleted */
	gkd_secret_service_emit_collection_deleted (self->service, path);
	gkd_exported_collection_complete_delete (skeleton, invocation, "/");

 cleanup:
	g_free (path);
	g_object_unref (object);

	return TRUE;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
skeleton_destroy_func (gpointer user_data)
{
	GDBusInterfaceSkeleton *skeleton = user_data;
	g_dbus_interface_skeleton_unexport (skeleton);
	g_object_unref (skeleton);
}

static void
gkd_secret_objects_init (GkdSecretObjects *self)
{
	self->collections_to_skeletons = g_hash_table_new_full (g_str_hash, g_str_equal,
								g_free, skeleton_destroy_func);
	self->items_to_skeletons = g_hash_table_new_full (g_str_hash, g_str_equal,
							  g_free, skeleton_destroy_func);
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

	g_clear_pointer (&self->collections_to_skeletons, g_hash_table_unref);
	g_clear_pointer (&self->items_to_skeletons, g_hash_table_unref);

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
				 const gchar *caller,
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
	if (caller == NULL) {
		session = gkd_secret_service_internal_pkcs11_session (self->service);
	} else {
		session = gkd_secret_service_get_pkcs11_session (self->service, caller);
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

void
gkd_secret_objects_foreach_collection (GkdSecretObjects *self,
				       const gchar *caller,
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
	if (caller == NULL) {
		session = gkd_secret_service_internal_pkcs11_session (self->service);
	} else {
		session = gkd_secret_service_get_pkcs11_session (self->service, caller);
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

GVariant *
gkd_secret_objects_append_collection_paths (GkdSecretObjects *self,
					    const gchar *caller)
{
	GVariantBuilder builder;

	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ao"));
	gkd_secret_objects_foreach_collection (self, caller, on_object_path_append_to_builder, &builder);

	return g_variant_builder_end (&builder);
}

gboolean
gkd_secret_objects_handle_search_items (GkdSecretObjects *self,
					GDBusMethodInvocation *invocation,
					GVariant *attributes,
					const gchar *base,
					gboolean separate_locked)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckObject *search;
	GckSession *session;
	GError *error = NULL;
	gchar *identifier;
	gpointer data;
	gsize n_data;
	GList *locked, *unlocked;
	GList *items;
	GVariantBuilder result;

	if (!gkd_secret_property_parse_fields (attributes, &builder)) {
		gck_builder_clear (&builder);
		g_dbus_method_invocation_return_error_literal (invocation,
							       G_DBUS_ERROR,
							       G_DBUS_ERROR_FAILED,
							       "Invalid data in attributes argument");
		return TRUE;
	}

	if (base != NULL) {
		if (!parse_object_path (self, base, &identifier, NULL))
			g_return_val_if_reached (FALSE);
		gck_builder_add_string (&builder, CKA_G_COLLECTION, identifier);
		g_free (identifier);
	}

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_SEARCH);
	gck_builder_add_boolean (&builder, CKA_TOKEN, FALSE);

	/* The session we're using to access the object */
	session = gkd_secret_service_get_pkcs11_session (self->service, g_dbus_method_invocation_get_sender (invocation));
	g_return_val_if_fail (session, FALSE);

	/* Create the search object */
	search = gck_session_create_object (session, gck_builder_end (&builder), NULL, &error);

	if (error != NULL) {
		g_dbus_method_invocation_return_error (invocation,
						       G_DBUS_ERROR,
						       G_DBUS_ERROR_FAILED,
						       "Couldn't search for items: %s",
						       egg_error_message (error));
		g_clear_error (&error);
		return TRUE;
	}

	/* Get the matched item handles, and delete the search object */
	data = gck_object_get_data (search, CKA_G_MATCHED, NULL, &n_data, &error);
	gck_object_destroy (search, NULL, NULL);
	g_object_unref (search);

	if (error != NULL) {
		g_dbus_method_invocation_return_error (invocation,
						       G_DBUS_ERROR,
						       G_DBUS_ERROR_FAILED,
						       "Couldn't retrieve matched items: %s",
						       egg_error_message (error));
		g_clear_error (&error);
		return TRUE;
	}

	/* Build a list of object handles */
	items = gck_objects_from_handle_array (session, data, n_data / sizeof (CK_OBJECT_HANDLE));
	g_free (data);

	/* Filter out the locked items */
	if (separate_locked) {
		GVariant *unlocked_variant, *locked_variant;

		item_cleanup_search_results (session, items, &locked, &unlocked);

		g_variant_builder_init (&result, G_VARIANT_TYPE ("ao"));
		objects_foreach_item (self, unlocked, NULL, on_object_path_append_to_builder, &result);
		unlocked_variant = g_variant_builder_end (&result);

		g_variant_builder_init (&result, G_VARIANT_TYPE ("ao"));
		objects_foreach_item (self, locked, NULL, on_object_path_append_to_builder, &result);
		locked_variant = g_variant_builder_end (&result);

		g_list_free (locked);
		g_list_free (unlocked);

		g_dbus_method_invocation_return_value (invocation,
						       g_variant_new ("(@ao@ao)",
								      unlocked_variant,
								      locked_variant));
	} else {
		g_variant_builder_init (&result, G_VARIANT_TYPE ("ao"));
		objects_foreach_item (self, items, NULL, on_object_path_append_to_builder, &result);

		g_dbus_method_invocation_return_value (invocation,
						       g_variant_new ("(@ao)", g_variant_builder_end (&result)));
	}

	gck_list_unref_free (items);

	return TRUE;
}

gboolean
gkd_secret_objects_handle_get_secrets (GkdSecretObjects *self,
				       GDBusMethodInvocation *invocation,
				       const gchar **paths,
				       const gchar *session_path)
{
	GkdSecretSession *session;
	GkdSecretSecret *secret;
	GckObject *item;
	const char *caller;
	int i;
	GVariantBuilder builder;
	GError *error = NULL;

	caller = g_dbus_method_invocation_get_sender (invocation);
	session = gkd_secret_service_lookup_session (self->service, session_path, caller);
	if (session == NULL) {
		g_dbus_method_invocation_return_error_literal (invocation, GKD_SECRET_ERROR,
							       GKD_SECRET_ERROR_NO_SESSION,
							       "The session does not exist");
		return TRUE;
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{o(oayays)"));

	for (i = 0; paths[i] != NULL; ++i) {

		/* Try to find the item, if it doesn't exist, just ignore */
		item = gkd_secret_objects_lookup_item (self, caller, paths[i]);
		if (!item)
			continue;

		secret = gkd_secret_session_get_item_secret (session, item, &error);
		g_object_unref (item);

		if (secret == NULL) {
			/* We ignore is locked, and just leave out from response */
			if (g_error_matches (error, GKD_SECRET_ERROR, GKD_SECRET_ERROR_IS_LOCKED)) {
				g_clear_error (&error);
				continue;

			/* All other errors stop the operation */
			} else {
				g_dbus_method_invocation_take_error (invocation, error);
				return TRUE;
			}
		}

		g_variant_builder_add (&builder, "o@(oayays)", paths[i], gkd_secret_secret_append (secret));
		gkd_secret_secret_free (secret);
	}

	g_dbus_method_invocation_return_value (invocation,
					       g_variant_new ("(@a{o(oayays)})", g_variant_builder_end (&builder)));
	return TRUE;
}

static void
on_each_item_emit_locked (GkdSecretObjects *self,
			  const gchar *path,
			  GckObject *object,
			  gpointer user_data)
{
	GkdExportedItem *skeleton;
	GVariant *value;
	GError *error = NULL;

	skeleton = g_hash_table_lookup (self->items_to_skeletons, path);
	if (skeleton == NULL) {
		g_warning ("setting locked state on item %s, but no skeleton found", path);
		return;
	}

	value = object_property_get (self, object, "Locked", &error);
	if (!value) {
		g_warning ("setting locked state on item %s, but no property value: %s",
			   path, error->message);
		g_error_free (error);
		return;
	}

	gkd_exported_item_set_locked (skeleton, g_variant_get_boolean (value));
	g_variant_unref (value);

	gkd_secret_objects_emit_item_changed (self, object);
}

void
gkd_secret_objects_emit_collection_locked (GkdSecretObjects *self,
					   GckObject *collection)
{
	gchar *collection_path;
	GkdExportedCollection *skeleton;
	GVariant *value;
	GError *error = NULL;

	collection_path = object_path_for_collection (collection);
	gkd_secret_objects_foreach_item (self, NULL, collection_path,
					 on_each_item_emit_locked, NULL);

	skeleton = g_hash_table_lookup (self->collections_to_skeletons, collection_path);
	if (skeleton == NULL) {
		g_warning ("setting locked state on collection %s, but no skeleton found", collection_path);
		return;
	}

	value = object_property_get (self, collection, "Locked", &error);
	if (!value) {
		g_warning ("setting locked state on item %s, but no property value: %s",
			   collection_path, error->message);
		g_error_free (error);
		return;
	}

	gkd_exported_collection_set_locked (skeleton, g_variant_get_boolean (value));
	g_variant_unref (value);

	gkd_secret_service_emit_collection_changed (self->service, collection_path);
	g_free (collection_path);
}

static void
gkd_secret_objects_register_item (GkdSecretObjects *self,
				  const gchar *item_path)
{
	GkdExportedItem *skeleton;
	GError *error = NULL;

	skeleton = g_hash_table_lookup (self->items_to_skeletons, item_path);
	if (skeleton != NULL) {
		g_warning ("asked to register item %p, but it's already registered", item_path);
		return;
	}

	skeleton = gkd_secret_item_skeleton_new (self);
	g_hash_table_insert (self->items_to_skeletons, g_strdup (item_path), skeleton);

	g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (skeleton),
					  gkd_secret_service_get_connection (self->service),
					  item_path, &error);
	if (error != NULL) {
		g_warning ("could not register secret item on session bus: %s", error->message);
		g_error_free (error);
	}

	g_signal_connect (skeleton, "handle-delete",
			  G_CALLBACK (item_method_delete), self);
	g_signal_connect (skeleton, "handle-get-secret",
			  G_CALLBACK (item_method_get_secret), self);
	g_signal_connect (skeleton, "handle-set-secret",
			  G_CALLBACK (item_method_set_secret), self);
}

static void
gkd_secret_objects_unregister_item (GkdSecretObjects *self,
				    const gchar *item_path)
{
	if (!g_hash_table_remove (self->items_to_skeletons, item_path)) {
		g_warning ("asked to unregister item %p, but it wasn't found", item_path);
		return;
	}
}

void
gkd_secret_objects_emit_item_created (GkdSecretObjects *self,
				      GckObject *collection,
				      const gchar *item_path)
{
	GkdExportedCollection *skeleton;
	gchar *collection_path;
	gchar **items;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (GCK_OBJECT (collection));
	g_return_if_fail (item_path != NULL);

	collection_path = object_path_for_collection (collection);
	skeleton = g_hash_table_lookup (self->collections_to_skeletons, collection_path);
	g_return_if_fail (skeleton != NULL);

	gkd_secret_objects_register_item (self, item_path);
	gkd_exported_collection_emit_item_created (skeleton, item_path);

	items = gkd_secret_objects_get_collection_items (self, collection_path);
	gkd_exported_collection_set_items (skeleton, (const gchar **) items);

	g_free (collection_path);
	g_strfreev (items);
}

void
gkd_secret_objects_emit_item_changed (GkdSecretObjects *self,
				      GckObject *item)
{
	GkdExportedCollection *skeleton;
	gchar *collection_path;
	gchar *item_path;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (GCK_OBJECT (item));

	collection_path = collection_path_for_item (item);
	skeleton = g_hash_table_lookup (self->collections_to_skeletons, collection_path);
	g_return_if_fail (skeleton != NULL);

	item_path = object_path_for_item (collection_path, item);
	gkd_exported_collection_emit_item_changed (skeleton, item_path);

	g_free (item_path);
	g_free (collection_path);
}

void
gkd_secret_objects_emit_item_deleted (GkdSecretObjects *self,
				      GckObject *collection,
				      const gchar *item_path)
{
	GkdExportedCollection *skeleton;
	gchar *collection_path;
	gchar **items;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (GCK_OBJECT (collection));
	g_return_if_fail (item_path != NULL);

	collection_path = object_path_for_collection (collection);
	skeleton = g_hash_table_lookup (self->collections_to_skeletons, collection_path);
	g_return_if_fail (skeleton != NULL);

	gkd_secret_objects_unregister_item (self, item_path);
	gkd_exported_collection_emit_item_deleted (skeleton, item_path);

	items = gkd_secret_objects_get_collection_items (self, collection_path);
	gkd_exported_collection_set_items (skeleton, (const gchar **) items);

	g_strfreev (items);
	g_free (collection_path);
}

static void
gkd_secret_objects_init_collection_items (GkdSecretObjects *self,
					  const gchar *collection_path)
{
	gchar **items;
	gint idx;

	items = gkd_secret_objects_get_collection_items (self, collection_path);
	for (idx = 0; items[idx] != NULL; idx++)
		gkd_secret_objects_register_item (self, items[idx]);

	g_strfreev (items);
}

void
gkd_secret_objects_register_collection (GkdSecretObjects *self,
					const gchar *collection_path)
{
	GkdExportedCollection *skeleton;
	GError *error = NULL;

	skeleton = g_hash_table_lookup (self->collections_to_skeletons, collection_path);
	if (skeleton != NULL) {
		g_warning ("asked to register collection %p, but it's already registered", collection_path);
		return;
	}

	skeleton = gkd_secret_collection_skeleton_new (self);
	g_hash_table_insert (self->collections_to_skeletons, g_strdup (collection_path), skeleton);

	g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (skeleton),
					  gkd_secret_service_get_connection (self->service),
					  collection_path, &error);
	if (error != NULL) {
		g_warning ("could not register secret collection on session bus: %s", error->message);
		g_error_free (error);
	}

	g_signal_connect (skeleton, "handle-create-item",
			  G_CALLBACK (collection_method_create_item), self);
	g_signal_connect (skeleton, "handle-delete",
			  G_CALLBACK (collection_method_delete), self);
	g_signal_connect (skeleton, "handle-search-items",
			  G_CALLBACK (collection_method_search_items), self);

	gkd_secret_objects_init_collection_items (self, collection_path);
}

void
gkd_secret_objects_unregister_collection (GkdSecretObjects *self,
					  const gchar *collection_path)
{
	if (!g_hash_table_remove (self->collections_to_skeletons, collection_path)) {
		g_warning ("asked to unregister collection %p, but it wasn't found", collection_path);
		return;
	}
}
