/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
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

#include "gck-secret-collection.h"
#include "gck-secret-fields.h"
#include "gck-secret-item.h"
#include "gck-secret-search.h"

#include "gck/gck-attributes.h"
#include "gck/gck-manager.h"
#include "gck/gck-module.h"
#include "gck/gck-session.h"
#include "gck/gck-transaction.h"
#include "gck/gck-util.h"

#include "pkcs11i.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_COLLECTION_ID,
	PROP_FIELDS
};

struct _GckSecretSearch {
	GckObject parent;
	gchar *collection_id;
	GHashTable *fields;
	GList *managers;
	GHashTable *handles;
};

G_DEFINE_TYPE (GckSecretSearch, gck_secret_search, GCK_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gboolean
match_object_against_criteria (GckSecretSearch *self, GckObject *object)
{
	GckSecretCollection *collection;
	GckSecretItem *item;
	GHashTable *fields;
	const gchar *identifier;

	if (!GCK_IS_SECRET_ITEM (object))
		return FALSE;

	item = GCK_SECRET_ITEM (object);

	/* Collection should match unless any collection allowed */
	if (self->collection_id) {
		collection = gck_secret_item_get_collection (item);
		g_return_val_if_fail (collection, FALSE);
		identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (collection));
		g_return_val_if_fail (identifier, FALSE);
		if (!g_str_equal (identifier, self->collection_id))
			return FALSE;
	}

	/* Fields should match using our special algorithm */
	fields = gck_secret_item_get_fields (item);
	return gck_secret_fields_match (fields, self->fields);
}

static void
on_manager_added_object (GckManager *manager, GckObject *object, gpointer user_data)
{
	GckSecretSearch *self = user_data;
	CK_OBJECT_HANDLE handle;

	g_return_if_fail (GCK_IS_SECRET_SEARCH (self));

	handle = gck_object_get_handle (object);
	g_return_if_fail (handle);

	g_return_if_fail (g_hash_table_lookup (self->handles, &handle) == NULL);

	if (match_object_against_criteria (self, object)) {
		g_hash_table_replace (self->handles, gck_util_ulong_alloc (handle), "unused");
		gck_object_notify_attribute (GCK_OBJECT (self), CKA_G_MATCHED);
	}
}

static void
on_manager_removed_object (GckManager *manager, GckObject *object, gpointer user_data)
{
	GckSecretSearch *self = user_data;
	CK_OBJECT_HANDLE handle;

	g_return_if_fail (GCK_IS_SECRET_SEARCH (self));

	handle = gck_object_get_handle (object);
	g_return_if_fail (handle);

	if (g_hash_table_lookup (self->handles, &handle) != NULL) {
		g_hash_table_remove (self->handles, &handle);
		gck_object_notify_attribute (GCK_OBJECT (self), CKA_G_MATCHED);
	}
}

static void
on_manager_changed_object (GckManager *manager, GckObject *object,
                           CK_ATTRIBUTE_TYPE type, gpointer user_data)
{
	GckSecretSearch *self = user_data;
	CK_OBJECT_HANDLE handle;

	if (type != CKA_G_FIELDS)
		return;

	g_return_if_fail (GCK_IS_SECRET_SEARCH (self));

	handle = gck_object_get_handle (object);
	g_return_if_fail (handle);

	/* Should we have this object? */
	if (match_object_against_criteria (self, object)) {
		if (g_hash_table_lookup (self->handles, &handle) == NULL) {
			g_hash_table_replace (self->handles, gck_util_ulong_alloc (handle), "unused");
			gck_object_notify_attribute (GCK_OBJECT (self), CKA_G_MATCHED);
		}

	/* Should we not have this object? */
	} else {
		if (g_hash_table_lookup (self->handles, &handle) != NULL) {
			g_hash_table_remove (self->handles, &handle);
			gck_object_notify_attribute (GCK_OBJECT (self), CKA_G_MATCHED);
		}
	}
}

static void
on_manager_gone_away (gpointer user_data, GObject *where_the_object_was)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (user_data);
	GList *l;

	g_return_if_fail (self);

	l = g_list_find (self->managers, where_the_object_was);
	g_return_if_fail (l != NULL);
	self->managers = g_list_delete_link (self->managers, l);
}

static void
populate_search_from_manager (GckSecretSearch *self, GckManager *manager)
{
	GList *objects, *o;

	self->managers = g_list_append (self->managers, manager);

	/* Add in all the objects */
	objects = gck_manager_find_by_class (manager, CKO_SECRET_KEY);
	for (o = objects; o; o = g_list_next (o))
		on_manager_added_object (manager, o->data, self);
	g_list_free (objects);

	/* Track this manager */
	g_object_weak_ref (G_OBJECT (manager), on_manager_gone_away, self);

	/* Watch for further events of objects */
	g_signal_connect (manager, "object-added", G_CALLBACK (on_manager_added_object), self);
	g_signal_connect (manager, "object-removed", G_CALLBACK (on_manager_removed_object), self);
	g_signal_connect (manager, "attribute-changed", G_CALLBACK (on_manager_changed_object), self);
}

static GckObject*
factory_create_search (GckSession *session, GckTransaction *transaction,
                       CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	GckManager *s_manager, *m_manager;
	GckSecretSearch *search;
	gchar *identifier = NULL;
	CK_ATTRIBUTE *attr;
	GHashTable *fields;
	GckModule *module;
	CK_RV rv;

	g_return_val_if_fail (GCK_IS_TRANSACTION (transaction), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);

	/* Find the fields being requested */
	attr = gck_attributes_find (attrs, n_attrs, CKA_G_FIELDS);
	if (attr == NULL) {
		gck_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
		return NULL;
	}

	/* Parse the fields, into our internal representation */
	rv = gck_secret_fields_parse (attr, &fields);
	gck_attribute_consume (attr);
	if (rv != CKR_OK) {
		gck_transaction_fail (transaction, rv);
		return NULL;
	}

	s_manager = gck_session_get_manager (session);
	module = gck_session_get_module (session);
	m_manager = gck_module_get_manager (module);

	/* See if a collection attribute was specified, not present means all collections */
	attr = gck_attributes_find (attrs, n_attrs, CKA_G_COLLECTION);
	if (attr) {
		rv = gck_attribute_get_string (attr, &identifier);
		if (rv != CKR_OK) {
			g_hash_table_unref (fields);
			gck_transaction_fail (transaction, rv);
			return NULL;
		}
	}

	search = g_object_new (GCK_TYPE_SECRET_SEARCH,
	                       "module", module,
	                       "manager", s_manager,
	                       "fields", fields,
	                       "collection-id", identifier,
	                       NULL);

	/* Load any new items or collections */
	gck_module_refresh_token (module);

	populate_search_from_manager (search, s_manager);
	populate_search_from_manager (search, m_manager);

	gck_session_complete_object_creation (session, transaction, GCK_OBJECT (search),
	                                      TRUE, attrs, n_attrs);
	return GCK_OBJECT (search);
}

static void
add_each_handle_to_array (gpointer key, gpointer value, gpointer user_data)
{
	GArray *array = user_data;
	CK_OBJECT_HANDLE *handle = key;
	g_array_append_val (array, *handle);
}

static CK_RV
attribute_set_handles (GHashTable *handles, CK_ATTRIBUTE_PTR attr)
{
	GArray *array;
	CK_RV rv;

	g_assert (handles);
	g_assert (attr);

	/* Want the length */
	if (!attr->pValue) {
		attr->ulValueLen = sizeof (CK_OBJECT_HANDLE) * g_hash_table_size (handles);
		return CKR_OK;
	}

	/* Get the actual values */
	array = g_array_new (FALSE, TRUE, sizeof (CK_OBJECT_HANDLE));
	g_hash_table_foreach (handles, add_each_handle_to_array, array);
	rv = gck_attribute_set_data (attr, array->data, array->len * sizeof (CK_OBJECT_HANDLE));
	g_array_free (array, TRUE);
	return rv;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static CK_RV
gck_secret_search_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (base);

	switch (attr->type) {
	case CKA_CLASS:
		return gck_attribute_set_ulong (attr, CKO_G_SEARCH);
	case CKA_MODIFIABLE:
		return gck_attribute_set_bool (attr, CK_TRUE); /* TODO: This is needed for deleting? */
	case CKA_G_COLLECTION:
		if (!self->collection_id)
			return gck_attribute_set_empty (attr);
		return gck_attribute_set_string (attr, self->collection_id);
	case CKA_G_FIELDS:
		return gck_secret_fields_serialize (attr, self->fields);
	case CKA_G_MATCHED:
		return attribute_set_handles (self->handles, attr);
	}

	return GCK_OBJECT_CLASS (gck_secret_search_parent_class)->get_attribute (base, session, attr);
}


static void
gck_secret_search_init (GckSecretSearch *self)
{
	self->handles = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal, gck_util_ulong_free, NULL);
}

static GObject*
gck_secret_search_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (G_OBJECT_CLASS (gck_secret_search_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);

	g_return_val_if_fail (self->fields, NULL);

	return G_OBJECT (self);
}

static void
gck_secret_search_set_property (GObject *obj, guint prop_id, const GValue *value,
                                    GParamSpec *pspec)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (obj);
	switch (prop_id) {
	case PROP_COLLECTION_ID:
		g_return_if_fail (!self->collection_id);
		self->collection_id = g_value_dup_string (value);
		break;
	case PROP_FIELDS:
		g_return_if_fail (!self->fields);
		self->fields = g_value_dup_boxed (value);
		g_return_if_fail (self->fields);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_search_get_property (GObject *obj, guint prop_id, GValue *value,
                                    GParamSpec *pspec)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (obj);
	switch (prop_id) {
	case PROP_COLLECTION_ID:
		g_value_set_string (value, self->collection_id);
		break;
	case PROP_FIELDS:
		g_return_if_fail (self->fields);
		g_value_set_boxed (value, gck_secret_search_get_fields (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_search_dispose (GObject *obj)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (obj);
	GList *l;

	for (l = self->managers; l; l = g_list_next (l)) {
		g_signal_handlers_disconnect_by_func (l->data, on_manager_added_object, self);
		g_signal_handlers_disconnect_by_func (l->data, on_manager_removed_object, self);
		g_signal_handlers_disconnect_by_func (l->data, on_manager_changed_object, self);
		g_object_weak_unref (G_OBJECT (l->data), on_manager_gone_away, self);
	}
	g_list_free (self->managers);
	self->managers = NULL;

	g_free (self->collection_id);
	self->collection_id = NULL;

	G_OBJECT_CLASS (gck_secret_search_parent_class)->dispose (obj);
}

static void
gck_secret_search_finalize (GObject *obj)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (obj);

	g_assert (!self->managers);

	if (self->fields)
		g_hash_table_destroy (self->fields);
	self->fields = NULL;

	G_OBJECT_CLASS (gck_secret_search_parent_class)->finalize (obj);
}

static void
gck_secret_search_class_init (GckSecretSearchClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);

	gck_secret_search_parent_class = g_type_class_peek_parent (klass);

	gobject_class->constructor = gck_secret_search_constructor;
	gobject_class->dispose = gck_secret_search_dispose;
	gobject_class->finalize = gck_secret_search_finalize;
	gobject_class->set_property = gck_secret_search_set_property;
	gobject_class->get_property = gck_secret_search_get_property;

	gck_class->get_attribute = gck_secret_search_get_attribute;

	g_object_class_install_property (gobject_class, PROP_COLLECTION_ID,
	           g_param_spec_string ("collection-id", "Collection ID", "Item's Collection's Identifier",
	                                NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_FIELDS,
	           g_param_spec_boxed ("fields", "Fields", "Item's fields",
	                               GCK_BOXED_SECRET_FIELDS, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GckFactory*
gck_secret_search_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_G_SEARCH;
	static CK_BBOOL token = CK_FALSE;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
	};

	static GckFactory factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_search
	};

	return &factory;
}

GHashTable*
gck_secret_search_get_fields (GckSecretSearch *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_SEARCH (self), NULL);
	return self->fields;
}

const gchar*
gck_secret_search_get_collection_id (GckSecretSearch *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_SEARCH (self), NULL);
	return self->collection_id;
}
