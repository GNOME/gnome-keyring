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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkm-secret-collection.h"
#include "gkm-secret-fields.h"
#include "gkm-secret-item.h"
#include "gkm-secret-search.h"

#include "gkm/gkm-attributes.h"
#include "gkm/gkm-manager.h"
#include "gkm/gkm-module.h"
#include "gkm/gkm-session.h"
#include "gkm/gkm-transaction.h"
#include "gkm/gkm-util.h"

#include "pkcs11i.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_COLLECTION_ID,
	PROP_FIELDS,
	PROP_SCHEMA_NAME
};

struct _GkmSecretSearch {
	GkmObject parent;
	gchar *collection_id;
	GHashTable *fields;
	gchar *schema_name;
	GList *managers;
	GHashTable *objects;
};

G_DEFINE_TYPE (GkmSecretSearch, gkm_secret_search, GKM_TYPE_OBJECT);

static gboolean
match_object_against_criteria (GkmSecretSearch *self, GkmObject *object)
{
	GkmSecretCollection *collection;
	GkmSecretItem *item;
	GHashTable *fields;
	const gchar *identifier;
	const gchar *schema;

	if (!GKM_IS_SECRET_ITEM (object))
		return FALSE;

	item = GKM_SECRET_ITEM (object);

	/* Collection should match unless any collection allowed */
	if (self->collection_id) {
		collection = gkm_secret_item_get_collection (item);
		g_return_val_if_fail (collection, FALSE);
		identifier = gkm_secret_object_get_identifier (GKM_SECRET_OBJECT (collection));
		g_return_val_if_fail (identifier, FALSE);
		if (!g_str_equal (identifier, self->collection_id))
			return FALSE;
	}

	fields = gkm_secret_item_get_fields (item);

	/* Match the schema, if we have one */
	if (self->schema_name) {
		schema = gkm_secret_item_get_schema (item);

		/* Does the item has a schema set from the item type? */
		if (schema != NULL) {
			if (!g_str_equal (schema, self->schema_name))
				return FALSE;

		/* See if the item has a schema set in the attributes */
		} else {
			if (!gkm_secret_fields_match_one (fields, GKM_SECRET_FIELD_SCHEMA, self->schema_name))
				return FALSE;
		}
	}

	/* Fields should match using our special algorithm */
	return gkm_secret_fields_match (fields, self->fields);
}

static void
on_manager_added_object (GkmManager *manager, GkmObject *object, gpointer user_data)
{
	GkmSecretSearch *self = user_data;

	g_return_if_fail (GKM_IS_SECRET_SEARCH (self));

	g_return_if_fail (g_hash_table_lookup (self->objects, object) == NULL);

	if (match_object_against_criteria (self, object)) {
		g_hash_table_replace (self->objects, g_object_ref (object), "unused");
		gkm_object_notify_attribute (GKM_OBJECT (self), CKA_G_MATCHED);
	}
}

static void
on_manager_removed_object (GkmManager *manager, GkmObject *object, gpointer user_data)
{
	GkmSecretSearch *self = user_data;

	g_return_if_fail (GKM_IS_SECRET_SEARCH (self));

	if (g_hash_table_remove (self->objects, object))
		gkm_object_notify_attribute (GKM_OBJECT (self), CKA_G_MATCHED);
}

static void
on_manager_changed_object (GkmManager *manager, GkmObject *object,
                           CK_ATTRIBUTE_TYPE type, gpointer user_data)
{
	GkmSecretSearch *self = user_data;
	CK_OBJECT_HANDLE handle;

	if (type != CKA_G_FIELDS)
		return;

	g_return_if_fail (GKM_IS_SECRET_SEARCH (self));

	handle = gkm_object_get_handle (object);
	g_return_if_fail (handle);

	/* Should we have this object? */
	if (match_object_against_criteria (self, object)) {
		if (g_hash_table_lookup (self->objects, object) == NULL) {
			g_hash_table_replace (self->objects, g_object_ref (object), "unused");
			gkm_object_notify_attribute (GKM_OBJECT (self), CKA_G_MATCHED);
		}

	/* Should we not have this object? */
	} else {
		if (g_hash_table_remove (self->objects, object))
			gkm_object_notify_attribute (GKM_OBJECT (self), CKA_G_MATCHED);
	}
}

static void
on_manager_gone_away (gpointer user_data, GObject *where_the_object_was)
{
	GkmSecretSearch *self = GKM_SECRET_SEARCH (user_data);
	GList *l;

	g_return_if_fail (self);

	l = g_list_find (self->managers, where_the_object_was);
	g_return_if_fail (l != NULL);
	self->managers = g_list_delete_link (self->managers, l);
}

static void
populate_search_from_manager (GkmSecretSearch *self, GkmSession *session, GkmManager *manager)
{
	GList *objects, *o;

	self->managers = g_list_append (self->managers, manager);

	/* Add in all the objects */
	objects = gkm_manager_find_by_class (manager, session, CKO_SECRET_KEY);
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

static GkmObject*
factory_create_search (GkmSession *session, GkmTransaction *transaction,
                       CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	GkmManager *s_manager, *m_manager;
	GkmSecretSearch *search;
	gchar *identifier = NULL;
	CK_ATTRIBUTE *attr;
	GHashTable *fields;
	gchar *schema_name;
	GkmModule *module;
	CK_RV rv;

	g_return_val_if_fail (GKM_IS_TRANSACTION (transaction), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);

	/* Find the fields being requested */
	attr = gkm_attributes_find (attrs, n_attrs, CKA_G_FIELDS);
	if (attr == NULL) {
		gkm_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
		return NULL;
	}

	/* Parse the fields, into our internal representation */
	rv = gkm_secret_fields_parse (attr, &fields, &schema_name);
	gkm_attribute_consume (attr);
	if (rv != CKR_OK) {
		gkm_transaction_fail (transaction, rv);
		return NULL;
	}

	/* Remove the schema name from the search fields, handle that separately */
	g_hash_table_remove (fields, GKM_SECRET_FIELD_SCHEMA);

	s_manager = gkm_session_get_manager (session);
	module = gkm_session_get_module (session);
	m_manager = gkm_module_get_manager (module);

	/* See if a collection attribute was specified, not present means all collections */
	attr = gkm_attributes_find (attrs, n_attrs, CKA_G_COLLECTION);
	if (attr) {
		rv = gkm_attribute_get_string (attr, &identifier);
		if (rv != CKR_OK) {
			g_free (schema_name);
			g_hash_table_unref (fields);
			gkm_transaction_fail (transaction, rv);
			return NULL;
		}
	}

	search = g_object_new (GKM_TYPE_SECRET_SEARCH,
	                       "module", module,
	                       "manager", s_manager,
	                       "fields", fields,
	                       "schema-name", schema_name,
	                       "collection-id", identifier,
	                       NULL);
	g_free (identifier);

	/* Load any new items or collections */
	gkm_module_refresh_token (module);

	populate_search_from_manager (search, session, s_manager);
	populate_search_from_manager (search, session, m_manager);

	gkm_session_complete_object_creation (session, transaction, GKM_OBJECT (search),
	                                      TRUE, attrs, n_attrs);

	g_hash_table_unref (fields);
	g_free (schema_name);

	return GKM_OBJECT (search);
}

static gint
on_matched_sort_modified (gconstpointer a,
                          gconstpointer b)
{
	glong modified_a;
	glong modified_b;

	/* Sorting in reverse order */

	modified_a = gkm_secret_object_get_modified (GKM_SECRET_OBJECT (a));
	modified_b = gkm_secret_object_get_modified (GKM_SECRET_OBJECT (b));

	if (modified_a < modified_b)
		return 1;
	if (modified_a > modified_b)
		return -1;

	return 0;
}

static CK_RV
attribute_set_handles (GHashTable *objects,
                       CK_ATTRIBUTE_PTR attr)
{
	GList *list, *l;
	GArray *array;
	gulong handle;
	CK_RV rv;

	g_assert (objects);
	g_assert (attr);

	/* Want the length */
	if (!attr->pValue) {
		attr->ulValueLen = sizeof (CK_OBJECT_HANDLE) * g_hash_table_size (objects);
		return CKR_OK;
	}

	/* Get the actual values */
	list = g_list_sort (g_hash_table_get_keys (objects), on_matched_sort_modified);
	array = g_array_new (FALSE, TRUE, sizeof (CK_OBJECT_HANDLE));

	for (l = list; l != NULL; l = g_list_next (l)) {
		handle = gkm_object_get_handle (l->data);
		g_array_append_val (array, handle);
	}

	rv = gkm_attribute_set_data (attr, array->data, array->len * sizeof (CK_OBJECT_HANDLE));
	g_array_free (array, TRUE);
	g_list_free (list);

	return rv;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static CK_RV
gkm_secret_search_get_attribute (GkmObject *base, GkmSession *session, CK_ATTRIBUTE_PTR attr)
{
	GkmSecretSearch *self = GKM_SECRET_SEARCH (base);

	switch (attr->type) {
	case CKA_CLASS:
		return gkm_attribute_set_ulong (attr, CKO_G_SEARCH);
	case CKA_MODIFIABLE:
		return gkm_attribute_set_bool (attr, CK_TRUE); /* TODO: This is needed for deleting? */
	case CKA_G_COLLECTION:
		if (!self->collection_id)
			return gkm_attribute_set_empty (attr);
		return gkm_attribute_set_string (attr, self->collection_id);
	case CKA_G_FIELDS:
		return gkm_secret_fields_serialize (attr, self->fields, self->schema_name);
	case CKA_G_MATCHED:
		return attribute_set_handles (self->objects, attr);
	}

	return GKM_OBJECT_CLASS (gkm_secret_search_parent_class)->get_attribute (base, session, attr);
}


static void
gkm_secret_search_init (GkmSecretSearch *self)
{
	self->objects = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);
}

static GObject*
gkm_secret_search_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkmSecretSearch *self = GKM_SECRET_SEARCH (G_OBJECT_CLASS (gkm_secret_search_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);

	g_return_val_if_fail (self->fields, NULL);

	return G_OBJECT (self);
}

static void
gkm_secret_search_set_property (GObject *obj, guint prop_id, const GValue *value,
                                    GParamSpec *pspec)
{
	GkmSecretSearch *self = GKM_SECRET_SEARCH (obj);
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
	case PROP_SCHEMA_NAME:
		g_return_if_fail (self->schema_name == NULL);
		self->schema_name = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkm_secret_search_get_property (GObject *obj, guint prop_id, GValue *value,
                                    GParamSpec *pspec)
{
	GkmSecretSearch *self = GKM_SECRET_SEARCH (obj);
	switch (prop_id) {
	case PROP_COLLECTION_ID:
		g_value_set_string (value, self->collection_id);
		break;
	case PROP_FIELDS:
		g_return_if_fail (self->fields);
		g_value_set_boxed (value, gkm_secret_search_get_fields (self));
		break;
	case PROP_SCHEMA_NAME:
		g_value_set_string (value, self->schema_name);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkm_secret_search_dispose (GObject *obj)
{
	GkmSecretSearch *self = GKM_SECRET_SEARCH (obj);
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

	g_hash_table_remove_all (self->objects);

	G_OBJECT_CLASS (gkm_secret_search_parent_class)->dispose (obj);
}

static void
gkm_secret_search_finalize (GObject *obj)
{
	GkmSecretSearch *self = GKM_SECRET_SEARCH (obj);

	g_assert (!self->managers);

	g_free (self->schema_name);
	self->schema_name = NULL;

	if (self->fields)
		g_hash_table_destroy (self->fields);
	self->fields = NULL;

	g_hash_table_destroy (self->objects);

	G_OBJECT_CLASS (gkm_secret_search_parent_class)->finalize (obj);
}

static void
gkm_secret_search_class_init (GkmSecretSearchClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkmObjectClass *gkm_class = GKM_OBJECT_CLASS (klass);

	gkm_secret_search_parent_class = g_type_class_peek_parent (klass);

	gobject_class->constructor = gkm_secret_search_constructor;
	gobject_class->dispose = gkm_secret_search_dispose;
	gobject_class->finalize = gkm_secret_search_finalize;
	gobject_class->set_property = gkm_secret_search_set_property;
	gobject_class->get_property = gkm_secret_search_get_property;

	gkm_class->get_attribute = gkm_secret_search_get_attribute;

	g_object_class_install_property (gobject_class, PROP_COLLECTION_ID,
	           g_param_spec_string ("collection-id", "Collection ID", "Item's Collection's Identifier",
	                                NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_FIELDS,
	           g_param_spec_boxed ("fields", "Fields", "Item's fields",
	                               GKM_BOXED_SECRET_FIELDS, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_SCHEMA_NAME,
	           g_param_spec_string ("schema_name", "Schema Name", "Schema name to match",
	                                NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkmFactory*
gkm_secret_search_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_G_SEARCH;
	static CK_BBOOL token = CK_FALSE;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
	};

	static GkmFactory factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_search
	};

	return &factory;
}

GHashTable*
gkm_secret_search_get_fields (GkmSecretSearch *self)
{
	g_return_val_if_fail (GKM_IS_SECRET_SEARCH (self), NULL);
	return self->fields;
}

const gchar *
gkm_secret_search_get_schema_name (GkmSecretSearch *self)
{
	g_return_val_if_fail (GKM_IS_SECRET_SEARCH (self), NULL);
	return self->schema_name;
}

const gchar*
gkm_secret_search_get_collection_id (GkmSecretSearch *self)
{
	g_return_val_if_fail (GKM_IS_SECRET_SEARCH (self), NULL);
	return self->collection_id;
}
