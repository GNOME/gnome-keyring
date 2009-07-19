/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *  
 * You should have received a copy of the GNU Lesser General 
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "gck-attributes.h"
#include "gck-manager.h"
#include "gck-util.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <stdarg.h>

enum {
	PROP_0,
	PROP_FOR_TOKEN
};

struct _GckManagerPrivate {
	gboolean for_token;
	GList *objects;
	GHashTable *index_by_attribute;
	GHashTable *index_by_property;
};

typedef struct _Index {
	gboolean unique;
	CK_ATTRIBUTE_TYPE attribute_type;
	gchar *property_name;
	GHashTable *values;
	GHashTable *objects;
} Index;

typedef struct _Finder {
	GckManager *manager;
	void (*accumulator) (struct _Finder *ctx, GckObject *found);
	gpointer results;
	CK_ATTRIBUTE_PTR attrs;
	CK_ULONG n_attrs;
} Finder;

G_DEFINE_TYPE(GckManager, gck_manager, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void
attribute_free (gpointer data)
{
	CK_ATTRIBUTE_PTR attr = data;
	if (attr) {
		g_free (attr->pValue);
		g_slice_free (CK_ATTRIBUTE, attr);
	}
}

static Index*
index_new (gboolean unique)
{
	Index *index = g_slice_new0 (Index);
	index->unique = unique;
	
	if (unique)
		index->values = g_hash_table_new_full (gck_attribute_hash, gck_attribute_equal, attribute_free, NULL);
	else
		index->values = g_hash_table_new_full (gck_attribute_hash, gck_attribute_equal, attribute_free,
		                                       (GDestroyNotify)g_hash_table_destroy);
	
	index->objects = g_hash_table_new (g_direct_hash, g_direct_equal);
	
	return index;
}

static void
index_free (gpointer data)
{
	Index *index = data;
	if (index) {
		g_hash_table_destroy (index->values);
		g_hash_table_destroy (index->objects);
		g_free (index->property_name);
		g_slice_free (Index, index);
	}
}

static gboolean
read_attribute(GckObject *object, CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE_PTR *result)
{
	CK_ATTRIBUTE attr;
	CK_RV rv;
	
	g_assert (GCK_IS_OBJECT (object));
	g_assert (result);
	
	*result = NULL;
	
	attr.type = type;
	attr.pValue = NULL;
	attr.ulValueLen = 0;
		
	/* Figure out memory length */
	rv = gck_object_get_attribute (object, NULL, &attr);
	
	/* Not an error, just not present */
	if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
		*result = NULL;
		return TRUE;
	}
		
	if (rv != CKR_OK) {
		g_warning ("accessing indexed attribute failed");
		return FALSE;
	}
		
	/* Allocate memory length */
	if (attr.ulValueLen) {
		attr.pValue = g_malloc0 (attr.ulValueLen);
		rv = gck_object_get_attribute (object, NULL, &attr);
		if (rv != CKR_OK) {
			g_warning ("accessing indexed attribute failed");
			g_free (attr.pValue);
			return FALSE;
		}
	}

	*result = g_slice_new (CK_ATTRIBUTE);
	memcpy (*result, &attr, sizeof (CK_ATTRIBUTE));
	return TRUE;
}

static gboolean
read_value (GckObject *object, const gchar *property, CK_ATTRIBUTE_PTR *result)
{
	CK_ATTRIBUTE attr;
	GParamSpec *spec;
	GValue value = { 0, };
	CK_ULONG number;
	CK_BBOOL boolean;
	
	g_assert (GCK_IS_OBJECT (object));
	g_assert (property);
	g_assert (result);
	
	spec = g_object_class_find_property (G_OBJECT_GET_CLASS (object), 
	                                     property);
		
	/* Not an error, just no such property on object */ 
	if (spec == NULL) {
		*result = NULL;
		return TRUE;
	}
	
	g_value_init(&value, spec->value_type);
	g_object_get_property (G_OBJECT (object), property, &value);

	attr.type = (CK_ATTRIBUTE_TYPE)-1;
	attr.pValue = NULL;
	attr.ulValueLen = 0;

	/* We only support specific types of values */
	switch (spec->value_type)
	{
	case G_TYPE_STRING:
		attr.pValue = g_value_dup_string (&value);
		attr.ulValueLen = attr.pValue ? strlen (attr.pValue) : 0;
		break;
	case G_TYPE_INT:
		number = g_value_get_int (&value);
		attr.ulValueLen = sizeof (number);
		attr.pValue = g_memdup (&number, attr.ulValueLen);
		break;
	case G_TYPE_UINT:
		number = g_value_get_uint (&value);
		attr.ulValueLen = sizeof (number);
		attr.pValue = g_memdup (&number, attr.ulValueLen);
		break;
	case G_TYPE_LONG:
		number = g_value_get_long (&value);
		attr.ulValueLen = sizeof (number);
		attr.pValue = g_memdup (&number, attr.ulValueLen);
		break;
	case G_TYPE_ULONG:
		number = g_value_get_ulong (&value);
		attr.ulValueLen = sizeof (number);
		attr.pValue = g_memdup (&number, attr.ulValueLen);
		break;
	case G_TYPE_BOOLEAN:
		boolean = g_value_get_boolean (&value) ? CK_TRUE : CK_FALSE;
		attr.ulValueLen = sizeof (boolean);
		attr.pValue = g_memdup (&boolean, attr.ulValueLen);
		break;
	default:
		g_warning ("couldn't convert value from type %s into attribute", 
		           g_type_name (spec->value_type));
		g_value_unset (&value);
		return FALSE;
	};
	
	if (attr.pValue) {
		*result = g_slice_new (CK_ATTRIBUTE);
		memcpy (*result, &attr, sizeof (CK_ATTRIBUTE));
	} else {
		*result = NULL;
	}
	
	g_value_unset (&value);
	return TRUE;
}

static void
index_remove_attr (Index *index, gpointer object, CK_ATTRIBUTE_PTR attr)
{
	GHashTable *objects;

	g_assert (index);
	g_assert (object);
	g_assert (attr);
	
	if (index->unique) {
		if (!g_hash_table_remove (index->values, attr))
			g_assert_not_reached ();
	} else {
		objects = g_hash_table_lookup (index->values, attr);
		g_assert (objects);
		if (!g_hash_table_remove (objects, object))
			g_assert_not_reached ();
		if (g_hash_table_size (objects) == 0)
			if (!g_hash_table_remove (index->values, attr))
				g_assert_not_reached ();
	}
}

static void
index_remove (Index *index, gpointer object)
{
	CK_ATTRIBUTE_PTR attr;

	/* 
	 * We don't actually access the object. We want to be able to 
	 * handle objects that have been destroyed as well.
	 */
	
	g_assert (object);
	g_assert (index);
	
	attr = g_hash_table_lookup (index->objects, object);
	
	/* Object not in this index */
	if (attr == NULL) 
		return;

	/* Remove the actual value */
	index_remove_attr (index, object, attr);
	
	if (!g_hash_table_remove (index->objects, object))
		g_assert_not_reached ();
}

static void
index_update (Index *index, GckObject *object)
{
	CK_ATTRIBUTE_PTR attr = NULL;
	CK_ATTRIBUTE_PTR prev;
	GHashTable *objects;
	gboolean ret;

	g_assert (GCK_IS_OBJECT (object));
	g_assert (index);
	
	/* Get the value for this index */
	if (index->property_name)
		ret = read_value (object, index->property_name, &attr);
	else 
		ret = read_attribute (object, index->attribute_type, &attr);
	g_return_if_fail (ret);
	
	/* No such attribute/property on object */
	if (attr == NULL)
		return;

	prev = g_hash_table_lookup (index->objects, object);
	if (prev != NULL) {
		
		/* The previous one is same, ignore */
		if (gck_attribute_equal (prev, attr)) {
			attribute_free (attr);
			return;
		}
		
		/* Remove the previous one */
		index_remove_attr (index, object, prev);
	} 

	/* In this case values is a direct pointer to the object */
	if (index->unique) {
		g_return_if_fail (g_hash_table_lookup (index->values, attr) == NULL);
		g_hash_table_replace (index->values, attr, object);
		g_hash_table_replace (index->objects, object, attr);
		
	/* In this case values is a pointer to a hash set of objects */
	} else {
		gpointer key, value;
		if (g_hash_table_lookup_extended (index->values, attr, &key, &value)) {
			attribute_free (attr);
			objects = value;
			attr = key;
		} else {
			objects = g_hash_table_new (g_direct_hash, g_direct_equal);
			g_hash_table_insert (index->values, attr, objects);
		}

		g_hash_table_insert (objects, object, object);
		g_hash_table_replace (index->objects, object, attr);
	}
}

static gboolean
index_contains (Index *index, GckObject *object, CK_ATTRIBUTE_PTR attr)
{
	GHashTable *objects;
	
	g_assert (index);
	g_assert (GCK_IS_OBJECT (object));
	g_assert (attr);
	
	if (index->unique) {
		return (g_hash_table_lookup (index->values, attr) == object);
	} else {
		objects = g_hash_table_lookup (index->values, attr);
		return (objects && g_hash_table_lookup (objects, object) == object);
	}
}

static void
index_object_each (gpointer key, gpointer value, gpointer user_data)
{
	index_update (value, user_data);
}

static void
index_remove_each (gpointer key, gpointer value, gpointer user_data)
{
	index_remove (value, user_data);
}

static void
notify_attribute (GckObject *object, CK_ATTRIBUTE_TYPE attr_type, GckManager *self)
{
	Index *index;
	
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_return_if_fail (GCK_IS_MANAGER (self));
	g_return_if_fail (gck_object_get_manager (object) == self);
	
	index = g_hash_table_lookup (self->pv->index_by_attribute, &attr_type);
	if (index != NULL) 
		index_update (index, object);
}

static void
notify_property (GckObject *object, GParamSpec *spec, GckManager *self)
{
	Index *index;
	
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_return_if_fail (GCK_IS_MANAGER (self));
	g_return_if_fail (gck_object_get_manager (object) == self);
	
	index = g_hash_table_lookup (self->pv->index_by_property, spec->name);
	if (index != NULL)
		index_update (index, object);
}

static void
add_object (GckManager *self, GckObject *object)
{
	CK_OBJECT_HANDLE handle;
	
	g_assert (GCK_IS_MANAGER (self));
	g_assert (GCK_IS_OBJECT (object));
	g_assert (gck_object_get_manager (object) == NULL);
	
	handle = gck_object_get_handle (object);
	if (!handle) {
		/* Make a new handle */
		handle = gck_util_next_handle ();
		gck_object_set_handle (object, handle);
	}

	/* 
	 * We don't ref the objects or anything. They're expected to 
	 * unregister upon dispose.   
	 */
	
	/* Note objects is being managed */
	self->pv->objects = g_list_prepend (self->pv->objects, object);
	g_object_set (object, "manager", self, NULL);
	
	/* Now index the object properly */
	g_hash_table_foreach (self->pv->index_by_attribute, index_object_each, object);
	g_hash_table_foreach (self->pv->index_by_property, index_object_each, object);
	g_signal_connect (object, "notify-attribute", G_CALLBACK (notify_attribute), self);
	g_signal_connect (object, "notify", G_CALLBACK (notify_property), self);
}

static void
remove_object (GckManager *self, GckObject *object)
{
	CK_OBJECT_HANDLE handle;
	
	g_assert (GCK_IS_MANAGER (self));
	g_assert (GCK_IS_OBJECT (object));
	g_assert (gck_object_get_manager (object) == self);
	
	handle = gck_object_get_handle (object);
	g_assert (handle);
	
	/* Remove from all indexes */
	g_signal_handlers_disconnect_by_func (object, G_CALLBACK (notify_attribute), self);
	g_signal_handlers_disconnect_by_func (object, G_CALLBACK (notify_property), self);
	g_hash_table_foreach (self->pv->index_by_attribute, index_remove_each, object);
	g_hash_table_foreach (self->pv->index_by_property, index_remove_each, object);
	
	/* Release object management */		
	self->pv->objects = g_list_remove (self->pv->objects, object);
	g_object_set (object, "manager", NULL, NULL);
}

static void
find_each_object (gpointer unused, gpointer object, gpointer user_data)
{
	Finder *finder = user_data;
	CK_ATTRIBUTE_PTR attr;
	Index *index;
	CK_ULONG i;
	
	g_assert (finder);
	g_assert (GCK_IS_MANAGER (finder->manager));
	
	/* Match the object against all the other attributes */
	for (i = 0; i < finder->n_attrs; ++i) {
		attr = &(finder->attrs[i]);
		index = g_hash_table_lookup (finder->manager->pv->index_by_attribute, &attr->type);
		if (index) {
			if (!index_contains (index, object, attr))
				return;
		} else {
			if (!gck_object_match (object, NULL, attr))
				return;
		}
	}
	
	(finder->accumulator) (finder, object);
}

static void
find_for_attributes (Finder *finder)
{
	GHashTable *objects;
	CK_ATTRIBUTE_PTR first;
	GckObject *object;
	Index *index;
	GList *l;
	
	g_assert (finder);
	g_assert (GCK_IS_MANAGER (finder->manager));
	g_assert (!finder->n_attrs || finder->attrs);
	
	/* All the objects */
	if (!finder->n_attrs) {
		for (l = finder->manager->pv->objects; l; l = g_list_next (l)) 
			(finder->accumulator) (finder, l->data);
		return;
	}

	first = finder->attrs;
	finder->attrs = finder->attrs + 1;
	finder->n_attrs = finder->n_attrs - 1;

	index = g_hash_table_lookup (finder->manager->pv->index_by_attribute, 
	                             &first->type);

	
	/* No indexes, have to manually match */
	if (!index) {
		
		for (l = finder->manager->pv->objects; l; l = g_list_next (l)) {
			if (gck_object_match (l->data, NULL, first))
				find_each_object (NULL, l->data, finder);
		}
		
		return;
	}
	
	/* Yay, an index */
	if (index->unique) {
		object = g_hash_table_lookup (index->values, first);
		if (object)
			find_each_object (NULL, object, finder);
	} else {
		objects = g_hash_table_lookup (index->values, first);
		if (objects)
			g_hash_table_foreach (objects, find_each_object, finder);
	}
}

static void
accumulate_list (Finder *finder, GckObject *object)
{
	finder->results = g_list_prepend (finder->results, object);
}

static void
accumulate_one (Finder *finder, GckObject *object)
{
	if (!finder->results)
		finder->results = object;
}

static void
accumulate_handles (Finder *finder, GckObject *object)
{
	CK_OBJECT_HANDLE handle = gck_object_get_handle (object);
	g_return_if_fail (handle);
	g_array_append_val (finder->results, handle);
}

static void
accumulate_public_handles (Finder *finder, GckObject *object)
{
	gboolean is_private;
	if (gck_object_get_attribute_boolean (object, NULL, CKA_PRIVATE, &is_private) && is_private)
		return;
	accumulate_handles (finder, object);
}

static void
values_to_list (gpointer key, gpointer value, gpointer user_data)
{
	GList** list = (GList**)user_data;
	*list = g_list_prepend (*list, value);
}

static GList*
find_all_for_property (GckManager *self, const gchar *property, CK_ATTRIBUTE_PTR attr)
{
	GckObject *object;
	GHashTable *objects;
	GList *results = NULL;
	Index *index;
	
	g_assert (GCK_IS_MANAGER (self));
	g_assert (property);
	g_assert (attr);
	
	index = g_hash_table_lookup (self->pv->index_by_property, property);
	g_return_val_if_fail (index, NULL);
	
	if (index->unique) {
		object = g_hash_table_lookup (index->values, attr);
		return object ? g_list_prepend (NULL, object) : NULL;
	} else {
		objects = g_hash_table_lookup (index->values, attr);
		if (!objects)
			return NULL;
		g_hash_table_foreach (objects, values_to_list, &results);
		return results;
	}	
}

static GckObject*
find_one_for_property (GckManager *self, const gchar *property, CK_ATTRIBUTE_PTR attr)
{
	GckObject *object;
	GHashTable *objects;
	GList *results = NULL;
	Index *index;
	
	g_assert (GCK_IS_MANAGER (self));
	g_assert (property);
	g_assert (attr);
	
	index = g_hash_table_lookup (self->pv->index_by_property, property);
	g_return_val_if_fail (index, NULL);
	
	if (index->unique) {
		return g_hash_table_lookup (index->values, attr);
	} else {
		objects = g_hash_table_lookup (index->values, attr);
		if (!objects)
			return NULL;
		g_hash_table_foreach (objects, values_to_list, &results);
		object = results ? results->data : NULL;
		g_list_free (results);
		return object;
	}	
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gck_manager_init (GckManager *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE(self, GCK_TYPE_MANAGER, GckManagerPrivate);
	self->pv->index_by_attribute = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal,
	                                                      gck_util_ulong_free, index_free);
	self->pv->index_by_property = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                                     g_free, index_free);
	gck_manager_add_property_index (self, "handle", TRUE);
	gck_manager_add_attribute_index (self, CKA_ID, FALSE);
	gck_manager_add_attribute_index (self, CKA_CLASS, FALSE);
}

static void
gck_manager_set_property (GObject *obj, guint prop_id, const GValue *value, 
                          GParamSpec *pspec)
{
	GckManager *self = GCK_MANAGER (obj);
	
	switch (prop_id) {
	case PROP_FOR_TOKEN:
		self->pv->for_token = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_manager_get_property (GObject *obj, guint prop_id, GValue *value, 
                          GParamSpec *pspec)
{
	GckManager *self = GCK_MANAGER (obj);
	
	switch (prop_id) {
	case PROP_FOR_TOKEN:
		g_value_set_boolean (value, gck_manager_get_for_token (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}


static void
gck_manager_dispose (GObject *obj)
{
	GckManager *self = GCK_MANAGER (obj);
 	GList *objects, *l;

	/* Unregister all objects */
	objects = g_list_copy (self->pv->objects);
	for (l = objects; l; l = g_list_next (l)) 
		gck_manager_unregister_object (self, GCK_OBJECT (l->data));
	g_list_free (objects);
	
	g_return_if_fail (self->pv->objects == NULL);

	G_OBJECT_CLASS (gck_manager_parent_class)->dispose (obj);
}

static void
gck_manager_finalize (GObject *obj)
{
	GckManager *self = GCK_MANAGER (obj);
 	
	g_assert (!self->pv->objects);
	g_hash_table_destroy (self->pv->index_by_attribute);
	g_hash_table_destroy (self->pv->index_by_property);

	G_OBJECT_CLASS (gck_manager_parent_class)->finalize (obj);
}

static void
gck_manager_class_init (GckManagerClass *klass)
{
	GObjectClass *gobject_class;
	gobject_class = (GObjectClass*)klass;

	gck_manager_parent_class = g_type_class_peek_parent (klass);
	gobject_class->dispose = gck_manager_dispose;
	gobject_class->get_property = gck_manager_get_property;
	gobject_class->set_property = gck_manager_set_property;
	gobject_class->finalize = gck_manager_finalize;

	g_type_class_add_private (gobject_class, sizeof (GckManagerPrivate));
	
	g_object_class_install_property (gobject_class, PROP_FOR_TOKEN,
	         g_param_spec_boolean ("for-token", "For Token", "Whether this manager is for token objects or not", 
	                               FALSE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
}

/* ------------------------------------------------------------------------
 * PUBLIC METHODS
 */

gboolean
gck_manager_get_for_token (GckManager *self)
{
	g_return_val_if_fail (GCK_IS_MANAGER (self), FALSE);
	return self->pv->for_token;
}

void
gck_manager_add_attribute_index (GckManager *self, CK_ATTRIBUTE_TYPE attr, gboolean unique)
{
	Index *index;
	GList *l;
	
	g_return_if_fail (GCK_IS_MANAGER (self));
	g_return_if_fail (!g_hash_table_lookup (self->pv->index_by_attribute, &attr));

	index = index_new (unique);
	index->attribute_type = attr;
	g_hash_table_replace (self->pv->index_by_attribute, gck_util_ulong_alloc (attr), index);
	
	for (l = self->pv->objects; l; l = g_list_next (l))
		index_update (index, l->data);
}

void
gck_manager_add_property_index (GckManager *self, const gchar *property, gboolean unique)
{
	Index *index;
	GList *l;
	
	g_return_if_fail (GCK_IS_MANAGER (self));
	g_return_if_fail (property);
	g_return_if_fail (!g_hash_table_lookup (self->pv->index_by_property, property));

	index = index_new (unique);
	index->property_name = g_strdup (property);
	g_hash_table_replace (self->pv->index_by_property, g_strdup (property), index);
	
	for (l = self->pv->objects; l; l = g_list_next (l))
		index_update (index, l->data);
}

void
gck_manager_register_object (GckManager *self, GckObject *object)
{
	g_return_if_fail (GCK_IS_MANAGER (self));
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_return_if_fail (gck_object_get_manager (object) == NULL);

	add_object (self, object);
}

void
gck_manager_unregister_object (GckManager *self, GckObject *object)
{
	g_return_if_fail (GCK_IS_MANAGER (self));
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_return_if_fail (gck_object_get_manager (object) == self);

	remove_object (self, object);
}

GckObject*
gck_manager_find_by_handle (GckManager *self, CK_OBJECT_HANDLE handle)
{
	g_return_val_if_fail (GCK_IS_MANAGER (self), NULL);
	g_return_val_if_fail (handle != 0, NULL);
	
	return gck_manager_find_one_by_number_property (self, "handle", handle);
}

GList*
gck_manager_find_by_number_property (GckManager *self, const gchar *property, gulong value)
{
	CK_ATTRIBUTE attr;
	CK_ULONG number = value;
	
	attr.type = (CK_ATTRIBUTE_TYPE)-1;
	attr.pValue = &number;
	attr.ulValueLen = sizeof (number);
	
	return find_all_for_property (self, property, &attr);	
}

GckObject*
gck_manager_find_one_by_number_property (GckManager *self, const gchar *property, gulong value)
{
	CK_ATTRIBUTE attr;
	CK_ULONG number = value;
	
	attr.type = (CK_ATTRIBUTE_TYPE)-1;
	attr.pValue = &number;
	attr.ulValueLen = sizeof (number);
	
	return find_one_for_property (self, property, &attr);
}

GList*
gck_manager_find_by_string_property (GckManager *self, const gchar *property, const gchar *value)
{
	CK_ATTRIBUTE attr;
	
	attr.type = (CK_ATTRIBUTE_TYPE)-1;
	attr.pValue = (void*)value;
	attr.ulValueLen = value ? strlen (value) : 0;
	
	return find_all_for_property (self, property, &attr);		
}

GckObject*
gck_manager_find_one_by_string_property (GckManager *self, const gchar *property, const gchar *value)
{
	CK_ATTRIBUTE attr;
	
	attr.type = (CK_ATTRIBUTE_TYPE)-1;
	attr.pValue = (void*)value;
	attr.ulValueLen = value ? strlen (value) : 0;
	
	return find_one_for_property (self, property, &attr);
}
                           
GckObject*
gck_manager_find_one_by_attributes (GckManager *self, CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	Finder finder;
	
	g_return_val_if_fail (GCK_IS_MANAGER (self), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);

	finder.accumulator = accumulate_one;
	finder.results = NULL;
	finder.manager = self;
	finder.attrs = attrs;
	finder.n_attrs = n_attrs;
	
	find_for_attributes (&finder);

	return finder.results;
}

GList*
gck_manager_find_by_attributes (GckManager *self, CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	Finder finder;
	
	g_return_val_if_fail (GCK_IS_MANAGER (self), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);

	finder.accumulator = accumulate_list;
	finder.results = NULL;
	finder.manager = self;
	finder.attrs = attrs;
	finder.n_attrs = n_attrs;
	
	find_for_attributes (&finder);

	return finder.results;
}

GckObject*
gck_manager_find_related (GckManager *self, CK_OBJECT_CLASS klass, GckObject *related_to)
{
	CK_ATTRIBUTE attrs[2];
	GckObject *object;
	guchar *id;
	gsize n_id;
	
	g_return_val_if_fail (GCK_IS_MANAGER (self), NULL);
	g_return_val_if_fail (GCK_IS_OBJECT (related_to), NULL);
	
	id = gck_object_get_attribute_data (related_to, NULL, CKA_ID, &n_id);
	if (id == NULL)
		return NULL;
	
	attrs[0].type = CKA_ID;
	attrs[0].pValue = id;
	attrs[0].ulValueLen = n_id;
	
	attrs[1].type = CKA_CLASS;
	attrs[1].pValue = &klass;
	attrs[1].ulValueLen = sizeof (klass);
	
	object = gck_manager_find_one_by_attributes (self, attrs, 2);
	g_free (id);
	
	return object;
}

CK_RV
gck_manager_find_handles (GckManager *self, gboolean also_private, 
                          CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, 
                          GArray *found)
{
	Finder finder;
	
	g_return_val_if_fail (GCK_IS_MANAGER (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (attrs || !n_attrs, CKR_GENERAL_ERROR);

	finder.accumulator = also_private ? accumulate_handles : accumulate_public_handles;
	finder.results = found;
	finder.manager = self;
	finder.attrs = attrs;
	finder.n_attrs = n_attrs;
	
	find_for_attributes (&finder);

	return CKR_OK;
}
