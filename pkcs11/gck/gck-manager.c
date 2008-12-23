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
	GHashTable *object_by_handle;
};

G_DEFINE_TYPE(GckManager, gck_manager, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * HELPERS
 */

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
		handle = (gck_util_next_handle () & GCK_OBJECT_HANDLE_MASK);
		if (self->pv->for_token)
			handle |= GCK_OBJECT_IS_PERMANENT;
		gck_object_set_handle (object, handle);
	}
	
	/* 
	 * Mapping of objects by PKCS#11 'handle', we don't ref the
	 * objects or anything. They're expected to unregister 
	 * upon finalizing.   
	 */
	g_assert (g_hash_table_lookup (self->pv->object_by_handle, &handle) == NULL); 
	g_hash_table_replace (self->pv->object_by_handle, gck_util_ulong_alloc (handle), object);
	
	/* Note objects is being managed */
	self->pv->objects = g_list_prepend (self->pv->objects, object);
	g_object_set (object, "manager", self, NULL);
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
	
	/* Mapping of objects by PKCS#11 'handle' */	
	g_assert (g_hash_table_lookup (self->pv->object_by_handle, &handle) == object); 
	g_hash_table_remove (self->pv->object_by_handle, &handle);
	
	/* Release object management */		
	self->pv->objects = g_list_remove (self->pv->objects, object);
	g_object_set (object, "manager", NULL, NULL);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gck_manager_init (GckManager *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE(self, GCK_TYPE_MANAGER, GckManagerPrivate);
	self->pv->object_by_handle = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal, 
	                                                    gck_util_ulong_free, NULL);
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
 	g_return_if_fail (g_hash_table_size (self->pv->object_by_handle) == 0);

	G_OBJECT_CLASS (gck_manager_parent_class)->dispose (obj);
}

static void
gck_manager_finalize (GObject *obj)
{
	GckManager *self = GCK_MANAGER (obj);
 	
	g_hash_table_destroy (self->pv->object_by_handle);
	g_assert (!self->pv->objects);

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
gck_manager_lookup_handle (GckManager *self, CK_OBJECT_HANDLE handle)
{
	g_return_val_if_fail (GCK_IS_MANAGER (self), NULL);
	g_return_val_if_fail (handle != 0, NULL);
	
	return (GckObject*)g_hash_table_lookup (self->pv->object_by_handle, &handle);
}

CK_RV
gck_manager_find_handles (GckManager *self, gboolean also_private, 
                          CK_ATTRIBUTE_PTR template, CK_ULONG count, GArray *found)
{
	CK_OBJECT_HANDLE handle;
	GckObject *object;
	gboolean is_private;
	GList *l;
	
	g_return_val_if_fail (GCK_IS_MANAGER (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (template || !count, CKR_GENERAL_ERROR);
	g_return_val_if_fail (found, CKR_GENERAL_ERROR);
	
	for (l = self->pv->objects; l; l = g_list_next (l)) {
		object = GCK_OBJECT (l->data);
		
		/* Exclude private objects if required */
		if (!also_private) {
			if (gck_object_get_attribute_boolean (object, CKA_PRIVATE, &is_private)) {
				if (is_private)
					continue;
			}
		}
		
		/* Match all the other attributes */
		if (gck_object_match_all (object, template, count)) {
			handle = gck_object_get_handle (object);
			g_return_val_if_fail (handle != 0, CKR_GENERAL_ERROR);
			g_array_append_val (found, handle);
		}
	}
	
	return CKR_OK;
	
}

#if 0
GList*
gck_manager_findv (GckManager *self, GType gtype, ...)
{
	CK_ATTRIBUTE attr;
	GArray *attrs = NULL;
	va_list va;
	CK_ULONG uval, spacer;
	CK_BBOOL bval;
	CK_VOID_PTR value;
	GList *ret = NULL;
	
	va_start (va, gtype);
	
	for (;;) {
		memset (&attr, 0, sizeof (attr));
		
		attr.type = va_arg (va, CK_ATTRIBUTE_TYPE);
		if (!attr.type) {
			
			/* 
			 * We keep this in a lower scope that our alloca 
			 * allocations, just in case some compiler gets the 
			 * bright idea (like GNU C in some cases) that it'll
			 * cleanup at variable scope rather than function scope.
			 */
			 
			ret = gck_manager_find (self, gtype, attrs);
			break;
		}	
		
		switch (gck_attribute_data_type (attr.type)) {
		case GCK_DATA_ULONG:
			uval = va_arg (va, CK_ULONG);
			gck_attribute_set_ulong (&attr, uval);
			spacer = va_arg (va, CK_ULONG);
			break;
		
		case GCK_DATA_BOOL:
			bval = va_arg (va, int) ? CK_TRUE : CK_FALSE;
			gck_attribute_set_boolean (&attr, bval);
			spacer = va_arg (va, CK_ULONG);
			break;
		
		case GCK_DATA_BYTES:
			value = va_arg (va, CK_VOID_PTR);
			uval = va_arg (va, CK_ULONG);
			gck_attribute_set_data (&attr, value, uval);
			break;

		default:
			g_warning ("unsupported type of data for attribute type: %d", (int)attr.type);
			return NULL;	
		};
		
		if (!attrs)
			attrs = gck_attributes_new ();
		g_array_append_val (attrs, attr);
	}

	va_end (va);
	
	gck_attributes_free (attrs);
	return ret;
}

GList*
gck_manager_find (GckManager *self, GType gtype, GArray *attrs)
{
	CK_OBJECT_CLASS *ocls = NULL;
	GckObject *object;
	gboolean do_refresh = TRUE;
	GList *l, *objects = NULL;
	
	g_return_val_if_fail (GCK_IS_MANAGER (self), NULL);

	/* Figure out the class of objects we're loading */
	if (attrs)
		ocls = (CK_OBJECT_CLASS*)gck_attributes_find (attrs, CKA_CLASS);
	if (ocls) {
		switch (*ocls) {
		/* TODO: Add here classes for which we don't want to refresh */
		default:
			break;
		}
	}
	
	if (gtype) {
		switch (gtype) {
		/* TODO: Add here classes for which we don't want to refresh */
		default:
			break;
		}
	}

	if (do_refresh) 
		gck_storage_refresh_all ();

	/* TODO: We may want to only go through objects of CKA_CLASS */
	for (l = self->objects; l; l = g_list_next (l)) {
		object = GCK_OBJECT (l->data);
		if (gtype && !G_TYPE_CHECK_INSTANCE_TYPE (l->data, gtype))
			continue;
		if (!attrs || gck_object_match (object, attrs))
			objects = g_list_prepend (objects, object);
	}
	
	return objects;
}

GckObject*
gck_manager_find_by_id (GckManager *self, GType gtype, gkrconstid id)
{
	CK_ATTRIBUTE attr;
	GckObject *object;
	gsize len;
	GList *l;
	
	g_return_val_if_fail (id, NULL);
	g_return_val_if_fail (GCK_IS_MANAGER (self), NULL);

	attr.pValue = (CK_VOID_PTR)gkr_id_get_raw (id, &len);
	attr.ulValueLen = len;
	attr.type = CKA_ID; 

	/* TODO: This needs to be done more efficiently */
	for (l = self->objects; l; l = g_list_next (l)) {
		object = GCK_OBJECT (l->data);
		if (gtype && !G_TYPE_CHECK_INSTANCE_TYPE (l->data, gtype))
			continue;
		if (gck_object_match_one (object, &attr))
			return object;
	}

	return NULL;	
}

GckObject*
gck_manager_find_by_digest (GckManager *self, gkrconstid digest)
{
	GckManagerPrivate *pv;
	GckObject *object;
	
	g_return_val_if_fail (digest, NULL);
	g_return_val_if_fail (GCK_IS_MANAGER (self), NULL);
	pv = GCK_MANAGER_GET_PRIVATE (self);

	object = GCK_OBJECT (g_hash_table_lookup (pv->object_by_digest, digest));
	return object;
}

#endif 
