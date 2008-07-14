/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-object.c - A base class for PK objects

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-pk-cert.h"
#include "gkr-pk-import.h"
#include "gkr-pk-index.h"
#include "gkr-pk-manager.h"
#include "gkr-pk-object.h"
#include "gkr-pk-privkey.h"
#include "gkr-pk-pubkey.h"
#include "gkr-pk-session.h"
#include "gkr-pk-storage.h"
#include "gkr-pk-util.h"

#include "common/gkr-location.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"
#include "pkcs11/pkcs11n.h"

#include "pkix/gkr-pkix-types.h"

#include <glib/gi18n.h>

#include <string.h>

/* --------------------------------------------------------------------------------
 * DECLARATIONS
 */

enum {
	PROP_0,
	PROP_MANAGER,
	PROP_LOCATION,
	PROP_DIGEST,
	PROP_ORIG_LABEL,
	PROP_LABEL,
	PROP_STORAGE
};

enum {
	LOADED_LABEL = 0x0001,
	LOADED_USAGES = 0x0002,
};

typedef struct _GkrPkObjectPrivate GkrPkObjectPrivate;

struct _GkrPkObjectPrivate {
	GHashTable *attr_cache;
	gchar *label;
	gchar *orig_label;
	guint load_state;
	gboolean dummy_digest;
	
	gchar *data_path;
	gchar *data_section;
};

#define GKR_PK_OBJECT_GET_PRIVATE(o)  \
	(G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PK_OBJECT, GkrPkObjectPrivate))

static guint64 unique_counter = 0;

G_DEFINE_TYPE(GkrPkObject, gkr_pk_object, G_TYPE_OBJECT);

/* --------------------------------------------------------------------------------
 * HELPERS
 */
 
static CK_RV
lookup_attribute (GkrPkObject *object, CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE_PTR *attr)
{
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE (object);
	GkrPkObjectClass *klass;
	CK_ATTRIBUTE cattr;
	CK_RV ret = 0;

	*attr = g_hash_table_lookup (pv->attr_cache, GUINT_TO_POINTER (type));
	if(*attr)
		return CKR_OK;
		
	klass = GKR_PK_OBJECT_GET_CLASS (object);
	memset (&cattr, 0, sizeof (cattr));
	cattr.type = type;

	/* Ask derived class for attribute */
	if (!klass->get_attribute)
		g_return_val_if_reached (CKR_ATTRIBUTE_TYPE_INVALID);
	ret = (*klass->get_attribute) (object, &cattr);

	if (ret != CKR_OK) {
		/* Shouldn't be returning these */
		g_assert (ret != CKR_BUFFER_TOO_SMALL);
		return ret;
	}
	
	g_assert (cattr.type == type); 
	*attr = gkr_pk_attribute_new (cattr.type);
	memcpy (*attr, &cattr, sizeof (cattr));
	memset (&cattr, 0, sizeof (cattr));
	
	g_hash_table_replace (pv->attr_cache, GUINT_TO_POINTER (type), *attr);
	return CKR_OK;
}

static void
move_indexes_if_necessary (GkrPkObject *obj, GkrPkStorage *copy_storage, 
                           GQuark copy_location)
{
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE (obj);
	GkrPkIndex *old_index = NULL;
	GkrPkIndex *new_index = NULL;
	
	if (obj->storage)
		old_index = gkr_pk_storage_index (obj->storage, obj->location);
	if (copy_storage)
		new_index = gkr_pk_storage_index (copy_storage, copy_location);
	
	if (old_index == new_index)
		return;
	
	gkr_pk_index_copy (old_index, new_index, obj->digest);
	
	/* 
	 * If the index is a dummy index, or wasn't being stored 
	 * somewhere 'real', then remove the old indexes too.
	 */
	if (pv->dummy_digest || !obj->storage)
		gkr_pk_index_delete (old_index, obj->digest);
}

/* --------------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_object_init (GkrPkObject *obj)
{
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE (obj);
	
	pv->attr_cache = g_hash_table_new_full (g_direct_hash, g_direct_equal, 
	                                        NULL, gkr_pk_attribute_free);
	
	/* Create a dummy digest which has the object address */
	pv->dummy_digest = TRUE;
	++unique_counter;
	obj->digest = gkr_id_new_digestv((guchar*)&obj, sizeof (obj),
	                                 (guchar*)&unique_counter, sizeof (unique_counter),
	                                 NULL);
}

static GObject*
gkr_pk_object_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkrPkManager *mgr;
	GkrPkObject *xobj;
	GObject *obj;
	guint i;
	
	obj = G_OBJECT_CLASS (gkr_pk_object_parent_class)->constructor (type, n_props, props);
	if (!obj) 
		return NULL;
		
	xobj = GKR_PK_OBJECT (obj);
	
	/* 
	 * Find the object manager and register, if we have 
	 * a digest setup already. Otherwise this'll happen
	 * later (see PROP_DIGEST in gkr_pk_object_set_property)
	  */
	if (xobj->digest) {
		for (i = 0; i < n_props; ++i) {
			if (props[i].pspec->name && g_str_equal (props[i].pspec->name, "manager")) {
				mgr = g_value_get_object (props[i].value);
				if (mgr) {
					gkr_pk_manager_register (mgr, xobj);
					g_return_val_if_fail (xobj->manager == mgr, obj);
				}
				break;
			}
		}
	}
	
	return obj;
}

static CK_RV
gkr_pk_object_get_attribute_common (GkrPkObject *obj, CK_ATTRIBUTE_PTR attr)
{
	CK_OBJECT_CLASS cls;

	switch (attr->type) {
	case CKA_LABEL:
		gkr_pk_attribute_set_string (attr, gkr_pk_object_get_label (obj));
		return CKR_OK;
	
	case CKA_TOKEN:
		gkr_pk_attribute_set_boolean (attr, 
			(obj->handle & GKR_PK_OBJECT_IS_PERMANENT) == GKR_PK_OBJECT_IS_PERMANENT);
		return CKR_OK;
		
	case CKA_PRIVATE:
		gkr_pk_attribute_set_boolean (attr, 
			(gkr_pk_object_get_ulong (obj, CKA_CLASS, &cls) == CKR_OK &&
			 gkc_pk_class_is_private (cls)));
		return CKR_OK; 

	case CKA_MODIFIABLE:
		/* TODO: Does this need to check somewhere? */
		gkr_pk_attribute_set_boolean (attr, CK_TRUE);
		return CKR_OK;
		
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
}

static CK_RV
gkr_pk_object_set_attribute_common (GkrPkObject *obj, CK_ATTRIBUTE_PTR attr)
{
	gchar *label;
	
	switch (attr->type) {
	case CKA_LABEL:
		if (!attr->pValue && attr->ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		label = g_strndup (attr->pValue, attr->ulValueLen);
		gkr_pk_object_set_label (obj, label);
		g_free (label);
		return CKR_OK;
		
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
		return CKR_ATTRIBUTE_READ_ONLY;
		
	case CKA_CLASS:
		return CKR_ATTRIBUTE_READ_ONLY;
		
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;	
	};
}

static guchar*
gkr_pk_object_serialize (GkrPkObject *obj, const gchar *password, gsize *n_data)
{
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), NULL);
	g_return_val_if_fail (n_data, NULL);
	
	*n_data = 0;
	return NULL;
}

static void
gkr_pk_object_get_property (GObject *obj, guint prop_id, GValue *value, 
                             GParamSpec *pspec)
{
	GkrPkObject *xobj = GKR_PK_OBJECT (obj);
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE (xobj);

	switch (prop_id) {
	case PROP_MANAGER:
		g_value_set_object (value, xobj->manager);
		break;
	case PROP_LOCATION:
		g_value_set_uint (value, xobj->location);
		break;
	case PROP_DIGEST:
		g_value_set_boxed (value, xobj->digest);
		break;
	case PROP_ORIG_LABEL:
		g_value_set_string (value, pv->orig_label);
		break;
	case PROP_LABEL:
		g_value_set_string (value, gkr_pk_object_get_label (xobj));
		break;
	case PROP_STORAGE:
		g_value_set_object (value, xobj->storage);
		break;
	}
}

static void
gkr_pk_object_set_property (GObject *obj, guint prop_id, const GValue *value, 
                              GParamSpec *pspec)
{
	GkrPkObject *xobj = GKR_PK_OBJECT (obj);
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE (xobj);
	GkrPkManager *manager;
	GkrPkIndex *index;
	GkrPkStorage *storage;
	gkrid digest;
	GQuark location;
	
	switch (prop_id) {
	case PROP_MANAGER:
		g_assert (!xobj->manager);
		/* 
		 * We set this up in the constructor after all other props have
		 * taken effect. See above.
		 */
		break; 
		
	case PROP_LOCATION:
		location = g_value_get_uint (value);
		if (location)
			move_indexes_if_necessary (xobj, xobj->storage, location);
		xobj->location = location; 
		gkr_pk_object_flush (xobj);
		break;
		
	case PROP_DIGEST:
		/* 
		 * This is a bit of complicated song and dance. The digest uniquely
		 * identifies the object in many cases. When it changes, all sorts 
		 * of stuff needs to change.
		 */
		
		g_return_if_fail (xobj->digest);
		digest = gkr_id_dup (g_value_get_boxed (value));
		g_return_if_fail (digest);
		
		/* Unregister old digest with object manager */
		manager = xobj->manager;
		if (manager)
			gkr_pk_manager_unregister (manager, xobj);

		/* Rename to the new digest in the index */
		index = xobj->storage ? gkr_pk_storage_index (xobj->storage, xobj->location) : NULL;
		if (gkr_pk_index_have (index, xobj->digest)) {
			if (!gkr_pk_index_rename (index, xobj->digest, digest))
				g_return_if_reached ();
		}

		/* Change to new digest */
		gkr_id_free (xobj->digest);
		xobj->digest = digest;
		gkr_pk_object_flush (xobj);

		/* Register with the object manager with the new digest */
		if (manager)
			gkr_pk_manager_register (manager, xobj);
		
		break;
		
	case PROP_ORIG_LABEL:
		g_free (pv->orig_label);
		pv->orig_label = g_value_dup_string (value);
		gkr_pk_object_flush (xobj);
		break;
		
	case PROP_LABEL:
		gkr_pk_object_set_label (xobj, g_value_get_string (value));
		break;
		
	case PROP_STORAGE:
		/* 
		 * We're changing storages at this point. We may get a new index
		 * so try to move everything from the old index to the new. 
		 */
		storage = g_value_get_object (value);
		if (storage)
			move_indexes_if_necessary (xobj, storage, xobj->location);
		
		/* We don't reference, storage should remove itself before the end */
		xobj->storage = storage;
		gkr_pk_object_flush (xobj);
		break;
	};
}
                                    
static void
gkr_pk_object_finalize (GObject *obj)
{
	GkrPkObject *xobj = GKR_PK_OBJECT (obj);
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE (xobj);
	
	if (pv->attr_cache)
		g_hash_table_destroy (pv->attr_cache);
		
	g_free (pv->orig_label);
	g_free (pv->data_path);
	g_free (pv->data_section);
	
	if (xobj->manager)
		gkr_pk_manager_unregister (xobj->manager, xobj);
	g_return_if_fail (xobj->manager == NULL);
	
	gkr_id_free (xobj->digest);
	xobj->digest = NULL;

	G_OBJECT_CLASS (gkr_pk_object_parent_class)->finalize (obj);
}

static void
gkr_pk_object_class_init (GkrPkObjectClass *klass)
{
	GObjectClass *gobject_class;
	gobject_class = (GObjectClass*) klass;

	gkr_pk_object_parent_class = g_type_class_peek_parent (klass);
	gobject_class->constructor = gkr_pk_object_constructor;
	gobject_class->get_property = gkr_pk_object_get_property;
	gobject_class->set_property = gkr_pk_object_set_property;
	gobject_class->finalize = gkr_pk_object_finalize;
	
	klass->get_attribute = gkr_pk_object_get_attribute_common;
	klass->set_attribute = gkr_pk_object_set_attribute_common;
	klass->serialize = gkr_pk_object_serialize;

	g_type_class_add_private (gobject_class, sizeof (GkrPkObjectPrivate));
	
	g_object_class_install_property (gobject_class, PROP_MANAGER, 
		g_param_spec_object ("manager", "Manager", "Object Manager",
		                     GKR_TYPE_PK_MANAGER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property (gobject_class, PROP_LOCATION,
		g_param_spec_uint ("location", "Location", "Location of Data",
		                   0, G_MAXUINT, 0, G_PARAM_READWRITE));
		                   
	g_object_class_install_property (gobject_class, PROP_DIGEST,
		g_param_spec_boxed ("digest", "Digest", "Digest Identifier for Data",
		                    GKR_ID_BOXED_TYPE, G_PARAM_READWRITE));
		                    
	g_object_class_install_property (gobject_class, PROP_ORIG_LABEL,
		g_param_spec_string ("orig-label", "Original Label", "Original Label",
		                     NULL, G_PARAM_READWRITE));
		                     
	g_object_class_install_property (gobject_class, PROP_LABEL,
		g_param_spec_string ("label", "Label", "PK Object Label",
		                     NULL, G_PARAM_READWRITE));
	
	g_object_class_install_property (gobject_class, PROP_STORAGE,
		g_param_spec_object ("storage", "Storage", "Storage for this Object",
		                     GKR_TYPE_PK_STORAGE, G_PARAM_READWRITE));
}

/* --------------------------------------------------------------------------------
 * PUBLIC 
 */
 
GType
gkr_pk_object_get_object_type (GQuark pkix_type)
{
	if (pkix_type == GKR_PKIX_PRIVATE_KEY) 
		return GKR_TYPE_PK_PRIVKEY;
	else if (pkix_type == GKR_PKIX_PUBLIC_KEY) 
		return GKR_TYPE_PK_PUBKEY;
	else if (pkix_type == GKR_PKIX_CERTIFICATE)
		return GKR_TYPE_PK_CERT;
	else 
		g_return_val_if_reached (0);
}

CK_RV
gkr_pk_object_create (GkrPkSession *session, 
                      GArray *attrs, GkrPkObject **object)
{
	GkrPkManager *the_manager;
	GkrPkStorage *the_storage;
	CK_ATTRIBUTE_PTR attr;
	CK_OBJECT_CLASS cls;
	CK_BBOOL token;
	GError *err = NULL;
	CK_RV ret;
	gboolean res;
	guint i;
	
	/* Find out if its a token object or not */
	if (!gkr_pk_attributes_boolean (attrs, CKA_TOKEN, &token))
		token = CK_FALSE;

	if (!gkr_pk_attributes_ulong (attrs, CKA_CLASS, &cls))
		return CKR_TEMPLATE_INCOMPLETE;

	/* Create the object with the right object manager */
	the_manager = token ? gkr_pk_manager_for_token () : session->manager;
	the_storage = token ? gkr_pk_storage_get_default () : session->storage; 

	/* Create the specific kind of object */
	switch (cls) {
	case CKO_PUBLIC_KEY:
		ret = gkr_pk_pubkey_create (the_manager, attrs, object);
		break;
		
	case CKO_PRIVATE_KEY:
		ret = gkr_pk_privkey_create (the_manager, attrs, object);
		break;
		
	case CKO_CERTIFICATE:
		ret = gkr_pk_cert_create (the_manager, attrs, object);
		break;
		
	case CKO_GNOME_IMPORT:
		/* 
		 * The import object, needs to have access to the session_manager, and 
		 * session_storage in order to import stuff there.
		 */
		ret = gkr_pk_import_create (the_manager, session, attrs, object);
		break;
	default:
		/* TODO: What's a better error code here? */
		return CKR_FUNCTION_NOT_SUPPORTED;
	};
	
	if (ret != CKR_OK)
		return ret;

	g_return_val_if_fail (*object != NULL, CKR_GENERAL_ERROR);

	/* Mark these bits as used */
	gkr_pk_attributes_consume (attrs, CKA_CLASS, CKA_TOKEN, -1);
	
	/* 
	 * Check that all the remaining attributes are either already
	 * set, if not try to set them on the object. 
	 */
	for (i = 0; i < attrs->len; ++i) {
		attr = &(g_array_index (attrs, CK_ATTRIBUTE, i));
		if (!gkr_pk_attribute_is_consumed (attr)) {
			ret = gkr_pk_object_set_attribute (*object, attr);
			if (ret != CKR_OK)
				break;
		}  
	} 	
	
	/* Unsuccessful so free the object */
	if (ret != CKR_OK) {
		g_object_unref (*object);
		*object = NULL;
		return ret;
	}
	
	/* Store the object in the store that was appropriate */
	res = gkr_pk_storage_store (the_storage, *object, &err);
	
	if (!res) {
		g_message ("couldn't store created object: %s", 
		           err && err->message ? err->message : "");
		g_clear_error (&err);
		g_object_unref (*object);
		*object = NULL;
		return CKR_FUNCTION_FAILED;
	}

	/* Register it with the object manager if necessary */
	if (!(*object)->manager)
		gkr_pk_manager_register (the_manager, *object);
	
	return CKR_OK;
}

void
gkr_pk_object_flush (GkrPkObject *object)
{
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE(object);
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	
	g_hash_table_remove_all (pv->attr_cache);
	
	g_free (pv->label);
	pv->label = NULL;
}

void
gkr_pk_object_lock (GkrPkObject *object)
{
	GkrPkObjectClass *klass;
	
	klass = GKR_PK_OBJECT_GET_CLASS (object);

	if (klass->lock)
		(*klass->lock) (object);
}

gboolean
gkr_pk_object_import (GkrPkObject *object)
{
	GkrPkObjectClass *klass;
	gboolean ret = TRUE;
	
	klass = GKR_PK_OBJECT_GET_CLASS (object);

	if (klass->import)
		ret = (*klass->import) (object);
	
	if (ret)
		gkr_pk_object_index_set_boolean (object, "imported", TRUE);
	
	return ret;
}

gboolean
gkr_pk_object_match_one (GkrPkObject *object, CK_ATTRIBUTE_PTR rattr)
{
	CK_ATTRIBUTE_PTR attr;
	CK_RV rv;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), CKR_GENERAL_ERROR);
	g_return_val_if_fail (rattr->pValue, FALSE);
	
	rv = lookup_attribute (object, rattr->type, &attr);
	if (rv != CKR_OK)
		return FALSE;
			
	g_assert (attr->type == rattr->type);
	if (attr->ulValueLen != rattr->ulValueLen)
		return FALSE;
	if (attr->pValue == rattr->pValue)
		return TRUE;
	if (!attr->pValue || !rattr->pValue)
		return FALSE;
	if (memcmp (attr->pValue, rattr->pValue, rattr->ulValueLen) != 0)
		return FALSE;

	return TRUE;
}

gboolean 
gkr_pk_object_match (GkrPkObject *object, GArray *attrs)
{
	CK_ATTRIBUTE_PTR rattr;
	guint i;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), CKR_GENERAL_ERROR);

	for (i = 0; i < attrs->len; ++i) {
		rattr = &(g_array_index (attrs, CK_ATTRIBUTE, i));
		if (!gkr_pk_object_match_one (object, rattr))
			return FALSE;
	} 
	
	return TRUE;
}

CK_OBJECT_HANDLE
gkr_pk_object_get_handle (GkrPkObject *object)
{
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), 0);
	return object->handle;
}

CK_RV
gkr_pk_object_get_attribute (GkrPkObject *object, CK_ATTRIBUTE_PTR attr)
{
	CK_ATTRIBUTE_PTR cattr;
	CK_RV ret;

	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), CKR_GENERAL_ERROR);
	g_return_val_if_fail (attr, CKR_GENERAL_ERROR);
		
	ret = lookup_attribute (object, attr->type, &cattr);
	if (ret == CKR_OK)
		gkr_pk_attribute_copy (attr, cattr);
	else
		gkr_pk_attribute_set_invalid (attr);
	
	return ret;
}

CK_RV
gkr_pk_object_get_ulong (GkrPkObject *object, CK_ATTRIBUTE_TYPE type,
                         CK_ULONG *value)
{
	CK_ATTRIBUTE_PTR cattr;
	CK_RV ret;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), CKR_GENERAL_ERROR);

	ret = lookup_attribute (object, type, &cattr);
	if (ret != CKR_OK)
		return ret;
		
	g_return_val_if_fail (cattr->type == type, CKR_GENERAL_ERROR);
	g_return_val_if_fail (cattr->ulValueLen == sizeof (CK_ULONG), CKR_GENERAL_ERROR);
	g_return_val_if_fail (cattr->pValue, CKR_GENERAL_ERROR);
	 
	if (value) 
		*value = *((CK_ULONG*)cattr->pValue);
		
	return CKR_OK;
}

CK_RV
gkr_pk_object_get_bool (GkrPkObject *object, CK_ATTRIBUTE_TYPE type,
                        CK_BBOOL *value)
{
	CK_ATTRIBUTE_PTR cattr;
	CK_RV ret;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), CKR_GENERAL_ERROR);

	ret = lookup_attribute (object, type, &cattr);
	if (ret != CKR_OK)
		return ret;
		
	g_return_val_if_fail (cattr->type == type, CKR_GENERAL_ERROR);
	g_return_val_if_fail (cattr->ulValueLen == sizeof (CK_BBOOL), CKR_GENERAL_ERROR);
	g_return_val_if_fail (cattr->pValue, CKR_GENERAL_ERROR);
	 
	if (value) 
		*value = *((CK_BBOOL*)cattr->pValue);
		
	return CKR_OK;
}

CK_RV
gkr_pk_object_get_attributes (GkrPkObject *object, GArray *attrs)
{
	CK_RV ret, rv;
	CK_ATTRIBUTE_PTR rattr, attr;
	guint i;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), CKR_GENERAL_ERROR);
	
	ret = CKR_OK;
	
	for (i = 0; i < attrs->len; ++i) {
		rattr = &(g_array_index (attrs, CK_ATTRIBUTE, i));
		rv = lookup_attribute (object, rattr->type, &attr);
		if (rv == CKR_OK) { 
			gkr_pk_attribute_copy (rattr, attr);
		} else {
			ret = rv;
			gkr_pk_attribute_set_invalid (rattr);
		}
	}
	
	return ret;
}

CK_RV
gkr_pk_object_set_attribute (GkrPkObject *object, CK_ATTRIBUTE_PTR attr)
{
	GkrPkObjectClass *klass;
	CK_ATTRIBUTE_PTR cattr;
	CK_BBOOL bvalue;
	CK_ULONG nvalue;
	gboolean found;
	CK_RV ret = 0;
	
	/* Get the current value for this attribute */ 
	found = (lookup_attribute (object, attr->type, &cattr) == CKR_OK);
	if (found) {
		
		/* Compare it with the the new one, and ignore if equal */
		if (gkr_pk_attribute_equal (attr, cattr))
			return CKR_OK;
	}

	klass = GKR_PK_OBJECT_GET_CLASS (object);

	/* A quick early check of the values */	
	switch (gkr_pk_attribute_data_type (attr->type))
	{
	case GKR_PK_DATA_BOOL:
		if (!gkr_pk_attribute_get_boolean (attr, &bvalue))
			return CKR_ATTRIBUTE_VALUE_INVALID;
		break;
		
	case GKR_PK_DATA_ULONG:
		if (!gkr_pk_attribute_get_ulong (attr, &nvalue))
			return CKR_ATTRIBUTE_VALUE_INVALID;
		break;

	case GKR_PK_DATA_BYTES:
		break;
		
	case GKR_PK_DATA_UNKNOWN:
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	default:
		g_assert_not_reached ();
		break;
	};

	/* If we didn't call above, then set via main method */
	if (klass->set_attribute)
		ret = (*klass->set_attribute) (object, attr);
	else
		ret = CKR_ATTRIBUTE_TYPE_INVALID; 
	
	/* 
	 * If a method and value was found for reading, but no method
	 * was found for writing, then this must be a readonly. 
	 */
	if (ret == CKR_ATTRIBUTE_TYPE_INVALID && found)
		ret = CKR_ATTRIBUTE_READ_ONLY;

	return ret;
}
                                                    
CK_RV
gkr_pk_object_set_ulong (GkrPkObject *object, CK_ATTRIBUTE_TYPE type, CK_ULONG value)
{
	CK_ATTRIBUTE attr = { type, &value, sizeof (value) }; 
	return gkr_pk_object_set_attribute (object, &attr);
}

CK_RV
gkr_pk_object_set_bool (GkrPkObject *object, CK_ATTRIBUTE_TYPE type, CK_BBOOL value)
{
	CK_ATTRIBUTE attr = { type, &value, sizeof (value) }; 
	return gkr_pk_object_set_attribute (object, &attr);
}
                                                    
CK_RV
gkr_pk_object_set_attributes (GkrPkObject *object, GArray *attrs)
{
	CK_ATTRIBUTE_PTR attr;
	CK_RV ret = CKR_OK;
	guint i;
	
	for (i = 0; i < attrs->len; ++i) {
		attr = &(g_array_index (attrs, CK_ATTRIBUTE, i));
		ret = gkr_pk_object_set_attribute (object, attr);
		if (ret != CKR_OK)
			break;  
	} 
	
	return ret;
}

gboolean
gkr_pk_object_has_label (GkrPkObject *xobj)
{
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE (xobj);
	g_return_val_if_fail (GKR_IS_PK_OBJECT (xobj), FALSE);
	
	return pv->orig_label != NULL || 
	       gkr_pk_object_index_has_value (xobj, GKR_PK_INDEX_LABEL);
}

const gchar*
gkr_pk_object_get_label (GkrPkObject *xobj)
{
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE (xobj);
	GType type;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (xobj), NULL);
	
	if (!pv->label) {
		/* Try the label from the index */
		pv->label = gkr_pk_object_index_get_string (xobj, GKR_PK_INDEX_LABEL);
				
		/* Try any original label handed us by parsers */
		if (!pv->label && pv->orig_label) 
			pv->label = g_strdup (pv->orig_label);
		
		/* Try and use the filename */
		if (!pv->label && xobj->location) 
			pv->label = gkr_location_to_display (xobj->location);
		
		/* Come up with a name depending on the type */
		if (!pv->label) {
			type = G_OBJECT_TYPE (xobj);
			if (type == GKR_TYPE_PK_CERT) {
				pv->label = g_strdup (_("Certificate"));
			} else if (type == GKR_TYPE_PK_PRIVKEY) {
				pv->label = g_strdup (_("Private Key"));
			} else if (type == GKR_TYPE_PK_PUBKEY) {
				pv->label = g_strdup (_("Public Key"));
			} else {
				g_warning ("no default label for objects of type: %s",
				           G_OBJECT_TYPE_NAME (xobj));
				pv->label = g_strdup (G_OBJECT_TYPE_NAME (xobj));
			}
		}
	}
	
	return pv->label;
}

void
gkr_pk_object_set_label (GkrPkObject *xobj, const gchar *label)
{
	g_return_if_fail (GKR_IS_PK_OBJECT (xobj));
	gkr_pk_object_index_set_string (xobj, "label", label);
}

/* -------------------------------------------------------------------
 * INDEX HELPERS 
 */

gboolean
gkr_pk_object_index_has_value (GkrPkObject *object, const gchar *field)
{
	GkrPkIndex *index = NULL;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), FALSE);
	g_return_val_if_fail (object->digest, FALSE);
	g_return_val_if_fail (field, FALSE);

	if (object->storage) {
		g_return_val_if_fail (GKR_IS_PK_STORAGE (object->storage), FALSE);
		index = gkr_pk_storage_index (object->storage, object->location);
		g_return_val_if_fail (index, FALSE);
	} 
	
	return gkr_pk_index_has_value (index, object->digest, field);
}

GQuark*
gkr_pk_object_index_get_quarks (GkrPkObject *object, const gchar *field)
{
	GkrPkIndex *index = NULL;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), NULL);
	g_return_val_if_fail (object->digest, NULL);
	g_return_val_if_fail (field, NULL);
	
	if (object->storage) {
		g_return_val_if_fail (GKR_IS_PK_STORAGE (object->storage), FALSE);
		index = gkr_pk_storage_index (object->storage, object->location);
		g_return_val_if_fail (index, FALSE);
	} 
	
	return gkr_pk_index_get_quarks (index, object->digest, field);
}

gchar*
gkr_pk_object_index_get_string (GkrPkObject *object, const gchar *field)
{
	GkrPkIndex *index = NULL;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), NULL);
	g_return_val_if_fail (object->digest, NULL);
	g_return_val_if_fail (field, NULL);
	
	if (object->storage) {
		g_return_val_if_fail (GKR_IS_PK_STORAGE (object->storage), FALSE);
		index = gkr_pk_storage_index (object->storage, object->location);
		g_return_val_if_fail (index, FALSE);
	} 
	
	return gkr_pk_index_get_string (index, object->digest, field);
}

guchar*
gkr_pk_object_index_get_binary (GkrPkObject *object, const gchar *field,
                                gsize *n_data)
{
	GkrPkIndex *index = NULL;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (object), NULL);
	g_return_val_if_fail (object->digest, NULL);
	g_return_val_if_fail (field, NULL);
	
	if (object->storage) {
		g_return_val_if_fail (GKR_IS_PK_STORAGE (object->storage), FALSE);
		index = gkr_pk_storage_index (object->storage, object->location);
		g_return_val_if_fail (index, FALSE);
	} 
	
	return gkr_pk_index_get_binary (index, object->digest, field, n_data);
}

void
gkr_pk_object_index_set_boolean (GkrPkObject *object, const gchar *field,
                                 gboolean value)
{
	GkrPkIndex *index = NULL;
	
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	g_return_if_fail (object->digest);
	g_return_if_fail (field);
	
	if (object->storage) {
		g_return_if_fail (GKR_IS_PK_STORAGE (object->storage));
		index = gkr_pk_storage_index (object->storage, object->location);
		g_return_if_fail (index);
	} 
	
	if (gkr_pk_index_set_boolean (index, object->digest, field, value))
		gkr_pk_object_flush (object);
}

void
gkr_pk_object_index_set_string (GkrPkObject *object, const gchar *field,
                                const gchar *string)
{
	GkrPkIndex *index = NULL;
	
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	g_return_if_fail (object->digest);
	g_return_if_fail (field);
	
	if (object->storage) {
		g_return_if_fail (GKR_IS_PK_STORAGE (object->storage));
		index = gkr_pk_storage_index (object->storage, object->location);
		g_return_if_fail (index);
	} 
	
	if (gkr_pk_index_set_string (index, object->digest, field, string))
		gkr_pk_object_flush (object);
}

void
gkr_pk_object_index_set_binary (GkrPkObject *object, const gchar *field,
                                const guchar *data, gsize n_data)
{
	GkrPkIndex *index = NULL;
	
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	g_return_if_fail (object->digest);
	g_return_if_fail (field);

	if (object->storage) {
		g_return_if_fail (GKR_IS_PK_STORAGE (object->storage));
		index = gkr_pk_storage_index (object->storage, object->location);
		g_return_if_fail (index);
	}
	
	if (gkr_pk_index_set_binary (index, object->digest, field, data, n_data))
		gkr_pk_object_flush (object);
}

void
gkr_pk_object_index_clear (GkrPkObject *object, const gchar *field)
{
	GkrPkIndex *index = NULL;
	
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	g_return_if_fail (object->digest);
	g_return_if_fail (field);

	if (object->storage) {
		g_return_if_fail (GKR_IS_PK_STORAGE (object->storage));
		index = gkr_pk_storage_index (object->storage, object->location);
		g_return_if_fail (index);
	}
	
	if (gkr_pk_index_clear (index, object->digest, field))
		gkr_pk_object_flush (object);
}
