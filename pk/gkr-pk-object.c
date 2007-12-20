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

#include "gkr-pk-index.h"
#include "gkr-pk-object.h"
#include "gkr-pk-object-manager.h"
#include "gkr-pk-util.h"

#include "common/gkr-location.h"

#include <string.h>

/* --------------------------------------------------------------------------------
 * DECLARATIONS
 */

enum {
	PROP_0,
	PROP_MANAGER,
	PROP_LOCATION,
	PROP_UNIQUE,
	PROP_ORIG_LABEL,
	PROP_LABEL
};

enum {
	LOADED_LABEL = 0x0001,
	LOADED_USAGES = 0x0002,
};

typedef struct _GkrPkObjectPrivate GkrPkObjectPrivate;

struct _GkrPkObjectPrivate {
	GHashTable *attr_cache;
	gchar *orig_label;
	guint load_state;
	
	gchar *data_path;
	gchar *data_section;
};

#define GKR_PK_OBJECT_GET_PRIVATE(o)  \
	(G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PK_OBJECT, GkrPkObjectPrivate))

G_DEFINE_TYPE(GkrPkObject, gkr_pk_object, G_TYPE_OBJECT);

/* --------------------------------------------------------------------------------
 * HELPERS
 */
 
static CK_RV
lookup_attribute (GkrPkObject *object, CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE_PTR *attr)
{
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE(object);
	GkrPkObjectClass *klass;
	CK_ATTRIBUTE cattr;
	CK_RV ret = 0;
	
	*attr = g_hash_table_lookup (pv->attr_cache, GUINT_TO_POINTER (type));
	if(*attr)
		return CKR_OK;
		
	klass = GKR_PK_OBJECT_GET_CLASS (object);
		
	memset (&cattr, 0, sizeof (cattr));
	cattr.type = type;

	switch (gkr_pk_attribute_data_type (type))
	{
	case GKR_PK_DATA_BOOL:
		if (!klass->get_bool_attribute)
			return CKR_ATTRIBUTE_TYPE_INVALID;
		ret = (*klass->get_bool_attribute) (object, &cattr);
		break;
		
	case GKR_PK_DATA_ULONG:
		if (!klass->get_ulong_attribute)
			return CKR_ATTRIBUTE_TYPE_INVALID;
		ret = (*klass->get_ulong_attribute) (object, &cattr);
		break;
		
	case GKR_PK_DATA_BYTES:
		if (!klass->get_data_attribute)
			return CKR_ATTRIBUTE_TYPE_INVALID;
		ret = (*klass->get_data_attribute) (object, &cattr);
		break;
		
	case GKR_PK_DATA_DATE:
		if (!klass->get_date_attribute)
			return CKR_ATTRIBUTE_TYPE_INVALID;
		ret = (*klass->get_date_attribute) (object, &cattr);
		break;
				
	case GKR_PK_DATA_UNKNOWN:
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	default:
		g_assert_not_reached ();
		break;
	};

	if (ret != CKR_OK)
	{
		/* Shouldn't be returning these */
		g_assert (ret != CKR_BUFFER_TOO_SMALL);
		return ret;
	}
	
	g_assert (cattr.type == type); 
	*attr = gkr_pk_attribute_new (cattr.type);
	gkr_pk_attribute_steal (*attr, &cattr);
	
	g_hash_table_replace (pv->attr_cache, GUINT_TO_POINTER (type), *attr);
	return CKR_OK;
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
}

static GObject*
gkr_pk_object_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkrPkObjectManager *mgr;
	GkrPkObject *xobj;
	GObject *obj;
	guint i;
	
	obj = G_OBJECT_CLASS (gkr_pk_object_parent_class)->constructor (type, n_props, props);
	if (!obj) 
		return NULL;
		
	xobj = GKR_PK_OBJECT (obj);
	
	/* Find the object manager and register */
	for (i = 0; i < n_props; ++i) {
		if (props[i].pspec->name && g_str_equal (props[i].pspec->name, "manager")) {
			mgr = g_value_get_object (props[i].value);
			if (mgr) {
				gkr_pk_object_manager_register (mgr, xobj);
				g_return_val_if_fail (xobj->manager == mgr, obj);
			}
			break;
		}
	}
	
	return obj;
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
	case PROP_UNIQUE:
		g_value_set_boxed (value, xobj->unique);
		break;
	case PROP_ORIG_LABEL:
		g_value_set_string (value, pv->orig_label);
		break;
	case PROP_LABEL:
		g_value_set_string (value, gkr_pk_object_get_label (xobj));
		break;
	}
}

static void
gkr_pk_object_set_property (GObject *obj, guint prop_id, const GValue *value, 
                              GParamSpec *pspec)
{
	GkrPkObject *xobj = GKR_PK_OBJECT (obj);
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE (xobj);
	
	switch (prop_id) {
	case PROP_MANAGER:
		g_assert (!xobj->manager);
		/* 
		 * We set this up in the constructor after all other props have
		 * taken effect. See above.
		 */
		break; 
	case PROP_LOCATION:
		xobj->location = g_value_get_uint (value);
		break;
	case PROP_UNIQUE:
		gkr_unique_free (xobj->unique);
		xobj->unique = gkr_unique_dup (g_value_get_boxed (value));
		break;
	case PROP_ORIG_LABEL:
		g_free (pv->orig_label);
		pv->orig_label = g_value_dup_string (value);
		break;
	case PROP_LABEL:
		gkr_pk_object_set_label (xobj, g_value_get_string (value));
		break;
	}
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
		gkr_pk_object_manager_unregister (xobj->manager, xobj);
	g_return_if_fail (xobj->manager == NULL);

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

	g_type_class_add_private (gobject_class, sizeof (GkrPkObjectPrivate));
	
	g_object_class_install_property (gobject_class, PROP_MANAGER, 
		g_param_spec_object ("manager", "Manager", "Object Manager",
		                     GKR_TYPE_PK_OBJECT_MANAGER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property (gobject_class, PROP_LOCATION,
		g_param_spec_uint ("location", "Location", "Location of Data",
		                   0, G_MAXUINT, 0, G_PARAM_READWRITE));
		                   
	g_object_class_install_property (gobject_class, PROP_UNIQUE,
		g_param_spec_boxed ("unique", "Unique", "Unique Identifier for Data",
		                    GKR_UNIQUE_BOXED_TYPE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
		                    
	g_object_class_install_property (gobject_class, PROP_ORIG_LABEL,
		g_param_spec_string ("orig-label", "Original Label", "Original Label",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
		                     
	g_object_class_install_property (gobject_class, PROP_LABEL,
		g_param_spec_string ("label", "Label", "PK Object Label",
		                     NULL, G_PARAM_READWRITE));
}

/* --------------------------------------------------------------------------------
 * PUBLIC 
 */
 
void
gkr_pk_object_flush (GkrPkObject *object)
{
	GkrPkObjectPrivate *pv = GKR_PK_OBJECT_GET_PRIVATE(object);
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	g_hash_table_remove_all (pv->attr_cache);
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

gchar*
gkr_pk_object_get_label (GkrPkObject *xobj)
{
	g_return_val_if_fail (GKR_IS_PK_OBJECT (xobj), NULL);
	return gkr_pk_index_get_string (xobj, "label");
}

void
gkr_pk_object_set_label (GkrPkObject *xobj, const gchar *label)
{
	g_return_if_fail (GKR_IS_PK_OBJECT (xobj));
	if (!label)
		gkr_pk_index_delete (xobj, "label");
	else
		gkr_pk_index_set_string (xobj, "label", label);
}
