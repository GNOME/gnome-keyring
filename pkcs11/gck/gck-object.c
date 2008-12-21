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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "pkcs11/pkcs11.h"

#include "gck-manager.h"
#include "gck-object.h"
#include "gck-util.h"

enum {
	PROP_0,
	PROP_HANDLE,
	PROP_MANAGER
};

struct _GckObjectPrivate {
	CK_OBJECT_HANDLE handle;
	GckManager *manager;
};

G_DEFINE_TYPE (GckObject, gck_object, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV 
gck_object_real_get_attribute (GckObject *self, CK_ATTRIBUTE* attr)
{
	switch (attr->type)
	{
	case CKA_CLASS:
		g_warning ("Derived class should have overridden CKA_CLASS");
		return CKR_GENERAL_ERROR;
	case CKA_LABEL:
		g_warning ("Derived class should have overridden CKA_LABEL");
		return gck_util_set_data (attr, "", 0);
	case CKA_MODIFIABLE:
	case CKA_PRIVATE:
		return gck_util_set_bool (attr, FALSE);
	case CKA_TOKEN:
		return gck_util_set_bool (attr, (self->pv->handle & GCK_OBJECT_IS_PERMANENT) ? TRUE : FALSE);
	};
	
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

#if 0
static CK_RV 
gck_object_real_set_attribute (GckObject *self, const CK_ATTRIBUTE* attr)
{
	switch (attr->type) {
	case CKA_LABEL:
		g_warning ("Derived class should have overridden CKA_LABEL");
		return CKR_ATTRIBUTE_READ_ONLY;
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
		return CKR_ATTRIBUTE_READ_ONLY;
		
	case CKA_CLASS:
		return CKR_ATTRIBUTE_READ_ONLY;
	};
	
	return CKR_ATTRIBUTE_TYPE_INVALID;
}
#endif

static CK_RV
gck_object_real_unlock (GckObject *self, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	gboolean always_auth;
	
	if (!gck_object_get_attribute_boolean (self, CKA_ALWAYS_AUTHENTICATE, &always_auth))
		always_auth = FALSE;
	
	/* A strange error code, but according to spec */
	if (!always_auth)
		return CKR_OPERATION_NOT_INITIALIZED;

	/* A derived class should have overridden this */
	g_return_val_if_reached (CKR_GENERAL_ERROR);
}

static GObject* 
gck_object_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckObject *self = GCK_OBJECT (G_OBJECT_CLASS (gck_object_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	


	
	return G_OBJECT (self);
}

static void
gck_object_init (GckObject *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_OBJECT, GckObjectPrivate);

}

static void
gck_object_dispose (GObject *obj)
{
	GckObject *self = GCK_OBJECT (obj);
	
	gck_object_set_manager (self, NULL);
    
	G_OBJECT_CLASS (gck_object_parent_class)->dispose (obj);
}

static void
gck_object_finalize (GObject *obj)
{
	GckObject *self = GCK_OBJECT (obj);
	
	g_assert (self->pv->manager == NULL);

	G_OBJECT_CLASS (gck_object_parent_class)->finalize (obj);
}

static void
gck_object_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	GckObject *self = GCK_OBJECT (obj);
	
	switch (prop_id) {
	case PROP_HANDLE:
		gck_object_set_handle (self, g_value_get_ulong (value));
		break;
	case PROP_MANAGER:
		gck_object_set_manager (self, g_value_get_object (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_object_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
	GckObject *self = GCK_OBJECT (obj);
	
	switch (prop_id) {
	case PROP_HANDLE:
		g_value_set_ulong (value, gck_object_get_handle (self));
		break;
	case PROP_MANAGER:
		g_value_set_object (value, gck_object_get_manager (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_object_class_init (GckObjectClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
	gck_object_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GckObjectPrivate));

	gobject_class->constructor = gck_object_constructor;
	gobject_class->dispose = gck_object_dispose;
	gobject_class->finalize = gck_object_finalize;
	gobject_class->set_property = gck_object_set_property;
	gobject_class->get_property = gck_object_get_property;
	
	klass->unlock = gck_object_real_unlock;
	klass->get_attribute = gck_object_real_get_attribute;
#if 0
	klass->set_attribute = gck_object_real_set_attribute;
#endif
	
	g_object_class_install_property (gobject_class, PROP_HANDLE,
	           g_param_spec_ulong ("handle", "Handle", "Object handle",
	                               0, G_MAXULONG, 0, G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_MANAGER,
	           g_param_spec_object ("manager", "Manager", "Object manager", 
	                                GCK_TYPE_MANAGER, G_PARAM_READWRITE));
	
#if 0
	signals[SIGNAL] = g_signal_new ("signal", GCK_TYPE_OBJECT, 
	                                G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GckObjectClass, signal),
	                                NULL, NULL, g_cclosure_marshal_VOID__OBJECT, 
	                                G_TYPE_NONE, 0);
#endif
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

gboolean
gck_object_match (GckObject *self, CK_ATTRIBUTE_PTR match)
{
	CK_ATTRIBUTE attr;
	gboolean matched = FALSE;
	CK_RV rv;
	
	g_return_val_if_fail (GCK_IS_OBJECT (self), FALSE);
	
	if (!match->pValue)
		return FALSE;
	
	attr.type = match->type;
	attr.pValue = g_malloc0 (match->ulValueLen > 4 ? match->ulValueLen : 4);
	attr.ulValueLen = match->ulValueLen;
	
	matched = FALSE;
	
	rv = gck_object_get_attribute (self, &attr);
	matched = (rv == CKR_OK) && 
	          (match->ulValueLen == attr.ulValueLen) &&
	          (memcmp (match->pValue, attr.pValue, attr.ulValueLen) == 0);
	
	g_free (attr.pValue);
	return matched;
}

gboolean
gck_object_match_all (GckObject *self, CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	CK_ULONG i;
	
	g_return_val_if_fail (GCK_IS_OBJECT (self), FALSE);
	
	for (i = 0; i < n_attrs; ++i) {
		if (!gck_object_match (self, &attrs[i]))
			return FALSE;
	}
	
	return TRUE;
}

CK_OBJECT_HANDLE
gck_object_get_handle (GckObject *self)
{
	g_return_val_if_fail (GCK_IS_OBJECT (self), 0);
	return self->pv->handle;	
}

void
gck_object_set_handle (GckObject *self, CK_OBJECT_HANDLE handle)
{
	g_return_if_fail (GCK_IS_OBJECT (self));
	g_return_if_fail (handle != 0);
	g_return_if_fail (self->pv->handle == 0);

	self->pv->handle = handle;
	g_object_notify (G_OBJECT (self), "handle");	
}

GckManager*
gck_object_get_manager (GckObject *self)
{
	g_return_val_if_fail (GCK_IS_OBJECT (self), NULL);
	return self->pv->manager;
}

void
gck_object_set_manager (GckObject *self, GckManager *manager)
{
	g_return_if_fail (GCK_IS_OBJECT (self));
	g_return_if_fail (!manager || GCK_IS_MANAGER (manager));

	if (self->pv->manager) {
		g_return_if_fail (!manager);
		g_object_remove_weak_pointer (G_OBJECT (self->pv->manager), 
		                              (gpointer*)&(self->pv->manager));
	}
	
	self->pv->manager = manager;
	if (self->pv->manager)
		g_object_add_weak_pointer (G_OBJECT (self->pv->manager), 
		                           (gpointer*)&(self->pv->manager));
	
	g_object_notify (G_OBJECT (self), "manager");
}

CK_RV
gck_object_unlock (GckObject *self, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	g_return_val_if_fail (GCK_IS_OBJECT (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (GCK_OBJECT_GET_CLASS (self)->unlock, CKR_GENERAL_ERROR);
	return GCK_OBJECT_GET_CLASS (self)->unlock (self, pin, n_pin);
}


gboolean
gck_object_get_attribute_boolean (GckObject *self, CK_ATTRIBUTE_TYPE type, gboolean *value)
{
	CK_ATTRIBUTE attr;
	CK_BBOOL bvalue;
	
	g_return_val_if_fail (GCK_IS_OBJECT (self), FALSE);
	g_return_val_if_fail (value, FALSE);
	
	attr.type = type;
	attr.ulValueLen = sizeof (CK_BBOOL);
	attr.pValue = &bvalue;
	
	if (gck_object_get_attribute (self, &attr) != CKR_OK)
		return FALSE;
	
	*value = (bvalue == CK_TRUE) ? TRUE : FALSE;
	return TRUE;
}

gboolean
gck_object_get_attribute_ulong (GckObject *self, CK_ATTRIBUTE_TYPE type, gulong *value)
{
	CK_ATTRIBUTE attr;
	CK_ULONG uvalue;
	
	g_return_val_if_fail (GCK_IS_OBJECT (self), FALSE);
	g_return_val_if_fail (value, FALSE);
	
	attr.type = type;
	attr.ulValueLen = sizeof (CK_ULONG);
	attr.pValue = &uvalue;
	
	if (gck_object_get_attribute (self, &attr) != CKR_OK)
		return FALSE;
	
	*value = uvalue;
	return TRUE;
}

void*
gck_object_get_attribute_data (GckObject *self, CK_ATTRIBUTE_TYPE type, gsize *n_data)
{
	CK_ATTRIBUTE attr;
	
	g_return_val_if_fail (GCK_IS_OBJECT (self), NULL);
	g_return_val_if_fail (n_data, NULL);
	
	attr.type = type;
	attr.ulValueLen = 0;
	attr.pValue = NULL;
	
	if (gck_object_get_attribute (self, &attr) != CKR_OK)
		return NULL;

	if (attr.ulValueLen == 0)
		attr.ulValueLen = 1;
	
	attr.pValue = g_malloc0 (attr.ulValueLen);
	
	if (gck_object_get_attribute (self, &attr) != CKR_OK) {
		g_free (attr.pValue);
		return NULL;
	}
	
	return attr.pValue;
}
