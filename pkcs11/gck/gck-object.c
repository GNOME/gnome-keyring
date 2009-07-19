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
#include "pkcs11/pkcs11g.h"

#include "gck-attributes.h"
#include "gck-manager.h"
#include "gck-object.h"
#include "gck-transaction.h"
#include "gck-session.h"
#include "gck-store.h"
#include "gck-timer.h"
#include "gck-util.h"

enum {
	PROP_0,
	PROP_HANDLE,
	PROP_MODULE,
	PROP_MANAGER,
	PROP_STORE,
	PROP_UNIQUE
};

enum {
	NOTIFY_ATTRIBUTE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct _GckObjectTransient {
	GckTimer *timed_timer;
	glong timed_when;
} GckObjectTransient;

struct _GckObjectPrivate {
	CK_OBJECT_HANDLE handle;
	GckModule *module;
	GckManager *manager;
	GckStore *store;
	gchar *unique;
	GckObjectTransient *transient;
};

G_DEFINE_TYPE (GckObject, gck_object, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static void
kaboom_callback (GckTimer *timer, gpointer user_data)
{
	GckObject *self = user_data;
	GckTransaction *transaction;
	GckObjectTransient *transient;
	CK_RV rv;

	g_return_if_fail (GCK_IS_OBJECT (self));
	g_return_if_fail (self->pv->transient);
	transient = self->pv->transient;

	g_return_if_fail (timer == transient->timed_timer);
	transient->timed_timer = NULL;

	g_object_ref (self);

	transaction = gck_transaction_new ();

	/* Off we go */
	gck_object_destroy (self, transaction);

	gck_transaction_complete (transaction);
	rv = gck_transaction_get_result (transaction);
	g_object_unref (transaction);

	if (rv != CKR_OK)
		g_warning ("Unexpected failure to auto destruct object (code: %lu)", (gulong)rv);

	g_object_unref (self);
}

static gboolean
start_callback (GckTransaction *transaction, GObject *obj, gpointer user_data)
{
	GckObject *self = GCK_OBJECT (obj);
	GckObjectTransient *transient;

	g_return_val_if_fail (GCK_IS_OBJECT (self), FALSE);
	g_return_val_if_fail (self->pv->transient, FALSE);
	transient = self->pv->transient;

	g_return_val_if_fail (!transient->timed_timer, FALSE);
	transient->timed_timer = gck_timer_start (self->pv->module, transient->timed_when, 
	                                          kaboom_callback, self);

	return TRUE;
}

static void
module_went_away (gpointer data, GObject *old_module)
{
	GckObject *self = GCK_OBJECT (data);
	g_return_if_fail (self->pv->module);
	g_warning ("module destroyed before object that module contained");
	self->pv->module = NULL;
}

static gboolean
complete_destroy (GckTransaction *transaction, GObject *unused, gpointer user_data)
{
	gck_util_dispose_unref (user_data);
	return TRUE;
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV 
gck_object_real_get_attribute (GckObject *self, GckSession *session, CK_ATTRIBUTE* attr)
{
	CK_RV rv;
	
	switch (attr->type)
	{
	case CKA_CLASS:
		g_warning ("Derived class should have overridden CKA_CLASS");
		return CKR_GENERAL_ERROR;
	case CKA_MODIFIABLE:
		return gck_attribute_set_bool (attr, self->pv->store ? TRUE : FALSE);
	case CKA_PRIVATE:
		return gck_attribute_set_bool (attr, FALSE);
	case CKA_TOKEN:
		if (!self->pv->manager)
			return gck_attribute_set_bool (attr, FALSE);
		return gck_attribute_set_bool (attr, gck_manager_get_for_token (self->pv->manager));
	case CKA_GNOME_UNIQUE:
		if (self->pv->unique)
			return gck_attribute_set_string (attr, self->pv->unique);
		return CKR_ATTRIBUTE_TYPE_INVALID;
	case CKA_GNOME_TRANSIENT:
		return gck_attribute_set_bool (attr, self->pv->transient ? TRUE : FALSE);
	case CKA_GNOME_AUTO_DESTRUCT:
		return gck_attribute_set_time (attr, self->pv->transient ?
		                                     self->pv->transient->timed_when : -1);
	};

	/* Give store a shot */
	if (self->pv->store) {
		rv = gck_store_get_attribute (self->pv->store, self, attr);
		if (rv != CKR_ATTRIBUTE_TYPE_INVALID)
			return rv;
	}

	/* Now some more defaults */
	switch (attr->type) {
	case CKA_LABEL:
		return gck_attribute_set_data (attr, "", 0);
	}
	
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static void 
gck_object_real_set_attribute (GckObject *self, GckSession *session,
                               GckTransaction* transaction, CK_ATTRIBUTE* attr)
{
	switch (attr->type) {
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
	case CKA_CLASS:
		gck_transaction_fail (transaction, CKR_ATTRIBUTE_READ_ONLY);
		return;
	case CKA_GNOME_UNIQUE:
		gck_transaction_fail (transaction, self->pv->unique ? 
		                                       CKR_ATTRIBUTE_READ_ONLY : 
		                                       CKR_ATTRIBUTE_TYPE_INVALID);
		return;
	};

	/* Give store a shot */
	if (self->pv->store) {
		gck_store_set_attribute (self->pv->store, transaction, self, attr);
		return;
	}

	/* Now some more defaults */
	switch (attr->type) {
	case CKA_LABEL:
		gck_transaction_fail (transaction, CKR_ATTRIBUTE_READ_ONLY);
		return;
	}	

	gck_transaction_fail (transaction, CKR_ATTRIBUTE_TYPE_INVALID);
}

static void
gck_object_real_create_attributes (GckObject *self, GckSession *session,
                                   GckTransaction *transaction, CK_ATTRIBUTE *attrs, CK_ULONG n_attrs)
{
	CK_ATTRIBUTE_PTR transient_attr;
	CK_ATTRIBUTE_PTR lifetime_attr;
	gboolean transient = FALSE;
	glong lifetime = -1;
	CK_RV rv;

	/* Parse the transient attribute */
	transient_attr = gck_attributes_find (attrs, n_attrs, CKA_GNOME_TRANSIENT);
	if (transient_attr) {
		rv = gck_attribute_get_bool (transient_attr, &transient);
		gck_attribute_consume (transient_attr);
		if (rv != CKR_OK) {
			gck_transaction_fail (transaction, rv);
			return;
		}
	}

	/* Parse the auto destruct attribute */
	lifetime_attr = gck_attributes_find (attrs, n_attrs, CKA_GNOME_AUTO_DESTRUCT);
	if (lifetime_attr) {
		rv = gck_attribute_get_time (lifetime_attr, &lifetime);
		gck_attribute_consume (lifetime_attr);
		if (rv != CKR_OK) {
			gck_transaction_fail (transaction, rv);
			return;
		}
		
		/* Default for the transient attribute */
		if (!transient_attr)
			transient = TRUE;
	}

	if (transient) {
		self->pv->transient = g_slice_new0 (GckObjectTransient);
		self->pv->transient->timed_when = lifetime;
	}

	if (lifetime >= 0) {
		if (!self->pv->transient) {
			gck_transaction_fail (transaction, CKR_TEMPLATE_INCONSISTENT);
			return;
		}

		gck_transaction_add (transaction, self, start_callback, NULL);
	}
}

static CK_RV
gck_object_real_unlock (GckObject *self, GckAuthenticator *auth)
{
	/* A derived class should have overridden this */
	return CKR_FUNCTION_FAILED;
}

static GObject* 
gck_object_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckObject *self = GCK_OBJECT (G_OBJECT_CLASS (gck_object_parent_class)->constructor(type, n_props, props));

	g_return_val_if_fail (self, NULL);	
	g_return_val_if_fail (GCK_IS_MODULE (self->pv->module), NULL);
	
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
	GckObjectTransient *transient;
	
	if (self->pv->manager)
		gck_manager_unregister_object (self->pv->manager, self);
	g_assert (self->pv->manager == NULL);
	
	g_object_set (self, "store", NULL, NULL);
	g_assert (self->pv->store == NULL);

	if (self->pv->transient) {
		transient = self->pv->transient;
		if (transient->timed_timer)
			gck_timer_cancel (transient->timed_timer);
		transient->timed_timer = NULL;

		g_slice_free (GckObjectTransient, transient);
		self->pv->transient = NULL;
	}
    
	G_OBJECT_CLASS (gck_object_parent_class)->dispose (obj);
}

static void
gck_object_finalize (GObject *obj)
{
	GckObject *self = GCK_OBJECT (obj);
	
	g_assert (self->pv->manager == NULL);
	g_free (self->pv->unique);
	
	/* This is done here, as an object must have a module even after dispose */
	g_object_weak_unref (G_OBJECT (self->pv->module), module_went_away, self);
	self->pv->module = NULL;

	g_assert (self->pv->transient == NULL);

	G_OBJECT_CLASS (gck_object_parent_class)->finalize (obj);
}

static void
gck_object_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	GckObject *self = GCK_OBJECT (obj);
	GckManager *manager;
	GckStore *store;
	
	switch (prop_id) {
	case PROP_HANDLE:
		gck_object_set_handle (self, g_value_get_ulong (value));
		break;
	case PROP_MODULE:
		g_return_if_fail (!self->pv->module);
		self->pv->module = g_value_get_object (value);
		g_return_if_fail (GCK_IS_MODULE (self->pv->module));
		g_object_weak_ref (G_OBJECT (self->pv->module), module_went_away, self);
		break;
	case PROP_MANAGER:
		manager = g_value_get_object (value);
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
		break;
	case PROP_STORE:
		store = g_value_get_object (value);
		if (self->pv->store) {
			g_return_if_fail (!store);
			g_object_remove_weak_pointer (G_OBJECT (self->pv->store), 
			                              (gpointer*)&(self->pv->store));
		}
		self->pv->store = store;
		if (self->pv->store)
			g_object_add_weak_pointer (G_OBJECT (self->pv->store), 
			                           (gpointer*)&(self->pv->store));
		
		g_object_notify (G_OBJECT (self), "store");
		break;
	case PROP_UNIQUE:
		g_return_if_fail (!self->pv->unique);
		self->pv->unique = g_value_dup_string (value);
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
	case PROP_MODULE:
		g_return_if_fail (GCK_IS_MODULE (self->pv->module));
		g_value_set_object (value, gck_object_get_module (self));
		break;
	case PROP_MANAGER:
		g_value_set_object (value, gck_object_get_manager (self));
		break;
	case PROP_STORE:
		g_value_set_object (value, self->pv->store);
		break;
	case PROP_UNIQUE:
		g_value_set_string (value, gck_object_get_unique (self));
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
	klass->set_attribute = gck_object_real_set_attribute;
	klass->create_attributes = gck_object_real_create_attributes;
	
	g_object_class_install_property (gobject_class, PROP_HANDLE,
	           g_param_spec_ulong ("handle", "Handle", "Object handle",
	                               0, G_MAXULONG, 0, G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_MODULE,
	           g_param_spec_object ("module", "Module", "Object module", 
	                                GCK_TYPE_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property (gobject_class, PROP_MANAGER,
	           g_param_spec_object ("manager", "Manager", "Object manager", 
	                                GCK_TYPE_MANAGER, G_PARAM_READWRITE));
	
	g_object_class_install_property (gobject_class, PROP_STORE,
	           g_param_spec_object ("store", "Store", "Object store", 
	                                GCK_TYPE_STORE, G_PARAM_READWRITE));
	
	g_object_class_install_property (gobject_class, PROP_UNIQUE,
	           g_param_spec_string ("unique", "Unique Identifer", "Machine unique identifier", 
	                                NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	signals[NOTIFY_ATTRIBUTE] = g_signal_new ("notify-attribute", GCK_TYPE_OBJECT, 
	                                G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GckObjectClass, notify_attribute),
	                                NULL, NULL, g_cclosure_marshal_VOID__ULONG, 
	                                G_TYPE_NONE, 1, G_TYPE_ULONG);
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

CK_RV
gck_object_get_attribute (GckObject *self, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	g_return_val_if_fail (GCK_IS_OBJECT (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (attr, CKR_GENERAL_ERROR);
	g_assert (GCK_OBJECT_GET_CLASS (self)->get_attribute);
	return GCK_OBJECT_GET_CLASS (self)->get_attribute (self, session, attr);
}

void
gck_object_set_attribute (GckObject *self, GckSession *session,
                          GckTransaction *transaction, CK_ATTRIBUTE_PTR attr)
{
	CK_ATTRIBUTE check;
	CK_RV rv;
	
	g_return_if_fail (GCK_IS_OBJECT (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));
	g_return_if_fail (attr);

	g_assert (GCK_OBJECT_GET_CLASS (self)->set_attribute);

	/* Check if this attribute exists */
	check.type = attr->type;
	check.pValue = 0;
	check.ulValueLen = 0;
	rv = gck_object_get_attribute (self, session, &check);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_SENSITIVE) {
		gck_transaction_fail (transaction, rv);
		return;
	}
	
	/* Check that the value will actually change */
	if (rv == CKR_ATTRIBUTE_SENSITIVE || !gck_object_match (self, session, attr))
		GCK_OBJECT_GET_CLASS (self)->set_attribute (self, session, transaction, attr);
}

void
gck_object_create_attributes (GckObject *self, GckSession *session, GckTransaction *transaction,
                              CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	g_return_if_fail (GCK_IS_OBJECT (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));
	g_return_if_fail (GCK_IS_SESSION (session));
	g_return_if_fail (attrs);

	g_assert (GCK_OBJECT_GET_CLASS (self)->create_attributes);

	/* Check that the value will actually change */
	GCK_OBJECT_GET_CLASS (self)->create_attributes (self, session, transaction, attrs, n_attrs);
}

void
gck_object_notify_attribute  (GckObject *self, CK_ATTRIBUTE_TYPE attr_type)
{
	g_return_if_fail (GCK_IS_OBJECT (self));
	g_signal_emit (self, signals[NOTIFY_ATTRIBUTE], 0, attr_type);
}

gboolean
gck_object_match (GckObject *self, GckSession *session, CK_ATTRIBUTE_PTR match)
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
	
	rv = gck_object_get_attribute (self, session, &attr);
	matched = (rv == CKR_OK) && 
	          (match->ulValueLen == attr.ulValueLen) &&
	          (memcmp (match->pValue, attr.pValue, attr.ulValueLen) == 0);
	
	g_free (attr.pValue);
	return matched;
}

gboolean
gck_object_match_all (GckObject *self, GckSession *session,
                      CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	CK_ULONG i;
	
	g_return_val_if_fail (GCK_IS_OBJECT (self), FALSE);
	
	for (i = 0; i < n_attrs; ++i) {
		if (!gck_object_match (self, session, &attrs[i]))
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

GckModule*
gck_object_get_module (GckObject *self)
{
	g_return_val_if_fail (GCK_IS_OBJECT (self), NULL);
	g_return_val_if_fail (GCK_IS_MODULE (self->pv->module), NULL);
	return self->pv->module;
}

const gchar*
gck_object_get_unique (GckObject *self)
{
	g_return_val_if_fail (GCK_IS_OBJECT (self), NULL);
	return self->pv->unique;
}

gboolean
gck_object_get_transient (GckObject *self)
{
	g_return_val_if_fail (GCK_IS_OBJECT (self), FALSE);
	return self->pv->transient ? TRUE : FALSE;
}


CK_RV
gck_object_unlock (GckObject *self, GckAuthenticator *auth)
{
	g_return_val_if_fail (GCK_IS_OBJECT (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (GCK_OBJECT_GET_CLASS (self)->unlock, CKR_GENERAL_ERROR);
	return GCK_OBJECT_GET_CLASS (self)->unlock (self, auth);
}


gboolean
gck_object_get_attribute_boolean (GckObject *self, GckSession *session,
                                  CK_ATTRIBUTE_TYPE type, gboolean *value)
{
	CK_ATTRIBUTE attr;
	CK_BBOOL bvalue;
	
	g_return_val_if_fail (GCK_IS_OBJECT (self), FALSE);
	g_return_val_if_fail (value, FALSE);
	
	attr.type = type;
	attr.ulValueLen = sizeof (CK_BBOOL);
	attr.pValue = &bvalue;
	
	if (gck_object_get_attribute (self, session, &attr) != CKR_OK)
		return FALSE;
	
	*value = (bvalue == CK_TRUE) ? TRUE : FALSE;
	return TRUE;
}

gboolean
gck_object_get_attribute_ulong (GckObject *self, GckSession *session,
                                CK_ATTRIBUTE_TYPE type, gulong *value)
{
	CK_ATTRIBUTE attr;
	CK_ULONG uvalue;
	
	g_return_val_if_fail (GCK_IS_OBJECT (self), FALSE);
	g_return_val_if_fail (value, FALSE);
	
	attr.type = type;
	attr.ulValueLen = sizeof (CK_ULONG);
	attr.pValue = &uvalue;
	
	if (gck_object_get_attribute (self, session, &attr) != CKR_OK)
		return FALSE;
	
	*value = uvalue;
	return TRUE;
}

void*
gck_object_get_attribute_data (GckObject *self, GckSession *session,
                               CK_ATTRIBUTE_TYPE type, gsize *n_data)
{
	CK_ATTRIBUTE attr;
	
	g_return_val_if_fail (GCK_IS_OBJECT (self), NULL);
	g_return_val_if_fail (n_data, NULL);
	
	attr.type = type;
	attr.ulValueLen = 0;
	attr.pValue = NULL;
	
	if (gck_object_get_attribute (self, session, &attr) != CKR_OK)
		return NULL;

	if (attr.ulValueLen == 0)
		attr.ulValueLen = 1;
	
	attr.pValue = g_malloc0 (attr.ulValueLen);
	
	if (gck_object_get_attribute (self, session, &attr) != CKR_OK) {
		g_free (attr.pValue);
		return NULL;
	}
	
	*n_data = attr.ulValueLen;
	return attr.pValue;
}

void
gck_object_destroy (GckObject *self, GckTransaction *transaction)
{
	GckSession *session;
	GckManager *manager;
	GckModule *module;

	g_return_if_fail (GCK_IS_OBJECT (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));
	g_return_if_fail (self->pv->module);

	g_object_ref (self);

	session = gck_session_for_session_object (self);
	if (session != NULL) {
		gck_session_destroy_session_object (session, transaction, self);
	} else {
		manager = gck_object_get_manager (self);
		module = gck_object_get_module (self);
		if (manager == gck_module_get_manager (module))
			gck_module_remove_token_object (module, transaction, self);
	}

	/* Forcefully dispose of the object once the transaction completes */
	gck_transaction_add (transaction, NULL, complete_destroy, g_object_ref (self));

	g_object_unref (self);
}
