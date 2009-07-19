/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
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
#include "gck-authenticator.h"
#include "gck-login.h"
#include "gck-session.h"
#include "gck-transaction.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"

enum {
	PROP_0,
	PROP_OBJECT,
	PROP_LOGIN,
	PROP_USES_REMAINING
};

struct _GckAuthenticatorPrivate {

	/* The object we authenticated */
	GckObject *object;
	
	/* Optional login */
	GckLogin *login;
	
	/* Can limit by number of uses remaining */
	gint uses_remaining;
};

G_DEFINE_TYPE (GckAuthenticator, gck_authenticator, GCK_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static void
factory_create_authenticator (GckSession *session, GckTransaction *transaction, 
                              CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, GckObject **result)
{
	CK_OBJECT_HANDLE handle;
	GckAuthenticator *auth;
	CK_ATTRIBUTE *attr;
	GckObject *object;
	CK_RV rv;
	
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (attrs || !n_attrs);
	g_return_if_fail (result);

	/* The handle is required */
	if (!gck_attributes_find_ulong (attrs, n_attrs, CKA_GNOME_OBJECT, &handle)) {
		gck_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
		return;
	}

	/* Must be a valid object */
	rv = gck_session_lookup_readable_object (session, handle, &object);
	if (rv != CKR_OK) {
		gck_transaction_fail (transaction, rv);
		return;
	}
	
	/* The value is optional */
	attr = gck_attributes_find (attrs, n_attrs, CKA_VALUE);

 	gck_attributes_consume (attrs, n_attrs, CKA_VALUE, CKA_GNOME_OBJECT, G_MAXULONG);
	
	rv = gck_authenticator_create (object, attr ? attr->pValue : NULL, 
	                               attr ? attr->ulValueLen : 0, &auth);
	if (rv == CKR_OK)
		*result = GCK_OBJECT (auth);
	else
		gck_transaction_fail (transaction, rv);
}

static void
self_destruct (GckAuthenticator *self)
{
	GckTransaction *transaction;
	CK_RV rv;
	
	g_assert (GCK_IS_AUTHENTICATOR (self));
	
	transaction = gck_transaction_new ();

	/* Destroy ourselves */
	gck_object_destroy (GCK_OBJECT (self), transaction);
	
	gck_transaction_complete (transaction);
	rv = gck_transaction_get_result (transaction);
	g_object_unref (transaction);

	if (rv != CKR_OK)
		g_warning ("Couldn't destroy authenticator object: (code %lu)", (gulong)rv);
}

static void
object_went_away (gpointer data, GObject *old_object)
{
	GckAuthenticator *self = data;
	g_return_if_fail (GCK_IS_AUTHENTICATOR (self));
	self->pv->object = NULL;
	self_destruct (self);
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV 
gck_authenticator_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE *attr)
{
	GckAuthenticator *self = GCK_AUTHENTICATOR (base);

	switch (attr->type) {

	case CKA_CLASS:
		return gck_attribute_set_ulong (attr, CKO_GNOME_AUTHENTICATOR);

	case CKA_PRIVATE:
		return gck_attribute_set_bool (attr, TRUE);

	case CKA_GNOME_OBJECT:
		g_return_val_if_fail (self->pv->object, CKR_GENERAL_ERROR);
		return gck_attribute_set_ulong (attr, gck_object_get_handle (self->pv->object));

	case CKA_GNOME_USES_REMAINING:
		if (self->pv->uses_remaining < 0)
			return gck_attribute_set_ulong (attr, (CK_ULONG)-1);
		else
			return gck_attribute_set_ulong (attr, self->pv->uses_remaining);
		
	case CKA_VALUE:
		return CKR_ATTRIBUTE_SENSITIVE;
	};

	return GCK_OBJECT_CLASS (gck_authenticator_parent_class)->get_attribute (base, session, attr);
}

static GObject* 
gck_authenticator_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckAuthenticator *self = GCK_AUTHENTICATOR (G_OBJECT_CLASS (gck_authenticator_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	

	g_return_val_if_fail (self->pv->object, NULL);

	return G_OBJECT (self);
}

static void
gck_authenticator_init (GckAuthenticator *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_AUTHENTICATOR, GckAuthenticatorPrivate);
	self->pv->uses_remaining = -1;
}

static void
gck_authenticator_dispose (GObject *obj)
{
	GckAuthenticator *self = GCK_AUTHENTICATOR (obj);

	if (self->pv->object)
		g_object_weak_unref (G_OBJECT (self->pv->object), object_went_away, self);
	self->pv->object = NULL;
	
	if (self->pv->login)
		g_object_unref (self->pv->login);
	self->pv->login = NULL;
	
	G_OBJECT_CLASS (gck_authenticator_parent_class)->dispose (obj);
}

static void
gck_authenticator_finalize (GObject *obj)
{
	GckAuthenticator *self = GCK_AUTHENTICATOR (obj);
	
	g_assert (!self->pv->object);
	g_assert (!self->pv->login);

	G_OBJECT_CLASS (gck_authenticator_parent_class)->finalize (obj);
}

static void
gck_authenticator_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                GParamSpec *pspec)
{
	GckAuthenticator *self = GCK_AUTHENTICATOR (obj);
	
	switch (prop_id) {
	case PROP_OBJECT:
		g_return_if_fail (!self->pv->object);
		self->pv->object = g_value_get_object (value);
		g_return_if_fail (GCK_IS_OBJECT (self->pv->object));
		g_object_weak_ref (G_OBJECT (self->pv->object), object_went_away, self);
		break;
	case PROP_LOGIN:
		gck_authenticator_set_login (self, g_value_get_object (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_authenticator_get_property (GObject *obj, guint prop_id, GValue *value, 
                              GParamSpec *pspec)
{
	GckAuthenticator *self = GCK_AUTHENTICATOR (obj);
	
	switch (prop_id) {
	case PROP_OBJECT:
		g_value_set_object (value, gck_authenticator_get_object (self));
		break;
	case PROP_LOGIN:
		g_value_set_object (value, gck_authenticator_get_login (self));
		break;
	case PROP_USES_REMAINING:
		g_value_set_int (value, gck_authenticator_get_uses_remaining (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_authenticator_class_init (GckAuthenticatorClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	
	gck_authenticator_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GckAuthenticatorPrivate));

	gobject_class->constructor = gck_authenticator_constructor;
	gobject_class->dispose = gck_authenticator_dispose;
	gobject_class->finalize = gck_authenticator_finalize;
	gobject_class->set_property = gck_authenticator_set_property;
	gobject_class->get_property = gck_authenticator_get_property;
	
	gck_class->get_attribute = gck_authenticator_real_get_attribute;
    
	g_object_class_install_property (gobject_class, PROP_OBJECT,
	           g_param_spec_object ("object", "Object", "Object authenticated", 
	                                GCK_TYPE_OBJECT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_LOGIN,
	           g_param_spec_object ("login", "Login", "Optiontal login", 
	                                GCK_TYPE_LOGIN, G_PARAM_READWRITE));
	
	g_object_class_install_property (gobject_class, PROP_USES_REMAINING,
	           g_param_spec_int ("uses-remaining", "Uses Remaining", "Uses remaining",
	                             -1, G_MAXINT, -1, G_PARAM_READWRITE));
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckFactoryInfo*
gck_authenticator_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_GNOME_AUTHENTICATOR;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
	};

	static GckFactoryInfo factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_authenticator
	};
	
	return &factory;
}

CK_RV
gck_authenticator_create (GckObject *object, CK_UTF8CHAR_PTR pin,
                          CK_ULONG n_pin, GckAuthenticator **result)
{
	GckAuthenticator *auth;
	GckLogin *login = NULL;
	CK_RV rv;
	
	g_return_val_if_fail (GCK_IS_OBJECT (object), CKR_GENERAL_ERROR);
	g_return_val_if_fail (result, CKR_GENERAL_ERROR);
	
	if (pin != NULL)
		login = gck_login_new (pin, n_pin);
	
	auth = g_object_new (GCK_TYPE_AUTHENTICATOR, 
	                     "module", gck_object_get_module (object), 
	                     "login", login, "object", object, NULL);
	
	/* Now the unlock must work */
	rv = gck_object_unlock (object, auth);
	if (rv == CKR_OK)
		*result = auth;
	else
		g_object_unref (auth);
	
	return rv;
}

GckLogin*
gck_authenticator_get_login (GckAuthenticator *self)
{
	g_return_val_if_fail (GCK_IS_AUTHENTICATOR (self), NULL);
	return self->pv->login;
}

void
gck_authenticator_set_login (GckAuthenticator *self, GckLogin *login)
{
	g_return_if_fail (GCK_IS_AUTHENTICATOR (self));
	
	if (login) {
		g_return_if_fail (GCK_IS_LOGIN (login));
		g_object_ref (login);
	}
	if (self->pv->login)
		g_object_unref (self->pv->login);
	self->pv->login = login;
	
	g_object_notify (G_OBJECT (self), "login");
}

const gchar*
gck_authenticator_get_password (GckAuthenticator *self, gsize *n_password)
{
	g_return_val_if_fail (GCK_IS_AUTHENTICATOR (self), NULL);
	g_return_val_if_fail (n_password, NULL);
	
	if (!self->pv->login) {
		*n_password = 0;
		return NULL;
	}
	
	return gck_login_get_password (self->pv->login, n_password);	
}

GckObject*
gck_authenticator_get_object (GckAuthenticator *self)
{
	g_return_val_if_fail (GCK_IS_AUTHENTICATOR (self), NULL);
	g_return_val_if_fail (GCK_IS_OBJECT (self->pv->object), NULL);
	return self->pv->object;
}

gint
gck_authenticator_get_uses_remaining (GckAuthenticator *self)
{
	g_return_val_if_fail (GCK_IS_AUTHENTICATOR (self), 0);
	return self->pv->uses_remaining;
}

void
gck_authenticator_set_uses_remaining (GckAuthenticator *self,
                                      gint use_count)
{
	g_return_if_fail (GCK_IS_AUTHENTICATOR (self));
	g_return_if_fail (use_count != 0);
	
	self->pv->uses_remaining = use_count;
	g_object_notify (G_OBJECT (self), "uses-remaining");
}

void
gck_authenticator_throw_away_one_use (GckAuthenticator *self)
{
	g_return_if_fail (GCK_IS_AUTHENTICATOR (self));
	if (self->pv->uses_remaining > 0)
		--(self->pv->uses_remaining);
	if (self->pv->uses_remaining == 0)
		self_destruct (self);
}
