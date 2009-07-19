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

#include "gck-user-private-key.h"

#include "gck/gck-attributes.h"
#include "gck/gck-crypto.h"
#include "gck/gck-data-der.h"
#include "gck/gck-factory.h"
#include "gck/gck-login.h"
#include "gck/gck-manager.h"
#include "gck/gck-object.h"
#include "gck/gck-serializable.h"
#include "gck/gck-session.h"
#include "gck/gck-sexp.h"
#include "gck/gck-util.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
};

struct _GckUserPrivateKey {
	GckPrivateKey parent;
	
	guchar *private_data;
	gsize n_private_data;
	
	GckSexp *private_sexp;
	gboolean is_encrypted;
	GckLogin *login;
};

static void gck_user_private_key_serializable (GckSerializableIface *iface);

G_DEFINE_TYPE_EXTENDED (GckUserPrivateKey, gck_user_private_key, GCK_TYPE_PRIVATE_KEY, 0,
               G_IMPLEMENT_INTERFACE (GCK_TYPE_SERIALIZABLE, gck_user_private_key_serializable));

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static void
factory_create_private_key (GckSession *session, GckTransaction *transaction, 
                            CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, GckObject **object)
{
	GckUserPrivateKey *key;
	GckSexp *sexp;
	
	g_return_if_fail (attrs || !n_attrs);
	g_return_if_fail (object);

	sexp = gck_private_key_create_sexp (session, transaction, attrs, n_attrs);
	if (sexp == NULL)
		return;
	
	key = g_object_new (GCK_TYPE_USER_PRIVATE_KEY, "base-sexp", sexp, 
	                    "module", gck_session_get_module (session), NULL);
	g_return_if_fail (!key->private_sexp);
	key->private_sexp = gck_sexp_ref (sexp);
	
	*object = GCK_OBJECT (key);
	gck_sexp_unref (sexp);
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV
gck_user_private_key_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	switch (attr->type) {
	case CKA_ALWAYS_AUTHENTICATE:
		return gck_attribute_set_bool (attr, FALSE);
	}
	
	return GCK_OBJECT_CLASS (gck_user_private_key_parent_class)->get_attribute (base, session, attr);
}

static GckSexp* 
gck_user_private_key_real_acquire_crypto_sexp (GckKey *base, GckSession *unused)
{
	GckUserPrivateKey *self = GCK_USER_PRIVATE_KEY (base);
	gcry_sexp_t sexp;
	GckDataResult res;
	const gchar *password;
	gsize n_password;
	
	/* Non encrypted case */
	if (self->private_sexp)
		return gck_sexp_ref (self->private_sexp);

	g_return_val_if_fail (self->login, NULL);
	g_return_val_if_fail (self->is_encrypted, NULL);
	
	password = gck_login_get_password (self->login, &n_password);
	res = gck_data_der_read_private_pkcs8 (self->private_data, self->n_private_data, 
	                                       password, n_password, &sexp);
	g_return_val_if_fail (res == GCK_DATA_SUCCESS, NULL);
	
	return gck_sexp_new (sexp);
}

static void
gck_user_private_key_init (GckUserPrivateKey *self)
{
	
}

static void
gck_user_private_key_dispose (GObject *obj)
{
	GckUserPrivateKey *self = GCK_USER_PRIVATE_KEY (obj);
	
	if (self->login)
		g_object_unref (self->login);
	self->login = NULL;
    
	G_OBJECT_CLASS (gck_user_private_key_parent_class)->dispose (obj);
}

static void
gck_user_private_key_finalize (GObject *obj)
{
	GckUserPrivateKey *self = GCK_USER_PRIVATE_KEY (obj);
	
	g_assert (self->login == NULL);
	
	g_free (self->private_data);
	self->private_data = NULL;
	
	if (self->private_sexp)
		gck_sexp_unref (self->private_sexp);
	self->private_sexp = NULL;
	
	G_OBJECT_CLASS (gck_user_private_key_parent_class)->finalize (obj);
}

static void
gck_user_private_key_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_user_private_key_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_user_private_key_class_init (GckUserPrivateKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	GckKeyClass *key_class = GCK_KEY_CLASS (klass);
	
	gobject_class->dispose = gck_user_private_key_dispose;
	gobject_class->finalize = gck_user_private_key_finalize;
	gobject_class->set_property = gck_user_private_key_set_property;
	gobject_class->get_property = gck_user_private_key_get_property;
	
	gck_class->get_attribute = gck_user_private_key_real_get_attribute;
	
	key_class->acquire_crypto_sexp = gck_user_private_key_real_acquire_crypto_sexp;
}

static gboolean
gck_user_private_key_real_load (GckSerializable *base, GckLogin *login, const guchar *data, gsize n_data)
{
	GckUserPrivateKey *self = GCK_USER_PRIVATE_KEY (base);
	GckDataResult res;
	gcry_sexp_t sexp, pub;
	GckSexp *wrapper;
	const gchar *password;
	gsize n_password;

	g_return_val_if_fail (GCK_IS_USER_PRIVATE_KEY (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	
	res = gck_data_der_read_private_pkcs8 (data, n_data, NULL, 0, &sexp);
	
	/* An unencrypted pkcs8 file */
	if (res == GCK_DATA_SUCCESS) {
		self->is_encrypted = FALSE;
	
	/* If it's locked, then use our token password */
	} else if (res == GCK_DATA_LOCKED) {
		self->is_encrypted = TRUE;
		
		if (!login) {
			g_message ("encountered private key but no private key present");
			return FALSE;
		}
	
		password = gck_login_get_password (login, &n_password);
		res = gck_data_der_read_private_pkcs8 (data, n_data, password, n_password, &sexp);
	}

	switch (res) {
	case GCK_DATA_LOCKED:
		g_message ("private key is encrypted with wrong password");
		return FALSE;
	case GCK_DATA_FAILURE:
		g_message ("couldn't parse private key");
		return FALSE;
	case GCK_DATA_UNRECOGNIZED:
		g_message ("invalid or unrecognized private key");
		return FALSE;
	case GCK_DATA_SUCCESS:
		break;
	default:
		g_assert_not_reached();
	}
	
	/* Calculate a public key as our 'base' */
	if (!gck_crypto_sexp_key_to_public (sexp, &pub))
		g_return_val_if_reached (FALSE);
	
	/* Keep the public part of the key around for answering queries */
	wrapper = gck_sexp_new (pub);
	gck_key_set_base_sexp (GCK_KEY (self), wrapper);
	gck_sexp_unref (wrapper);
	
	/* Encrypted private key, keep login and data */
	if (self->is_encrypted) {
		g_free (self->private_data);
		self->n_private_data = n_data;
		self->private_data = g_memdup (data, n_data);
		
		g_object_ref (login);
		if (self->login)
			g_object_unref (self->login);
		self->login = login;

		/* Don't need the private key any more */
		gcry_sexp_release (sexp);

	/* Not encrypted, just keep the parsed key */
	} else {
		wrapper = gck_sexp_new (sexp);
		if (self->private_sexp)
			gck_sexp_unref (self->private_sexp);
		self->private_sexp = wrapper;
		
		if (self->login)
			g_object_unref (login);
		self->login = NULL;
	}
	
	return TRUE;
}

static gboolean 
gck_user_private_key_real_save (GckSerializable *base, GckLogin *login, guchar **data, gsize *n_data)
{
	GckUserPrivateKey *self = GCK_USER_PRIVATE_KEY (base);
	const gchar *password;
	gsize n_password;
	GckSexp *sexp;
	
	g_return_val_if_fail (GCK_IS_USER_PRIVATE_KEY (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);
	
	sexp = gck_user_private_key_real_acquire_crypto_sexp (GCK_KEY (self), NULL);
	g_return_val_if_fail (sexp, FALSE);
	
	password = gck_login_get_password (login, &n_password);
	if (password == NULL) 
		*data = gck_data_der_write_private_pkcs8_plain (gck_sexp_get (sexp), n_data);
	else
		*data = gck_data_der_write_private_pkcs8_crypted (gck_sexp_get (sexp), password,
		                                                  n_password, n_data);
	
	gck_sexp_unref (sexp);
	return *data != NULL;
}

static void 
gck_user_private_key_serializable (GckSerializableIface *iface)
{
	iface->extension = ".pkcs8";
	iface->load = gck_user_private_key_real_load;
	iface->save = gck_user_private_key_real_save;
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckFactoryInfo*
gck_user_private_key_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
	static CK_BBOOL token = CK_TRUE;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_TOKEN, &token, sizeof (token) }, 
	};

	static GckFactoryInfo factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_private_key
	};
	
	return &factory;
}
