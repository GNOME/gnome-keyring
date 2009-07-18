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

#include "gck-user-public-key.h"

#include "gck/gck-attributes.h"
#include "gck/gck-data-der.h"
#include "gck/gck-factory.h"
#include "gck/gck-serializable.h"
#include "gck/gck-session.h"
#include "gck/gck-object.h"
#include "gck/gck-util.h"

#include <glib/gi18n.h>

struct _GckUserPublicKey {
	GckPublicKey parent;
};

static void gck_user_public_key_serializable (GckSerializableIface *iface);

G_DEFINE_TYPE_EXTENDED (GckUserPublicKey, gck_user_public_key, GCK_TYPE_PUBLIC_KEY, 0,
               G_IMPLEMENT_INTERFACE (GCK_TYPE_SERIALIZABLE, gck_user_public_key_serializable));

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
factory_create_public_key (GckSession *session, GckTransaction *transaction, 
                           CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, GckObject **object)
{
	GckSexp *sexp;
	
	g_return_if_fail (attrs || !n_attrs);
	g_return_if_fail (object);

	sexp = gck_public_key_create_sexp (session, transaction, attrs, n_attrs);
	if (sexp != NULL) {
		*object = g_object_new (GCK_TYPE_USER_PUBLIC_KEY, "base-sexp", sexp, 
		                        "module", gck_session_get_module (session), NULL);
		gck_sexp_unref (sexp);
	}
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static void
gck_user_public_key_init (GckUserPublicKey *self)
{
	
}

static void
gck_user_public_key_finalize (GObject *obj)
{
	/* GckUserPublicKey *self = GCK_USER_PUBLIC_KEY (obj); */
	G_OBJECT_CLASS (gck_user_public_key_parent_class)->finalize (obj);
}

static void
gck_user_public_key_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                  GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_user_public_key_get_property (GObject *obj, guint prop_id, GValue *value, 
                                  GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_user_public_key_class_init (GckUserPublicKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
	gobject_class->finalize = gck_user_public_key_finalize;
	gobject_class->set_property = gck_user_public_key_set_property;
	gobject_class->get_property = gck_user_public_key_get_property;
}


static gboolean
gck_user_public_key_real_load (GckSerializable *base, GckLogin *login, const guchar *data, gsize n_data)
{
	GckUserPublicKey *self = GCK_USER_PUBLIC_KEY (base);
	GckDataResult res;
	GckSexp *wrapper;
	gcry_sexp_t sexp;
	
	g_return_val_if_fail (GCK_IS_USER_PUBLIC_KEY (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	
	res = gck_data_der_read_public_key (data, n_data, &sexp);
	
	switch (res) {
	case GCK_DATA_LOCKED:
		g_message ("public key is locked");
		return FALSE;
	case GCK_DATA_FAILURE:
		g_message ("couldn't parse public key");
		return FALSE;
	case GCK_DATA_UNRECOGNIZED:
		g_message ("invalid or unrecognized public key");
		return FALSE;
	case GCK_DATA_SUCCESS:
		break;
	default:
		g_assert_not_reached();
	}

	wrapper = gck_sexp_new (sexp);
	gck_key_set_base_sexp (GCK_KEY (self), wrapper);
	gck_sexp_unref (wrapper);
	
	return TRUE;
}

static gboolean 
gck_user_public_key_real_save (GckSerializable *base, GckLogin *login, guchar **data, gsize *n_data)
{
	GckUserPublicKey *self = GCK_USER_PUBLIC_KEY (base);
	GckSexp *wrapper;

	g_return_val_if_fail (GCK_IS_USER_PUBLIC_KEY (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	wrapper = gck_key_get_base_sexp (GCK_KEY (self));
	g_return_val_if_fail (wrapper, FALSE);
	
	*data = gck_data_der_write_public_key (gck_sexp_get (wrapper), n_data);
	return *data != NULL;
}

static void 
gck_user_public_key_serializable (GckSerializableIface *iface)
{
	iface->extension = ".pub";
	iface->load = gck_user_public_key_real_load;
	iface->save = gck_user_public_key_real_save;
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckFactoryInfo*
gck_user_public_key_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
	static CK_BBOOL token = CK_TRUE;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_TOKEN, &token, sizeof (token) }, 
	};

	static GckFactoryInfo factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_public_key
	};
	
	return &factory;
}
