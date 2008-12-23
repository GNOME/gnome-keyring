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

#include "gck-crypto.h"
#include "gck-public-key.h"
#include "gck-util.h"

#if 0
enum {
	PROP_0,
	PROP_PUBLIC_KEY
};

struct _GckPublicKeyPrivate {
};
#endif

G_DEFINE_TYPE (GckPublicKey, gck_public_key, GCK_TYPE_KEY);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static CK_RV
return_modulus_bits (GckPublicKey *self, CK_ATTRIBUTE_PTR attr)
{
	gcry_sexp_t numbers;
	gcry_mpi_t mpi;
	int algorithm;
	CK_RV rv;
	
	if (!gck_crypto_sexp_parse_key (gck_sexp_get (gck_key_get_base_sexp (GCK_KEY (self))),
	                                &algorithm, NULL, &numbers))
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	
	if (algorithm != GCRY_PK_RSA) {
		gcry_sexp_release (numbers);
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	
	g_assert (numbers);
	if (!gck_crypto_sexp_extract_mpi (numbers, &mpi, "n", NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	gcry_sexp_release (numbers);
	rv = gck_util_set_ulong (attr, gcry_mpi_get_nbits (mpi));
	gcry_mpi_release (mpi);

	return rv;
}

/* -----------------------------------------------------------------------------
 * PUBLIC_KEY 
 */

static CK_RV 
gck_public_key_real_get_attribute (GckObject *base, CK_ATTRIBUTE* attr)
{
	GckPublicKey *self = GCK_PUBLIC_KEY (base);
	
	switch (attr->type)
	{
	
	case CKA_CLASS:
		return gck_util_set_ulong (attr, CKO_PUBLIC_KEY);
	
	case CKA_ENCRYPT:
		return gck_util_set_bool (attr, gck_key_get_algorithm (GCK_KEY (self)) == GCRY_PK_RSA);
		
	case CKA_VERIFY:
		return gck_util_set_bool (attr, TRUE);
		
	case CKA_VERIFY_RECOVER:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_WRAP:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_TRUSTED:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_WRAP_TEMPLATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	case CKA_MODULUS_BITS:
		return return_modulus_bits (self, attr);
		
	case CKA_MODULUS:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_RSA, "n", attr);
		
	case CKA_PUBLIC_EXPONENT:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_RSA, "e", attr);
		
	case CKA_PRIME:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_DSA, "p", attr);
		
	case CKA_SUBPRIME:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_DSA, "q", attr);
		
	case CKA_BASE:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_DSA, "g", attr);
		
	/* DSA public value */
	case CKA_VALUE:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_DSA, "y", attr);
	};
	
	return GCK_OBJECT_CLASS (gck_public_key_parent_class)->get_attribute (base, attr);
}

#if 0
static CK_RV 
gck_public_key_real_set_attribute (GckPublicKey *public_key, const CK_ATTRIBUTE* attr)
{
	switch (attr->type) {
	/* TODO: CKA_LABEL */

	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
		return CKR_ATTRIBUTE_READ_ONLY;
		
	case CKA_CLASS:
		return CKR_ATTRIBUTE_READ_ONLY;
	};
	
	return CKA_ATTRIBUTE_TYPE_INVALID;
}
#endif

static GckSexp*
gck_public_key_acquire_crypto_sexp (GckKey *self)
{
	GckSexp* sexp;
	
	sexp = gck_key_get_base_sexp (self);
	if (sexp != NULL)
		gck_sexp_ref (sexp);
	
	return sexp;
}

static GObject* 
gck_public_key_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckPublicKey *self = GCK_PUBLIC_KEY (G_OBJECT_CLASS (gck_public_key_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	
	
	return G_OBJECT (self);
}

static void
gck_public_key_init (GckPublicKey *self)
{
#if 0
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_PUBLIC_KEY, GckPublicKeyPrivate);
#endif
}

static void
gck_public_key_dispose (GObject *obj)
{
#if 0
	GckPublicKey *self = GCK_PUBLIC_KEY (obj);
#endif
	G_OBJECT_CLASS (gck_public_key_parent_class)->dispose (obj);
}

static void
gck_public_key_finalize (GObject *obj)
{
#if 0
	GckPublicKey *self = GCK_PUBLIC_KEY (obj);
#endif
	G_OBJECT_CLASS (gck_public_key_parent_class)->finalize (obj);
}

static void
gck_public_key_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
#if 0
	GckPublicKey *self = GCK_PUBLIC_KEY (obj);
#endif
	
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_public_key_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
#if 0
	GckPublicKey *self = GCK_PUBLIC_KEY (obj);
#endif
	
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_public_key_class_init (GckPublicKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	GckKeyClass *key_class = GCK_KEY_CLASS (klass);
	
	gck_public_key_parent_class = g_type_class_peek_parent (klass);
#if 0
	g_type_class_add_private (klass, sizeof (GckPublicKeyPrivate));
#endif
	
	gobject_class->constructor = gck_public_key_constructor;
	gobject_class->dispose = gck_public_key_dispose;
	gobject_class->finalize = gck_public_key_finalize;
	gobject_class->set_property = gck_public_key_set_property;
	gobject_class->get_property = gck_public_key_get_property;
	
	gck_class->get_attribute = gck_public_key_real_get_attribute;
#if 0
	gck_class->set_attribute = gck_public_key_real_set_attribute;
#endif
	
	key_class->acquire_crypto_sexp = gck_public_key_acquire_crypto_sexp;
	
#if 0
	g_public_key_class_install_property (gobject_class, PROP_PUBLIC_KEY,
	           g_param_spec_pointer ("public_key", "PublicKey", "PublicKey.", G_PARAM_READWRITE));
    
	signals[SIGNAL] = g_signal_new ("signal", GCK_TYPE_PUBLIC_KEY, 
	                                G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GckPublicKeyClass, signal),
	                                NULL, NULL, g_cclosure_marshal_VOID__OBJECT, 
	                                G_TYPE_NONE, 0);
#endif
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */
