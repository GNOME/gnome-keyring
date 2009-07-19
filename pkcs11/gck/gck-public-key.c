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

#include "gck-attributes.h"
#include "gck-crypto.h"
#include "gck-factory.h"
#include "gck-public-key.h"
#include "gck-session.h"
#include "gck-transaction.h"
#include "gck-util.h"

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
	rv = gck_attribute_set_ulong (attr, gcry_mpi_get_nbits (mpi));
	gcry_mpi_release (mpi);

	return rv;
}

static CK_RV
create_rsa_public (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, gcry_sexp_t *skey)
{
	gcry_error_t gcry;
	gcry_mpi_t n = NULL;
	gcry_mpi_t e = NULL;
	CK_RV ret;
	
	if (!gck_attributes_find_mpi (attrs, n_attrs, CKA_MODULUS, &n) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_PUBLIC_EXPONENT, &e)) { 
	    	ret = CKR_TEMPLATE_INCOMPLETE;
	    	goto done;
	}
	
	gcry = gcry_sexp_build (skey, NULL, 
	                        "(public-key (rsa (n %m) (e %m)))", 
	                        n, e);

	if (gcry != 0) {
		g_message ("couldn't create RSA key from passed attributes: %s", gcry_strerror (gcry));
		ret = CKR_FUNCTION_FAILED;
		goto done;
	}
	
	gck_attributes_consume (attrs, n_attrs, CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_MODULUS_BITS, G_MAXULONG); 
	ret = CKR_OK;

done:
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	return ret;	
}

static CK_RV
create_dsa_public (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, gcry_sexp_t *skey)
{
	gcry_error_t gcry;
	gcry_mpi_t p = NULL;
	gcry_mpi_t q = NULL;
	gcry_mpi_t g = NULL;
	gcry_mpi_t y = NULL;
	CK_RV ret;
	
	if (!gck_attributes_find_mpi (attrs, n_attrs, CKA_PRIME, &p) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_SUBPRIME, &q) || 
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_BASE, &g) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_VALUE, &y)) {
	    	ret = CKR_TEMPLATE_INCOMPLETE;
	    	goto done;
	}
	
	gcry = gcry_sexp_build (skey, NULL, 
	                        "(public-key (dsa (p %m) (q %m) (g %m) (y %m)))",
	                        p, q, g, y);

	if (gcry != 0) {
		g_message ("couldn't create DSA key from passed attributes: %s", gcry_strerror (gcry));
		ret = CKR_FUNCTION_FAILED;
		goto done;
	}

	gck_attributes_consume (attrs, n_attrs, CKA_PRIME, CKA_SUBPRIME, 
	                        CKA_BASE, CKA_VALUE, G_MAXULONG);
	ret = CKR_OK;

done:
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	return ret;
}

static void
factory_create_public_key (GckSession *session, GckTransaction *transaction, 
                           CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, GckObject **object)
{
	GckSexp *sexp;
	
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (attrs || !n_attrs);
	g_return_if_fail (object);

	sexp = gck_public_key_create_sexp (session, transaction, attrs, n_attrs);
	if (sexp != NULL) {
		*object = g_object_new (GCK_TYPE_PUBLIC_KEY, "base-sexp", sexp, 
		                        "module", gck_session_get_module (session), NULL);
		gck_sexp_unref (sexp);
	}
}

/* -----------------------------------------------------------------------------
 * PUBLIC_KEY 
 */

static CK_RV 
gck_public_key_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE* attr)
{
	GckPublicKey *self = GCK_PUBLIC_KEY (base);
	
	switch (attr->type)
	{
	
	case CKA_CLASS:
		return gck_attribute_set_ulong (attr, CKO_PUBLIC_KEY);
	
	case CKA_ENCRYPT:
		return gck_attribute_set_bool (attr, gck_key_get_algorithm (GCK_KEY (self)) == GCRY_PK_RSA);
		
	case CKA_VERIFY:
		return gck_attribute_set_bool (attr, TRUE);
		
	case CKA_VERIFY_RECOVER:
		return gck_attribute_set_bool (attr, FALSE);
		
	case CKA_WRAP:
		return gck_attribute_set_bool (attr, FALSE);
		
	case CKA_TRUSTED:
		return gck_attribute_set_bool (attr, FALSE);
		
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
	
	return GCK_OBJECT_CLASS (gck_public_key_parent_class)->get_attribute (base, session, attr);
}

static GckSexp*
gck_public_key_acquire_crypto_sexp (GckKey *self, GckSession *session)
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

}

static void
gck_public_key_dispose (GObject *obj)
{
	G_OBJECT_CLASS (gck_public_key_parent_class)->dispose (obj);
}

static void
gck_public_key_finalize (GObject *obj)
{
	G_OBJECT_CLASS (gck_public_key_parent_class)->finalize (obj);
}

static void
gck_public_key_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
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
	
	gobject_class->constructor = gck_public_key_constructor;
	gobject_class->dispose = gck_public_key_dispose;
	gobject_class->finalize = gck_public_key_finalize;
	gobject_class->set_property = gck_public_key_set_property;
	gobject_class->get_property = gck_public_key_get_property;
	
	gck_class->get_attribute = gck_public_key_real_get_attribute;
	
	key_class->acquire_crypto_sexp = gck_public_key_acquire_crypto_sexp;
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckSexp*
gck_public_key_create_sexp (GckSession *session, GckTransaction *transaction, 
                            CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
 	CK_KEY_TYPE type;
 	gcry_sexp_t sexp;
 	CK_RV ret;
 
	g_return_val_if_fail (GCK_IS_TRANSACTION (transaction), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);

	if (!gck_attributes_find_ulong (attrs, n_attrs, CKA_KEY_TYPE, &type)) {
		gck_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
		return NULL;
	}
		
 	gck_attributes_consume (attrs, n_attrs, CKA_KEY_TYPE, CKA_CLASS, G_MAXULONG);

 	switch (type) {
	case CKK_RSA:
		ret = create_rsa_public (attrs, n_attrs, &sexp);
		break;
	case CKK_DSA:
		ret = create_dsa_public (attrs, n_attrs, &sexp);
		break;
	default:
		ret = CKR_ATTRIBUTE_VALUE_INVALID;
		break;
 	};

	if (ret != CKR_OK) {
		gck_transaction_fail (transaction, ret);
		return NULL;
	}
	
	g_return_val_if_fail (sexp, NULL);
	return gck_sexp_new (sexp);
}

GckFactoryInfo*
gck_public_key_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) }
	};

	static GckFactoryInfo factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_public_key
	};
	
	return &factory;
}
