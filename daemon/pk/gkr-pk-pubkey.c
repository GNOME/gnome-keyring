/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-pubkey.c - A PK public key

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
#include "gkr-pk-index.h"
#include "gkr-pk-object.h"
#include "gkr-pk-manager.h"
#include "gkr-pk-pubkey.h"
#include "gkr-pk-storage.h"
#include "gkr-pk-util.h"

#include "common/gkr-crypto.h"
#include "common/gkr-id.h"
#include "common/gkr-location.h"

#include "pkix/gkr-pkix-der.h"
#include "pkix/gkr-pkix-serialize.h"

#include <glib.h>
#include <glib-object.h>

#include <gcrypt.h>

#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------------------
 * DECLARATIONS
 */

enum {
	PROP_0,
	PROP_GCRYPT_SEXP
};

struct _GkrPkPubkeyData {
	int algorithm;
	gkrid keyid;
	gcry_sexp_t s_key;
	gcry_sexp_t numbers;
};

G_DEFINE_TYPE (GkrPkPubkey, gkr_pk_pubkey, GKR_TYPE_PK_OBJECT);

/* -------------------------------------------------------------------------------------
 * HELPERS
 */

static void
initialize_from_key (GkrPkPubkey *key)
{
	gcry_sexp_t numbers;
	gboolean is_priv;
	int algorithm;
	
	gcry_sexp_release (key->pub->numbers);
	key->pub->numbers = NULL;
	
	gkr_id_free (key->pub->keyid);
	key->pub->keyid = NULL;
	
	key->pub->algorithm = 0; 
	
	if (!key->pub->s_key)
		return;
		
	/* Parse it into handy parts */
	if (!gkr_crypto_skey_parse (key->pub->s_key, &algorithm, &is_priv, &numbers))
		g_return_if_reached ();

	g_return_if_fail (!is_priv);	
	g_assert (numbers);
	g_assert (algorithm);
	
	key->pub->numbers = numbers;
	key->pub->algorithm = algorithm;
	key->pub->keyid = gkr_crypto_skey_make_id (key->pub->s_key);
	
	/* Make sure any cache data is current */	
	gkr_pk_object_flush (GKR_PK_OBJECT (key));
}

static gboolean
load_public_key (GkrPkPubkey *key)
{
	GError *err = NULL;
	GkrPkObject *obj;

	if (key->pub->s_key)
		return TRUE;
		
	obj = GKR_PK_OBJECT (key);
	
	if (!gkr_pk_storage_load (obj->storage, obj, &err)) {
		g_message ("couldn't load public key for: %s: %s", 
		           g_quark_to_string (obj->location),
		           err && err->message ? err->message : "");
		g_error_free (err);
		return FALSE;
	}

	/* This can happen if the user cancels out of a dialog */
	if (!key->pub->s_key)
		return FALSE;

	return TRUE;
}

static CK_RV
create_rsa_public (GArray *attrs, gcry_sexp_t *skey)
{
	gcry_error_t gcry;
	gcry_mpi_t n = NULL;
	gcry_mpi_t e = NULL;
	CK_RV ret;
	
	if (!gkr_pk_attributes_mpi (attrs, CKA_MODULUS, &n) ||
	    !gkr_pk_attributes_mpi (attrs, CKA_PUBLIC_EXPONENT, &e)) {
	    	ret = CKR_TEMPLATE_INCOMPLETE;
	    	goto done;
	}		
	
	gcry = gcry_sexp_build (skey, NULL, 
	                        "(public-key (rsa (n %m) (e %m)))", n, e);

	/* TODO: We should be mapping better return codes */
	if (gcry != 0) {
		g_message ("couldn't create RSA key from passed attributes");
		ret = CKR_FUNCTION_FAILED;
		goto done;
	}
	
	gkr_pk_attributes_consume (attrs, CKA_MODULUS, CKA_PUBLIC_EXPONENT, -1);
	ret = CKR_OK;

done:
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	return ret;	
}

static CK_RV
create_dsa_public (GArray *attrs, gcry_sexp_t *skey)
{
	gcry_error_t gcry;
	gcry_mpi_t p = NULL;
	gcry_mpi_t q = NULL;
	gcry_mpi_t g = NULL;
	gcry_mpi_t value = NULL;
	CK_RV ret;
	
	if (!gkr_pk_attributes_mpi (attrs, CKA_PRIME, &p) ||
	    !gkr_pk_attributes_mpi (attrs, CKA_SUBPRIME, &q) || 
	    !gkr_pk_attributes_mpi (attrs, CKA_BASE, &g) ||
	    !gkr_pk_attributes_mpi (attrs, CKA_VALUE, &value)) {
	    	ret = CKR_TEMPLATE_INCOMPLETE;
	    	goto done;
	}
	    
	gcry = gcry_sexp_build (skey, NULL, 
	                        "(public-key (dsa (p %m) (q %m) (g %m) (y %m)))",
	                        p, q, g, value);	    		

	/* TODO: We should be mapping better return codes */
	if (gcry != 0) {
		g_message ("couldn't create DSA key from passed attributes");
		ret = CKR_FUNCTION_FAILED;
		goto done;
	}
	
	gkr_pk_attributes_consume (attrs, CKA_PRIME, CKA_SUBPRIME, 
	                           CKA_BASE, CKA_VALUE, -1);
	ret = CKR_OK;
	
done:
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (value);
	return ret;
}

static CK_RV
attribute_from_related (GkrPkPubkey *key, GType type, CK_ATTRIBUTE_PTR attr)
{
	GkrPkObject *crt, *obj;
	
	if (!load_public_key (key))
		return CKR_FUNCTION_FAILED;
	
	obj = GKR_PK_OBJECT (key);	
	crt = gkr_pk_manager_find_by_id (obj->manager, type, key->pub->keyid);
	
	if (crt == NULL)
		return CKR_FUNCTION_FAILED;
		
	return gkr_pk_object_get_attribute (crt, attr);
}

static CK_RV
extract_key_mpi (GkrPkPubkey *key, int algorithm, const char *part, CK_ATTRIBUTE_PTR attr)
{
	gcry_mpi_t mpi;
	gboolean ret;
	
	if (!load_public_key (key))
		return CKR_FUNCTION_FAILED;
	
	if (key->pub->algorithm != algorithm)
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	g_assert (key->pub->numbers);
	ret = gkr_crypto_sexp_extract_mpi (key->pub->numbers, &mpi, part, NULL);
	g_return_val_if_fail (ret, CKR_GENERAL_ERROR);
	gkr_pk_attribute_set_mpi (attr, mpi);
	gcry_mpi_release (mpi);
	return CKR_OK;
}

static CK_RV
extract_key_value (GkrPkPubkey *key, CK_ATTRIBUTE_PTR attr)
{
	guchar *data;
	gsize n_data;
	
	if (!load_public_key (key))
		return CKR_FUNCTION_FAILED;
	
	switch (gkr_pk_pubkey_get_algorithm (key)) {
	case GCRY_PK_RSA:
		data = gkr_pkix_der_write_public_key_rsa (key->pub->s_key, &n_data);
		g_return_val_if_fail (data, CKR_GENERAL_ERROR);
		
		gkr_pk_attribute_set_data (attr, data, n_data);
		g_free (data);
		return CKR_OK;
		
	case GCRY_PK_DSA:
		return extract_key_mpi (key, GCRY_PK_DSA, "y", attr);
			
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
}

/* -------------------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_pubkey_init (GkrPkPubkey *key)
{
	key->pub = G_TYPE_INSTANCE_GET_PRIVATE (key, GKR_TYPE_PK_PUBKEY, GkrPkPubkeyData);
	memset (key->pub, 0, sizeof (GkrPkPubkeyData));
}

static void
gkr_pk_pubkey_get_property (GObject *obj, guint prop_id, GValue *value, 
                            GParamSpec *pspec)
{
	GkrPkPubkey *key = GKR_PK_PUBKEY (obj);

	switch (prop_id) {
	case PROP_GCRYPT_SEXP:
		g_value_set_pointer (value, key->pub->s_key);
		break;
	}
}

static void
gkr_pk_pubkey_set_property (GObject *obj, guint prop_id, const GValue *value, 
                            GParamSpec *pspec)
{
	GkrPkPubkey *key = GKR_PK_PUBKEY (obj);
	
	switch (prop_id) {
	case PROP_GCRYPT_SEXP:
		if (key->pub->s_key)
			gcry_sexp_release (key->pub->s_key);
		key->pub->s_key = (gcry_sexp_t)g_value_get_pointer (value);
		initialize_from_key (key);
		break;
	}
}

static CK_RV
gkr_pk_pubkey_get_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkPubkey *key = GKR_PK_PUBKEY (obj);
	gcry_mpi_t mpi;
	CK_RV ret;
	
	switch (attr->type)
	{
	case CKA_ENCRYPT:
	case CKA_EXTRACTABLE:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
		gkr_pk_attribute_set_boolean (attr, CK_TRUE);
		return CKR_OK;
	
	case CKA_ALWAYS_AUTHENTICATE:
	case CKA_DERIVE:
	case CKA_PRIVATE:
	case CKA_SENSITIVE:
	case CKA_WRAP:
	case CKA_WRAP_WITH_TRUSTED:
		gkr_pk_attribute_set_boolean (attr, CK_FALSE);
		return CKR_OK;
		
	/* TODO: Use our definition of trusted */
	case CKA_TRUSTED:
		gkr_pk_attribute_set_boolean (attr, CK_FALSE);
		return CKR_OK;
		
	/* TODO: Perhaps we can detect this in some way */
	case CKA_LOCAL:
		gkr_pk_attribute_set_boolean (attr, CK_FALSE);
		return CKR_OK;
		
	case CKA_CLASS:
		gkr_pk_attribute_set_ulong (attr, CKO_PUBLIC_KEY);
		return CKR_OK;
		
	case CKA_KEY_TYPE:
		if (!load_public_key (key))
			return CKR_FUNCTION_FAILED;
		switch (key->pub->algorithm) {
		case GCRY_PK_RSA:
			gkr_pk_attribute_set_ulong (attr, CKK_RSA);
			break;
		case GCRY_PK_DSA:
			gkr_pk_attribute_set_ulong (attr, CKK_DSA);
			break;
		default:
			g_return_val_if_reached (CKR_GENERAL_ERROR);
			break;
		}
		return CKR_OK;
	
	case CKA_MODULUS_BITS:
		if (!load_public_key (key))
			return CKR_FUNCTION_FAILED;
		if (key->pub->algorithm != GCRY_PK_RSA)
			return CKR_ATTRIBUTE_TYPE_INVALID;
		g_assert (key->pub->numbers);
		ret = gkr_crypto_sexp_extract_mpi (key->pub->numbers, &mpi, "n", NULL);
		g_return_val_if_fail (ret, CKR_GENERAL_ERROR);
		gkr_pk_attribute_set_ulong (attr, gcry_mpi_get_nbits (mpi));
		gcry_mpi_release (mpi);
		return CKR_OK;
		
	/* TODO: Once we can generate keys, this should change */
	case CKA_KEY_GEN_MECHANISM:
		gkr_pk_attribute_set_ulong (attr, CK_UNAVAILABLE_INFORMATION);
		return CKR_OK;
		
	case CKA_ID:
		/* Always a SHA-1 hash output buffer */
		if (!load_public_key (key) || !key->pub->keyid)
			return CKR_FUNCTION_FAILED;
		gkr_pk_attribute_set_id (attr, key->pub->keyid);
		return CKR_OK;

	case CKA_SUBJECT:
		/* The subject of a related certificate */
		if (attribute_from_related (key, GKR_TYPE_PK_CERT, attr) == CKR_OK)
			return CKR_OK;
			
		/* Empty subject */
		gkr_pk_attribute_clear (attr);
		return CKR_OK;

	case CKA_MODULUS:
		return extract_key_mpi (key, GCRY_PK_RSA, "n", attr);
		
	case CKA_PUBLIC_EXPONENT:
		return extract_key_mpi (key, GCRY_PK_RSA, "e", attr);
	
	case CKA_PRIME:
		return extract_key_mpi (key, GCRY_PK_DSA, "p", attr);
		
	case CKA_SUBPRIME:
		return extract_key_mpi (key, GCRY_PK_DSA, "q", attr);
		
	case CKA_BASE:
		return extract_key_mpi (key, GCRY_PK_DSA, "g", attr);
	
	case CKA_VALUE:
		return extract_key_value (key, attr);
	
	case CKA_ALLOWED_MECHANISMS:
		return gkr_pk_pubkey_allowed_mechanisms (key->pub->algorithm, attr);
		
	case CKA_UNWRAP_TEMPLATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	/* These will be empty */
	case CKA_START_DATE:
	case CKA_END_DATE:
		gkr_pk_attribute_set_data(attr, "", 0);
		return CKR_OK;
	
	default:
		break;
	};

	return GKR_PK_OBJECT_CLASS (gkr_pk_pubkey_parent_class)->get_attribute (obj, attr);
}

static guchar*
gkr_pk_pubkey_serialize (GkrPkObject *obj, const gchar *password, gsize *n_data)
{
	GkrPkPubkey *key = GKR_PK_PUBKEY (obj);
	
	if (!load_public_key (key))
		return NULL;
		
	g_return_val_if_fail (key->pub->s_key, NULL);
	
	/* Write it to the indexes */
	return gkr_pkix_serialize_public_key (key->pub->s_key, n_data);
}

static void
gkr_pk_pubkey_finalize (GObject *obj)
{
	GkrPkPubkey *key = GKR_PK_PUBKEY (obj);

	gcry_sexp_release (key->pub->s_key);
	key->pub->s_key = NULL;
	
	initialize_from_key (key);
	g_assert (!key->pub->numbers);
	g_assert (!key->pub->keyid);
	
	G_OBJECT_CLASS (gkr_pk_pubkey_parent_class)->finalize (obj);
}

static void
gkr_pk_pubkey_class_init (GkrPkPubkeyClass *klass)
{
	GObjectClass *gobject_class;
	GkrPkObjectClass *parent_class;

	gkr_pk_pubkey_parent_class = g_type_class_peek_parent (klass);
	
	parent_class = GKR_PK_OBJECT_CLASS (klass);
	parent_class->get_attribute = gkr_pk_pubkey_get_attribute;
	parent_class->serialize = gkr_pk_pubkey_serialize;
	
	gobject_class = (GObjectClass*)klass;
	gobject_class->get_property = gkr_pk_pubkey_get_property;
	gobject_class->set_property = gkr_pk_pubkey_set_property;
	gobject_class->finalize = gkr_pk_pubkey_finalize;
	
	g_object_class_install_property (gobject_class, PROP_GCRYPT_SEXP,
		g_param_spec_pointer ("gcrypt-sexp", "Key", "S-Expression key",
		                      G_PARAM_READWRITE));
		                      
	g_type_class_add_private (klass, sizeof (GkrPkPubkeyData));
}

GkrPkObject*
gkr_pk_pubkey_new (GkrPkManager *manager, GQuark location, gcry_sexp_t s_key)
{
	GkrPkObject *key;
	guchar hash[20];
	gkrid digest; 
	
	g_return_val_if_fail (GKR_IS_PK_MANAGER (manager), NULL);
	g_return_val_if_fail (s_key != NULL, NULL);
	
	if (!gcry_pk_get_keygrip (s_key, hash))
		g_return_val_if_reached (NULL);
	
	/* We need to create a digest for this key */
	digest = gkr_id_new_digestv ((const guchar*)"public-key", 10, hash, 20, NULL);
	
	key = g_object_new (GKR_TYPE_PK_PUBKEY, "manager", manager, "location", location, 
	                    "gcrypt-sexp", s_key, "digest", digest, NULL);
	                    
	gkr_id_free (digest);
	return key;
}

GkrPkPubkey*
gkr_pk_pubkey_instance (GkrPkManager *manager, GQuark location, gcry_sexp_t s_key)
{
	GkrPkObject *pub;
	gkrid keyid;
	
	g_return_val_if_fail (s_key, NULL);
	g_return_val_if_fail (GKR_IS_PK_MANAGER (manager), NULL);
	
	/* Make sure we have the keyid properly */
	keyid = gkr_crypto_skey_make_id (s_key);
	g_return_val_if_fail (keyid, NULL);
	
	/* Try the lookup */
	pub = gkr_pk_manager_find_by_id (manager, GKR_TYPE_PK_PUBKEY, keyid);
	gkr_id_free (keyid);
	
	if (pub != NULL) {
		gcry_sexp_release (s_key);
		g_object_ref (pub);
		return GKR_PK_PUBKEY (pub);
	}
	
	pub = gkr_pk_pubkey_new (manager, location, s_key);
	return GKR_PK_PUBKEY (pub);
}

CK_RV
gkr_pk_pubkey_create (GkrPkManager* manager, GArray* array, 
                      GkrPkObject **object)
{
 	CK_KEY_TYPE type;
 	gcry_sexp_t sexp;
 	CK_RV ret;
 	
	g_return_val_if_fail (GKR_IS_PK_MANAGER (manager), CKR_GENERAL_ERROR);
	g_return_val_if_fail (array, CKR_GENERAL_ERROR);
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);
	
	*object = NULL;
	
	if (!gkr_pk_attributes_ulong (array, CKA_KEY_TYPE, &type))
 		return CKR_TEMPLATE_INCOMPLETE;
 	gkr_pk_attributes_consume (array, CKA_KEY_TYPE, -1);

 	switch (type) {
	case CKK_RSA:
		ret = create_rsa_public (array, &sexp);
		break;
	case CKK_DSA:
		ret = create_dsa_public (array, &sexp);
		break;
	default:
		return CKR_ATTRIBUTE_VALUE_INVALID;
 	};

	if (ret != CKR_OK)
		return ret;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);	
	*object = gkr_pk_pubkey_new (manager, 0, sexp);
	
	return CKR_OK;
}

gkrconstid
gkr_pk_pubkey_get_keyid (GkrPkPubkey *key)
{
	g_return_val_if_fail (GKR_IS_PK_PUBKEY (key), NULL);
	if (!load_public_key (key) || !key->pub->keyid)
		return NULL;
	return key->pub->keyid;
}

gcry_sexp_t 
gkr_pk_pubkey_get_key (GkrPkPubkey *key)
{
	g_return_val_if_fail (GKR_IS_PK_PUBKEY (key), NULL);
	if (!load_public_key (key))
		return NULL;
	return key->pub->s_key;
}

int
gkr_pk_pubkey_get_algorithm (GkrPkPubkey *key)
{
	g_return_val_if_fail (GKR_IS_PK_PUBKEY (key), 0);
	if (!load_public_key (key))
		return 0;
	return key->pub->algorithm;
}

CK_RV
gkr_pk_pubkey_allowed_mechanisms (int algorithm, CK_ATTRIBUTE_PTR attr)
{
	CK_MECHANISM_TYPE mechanisms[3];
	CK_ULONG n_mechanisms;
	
	g_return_val_if_fail (attr, CKR_GENERAL_ERROR);
	
	switch (algorithm) {
	case GCRY_PK_RSA:
		mechanisms[0] = CKM_RSA_PKCS;
		mechanisms[1] = CKM_RSA_X_509;
		n_mechanisms = 2;
		break;
	case GCRY_PK_DSA:
		mechanisms[0] = CKM_DSA;
		n_mechanisms = 1;
		break;
	default:
		n_mechanisms = 0;
		break;
	}
	
	gkr_pk_attribute_set_data (attr, mechanisms, sizeof(CK_MECHANISM_TYPE) * n_mechanisms);
	return CKR_OK;
}
