/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-privkey.c - An PK private key

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
#include "gkr-pk-object-manager.h"
#include "gkr-pk-object-storage.h"
#include "gkr-pk-privkey.h"
#include "gkr-pk-pubkey.h"
#include "gkr-pk-util.h"

#include "common/gkr-crypto.h"
#include "common/gkr-id.h"
#include "common/gkr-location.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"

#include "pkix/gkr-pkix-der.h"
#include "pkix/gkr-pkix-serialize.h"

#include <glib.h>
#include <glib-object.h>

#include <gcrypt.h>

#include <stdio.h>
#include <string.h>

#define SSH_AUTHENTICATION (g_quark_from_static_string ("ssh-authentication"))

/* -------------------------------------------------------------------------------------
 * DECLARATIONS
 */

enum {
	PROP_0,
	PROP_GCRYPT_SEXP
};

struct _GkrPkPrivkeyData {
	int algorithm;
	GkrPkPubkey *pubkey;
	gcry_sexp_t s_key;
	gcry_sexp_t numbers;
};

G_DEFINE_TYPE (GkrPkPrivkey, gkr_pk_privkey, GKR_TYPE_PK_OBJECT);

/* -------------------------------------------------------------------------------------
 * HELPERS
 */

static gboolean
load_private_key (GkrPkPrivkey *key)
{
	GError *err = NULL;
	GkrPkObject *obj;

	if (key->priv->s_key)
		return TRUE;
		
	obj = GKR_PK_OBJECT (key);
	
	g_return_val_if_fail (obj->storage, CKR_GENERAL_ERROR);
	if (!gkr_pk_object_storage_load_complete (obj->storage, obj, &err)) {
		g_message ("couldn't load private key for: %s: %s", 
		           g_quark_to_string (obj->location),
		           err && err->message ? err->message : "");
		g_error_free (err);
		return FALSE;
	}

	/* This can happen if the user cancels out of a dialog */
	if (!key->priv->s_key)
		return FALSE;

	return TRUE;
}
 
static GkrPkPubkey*
get_public_key (GkrPkPrivkey *key, gboolean force)
{
	gcry_sexp_t s_key = NULL;
	GkrPkObject *obj;
	GkrPkixResult res;
	guchar *data;
	gsize n_data;

	if (key->priv->pubkey)
		goto done;
		
	obj = GKR_PK_OBJECT (key);
	
	/* Do we have a public key in the indexes? */
	data = gkr_pk_index_get_binary (obj, "public-key", &n_data);
	if (data) {
		res = gkr_pkix_der_read_public_key (data, n_data, &s_key);
		if (res == GKR_PKIX_SUCCESS) {
			key->priv->pubkey = gkr_pk_pubkey_instance (obj->manager, 
			                                            obj->location, s_key);
			goto done;
		} 

		gkr_pk_index_delete (obj, "public-key");	
		g_warning ("invalid public-key in indexes for: %s", g_quark_to_string (obj->location));
	}
	
	/* 'Import' the public key from the private key */
	if (force && !key->priv->s_key) {
		if (!load_private_key (key))
			goto done;
	}

	/* Create one from the private key */
	if (key->priv->s_key) {
		if (!gkr_crypto_skey_private_to_public (key->priv->s_key, &s_key))
			g_return_val_if_reached (NULL);
			
		g_assert (s_key);
			
		/* Write it to the indexes */
		data = gkr_pkix_der_write_public_key (s_key, &n_data);
		g_return_val_if_fail (data != NULL, NULL);
		
		/* Write the public key out to the indexes */
		if (!gkr_pk_index_set_binary (obj, "public-key", data, n_data))
			g_warning ("couldn't write public key to index for: %s", g_quark_to_string (obj->location));
		
		key->priv->pubkey = gkr_pk_pubkey_instance (obj->manager, 0, s_key);
		goto done;
	}
	
done:
	return key->priv->pubkey;
}

static CK_RV
create_rsa_private (GArray *attrs, gcry_sexp_t *skey)
{
	gcry_error_t gcry;
	gcry_mpi_t n = NULL;
	gcry_mpi_t e = NULL;
	gcry_mpi_t d = NULL;
	gcry_mpi_t p = NULL;
	gcry_mpi_t q = NULL;
	gcry_mpi_t u = NULL;
	CK_RV ret;
	
	if (!gkr_pk_attributes_mpi (attrs, CKA_MODULUS, &n) ||
	    !gkr_pk_attributes_mpi (attrs, CKA_PUBLIC_EXPONENT, &e) || 
	    !gkr_pk_attributes_mpi (attrs, CKA_PRIVATE_EXPONENT, &d) || 
	    !gkr_pk_attributes_mpi (attrs, CKA_PRIME_1, &p) || 
	    !gkr_pk_attributes_mpi (attrs, CKA_PRIME_2, &q)) {
	    	ret = CKR_TEMPLATE_INCOMPLETE;
	    	goto done;
	}		
	
	/* Fix up the incoming key so gcrypt likes it */    	
	if (gcry_mpi_cmp (p, q) > 0)
		gcry_mpi_swap (p, q);

	/* Compute U.  */
	u = gcry_mpi_snew (gcry_mpi_get_nbits (n));
	gcry_mpi_invm (u, p, q);
	
	gcry = gcry_sexp_build (skey, NULL, 
	                        "(private-key (rsa (n %m) (e %m) (d %m) (p %m) (q %m) (u %m)))", 
	                        n, e, d, p, q, u);

	/* TODO: We should be mapping better return codes */
	if (gcry != 0) {
		g_message ("couldn't create RSA key from passed attributes");
		ret = CKR_GENERAL_ERROR;
		goto done;
	}
	
	gkr_pk_attributes_consume (attrs, CKA_MODULUS, CKA_PUBLIC_EXPONENT, 
	                           CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2, 
	                           CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT, -1);
	ret = CKR_OK;

done:
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	gcry_mpi_release (d);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (u);
	return ret;	
}

static CK_RV
create_dsa_private (GArray *attrs, gcry_sexp_t *skey)
{
	gcry_error_t gcry;
	gcry_mpi_t p = NULL;
	gcry_mpi_t q = NULL;
	gcry_mpi_t g = NULL;
	gcry_mpi_t y = NULL;
	gcry_mpi_t value = NULL;
	CK_RV ret;
	
	if (!gkr_pk_attributes_mpi (attrs, CKA_PRIME, &p) ||
	    !gkr_pk_attributes_mpi (attrs, CKA_SUBPRIME, &q) || 
	    !gkr_pk_attributes_mpi (attrs, CKA_BASE, &g) ||
	    !gkr_pk_attributes_mpi (attrs, CKA_VALUE, &value)) {
	    	ret = CKR_TEMPLATE_INCOMPLETE;
	    	goto done;
	}
	
	/* Calculate the public part from the private */
	y = gcry_mpi_snew (gcry_mpi_get_nbits (value));
	g_return_val_if_fail (y, CKR_GENERAL_ERROR);
  	gcry_mpi_powm (y, g, value, p);

	gcry = gcry_sexp_build (skey, NULL, 
	                        "(private-key (dsa (p %m) (q %m) (g %m) (y %m) (x %m)))",
	                        p, q, g, y, value);

	/* TODO: We should be mapping better return codes */
	if (gcry != 0) {
		g_message ("couldn't create DSA key from passed attributes");
		ret = CKR_GENERAL_ERROR;
		goto done;
	}

	gkr_pk_attributes_consume (attrs, CKA_PRIME, CKA_SUBPRIME, 
	                           CKA_BASE, CKA_VALUE, -1);
	ret = CKR_OK;

done:
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (value);
	return ret;
}


static void
initialize_from_key (GkrPkPrivkey *key)
{
	gcry_sexp_t numbers;
	gboolean is_priv;
	int algorithm;
	
	gcry_sexp_release (key->priv->numbers);
	key->priv->numbers = NULL;
	
	key->priv->algorithm = 0; 
	
	if (!key->priv->s_key)
		return;

	/* Parse it into handy parts */
	if (!gkr_crypto_skey_parse (key->priv->s_key, &algorithm, &is_priv, &numbers))
		g_return_if_reached ();

	g_return_if_fail (is_priv);	
	g_assert (numbers);
	g_assert (algorithm);
	
	key->priv->numbers = numbers;
	key->priv->algorithm = algorithm;
	
	/* The the chance to try and make sure the public key exists */
	get_public_key (key, FALSE);

	/* Make sure any cache data is current */	
	gkr_pk_object_flush (GKR_PK_OBJECT (key));
}

static CK_RV
attribute_from_public (GkrPkPrivkey *key, CK_ATTRIBUTE_PTR attr)
{
	GkrPkPubkey *pub = get_public_key (key, TRUE);
	if (pub == NULL)
		return CKR_GENERAL_ERROR;
	return gkr_pk_object_get_attribute (GKR_PK_OBJECT (pub), attr);
}

static CK_RV
attribute_from_certificate (GkrPkPrivkey *key, CK_ATTRIBUTE_PTR attr)
{
	GkrPkObject *crt, *obj;
	gkrconstid keyid;
	
	keyid = gkr_pk_privkey_get_keyid (key);
	if (!keyid)
		return CKR_GENERAL_ERROR;
		
	obj = GKR_PK_OBJECT (key);
	crt = gkr_pk_object_manager_find_by_id (obj->manager, GKR_TYPE_PK_CERT, keyid); 
	if (crt == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	return gkr_pk_object_get_attribute (crt, attr);
}

static CK_RV
extract_key_mpi (GkrPkPrivkey *key, int algorithm, const char *part, CK_ATTRIBUTE_PTR attr)
{
	gcry_mpi_t mpi = NULL;
	gboolean ret;

	/* Extract it from public key if no key available */
	if (!key->priv->s_key && attribute_from_public (key, attr) == CKR_OK)
		return CKR_OK;
		
	/* Load our key */
	if (!load_private_key (key))
		return CKR_GENERAL_ERROR;
	
	if (key->priv->algorithm != algorithm)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	g_assert (key->priv->numbers);
	ret = gkr_crypto_sexp_extract_mpi (key->priv->numbers, &mpi, part, NULL);
	g_return_val_if_fail (ret, CKR_GENERAL_ERROR);
	gkr_pk_attribute_set_mpi (attr, mpi);
	gcry_mpi_release (mpi);
	return CKR_OK;
}

/* -------------------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_privkey_init (GkrPkPrivkey *key)
{
	key->priv = G_TYPE_INSTANCE_GET_PRIVATE (key, GKR_TYPE_PK_PRIVKEY, GkrPkPrivkeyData);
	memset (key->priv, 0, sizeof (GkrPkPrivkeyData));
}

static void
gkr_pk_privkey_get_property (GObject *obj, guint prop_id, GValue *value, 
                             GParamSpec *pspec)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);

	switch (prop_id) {
	case PROP_GCRYPT_SEXP:
		g_value_set_pointer (value, key->priv->s_key);
		break;
	}
}

static void
gkr_pk_privkey_set_property (GObject *obj, guint prop_id, const GValue *value, 
                             GParamSpec *pspec)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);
	
	switch (prop_id) {
	case PROP_GCRYPT_SEXP:
		if (key->priv->s_key)
			gcry_sexp_release (key->priv->s_key);
		key->priv->s_key = (gcry_sexp_t)g_value_get_pointer (value);
		initialize_from_key (key);
		break;
	}
}

static CK_RV
gkr_pk_privkey_get_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);
	gkrconstid keyid;
	GQuark *quarks;
	guchar *value;
	gsize len;
	
	switch (attr->type)
	{
	case CKA_DECRYPT:
	case CKA_PRIVATE:
	case CKA_SENSITIVE:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_WRAP_WITH_TRUSTED:
		gkr_pk_attribute_set_boolean (attr, CK_TRUE);
		return CKR_OK;
	
	case CKA_DERIVE:
	case CKA_EXTRACTABLE:
	case CKA_UNWRAP:
		gkr_pk_attribute_set_boolean (attr, CK_FALSE);
		return CKR_OK;

	case CKA_GNOME_PURPOSE_SSH_AUTH:
		quarks = gkr_pk_index_get_quarks (obj, "purposes");
		gkr_pk_attribute_set_boolean (attr, quarks && 
				gkr_pk_index_quarks_has (quarks, SSH_AUTHENTICATION));
		gkr_pk_index_quarks_free (quarks);
		return CKR_OK;

	/* TODO: Perhaps we can detect this in some way */
	case CKA_ALWAYS_SENSITIVE:
	case CKA_LOCAL:
	case CKA_NEVER_EXTRACTABLE:
		gkr_pk_attribute_set_boolean (attr, CK_FALSE);
		return CKR_OK;
		
	/* TODO: We may be able to detect this for certain keys */
	case CKA_ALWAYS_AUTHENTICATE:
		gkr_pk_attribute_set_boolean (attr, CK_FALSE);
		return CKR_OK;
		
	case CKA_CLASS:
		gkr_pk_attribute_set_ulong (attr, CKO_PRIVATE_KEY);
		return CKR_OK;
		
	case CKA_KEY_TYPE:
		if (attribute_from_public (key, attr) != CKR_OK)
			gkr_pk_attribute_set_ulong (attr, CK_UNAVAILABLE_INFORMATION);
		return CKR_OK;
		
	/* TODO: Once we can generate keys, this should change */
	case CKA_KEY_GEN_MECHANISM:
		gkr_pk_attribute_set_ulong (attr, CK_UNAVAILABLE_INFORMATION);
		return CKR_OK;
		
	case CKA_ID:
		keyid = gkr_pk_privkey_get_keyid (key);
		if (!keyid) 
			return CKR_GENERAL_ERROR;
		value = (CK_VOID_PTR)gkr_id_get_raw (keyid, &len);
		gkr_pk_attribute_set_data (attr, value, len);
		return CKR_OK;

	case CKA_SUBJECT:
		return attribute_from_certificate (key, attr);

	case CKA_MODULUS:
		return extract_key_mpi (key, GCRY_PK_RSA, "n", attr);
		
	case CKA_PUBLIC_EXPONENT:
		return extract_key_mpi (key, GCRY_PK_RSA, "e", attr);
	
	/* RSA private parts, we never allow */
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
		return CKR_ATTRIBUTE_SENSITIVE;
	
	case CKA_PRIME:
		return extract_key_mpi (key, GCRY_PK_DSA, "p", attr);
		
	case CKA_SUBPRIME:
		return extract_key_mpi (key, GCRY_PK_DSA, "q", attr);
		
	case CKA_BASE:
		return extract_key_mpi (key, GCRY_PK_DSA, "g", attr);
	
	/* DSA private parts, we never allow */
	case CKA_VALUE:
		return CKR_ATTRIBUTE_SENSITIVE;
	
	/* TODO: We need to implement this: ARRAY[1] (CKM_RSA_PKCS) */
	case CKA_ALLOWED_MECHANISMS:
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	case CKA_UNWRAP_TEMPLATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	/* We don't support these */
	case CKA_START_DATE:
	case CKA_END_DATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;

	default:
		break;
	};

	return GKR_PK_OBJECT_CLASS (gkr_pk_privkey_parent_class)->get_attribute (obj, attr);
}

static guchar*
gkr_pk_privkey_serialize (GkrPkObject *obj, const gchar *password, gsize *n_data)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);
	
	if (!load_private_key (key))
		return NULL;
		
	g_return_val_if_fail (key->priv->s_key, NULL);
	
	/* Write it out */
	return gkr_pkix_serialize_private_key_pkcs8 (key->priv->s_key, password, n_data);
}

static void
gkr_pk_privkey_lock (GkrPkObject *obj)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);

	if (!key->priv->s_key)
		return;
	
	gcry_sexp_release (key->priv->s_key);
	key->priv->s_key = NULL;
	
	initialize_from_key (key);
}

static void
gkr_pk_privkey_dispose (GObject *obj)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);

	if (key->priv->pubkey) {
		g_object_unref (key->priv->pubkey);
		key->priv->pubkey = NULL;
	}
	
	G_OBJECT_CLASS (gkr_pk_privkey_parent_class)->dispose (obj);
}

static void
gkr_pk_privkey_finalize (GObject *obj)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);

	g_assert (!key->priv->pubkey);

	gcry_sexp_release (key->priv->s_key);
	key->priv->s_key = NULL;

	gcry_sexp_release (key->priv->numbers);
	key->priv->numbers = NULL;	
	
	G_OBJECT_CLASS (gkr_pk_privkey_parent_class)->finalize (obj);
}

static void
gkr_pk_privkey_class_init (GkrPkPrivkeyClass *klass)
{
	GObjectClass *gobject_class;
	GkrPkObjectClass *parent_class;

	gkr_pk_privkey_parent_class = g_type_class_peek_parent (klass);
	
	parent_class = GKR_PK_OBJECT_CLASS (klass);
	parent_class->get_attribute = gkr_pk_privkey_get_attribute;
	parent_class->serialize = gkr_pk_privkey_serialize;
	parent_class->lock = gkr_pk_privkey_lock;
	
	gobject_class = (GObjectClass*)klass;
	gobject_class->get_property = gkr_pk_privkey_get_property;
	gobject_class->set_property = gkr_pk_privkey_set_property;
	gobject_class->dispose = gkr_pk_privkey_dispose;
	gobject_class->finalize = gkr_pk_privkey_finalize;
	
	g_object_class_install_property (gobject_class, PROP_GCRYPT_SEXP,
		g_param_spec_pointer ("gcrypt-sexp", "Key", "S-Expression key",
		                      G_PARAM_READWRITE));
		                      
	g_type_class_add_private (klass, sizeof (GkrPkPrivkeyData));
}

GkrPkObject*
gkr_pk_privkey_new (GkrPkObjectManager *mgr, GQuark location, gcry_sexp_t s_key)
{
	GkrPkObject *key;
	guchar hash[20];
	gkrid digest; 
	
	g_return_val_if_fail (s_key != NULL, NULL);
	
	if (!gcry_pk_get_keygrip (s_key, hash))
		g_return_val_if_reached (NULL);
	
	/* We need to create a digest for this key */
	digest = gkr_id_new_digestv ((const guchar*)"private-key", 11, hash, 20, NULL);
	
	key = g_object_new (GKR_TYPE_PK_PRIVKEY, "manager", mgr, "location", location, 
	                    "gcrypt-sexp", s_key, "digest", digest, NULL);
	                    
	gkr_id_free (digest);
	
	return key;
}

CK_RV
gkr_pk_privkey_create (GkrPkObjectManager* manager, GArray* array, 
                       GkrPkObject **object)
{
 	CK_KEY_TYPE type;
 	gcry_sexp_t sexp;
 	CK_RV ret;
 	
	g_return_val_if_fail (GKR_IS_PK_OBJECT_MANAGER (manager), CKR_GENERAL_ERROR);
	g_return_val_if_fail (array, CKR_GENERAL_ERROR);
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);
	
	*object = NULL;
	
	if (!gkr_pk_attributes_ulong (array, CKA_KEY_TYPE, &type))
 		return CKR_TEMPLATE_INCOMPLETE;
 	gkr_pk_attributes_consume (array, CKA_KEY_TYPE, -1);

 	switch (type) {
	case CKK_RSA:
		ret = create_rsa_private (array, &sexp);
		break;
	case CKK_DSA:
		ret = create_dsa_private (array, &sexp);
		break;
	default:
		return CKR_ATTRIBUTE_VALUE_INVALID;
 	};

	if (ret != CKR_OK)
		return ret;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);	
	*object = gkr_pk_privkey_new (manager, 0, sexp);
	
	return CKR_OK;
}

gkrconstid
gkr_pk_privkey_get_keyid (GkrPkPrivkey *key)
{
	GkrPkPubkey *pub;
	
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (key), NULL);
	
	/* Access via public key */
	pub = get_public_key (key, TRUE);
	if(!pub)
		return NULL;
	
	return gkr_pk_pubkey_get_keyid (pub);
}

gcry_sexp_t 
gkr_pk_privkey_get_key (GkrPkPrivkey *key)
{
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (key), NULL);
	if (!load_private_key (key))
		return NULL;
	return key->priv->s_key;
}

int
gkr_pk_privkey_get_algorithm (GkrPkPrivkey *key)
{
	GkrPkPubkey *pub;
	
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (key), 0);

	/* If we have it access directly */
	if (key->priv->algorithm)
		return key->priv->algorithm;
	
	/* Otherwise access via public key */
	pub = get_public_key (key, TRUE);
	return gkr_pk_pubkey_get_algorithm (GKR_PK_PUBKEY (pub));
}

GkrPkPubkey*
gkr_pk_privkey_get_public (GkrPkPrivkey *key)
{
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (key), NULL);
	return get_public_key (key, TRUE);
}
