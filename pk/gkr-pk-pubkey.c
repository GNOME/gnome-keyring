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
#include "gkr-pk-object-manager.h"
#include "gkr-pk-object-storage.h"
#include "gkr-pk-pubkey.h"
#include "gkr-pk-util.h"

#include "common/gkr-crypto.h"
#include "common/gkr-location.h"
#include "common/gkr-unique.h"

#include "pkix/gkr-pkix-der.h"

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
	gkrunique keyid;
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
	
	gkr_unique_free (key->pub->keyid);
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
	
	if (!gkr_pk_object_storage_load_complete (obj->storage, obj, GKR_PK_OBJECT_REASON_UNKNOWN, &err)) {
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
attribute_from_related (GkrPkPubkey *key, GType type, CK_ATTRIBUTE_PTR attr)
{
	GkrPkObject *crt, *obj;
	
	if (!load_public_key (key))
		return CKR_GENERAL_ERROR;
	
	obj = GKR_PK_OBJECT (key);	
	crt = gkr_pk_object_manager_find_by_id (obj->manager, type, key->pub->keyid);
	
	if (crt == NULL)
		return CKR_GENERAL_ERROR;
		
	return gkr_pk_object_get_attribute (crt, attr);
}

static CK_RV
extract_key_mpi (GkrPkPubkey *key, int algorithm, const char *part, CK_ATTRIBUTE_PTR attr)
{
	gcry_mpi_t mpi;
	gboolean ret;
	
	if (!load_public_key (key))
		return CKR_GENERAL_ERROR;
	
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
		return CKR_GENERAL_ERROR;
	
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
gkr_pk_pubkey_get_bool_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	gboolean val;
	
	switch (attr->type)
	{
	case CKA_ALWAYS_AUTHENTICATE:
	case CKA_ENCRYPT:
	case CKA_EXTRACTABLE:
	case CKA_TOKEN:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
		val = TRUE;
		break;
	
	case CKA_DERIVE:
	case CKA_MODIFIABLE:
	case CKA_PRIVATE:
	case CKA_SENSITIVE:
	case CKA_WRAP:
	case CKA_WRAP_WITH_TRUSTED:
		val = FALSE;
		break;
		
	/* TODO: Use our definition of trusted */
	case CKA_TRUSTED:
		val = FALSE;
		break;
		
	/* TODO: Perhaps we can detect this in some way */
	case CKA_LOCAL:
		val = FALSE;	
		break;
		
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	gkr_pk_attribute_set_boolean (attr, val);
	return CKR_OK;
}

static CK_RV 
gkr_pk_pubkey_get_ulong_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkPubkey *key = GKR_PK_PUBKEY (obj);
	gcry_mpi_t mpi;
	gboolean ret;
	gulong val;
	
	switch (attr->type)
	{
	case CKA_CLASS:
		val = CKO_PUBLIC_KEY;
		break;
		
	case CKA_KEY_TYPE:
		if (!load_public_key (key))
			return CKR_GENERAL_ERROR;
		switch (key->pub->algorithm) {
		case GCRY_PK_RSA:
			val = CKK_RSA;
			break;
		case GCRY_PK_DSA:
			val = CKK_DSA;
			break;
		default:
			g_return_val_if_reached (CKR_GENERAL_ERROR);
			break;
		}
		break;
	
	case CKA_MODULUS_BITS:
		if (!load_public_key (key))
			return CKR_GENERAL_ERROR;
		if (key->pub->algorithm != GCRY_PK_RSA)
			return CKR_ATTRIBUTE_TYPE_INVALID;
		g_assert (key->pub->numbers);
		ret = gkr_crypto_sexp_extract_mpi (key->pub->numbers, &mpi, "n", NULL);
		g_return_val_if_fail (ret, CKR_GENERAL_ERROR);
		val = gcry_mpi_get_nbits (mpi);
		gcry_mpi_release (mpi);
		break;
		
	/* TODO: Once we can generate keys, this should change */
	case CKA_KEY_GEN_MECHANISM:
		return CK_UNAVAILABLE_INFORMATION;
		
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	gkr_pk_attribute_set_ulong (attr, val);
	return CKR_OK;
}

static CK_RV
gkr_pk_pubkey_get_data_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkPubkey *key = GKR_PK_PUBKEY (obj);
	gchar *label;
	
	switch (attr->type)
	{
	case CKA_LABEL:
		g_object_get (obj, "label", &label, NULL);
		if (!label)
			label = gkr_location_to_display (obj->location);
		gkr_pk_attribute_set_string (attr, label);
		g_free (label);
		return CKR_OK;
		
	case CKA_ID:
		/* Always a SHA-1 hash output buffer */
		if (!load_public_key (key) || !key->pub->keyid)
			return CKR_GENERAL_ERROR;
		gkr_pk_attribute_set_unique (attr, key->pub->keyid);
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
	
	/* TODO: We need to implement this: ARRAY[1] (CKM_RSA_PKCS) */
	case CKA_ALLOWED_MECHANISMS:
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	case CKA_UNWRAP_TEMPLATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	default:
		break;
	};

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV 
gkr_pk_pubkey_get_date_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	switch (attr->type)
	{
	/* We don't support these */
	case CKA_START_DATE:
	case CKA_END_DATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
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
	parent_class->get_bool_attribute = gkr_pk_pubkey_get_bool_attribute;
	parent_class->get_ulong_attribute = gkr_pk_pubkey_get_ulong_attribute;
	parent_class->get_data_attribute = gkr_pk_pubkey_get_data_attribute;
	parent_class->get_date_attribute = gkr_pk_pubkey_get_date_attribute;
	
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
gkr_pk_pubkey_new (GQuark location, gcry_sexp_t s_key)
{
	GkrPkObject *key;
	guchar hash[20];
	gkrunique unique; 
	
	g_return_val_if_fail (s_key != NULL, NULL);
	
	if (!gcry_pk_get_keygrip (s_key, hash))
		g_return_val_if_reached (NULL);
	
	/* We need to create a unique for this key */
	unique = gkr_unique_new_digestv ((const guchar*)"public-key", 10, hash, 20, NULL);
	
	key = g_object_new (GKR_TYPE_PK_PUBKEY, "location", location, 
	                    "gcrypt-sexp", s_key, "unique", unique, NULL);
	                    
	gkr_unique_free (unique);
	return key;
}

GkrPkPubkey*
gkr_pk_pubkey_instance (GkrPkObjectManager *manager, GQuark location, gcry_sexp_t s_key)
{
	GkrPkObject *pub;
	gkrunique keyid;
	
	g_return_val_if_fail (s_key, NULL);
	
	/* Make sure we have the keyid properly */
	keyid = gkr_crypto_skey_make_id (s_key);
	g_return_val_if_fail (keyid, NULL);
	
	/* Try the lookup */
	pub = gkr_pk_object_manager_find_by_id (manager, GKR_TYPE_PK_PUBKEY, keyid);
	gkr_unique_free (keyid);
	
	if (pub != NULL) {
		gcry_sexp_release (s_key);
		g_object_ref (pub);
		return GKR_PK_PUBKEY (pub);
	}
	
	pub = gkr_pk_pubkey_new (location, s_key);
	gkr_pk_object_manager_register (manager, pub);
	return GKR_PK_PUBKEY (pub);
}

gkrconstunique
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
