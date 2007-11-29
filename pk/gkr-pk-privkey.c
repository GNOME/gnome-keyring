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

#include "gkr-pk-index.h"
#include "gkr-pk-object.h"
#include "gkr-pk-object-manager.h"
#include "gkr-pk-privkey.h"
#include "gkr-pk-pubkey.h"
#include "gkr-pk-util.h"

#include "common/gkr-crypto.h"
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

struct _GkrPkPrivkeyData {
	int algorithm;
	gkrunique keyid;
	gcry_sexp_t s_key;
	gcry_sexp_t numbers;
};

G_DEFINE_TYPE (GkrPkPrivkey, gkr_pk_privkey, GKR_TYPE_PK_OBJECT);

/* -------------------------------------------------------------------------------------
 * HELPERS
 */

static gboolean
load_private_key (GkrPkPrivkey *key, GkrPkObjectReason reason)
{
	GError *err = NULL;
	GkrPkObject *obj;

	if (key->priv->s_key)
		return TRUE;
		
	obj = GKR_PK_OBJECT (key);
		
	if (!gkr_pk_object_manager_load_complete (obj->manager, obj, reason, &err)) {
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
 
static GkrPkObject*
get_public_key (GkrPkPrivkey *key, gboolean force)
{
	gcry_sexp_t s_key = NULL;
	GkrPkObject *pub = NULL;
	GkrPkObject *obj;
	GkrParseResult res;
	gkrconstunique keyid;
	guchar *data;
	gsize n_data;
	
	obj = GKR_PK_OBJECT (key);
	
	/* Try and find the matching public key */
	if (key->priv->keyid) {
		pub = gkr_pk_object_manager_find_by_id (obj->manager, GKR_TYPE_PK_PUBKEY, 
		                                        key->priv->keyid);
		if (pub != NULL)
			return pub;
	}
	
	/* Do we have a public key in the indexes? */
	data = gkr_pk_index_get_binary (obj->location, obj->unique, "public-key", &n_data);
	if (data) {
		res = gkr_pkix_der_read_public_key (data, n_data, &s_key);
		if (res == GKR_PARSE_SUCCESS) {
			pub = gkr_pk_pubkey_new (obj->location, s_key);
			
			/* Fill in our keyid, so we have that at least */
			if (!key->priv->keyid) {
				keyid = gkr_pk_pubkey_get_keyid (GKR_PK_PUBKEY (pub));
				key->priv->keyid = gkr_unique_dup (keyid);
			}
			
			gkr_pk_object_manager_register (obj->manager, pub);
			return pub;
		} 

		gkr_pk_index_delete (obj->location, obj->unique, "public-key");	
		g_warning ("invalid public-key in indexes for: %s", g_quark_to_string (obj->location));
	}
	
	/* 'Import' the public key from the private key */
	if (force && !key->priv->s_key) {
		if (!load_private_key (key, GKR_PK_OBJECT_REASON_IMPORT))
			return NULL;
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
		if (!gkr_pk_index_set_binary (obj->location, obj->unique, "public-key", data, n_data))
			g_warning ("couldn't write public key to index for: %s", g_quark_to_string (obj->location));
		
		pub = gkr_pk_pubkey_new (0, s_key);
		gkr_pk_object_manager_register (obj->manager, pub);
		return pub;
	}
	
	return NULL;
}

static void
initialize_from_key (GkrPkPrivkey *key)
{
	gcry_sexp_t numbers;
	gboolean is_priv;
	int algorithm;
	
	gcry_sexp_release (key->priv->numbers);
	key->priv->numbers = NULL;
	
	gkr_unique_free (key->priv->keyid);
	key->priv->keyid = NULL;
	
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
	key->priv->keyid = gkr_crypto_skey_make_id (key->priv->s_key);
	
	/* The the chance to try and make sure the public key exists */
	get_public_key (key, FALSE);

	/* Make sure any cache data is current */	
	gkr_pk_object_flush (GKR_PK_OBJECT (key));
}

static CK_RV
attribute_from_public (GkrPkPrivkey *key, CK_ATTRIBUTE_PTR attr)
{
	GkrPkObject *pub;
	pub = get_public_key (key, TRUE);
	if (pub == NULL)
		return CKR_GENERAL_ERROR;
	return gkr_pk_object_get_attribute (pub, attr);
}

static CK_RV
attribute_from_certificate (GkrPkPrivkey *key, CK_ATTRIBUTE_PTR attr)
{
	GkrPkObject *crt, *obj;
	gkrconstunique keyid;
	
	keyid = gkr_pk_privkey_get_keyid (key);
	if (!keyid)
		return CKR_GENERAL_ERROR;
		
	obj = GKR_PK_OBJECT (key);
	crt = gkr_pk_object_manager_find_by_id (obj->manager, CKO_CERTIFICATE, keyid); 
	if (crt == NULL)
		return CKR_GENERAL_ERROR;
		
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
	if (!load_private_key (key, GKR_PK_OBJECT_REASON_UNKNOWN))
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
gkr_pk_privkey_get_bool_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	gboolean val;
	
	switch (attr->type)
	{
	case CKA_DECRYPT:
	case CKA_PRIVATE:
	case CKA_SENSITIVE:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_TOKEN:
	case CKA_WRAP_WITH_TRUSTED:
		val = TRUE;
		break;
	
	case CKA_DERIVE:
	case CKA_EXTRACTABLE:
	case CKA_MODIFIABLE:
	case CKA_UNWRAP:
		val = FALSE; 
		break;

	/* TODO: Perhaps we can detect this in some way */
	case CKA_ALWAYS_SENSITIVE:
	case CKA_LOCAL:
	case CKA_NEVER_EXTRACTABLE:
		val = FALSE;	
		break;
		
	/* TODO: We may be able to detect this for certain keys */
	case CKA_ALWAYS_AUTHENTICATE:
		val = FALSE;
		break;
		
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	gkr_pk_attribute_set_boolean (attr, val);
	return CKR_OK;
}

static CK_RV 
gkr_pk_privkey_get_ulong_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);
	guint val;
	
	switch (attr->type)
	{
	case CKA_CLASS:
		val = CKO_PRIVATE_KEY;
		break;
		
	case CKA_KEY_TYPE:
		if (attribute_from_public (key, attr) == CKR_OK)
			return CKR_OK;
		val = CK_UNAVAILABLE_INFORMATION;
		break;
		
	/* TODO: Once we can generate keys, this should change */
	case CKA_KEY_GEN_MECHANISM:
		val = CK_UNAVAILABLE_INFORMATION;
		break;
		
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	gkr_pk_attribute_set_uint (attr, val);
	return CKR_OK;
}

static CK_RV
gkr_pk_privkey_get_data_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);
	gchar *label;
	guchar *value;
	gsize len;
	
	switch (attr->type)
	{
	case CKA_LABEL:
		g_object_get (obj, "label", &label, NULL);
		if (label) {
			gkr_pk_attribute_set_string (attr, label);
			g_free (label);
			return CKR_OK;
		}
		
		return attribute_from_certificate (key, attr);
		
	case CKA_ID:
		if (!key->priv->s_key)
			return attribute_from_public (key, attr);
		value = (CK_VOID_PTR)gkr_unique_get_raw (key->priv->keyid, &len);
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
		
	default:
		break;
	};

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV 
gkr_pk_privkey_get_date_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
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
gkr_pk_privkey_finalize (GObject *obj)
{
	GkrPkPrivkey *key = GKR_PK_PRIVKEY (obj);

	gcry_sexp_release (key->priv->s_key);
	key->priv->s_key = NULL;
	
	initialize_from_key (key);
	
	g_assert (!key->priv->numbers);
	g_assert (!key->priv->keyid);
	
	G_OBJECT_CLASS (gkr_pk_privkey_parent_class)->finalize (obj);
}

static void
gkr_pk_privkey_class_init (GkrPkPrivkeyClass *klass)
{
	GObjectClass *gobject_class;
	GkrPkObjectClass *parent_class;

	gkr_pk_privkey_parent_class = g_type_class_peek_parent (klass);
	
	parent_class = GKR_PK_OBJECT_CLASS (klass);
	parent_class->get_bool_attribute = gkr_pk_privkey_get_bool_attribute;
	parent_class->get_ulong_attribute = gkr_pk_privkey_get_ulong_attribute;
	parent_class->get_data_attribute = gkr_pk_privkey_get_data_attribute;
	parent_class->get_date_attribute = gkr_pk_privkey_get_date_attribute;
	
	gobject_class = (GObjectClass*)klass;
	gobject_class->get_property = gkr_pk_privkey_get_property;
	gobject_class->set_property = gkr_pk_privkey_set_property;
	gobject_class->finalize = gkr_pk_privkey_finalize;
	
	g_object_class_install_property (gobject_class, PROP_GCRYPT_SEXP,
		g_param_spec_pointer ("gcrypt-sexp", "Key", "S-Expression key",
		                      G_PARAM_READWRITE));
		                      
	g_type_class_add_private (klass, sizeof (GkrPkPrivkeyData));
}

GkrPkObject*
gkr_pk_privkey_new (GQuark location, gcry_sexp_t s_key)
{
	GkrPkObject *key;
	guchar hash[20];
	gkrunique unique; 
	
	g_return_val_if_fail (s_key != NULL, NULL);
	
	if (!gcry_pk_get_keygrip (s_key, hash))
		g_return_val_if_reached (NULL);
	
	/* We need to create a unique for this key */
	unique = gkr_unique_new_digestv ((const guchar*)"private-key", 11, hash, 20, NULL);
	
	key = g_object_new (GKR_TYPE_PK_PRIVKEY, "location", location, 
	                    "gcrypt-sexp", s_key, "unique", unique, NULL);
	                    
	gkr_unique_free (unique);
	
	return key;
}

gkrconstunique
gkr_pk_privkey_get_keyid (GkrPkPrivkey *key)
{
	GkrPkObject *pub;
	
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (key), NULL);
	
	/* If we have it access directly */
	if (key->priv->keyid)
		return key->priv->keyid;
	
	/* Otherwise access via public key */
	pub = get_public_key (key, TRUE);
	return gkr_pk_pubkey_get_keyid (GKR_PK_PUBKEY (pub));
}

gcry_sexp_t 
gkr_pk_privkey_get_key (GkrPkPrivkey *key)
{
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (key), NULL);
	if (!load_private_key (key, GKR_PK_OBJECT_REASON_UNKNOWN))
		return NULL;
	return key->priv->s_key;
}

int
gkr_pk_privkey_get_algorithm (GkrPkPrivkey *key)
{
	GkrPkObject *pub;
	
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (key), 0);

	/* If we have it access directly */
	if (key->priv->algorithm)
		return key->priv->algorithm;
	
	/* Otherwise access via public key */
	pub = get_public_key (key, TRUE);
	return gkr_pk_pubkey_get_algorithm (GKR_PK_PUBKEY (pub));
}

GkrPkObject*
gkr_pk_privkey_get_public (GkrPkPrivkey *key)
{
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (key), NULL);
	return get_public_key (key, TRUE);
}
