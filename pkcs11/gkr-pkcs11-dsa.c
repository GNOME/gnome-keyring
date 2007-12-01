/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkcs11-dsa.c - DSA mechanism code for PKCS#11

   Copyright (C) 2007, Stefan Walter

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

#include "gkr-pkcs11-dsa.h"

#include "common/gkr-crypto.h"

#include "pk/gkr-pk-pubkey.h"
#include "pk/gkr-pk-privkey.h"
#include "pk/gkr-pk-util.h"

static CK_RV
object_to_public_key (GkrPkObject *object, gcry_sexp_t *s_key)
{
	GkrPkPubkey *key;

	/* Validate and extract the key */
	if (!GKR_IS_PK_PUBKEY (object))
		return CKR_KEY_HANDLE_INVALID;
		
	key = GKR_PK_PUBKEY (object);
	if (gkr_pk_pubkey_get_algorithm (key) != GCRY_PK_DSA)
		return CKR_KEY_TYPE_INCONSISTENT;

	*s_key = gkr_pk_pubkey_get_key (key);
	if (!*s_key) {
		/* TODO: This happens when the user doesn't unlock key, proper code */
		g_warning ("couldn't get public key");
		return CKR_GENERAL_ERROR;
	}
	
	return CKR_OK;
}

static CK_RV
object_to_private_key (GkrPkObject *object, gcry_sexp_t *s_key)
{
	GkrPkPrivkey *key;

	/* Validate and extract the key */
	if (!GKR_IS_PK_PRIVKEY (object))
		return CKR_KEY_HANDLE_INVALID;
		
	key = GKR_PK_PRIVKEY (object);
	if (gkr_pk_privkey_get_algorithm (key) != GCRY_PK_DSA)
		return CKR_KEY_TYPE_INCONSISTENT;

	*s_key = gkr_pk_privkey_get_key (key);
	if (!*s_key) {
		/* TODO: This happens when the user doesn't unlock key, proper code */
		g_warning ("couldn't get private key");
		return CKR_GENERAL_ERROR;
	}
	
	return CKR_OK;
}

CK_RV
gkr_pkcs11_dsa_sign (GkrPkObject *object, const guchar *plain, gsize n_plain, 
                     guchar **signature, gsize *n_signature)
{
	gcry_sexp_t s_key, ssig, splain;
	gcry_error_t gcry;
	gcry_mpi_t mpi;
	gboolean res;
	CK_RV ret;
	
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);

	ret = object_to_private_key (object, &s_key);
	if (ret != CKR_OK)
		return ret;
		
	/* If no output, then don't process */
	if (!signature)
		return CKR_OK;

	if (!plain)
		return CKR_ARGUMENTS_BAD;
				
	if (n_plain != 20)
		return CKR_DATA_LEN_RANGE;
		
	/* Prepare the input s-expression */
	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, plain, n_plain, NULL);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	gcry = gcry_sexp_build (&splain, NULL, "(data (flags raw) (value %m))", mpi);
	gcry_mpi_release (mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	/* Do the magic */
	gcry = gcry_pk_sign (&ssig, splain, s_key);
	gcry_sexp_release (splain);
	
	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_warning ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_GENERAL_ERROR;
	}

	*signature = g_new0 (guchar, 40);
	*n_signature = 40;
	
	res = gkr_crypto_sexp_extract_mpi_aligned (ssig, *signature, 20, "dsa", "r", NULL) && 
	      gkr_crypto_sexp_extract_mpi_aligned (ssig, *signature + 20, 20, "dsa", "s", NULL);
	g_return_val_if_fail (res, CKR_GENERAL_ERROR);
	
	gcry_sexp_release (ssig);
	return CKR_OK;
}

CK_RV
gkr_pkcs11_dsa_verify (GkrPkObject *object, const guchar *plain, gsize n_plain, 
                       const guchar *signature, gsize n_signature)
{
	gcry_sexp_t s_key, ssig, splain;
	gcry_error_t gcry;
	gcry_mpi_t mpi, mpi2;
	CK_RV ret;
	
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);
	
	ret = object_to_public_key (object, &s_key);
	if (ret != CKR_OK)
		return ret;
		
	/* If no data, then don't process */
	if (!plain)
		return CKR_OK;

	if (!signature)
		return CKR_ARGUMENTS_BAD;
	if (n_plain != 20)
		return CKR_DATA_LEN_RANGE;				
	if (n_signature != 40)
		return CKR_DATA_LEN_RANGE;

	/* Prepare the input s-expressions */
	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, plain, n_plain, NULL);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	gcry = gcry_sexp_build (&splain, NULL, "(data (flags raw) (value %m))", mpi);
	gcry_mpi_release (mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, signature, 20, NULL);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	gcry = gcry_mpi_scan (&mpi2, GCRYMPI_FMT_USG, signature + 20, 20, NULL);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	gcry = gcry_sexp_build (&ssig, NULL, "(sig-val (dsa (r %m) (s %m)))", mpi, mpi2);
	gcry_mpi_release (mpi);
	gcry_mpi_release (mpi2);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	
	/* Do the magic */
	gcry = gcry_pk_verify (ssig, splain, s_key);
	gcry_sexp_release (splain);
	gcry_sexp_release (ssig);
	
	/* TODO: See if any other codes should be mapped */
	if (gcry_err_code (gcry) == GPG_ERR_BAD_SIGNATURE) {
		return CKR_SIGNATURE_INVALID;
	} else if (gcry) {
		g_warning ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

CK_RV
gkr_pkcs11_dsa_create_key (const GArray* attrs, GkrPkObject **key)
{
	CK_OBJECT_CLASS cls;
	gcry_sexp_t skey;
	gcry_error_t gcry;
	gcry_mpi_t p = NULL;
	gcry_mpi_t q = NULL;
	gcry_mpi_t g = NULL;
	gcry_mpi_t value = NULL;
	gcry_mpi_t y = NULL;
	gboolean priv;
	CK_RV ret;
	
	g_return_val_if_fail (attrs, CKR_GENERAL_ERROR);
	g_return_val_if_fail (key, CKR_GENERAL_ERROR);
	
	/* Figure out if it's public or private */
	if (!gkr_pk_attributes_ulong (attrs, CKA_CLASS, &cls)) {
		ret = CKR_TEMPLATE_INCOMPLETE;
		goto done;
	}
	if (cls == CKO_PRIVATE_KEY)
		priv = TRUE;
	else if (cls == CKO_PUBLIC_KEY)
		priv = FALSE;
	else {
		ret = CKR_ATTRIBUTE_VALUE_INVALID;
		goto done;
	}
	
	if (!gkr_pk_attributes_mpi (attrs, CKA_PRIME, &p) ||
	    !gkr_pk_attributes_mpi (attrs, CKA_SUBPRIME, &q) || 
	    !gkr_pk_attributes_mpi (attrs, CKA_BASE, &g) ||
	    !gkr_pk_attributes_mpi (attrs, CKA_VALUE, &value)) {
	    	ret = CKR_TEMPLATE_INCOMPLETE;
	    	goto done;
	} 
	    	
	/* Create a private key */
	if (priv) {
	    		
		/* Calculate the public part from the private */
		y = gcry_mpi_snew (gcry_mpi_get_nbits (value));
  		gcry_mpi_powm (y, g, value, p);
  			
		gcry = gcry_sexp_build (&skey, NULL, "(private-key (dsa (p %m) (q %m) (g %m) (y %m) (x %m)))",
		                        p, q, g, value);
	    		
	/* Create a public key */
	} else {
	    		
		gcry = gcry_sexp_build (&skey, NULL, "(public-key (dsa (p %m) (q %m) (g %m) (y %m)))",
		                        p, q, g, value);	    		
    	}
	
	/* TODO: We should be mapping better return codes */
	if (gcry != 0) {
		g_message ("couldn't create DSA key from passed attributes");
		ret = CKR_GENERAL_ERROR;
		goto done;
	}
	
	if (priv) 
		*key = gkr_pk_privkey_new (0, skey);
	else
		*key = gkr_pk_pubkey_new (0, skey); 

	/* TODO: We should verify remainder of attributes */
	ret = CKR_OK;
		
done:
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (value);
	
	return CKR_OK;
}
