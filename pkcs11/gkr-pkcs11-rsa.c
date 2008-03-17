/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkcs11-rsa.c - RSA mechanism code for PKCS#11

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

#include "gkr-pkcs11-rsa.h"

#include "common/gkr-crypto.h"

#include "pk/gkr-pk-pubkey.h"
#include "pk/gkr-pk-privkey.h"

static CK_RV
object_to_public_key (GkrPkObject *object, gcry_sexp_t *s_key)
{
	GkrPkPubkey *key;

	/* Validate and extract the key */
	if (!GKR_IS_PK_PUBKEY (object))
		return CKR_KEY_HANDLE_INVALID;
		
	key = GKR_PK_PUBKEY (object);
	if (gkr_pk_pubkey_get_algorithm (key) != GCRY_PK_RSA)
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
	if (gkr_pk_privkey_get_algorithm (key) != GCRY_PK_RSA)
		return CKR_KEY_TYPE_INCONSISTENT;

	*s_key = gkr_pk_privkey_get_key (key);
	if (!*s_key) {
		/* TODO: This happens when the user doesn't unlock key, proper code */
		g_warning ("couldn't get private key");
		return CKR_GENERAL_ERROR;
	}
	
	return CKR_OK;
}

static CK_RV
data_to_sexp (const gchar *format, guint nbits, GkrCryptoPadding padfunc, 
              const guchar *data, gsize n_data, gcry_sexp_t *sexp)
{
	guchar *padded = NULL;
	gcry_error_t gcry;
	gcry_mpi_t mpi;
	gsize n_padded;

	g_assert (format);
	g_assert (sexp);	
	
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	if (padfunc) {
		padded = (padfunc) (nbits, data, n_data, &n_padded);
		if (!padded)
			return CKR_DATA_LEN_RANGE;
	}
		
	/* Prepare the input s expression */
	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, 
                              padded ? padded : data, 
	                      padded ? n_padded : n_data, NULL);
	g_free (padded);

	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	gcry = gcry_sexp_build (sexp, NULL, format, mpi);
	gcry_mpi_release (mpi);

	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	g_assert (*sexp);
	return CKR_OK;
} 

static CK_RV
sexp_to_data (const gchar* format1, const gchar *format2, const gchar *format3,
              guint nbits, GkrCryptoPadding padfunc, gcry_sexp_t sexp, 
              guchar **data, gsize *n_data)
{
	g_assert (format1);
	g_assert (sexp);
	g_assert (data);
	g_assert (n_data);

	/* Now extract and send it back out */
	*data = gkr_crypto_sexp_extract_mpi_padded (sexp, nbits, n_data, padfunc,
	                                            format1, format2, format3, NULL);
	g_return_val_if_fail (*data, CKR_GENERAL_ERROR);

	return CKR_OK;  
} 

CK_RV
gkr_pkcs11_rsa_encrypt (GkrPkObject *key, GkrCryptoPadding padfunc,
                        const guchar *plain, gsize n_plain, 
                        guchar **encrypted, gsize *n_encrypted)
{
	gcry_sexp_t s_key, splain, senc;
	gcry_error_t gcry;
	guint nbits;
	CK_RV ret;
	
	g_return_val_if_fail (key, CKR_GENERAL_ERROR);

	ret = object_to_public_key (key, &s_key);
	if (ret != CKR_OK)
		return ret;
		
	/* If no output, then don't process */
	if (!plain)
		return CKR_OK;

	/* The key size */
	nbits = gcry_pk_get_nbits (s_key);
	g_return_val_if_fail (nbits > 0, CKR_GENERAL_ERROR);
	
	/* Prepare the input s expression */
	ret = data_to_sexp ("(data (flags raw) (value %m))", 
	                    nbits, padfunc, plain, n_plain, &splain);
	if (ret != CKR_OK)
		return ret;
	
	/* Do the magic */
	gcry = gcry_pk_encrypt (&senc, splain, s_key);
	gcry_sexp_release (splain);
	
	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_warning ("encrypting of the data failed: %s", gcry_strerror (gcry));
		return CKR_GENERAL_ERROR;
	}

	/* Now extract and send it back out */
	ret = sexp_to_data ("enc-val", "rsa", "a", nbits, NULL, senc, encrypted, n_encrypted);
	gcry_sexp_release (senc);
	
	return ret;
}

CK_RV
gkr_pkcs11_rsa_decrypt (GkrPkObject *object, GkrCryptoPadding padfunc, 
                        const guchar *encrypted, gsize n_encrypted, 
                        guchar **plain, gsize *n_plain)
{
	gcry_sexp_t s_key, splain, sdata;
	gcry_error_t gcry;
	guint nbits;
	CK_RV ret;
	
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);

	ret = object_to_private_key (object, &s_key);
	if (ret != CKR_OK)
		return ret;
		
	/* If no output, then don't process */
	if (!plain)
		return CKR_OK;

	/* The key size */
	nbits = gcry_pk_get_nbits (s_key);
	g_return_val_if_fail (nbits > 0, CKR_GENERAL_ERROR);
	
	if (n_encrypted != nbits / 8)
		return CKR_DATA_LEN_RANGE;
		
	/* Prepare the input s expression */
	ret = data_to_sexp ("(enc-val (flags) (rsa (a %m)))", 
	                    nbits, NULL, encrypted, n_encrypted, &sdata);
	if (ret != CKR_OK)
		return ret;
gkr_crypto_sexp_dump (sdata);
	
	/* Do the magic */
	gcry = gcry_pk_decrypt (&splain, sdata, s_key);
	gcry_sexp_release (sdata);
	
	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_warning ("decrypting of the data failed: %s", gcry_strerror (gcry));
		return CKR_GENERAL_ERROR;
	}
gkr_crypto_sexp_dump (splain);

	/* Now extract and send it back out */
	ret = sexp_to_data ("value", NULL, NULL, nbits, padfunc, splain, plain, n_plain);
	gcry_sexp_release (splain);
	
	return ret;
}

CK_RV
gkr_pkcs11_rsa_sign (GkrPkObject *object, GkrCryptoPadding padfunc, 
                     const guchar *input, gsize n_input, 
                     guchar **signature, gsize *n_signature)
{
	gcry_sexp_t s_key, ssig, sdata;
	gcry_error_t gcry;
	guint nbits;
	CK_RV ret;
	
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);

	ret = object_to_private_key (object, &s_key);
	if (ret != CKR_OK)
		return ret;
		
	/* If no output, then don't process */
	if (!signature)
		return CKR_OK;
		
	/* The key size */
	nbits = gcry_pk_get_nbits (s_key);
	g_return_val_if_fail (nbits > 0, CKR_GENERAL_ERROR);

	/* Prepare the input s expression */
	ret = data_to_sexp ("(data (flags raw) (value %m))", 
	                    nbits, padfunc, input, n_input, &sdata);
	if (ret != CKR_OK)
		return ret;

	/* Do the magic */
	gcry = gcry_pk_sign (&ssig, sdata, s_key);
	gcry_sexp_release (sdata);
	
	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_warning ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_GENERAL_ERROR;
	}

	/* Now extract and send it back out */
	ret = sexp_to_data ("rsa", "s", NULL, nbits, NULL, ssig, signature, n_signature);
	gcry_sexp_release (ssig);
	
	return ret;
}

CK_RV
gkr_pkcs11_rsa_verify (GkrPkObject *object, GkrCryptoPadding padfunc, 
                       const guchar *data, gsize n_data, 
                       const guchar *signature, gsize n_signature)
{
	gcry_sexp_t s_key, ssig, sdata;
	gcry_error_t gcry;
	guint nbits;
	CK_RV ret;
	
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);
	
	ret = object_to_public_key (object, &s_key);
	if (ret != CKR_OK)
		return ret;
		
	/* If no data, then don't process */
	if (!data)
		return CKR_OK;

	g_return_val_if_fail (data, CKR_GENERAL_ERROR);
	g_return_val_if_fail (signature, CKR_GENERAL_ERROR);
		
	/* The key size */
	nbits = gcry_pk_get_nbits (s_key);
	g_return_val_if_fail (nbits > 0, CKR_GENERAL_ERROR);

	/* Prepare the input s expressions */
	ret = data_to_sexp ("(data (flags raw) (value %m))", 
	                    nbits, padfunc, data, n_data, &sdata);
	if (ret != CKR_OK)
		return ret;

	ret = data_to_sexp ("(sig-val (rsa (s %m)))", 
	                    nbits, NULL, signature, n_signature, &ssig);
	if (ret != CKR_OK) {
		gcry_sexp_release (sdata);
		return ret;
	}
		
	/* Do the magic */
	gcry = gcry_pk_verify (ssig, sdata, s_key);
	gcry_sexp_release (sdata);
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
