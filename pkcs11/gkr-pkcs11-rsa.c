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

CK_RV
gkr_pkcs11_rsa_raw_decrypt (GkrPkObject *object, const guchar *encrypted, gsize n_encrypted, 
                            guchar **plain, gsize *n_plain)
{
	gcry_sexp_t s_key, splain, sdata;
	GkrPkPrivkey *key;
	gcry_error_t gcry;
	gcry_mpi_t mpi;
	gboolean res;
	guint nbits, zeroes;
	
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);

	/* Validate and extract the key */
	if (!GKR_IS_PK_PRIVKEY (object))
		return CKR_KEY_HANDLE_INVALID;
		
	key = GKR_PK_PRIVKEY (object);
	if (gkr_pk_privkey_get_algorithm (key) != GCRY_PK_RSA)
		return CKR_KEY_TYPE_INCONSISTENT;

	s_key = gkr_pk_privkey_get_key (key);
	if (!s_key) {
		g_warning ("couldn't get private decrypting key");
		return CKR_GENERAL_ERROR;
	}
	
	/* If no output, then don't process */
	if (!plain)
		return CKR_OK;
		
	/* Prepare the input s expression */
	g_return_val_if_fail (encrypted, CKR_GENERAL_ERROR);
	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, encrypted, n_encrypted, NULL);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	gcry = gcry_sexp_build (&sdata, NULL, "(enc-val (flags no-blinding) (rsa (a %m)))", mpi);
	gcry_mpi_release (mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	
	/* Do the magic */
	gcry = gcry_pk_decrypt (&splain, sdata, s_key);
	gcry_sexp_release (sdata);
	
	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_warning ("decrypting of the data failed: %s", gcry_strerror (gcry));
		return CKR_GENERAL_ERROR;
	}

	/* Now extract and send it back out */
	res = gkr_crypto_sexp_extract_mpi (splain, &mpi, "value", NULL);
	gcry_sexp_release (splain);
	g_return_val_if_fail (res, CKR_GENERAL_ERROR);

	/* The key size */
	nbits = gcry_pk_get_nbits (s_key);
	g_return_val_if_fail (nbits > 0, CKR_GENERAL_ERROR);

	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_STD, NULL, 0, n_plain, mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	zeroes = (*n_plain < nbits / 8) ? (nbits / 8) - *n_plain : 0;
	*plain = g_malloc0 (*n_plain + zeroes);
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, *plain + zeroes, *n_plain, n_plain, mpi);	
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	*n_plain += zeroes;
	g_assert (*n_plain >= nbits / 8);
	g_assert (*plain);

	gcry_mpi_release (mpi);
	
	return CKR_OK;
}

CK_RV
gkr_pkcs11_rsa_raw_sign (GkrPkObject *object, const guchar *input, gsize n_input, 
                         guchar **output, gsize *n_output)
{
	gcry_sexp_t s_key, ssig, sdata;
	GkrPkPrivkey *key;
	gcry_error_t gcry;
	gcry_mpi_t mpi;
	gboolean res;
	
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);

	/* Validate and extract the key */
	if (!GKR_IS_PK_PRIVKEY (object))
		return CKR_KEY_HANDLE_INVALID;
		
	key = GKR_PK_PRIVKEY (object);
	if (gkr_pk_privkey_get_algorithm (key) != GCRY_PK_RSA)
		return CKR_KEY_TYPE_INCONSISTENT;

	s_key = gkr_pk_privkey_get_key (key);
	if (!s_key) {
		g_warning ("couldn't get private signing key");
		return CKR_GENERAL_ERROR;
	}
		
	/* If no output, then don't process */
	if (!output)
		return CKR_OK;
		
	/* Prepare the input s expression */
	g_return_val_if_fail (input, CKR_GENERAL_ERROR);
	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, input, n_input, NULL);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	gcry = gcry_sexp_build (&sdata, NULL, "(data (flags raw) (value %m))", mpi);
	gcry_mpi_release (mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	
	/* Do the magic */
	gcry = gcry_pk_sign (&ssig, sdata, s_key);
	gcry_sexp_release (sdata);
	
	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_warning ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_GENERAL_ERROR;
	}

	/* Now extract and send it back out */
	res = gkr_crypto_sexp_extract_mpi (ssig, &mpi, "rsa", "s", NULL);
	gcry_sexp_release (ssig);
	g_return_val_if_fail (res, CKR_GENERAL_ERROR);

	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, n_output, mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	*output = g_malloc0 (*n_output);
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, *output, *n_output, n_output, mpi);	
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	gcry_mpi_release (mpi);
	
	g_return_val_if_fail (*output, CKR_GENERAL_ERROR);
	
	return CKR_OK;
}

CK_RV
gkr_pkcs11_rsa_raw_verify (GkrPkObject *object, const guchar *data, gsize n_data, 
                           const guchar *signature, gsize n_signature)
{
	gcry_sexp_t s_key, ssig, sdata;
	GkrPkPubkey *key;
	gcry_error_t gcry;
	gcry_mpi_t mpi;
	
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);
	
	/* Validate and extract the key */
	if (!GKR_IS_PK_PUBKEY (object))
		return CKR_KEY_HANDLE_INVALID;
		
	key = GKR_PK_PUBKEY (object);
	if (gkr_pk_pubkey_get_algorithm (key) != GCRY_PK_RSA)
		return CKR_KEY_TYPE_INCONSISTENT;

	s_key = gkr_pk_pubkey_get_key (key);
	if (!s_key) {
		g_warning ("couldn't get public verifying key");
		return CKR_GENERAL_ERROR;
	}
		
	/* If no data, then don't process */
	if (!data)
		return CKR_OK;

	g_return_val_if_fail (data, CKR_GENERAL_ERROR);
	g_return_val_if_fail (signature, CKR_GENERAL_ERROR);
		
	/* Prepare the input s expressions */
	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, data, n_data, NULL);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	gcry = gcry_sexp_build (&sdata, NULL, "(data (flags raw) (value %m))", mpi);
	gcry_mpi_release (mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, signature, n_signature, NULL);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	gcry = gcry_sexp_build (&ssig, NULL, "(sig-val (rsa (s %m)))", mpi);
	gcry_mpi_release (mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	
	/* Do the magic */
	gcry = gcry_pk_verify (ssig, sdata, s_key);
	gcry_sexp_release (sdata);
	gcry_sexp_release (ssig);
	
	/* TODO: See if any other codes should be mapped */
	if (gcry == GPG_ERR_BAD_SIGNATURE) {
		return CKR_SIGNATURE_INVALID;
	} else if (gcry) {
		g_warning ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}
