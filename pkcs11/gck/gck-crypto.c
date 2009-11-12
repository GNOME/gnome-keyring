/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *  
 * You should have received a copy of the GNU Lesser General 
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "gck-crypto.h"
#include "gck-mechanism-dsa.h"
#include "gck-mechanism-rsa.h"
#include "gck-session.h"
#include "gck-sexp.h"
#include "gck-sexp-key.h"

#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

/* ----------------------------------------------------------------------------
 * PUBLIC
 */

CK_RV
gck_crypto_data_to_sexp (const gchar *format, guint nbits, GckCryptoPadding padding,
                         CK_BYTE_PTR data, CK_ULONG n_data, gcry_sexp_t *sexp)
{
	guchar *padded = NULL;
	gcry_error_t gcry;
	gcry_mpi_t mpi;
	gsize n_padded;

	g_assert (format);
	g_assert (sexp);	
	
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	if (padding) {
		padded = (padding) (nbits, data, n_data, &n_padded);
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

CK_RV
gck_crypto_sexp_to_data (gcry_sexp_t sexp, guint bits, CK_BYTE_PTR data,
                         CK_ULONG *n_data, GckCryptoPadding padding, ...)
{
	gcry_sexp_t at = NULL;
	gsize n_block, offset, len;
	gcry_mpi_t mpi = NULL;
	guchar *block;
	va_list va;
	gcry_error_t gcry;
	
	g_assert (sexp);
	g_assert (data);
	g_assert (n_data);
	g_assert (bits);

	/* First try and dig out sexp child based on arguments */
	va_start (va, padding);
	at = gck_sexp_get_childv (sexp, va);
	va_end (va);
	
	/* It's expected we would find it */
	g_return_val_if_fail (at != NULL, CKR_GENERAL_ERROR);

	/* Parse out the MPI */
	mpi = gcry_sexp_nth_mpi (at, 1, GCRYMPI_FMT_USG);
	g_return_val_if_fail (at != NULL, CKR_GENERAL_ERROR);
	gcry_sexp_release (at);
	
	/* Print out the MPI into the end of a temporary buffer */
	n_block = (bits + 7) / 8;
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &len, mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	g_return_val_if_fail (len <= n_block, CKR_GENERAL_ERROR);
	offset = n_block - len;
	block = g_malloc0 (n_block);
	memset (block, 0, offset);
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, block + offset, len, &len, mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	g_return_val_if_fail (len == n_block - offset, CKR_GENERAL_ERROR);
	gcry_mpi_release (mpi);
		
	/* Pad it properly if necessary */
	if (padding != NULL) {
		guchar *padded = (padding) (bits, block, n_block, &n_block);
		g_free (block);
		if (!padded)
			return CKR_DATA_LEN_RANGE;
		block = padded;
	}
	
	/* Now stuff it into the output buffer */
	if (n_block > *n_data)
		return CKR_BUFFER_TOO_SMALL;

	memcpy (data, block, n_block);
	*n_data = n_block;
	g_free (block);
	
	return CKR_OK;
}


CK_RV
gck_crypto_encrypt (GckSession *session, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data,
                    CK_ULONG n_data, CK_BYTE_PTR encrypted, CK_ULONG_PTR n_encrypted)
{
	GckSexp *sexp;

	switch (mech) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
		sexp = gck_session_get_crypto_state (session);
		g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
		return gck_crypto_encrypt_xsa (gck_sexp_get (sexp), mech, data, n_data, encrypted, n_encrypted);
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	}
}

CK_RV
gck_crypto_encrypt_xsa (gcry_sexp_t sexp, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data,
                        CK_ULONG n_data, CK_BYTE_PTR encrypted, CK_ULONG_PTR n_encrypted)
{
	int algorithm;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_encrypted, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);
	
	if (!gck_sexp_parse_key (sexp, &algorithm, NULL, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	/* 
	 * The algorithm checks below are merely sanity checks.
	 * Other code should have checed this at an earlier stage
	 * and return the right error codes if invalid.
	 */
	
	switch (mech) {
	case CKM_RSA_PKCS:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR); 
		rv = gck_mechanism_rsa_encrypt (sexp, gck_mechanism_rsa_pad_two, data, n_data, encrypted, n_encrypted);
		break;
	case CKM_RSA_X_509:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR);
		rv = gck_mechanism_rsa_encrypt (sexp, gck_mechanism_rsa_pad_raw, data, n_data, encrypted, n_encrypted);
		break;
	default:
		/* Again shouldn't be reached */
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	};
	
	return rv;	
}

CK_RV
gck_crypto_decrypt (GckSession *session, CK_MECHANISM_TYPE mech, CK_BYTE_PTR encrypted,
                    CK_ULONG n_encrypted, CK_BYTE_PTR data, CK_ULONG_PTR n_data)
{
	GckSexp *sexp;

	switch (mech) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
		sexp = gck_session_get_crypto_state (session);
		g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
		return gck_crypto_decrypt_xsa (gck_sexp_get (sexp), mech, encrypted, n_encrypted, data, n_data);
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	}
}

CK_RV
gck_crypto_decrypt_xsa (gcry_sexp_t sexp, CK_MECHANISM_TYPE mech, CK_BYTE_PTR encrypted,
                        CK_ULONG n_encrypted, CK_BYTE_PTR data, CK_ULONG_PTR n_data)
{
	int algorithm;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_data, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (encrypted, CKR_ARGUMENTS_BAD);
	
	if (!gck_sexp_parse_key (sexp, &algorithm, NULL, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	/* 
	 * The algorithm checks below are merely sanity checks.
	 * Other code should have checed this at an earlier stage
	 * and return the right error codes if invalid.
	 */
	
	switch (mech) {
	case CKM_RSA_PKCS:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR); 
		rv = gck_mechanism_rsa_decrypt (sexp, gck_mechanism_rsa_unpad_two, encrypted, n_encrypted, data, n_data);
		break;
	case CKM_RSA_X_509:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR);
		rv = gck_mechanism_rsa_decrypt (sexp, NULL, encrypted, n_encrypted, data, n_data);
		break;
	default:
		/* Again shouldn't be reached */
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	};
	
	return rv;	
}

CK_RV
gck_crypto_sign (GckSession *session, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data,
                 CK_ULONG n_data, CK_BYTE_PTR signature, CK_ULONG_PTR n_signature)
{
	GckSexp *sexp;

	switch (mech) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
	case CKM_DSA:
		sexp = gck_session_get_crypto_state (session);
		g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
		return gck_crypto_sign_xsa (gck_sexp_get (sexp), mech, data, n_data, signature, n_signature);
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	}
}

CK_RV
gck_crypto_sign_xsa (gcry_sexp_t sexp, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data,
                     CK_ULONG n_data, CK_BYTE_PTR signature, CK_ULONG_PTR n_signature)
{
	int algorithm;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);
	
	if (!gck_sexp_parse_key (sexp, &algorithm, NULL, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	/* 
	 * The algorithm checks below are merely sanity checks.
	 * Other code should have checed this at an earlier stage
	 * and return the right error codes if invalid.
	 */
	
	switch (mech) {
	case CKM_RSA_PKCS:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR); 
		rv = gck_mechanism_rsa_sign (sexp, gck_mechanism_rsa_pad_one, data, n_data, signature, n_signature);
		break;
	case CKM_RSA_X_509:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR);
		rv = gck_mechanism_rsa_sign (sexp, gck_mechanism_rsa_pad_raw, data, n_data, signature, n_signature);
		break;
	case CKM_DSA:
		g_return_val_if_fail (algorithm == GCRY_PK_DSA, CKR_GENERAL_ERROR);
		rv = gck_mechanism_dsa_sign (sexp, data, n_data, signature, n_signature);
		break;
	default:
		/* Again shouldn't be reached */
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	};
	
	return rv;
}

CK_RV
gck_crypto_verify (GckSession *session, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data,
                   CK_ULONG n_data, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	GckSexp *sexp;

	switch (mech) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
	case CKM_DSA:
		sexp = gck_session_get_crypto_state (session);
		g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
		return gck_crypto_verify_xsa (gck_sexp_get (sexp), mech, data, n_data, signature, n_signature);
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	}
}

CK_RV
gck_crypto_verify_xsa (gcry_sexp_t sexp, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data,
                       CK_ULONG n_data, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	int algorithm;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);
	
	if (!gck_sexp_parse_key (sexp, &algorithm, NULL, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	/* 
	 * The algorithm checks below are merely sanity checks.
	 * Other code should have checed this at an earlier stage
	 * and return the right error codes if invalid.
	 */
	
	switch (mech) {
	case CKM_RSA_PKCS:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR); 
		rv = gck_mechanism_rsa_verify (sexp, gck_mechanism_rsa_pad_one, data, n_data, signature, n_signature);
		break;
	case CKM_RSA_X_509:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR);
		rv = gck_mechanism_rsa_verify (sexp, gck_mechanism_rsa_pad_raw, data, n_data, signature, n_signature);
		break;
	case CKM_DSA:
		g_return_val_if_fail (algorithm == GCRY_PK_DSA, CKR_GENERAL_ERROR);
		rv = gck_mechanism_dsa_verify (sexp, data, n_data, signature, n_signature);
		break;
	default:
		/* Again shouldn't be reached */
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	};
	
	return rv;
}

CK_RV 
gck_crypto_perform (GckSession *session, CK_MECHANISM_TYPE mech, CK_ATTRIBUTE_TYPE method,
                    CK_BYTE_PTR bufone, CK_ULONG n_bufone, CK_BYTE_PTR buftwo, CK_ULONG_PTR n_buftwo)
{
	g_return_val_if_fail (GCK_IS_SESSION (session), CKR_GENERAL_ERROR);
	g_return_val_if_fail (method, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_buftwo, CKR_GENERAL_ERROR);
	
	switch (method) {
	case CKA_ENCRYPT:
		return gck_crypto_encrypt (session, mech, bufone, n_bufone, buftwo, n_buftwo);
	case CKA_DECRYPT:
		return gck_crypto_decrypt (session, mech, bufone, n_bufone, buftwo, n_buftwo);
	case CKA_SIGN:
		return gck_crypto_sign (session, mech, bufone, n_bufone, buftwo, n_buftwo);
	case CKA_VERIFY:
		return gck_crypto_verify (session, mech, bufone, n_bufone, buftwo, *n_buftwo);
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	}
}

/* ----------------------------------------------------------------------------
 * PREPARE FUNCTIONS
 */

CK_RV
gck_crypto_prepare (GckSession *session, CK_MECHANISM_TYPE mech, GckObject *key)
{
	g_return_val_if_fail (GCK_IS_SESSION (session), CKR_GENERAL_ERROR);

	switch (mech) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
	case CKM_DSA:
		return gck_crypto_prepare_xsa (session, mech, key);
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	}
}

CK_RV
gck_crypto_prepare_xsa (GckSession *session, CK_MECHANISM_TYPE mech, GckObject *key)
{
	GckSexp *sexp;

	g_return_val_if_fail (GCK_IS_SESSION (session), CKR_GENERAL_ERROR);
	g_return_val_if_fail (GCK_IS_SEXP_KEY (key), CKR_GENERAL_ERROR);

	/* Load up the actual sexp we're going to use */
	sexp = gck_sexp_key_acquire_crypto_sexp (GCK_SEXP_KEY (key), session);
	if (sexp == NULL)
		return CKR_USER_NOT_LOGGED_IN;

	gck_session_set_crypto_state (session, sexp, gck_sexp_unref);
	return CKR_OK;
}

/* --------------------------------------------------------------------------
 * INITIALIZATION
 */


void
gck_crypto_initialize (void)
{
	egg_libgcrypt_initialize ();
}
