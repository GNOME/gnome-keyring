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

#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

/* ----------------------------------------------------------------------------
 * INTERNAL
 */

static gcry_sexp_t
sexp_get_childv (gcry_sexp_t sexp, va_list va)
{
	gcry_sexp_t at = NULL;
	gcry_sexp_t child;
	const char *name;
	
	for(;;) {
		name = va_arg (va, const char*);
		if (!name)
			break;

		child = gcry_sexp_find_token (at ? at : sexp, name, 0);
		gcry_sexp_release (at);
		at = child;
		if (at == NULL)
			break;
	}
	
	va_end (va);

	return at;
}

static CK_RV
data_to_sexp (const gchar *format, guint nbits, GckCryptoPadding padding, 
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

/* For the sake of checking arguments */
static CK_RV
sexp_to_data (gcry_sexp_t sexp, guint bits, CK_BYTE_PTR data, 
              CK_ULONG *n_data, GckCryptoPadding padding, 
              ...) G_GNUC_NULL_TERMINATED;

static CK_RV
sexp_to_data (gcry_sexp_t sexp, guint bits, CK_BYTE_PTR data, 
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
	at = sexp_get_childv (sexp, va);
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

static void
fill_random_nonzero (guchar *data, gsize n_data)
{
	guchar *rnd;
	guint n_zero, i, j;
	
	gcry_randomize (data, n_data, GCRY_STRONG_RANDOM);

	/* Find any zeros in random data */
	n_zero = 0;
	for (i = 0; i < n_data; ++i) {
		if (data[i] == 0x00)
			++n_zero;
	}

	while (n_zero > 0) {
		rnd = gcry_random_bytes (n_zero, GCRY_STRONG_RANDOM);
		n_zero = 0;
		for (i = 0, j = 0; i < n_data; ++i) {
			if (data[i] != 0x00)
				continue;
				
			/* Use some of the replacement data */
			data[i] = rnd[j];
			++j;
			
			/* It's zero again :( */
			if (data[i] == 0x00)
				n_zero++;
		}
		
		gcry_free (rnd);
	}
}

static guchar*
unpad_rsa_pkcs1 (guchar bt, guint n_modulus, const guchar* padded,
                 gsize n_padded, gsize *n_raw)
{ 
	const guchar *at;
	guint check;
	guchar *raw;
	
	check = (n_modulus + 7) / 8;
	
	/* The absolute minimum size including padding */
	g_return_val_if_fail (check >= 3 + 8, NULL);
	
	if (n_padded != check)
		return NULL;
		
	/* Check the header */
	if (padded[0] != 0x00 || padded[1] != bt)
		return NULL;
	
	/* The first zero byte after the header */
	at = memchr (padded + 2, 0x00, n_padded - 2);
	if (!at)
		return NULL;
		
	++at;
	*n_raw = n_padded - (at - padded);
	raw = g_new0 (guchar, *n_raw);
	memcpy (raw, at, *n_raw);
	return raw;
}


/* ----------------------------------------------------------------------------
 * PUBLIC
 */

CK_RV
gck_crypto_encrypt (gcry_sexp_t sexp, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, 
                    CK_ULONG n_data, CK_BYTE_PTR encrypted, CK_ULONG_PTR n_encrypted)
{
	int algorithm;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_encrypted, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);
	
	if (!gck_crypto_sexp_parse_key (sexp, &algorithm, NULL, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	/* 
	 * The algorithm checks below are merely sanity checks.
	 * Other code should have checed this at an earlier stage
	 * and return the right error codes if invalid.
	 */
	
	switch (mech) {
	case CKM_RSA_PKCS:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR); 
		rv = gck_crypto_encrypt_rsa (sexp, gck_crypto_rsa_pad_two, data, n_data, encrypted, n_encrypted);
		break;
	case CKM_RSA_X_509:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR);
		rv = gck_crypto_encrypt_rsa (sexp, gck_crypto_rsa_pad_raw, data, n_data, encrypted, n_encrypted);
		break;
	default:
		/* Again shouldn't be reached */
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	};
	
	return rv;	
}

CK_RV
gck_crypto_encrypt_rsa (gcry_sexp_t sexp, GckCryptoPadding padding, CK_BYTE_PTR data, 
                        CK_ULONG n_data, CK_BYTE_PTR encrypted, CK_ULONG_PTR n_encrypted)
{
	gcry_sexp_t splain, sdata;
	gcry_error_t gcry;
	guint nbits;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_encrypted, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	nbits = gcry_pk_get_nbits (sexp);
	g_return_val_if_fail (nbits > 0, CKR_GENERAL_ERROR);

	/* Just want to know the length */
	if (!encrypted) {
		*n_encrypted = (nbits + 7) / 8;
		return CKR_OK;
	}

	/* Prepare the input s expression */
	rv = data_to_sexp ("(data (flags raw) (value %m))", 
	                   nbits, padding, data, n_data, &splain);
	if (rv != CKR_OK)
		return rv;
	
	/* Do the magic */
	gcry = gcry_pk_encrypt (&sdata, splain, sexp);
	gcry_sexp_release (splain);
	
	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_message ("encrypting of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	/* Now extract and send it back out */
	rv = sexp_to_data (sdata, nbits, encrypted, n_encrypted, NULL, "enc-val", "rsa", "a", NULL);
	gcry_sexp_release (sdata);
	
	return rv;
}

CK_RV
gck_crypto_decrypt (gcry_sexp_t sexp, CK_MECHANISM_TYPE mech, CK_BYTE_PTR encrypted, 
                    CK_ULONG n_encrypted, CK_BYTE_PTR data, CK_ULONG_PTR n_data)
{
	int algorithm;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_data, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (encrypted, CKR_ARGUMENTS_BAD);
	
	if (!gck_crypto_sexp_parse_key (sexp, &algorithm, NULL, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	/* 
	 * The algorithm checks below are merely sanity checks.
	 * Other code should have checed this at an earlier stage
	 * and return the right error codes if invalid.
	 */
	
	switch (mech) {
	case CKM_RSA_PKCS:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR); 
		rv = gck_crypto_decrypt_rsa (sexp, gck_crypto_rsa_unpad_two, encrypted, n_encrypted, data, n_data);
		break;
	case CKM_RSA_X_509:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR);
		rv = gck_crypto_decrypt_rsa (sexp, NULL, encrypted, n_encrypted, data, n_data);
		break;
	default:
		/* Again shouldn't be reached */
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	};
	
	return rv;	
}

CK_RV
gck_crypto_decrypt_rsa (gcry_sexp_t sexp, GckCryptoPadding padding, CK_BYTE_PTR encrypted, 
                        CK_ULONG n_encrypted, CK_BYTE_PTR data, CK_ULONG_PTR n_data)
{
	gcry_sexp_t splain, sdata;
	gcry_error_t gcry;
	guint nbits;
	CK_RV rv;

	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_data, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (encrypted, CKR_ARGUMENTS_BAD);

	nbits = gcry_pk_get_nbits (sexp);
	g_return_val_if_fail (nbits > 0, CKR_GENERAL_ERROR);

	/* Just want to know the length */
	if (!data) {
		*n_data = (nbits + 7) / 8;
		return CKR_OK;
	}
	
	if (n_encrypted != (nbits + 7) / 8) 
		return CKR_DATA_LEN_RANGE;
	
	/* Prepare the input s expression */
	rv = data_to_sexp ("(enc-val (flags) (rsa (a %m)))", 
	                   nbits, NULL, encrypted, n_encrypted, &sdata);
	if (rv != CKR_OK)
		return rv;

	/* Do the magic */
	gcry = gcry_pk_decrypt (&splain, sdata, sexp);
	gcry_sexp_release (sdata);

	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_message ("decrypting of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	/* Now extract and send it back out */
	rv = sexp_to_data (splain, nbits, data, n_data, padding, "value", NULL);
	gcry_sexp_release (splain);
	
	return rv;
}

CK_RV
gck_crypto_sign (gcry_sexp_t sexp, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, 
                 CK_ULONG n_data, CK_BYTE_PTR signature, CK_ULONG_PTR n_signature)
{
	int algorithm;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);
	
	if (!gck_crypto_sexp_parse_key (sexp, &algorithm, NULL, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	/* 
	 * The algorithm checks below are merely sanity checks.
	 * Other code should have checed this at an earlier stage
	 * and return the right error codes if invalid.
	 */
	
	switch (mech) {
	case CKM_RSA_PKCS:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR); 
		rv = gck_crypto_sign_rsa (sexp, gck_crypto_rsa_pad_one, data, n_data, signature, n_signature);
		break;
	case CKM_RSA_X_509:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR);
		rv = gck_crypto_sign_rsa (sexp, gck_crypto_rsa_pad_raw, data, n_data, signature, n_signature);
		break;
	case CKM_DSA:
		g_return_val_if_fail (algorithm == GCRY_PK_DSA, CKR_GENERAL_ERROR);
		rv = gck_crypto_sign_dsa (sexp, data, n_data, signature, n_signature);
		break;
	default:
		/* Again shouldn't be reached */
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	};
	
	return rv;
}

CK_RV
gck_crypto_sign_rsa (gcry_sexp_t sexp, GckCryptoPadding padding, CK_BYTE_PTR data, 
                     CK_ULONG n_data, CK_BYTE_PTR signature, CK_ULONG_PTR n_signature)
{
	gcry_sexp_t ssig, sdata;
	guint nbits; 
	gcry_error_t gcry;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	nbits = gcry_pk_get_nbits (sexp);
	g_return_val_if_fail (nbits > 0, CKR_GENERAL_ERROR);

	/* Just want to know the length */
	if (!signature) {
		*n_signature = (nbits + 7) / 8;
		return CKR_OK;
	}
	
	/* Prepare the input sexp */
	rv = data_to_sexp ("(data (flags raw) (value %m))", 
	                    nbits, padding, data, n_data, &sdata);
	if (rv != CKR_OK)
		return rv;

	/* Do the magic */
	gcry = gcry_pk_sign (&ssig, sdata, sexp);
	gcry_sexp_release (sdata);

	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_message ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	/* Now extract and send it back out */
	rv = sexp_to_data (ssig, nbits, signature, n_signature, NULL, "rsa", "s", NULL);
	gcry_sexp_release (ssig);
	
	return rv;
}

CK_RV
gck_crypto_sign_dsa (gcry_sexp_t sexp, CK_BYTE_PTR data, CK_ULONG n_data, 
                     CK_BYTE_PTR signature, CK_ULONG_PTR n_signature)
{
	gcry_sexp_t ssig, splain;
	gcry_error_t gcry;
	gcry_mpi_t mpi;
	CK_ULONG size;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	if (n_data != 20)
		return CKR_DATA_LEN_RANGE;
	
	/* If no output, then don't process */
	if (!signature) {
		*n_signature = 40;
		return CKR_OK;
	} else if (*n_signature < 40) {
		*n_signature = 40;
		return CKR_BUFFER_TOO_SMALL;
	}
				
	/* Prepare the input s-expression */
	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, data, n_data, NULL);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	gcry = gcry_sexp_build (&splain, NULL, "(data (flags raw) (value %m))", mpi);
	gcry_mpi_release (mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	/* Do the magic */
	gcry = gcry_pk_sign (&ssig, splain, sexp);
	gcry_sexp_release (splain);
	
	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_message ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	g_assert (*n_signature >= 40);

	size = 20;
	rv = sexp_to_data (ssig, 20 * 8, signature, &size, NULL, "dsa", "r", NULL);
	if (rv == CKR_OK) {
		g_return_val_if_fail (size == 20, CKR_GENERAL_ERROR);
		rv = sexp_to_data (ssig, 20 * 8, signature + 20, &size, NULL, "dsa", "s", NULL);
		if (rv == CKR_OK) {
			g_return_val_if_fail (size == 20, CKR_GENERAL_ERROR);
			*n_signature = 40;
		}
	}
	
	gcry_sexp_release (ssig);
	return CKR_OK;
}

CK_RV
gck_crypto_verify (gcry_sexp_t sexp, CK_MECHANISM_TYPE mech, CK_BYTE_PTR data, 
                   CK_ULONG n_data, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	int algorithm;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);
	
	if (!gck_crypto_sexp_parse_key (sexp, &algorithm, NULL, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	/* 
	 * The algorithm checks below are merely sanity checks.
	 * Other code should have checed this at an earlier stage
	 * and return the right error codes if invalid.
	 */
	
	switch (mech) {
	case CKM_RSA_PKCS:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR); 
		rv = gck_crypto_verify_rsa (sexp, gck_crypto_rsa_pad_one, data, n_data, signature, n_signature);
		break;
	case CKM_RSA_X_509:
		g_return_val_if_fail (algorithm == GCRY_PK_RSA, CKR_GENERAL_ERROR);
		rv = gck_crypto_verify_rsa (sexp, gck_crypto_rsa_pad_raw, data, n_data, signature, n_signature);
		break;
	case CKM_DSA:
		g_return_val_if_fail (algorithm == GCRY_PK_DSA, CKR_GENERAL_ERROR);
		rv = gck_crypto_verify_dsa (sexp, data, n_data, signature, n_signature);
		break;
	default:
		/* Again shouldn't be reached */
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	};
	
	return rv;
}

CK_RV
gck_crypto_verify_rsa (gcry_sexp_t sexp, GckCryptoPadding padding, CK_BYTE_PTR data, 
                       CK_ULONG n_data, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	gcry_sexp_t ssig, sdata;
	gcry_error_t gcry;
	guint nbits;
	CK_RV rv;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	/* The key size */
	nbits = gcry_pk_get_nbits (sexp);
	g_return_val_if_fail (nbits > 0, CKR_GENERAL_ERROR);
	
	if (n_signature != (nbits + 7) / 8)
		return CKR_SIGNATURE_LEN_RANGE;

	/* Prepare the input s expressions */
	rv = data_to_sexp ("(data (flags raw) (value %m))", 
	                   nbits, padding, data, n_data, &sdata);
	if (rv != CKR_OK)
		return rv;

	rv = data_to_sexp ("(sig-val (rsa (s %m)))", 
	                   nbits, NULL, signature, n_signature, &ssig);
	if (rv != CKR_OK) {
		gcry_sexp_release (sdata);
		return rv;
	}
		
	/* Do the magic */
	gcry = gcry_pk_verify (ssig, sdata, sexp);
	gcry_sexp_release (sdata);
	gcry_sexp_release (ssig);
	
	/* TODO: See if any other codes should be mapped */
	if (gcry_err_code (gcry) == GPG_ERR_BAD_SIGNATURE) {
		return CKR_SIGNATURE_INVALID;
	} else if (gcry) {
		g_message ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV
gck_crypto_verify_dsa (gcry_sexp_t sexp, CK_BYTE_PTR data, CK_ULONG n_data, 
                       CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	gcry_sexp_t ssig, splain;
	gcry_error_t gcry;
	gcry_mpi_t mpi, mpi2;
	
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	if (n_data != 20)
		return CKR_DATA_LEN_RANGE;				
	if (n_signature != 40)
		return CKR_SIGNATURE_LEN_RANGE;

	/* Prepare the input s-expressions */
	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, data, n_data, NULL);
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
	gcry = gcry_pk_verify (ssig, splain, sexp);
	gcry_sexp_release (splain);
	gcry_sexp_release (ssig);
	
	/* TODO: See if any other codes should be mapped */
	if (gcry_err_code (gcry) == GPG_ERR_BAD_SIGNATURE) {
		return CKR_SIGNATURE_INVALID;
	} else if (gcry) {
		g_message ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV 
gck_crypto_perform (gcry_sexp_t sexp, CK_MECHANISM_TYPE mech, CK_ATTRIBUTE_TYPE method, 
                    CK_BYTE_PTR bufone, CK_ULONG n_bufone, CK_BYTE_PTR buftwo, CK_ULONG_PTR n_buftwo)
{
	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (method, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_buftwo, CKR_GENERAL_ERROR);
	
	switch (method) {
	case CKA_ENCRYPT:
		return gck_crypto_encrypt (sexp, mech, bufone, n_bufone, buftwo, n_buftwo);
	case CKA_DECRYPT:
		return gck_crypto_decrypt (sexp, mech, bufone, n_bufone, buftwo, n_buftwo);
	case CKA_SIGN:
		return gck_crypto_sign (sexp, mech, bufone, n_bufone, buftwo, n_buftwo);
	case CKA_VERIFY:
		return gck_crypto_verify (sexp, mech, bufone, n_bufone, buftwo, *n_buftwo);
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	}
}

/* ----------------------------------------------------------------------------
 * SEXP FUNCTIONS
 */

#define PUBLIC_KEY "public-key"
#define PUBLIC_KEY_L 10
#define PRIVATE_KEY "private-key"
#define PRIVATE_KEY_L 11

gboolean
gck_crypto_sexp_parse_key (gcry_sexp_t s_key, int *algorithm, gboolean *is_private, 
                           gcry_sexp_t *numbers)
{
	gboolean ret = FALSE;
	gcry_sexp_t child = NULL;
	gchar *str = NULL;
  	const gchar *data;
  	gsize n_data;
  	gboolean priv;
  	int algo;

	data = gcry_sexp_nth_data (s_key, 0, &n_data);
	if (!data) 
		goto done;

	if (n_data == PUBLIC_KEY_L && strncmp (data, PUBLIC_KEY, PUBLIC_KEY_L) == 0)
		priv = FALSE;
	else if (n_data == PRIVATE_KEY_L && strncmp (data, PRIVATE_KEY, PRIVATE_KEY_L) == 0)
		priv = TRUE;
	else
		goto done;

	child = gcry_sexp_nth (s_key, 1);
	if (!child)
		goto done;
		
	data = gcry_sexp_nth_data (child, 0, &n_data);
	if (!data)
		goto done;
		
	str = g_alloca (n_data + 1);
	memcpy (str, data, n_data);
	str[n_data] = 0;
	
	algo = gcry_pk_map_name (str);
	if (!algo)
		goto done;

	/* Yay all done */
	if (algorithm)
		*algorithm = algo;
	if (numbers) {
		*numbers = child;
		child = NULL;
	}
	if (is_private)
		*is_private = priv;

	ret = TRUE;
	
done:
	gcry_sexp_release (child);
	return ret;
}

static gcry_sexp_t
rsa_numbers_to_public (gcry_sexp_t rsa)
{
	gcry_sexp_t pubkey = NULL;
	gcry_mpi_t n, e;
	gcry_error_t gcry;
	
	n = e = NULL;
	
	if (!gck_crypto_sexp_extract_mpi (rsa, &n, "n", NULL) || 
	    !gck_crypto_sexp_extract_mpi (rsa, &e, "e", NULL))
	    	goto done;
	    	
	gcry = gcry_sexp_build (&pubkey, NULL, "(public-key (rsa (n %m) (e %m)))",
	                        n, e);
	if (gcry)
		goto done;
	g_assert (pubkey);
	
done:
	gcry_mpi_release (n);
	gcry_mpi_release (e);

	return pubkey;
}

static gcry_sexp_t
dsa_numbers_to_public (gcry_sexp_t dsa)
{
	gcry_mpi_t p, q, g, y;
	gcry_sexp_t pubkey = NULL;
	gcry_error_t gcry;
	
	p = q = g = y = NULL;
	
	if (!gck_crypto_sexp_extract_mpi (dsa, &p, "p", NULL) || 
	    !gck_crypto_sexp_extract_mpi (dsa, &q, "q", NULL) ||
	    !gck_crypto_sexp_extract_mpi (dsa, &g, "g", NULL) ||
	    !gck_crypto_sexp_extract_mpi (dsa, &y, "y", NULL))
	    	goto done;
	    	
	gcry = gcry_sexp_build (&pubkey, NULL, "(public-key (dsa (p %m) (q %m) (g %m) (y %m)))",
	                        p, q, g, y);
	if (gcry)
		goto done;
	g_assert (pubkey);
	
done:
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);

	return pubkey;
}

gboolean
gck_crypto_sexp_key_to_public (gcry_sexp_t privkey, gcry_sexp_t *pubkey)
{
	gcry_sexp_t numbers;
	int algorithm;

	if (!gck_crypto_sexp_parse_key (privkey, &algorithm, NULL, &numbers))
		g_return_val_if_reached (FALSE);
		
	switch (algorithm) {
	case GCRY_PK_RSA:
		*pubkey = rsa_numbers_to_public (numbers);
		break;
	case GCRY_PK_DSA:
		*pubkey = dsa_numbers_to_public (numbers);
		break;
	default:
		g_return_val_if_reached (FALSE);
	} 
	
	gcry_sexp_release (numbers);
	return *pubkey ? TRUE : FALSE;
}

gboolean
gck_crypto_sexp_extract_mpi (gcry_sexp_t sexp, gcry_mpi_t *mpi, ...)
{
	gcry_sexp_t at = NULL;
	va_list va;
	
	g_assert (sexp);
	g_assert (mpi);
	
	va_start (va, mpi);
	at = sexp_get_childv (sexp, va);
	va_end (va);
	
	*mpi = NULL;
	if (at)
		*mpi = gcry_sexp_nth_mpi (at ? at : sexp, 1, GCRYMPI_FMT_USG);
	if (at)
		gcry_sexp_release (at);

	return (*mpi) ? TRUE : FALSE;
}

void
gck_crypto_sexp_dump (gcry_sexp_t sexp)
{
	gsize len;
	gchar *buf;
	
	len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	buf = g_malloc (len);
	gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, buf, len);
	g_printerr ("%s", buf);
	g_free (buf);
}

/* ----------------------------------------------------------------------------
 * PADDING FUNCTIONS
 */


guchar*
gck_crypto_rsa_pad_raw (guint n_modulus, const guchar* raw,
                        gsize n_raw, gsize *n_padded)
{
	gint total, n_pad;
	guchar *padded;

	/*
	 * 0x00 0x00 0x00 ... 0x?? 0x?? 0x?? ...
         *   padding               data
         */

	total = (n_modulus + 7) / 8;
	n_pad = total - n_raw;
	if (n_pad < 0) /* minumum padding */
		return NULL;

	padded = g_new0 (guchar, total);
	memset (padded, 0x00, n_pad);
	memcpy (padded + n_pad, raw, n_raw);
	
	*n_padded = total;
	return padded;
}

guchar*
gck_crypto_rsa_pad_one (guint n_modulus, const guchar* raw, 
                        gsize n_raw, gsize *n_padded)
{
	gint total, n_pad;
	guchar *padded;

	/*
	 * 0x00 0x01 0xFF 0xFF ... 0x00 0x?? 0x?? 0x?? ...
         *      type  padding              data
         */

	total = (n_modulus + 7) / 8;
	n_pad = total - 3 - n_raw;
	if (n_pad < 8) /* minumum padding */
		return NULL;

	padded = g_new0 (guchar, total);
	padded[1] = 1; /* Block type */
	memset (padded + 2, 0xff, n_pad);
	memcpy (padded + 3 + n_pad, raw, n_raw); 
	
	*n_padded = total;
	return padded;
}

guchar*
gck_crypto_rsa_pad_two (guint n_modulus, const guchar* raw, 
                        gsize n_raw, gsize *n_padded)
{
	gint total, n_pad;
	guchar *padded;

	/*
	 * 0x00 0x01 0x?? 0x?? ... 0x00 0x?? 0x?? 0x?? ...
         *      type  padding              data
         */

	total = (n_modulus + 7) / 8;
	n_pad = total - 3 - n_raw;
	if (n_pad < 8) /* minumum padding */
		return NULL;

	padded = g_new0 (guchar, total);
	padded[1] = 2; /* Block type */
	fill_random_nonzero (padded + 2, n_pad);
	memcpy (padded + 3 + n_pad, raw, n_raw); 
	
	*n_padded = total;
	return padded;
}

guchar* 
gck_crypto_rsa_unpad_one (guint bits, const guchar *padded, 
                          gsize n_padded, gsize *n_raw)
{
	return unpad_rsa_pkcs1 (0x01, bits, padded, n_padded, n_raw);
}

guchar* 
gck_crypto_rsa_unpad_two (guint bits, const guchar *padded, 
                          gsize n_padded, gsize *n_raw)
{
	return unpad_rsa_pkcs1 (0x02, bits, padded, n_padded, n_raw);
}

/* --------------------------------------------------------------------------
 * INITIALIZATION
 */


void
gck_crypto_initialize (void)
{
	egg_libgcrypt_initialize ();
}
