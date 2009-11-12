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

#include "gck-mechanism-rsa.h"
#include "gck-sexp.h"

#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

/* ----------------------------------------------------------------------------
 * INTERNAL
 */

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
gck_mechanism_rsa_encrypt (gcry_sexp_t sexp, GckCryptoPadding padding, CK_BYTE_PTR data,
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
	rv = gck_crypto_data_to_sexp ("(data (flags raw) (value %m))",
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
	rv = gck_crypto_sexp_to_data (sdata, nbits, encrypted, n_encrypted, NULL,
	                              "enc-val", "rsa", "a", NULL);
	gcry_sexp_release (sdata);

	return rv;
}

CK_RV
gck_mechanism_rsa_decrypt (gcry_sexp_t sexp, GckCryptoPadding padding, CK_BYTE_PTR encrypted,
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
	rv = gck_crypto_data_to_sexp ("(enc-val (flags) (rsa (a %m)))",
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
	rv = gck_crypto_sexp_to_data (splain, nbits, data, n_data, padding, "value", NULL);
	gcry_sexp_release (splain);

	return rv;
}

CK_RV
gck_mechanism_rsa_sign (gcry_sexp_t sexp, GckCryptoPadding padding, CK_BYTE_PTR data,
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
	rv = gck_crypto_data_to_sexp ("(data (flags raw) (value %m))",
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
	rv = gck_crypto_sexp_to_data (ssig, nbits, signature, n_signature, NULL, "rsa", "s", NULL);
	gcry_sexp_release (ssig);

	return rv;
}

CK_RV
gck_mechanism_rsa_verify (gcry_sexp_t sexp, GckCryptoPadding padding, CK_BYTE_PTR data,
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
	rv = gck_crypto_data_to_sexp ("(data (flags raw) (value %m))",
	                   nbits, padding, data, n_data, &sdata);
	if (rv != CKR_OK)
		return rv;

	rv = gck_crypto_data_to_sexp ("(sig-val (rsa (s %m)))",
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

/* ----------------------------------------------------------------------------
 * PADDING FUNCTIONS
 */


guchar*
gck_mechanism_rsa_pad_raw (guint n_modulus, const guchar* raw,
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
gck_mechanism_rsa_pad_one (guint n_modulus, const guchar* raw,
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
gck_mechanism_rsa_pad_two (guint n_modulus, const guchar* raw,
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
gck_mechanism_rsa_unpad_one (guint bits, const guchar *padded,
                             gsize n_padded, gsize *n_raw)
{
	return unpad_rsa_pkcs1 (0x01, bits, padded, n_padded, n_raw);
}

guchar*
gck_mechanism_rsa_unpad_two (guint bits, const guchar *padded,
                             gsize n_padded, gsize *n_raw)
{
	return unpad_rsa_pkcs1 (0x02, bits, padded, n_padded, n_raw);
}
