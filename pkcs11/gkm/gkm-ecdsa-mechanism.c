/*
 * gnome-keyring
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkm-crypto.h"
#include "gkm-ecdsa-mechanism.h"
#include "gkm-session.h"
#include "gkm-sexp.h"
#include "gkm-sexp-key.h"

#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

/* ----------------------------------------------------------------------------
 * PUBLIC
 */

CK_RV
gkm_ecdsa_mechanism_sign (gcry_sexp_t sexp, CK_BYTE_PTR data, CK_ULONG n_data,
                          CK_BYTE_PTR signature, CK_ULONG_PTR n_signature)
{
	gcry_sexp_t ssig, splain;
	gcry_error_t gcry;
	CK_ULONG size, key_bytes, key_bits;
	CK_RV rv;

	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	/* If no output, then don't process */
	key_bits = gcry_pk_get_nbits(sexp);
	key_bytes = (key_bits + 7)/8;
	if (!signature) {
		*n_signature = key_bytes * 2;
		return CKR_OK;
	} else if (*n_signature < (key_bytes * 2)) {
		*n_signature = key_bytes * 2;
		return CKR_BUFFER_TOO_SMALL;
	}

	/* Prepare the input s-expression */
	gcry = gcry_sexp_build (&splain, NULL, "(data (flags raw) (value %b))",
                                n_data, data);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	/* Do the magic */
	gcry = gcry_pk_sign (&ssig, splain, sexp);
	gcry_sexp_release (splain);

	/* TODO: Certain codes should be returned (data too big etc... ) */
	if (gcry) {
		g_message ("signing of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	/* signature consists of two mpint values concatenated */
	size = key_bytes;
	rv = gkm_crypto_sexp_to_data (ssig, key_bits, signature, &size, NULL, "ecdsa", "r", NULL);
	if (rv == CKR_OK) {
		g_return_val_if_fail (size == key_bytes, CKR_GENERAL_ERROR);
		rv = gkm_crypto_sexp_to_data (ssig, key_bits, signature + key_bytes, &size, NULL, "ecdsa", "s", NULL);
		if (rv == CKR_OK) {
			g_return_val_if_fail (size == key_bytes, CKR_GENERAL_ERROR);
			*n_signature = key_bytes * 2;
		}
	}

	gcry_sexp_release (ssig);
	return rv;
}

CK_RV
gkm_ecdsa_mechanism_verify (gcry_sexp_t sexp, CK_BYTE_PTR data, CK_ULONG n_data,
                            CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	gcry_sexp_t ssig, splain;
	gcry_error_t gcry;
	CK_ULONG key_bytes;

	g_return_val_if_fail (sexp, CKR_GENERAL_ERROR);
	g_return_val_if_fail (signature, CKR_ARGUMENTS_BAD);
	g_return_val_if_fail (data, CKR_ARGUMENTS_BAD);

	key_bytes = gcry_pk_get_nbits(sexp)/8;
	if (n_signature != key_bytes*2)
		return CKR_SIGNATURE_LEN_RANGE;

	/* Prepare the input s-expressions */
	gcry = gcry_sexp_build (&splain, NULL, "(data (flags raw) (value %b))",
                                n_data, data);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	gcry = gcry_sexp_build (&ssig, NULL, "(sig-val (ecdsa (r %b) (s %b)))",
                                key_bytes, signature, key_bytes, signature + key_bytes);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	/* Do the magic */
	gcry = gcry_pk_verify (ssig, splain, sexp);
	gcry_sexp_release (splain);
	gcry_sexp_release (ssig);

	/* TODO: See if any other codes should be mapped */
	if (gcry_err_code (gcry) == GPG_ERR_BAD_SIGNATURE) {
		return CKR_SIGNATURE_INVALID;
	} else if (gcry) {
		g_message ("verifying of the data failed: %s", gcry_strerror (gcry));
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

