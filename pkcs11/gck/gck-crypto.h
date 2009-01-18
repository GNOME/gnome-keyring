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

#ifndef GCKCRYPTO_H_
#define GCKCRYPTO_H_

#include <glib.h>

#include <gcrypt.h>

#include "pkcs11/pkcs11.h"

typedef guchar* (*GckCryptoPadding) (guint n_modulus, const guchar* raw, 
                                     gsize n_raw, gsize *n_padded);

static const CK_MECHANISM_TYPE GCK_CRYPTO_RSA_MECHANISMS[] = {
	CKM_RSA_PKCS,
	CKM_RSA_X_509
};

static const CK_MECHANISM_TYPE GCK_CRYPTO_DSA_MECHANISMS[] = {
	CKM_DSA
};

void                     gck_crypto_initialize                         (void);

CK_RV                    gck_crypto_perform                            (gcry_sexp_t sexp, 
                                                                        CK_MECHANISM_TYPE mech, 
                                                                        CK_ATTRIBUTE_TYPE method, 
                                                                        CK_BYTE_PTR bufone, 
                                                                        CK_ULONG n_bufone, 
                                                                        CK_BYTE_PTR buftwo, 
                                                                        CK_ULONG_PTR n_buftwo);

CK_RV                    gck_crypto_encrypt                            (gcry_sexp_t sexp, 
                                                                        CK_MECHANISM_TYPE mech, 
                                                                        CK_BYTE_PTR data, 
                                                                        CK_ULONG n_data, 
                                                                        CK_BYTE_PTR encrypted, 
                                                                        CK_ULONG_PTR n_encrypted);

CK_RV                    gck_crypto_encrypt_rsa                        (gcry_sexp_t sexp, 
                                                                        GckCryptoPadding padding, 
                                                                        CK_BYTE_PTR data, 
                                                                        CK_ULONG n_data, 
                                                                        CK_BYTE_PTR encrypted, 
                                                                        CK_ULONG_PTR n_encrypted);


CK_RV                    gck_crypto_decrypt                            (gcry_sexp_t sexp, 
                                                                        CK_MECHANISM_TYPE mech, 
                                                                        CK_BYTE_PTR encrypted, 
                                                                        CK_ULONG n_encrypted, 
									CK_BYTE_PTR data, 
									CK_ULONG_PTR n_data);

CK_RV                    gck_crypto_decrypt_rsa                        (gcry_sexp_t sexp, 
                                                                        GckCryptoPadding padding, 
                                                                        CK_BYTE_PTR encrypted, 
                                                                        CK_ULONG n_encrypted, 
                                                                        CK_BYTE_PTR data, 
                                                                        CK_ULONG_PTR n_data);

CK_RV                    gck_crypto_sign                               (gcry_sexp_t sexp, 
                                                                        CK_MECHANISM_TYPE mech, 
                                                                        CK_BYTE_PTR data, 
                                                                        CK_ULONG n_data, 
                                                                        CK_BYTE_PTR signature, 
                                                                        CK_ULONG_PTR n_signature);

CK_RV                    gck_crypto_sign_rsa                           (gcry_sexp_t sexp, 
                                                                        GckCryptoPadding padding, 
                                                                        CK_BYTE_PTR data, 
                                                                        CK_ULONG n_data, 
                                                                        CK_BYTE_PTR signature, 
                                                                        CK_ULONG_PTR n_signature);

CK_RV                    gck_crypto_sign_dsa                           (gcry_sexp_t sexp, 
                                                                        CK_BYTE_PTR data, 
                                                                        CK_ULONG n_data, 
                                                                        CK_BYTE_PTR signature, 
                                                                        CK_ULONG_PTR n_signature);

CK_RV                    gck_crypto_verify                             (gcry_sexp_t sexp, 
                                                                        CK_MECHANISM_TYPE mech, 
                                                                        CK_BYTE_PTR data, 
                                                                        CK_ULONG n_data, 
                                                                        CK_BYTE_PTR signature, 
                                                                        CK_ULONG n_signature);

CK_RV                    gck_crypto_verify_rsa                         (gcry_sexp_t sexp, 
                                                                        GckCryptoPadding padding, 
                                                                        CK_BYTE_PTR data, 
                                                                        CK_ULONG n_data, 
                                                                        CK_BYTE_PTR signature, 
                                                                        CK_ULONG n_signature);


CK_RV                    gck_crypto_verify_dsa                         (gcry_sexp_t sexp, 
                                                                        CK_BYTE_PTR data, 
                                                                        CK_ULONG n_data, 
                                                                        CK_BYTE_PTR signature, 
                                                                        CK_ULONG n_signature);

gboolean                 gck_crypto_sexp_parse_key                     (gcry_sexp_t sexp,
                                                                        int *algorithm, 
                                                                        gboolean *is_private, 
                                                                        gcry_sexp_t *numbers);

gboolean                 gck_crypto_sexp_key_to_public                 (gcry_sexp_t sexp, 
                                                                        gcry_sexp_t *pub);

gboolean                 gck_crypto_sexp_extract_mpi                   (gcry_sexp_t sexp, 
                                                                        gcry_mpi_t *mpi, 
                                                                        ...) G_GNUC_NULL_TERMINATED;

void                     gck_crypto_sexp_dump                          (gcry_sexp_t sexp);

guchar*	                 gck_crypto_rsa_pad_raw                        (guint bits, 
       	                                                                const guchar* raw,
       	                                                                gsize n_raw, 
       	                                                                gsize *n_padded);

guchar*                  gck_crypto_rsa_pad_one                        (guint bits, 
                                                                        const guchar* raw, 
                                                                        gsize n_raw, 
                                                                        gsize *n_padded);

guchar*                  gck_crypto_rsa_pad_two                        (guint bits, 
                                                                        const guchar* raw, 
                                                                        gsize n_raw, 
                                                                        gsize *n_padded);

guchar*                  gck_crypto_rsa_unpad_one                      (guint bits, 
                                                                        const guchar *padded, 
                                                                        gsize n_padded, 
                                                                        gsize *n_raw);

guchar*                  gck_crypto_rsa_unpad_two                      (guint bits, 
                                                                        const guchar* padded, 
                                                                        gsize n_padded, 
                                                                        gsize *n_raw);

#endif /* GCKCRYPTO_H_ */
