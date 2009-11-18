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

#include "gck-padding.h"
#include "gck-types.h"

#include "pkcs11/pkcs11.h"

#include <glib.h>

#include <gcrypt.h>

void                     gck_crypto_initialize                         (void);

CK_RV                    gck_crypto_prepare                            (GckSession *session,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        GckObject *key);

CK_RV                    gck_crypto_prepare_xsa                        (GckSession *session,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        GckObject *key);

CK_RV                    gck_crypto_perform                            (GckSession *session,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_ATTRIBUTE_TYPE method,
                                                                        CK_BYTE_PTR bufone,
                                                                        CK_ULONG n_bufone,
                                                                        CK_BYTE_PTR buftwo,
                                                                        CK_ULONG_PTR n_buftwo);

CK_RV                    gck_crypto_encrypt                            (GckSession *session,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG n_data,
                                                                        CK_BYTE_PTR encrypted,
                                                                        CK_ULONG_PTR n_encrypted);

CK_RV                    gck_crypto_encrypt_xsa                        (gcry_sexp_t sexp,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG n_data,
                                                                        CK_BYTE_PTR encrypted,
                                                                        CK_ULONG_PTR n_encrypted);

CK_RV                    gck_crypto_decrypt                            (GckSession *session,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_BYTE_PTR encrypted,
                                                                        CK_ULONG n_encrypted,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG_PTR n_data);

CK_RV                    gck_crypto_decrypt_xsa                        (gcry_sexp_t sexp,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_BYTE_PTR encrypted,
                                                                        CK_ULONG n_encrypted,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG_PTR n_data);

CK_RV                    gck_crypto_sign                               (GckSession *session,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG n_data,
                                                                        CK_BYTE_PTR signature,
                                                                        CK_ULONG_PTR n_signature);

CK_RV                    gck_crypto_sign_xsa                           (gcry_sexp_t sexp,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG n_data,
                                                                        CK_BYTE_PTR signature,
                                                                        CK_ULONG_PTR n_signature);

CK_RV                    gck_crypto_verify                             (GckSession *session,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG n_data,
                                                                        CK_BYTE_PTR signature,
                                                                        CK_ULONG n_signature);

CK_RV                    gck_crypto_verify_xsa                         (gcry_sexp_t sexp,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG n_data,
                                                                        CK_BYTE_PTR signature,
                                                                        CK_ULONG n_signature);

CK_RV                    gck_crypto_sexp_to_data                       (gcry_sexp_t sexp,
                                                                        guint bits,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG *n_data,
                                                                        GckPadding padding,
                                                                        ...) G_GNUC_NULL_TERMINATED;

CK_RV                    gck_crypto_data_to_sexp                       (const gchar *format,
                                                                        guint nbits,
                                                                        GckPadding padding,
                                                                        CK_BYTE_PTR data,
                                                                        CK_ULONG n_data,
                                                                        gcry_sexp_t *sexp);

CK_RV                    gck_crypto_generate_key_pair                  (GckSession *session,
                                                                        CK_MECHANISM_TYPE mech,
                                                                        CK_ATTRIBUTE_PTR pub_atts,
                                                                        CK_ULONG n_pub_atts,
                                                                        CK_ATTRIBUTE_PTR priv_atts,
                                                                        CK_ULONG n_priv_atts,
                                                                        GckObject **pub_key,
                                                                        GckObject **priv_key);

CK_RV                    gck_crypto_derive_key                         (GckSession *session,
                                                                        CK_MECHANISM_PTR mech,
                                                                        GckObject *base,
                                                                        CK_ATTRIBUTE_PTR attrs,
                                                                        CK_ULONG n_attrs,
                                                                        GckObject **derived);

gulong                   gck_crypto_secret_key_length                  (CK_KEY_TYPE type);

#endif /* GCKCRYPTO_H_ */
