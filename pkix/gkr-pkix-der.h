/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-der.h - parsing and serializing of common crypto DER structures 

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

#ifndef GKRPKIXDER_H_
#define GKRPKIXDER_H_

#include <glib.h>
#include <gcrypt.h>
#include <libtasn1.h>

#include "gkr-pkix-types.h"

/* -----------------------------------------------------------------------------
 * PRIVATE KEYS 
 */
 
GkrPkixResult gkr_pkix_der_read_private_key_rsa         (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

GkrPkixResult gkr_pkix_der_read_private_key_dsa         (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

GkrPkixResult gkr_pkix_der_read_private_key_dsa_parts   (const guchar *keydata, gsize n_keydata,
                                                         const guchar *params, gsize n_params, 
                                                         gcry_sexp_t *s_key);

GkrPkixResult gkr_pkix_der_read_private_key             (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

guchar*       gkr_pkix_der_write_private_key_rsa        (gcry_sexp_t s_key, gsize *n_data);

guchar*       gkr_pkix_der_write_private_key_dsa        (gcry_sexp_t s_key, gsize *len);

guchar*       gkr_pkix_der_write_private_key_dsa_part   (gcry_sexp_t skey, gsize *n_key);

guchar*       gkr_pkix_der_write_private_key_dsa_params (gcry_sexp_t skey, gsize *n_params);

guchar*       gkr_pkix_der_write_private_key            (gcry_sexp_t s_key, gsize *n_data);


/* -----------------------------------------------------------------------------
 * PUBLIC KEYS
 */

GkrPkixResult   gkr_pkix_der_read_public_key_rsa        (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

GkrPkixResult   gkr_pkix_der_read_public_key_dsa        (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

GkrPkixResult   gkr_pkix_der_read_public_key_dsa_parts  (const guchar *keydata, gsize n_keydata,
                                                         const guchar *params, gsize n_params,
                                                         gcry_sexp_t *s_key);
                                                         
GkrPkixResult   gkr_pkix_der_read_public_key            (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

GkrPkixResult   gkr_pkix_der_read_public_key_info       (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

guchar*         gkr_pkix_der_write_public_key_rsa       (gcry_sexp_t s_key, gsize *len);

guchar*         gkr_pkix_der_write_public_key_dsa       (gcry_sexp_t s_key, gsize *len);

guchar*         gkr_pkix_der_write_public_key           (gcry_sexp_t s_key, gsize *len);


/* -----------------------------------------------------------------------------
 * CERTIFICATES
 */

GkrPkixResult   gkr_pkix_der_read_certificate           (const guchar *data, gsize n_data, 
                                                         ASN1_TYPE *asn1);
                                                         
GkrPkixResult   gkr_pkix_der_read_basic_constraints     (const guchar *data, gsize n_data, 
                                                         gboolean *is_ca, guint *path_len);

GkrPkixResult   gkr_pkix_der_read_key_usage             (const guchar *data, gsize n_data, 
                                                         guint *key_usage);

GkrPkixResult   gkr_pkix_der_read_enhanced_usage        (const guchar *data, gsize n_data, 
                                                         GQuark **oids);

guchar*         gkr_pkix_der_write_certificate          (ASN1_TYPE asn1, gsize *n_data);

/* -----------------------------------------------------------------------------
 * CIPHERS
 */
 
GkrPkixResult      gkr_pkix_der_read_cipher                 (GQuark oid_scheme, const gchar *password, 
                                                             const guchar *data, gsize n_data, 
                                                             gcry_cipher_hd_t *cih);

GkrPkixResult      gkr_pkix_der_read_cipher_pkcs5_pbe       (int cipher_algo, int cipher_mode, 
                                                             int hash_algo, const gchar *password, 
                                                             const guchar *data, gsize n_data, 
                                                             gcry_cipher_hd_t *cih);

GkrPkixResult      gkr_pkix_der_read_cipher_pkcs5_pbes2     (const gchar *password, const guchar *data, 
                                                             gsize n_data, gcry_cipher_hd_t *cih);

GkrPkixResult      gkr_pkix_der_read_cipher_pkcs12_pbe      (int cipher_algo, int cipher_mode, 
                                                             const gchar *password, const guchar *data, 
                                                             gsize n_data, gcry_cipher_hd_t *cih);

#endif /*GKRPKIXDER_H_*/
