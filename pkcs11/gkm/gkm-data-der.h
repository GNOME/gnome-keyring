/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkm-data-der.h - parsing and serializing of common crypto DER structures

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef GKRPKIXDER_H_
#define GKRPKIXDER_H_

#include <glib.h>
#include <gcrypt.h>

#include "gkm-data-types.h"

#include "egg/egg-asn1x.h"

/* -----------------------------------------------------------------------------
 * PRIVATE KEYS
 */

GkmDataResult      gkm_data_der_read_private_key_rsa         (GBytes *data,
                                                              gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_private_key_dsa         (GBytes *data,
                                                              gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_private_key_dsa_parts   (GBytes *keydata,
                                                              GBytes *params,
                                                              gcry_sexp_t *s_key);

const gchar *      gkm_data_der_oid_to_curve                 (GQuark oid);

GQuark             gkm_data_der_oid_from_ec_params           (GBytes *params);

GBytes *           gkm_data_der_get_ec_params                (GQuark oid);

GBytes *           gkm_data_der_encode_ecdsa_q_str           (const guchar *data,
                                                              gsize data_len);

gboolean           gkm_data_der_encode_ecdsa_q               (gcry_mpi_t q,
                                                              GBytes **result);

gboolean           gkm_data_der_decode_ecdsa_q               (GBytes *data,
                                                              GBytes **result);

GBytes *           gkm_data_der_curve_to_ec_params           (const gchar *curve_name);

GkmDataResult      gkm_data_der_read_private_key_ecdsa       (GBytes *data,
                                                              gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_private_key             (GBytes *data,
                                                              gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_private_pkcs8           (GBytes *data,
                                                              const gchar *password,
                                                              gsize n_password,
                                                              gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_private_pkcs8_plain     (GBytes *data,
                                                              gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_private_pkcs8_crypted   (GBytes *data,
                                                              const gchar *password, gsize n_password,
                                                              gcry_sexp_t *s_key);

GBytes *           gkm_data_der_write_private_key_rsa        (gcry_sexp_t s_key);

GBytes *           gkm_data_der_write_private_key_dsa        (gcry_sexp_t s_key);

GBytes *           gkm_data_der_write_private_key_dsa_part   (gcry_sexp_t skey);

GBytes *           gkm_data_der_write_private_key_dsa_params (gcry_sexp_t skey);

GBytes *           gkm_data_der_write_private_key_ecdsa      (gcry_sexp_t s_key);

GBytes *           gkm_data_der_write_private_key            (gcry_sexp_t s_key);

GBytes *           gkm_data_der_write_private_pkcs8_plain    (gcry_sexp_t skey);

GBytes *           gkm_data_der_write_private_pkcs8_crypted  (gcry_sexp_t skey,
                                                              const gchar *password,
                                                              gsize n_password);

/* -----------------------------------------------------------------------------
 * PUBLIC KEYS
 */

GkmDataResult      gkm_data_der_read_public_key_rsa        (GBytes *data,
                                                            gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_public_key_dsa        (GBytes *data,
                                                            gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_public_key_dsa_parts  (GBytes *keydata,
                                                            GBytes *params,
                                                            gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_public_key_ecdsa      (GBytes *data,
                                                            gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_public_key            (GBytes *data,
                                                            gcry_sexp_t *s_key);

GkmDataResult      gkm_data_der_read_public_key_info       (GBytes *data,
                                                            gcry_sexp_t *s_key);

GBytes *           gkm_data_der_write_public_key_rsa       (gcry_sexp_t s_key);

GBytes *           gkm_data_der_write_public_key_dsa       (gcry_sexp_t s_key);

GBytes *           gkm_data_der_write_public_key_ecdsa     (gcry_sexp_t s_key);

GBytes *           gkm_data_der_write_public_key           (gcry_sexp_t s_key);


/* -----------------------------------------------------------------------------
 * CERTIFICATES
 */

GkmDataResult      gkm_data_der_read_certificate           (GBytes *data,
                                                            GNode **asn1);

GkmDataResult      gkm_data_der_read_basic_constraints     (GBytes *data,
                                                            gboolean *is_ca,
                                                            gint *path_len);

GkmDataResult      gkm_data_der_read_key_usage             (GBytes *data,
                                                            gulong *key_usage);

GkmDataResult      gkm_data_der_read_enhanced_usage        (GBytes *data,
                                                            GQuark **oids);

GBytes *           gkm_data_der_write_certificate          (GNode *asn1);

#endif /*GKRPKIXDER_H_*/
