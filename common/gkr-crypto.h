/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-crypto.h - common crypto functionality

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

#ifndef GKRCRYPTO_H_
#define GKRCRYPTO_H_

#include <glib.h>
#include <gcrypt.h>

#include "gkr-id.h"

void               gkr_crypto_setup                     (void);

gboolean           gkr_crypto_hex_encode                (const guchar *data, gsize n_data, 
                                                         gchar *encoded, gsize *n_encoded);

gboolean           gkr_crypto_hex_decode                (const gchar *data, gsize n_data, 
                                                         guchar *decoded, gsize *n_decoded);

gboolean           gkr_crypto_generate_symkey_simple    (int cipher_algo, int hash_algo, 
                                                         const gchar *password, const guchar *salt,
                                                         gsize n_salt, int iterations, 
                                                         guchar **key, guchar **iv);

gboolean           gkr_crypto_generate_symkey_pkcs12    (int cipher_algo, int hash_algo, 
                                                         const gchar *password, const guchar *salt, 
                                                         gsize n_salt, int iterations, 
                                                         guchar **key, guchar **iv);

gboolean           gkr_crypto_generate_symkey_pbe       (int cipher_algo, int hash_algo, 
                                                         const gchar *password, const guchar *salt, 
                                                         gsize n_salt, int iterations, 
                                                         guchar **key, guchar **iv);

gboolean           gkr_crypto_generate_symkey_pbkdf2    (int cipher_algo, int hash_algo, 
                                                         const gchar *password, const guchar *salt, 
                                                         gsize n_salt, int iterations, 
                                                         guchar **key, guchar **iv);

gcry_sexp_t        gkr_crypto_sexp_get_child            (gcry_sexp_t sexp, ...) 
                                                         G_GNUC_NULL_TERMINATED;

gboolean           gkr_crypto_sexp_extract_mpi          (gcry_sexp_t sexp, gcry_mpi_t *mpi, ...)
                                                         G_GNUC_NULL_TERMINATED;

gboolean           gkr_crypto_sexp_extract_mpi_aligned  (gcry_sexp_t sexp, guchar* block, gsize n_block, ...)
                                                         G_GNUC_NULL_TERMINATED;

void               gkr_crypto_sexp_dump                 (gcry_sexp_t sexp);

gboolean           gkr_crypto_skey_parse                (gcry_sexp_t s_key, int *algorithm, 
                                                         gboolean *is_priv, gcry_sexp_t *numbers);

gkrid              gkr_crypto_skey_make_id              (gcry_sexp_t s_key);

gboolean           gkr_crypto_skey_private_to_public    (gcry_sexp_t privkey, gcry_sexp_t *pubkey);

#endif /*GKRCRYPTO_H_*/
