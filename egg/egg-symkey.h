/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
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

#ifndef EGG_SYMKEY_H_
#define EGG_SYMKEY_H_

#include <glib.h>

#include <gcrypt.h>

gboolean                 egg_symkey_generate_simple             (int cipher_algo,
                                                                 int hash_algo,
                                                                 const gchar *password,
                                                                 gssize n_password,
                                                                 const guchar *salt,
                                                                 gsize n_salt,
                                                                 int iterations,
                                                                 guchar **key,
                                                                 guchar **iv);

gboolean                 egg_symkey_generate_pbe                (int cipher_algo,
                                                                 int hash_algo,
                                                                 const gchar *password,
                                                                 gssize n_password,
                                                                 const guchar *salt,
                                                                 gsize n_salt,
                                                                 int iterations,
                                                                 guchar **key,
                                                                 guchar **iv);

gboolean                 egg_symkey_generate_pkcs12             (int cipher_algo,
                                                                 int hash_algo,
                                                                 const gchar *password,
                                                                 gssize n_password,
                                                                 const guchar *salt,
                                                                 gsize n_salt,
                                                                 int iterations,
                                                                 guchar **key,
                                                                 guchar **iv);

gboolean                 egg_symkey_generate_pkcs12_mac         (int hash_algo,
                                                                 const gchar *password,
                                                                 gssize n_password,
                                                                 const guchar *salt,
                                                                 gsize n_salt,
                                                                 int iterations,
                                                                 guchar **key);

gboolean                 egg_symkey_generate_pbkdf2             (int cipher_algo,
                                                                 int hash_algo,
                                                                 const gchar *password,
                                                                 gssize n_password,
                                                                 const guchar *salt,
                                                                 gsize n_salt,
                                                                 int iterations,
                                                                 guchar **key,
                                                                 guchar **iv);

gboolean                 egg_symkey_read_cipher                 (GQuark oid_scheme,
                                                                 const gchar *password,
                                                                 gsize n_password,
                                                                 GNode *params,
                                                                 gcry_cipher_hd_t *cih);

gboolean                 egg_symkey_read_mac                    (GQuark oid_scheme,
                                                                 const gchar *password,
                                                                 gsize n_password,
                                                                 GNode *params,
                                                                 gcry_md_hd_t *mdh,
                                                                 gsize *digest_len);

#endif /* EGG_SYMKEY_H_ */
