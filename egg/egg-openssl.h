/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-openssl.h - OpenSSL compatibility functionality

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

#ifndef EGG_OPENSSL_H_
#define EGG_OPENSSL_H_

#include <glib.h>

int              egg_openssl_parse_algo        (const gchar *name, int *mode);

guchar *         egg_openssl_encrypt_block     (const gchar *dekinfo,
                                                const gchar *password,
                                                gssize n_password,
                                                GBytes *data,
                                                gsize *n_encrypted);

guchar *         egg_openssl_decrypt_block     (const gchar *dekinfo,
                                                const gchar *password,
                                                gssize n_password,
                                                GBytes *data,
                                                gsize *n_decrypted);

const gchar*     egg_openssl_get_dekinfo       (GHashTable *headers);

const gchar*     egg_openssl_prep_dekinfo      (GHashTable *headers);

#endif /* EGG_OPENSSL_H_ */
