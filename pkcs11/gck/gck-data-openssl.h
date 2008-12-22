/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-data-openssl.h - OpenSSL compatibility functionality

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

#ifndef GCKDATAOPENSSL_H_
#define GCKDATAOPENSSL_H_

#include "gck-data-types.h"

int              gck_data_openssl_parse_algo        (const gchar *name, int *mode);

gboolean         gck_data_openssl_encrypt_block     (const gchar *dekinfo, const gchar *password, 
                                                     const guchar *data, gsize n_data,
                                                     guchar **encrypted, gsize *n_encrypted);

GckDataResult    gck_data_openssl_decrypt_block     (const gchar *dekinfo, const gchar *password, 
                                                     const guchar *data, gsize n_data, 
                                                     guchar **decrypted, gsize *n_decrypted);

const gchar*     gck_data_openssl_get_dekinfo       (GHashTable *headers);

const gchar*     gck_data_openssl_prep_dekinfo      (GHashTable *headers);

#endif /* GCKDATAOPENSSL_H_ */
