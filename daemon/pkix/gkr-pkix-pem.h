/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-pem.h - PEM base64 helper routines

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

#ifndef GKRPKIPEM_H_
#define GKRPKIPEM_H_

#include <glib.h>

typedef void (*GkrPkixPemCallback) (GQuark type, const guchar *data, gsize n_data,
                                    GHashTable *headers, gpointer user_data);

GHashTable*    gkr_pkix_pem_headers_new       (void);

guint          gkr_pkix_pem_parse             (const guchar *data, gsize n_data, 
                                               GkrPkixPemCallback callback, 
                                               gpointer user_data);

guchar*        gkr_pkix_pem_write             (const guchar *data, gsize n_data, 
                                               GQuark type, GHashTable *headers,
                                               gsize *n_result);

#endif /*GKRPKIPEM_H_*/
