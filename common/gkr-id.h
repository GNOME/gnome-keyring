/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-id.h - Unique binary identifiers

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

#ifndef GKRID_H_
#define GKRID_H_

#include <glib.h>
#include <glib-object.h>

#define GKR_ID_MAX_LENGTH       1024 * 64

typedef gpointer gkrid;
typedef gconstpointer gkrconstid;

#define GKR_ID_BOXED_TYPE        (gkr_id_get_boxed_type ())

GType          gkr_id_get_boxed_type (void);

gkrid          gkr_id_new            (const guchar *data, gsize len);

gkrid          gkr_id_new_digest     (const guchar *data, gsize len);

gkrid          gkr_id_new_digestv    (const guchar *data, gsize len, ...)
                                         G_GNUC_NULL_TERMINATED;

guint          gkr_id_hash           (gkrconstid v);

gboolean       gkr_id_equals         (gkrconstid u1, gkrconstid u2);

gkrid          gkr_id_dup            (gkrconstid id);

gconstpointer  gkr_id_get_raw        (gkrconstid id, gsize *len);

void           gkr_id_free           (gpointer v); 

#endif /*GKRID_H_*/
