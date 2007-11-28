/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-unique.h - Unique binary identifiers

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

#ifndef GKRUNIQUE_H_
#define GKRUNIQUE_H_

#include <glib.h>
#include <glib-object.h>

#define GKR_UNIQUE_MAX_LENGTH       1024 * 64

typedef gpointer gkrunique;
typedef gconstpointer gkrconstunique;

#define GKR_UNIQUE_BOXED_TYPE        (gkr_unique_get_boxed_type ())

GType          gkr_unique_get_boxed_type (void);

gkrunique      gkr_unique_new            (const guchar *data, gsize len);

gkrunique      gkr_unique_new_digest     (const guchar *data, gsize len);

gkrunique      gkr_unique_new_digestv    (const guchar *data, gsize len, ...)
                                         G_GNUC_NULL_TERMINATED;

guint          gkr_unique_hash           (gkrconstunique v);

gboolean       gkr_unique_equals         (gkrconstunique u1, gkrconstunique u2);

gkrunique      gkr_unique_dup            (gkrconstunique uni);

gconstpointer  gkr_unique_get_raw        (gkrconstunique uni, gsize *len);

void           gkr_unique_free           (gpointer v); 

#endif /*GKRUNIQUE_H_*/
