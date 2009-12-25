/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-asn1.h - ASN.1/DER parsing and encoding routines

   Copyright (C) 2009 Stefan Walter

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

#ifndef EGG_ASN1X_H_
#define EGG_ASN1X_H_

#include <glib.h>

#include <libtasn1.h>


#ifndef HAVE_EGG_ALLOCATOR
typedef void* (*EggAllocator) (void* p, gsize);
#define HAVE_EGG_ALLOCATOR
#endif

GNode*              egg_asn1x_create             (const ASN1_ARRAY_TYPE *defs,
                                                  const gchar *type);

void                egg_asn1x_dump               (GNode *asn);

void                egg_asn1x_clear              (GNode *asn);

gboolean            egg_asn1x_decode             (GNode *asn,
                                                  gconstpointer data,
                                                  gsize n_data);

gboolean            egg_asn1x_validate           (GNode *asn);

gpointer            egg_asn1x_encode             (GNode *asn,
                                                  EggAllocator allocator,
                                                  gsize *n_data);

void                egg_asn1x_destroy            (gpointer asn);

#endif /*EGG_ASN1X_H_*/
