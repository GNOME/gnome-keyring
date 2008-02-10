/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-util.h - miscellaneous utilities for dealing with PKCS#11

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

#ifndef GKRPKUTIL_H_
#define GKRPKUTIL_H_

#include <glib.h>
#include <gcrypt.h>

#include "common/gkr-id.h"

#include "pkcs11/pkcs11.h"

typedef enum {
	GKR_PK_DATA_UNKNOWN = 0,
	GKR_PK_DATA_BOOL,
	GKR_PK_DATA_ULONG,
	GKR_PK_DATA_BYTES
} GkrPkDataType;

GkrPkDataType      gkr_pk_attribute_data_type             (CK_ATTRIBUTE_TYPE type);

CK_ATTRIBUTE_PTR   gkr_pk_attribute_new                   (CK_ATTRIBUTE_TYPE type);

CK_ATTRIBUTE_PTR   gkr_pk_attribute_dup                   (const CK_ATTRIBUTE_PTR attr);

gint               gkr_pk_attribute_equal                 (const CK_ATTRIBUTE_PTR one, 
                                                           const CK_ATTRIBUTE_PTR two);

void               gkr_pk_attribute_free                  (gpointer attr);

void               gkr_pk_attribute_copy                  (CK_ATTRIBUTE_PTR dest, const CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_steal                 (CK_ATTRIBUTE_PTR dest, CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_clear                 (CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_set_invalid           (CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_set_data              (CK_ATTRIBUTE_PTR attr, gconstpointer value,
                                                           gsize n_value);

void               gkr_pk_attribute_set_string            (CK_ATTRIBUTE_PTR attr, const gchar *str);

void               gkr_pk_attribute_set_id                (CK_ATTRIBUTE_PTR attr, gkrconstid id);

void               gkr_pk_attribute_set_boolean           (CK_ATTRIBUTE_PTR attr, CK_BBOOL value);

void               gkr_pk_attribute_set_date              (CK_ATTRIBUTE_PTR attr, time_t time);

void               gkr_pk_attribute_set_ulong             (CK_ATTRIBUTE_PTR attr, CK_ULONG value);

void               gkr_pk_attribute_set_mpi               (CK_ATTRIBUTE_PTR attr, gcry_mpi_t mpi);

gboolean           gkr_pk_attribute_get_boolean           (const CK_ATTRIBUTE_PTR attr, CK_BBOOL *value);

gboolean           gkr_pk_attribute_get_ulong             (const CK_ATTRIBUTE_PTR attr, CK_ULONG *value);
 
#define            gkr_pk_attributes_new()                (g_array_new (0, 1, sizeof (CK_ATTRIBUTE)))
 
CK_ATTRIBUTE_PTR   gkr_pk_attributes_find                 (const GArray* attrs, CK_ATTRIBUTE_TYPE type);

gboolean           gkr_pk_attributes_ulong                (const GArray* attrs, CK_ATTRIBUTE_TYPE type, 
                                                           CK_ULONG *value);

gboolean           gkr_pk_attributes_boolean              (const GArray* attrs, CK_ATTRIBUTE_TYPE type, 
                                                           CK_BBOOL *value);

gboolean           gkr_pk_attributes_mpi                  (const GArray* attrs, CK_ATTRIBUTE_TYPE type, 
                                                           gcry_mpi_t *mpi);

void               gkr_pk_attributes_append               (GArray *attrs, CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attributes_free                 (GArray *attrs);

/* 
 * 'Consumption' of attributes is used during setting of a set of attributes 
 * on an object, those that have been handled somewhere are marked consumed. 
 * This is useful for fallback handling. See gkr_pk_object_set_attribute().
 */ 
gboolean           gkr_pk_attribute_is_consumed           (const CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_consume               (CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attributes_consume              (GArray *attrs, ...);

/* Certain object classes are intrinsically private */
gboolean           gkc_pk_class_is_private                (CK_OBJECT_CLASS cls);

#endif /*GKRPKUTIL_H_*/
