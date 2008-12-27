/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-data-asn1.h - ASN.1 helper routines

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

#ifndef GCK_DATA_ASN_H_
#define GCK_DATA_ASN_H_

#include <libtasn1.h>
#include <gcrypt.h>
#include <glib.h>

#include "gck-data-types.h"

ASN1_TYPE          gck_data_asn1_get_pk_asn1type               (void);

ASN1_TYPE          gck_data_asn1_get_pkix_asn1type             (void);

ASN1_TYPE          gck_data_asn1_decode                        (const gchar *type, const guchar *data,
                                                                gsize n_data);

guchar*            gck_data_asn1_encode                        (ASN1_TYPE asn, const gchar* part, 
                                                                gsize *len, GckDataAllocator alloc); 

guchar*            gck_data_asn1_read_value                    (ASN1_TYPE asn, const gchar *part, 
                                                                gsize *len, GckDataAllocator alloc);

gboolean           gck_data_asn1_write_value                   (ASN1_TYPE asn, const gchar *part, 
                                                                const guchar* value, gsize len); 

GQuark             gck_data_asn1_read_oid                      (ASN1_TYPE asn, const gchar *part);

gboolean           gck_data_asn1_write_oid                     (ASN1_TYPE asn, const gchar *part, GQuark val);

gboolean           gck_data_asn1_read_boolean                  (ASN1_TYPE asn, const gchar *part, gboolean *val);

gboolean           gck_data_asn1_read_uint                     (ASN1_TYPE asn, const gchar *part, guint *val);

gboolean           gck_data_asn1_read_time                     (ASN1_TYPE asn, const gchar *part, time_t *val);

const guchar*      gck_data_asn1_read_content                  (ASN1_TYPE asn, const guchar *data, gsize n_data, 
                                                                const gchar *part, gsize *n_content);

const guchar*      gck_data_asn1_read_element                  (ASN1_TYPE asn, const guchar *data, gsize n_data, 
                                                                const gchar *part, gsize *n_element);
                                                                 
gboolean           gck_data_asn1_write_uint                    (ASN1_TYPE asn, const gchar *part, guint val);

gboolean           gck_data_asn1_read_mpi                      (ASN1_TYPE asn, const gchar *part, 
                                                                gcry_mpi_t *mpi);

gboolean           gck_data_asn1_read_secure_mpi               (ASN1_TYPE asn, const gchar *part, 
                                                                gcry_mpi_t *mpi);

gboolean           gck_data_asn1_write_mpi                     (ASN1_TYPE asn, const gchar *part, 
                                                                gcry_mpi_t mpi);
                                        
gchar*             gck_data_asn1_read_dn                       (ASN1_TYPE asn, const gchar *part);

gchar*             gck_data_asn1_read_dn_part                  (ASN1_TYPE asn, const gchar *part, const gchar *match);

gint               gck_data_asn1_element_length                (const guchar *data, gsize n_data);

const guchar*      gck_data_asn1_element_content               (const guchar *data, gsize n_data, gsize *n_content);

time_t             gck_data_asn1_parse_utc_time                (const gchar* value);

time_t             gck_data_asn1_parse_general_time            (const gchar* value);

#endif /*GCK_DATA_ASN_H_*/
