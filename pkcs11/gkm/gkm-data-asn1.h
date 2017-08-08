/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkm-data-asn1.h - ASN.1 helper routines

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

#ifndef GKM_DATA_ASN_H_
#define GKM_DATA_ASN_H_

#include <glib.h>
#include <gcrypt.h>

gboolean           gkm_data_asn1_read_mpi                      (GNode *asn,
                                                                gcry_mpi_t *mpi);

gboolean           gkm_data_asn1_write_mpi                     (GNode *asn,
                                                                gcry_mpi_t mpi);

gboolean           gkm_data_asn1_read_string_mpi               (GNode *asn,
                                                                gcry_mpi_t *mpi);

gboolean           gkm_data_asn1_write_string_mpi              (GNode *asn,
                                                                gcry_mpi_t mpi);

gboolean           gkm_data_asn1_read_string                   (GNode *asn,
                                                                GBytes **data);

gboolean           gkm_data_asn1_write_string                  (GNode *asn,
                                                                GBytes *data);

gboolean           gkm_data_asn1_read_bit_string               (GNode *asn,
                                                                GBytes **data,
                                                                gsize *data_bits);

gboolean           gkm_data_asn1_write_bit_string              (GNode *asn,
                                                                GBytes *data,
                                                                gsize data_bits);

gboolean           gkm_data_asn1_read_oid                      (GNode *asn,
                                                                GQuark *oid);

gboolean           gkm_data_asn1_write_oid                     (GNode *asn,
                                                                GQuark oid);

#endif /*GKM_DATA_ASN_H_*/
