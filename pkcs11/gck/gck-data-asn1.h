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

#include "egg/egg-asn1.h"
#include <gcrypt.h>

gboolean           gck_data_asn1_read_mpi                      (ASN1_TYPE asn, const gchar *part, 
                                                                gcry_mpi_t *mpi);

gboolean           gck_data_asn1_read_secure_mpi               (ASN1_TYPE asn, const gchar *part, 
                                                                gcry_mpi_t *mpi);

gboolean           gck_data_asn1_write_mpi                     (ASN1_TYPE asn, const gchar *part, 
                                                                gcry_mpi_t mpi);
                                        
#endif /*GCK_DATA_ASN_H_*/
