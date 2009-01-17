/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-asn1.c - ASN.1 helper routines

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

#include "config.h"

#include "gck-data-asn1.h"

gboolean
gck_data_asn1_read_mpi (ASN1_TYPE asn, const gchar *part, gcry_mpi_t *mpi)
{
  	gcry_error_t gcry;
  	gsize sz;
  	guchar *buf;

	buf = egg_asn1_read_value (asn, part, &sz, (EggAllocator)g_realloc);
	if (!buf)
		return FALSE;
	
	gcry = gcry_mpi_scan (mpi, GCRYMPI_FMT_STD, buf, sz, &sz);
	g_free (buf);

	if (gcry != 0)
		return FALSE;
	
	return TRUE;
}

gboolean
gck_data_asn1_read_secure_mpi (ASN1_TYPE asn, const gchar *part, gcry_mpi_t *mpi)
{
  	gcry_error_t gcry;
  	gsize sz;
  	guchar *buf;

	buf = egg_asn1_read_value (asn, part, &sz, (EggAllocator)gcry_realloc);
	if (!buf)
		return FALSE;
	
	gcry = gcry_mpi_scan (mpi, GCRYMPI_FMT_STD, buf, sz, &sz);
	gcry_free (buf);

	if (gcry != 0)
		return FALSE;
	
	return TRUE;
}

gboolean
gck_data_asn1_write_mpi (ASN1_TYPE asn, const gchar *part, gcry_mpi_t mpi)
{
	gcry_error_t gcry;
	gsize len;
	guchar *buf;
	int res;

	g_assert (asn);
	g_assert (part);
	g_assert (mpi);
	
	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_STD, NULL, 0, &len, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);
	g_return_val_if_fail (len > 0, FALSE); 

	buf = gcry_calloc_secure (len, 1);
	
	gcry = gcry_mpi_print (GCRYMPI_FMT_STD, buf, len, &len, mpi);	
	g_return_val_if_fail (gcry == 0, FALSE);
	
	res = asn1_write_value (asn, part, buf, len);
	gcry_free (buf);
	
	if (res != ASN1_SUCCESS)
		return FALSE;
		
	return TRUE;
}
