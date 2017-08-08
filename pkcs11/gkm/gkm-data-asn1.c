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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkm-data-asn1.h"

#include "egg/egg-asn1x.h"

static gboolean
gkm_data_asn1_read_mpi_internal (GNode *asn, gcry_mpi_t *mpi, GBytes *(*asn1_get)(GNode *))
{
	gcry_error_t gcry;
	GBytes *buf;
	gsize sz;

	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (mpi, FALSE);

	buf = asn1_get (asn);
	if (!buf)
		return FALSE;

	/* Automatically stores in secure memory if DER data is secure */
	sz = g_bytes_get_size (buf);
	gcry = gcry_mpi_scan (mpi, GCRYMPI_FMT_STD, g_bytes_get_data (buf, NULL), sz, &sz);
	g_bytes_unref (buf);
	if (gcry != 0)
		return FALSE;

	return TRUE;
}

static gboolean
gkm_data_asn1_write_mpi_internal (GNode *asn, gcry_mpi_t mpi, void (*asn1_set)(GNode *, GBytes *))
{
	gcry_error_t gcry;
	GBytes *bytes;
	gsize len;
	guchar *buf;

	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (mpi, FALSE);

	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_STD, NULL, 0, &len, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);
	g_return_val_if_fail (len > 0, FALSE);

	buf = gcry_calloc_secure (len, 1);

	gcry = gcry_mpi_print (GCRYMPI_FMT_STD, buf, len, &len, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);

	bytes = g_bytes_new_with_free_func (buf, len, gcry_free, buf);
	asn1_set (asn, bytes);
	g_bytes_unref (bytes);

	return TRUE;
}

/* ECDSA private key (d) is OCTET STRING encoded MPI */
gboolean
gkm_data_asn1_read_string_mpi (GNode *asn, gcry_mpi_t *mpi)
{
	return gkm_data_asn1_read_mpi_internal (asn, mpi, egg_asn1x_get_string_as_bytes);
}

gboolean
gkm_data_asn1_write_string_mpi (GNode *asn, gcry_mpi_t mpi)
{
	return gkm_data_asn1_write_mpi_internal (asn, mpi, egg_asn1x_set_string_as_bytes);
}

gboolean
gkm_data_asn1_read_mpi (GNode *asn, gcry_mpi_t *mpi)
{
	return gkm_data_asn1_read_mpi_internal (asn, mpi, egg_asn1x_get_integer_as_raw);
}

gboolean
gkm_data_asn1_write_mpi (GNode *asn, gcry_mpi_t mpi)
{
	return gkm_data_asn1_write_mpi_internal (asn, mpi, egg_asn1x_set_integer_as_raw);
}

/* ECDSA CKA_EC_POINT encodes q value as a OCTET STRING in PKCS#11 */
gboolean
gkm_data_asn1_read_string (GNode *asn, GBytes **data)
{
	GBytes *buf;

	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (data, FALSE);

	buf = egg_asn1x_get_string_as_bytes (asn);
	if (!buf)
		return FALSE;

	*data = buf;
	return TRUE;
}

gboolean
gkm_data_asn1_write_string (GNode *asn, GBytes *data)
{
	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (data, FALSE);

	egg_asn1x_set_string_as_bytes (asn, data);

	return TRUE;
}

/* ECDSA public key (q) is encoded as a bit string in PEM files */
gboolean
gkm_data_asn1_read_bit_string (GNode *asn, GBytes **data, gsize *data_bits)
{
	GBytes *buf;
	guint n_bits;

	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (data, FALSE);

	buf = egg_asn1x_get_bits_as_raw (asn, &n_bits);
	if (!buf)
		return FALSE;

	*data = buf;
	*data_bits = n_bits;
	return TRUE;
}

gboolean
gkm_data_asn1_write_bit_string (GNode *asn, GBytes *data, gsize data_bits)
{
	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (data, FALSE);

	egg_asn1x_set_bits_as_raw (asn, data, data_bits);

	return TRUE;
}

/* ECDSA differentiates curves based on the OID */
gboolean
gkm_data_asn1_read_oid (GNode *asn, GQuark *oid)
{
	GQuark q;

	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (oid, FALSE);

	q = egg_asn1x_get_oid_as_quark (asn);
	if (!q)
		return FALSE;

	*oid = q;
	return TRUE;
}

gboolean
gkm_data_asn1_write_oid (GNode *asn, GQuark oid)
{
	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (oid, FALSE);

	return egg_asn1x_set_oid_as_quark (asn, oid);
}
