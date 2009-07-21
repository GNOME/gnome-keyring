/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-data-asn1.c: Test ASN.1 routines

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

#include "run-auto-test.h"

#include "gck/gck-data-asn1.h"

#include <glib.h>
#include <gcrypt.h>
#include <libtasn1.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define extern 
#include "asn1-def-test.h"
#undef extern

static ASN1_TYPE asn1_test = NULL;

static ASN1_TYPE asn1_cert = NULL;
static guchar *data_cert = NULL;
static gsize n_data_cert = 0;

DEFINE_SETUP(asn1_tree)
{
	ASN1_TYPE pkix;
	
	int res = asn1_array2tree (test_asn1_tab, &asn1_test, NULL);
	g_assert (res == ASN1_SUCCESS);

	/* -------- */
	
	data_cert = test_read_testdata ("test-certificate-1.der", &n_data_cert);

	/* We'll be catching this error later */
	pkix = egg_asn1_get_pkix_asn1type ();
	if (!pkix) return;
	
	res = asn1_create_element (pkix, "PKIX1.Certificate", &asn1_cert); 
	g_assert (res == ASN1_SUCCESS);
	
	res = asn1_der_decoding (&asn1_cert, data_cert, n_data_cert, NULL);
	g_assert (res == ASN1_SUCCESS);
}

DEFINE_TEARDOWN(asn1_tree)
{
	asn1_delete_structure (&asn1_test);
	asn1_delete_structure (&asn1_cert);
	g_free (data_cert);
	data_cert = NULL;
}

DEFINE_TEST(asn1_integers)
{
	ASN1_TYPE asn;
	gcry_mpi_t mpi, mpt;
	guchar *data;
	gsize n_data;
	gboolean ret;
	int res;
	
	res = asn1_create_element (asn1_test, "TEST.TestIntegers", &asn);
	g_assert ("asn test structure is null" && asn != NULL);

	/* Make a random number */
	mpi = gcry_mpi_new (512);
	g_return_if_fail (mpi);
	gcry_mpi_randomize (mpi, 512, GCRY_WEAK_RANDOM);
	
	/* Write the mpi out */
	ret = gck_data_asn1_write_mpi (asn, "mpi", mpi);
	
	/* Now encode the whole caboodle */
	data = egg_asn1_encode (asn, "", &n_data, NULL);
	g_assert ("encoding asn1 didn't work" && data != NULL);
	
	asn1_delete_structure (&asn);
	
	/* Now decode it all nicely */
	res = asn1_create_element (asn1_test, "TEST.TestIntegers", &asn); 
	g_return_if_fail (res == ASN1_SUCCESS);
	
	res = asn1_der_decoding (&asn, data, n_data, NULL);
	g_assert ("decoding asn didn't work" && res == ASN1_SUCCESS);
	
	ret = gck_data_asn1_read_mpi (asn, "mpi", &mpt);
	g_assert ("couldn't read mpi from asn1" && ret);
	g_assert ("mpi returned is null" && mpt != NULL);
	g_assert ("mpi is wrong number" && gcry_mpi_cmp (mpi, mpt) == 0);

	g_free (data);
}
