/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pkix-parser.c: Test PKIX parser

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

#include "pkix/gkr-pkix-asn1.h"

#include <glib.h>
#include <gcrypt.h>
#include <libtasn1.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void)
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void)
 * 
 * Tests be run in the order specified here.
 */

#define extern 
#include "asn1-def-test.h"
#undef extern

ASN1_TYPE asn1_test;

void unit_setup_asn1 (void)
{
	int res = asn1_array2tree (test_asn1_tab, &asn1_test, NULL);
	g_return_if_fail (res == ASN1_SUCCESS);
}

void unit_test_asn1_types (CuTest* cu)
{
	ASN1_TYPE asn;
	
	asn = gkr_pkix_asn1_get_pk_asn1type ();
	CuAssert (cu, "pk asn type is null", asn != NULL);

	asn = gkr_pkix_asn1_get_pkix_asn1type ();
	CuAssert (cu, "pkix asn type is null", asn != NULL);
}

void unit_test_asn1_integers (CuTest* cu)
{
	ASN1_TYPE asn;
	gcry_mpi_t mpi, mpt;
	guchar *data;
	gsize n_data;
	gboolean ret;
	guint val;
	int res;
	
	res = asn1_create_element (asn1_test, "TEST.TestIntegers", &asn);
	CuAssert (cu, "asn test structure is null", asn != NULL);

	ret = gkr_pkix_asn1_write_uint (asn, "uint1", 35);
	CuAssert (cu, "couldn't write integer", ret);
	
	ret = gkr_pkix_asn1_write_uint (asn, "uint2", 23456);
	CuAssert (cu, "couldn't write integer", ret);
	
	ret = gkr_pkix_asn1_write_uint (asn, "uint3", 209384022);
	CuAssert (cu, "couldn't write integer", ret);
	
	/* Make a random number */
	mpi = gcry_mpi_new (512);
	g_return_if_fail (mpi);
	gcry_mpi_randomize (mpi, 512, GCRY_WEAK_RANDOM);
	
	/* Write the mpi out */
	ret = gkr_pkix_asn1_write_mpi (asn, "mpi", mpi);
	
	/* Now encode the whole caboodle */
	data = gkr_pkix_asn1_encode (asn, "", &n_data, NULL);
	CuAssert (cu, "encoding asn1 didn't work", data != NULL);
	
	asn1_delete_structure (&asn);
	
	/* Now decode it all nicely */
	res = asn1_create_element (asn1_test, "TEST.TestIntegers", &asn); 
	g_return_if_fail (res == ASN1_SUCCESS);
	
	res = asn1_der_decoding (&asn, data, n_data, NULL);
	CuAssert (cu, "decoding asn didn't work", res == ASN1_SUCCESS);
	
	/* And get out the values */
	ret = gkr_pkix_asn1_read_uint (asn, "uint1", &val);
	CuAssert (cu, "couldn't read integer from asn1", ret);
	CuAssert (cu, "integer is wrong value", val == 35);
	
	ret = gkr_pkix_asn1_read_uint (asn, "uint2", &val);
	CuAssert (cu, "couldn't read integer from asn1", ret);
	CuAssert (cu, "integer is wrong value", val == 23456);

	ret = gkr_pkix_asn1_read_uint (asn, "uint3", &val);
	CuAssert (cu, "couldn't read integer from asn1", ret);
	CuAssert (cu, "integer is wrong value", val == 209384022);
	
	ret = gkr_pkix_asn1_read_mpi (asn, "mpi", &mpt);
	CuAssert (cu, "couldn't read mpi from asn1", ret);
	CuAssert (cu, "mpi returned is null", mpt != NULL);
	CuAssert (cu, "mpi is wrong number", gcry_mpi_cmp (mpi, mpt) == 0);
}

typedef struct _TimeTestData {
	gchar *value;
	time_t ref;
} TimeTestData;

static const TimeTestData generalized_time_test_data[] = {
	{ "20070725130528Z", 1185368728 },
	{ "20070725130528.2134Z", 1185368728 },
	{ "20070725140528-0100", 1185368728 },
	{ "20070725040528+0900", 1185368728 },
	{ "20070725013528+1130", 1185368728 },
	{ "20070725Z", 1185321600 },
	{ "20070725+0000", 1185321600 },
	{ NULL, 0 }
};

static const TimeTestData utc_time_test_data[] = {
	/* Test the Y2K style wrap arounds */
	{ "070725130528Z", 1185368728 },  /* The year 2007 */
	{ "020725130528Z", 1027602328 },  /* The year 2002 */
	{ "970725130528Z", 869835928 },	  /* The year 1997 */
	{ "370725130528Z", 2132139928 },  /* The year 2037 */
	
	/* Test the time zones and other formats */
	{ "070725130528.2134Z", 1185368728 },
	{ "070725140528-0100", 1185368728 },
	{ "070725040528+0900", 1185368728 },
	{ "070725013528+1130", 1185368728 },
	{ "070725Z", 1185321600 },
	{ "070725+0000", 1185321600 },
	
	{ NULL, 0 }
};

void unit_test_asn1_general_time (CuTest* cu)
{
	time_t when;
	const TimeTestData *data;
	
	for (data = generalized_time_test_data; data->value; ++data) {
		when = gkr_pkix_asn1_parse_general_time (data->value);
		if (data->ref != when) {
			printf ("%s", data->value);
			printf ("%s != ", ctime (&when));
			printf ("%s\n", ctime (&data->ref));
			fflush (stdout);
		}
			
		CuAssert (cu, "decoded time doesn't match reference", data->ref == when);
	}
}

void unit_test_asn1_utc_time (CuTest* cu)
{
	time_t when;
	const TimeTestData *data;
	
	for (data = utc_time_test_data; data->value; ++data) {
		when = gkr_pkix_asn1_parse_utc_time (data->value);
		if (data->ref != when) {
			printf ("%s", data->value);
			printf ("%s != ", ctime (&when));
			printf ("%s\n", ctime (&data->ref));
			fflush (stdout);
		}
			
		CuAssert (cu, "decoded time doesn't match reference", data->ref == when);
	}
}
