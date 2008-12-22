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

ASN1_TYPE asn1_test = NULL;

DEFINE_SETUP(asn1_tree)
{
	int res = asn1_array2tree (test_asn1_tab, &asn1_test, NULL);
	g_assert (res == ASN1_SUCCESS);
}

DEFINE_TEARDOWN(asn1_tree)
{
	asn1_delete_structure (&asn1_test);
}

DEFINE_TEST(asn1_types)
{
	ASN1_TYPE asn;
	
	asn = gck_data_asn1_get_pk_asn1type ();
	g_assert ("pk asn type is null" && asn != NULL);

	asn = gck_data_asn1_get_pkix_asn1type ();
	g_assert ("pkix asn type is null" && asn != NULL);
}

DEFINE_TEST(asn1_integers)
{
	ASN1_TYPE asn;
	gcry_mpi_t mpi, mpt;
	guchar *data;
	gsize n_data;
	gboolean ret;
	guint val;
	int res;
	
	res = asn1_create_element (asn1_test, "TEST.TestIntegers", &asn);
	g_assert ("asn test structure is null" && asn != NULL);

	ret = gck_data_asn1_write_uint (asn, "uint1", 35);
	g_assert ("couldn't write integer" && ret);
	
	ret = gck_data_asn1_write_uint (asn, "uint2", 23456);
	g_assert ("couldn't write integer" && ret);
	
	ret = gck_data_asn1_write_uint (asn, "uint3", 209384022);
	g_assert ("couldn't write integer" && ret);
	
	/* Make a random number */
	mpi = gcry_mpi_new (512);
	g_return_if_fail (mpi);
	gcry_mpi_randomize (mpi, 512, GCRY_WEAK_RANDOM);
	
	/* Write the mpi out */
	ret = gck_data_asn1_write_mpi (asn, "mpi", mpi);
	
	/* Now encode the whole caboodle */
	data = gck_data_asn1_encode (asn, "", &n_data, NULL);
	g_assert ("encoding asn1 didn't work" && data != NULL);
	
	asn1_delete_structure (&asn);
	
	/* Now decode it all nicely */
	res = asn1_create_element (asn1_test, "TEST.TestIntegers", &asn); 
	g_return_if_fail (res == ASN1_SUCCESS);
	
	res = asn1_der_decoding (&asn, data, n_data, NULL);
	g_assert ("decoding asn didn't work" && res == ASN1_SUCCESS);
	
	/* And get out the values */
	ret = gck_data_asn1_read_uint (asn, "uint1", &val);
	g_assert ("couldn't read integer from asn1" && ret);
	g_assert_cmpuint (val, ==, 35);
	
	ret = gck_data_asn1_read_uint (asn, "uint2", &val);
	g_assert ("couldn't read integer from asn1" && ret);
	g_assert_cmpuint (val, ==, 23456);

	ret = gck_data_asn1_read_uint (asn, "uint3", &val);
	g_assert ("couldn't read integer from asn1" && ret);
	g_assert_cmpuint (val, ==, 209384022);
	
	ret = gck_data_asn1_read_mpi (asn, "mpi", &mpt);
	g_assert ("couldn't read mpi from asn1" && ret);
	g_assert ("mpi returned is null" && mpt != NULL);
	g_assert ("mpi is wrong number" && gcry_mpi_cmp (mpi, mpt) == 0);
}

DEFINE_TEST(write_value)
{
	ASN1_TYPE asn = NULL;
	guchar *data;
	gsize n_data;
	int res;
		
	res = asn1_create_element (asn1_test, "TEST.TestData", &asn);
	g_assert ("asn test structure is null" && asn != NULL);
		
	if (!gck_data_asn1_write_value (asn, "data", (const guchar*)"SOME DATA", 9))
		g_assert_not_reached ();

	data = gck_data_asn1_read_value (asn, "data", &n_data, NULL);
	g_assert (data != NULL);
	g_assert_cmpuint (n_data, ==, 9);
	g_assert (memcmp (data, "SOME DATA", 9) == 0);
	g_free (data);
	
	asn1_delete_structure (&asn); 
}

DEFINE_TEST(element_length_content)
{
	ASN1_TYPE asn = NULL;
	guchar buffer[1024];
	const guchar *content;
	gsize n_content;
	gint length;
	int res;
	
	res = asn1_create_element (asn1_test, "TEST.TestData", &asn);
	g_assert ("asn test structure is null" && asn != NULL);
	
	res = asn1_write_value (asn, "data", "SOME DATA", 9);
	g_assert (res == ASN1_SUCCESS);
	
	length = 1024;
	res = asn1_der_coding (asn, "", buffer, &length, NULL);
	g_assert (res == ASN1_SUCCESS);
	
	/* Now the real test */
	length = gck_data_asn1_element_length (buffer, 1024);
	g_assert_cmpint (length, ==, 13);
	
	content = gck_data_asn1_element_content (buffer, length, &n_content);
	g_assert (content);
	g_assert_cmpuint (n_content, ==, 11);
	
	content = gck_data_asn1_element_content (content, n_content, &n_content);
	g_assert (content);
	g_assert_cmpuint (n_content, ==, 9);	
	g_assert (memcmp (content, "SOME DATA", 9) == 0);
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

DEFINE_TEST(general_time)
{
	time_t when;
	const TimeTestData *data;
	
	for (data = generalized_time_test_data; data->value; ++data) {
		when = gck_data_asn1_parse_general_time (data->value);
		if (data->ref != when) {
			printf ("%s", data->value);
			printf ("%s != ", ctime (&when));
			printf ("%s\n", ctime (&data->ref));
			fflush (stdout);
		}
			
		g_assert ("decoded time doesn't match reference" && data->ref == when);
	}
}

DEFINE_TEST(utc_time)
{
	time_t when;
	const TimeTestData *data;
	
	for (data = utc_time_test_data; data->value; ++data) {
		when = gck_data_asn1_parse_utc_time (data->value);
		if (data->ref != when) {
			printf ("%s", data->value);
			printf ("%s != ", ctime (&when));
			printf ("%s\n", ctime (&data->ref));
			fflush (stdout);
		}
			
		g_assert ("decoded time doesn't match reference" && data->ref == when);
	}
}
