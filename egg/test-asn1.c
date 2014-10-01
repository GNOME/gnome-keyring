/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-asn1.c: Test ASN1 stuf

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"
#include "egg/egg-testing.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct _EggAsn1xDef ASN1_ARRAY_TYPE;
typedef struct _EggAsn1xDef asn1_static_node;
#include "test.asn.h"

const gchar I33[] =           "\x02\x01\x2A";
const gchar I253[] =           "\x02\x02\x00\xFD";
const gchar BFALSE[] =        "\x01\x01\x00";
const gchar BTRUE[] =         "\x01\x01\xFF";
const gchar SFARNSWORTH[] =   "\x04\x0A""farnsworth";
const gchar SIMPLICIT[] =     "\x85\x08""implicit";
const gchar SEXPLICIT[] =     "\xA5\x0A\x04\x08""explicit";
const gchar SUNIVERSAL[] =    "\x05\x09""universal";
const gchar TGENERALIZED[] =  "\x18\x0F""20070725130528Z";
const gchar BITS_TEST[] =  "\x03\x04\x06\x6e\x5d\xc0";
const gchar BITS_BAD[] =  "\x03\x04\x06\x6e\x5d\xc1";
const gchar BITS_ZERO[] =  "\x03\x01\x00";
const gchar NULL_TEST[] =  "\x05\x00";

/* ENUM with value = 2 */
const gchar ENUM_TWO[] =           "\x0A\x01\x02";

/* ENUM with value = 3 */
const gchar ENUM_THREE[] =           "\x0A\x01\x03";

#define XL(x) G_N_ELEMENTS (x) - 1

static void
test_boolean (void)
{
	GBytes *bytes;
	GNode *asn;
	gboolean value;

	asn = egg_asn1x_create (test_asn1_tab, "TestBoolean");
	g_assert (asn);

	g_assert_cmpint (EGG_ASN1X_BOOLEAN, ==, egg_asn1x_type (asn));

	/* Shouldn't succeed */
	if (egg_asn1x_get_boolean (asn, &value))
		g_assert_not_reached ();

	/* Decode a false */
	bytes = g_bytes_new_static (BFALSE, XL (BFALSE));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	value = TRUE;
	if (!egg_asn1x_get_boolean (asn, &value))
		g_assert_not_reached ();
	g_assert (value == FALSE);
	g_bytes_unref (bytes);

	/* Decode a true */
	bytes = g_bytes_new_static (BTRUE, XL (BTRUE));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	value = FALSE;
	if (!egg_asn1x_get_boolean (asn, &value))
		g_assert_not_reached ();
	g_assert (value == TRUE);
	g_bytes_unref (bytes);

	egg_asn1x_clear (asn);

	/* Shouldn't suceed after clear */
	if (egg_asn1x_get_boolean (asn, &value))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
}

static void
test_boolean_decode_bad (void)
{
	const gchar BOOLEAN_INVALID_LENGTH[] =   "\x01\x02\x00\x00";
	const gchar BOOLEAN_BAD_VALUE[] =        "\x01\x01\x05";

	GBytes *bytes;
	GNode *asn;
	gboolean ret;

	asn = egg_asn1x_create (test_asn1_tab, "TestBoolean");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (BOOLEAN_INVALID_LENGTH, XL (BOOLEAN_INVALID_LENGTH));
	ret = egg_asn1x_decode (asn, bytes);
	g_assert (ret == FALSE);
	g_assert (strstr (egg_asn1x_message (asn), "invalid length boolean") != NULL);
	g_bytes_unref (bytes);

	bytes = g_bytes_new_static (BOOLEAN_BAD_VALUE, XL (BOOLEAN_BAD_VALUE));
	ret = egg_asn1x_decode (asn, bytes);
	g_assert (ret == FALSE);
	g_assert (strstr (egg_asn1x_message (asn), "boolean must be true or false") != NULL);
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_boolean_default (void)
{
	GNode *asn;
	GBytes *bytes;

	const gchar BOOLEAN[] = "\x30\x00";

	asn = egg_asn1x_create (test_asn1_tab, "TestBooleanDefault");
	/* This is equal to the default value, and shouldn't be included */
	egg_asn1x_set_boolean (egg_asn1x_node (asn, "boolean", NULL), TRUE);

	bytes = egg_asn1x_encode (asn, NULL);
	egg_asn1x_assert (bytes != NULL, asn);
	egg_assert_cmpbytes (bytes, ==, BOOLEAN, XL (BOOLEAN));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_null (void)
{
	GNode *asn;
	GBytes *data;

	asn = egg_asn1x_create (test_asn1_tab, "TestNull");
	g_assert (asn);

	g_assert_cmpint (EGG_ASN1X_NULL, ==, egg_asn1x_type (asn));

	egg_asn1x_set_null (asn);

	data = egg_asn1x_encode (asn, g_realloc);
	egg_assert_cmpmem (NULL_TEST, XL (NULL_TEST), ==, g_bytes_get_data (data, NULL), g_bytes_get_size (data));

	if (!egg_asn1x_decode (asn, data))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
	g_bytes_unref (data);
}

static void
test_integer (void)
{
	GNode *asn;
	gulong value;
	GBytes *bytes;

	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (asn);

	g_assert_cmpint (EGG_ASN1X_INTEGER, ==, egg_asn1x_type (asn));

	/* Shouldn't succeed */
	if (egg_asn1x_get_integer_as_ulong (asn, &value))
		g_assert_not_reached ();

	/* Should suceed now */
	bytes = g_bytes_new_static (I33, XL (I33));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	if (!egg_asn1x_get_integer_as_ulong (asn, &value))
		g_assert_not_reached ();
	g_assert (value == 42);
	g_bytes_unref (bytes);

	egg_asn1x_clear (asn);

	/* Shouldn't suceed after clear */
	if (egg_asn1x_get_integer_as_ulong (asn, &value))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
}

static void
test_integer_zero_length (void)
{
	const gchar INTEGER_EMPTY[] =   "\x02\x00";

	GBytes *bytes;
	GNode *asn;
	gboolean ret;

	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (INTEGER_EMPTY, XL (INTEGER_EMPTY));
	ret = egg_asn1x_decode (asn, bytes);
	g_assert (ret == FALSE);
	g_assert (strstr (egg_asn1x_message (asn), "zero length integer") != NULL);
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_unsigned (void)
{
	GNode *asn;
	gulong value;
	GBytes *check;
	guchar val;
	GBytes *bytes;
	GBytes *usg;

	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (asn);

	g_assert_cmpint (EGG_ASN1X_INTEGER, ==, egg_asn1x_type (asn));

	/* Check with ulong */
	bytes = g_bytes_new_static (I253, XL (I253));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	if (!egg_asn1x_get_integer_as_ulong (asn, &value))
		g_assert_not_reached ();
	g_assert (value == 253);
	g_bytes_unref (bytes);

	egg_asn1x_clear (asn);

	egg_asn1x_set_integer_as_ulong (asn, 253);

	check = egg_asn1x_encode (asn, NULL);
	egg_assert_cmpmem (I253, XL (I253), ==, g_bytes_get_data (check, NULL), g_bytes_get_size (check));
	g_bytes_unref (check);

	/* Now check with usg */
	bytes = g_bytes_new_static (I253, XL (I253));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	val = 0xFD; /* == 253 */
	usg = egg_asn1x_get_integer_as_usg (asn);
	egg_assert_cmpmem (&val, 1, ==, g_bytes_get_data (usg, NULL), g_bytes_get_size (usg));
	g_bytes_unref (usg);

	egg_asn1x_clear (asn);

	egg_asn1x_take_integer_as_usg (asn, g_bytes_new_static (&val, 1));

	check = egg_asn1x_encode (asn, NULL);
	egg_assert_cmpsize (g_bytes_get_size (check), ==, XL (I253));
	egg_assert_cmpmem (I253, XL (I253), ==, g_bytes_get_data (check, NULL), g_bytes_get_size (check));
	g_bytes_unref (check);

	egg_asn1x_destroy (asn);
}

static void
test_unsigned_not_set (void)
{
	GNode *asn;
	GBytes *bytes;

	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (asn);

	bytes = egg_asn1x_get_integer_as_usg (asn);
	g_assert (bytes == NULL);

	egg_asn1x_destroy (asn);
}

static void
test_unsigned_default (void)
{
	GNode *asn;
	GBytes *bytes;

	const gchar INTEGERS[] = "\x30\x06\x02\x01\x01\x02\x01\x02";

	asn = egg_asn1x_create (test_asn1_tab, "TestIntegers");
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "uint1", NULL), 1);
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "uint2", NULL), 2);
	/* This is equal to the default value, and shouldn't be included */
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "uint3", NULL), 8888);

	bytes = egg_asn1x_encode (asn, NULL);
	egg_assert_cmpbytes (bytes, ==, INTEGERS, XL (INTEGERS));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_unsigned_constant (void)
{
	gulong value;
	GNode *asn;

	/* const gchar SEQ[] = "\x30\x00"; */

	asn = egg_asn1x_create (test_asn1_tab, "TestConstant");
	if (!egg_asn1x_get_integer_as_ulong (egg_asn1x_node (asn, "version", NULL), &value))
		g_assert_not_reached ();
	g_assert_cmpint (value, ==, 3);

	egg_asn1x_destroy (asn);
}

static void
test_unsigned_zero (void)
{
	GBytes *bytes;
	GNode *asn;

	const gchar DER[] = "\x02\x01\x00";

	/* No bits set in 0 but should still be 1 byte */
	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	egg_asn1x_set_integer_as_ulong (asn, 0);

	bytes = egg_asn1x_encode (asn, NULL);
	egg_asn1x_assert (bytes != NULL, asn);
	egg_assert_cmpbytes (bytes, ==, DER, XL (DER));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_integer_raw (void)
{
	GNode *asn;
	GBytes *bytes;

	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static ("\x01\x02\x03", 3);
	egg_asn1x_set_integer_as_raw (asn, bytes);
	g_bytes_unref (bytes);

	bytes = egg_asn1x_encode (asn, NULL);
	egg_assert_cmpbytes (bytes, ==, "\x02\x03\x01\x02\x03", 5);
	g_bytes_unref (bytes);

	bytes = egg_asn1x_get_integer_as_raw (asn);
	egg_assert_cmpbytes (bytes, ==, "\x01\x02\x03", 3);
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_integer_raw_not_twos_complement (void)
{
	/* Ugh ... g_test_trap_subprocess */
	g_test_trap_subprocess ("/asn1/integer/raw-not-twos-complement/subprocess", 0,
	                        G_TEST_SUBPROCESS_INHERIT_STDOUT);
	g_test_trap_assert_failed ();
	g_test_trap_assert_stderr ("*not two's complement*");
}

static void
test_integer_raw_not_twos_complement_subprocess (void)
{
	GNode *asn;
	GBytes *bytes;

	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static ("\x81\x02\x03", 3);

	egg_asn1x_set_integer_as_raw (asn, bytes); /* UNREACHABLE: */
	g_bytes_unref (bytes);
	egg_asn1x_destroy (asn);
}

static void
test_octet_string (void)
{
	GNode *asn;
	gchar *value;
	GBytes *bytes;

	asn = egg_asn1x_create (test_asn1_tab, "TestOctetString");
	g_assert (asn);

	g_assert_cmpint (EGG_ASN1X_OCTET_STRING, ==, egg_asn1x_type (asn));

	/* Shouldn't succeed */
	if (egg_asn1x_get_string_as_utf8 (asn, NULL))
		g_assert_not_reached ();

	/* Should work */
	bytes = g_bytes_new_static (SFARNSWORTH, XL (SFARNSWORTH));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	value = egg_asn1x_get_string_as_utf8 (asn, NULL);
	g_assert_cmpstr (value, ==, "farnsworth");
	g_free (value);

	egg_asn1x_clear (asn);

	/* Shouldn't succeed */
	if (egg_asn1x_get_string_as_utf8 (asn, NULL))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
}

static void
test_octet_string_set_bad_utf8 (void)
{
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestOctetString");
	g_assert (asn);

	if (egg_asn1x_set_string_as_utf8 (asn, "\xFF\xFA", NULL))
		g_assert_not_reached ();

	/* Shouldn't succeed */
	if (egg_asn1x_get_string_as_utf8 (asn, NULL))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
}

static void
test_octet_string_bmp_as_utf8 (void)
{
	GBytes *bytes;
	GNode *asn;
	gchar *data;

	const gchar SFUER[] =   "\x04\x06""\x00\x46\x00\xfc\x00\x72";

	bytes = g_bytes_new_static (SFUER, XL (SFUER));
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestOctetString", bytes);
	g_assert (asn != NULL);
	g_bytes_unref (bytes);

	data = egg_asn1x_get_bmpstring_as_utf8 (asn);
	g_assert_cmpstr (data, ==, "F\303\274r");

	g_free (data);
	egg_asn1x_destroy (asn);
}

static void
test_octet_string_get_as_bytes (void)
{
	GBytes *bytes;
	GNode *asn;

	bytes = g_bytes_new_static (SFARNSWORTH, XL (SFARNSWORTH));
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestOctetString", bytes);
	g_assert (asn != NULL);
	g_bytes_unref (bytes);

	bytes = egg_asn1x_get_string_as_bytes (asn);
	g_assert (bytes != NULL);
	egg_assert_cmpbytes (bytes, ==, "farnsworth", 10);
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_octet_string_set_as_bytes (void)
{
	GBytes *bytes;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestOctetString");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static ("farnsworth", 10);
	egg_asn1x_set_string_as_bytes (asn, bytes);
	g_bytes_unref (bytes);

	bytes = egg_asn1x_encode (asn, NULL);
	g_assert (bytes != NULL);
	egg_assert_cmpbytes (bytes, ==, SFARNSWORTH, XL (SFARNSWORTH));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_octet_string_structured (void)
{
	GBytes *bytes;
	GNode *asn;
	guchar *string;
	gsize n_string = 0;

	const gchar STRUCTURED[] = "\x24\x0c"
	                               "\x04\x04""blah"
	                               "\x04\x04""blah";

	bytes = g_bytes_new_static (STRUCTURED, XL (STRUCTURED));
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestOctetString", bytes);
	g_bytes_unref (bytes);

	string = egg_asn1x_get_string_as_raw (asn, NULL, &n_string);
	g_assert_cmpstr ((gchar *)string, ==, "blahblah");
	g_assert_cmpint (n_string, ==, 8);
	g_free (string);

	egg_asn1x_destroy (asn);
}

static void
test_octet_string_structured_bad (void)
{
	GBytes *bytes;
	GNode *asn;
	guchar *string;
	gsize n_string = 0;

	const gchar STRUCTURED[] = "\x24\x0c"
	                               "\x24\x04\x04\02""bl"
	                               "\x04\x04""blah";

	bytes = g_bytes_new_static (STRUCTURED, XL (STRUCTURED));
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestOctetString", bytes);
	g_bytes_unref (bytes);

	string = egg_asn1x_get_string_as_raw (asn, NULL, &n_string);
	g_assert (string == NULL);

	egg_asn1x_destroy (asn);
}

static void
test_generalized_time (void)
{
	GBytes *bytes;
	GNode *asn;
	glong value;

	asn = egg_asn1x_create (test_asn1_tab, "TestGeneralized");
	g_assert (asn);

	g_assert_cmpint (EGG_ASN1X_TIME, ==, egg_asn1x_type (asn));

	/* Shouldn't succeed */
	value = egg_asn1x_get_time_as_long (asn);
	g_assert (value == -1);

	/* Should work */
	bytes = g_bytes_new_static (TGENERALIZED, XL (TGENERALIZED));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);
	value = egg_asn1x_get_time_as_long (asn);
	g_assert (value == 1185368728);

	egg_asn1x_clear (asn);

	/* Shouldn't succeed */
	value = egg_asn1x_get_time_as_long (asn);
	g_assert (value == -1);

	egg_asn1x_destroy (asn);
}

static void
test_time_get_missing (void)
{
	GDate date;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestGeneralized");
	if (egg_asn1x_get_time_as_date (asn, &date))
		g_assert_not_reached ();
	g_assert (egg_asn1x_get_time_as_long (asn) == -1);
	egg_asn1x_destroy (asn);
}

static void
test_implicit_encode (void)
{
	GBytes *bytes;
	GNode *asn;
	gchar *value;

	asn = egg_asn1x_create (test_asn1_tab, "TestImplicit");
	g_assert (asn);

	/* Should work */
	bytes = g_bytes_new_static (SIMPLICIT, XL (SIMPLICIT));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);
	value = egg_asn1x_get_string_as_utf8 (asn, NULL);
	g_assert_cmpstr (value, ==, "implicit");
	g_free (value);

	egg_asn1x_destroy (asn);
}

static void
test_implicit_decode (void)
{
	GBytes *bytes;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestImplicit");
	g_assert (asn);

	if (!egg_asn1x_set_string_as_utf8 (asn, g_strdup ("implicit"), g_free))
		g_assert_not_reached ();

	bytes = egg_asn1x_encode (asn, NULL);
	egg_assert_cmpbytes (bytes, ==, SIMPLICIT, XL (SIMPLICIT));

	egg_asn1x_destroy (asn);
	g_bytes_unref (bytes);
}

static void
test_explicit_decode (void)
{
	GBytes *bytes;
	GNode *asn;
	gchar *value;

	asn = egg_asn1x_create (test_asn1_tab, "TestExplicit");
	g_assert (asn);

	/* Should work */
	bytes = g_bytes_new_static (SEXPLICIT, XL (SEXPLICIT));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	value = egg_asn1x_get_string_as_utf8 (asn, NULL);
	g_assert_cmpstr (value, ==, "explicit");
	g_free (value);

	egg_asn1x_destroy (asn);
}

static void
test_explicit_no_context_specific (void)
{
	GBytes *bytes;
	GNode *asn;

	const gchar DER[] =     "\x45\x0A\x04\x08""explicit";

	asn = egg_asn1x_create (test_asn1_tab, "TestExplicit");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "missing context specific tag"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_explicit_no_context_child (void)
{
	GBytes *bytes;
	GNode *asn;

	const gchar DER[] =     "\xA5\x00";

	asn = egg_asn1x_create (test_asn1_tab, "TestExplicit");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "missing context specific child"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_explicit_extra_context_child (void)
{
	GBytes *bytes;
	GNode *asn;

	const gchar DER[] =     "\xA5\x14"
	                               "\x04\x08""explicit"
	                               "\x04\x08""explicit";

	asn = egg_asn1x_create (test_asn1_tab, "TestExplicit");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "multiple context specific children"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_explicit_encode (void)
{
	GBytes *bytes;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestExplicit");
	g_assert (asn);

	if (!egg_asn1x_set_string_as_utf8 (asn, g_strdup ("explicit"), g_free))
		g_assert_not_reached ();

	bytes = egg_asn1x_encode (asn, NULL);
	egg_assert_cmpbytes (bytes, ==, SEXPLICIT, XL (SEXPLICIT));

	egg_asn1x_destroy (asn);
	g_bytes_unref (bytes);
}

static void
test_universal_decode (void)
{
	GBytes *bytes;
	GNode *asn;
	gchar *value;

	asn = egg_asn1x_create (test_asn1_tab, "TestUniversal");
	g_assert (asn);

	/* Should work */
	bytes = g_bytes_new_static (SUNIVERSAL, XL (SUNIVERSAL));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	value = egg_asn1x_get_string_as_utf8 (asn, NULL);
	g_assert_cmpstr (value, ==, "universal");
	g_free (value);

	egg_asn1x_destroy (asn);
}

static void
test_universal_encode (void)
{
	GBytes *bytes;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestUniversal");
	g_assert (asn);

	if (!egg_asn1x_set_string_as_utf8 (asn, g_strdup ("universal"), g_free))
		g_assert_not_reached ();

	bytes = egg_asn1x_encode (asn, NULL);
	egg_assert_cmpbytes (bytes, ==, SUNIVERSAL, XL (SUNIVERSAL));

	egg_asn1x_destroy (asn);
	g_bytes_unref (bytes);
}

static void
test_bit_string_decode (void)
{
	GBytes *bytes;
	GNode *asn;
	GBytes *bits;
	guint n_bits;
	const guchar *data;

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");
	g_assert (asn);

	g_assert_cmpint (EGG_ASN1X_BIT_STRING, ==, egg_asn1x_type (asn));

	/* Should work */
	bytes = g_bytes_new_static (BITS_TEST, XL (BITS_TEST));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	bits = egg_asn1x_get_bits_as_raw (asn, &n_bits);
	g_assert (bits != NULL);
	g_assert_cmpuint (n_bits, ==, 18);
	data = g_bytes_get_data (bits, NULL);
	g_assert_cmpint (data[0], ==, 0x6e);
	g_assert_cmpint (data[1], ==, 0x5d);
	g_assert_cmpint (data[2], ==, 0xc0);

	g_bytes_unref (bits);
	egg_asn1x_destroy (asn);
}

static void
test_bit_string_decode_bad (void)
{
	GBytes *bytes;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");
	g_assert (asn);

	/* Should not work */
	bytes = g_bytes_new_static (BITS_BAD, XL (BITS_BAD));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_bit_string_decode_ulong (void)
{
	GBytes *bytes;
	GNode *asn;
	gulong bits;
	guint n_bits;

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");
	g_assert (asn);

	/* Should work */
	bytes = g_bytes_new_static (BITS_TEST, XL (BITS_TEST));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	if (!egg_asn1x_get_bits_as_ulong (asn, &bits, &n_bits))
		g_assert_not_reached ();

	g_assert_cmpuint (n_bits, ==, 18);
	g_assert_cmphex (bits, ==, 0x1b977);

	egg_asn1x_destroy (asn);
}

static void
test_bit_string_ulong_too_long (void)
{
	GBytes *bytes;
	GNode *asn;
	gulong bits;
	guint n_bits;

	const gchar BITS_TEST[] =  "\x03\x20\x00\x01\x02\x03\x04\x05\x06\x07"
	                                   "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	                                   "\x00\x01\x02\x03\x04\x05\x06\x07"
	                                   "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");
	g_assert (asn);

	/* Should work */

	bytes = g_bytes_new_static (BITS_TEST, XL (BITS_TEST));
	if (!egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	if (egg_asn1x_get_bits_as_ulong (asn, &bits, &n_bits))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
}

static void
test_bit_string_get_not_set (void)
{
	GNode *asn;
	gulong bits;
	guint n_bits;

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");

	if (egg_asn1x_get_bits_as_ulong (asn, &bits, &n_bits))
		g_assert_not_reached ();
	g_assert (egg_asn1x_get_bits_as_raw (asn, &n_bits) == NULL);

	egg_asn1x_destroy (asn);
}

static void
test_bit_string_invalid_length (void)
{
	GBytes *bytes;
	GNode *asn;

	const gchar DER[] =  "\x03\x00";

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");
	g_assert (asn);

	/* Should work */

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "invalid length bit string"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_bit_string_invalid_empty (void)
{
	GBytes *bytes;
	GNode *asn;

	const gchar DER[] =  "\x03\x01\x09";

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");
	g_assert (asn);

	/* Should work */

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "invalid number of empty bits"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_bit_string_encode_decode (void)
{
	GBytes *data;
	GNode *asn;
	guchar bits[] = { 0x5d, 0x6e, 0x83 };
	GBytes *check;
	GBytes *bytes;
	const guchar *ch;
	guint n_bits = 17;
	guint n_check;

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");
	g_assert (asn);

	bytes = g_bytes_new (bits, 3);
	egg_asn1x_set_bits_as_raw (asn, bytes, n_bits);
	g_bytes_unref (bytes);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data);

	if (!egg_asn1x_decode (asn, data))
		g_assert_not_reached ();

	g_bytes_unref (data);

	check = egg_asn1x_get_bits_as_raw (asn, &n_check);
	g_assert (check != NULL);
	g_assert_cmpuint (n_check, ==, 17);
	ch = g_bytes_get_data (check, NULL);
	g_assert_cmpint (ch[0], ==, 0x5d);
	g_assert_cmpint (ch[1], ==, 0x6e);
	g_assert_cmpint (ch[2], ==, 0x80);

	g_bytes_unref (check);
	egg_asn1x_destroy (asn);
}

static void
test_bit_string_encode_decode_ulong (void)
{
	GBytes *data;
	GNode *asn;
	gulong check, bits = 0x0101b977;
	guint n_check, n_bits = 18;

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");
	g_assert (asn);

	egg_asn1x_set_bits_as_ulong (asn, bits, n_bits);
	data = egg_asn1x_encode (asn, NULL);
	g_assert (data);

	if (!egg_asn1x_decode (asn, data))
		g_assert_not_reached ();

	g_bytes_unref (data);

	if (!egg_asn1x_get_bits_as_ulong (asn, &check, &n_check))
		g_assert_not_reached ();

	g_assert_cmpuint (n_check, ==, 18);
	g_assert_cmphex (check, ==, 0x1b977);

	egg_asn1x_destroy (asn);
}

static void
test_bit_string_encode_decode_zero (void)
{
	GBytes *data;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestBitString");
	g_assert (asn);

	egg_asn1x_take_bits_as_raw (asn, g_bytes_new_static ("", 0), 0);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data);

	egg_assert_cmpmem (g_bytes_get_data (data, NULL), g_bytes_get_size (data), ==, BITS_ZERO, XL (BITS_ZERO));

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
}

static void
test_have (void)
{
	GBytes *data;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestBoolean");
	g_assert (asn);

	g_assert (!egg_asn1x_have (asn));

	egg_asn1x_set_boolean (asn, TRUE);

	g_assert (egg_asn1x_have (asn));

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data);

	g_assert (egg_asn1x_have (asn));

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
}

static gboolean is_freed = FALSE;

static void
test_is_freed (gpointer unused)
{
	g_assert (!is_freed);
	is_freed = TRUE;
}

static void
test_any_raw (void)
{
	GBytes *bytes;
	GNode *asn, *node;
	GBytes *data;
	GBytes *check;

	/* ENCODED SEQUENCE ANY with OCTET STRING */
	const gchar SEQ_ENCODING[] =  "\x30\x0C\x04\x0A""farnsworth";

	asn = egg_asn1x_create (test_asn1_tab, "TestAnySeq");
	g_assert (asn);

	is_freed = FALSE;
	node = egg_asn1x_node (asn, "contents", NULL);
	g_assert (node);

	bytes = g_bytes_new_with_free_func (SFARNSWORTH, XL (SFARNSWORTH),
	                                      test_is_freed, NULL);
	if (!egg_asn1x_set_any_raw (node, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data != NULL);

	egg_assert_cmpbytes (data, ==, SEQ_ENCODING, XL (SEQ_ENCODING));

	check = egg_asn1x_get_element_raw (node);
	g_assert (check != NULL);
	egg_assert_cmpbytes (check, ==, SFARNSWORTH, XL (SFARNSWORTH));
	g_bytes_unref (check);

	check = egg_asn1x_get_any_raw (node, NULL);
	g_assert (check != NULL);
	egg_assert_cmpbytes (check, ==, SFARNSWORTH, XL (SFARNSWORTH));
	g_bytes_unref (check);

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
	g_assert (is_freed);
}

static void
test_any_raw_explicit (void)
{
	GBytes *bytes;
	GNode *asn, *node;
	GBytes *data;

	/* ENCODED SEQUENCE [89] ANY with OCTET STRING */
	const gchar SEQ_ENCODING[] =  "\x30\x0F\xBF\x59\x0C\x04\x0A""farnsworth";

	asn = egg_asn1x_create (test_asn1_tab, "TestAnyExp");
	g_assert (asn);

	is_freed = FALSE;
	node = egg_asn1x_node (asn, "contents", NULL);
	g_assert (node);

	bytes = g_bytes_new_with_free_func (SFARNSWORTH, XL (SFARNSWORTH), test_is_freed, NULL);
	if (!egg_asn1x_set_any_raw (node, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data != NULL);

	egg_assert_cmpbytes (data, ==, SEQ_ENCODING, XL (SEQ_ENCODING));

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
	g_assert (is_freed);
}

static void
test_any_raw_invalid (void)
{
	GBytes *bytes;
	GNode *asn, *node;

	const gchar TRUNCATED[] =  "\x04\x0A""farns";

	asn = egg_asn1x_create (test_asn1_tab, "TestAnySeq");
	g_assert (asn != NULL);

	node = egg_asn1x_node (asn, "contents", NULL);
	g_assert (node != NULL);

	bytes = g_bytes_new_static (TRUNCATED, XL (TRUNCATED));
	if (egg_asn1x_set_any_raw (node, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (node), "content is not encoded properly") != NULL);
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_any_raw_not_set (void)
{
	GBytes *check;
	GNode *asn, *node;

	asn = egg_asn1x_create (test_asn1_tab, "TestAnySeq");
	g_assert (asn != NULL);

	node = egg_asn1x_node (asn, "contents", NULL);
	g_assert (node != NULL);

	check = egg_asn1x_get_any_raw (node, NULL);
	g_assert (check == NULL);

	egg_asn1x_destroy (asn);
}

static void
test_any_into (void)
{
	GBytes *bytes;
	GNode *asn, *node;
	GNode *part;
	GBytes *data;
	GBytes *check;

	/* ENCODED SEQUENCE ANY with OCTET STRING */
	const gchar SEQ_ENCODING[] =  "\x30\x0C\x04\x0A""farnsworth";

	asn = egg_asn1x_create (test_asn1_tab, "TestAnySeq");
	g_assert (asn != NULL);

	is_freed = FALSE;
	node = egg_asn1x_node (asn, "contents", NULL);
	g_assert (node);

	bytes = g_bytes_new_with_free_func (SFARNSWORTH, XL (SFARNSWORTH),
	                                    test_is_freed, NULL);
	part = egg_asn1x_create_and_decode (test_asn1_tab, "TestOctetString", bytes);
	g_assert (part != NULL);
	g_bytes_unref (bytes);

	egg_asn1x_set_any_from (node, part);
	egg_asn1x_destroy (part);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data != NULL);
	egg_assert_cmpbytes (data, ==, SEQ_ENCODING, XL (SEQ_ENCODING));

	part = egg_asn1x_create (test_asn1_tab, "TestOctetString");
	if (!egg_asn1x_get_any_into (node, part))
		g_assert_not_reached ();

	check = egg_asn1x_encode (part, NULL);
	egg_asn1x_destroy (part);
	g_assert (check != NULL);
	egg_assert_cmpbytes (check, ==, SFARNSWORTH, XL (SFARNSWORTH));
	g_bytes_unref (check);

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
	g_assert (is_freed);
}

static void
test_any_into_explicit (void)
{
	GBytes *bytes;
	GNode *asn, *node;
	GNode *part;
	GBytes *data;
	GBytes *check;

	/* ENCODED SEQUENCE [89] ANY with OCTET STRING */
	const gchar SEQ_ENCODING[] =  "\x30\x0F\xBF\x59\x0C\x04\x0A""farnsworth";

	asn = egg_asn1x_create (test_asn1_tab, "TestAnyExp");
	g_assert (asn != NULL);

	is_freed = FALSE;
	node = egg_asn1x_node (asn, "contents", NULL);
	g_assert (node);

	bytes = g_bytes_new_with_free_func (SFARNSWORTH, XL (SFARNSWORTH),
	                                    test_is_freed, NULL);
	part = egg_asn1x_create_and_decode (test_asn1_tab, "TestOctetString", bytes);
	g_assert (part != NULL);
	g_bytes_unref (bytes);

	egg_asn1x_set_any_from (node, part);
	egg_asn1x_destroy (part);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data != NULL);
	egg_assert_cmpbytes (data, ==, SEQ_ENCODING, XL (SEQ_ENCODING));

	part = egg_asn1x_create (test_asn1_tab, "TestOctetString");
	if (!egg_asn1x_get_any_into (node, part))
		g_assert_not_reached ();

	check = egg_asn1x_encode (part, NULL);
	egg_asn1x_destroy (part);
	g_assert (check != NULL);
	egg_assert_cmpbytes (check, ==, SFARNSWORTH, XL (SFARNSWORTH));
	g_bytes_unref (check);

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
	g_assert (is_freed);
}

static void
test_any_into_explicit_not_set (void)
{
	GNode *asn, *node;
	GNode *part;

	asn = egg_asn1x_create (test_asn1_tab, "TestAnyExp");
	g_assert (asn != NULL);

	node = egg_asn1x_node (asn, "contents", NULL);
	g_assert (node);

	part = egg_asn1x_create (test_asn1_tab, "TestOctetString");
	if (egg_asn1x_get_any_into (node, part))
		g_assert_not_reached ();

	egg_asn1x_destroy (part);
	egg_asn1x_destroy (asn);
}

static void
test_choice_not_chosen (void)
{
	GBytes *bytes;
	GNode *asn, *node;
	GBytes *data;

	asn = egg_asn1x_create (test_asn1_tab, "TestAnyChoice");
	g_assert (asn);

	g_assert_cmpint (EGG_ASN1X_CHOICE, ==, egg_asn1x_type (asn));

	node = egg_asn1x_node (asn, "choiceShortTag", NULL);
	g_assert (node);

	bytes = g_bytes_new_static (SFARNSWORTH, XL (SFARNSWORTH));
	if (!egg_asn1x_set_any_raw (node, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	/* egg_asn1x_set_choice() was not called */
	data = egg_asn1x_encode (asn, NULL);
	g_assert (data == NULL);
	g_assert (egg_asn1x_message (asn));
	g_assert (strstr (egg_asn1x_message (asn), "TestAnyChoice") != NULL);

	egg_asn1x_destroy (asn);
}

static void
perform_asn1_any_choice_set_raw (const gchar *choice, const gchar *encoding, gsize n_encoding)
{
	GBytes *bytes;
	GNode *asn, *node;
	GBytes *data;
	GBytes *check;

	asn = egg_asn1x_create (test_asn1_tab, "TestAnyChoice");
	g_assert (asn);

	g_assert_cmpint (EGG_ASN1X_CHOICE, ==, egg_asn1x_type (asn));

	is_freed = FALSE;
	node = egg_asn1x_node (asn, choice, NULL);
	g_assert (node);

	if (!egg_asn1x_set_choice (asn, node))
		g_assert_not_reached ();

	bytes = g_bytes_new_with_free_func (SFARNSWORTH, XL (SFARNSWORTH), test_is_freed, NULL);
	if (!egg_asn1x_set_any_raw (node, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	data = egg_asn1x_encode (asn, NULL);
	if (data == NULL) {
		g_printerr ("%s\n", egg_asn1x_message (asn));
		g_assert_not_reached ();
	}
	g_assert (data != NULL);

	egg_assert_cmpbytes (data, ==, encoding, n_encoding);

	check = egg_asn1x_get_element_raw (node);
	g_assert (check != NULL);

	egg_assert_cmpbytes (check, ==, SFARNSWORTH, XL (SFARNSWORTH));

	g_bytes_unref (data);
	g_bytes_unref (check);
	egg_asn1x_destroy (asn);
	g_assert (is_freed);
}

static void
test_any_choice_set_raw_short_tag (void)
{
	const gchar ENCODING[] = "\xBE\x0C\x04\x0A""farnsworth";
	perform_asn1_any_choice_set_raw ("choiceShortTag", ENCODING, XL (ENCODING));
}

static void
test_any_choice_set_raw_long_tag (void)
{
	const gchar ENCODING[] = "\xBF\x1F\x0C\x04\x0A""farnsworth";
	perform_asn1_any_choice_set_raw ("choiceLongTag", ENCODING, XL (ENCODING));
}

static void
test_seq_of_any (void)
{
	GNode *asn;
	GNode *integer;
	GBytes *bytes;
	gboolean ret;
	gulong value;

	const gchar DER[] = "\x30\x06"
	                        "\x02\x01\x88"
	                        "\x02\x01\x33";

	asn = egg_asn1x_create (test_asn1_tab, "TestSeqOfAny");
	g_assert (asn != NULL);

	egg_asn1x_append (asn);
	egg_asn1x_append (asn);

	bytes = g_bytes_new_static (DER, XL (DER));
	ret = egg_asn1x_decode (asn, bytes);
	egg_asn1x_assert (ret == TRUE, asn);
	g_bytes_unref (bytes);

	integer = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (integer != NULL);

	ret = egg_asn1x_get_any_into (egg_asn1x_node (asn, 1, NULL), integer);
	egg_asn1x_assert (ret == TRUE, integer);
	if (!egg_asn1x_get_integer_as_ulong (integer, &value))
		g_assert_not_reached ();
	g_assert_cmpint (value, ==, 0x88);

	ret = egg_asn1x_get_any_into (egg_asn1x_node (asn, 2, NULL), integer);
	egg_asn1x_assert (ret == TRUE, integer);
	if (!egg_asn1x_get_integer_as_ulong (integer, &value))
		g_assert_not_reached ();
	g_assert_cmpint (value, ==, 0x33);

	egg_asn1x_destroy (integer);
	egg_asn1x_destroy (asn);
}

static void
test_seq_of_invalid (void)
{
	GNode *asn;
	GBytes *bytes;

	const gchar DER[] = "\x30\x05"
	                        "\x04\x00"
	                        "\x02\x01\x88";

	asn = egg_asn1x_create (test_asn1_tab, "TestSeqOf");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_seq_of_different (void)
{
	GNode *asn;
	GBytes *bytes;

	const gchar DER[] = "\x30\x05"
	                        "\x02\x01\x88"
	                        "\x04\x00";

	asn = egg_asn1x_create (test_asn1_tab, "TestSeqOf");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_set_order (void)
{
	GNode *asn;
	GBytes *bytes;

	const gchar DER[] = "\x31\x0f"
	                        "\xA2\x03\x02\x01\x99"
	                        "\xA1\x03\x02\x01\x88"
	                        "\xA3\x03\x02\x01\x88";

	asn = egg_asn1x_create (test_asn1_tab, "TestSet");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "content must be in ascending order"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_append (void)
{
	GBytes *bytes;
	GNode *asn;
	GNode *child;
	GBytes *data;

	/* SEQUENCE OF with one INTEGER = 1 */
	const gchar SEQOF_ONE[] =  "\x30\x03\x02\x01\x01";

	/* SEQUENCE OF with two INTEGER = 1, 2 */
	const gchar SEQOF_TWO[] =  "\x30\x06\x02\x01\x01\x02\x01\x02";

	bytes = g_bytes_new_static (SEQOF_ONE, XL (SEQOF_ONE));
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestSeqOf", bytes);
	g_assert (asn);
	g_bytes_unref (bytes);

	g_assert_cmpint (EGG_ASN1X_SEQUENCE_OF, ==, egg_asn1x_type (asn));

	child = egg_asn1x_append (asn);
	g_assert (child);

	/* Second integer is 2 */
	egg_asn1x_set_integer_as_ulong (child, 2);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data != NULL);

	egg_assert_cmpbytes (data, ==, SEQOF_TWO, XL (SEQOF_TWO));

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
}

static void
test_append_and_clear (void)
{
	GBytes *data;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestSeqOf");
	g_assert (asn);

	g_assert_cmpuint (egg_asn1x_count (asn), ==, 0);

	egg_asn1x_set_integer_as_ulong (egg_asn1x_append (asn), 2);
	egg_asn1x_set_integer_as_ulong (egg_asn1x_append (asn), 3);

	g_assert_cmpuint (egg_asn1x_count (asn), ==, 2);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data != NULL);

	g_assert_cmpuint (egg_asn1x_count (asn), ==, 2);

	egg_asn1x_clear (asn);
	g_assert_cmpuint (egg_asn1x_count (asn), ==, 0);

	egg_asn1x_destroy (asn);
	g_bytes_unref (data);
}

static void
test_setof (void)
{
	GBytes *bytes;
	GNode *asn;
	GBytes *data;

	/* SEQUENCE OF with one INTEGER = 3 */
	const gchar SETOF_ONE[] =  "\x31\x03\x02\x01\x03";

	/* SET OF with two INTEGER = 1, 3, 8 */
	const gchar SETOF_THREE[] =  "\x31\x09\x02\x01\x01\x02\x01\x03\x02\x01\x08";

	bytes = g_bytes_new_static (SETOF_ONE, XL (SETOF_ONE));
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestSetOf", bytes);
	g_assert (asn != NULL);
	g_bytes_unref (bytes);

	g_assert_cmpint (EGG_ASN1X_SET_OF, ==, egg_asn1x_type (asn));

	/* Add integer 1, in SET OF DER should sort to front */
	egg_asn1x_set_integer_as_ulong (egg_asn1x_append (asn), 1);

	/* Add integer 8, in SET OF DER should sort to back */
	egg_asn1x_set_integer_as_ulong (egg_asn1x_append (asn), 8);

	data = egg_asn1x_encode (asn, NULL);
	if (data == NULL) {
		g_printerr ("%s\n", egg_asn1x_message (asn));
		g_assert_not_reached ();
	}

	egg_assert_cmpbytes (data, ==, SETOF_THREE, XL (SETOF_THREE));

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
}

static void
test_setof_empty (void)
{
	GBytes *data;
	GNode *asn;

	/* SEQUENCE OF with nothing */
	const gchar SETOF_NONE[] =  "\x31\x00";

	asn = egg_asn1x_create (test_asn1_tab, "TestSetOf");
	g_assert (asn);

	data = egg_asn1x_encode (asn, NULL);
	if (data == NULL) {
		g_printerr ("%s\n", egg_asn1x_message (asn));
		g_assert_not_reached ();
	}

	egg_assert_cmpbytes (data, ==, SETOF_NONE, XL (SETOF_NONE));

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
}

static void
test_enumerated (void)
{
	GBytes *bytes;
	GNode *asn;
	GBytes *data;
	GQuark value;

	bytes = g_bytes_new_static (ENUM_TWO, XL (ENUM_TWO));
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestEnumerated", bytes);
	g_assert (asn != NULL);
	g_bytes_unref (bytes);

	g_assert_cmpint (EGG_ASN1X_ENUMERATED, ==, egg_asn1x_type (asn));

	value = egg_asn1x_get_enumerated (asn);
	g_assert (value);
	g_assert_cmpstr (g_quark_to_string (value), ==, "valueTwo");

	egg_asn1x_set_enumerated (asn, g_quark_from_static_string ("valueThree"));

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data != NULL);

	egg_assert_cmpbytes (data, ==, ENUM_THREE, XL (ENUM_THREE));

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
}

static void
test_enumerated_decode_bad (void)
{
	const gchar ENUM_NEGATIVE[] =           "\x0A\x01\x85";

	GBytes *bytes;
	GNode *asn;
	gboolean ret;

	asn = egg_asn1x_create (test_asn1_tab, "TestEnumerated");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (ENUM_NEGATIVE, XL (ENUM_NEGATIVE));
	ret = egg_asn1x_decode (asn, bytes);
	g_assert (ret == FALSE);
	g_assert (strstr (egg_asn1x_message (asn), "enumerated must be positive") != NULL);
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_enumerated_not_in_list (void)
{
	const gchar ENUM_OTHER[] =   "\x0A\x01\x08";
	const gchar ENUM_LARGE[] =   "\x0A\x20\x00\x01\x02\x03\x04\x05\x06\x07"
	                                     "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	                                     "\x00\x01\x02\x03\x04\x05\x06\x07"
	                                     "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

	GBytes *bytes;
	GNode *asn;
	gboolean ret;

	asn = egg_asn1x_create (test_asn1_tab, "TestEnumerated");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (ENUM_OTHER, XL (ENUM_OTHER));
	ret = egg_asn1x_decode (asn, bytes);
	g_assert (ret == FALSE);
	g_assert (strstr (egg_asn1x_message (asn), "not part of list") != NULL);
	g_bytes_unref (bytes);

	bytes = g_bytes_new_static (ENUM_LARGE, XL (ENUM_LARGE));
	ret = egg_asn1x_decode (asn, bytes);
	g_assert (ret == FALSE);
	g_assert (strstr (egg_asn1x_message (asn), "not part of list") != NULL);
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_enumerated_not_set (void)
{
	GNode *asn;
	GQuark value;

	asn = egg_asn1x_create (test_asn1_tab, "TestEnumerated");
	g_assert (asn != NULL);

	value = egg_asn1x_get_enumerated (asn);
	g_assert (value == 0);

	egg_asn1x_destroy (asn);
}


typedef struct {
	GNode *asn1;
	guchar *data;
	gsize n_data;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	GBytes *bytes;

	if (!g_file_get_contents (SRCDIR "/egg/fixtures/test-certificate-1.der",
	                          (gchar**)&test->data, &test->n_data, NULL))
		g_assert_not_reached ();

	test->asn1 = egg_asn1x_create (pkix_asn1_tab, "Certificate");
	g_assert (test->asn1 != NULL);

	bytes = g_bytes_new_static (test->data, test->n_data);
	if (!egg_asn1x_decode (test->asn1, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);
}

static void
teardown (Test *test, gconstpointer unused)
{
	egg_asn1x_destroy (test->asn1);
	g_free (test->data);
}

static void
test_node_name (Test* test, gconstpointer unused)
{
	g_assert_cmpstr (egg_asn1x_name (test->asn1), ==, "Certificate");
}

static void
test_asn1_integers (Test* test, gconstpointer unused)
{
	GBytes *data;
	GNode *asn;
	gboolean ret;
	gulong val;

	asn = egg_asn1x_create (test_asn1_tab, "TestIntegers");
	g_assert ("asn test structure is null" && asn != NULL);

	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "uint1", NULL), 35);
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "uint2", NULL), 23456);
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "uint3", NULL), 209384022);

	/* Now encode the whole caboodle */
	data = egg_asn1x_encode (asn, NULL);
	g_assert ("encoding asn1 didn't work" && data != NULL);

	egg_asn1x_destroy (asn);

	/* Now decode it all nicely */
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestIntegers", data);
	g_return_if_fail (asn != NULL);

	/* And get out the values */
	ret = egg_asn1x_get_integer_as_ulong (egg_asn1x_node (asn, "uint1", NULL), &val);
	g_assert ("couldn't read integer from asn1" && ret);
	g_assert_cmpuint (val, ==, 35);

	ret = egg_asn1x_get_integer_as_ulong (egg_asn1x_node (asn, "uint2", NULL), &val);
	g_assert ("couldn't read integer from asn1" && ret);
	g_assert_cmpuint (val, ==, 23456);

	ret = egg_asn1x_get_integer_as_ulong (egg_asn1x_node (asn, "uint3", NULL), &val);
	g_assert ("couldn't read integer from asn1" && ret);
	g_assert_cmpuint (val, ==, 209384022);

	egg_asn1x_destroy (asn);
	g_bytes_unref (data);
}

static void
test_boolean_seq (Test* test, gconstpointer unused)
{
	GBytes *data;
	GNode *asn = NULL;
	gboolean value, ret;

	/* The first boolean has a default of FALSE, so doesn't get encoded if FALSE */
	const gchar SEQ_BOOLEAN_TRUE_FALSE[] = "\x30\x06\x01\x01\xFF\x01\x01\x00";
	const gchar SEQ_BOOLEAN_FALSE_FALSE[] = "\x30\x03\x01\x01\x00";

	asn = egg_asn1x_create (test_asn1_tab, "TestBooleanSeq");
	g_assert ("asn test structure is null" && asn != NULL);

	/* Get the default value */
	value = TRUE;
	ret = egg_asn1x_get_boolean (egg_asn1x_node (asn, "boolean", NULL), &value);
	g_assert (ret == TRUE);
	g_assert (value == FALSE);

	egg_asn1x_set_boolean (egg_asn1x_node (asn, "boolean", NULL), TRUE);
	egg_asn1x_set_boolean (egg_asn1x_node (asn, "boolean2", NULL), FALSE);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data != NULL);
	egg_assert_cmpbytes (data, ==, SEQ_BOOLEAN_TRUE_FALSE, XL (SEQ_BOOLEAN_TRUE_FALSE));
	g_bytes_unref (data);

	ret = egg_asn1x_get_boolean (egg_asn1x_node (asn, "boolean", NULL), &value);
	g_assert (ret);
	g_assert (value == TRUE);

	egg_asn1x_set_boolean (egg_asn1x_node (asn, "boolean", NULL), FALSE);

	data = egg_asn1x_encode (asn, NULL);
	g_assert (data != NULL);
	egg_assert_cmpbytes (data, ==, SEQ_BOOLEAN_FALSE_FALSE, XL (SEQ_BOOLEAN_FALSE_FALSE));

	ret = egg_asn1x_get_boolean (egg_asn1x_node (asn, "boolean", NULL), &value);
	g_assert (ret);
	g_assert (value == FALSE);

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
}

static void
test_write_value (Test* test, gconstpointer unused)
{
	GBytes *encoded;
	GNode *asn = NULL;
	guchar *data;
	gsize n_data;

	asn = egg_asn1x_create (test_asn1_tab, "TestData");
	g_assert ("asn test structure is null" && asn != NULL);

	egg_asn1x_set_string_as_raw (egg_asn1x_node (asn, "data", NULL), (guchar*)"SOME DATA", 9, NULL);

	encoded = egg_asn1x_encode (asn, NULL);
	g_assert (encoded);

	data = egg_asn1x_get_string_as_raw (egg_asn1x_node (asn, "data", NULL), NULL, &n_data);
	g_assert (data != NULL);
	g_assert_cmpuint (n_data, ==, 9);
	g_assert (memcmp (data, "SOME DATA", 9) == 0);
	g_free (data);

	g_bytes_unref (encoded);
	egg_asn1x_destroy (asn);
}

static void
test_element_length_content (Test* test, gconstpointer unused)
{
	GBytes *buffer;
	GNode *asn = NULL;
	const guchar *content;
	gsize n_content;
	gssize length;

	asn = egg_asn1x_create (test_asn1_tab, "TestData");
	g_assert ("asn test structure is null" && asn != NULL);

	egg_asn1x_set_string_as_raw (egg_asn1x_node (asn, "data", NULL), (guchar*)"SOME DATA", 9, NULL);

	buffer = egg_asn1x_encode (asn, NULL);
	g_assert (buffer != NULL);

	/* Now the real test */
	length = egg_asn1x_element_length (g_bytes_get_data (buffer, NULL),
	                                   g_bytes_get_size (buffer) + 1024);
	g_assert_cmpint (length, ==, 13);

	content = egg_asn1x_element_content (g_bytes_get_data (buffer, NULL),
	                                     length, &n_content);
	g_assert (content != NULL);
	g_assert_cmpuint (n_content, ==, 11);

	content = egg_asn1x_element_content (content, n_content, &n_content);
	g_assert (content);
	g_assert_cmpuint (n_content, ==, 9);
	g_assert (memcmp (content, "SOME DATA", 9) == 0);

	const guchar *BAD_ASN_TAG = (guchar *)"\x00";
	content = egg_asn1x_element_content (BAD_ASN_TAG, 1, &n_content);
	g_assert (content == NULL);

	const guchar *BAD_ASN_LENGTH = (guchar *)"\x30\x80";
	content = egg_asn1x_element_content (BAD_ASN_LENGTH, 2, &n_content);
	g_assert (content == NULL);

	egg_asn1x_destroy (asn);
	g_bytes_unref (buffer);
}

static void
test_read_element (Test* test, gconstpointer unused)
{
	GBytes *buffer;
	GNode *asn = NULL;
	GBytes *data;

	asn = egg_asn1x_create (test_asn1_tab, "TestData");
	g_assert ("asn test structure is null" && asn != NULL);

	egg_asn1x_set_string_as_raw (egg_asn1x_node (asn, "data", NULL), (guchar*)"SOME DATA", 9, NULL);

	buffer = egg_asn1x_encode (asn, NULL);
	g_assert (buffer != NULL);

	/* Have to decode before we can get raw elements */
	if (!egg_asn1x_decode (asn, buffer))
		g_assert_not_reached ();

	/* Now the real test */
	data = egg_asn1x_get_element_raw (egg_asn1x_node (asn, "data", NULL));
	g_assert (data != NULL);
	g_assert_cmpint (g_bytes_get_size (data), ==, 11);
	g_bytes_unref (data);

	data = egg_asn1x_get_value_raw (egg_asn1x_node (asn, "data", NULL));
	g_assert (data != NULL);
	egg_assert_cmpbytes (data, ==, "SOME DATA", 9);
	g_bytes_unref (data);

	egg_asn1x_destroy (asn);
	g_bytes_unref (buffer);
}

static void
test_oid (void)
{
	GBytes *buffer;
	GNode *asn = NULL;
	GNode *node;
	GQuark oid, check;

	asn = egg_asn1x_create (test_asn1_tab, "TestOid");
	g_assert ("asn test structure is null" && asn != NULL);

	node = egg_asn1x_node (asn, "oid", NULL);
	g_assert_cmpint (EGG_ASN1X_OBJECT_ID, ==, egg_asn1x_type (node));

	if (!egg_asn1x_set_oid_as_string (node, "1.2.34567.89"))
		g_assert_not_reached ();

	buffer = egg_asn1x_encode (asn, NULL);
	g_assert (buffer != NULL);

	/* Now a quark has been defined */
	check = g_quark_from_static_string ("1.2.34567.89");
	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "oid", NULL));
	g_assert (oid);
	g_assert (check == oid);
	g_assert_cmpstr (g_quark_to_string (oid), ==, "1.2.34567.89");

	/* Write a different OID */
	if (!egg_asn1x_set_oid_as_quark (egg_asn1x_node (asn, "oid", NULL), g_quark_from_static_string ("5.4.3.2.1678")))
		g_assert_not_reached ();

	g_bytes_unref (buffer);
	buffer = egg_asn1x_encode (asn, NULL);
	g_assert (buffer != NULL);

	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "oid", NULL));
	g_assert (oid);
	g_assert_cmpstr (g_quark_to_string (oid), ==, "5.4.3.2.1678");

	g_bytes_unref (buffer);
	egg_asn1x_destroy (asn);
}

static void
test_oid_set_invalid (void)
{
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestOid");
	g_assert ("asn test structure is null" && asn != NULL);

	if (egg_asn1x_set_oid_as_string (egg_asn1x_node (asn, "oid", NULL), "abcd"))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
}

static void
test_oid_decode_bad (void)
{
	GBytes *bytes;
	GNode *asn;
	gboolean ret;

	/* Has invalid leading integer in oid value */
	const gchar INVALID_OID[] = "\x30\x07\x06\x05\x2b\x80\x83\x82\x1a";

	asn = egg_asn1x_create (test_asn1_tab, "TestOid");
	g_assert ("asn test structure is null" && asn != NULL);

	bytes = g_bytes_new_static (INVALID_OID, XL (INVALID_OID));
	ret = egg_asn1x_decode (asn, bytes);
	g_assert (ret == FALSE);
	g_assert (strstr (egg_asn1x_message (asn), "object id encoding is invalid") != NULL);

	g_bytes_unref (bytes);
	egg_asn1x_destroy (asn);
}

static void
test_oid_get_no_value (void)
{
	GNode *asn;
	gchar *oid;

	asn = egg_asn1x_create (test_asn1_tab, "TestOid");
	g_assert ("asn test structure is null" && asn != NULL);

	oid = egg_asn1x_get_oid_as_string (egg_asn1x_node (asn, "oid", NULL));
	g_assert (oid == NULL);

	egg_asn1x_destroy (asn);
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

	/* Bad ones */
	{ "200707", -1 },

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

	/* Bad ones */
	{ "0707", -1 },

	{ NULL, 0 }
};

static void
test_general_time (Test* test, gconstpointer unused)
{
	time_t when;
	const TimeTestData *data;

	for (data = generalized_time_test_data; data->value; ++data) {
		when = egg_asn1x_parse_time_general (data->value, -1);
		if (data->ref != when) {
			printf ("%s", data->value);
			printf ("%s != ", ctime (&when));
			printf ("%s\n", ctime (&data->ref));
			fflush (stdout);
		}

		g_assert ("decoded time doesn't match reference" && data->ref == when);
	}
}

static void
test_utc_time (Test* test, gconstpointer unused)
{
	time_t when;
	const TimeTestData *data;

	for (data = utc_time_test_data; data->value; ++data) {
		when = egg_asn1x_parse_time_utc (data->value, -1);
		if (data->ref != when) {
			printf ("%s", data->value);
			printf ("%s != ", ctime (&when));
			printf ("%s\n", ctime (&data->ref));
			fflush (stdout);
		}

		g_assert ("decoded time doesn't match reference" && data->ref == when);
	}
}

static void
test_read_time (Test* test, gconstpointer unused)
{
	glong time;

	time = egg_asn1x_get_time_as_long (egg_asn1x_node (test->asn1, "tbsCertificate", "validity", "notBefore", NULL));
	g_assert_cmpint (time, ==, 820454400);
}

static void
test_read_date (Test* test, gconstpointer unused)
{
	GDate date;
	if (!egg_asn1x_get_time_as_date (egg_asn1x_node (test->asn1, "tbsCertificate", "validity", "notAfter", NULL), &date))
		g_assert_not_reached ();
	g_assert_cmpint (date.day, ==, 31);
	g_assert_cmpint (date.month, ==, 12);
	g_assert_cmpint (date.year, ==, 2020);
}

static void
test_create_by_oid (Test* test, gconstpointer unused)
{
	/* id-at-initials = X520initials */
	GNode *node = egg_asn1x_create (pkix_asn1_tab, "2.5.4.43");
	g_assert (node != NULL);
	g_assert_cmpstr (egg_asn1x_name (node), ==, "X520initials");
	egg_asn1x_destroy (node);
}

static void
test_create_by_oid_invalid (Test* test, gconstpointer unused)
{
	GNode *node = egg_asn1x_create (pkix_asn1_tab, "23.23.23.23");
	g_assert (node == NULL);
}

static void
test_create_by_bad_order (Test* test, gconstpointer unused)
{
	/*
	 * In pkix.asn the definition for parts of this oid
	 * come in the wrong order. However this should still work.
	 */

	/* id-pe-authorityInfoAccess = AuthorityInfoAccessSyntax */
	GNode *node = egg_asn1x_create (pkix_asn1_tab, "1.3.6.1.5.5.7.1.1");
	g_assert (node != NULL);
	g_assert_cmpstr (egg_asn1x_name (node), ==, "AuthorityInfoAccessSyntax");
	egg_asn1x_destroy (node);
}

static void
test_count (Test* test, gconstpointer unused)
{
	GNode *node;

	node = egg_asn1x_node (test->asn1, "tbsCertificate", "issuer", "rdnSequence", NULL);
	g_assert (node);
	g_assert_cmpuint (egg_asn1x_count (node), ==, 7);
}

static void
test_nested_fails_with_extra (void)
{
	gboolean ret;
	GBytes *bytes;
	GNode *asn;

	const gchar SEQ_NESTED[] =  "\x30\x0C"
	                                 "\x04\x03""one"
	                                 "\x04\x05""extra";

	asn = egg_asn1x_create (test_asn1_tab, "TestData");
	g_assert ("asn test structure is null" && asn != NULL);

	bytes = g_bytes_new_static (SEQ_NESTED, XL (SEQ_NESTED));
	ret = egg_asn1x_decode (asn, bytes);
	egg_asn1x_assert (ret == FALSE, asn);
	egg_asn1x_assert (strstr (egg_asn1x_message (asn), "encountered extra tag"), asn);
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_nested_unexpected (void)
{
	gboolean ret;
	GBytes *bytes;
	GNode *asn;

	const gchar SEQ_NESTED[] =  "\x30\x03"
	                                 "\x02\x01\x2A";

	asn = egg_asn1x_create (test_asn1_tab, "TestData");
	g_assert ("asn test structure is null" && asn != NULL);

	bytes = g_bytes_new_static (SEQ_NESTED, XL (SEQ_NESTED));
	ret = egg_asn1x_decode (asn, bytes);
	egg_asn1x_assert (ret == FALSE, asn);
	egg_asn1x_assert (strstr (egg_asn1x_message (asn), "decoded tag did not match expected"), asn);
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_create_and_decode_invalid (void)
{
	GBytes *bytes;
	GNode *asn;

	bytes = g_bytes_new_static ("", 0);
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestData", bytes);
	g_assert (asn == NULL);
	g_bytes_unref (bytes);
}

static void
test_decode_extra (void)
{
	GBytes *bytes;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestSeqOf");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static ("\x30\x00\x11", 3);
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "extra unexpected trailing data"));
	g_bytes_unref (bytes);
	egg_asn1x_destroy (asn);
}

static void
test_decode_nested_short (void)
{
	GBytes *bytes;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestSeqOfAny");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static ("\x30\x02\xA5\x08", 4);
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "content is not encoded properly"));
	g_bytes_unref (bytes);

	bytes = g_bytes_new_static ("\x30\x04\x30\x02\xA5\x08", 6);
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "content is not encoded properly"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_decode_indefinite_primitive (void)
{
	GBytes *bytes;
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static ("\x04\x80\x04\x01\x55\x00\x00", 7);
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "indefinite length on non-structured type"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_decode_invalid_long_length (void)
{
	GBytes *bytes;
	GNode *asn;

	const gchar DER[] = "\x04\xA0"
			"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
			"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "content is not encoded properly"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_decode_truncated_at_tag (void)
{
	GBytes *bytes;
	GNode *asn;

	const gchar DER[] = "\x04";
	asn = egg_asn1x_create (test_asn1_tab, "TestInteger");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (DER, XL (DER));
	if (egg_asn1x_decode (asn, bytes))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "content is not encoded properly"));
	g_bytes_unref (bytes);

	egg_asn1x_destroy (asn);
}

static void
test_decode_long_tag (void)
{
	GBytes *bytes;
	GNode *asn;
	gboolean ret;

	const gchar DER[] = "\xbf\x89\x52\x03\x04\x01\x33";

	asn = egg_asn1x_create (test_asn1_tab, "TestTagLong");
	g_assert (asn != NULL);

	bytes = g_bytes_new_static (DER, XL (DER));
	ret = egg_asn1x_decode (asn, bytes);
	egg_asn1x_assert (ret == TRUE, asn);

	g_bytes_unref (bytes);
	egg_asn1x_destroy (asn);

}

static void
test_create_quark (void)
{
	GNode *asn;

	asn = egg_asn1x_create_quark (test_asn1_tab, g_quark_from_static_string ("1.5.13"));
	g_assert (asn != NULL);
	g_assert_cmpstr (egg_asn1x_name (asn), ==, "TestIntegers");
	egg_asn1x_destroy (asn);
}

static void
test_validate_default (void)
{
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestBooleanSeq");
	/* We leave first boolean field empty */
	egg_asn1x_set_boolean (egg_asn1x_node (asn, "boolean2", NULL), TRUE);
	if (!egg_asn1x_validate (asn, TRUE))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
}

static void
test_validate_missing (void)
{
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestBooleanSeq");
	/* No fields set */
	if (egg_asn1x_validate (asn, TRUE))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "missing value") != NULL);
	egg_asn1x_destroy (asn);
}

static void
test_validate_seq_of_child_invalid (void)
{
	GNode *asn;
	GNode *child;

	asn = egg_asn1x_create (test_asn1_tab, "TestSeqOfSeq");
	child = egg_asn1x_append (asn);
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (child, "uint1", NULL), 5);
	/* We didn't set uint2 or uint3 so the child is invalid */
	if (egg_asn1x_validate (asn, TRUE))
		g_assert_not_reached ();
	g_assert (strstr (egg_asn1x_message (asn), "missing value") != NULL);
	egg_asn1x_destroy (asn);

}

static void
test_validate_optional_seq (void)
{
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestSeqOptional");
	if (!egg_asn1x_validate (asn, TRUE))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
}

static void
test_element_get_not_set (void)
{
	GNode *asn;

	asn = egg_asn1x_create (test_asn1_tab, "TestBooleanSeq");
	g_assert (egg_asn1x_get_element_raw (asn) == NULL);
	egg_asn1x_destroy (asn);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/asn1/decode/extra", test_decode_extra);
	g_test_add_func ("/asn1/decode/nested-short", test_decode_nested_short);
	g_test_add_func ("/asn1/decode/indefinite-primitive", test_decode_indefinite_primitive);
	g_test_add_func ("/asn1/decode/invalid-long-length", test_decode_invalid_long_length);
	g_test_add_func ("/asn1/decode/truncated-at-tag", test_decode_truncated_at_tag);
	g_test_add_func ("/asn1/decode/decode-long-tag", test_decode_long_tag);
	g_test_add_func ("/asn1/boolean", test_boolean);
	g_test_add_func ("/asn1/boolean-bad", test_boolean_decode_bad);
	g_test_add_func ("/asn1/boolean-default", test_boolean_default);
	g_test_add_func ("/asn1/null", test_null);
	g_test_add_func ("/asn1/integer", test_integer);
	g_test_add_func ("/asn1/integer-zero-length", test_integer_zero_length);
	g_test_add_func ("/asn1/integer/raw", test_integer_raw);
	g_test_add_func ("/asn1/integer/raw-not-twos-complement", test_integer_raw_not_twos_complement);
	g_test_add_func ("/asn1/integer/raw-not-twos-complement/subprocess", test_integer_raw_not_twos_complement_subprocess);
	g_test_add_func ("/asn1/unsigned", test_unsigned);
	g_test_add_func ("/asn1/unsigned/not-set", test_unsigned_not_set);
	g_test_add_func ("/asn1/unsigned/default", test_unsigned_default);
	g_test_add_func ("/asn1/unsigned/constant", test_unsigned_constant);
	g_test_add_func ("/asn1/unsigned/zero", test_unsigned_zero);
	g_test_add_func ("/asn1/octet_string", test_octet_string);
	g_test_add_func ("/asn1/octet-string/set-bad-utf8", test_octet_string_set_bad_utf8);
	g_test_add_func ("/asn1/octet-string/bmp-as-utf8", test_octet_string_bmp_as_utf8);
	g_test_add_func ("/asn1/octet-string/get-as-bytes", test_octet_string_get_as_bytes);
	g_test_add_func ("/asn1/octet-string/set-as-bytes", test_octet_string_set_as_bytes);
	g_test_add_func ("/asn1/octet-string/structured", test_octet_string_structured);
	g_test_add_func ("/asn1/octet-string/structured-bad", test_octet_string_structured_bad);
	g_test_add_func ("/asn1/generalized_time", test_generalized_time);
	g_test_add_func ("/asn1/time-get-missing", test_time_get_missing);
	g_test_add_func ("/asn1/implicit/decode", test_implicit_decode);
	g_test_add_func ("/asn1/implicit/encode", test_implicit_encode);
	g_test_add_func ("/asn1/explicit/decode", test_explicit_decode);
	g_test_add_func ("/asn1/explicit/encode", test_explicit_encode);
	g_test_add_func ("/asn1/explicit/no-context-specific", test_explicit_no_context_specific);
	g_test_add_func ("/asn1/explicit/no-context-child", test_explicit_no_context_child);
	g_test_add_func ("/asn1/explicit/extra-context-child", test_explicit_extra_context_child);
	g_test_add_func ("/asn1/universal/decode", test_universal_decode);
	g_test_add_func ("/asn1/universal/encode", test_universal_encode);
	g_test_add_func ("/asn1/bit_string_decode", test_bit_string_decode);
	g_test_add_func ("/asn1/bit_string_decode_bad", test_bit_string_decode_bad);
	g_test_add_func ("/asn1/bit_string_decode_ulong", test_bit_string_decode_ulong);
	g_test_add_func ("/asn1/bit_string_encode_decode", test_bit_string_encode_decode);
	g_test_add_func ("/asn1/bit_string_encode_decode_ulong", test_bit_string_encode_decode_ulong);
	g_test_add_func ("/asn1/bit_string_encode_decode_zero", test_bit_string_encode_decode_zero);
	g_test_add_func ("/asn1/bit-string/ulong-too-long", test_bit_string_ulong_too_long);
	g_test_add_func ("/asn1/bit-string/get-not-set", test_bit_string_get_not_set);
	g_test_add_func ("/asn1/bit-string/invalid-length", test_bit_string_invalid_length);
	g_test_add_func ("/asn1/bit-string/invalid-empty", test_bit_string_invalid_empty);
	g_test_add_func ("/asn1/oid", test_oid);
	g_test_add_func ("/asn1/oid/set-invalid", test_oid_set_invalid);
	g_test_add_func ("/asn1/oid/get-no-value", test_oid_get_no_value);
	g_test_add_func ("/asn1/oid/decode-bad", test_oid_decode_bad);
	g_test_add_func ("/asn1/have", test_have);
	g_test_add_func ("/asn1/any-raw", test_any_raw);
	g_test_add_func ("/asn1/any-raw/explicit", test_any_raw_explicit);
	g_test_add_func ("/asn1/any-raw/invalid", test_any_raw_invalid);
	g_test_add_func ("/asn1/any-raw/not-set", test_any_raw_not_set);
	g_test_add_func ("/asn1/any-into", test_any_into);
	g_test_add_func ("/asn1/any-into/explicit", test_any_into_explicit);
	g_test_add_func ("/asn1/any-into/explicit-not-set", test_any_into_explicit_not_set);
	g_test_add_func ("/asn1/choice_not_chosen", test_choice_not_chosen);
	g_test_add_func ("/asn1/any_choice_set_raw_short_tag", test_any_choice_set_raw_short_tag);
	g_test_add_func ("/asn1/any_choice_set_raw_long_tag", test_any_choice_set_raw_long_tag);
	g_test_add_func ("/asn1/seq-of-any", test_seq_of_any);\
	g_test_add_func ("/asn1/seq-of-invalid", test_seq_of_invalid);
	g_test_add_func ("/asn1/seq-of-different", test_seq_of_different);
	g_test_add_func ("/asn1/set-order", test_set_order);
	g_test_add_func ("/asn1/append", test_append);
	g_test_add_func ("/asn1/append_and_clear", test_append_and_clear);
	g_test_add_func ("/asn1/setof", test_setof);
	g_test_add_func ("/asn1/setof_empty", test_setof_empty);
	g_test_add_func ("/asn1/enumerated", test_enumerated);
	g_test_add_func ("/asn1/enumerated-bad", test_enumerated_decode_bad);
	g_test_add_func ("/asn1/enumerated-not-in-list", test_enumerated_not_in_list);
	g_test_add_func ("/asn1/enumerated-not-set", test_enumerated_not_set);
	g_test_add_func ("/asn1/nested-fails-with-extra", test_nested_fails_with_extra);
	g_test_add_func ("/asn1/nested-unexpected", test_nested_unexpected);
	g_test_add_func ("/asn1/create-and-decode-invalid", test_create_and_decode_invalid);
	g_test_add_func ("/asn1/create-quark", test_create_quark);
	g_test_add_func ("/asn1/validate-default", test_validate_default);
	g_test_add_func ("/asn1/validate-missing", test_validate_missing);
	g_test_add_func ("/asn1/validate-seq-of-child-invalid", test_validate_seq_of_child_invalid);
	g_test_add_func ("/asn1/validate-optional-seq", test_validate_optional_seq);
	g_test_add_func ("/asn1/get-element/not-set", test_element_get_not_set);
	g_test_add ("/asn1/node_name", Test, NULL, setup, test_node_name, teardown);
	g_test_add ("/asn1/asn1_integers", Test, NULL, setup, test_asn1_integers, teardown);
	g_test_add ("/asn1/boolean_seq", Test, NULL, setup, test_boolean_seq, teardown);
	g_test_add ("/asn1/write_value", Test, NULL, setup, test_write_value, teardown);
	g_test_add ("/asn1/element_length_content", Test, NULL, setup, test_element_length_content, teardown);
	g_test_add ("/asn1/read_element", Test, NULL, setup, test_read_element, teardown);
	g_test_add ("/asn1/general_time", Test, NULL, setup, test_general_time, teardown);
	g_test_add ("/asn1/utc_time", Test, NULL, setup, test_utc_time, teardown);
	g_test_add ("/asn1/read_time", Test, NULL, setup, test_read_time, teardown);
	g_test_add ("/asn1/read_date", Test, NULL, setup, test_read_date, teardown);
	g_test_add ("/asn1/create_by_oid", Test, NULL, setup, test_create_by_oid, teardown);
	g_test_add ("/asn1/create_by_oid_invalid", Test, NULL, setup, test_create_by_oid_invalid, teardown);
	g_test_add ("/asn1/create_by_bad_order", Test, NULL, setup, test_create_by_bad_order, teardown);
	g_test_add ("/asn1/count", Test, NULL, setup, test_count, teardown);

	return g_test_run ();
}
