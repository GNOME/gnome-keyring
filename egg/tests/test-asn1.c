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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "test-suite.h"

#include "egg/egg-asn1x.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "asn1-def-tests.h"

const gchar I33[] =           "\x02\x01\x2A";
const gchar BFALSE[] =        "\x01\x01\x00";
const gchar BTRUE[] =         "\x01\x01\xFF";
const gchar SFARNSWORTH[] =   "\x04\x0A""farnsworth";
const gchar SIMPLICIT[] =     "\x85\x08""implicit";
const gchar SEXPLICIT[] =     "\xE5\x0A\x04\x08""explicit";
const gchar TGENERALIZED[] =  "\x18\x0F""20070725130528Z";

#define XL(x) G_N_ELEMENTS (x) - 1

DEFINE_TEST(asn1_boolean)
{
	GNode *asn;
	gboolean value;

	asn = egg_asn1x_create (tests_asn1_tab, "TestBoolean");
	g_assert (asn);

	/* Shouldn't succeed */
	if (egg_asn1x_get_boolean (asn, &value))
		g_assert_not_reached ();

	/* Decode a false */
	if (!egg_asn1x_decode (asn, BFALSE, XL (BFALSE)))
		g_assert_not_reached ();
	value = TRUE;
	if (!egg_asn1x_get_boolean (asn, &value))
		g_assert_not_reached ();
	g_assert (value == FALSE);

	/* Decode a true */
	if (!egg_asn1x_decode (asn, BTRUE, XL (BTRUE)))
		g_assert_not_reached ();
	value = FALSE;
	if (!egg_asn1x_get_boolean (asn, &value))
		g_assert_not_reached ();
	g_assert (value == TRUE);

	egg_asn1x_clear (asn);

	/* Shouldn't suceed after clear */
	if (egg_asn1x_get_boolean (asn, &value))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
}

DEFINE_TEST(asn1_integer)
{
	GNode *asn;
	gulong value;

	asn = egg_asn1x_create (tests_asn1_tab, "TestInteger");
	g_assert (asn);

	/* Shouldn't succeed */
	if (egg_asn1x_get_integer_as_ulong (asn, &value))
		g_assert_not_reached ();

	/* Should suceed now */
	if (!egg_asn1x_decode (asn, I33, XL (I33)))
		g_assert_not_reached ();
	if (!egg_asn1x_get_integer_as_ulong (asn, &value))
		g_assert_not_reached ();
	g_assert (value == 42);

	egg_asn1x_clear (asn);

	/* Shouldn't suceed after clear */
	if (egg_asn1x_get_integer_as_ulong (asn, &value))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
}

DEFINE_TEST(asn1_octet_string)
{
	GNode *asn;
	gchar *value;

	asn = egg_asn1x_create (tests_asn1_tab, "TestOctetString");
	g_assert (asn);

	/* Shouldn't succeed */
	if (egg_asn1x_get_string_as_utf8 (asn, NULL))
		g_assert_not_reached ();

	/* Should work */
	if (!egg_asn1x_decode (asn, SFARNSWORTH, XL (SFARNSWORTH)))
		g_assert_not_reached ();
	value = egg_asn1x_get_string_as_utf8 (asn, NULL);
	g_assert_cmpstr (value, ==, "farnsworth");
	g_free (value);

	egg_asn1x_clear (asn);

	/* Shouldn't succeed */
	if (egg_asn1x_get_string_as_utf8 (asn, NULL))
		g_assert_not_reached ();

	egg_asn1x_destroy (asn);
}

DEFINE_TEST(asn1_generalized_time)
{
	GNode *asn;
	glong value;

	asn = egg_asn1x_create (tests_asn1_tab, "TestGeneralized");
	g_assert (asn);

	/* Shouldn't succeed */
	value = egg_asn1x_get_time_as_long (asn);
	g_assert (value == -1);

	/* Should work */
	if (!egg_asn1x_decode (asn, TGENERALIZED, XL (TGENERALIZED)))
		g_assert_not_reached ();
	value = egg_asn1x_get_time_as_long (asn);
	g_assert (value == 1185368728);

	egg_asn1x_clear (asn);

	/* Shouldn't succeed */
	value = egg_asn1x_get_time_as_long (asn);
	g_assert (value == -1);

	egg_asn1x_destroy (asn);
}

DEFINE_TEST(asn1_implicit)
{
	GNode *asn;
	gchar *value;

	asn = egg_asn1x_create (tests_asn1_tab, "TestImplicit");
	g_assert (asn);

	/* Should work */
	if (!egg_asn1x_decode (asn, SIMPLICIT, XL (SIMPLICIT)))
		g_assert_not_reached ();
	value = egg_asn1x_get_string_as_utf8 (asn, NULL);
	g_assert_cmpstr (value, ==, "implicit");
	g_free (value);

	egg_asn1x_destroy (asn);
}

DEFINE_TEST(asn1_explicit)
{
	GNode *asn;
	gchar *value;

	asn = egg_asn1x_create (tests_asn1_tab, "TestExplicit");
	g_assert (asn);

	/* Should work */
	if (!egg_asn1x_decode (asn, SEXPLICIT, XL (SEXPLICIT)))
		g_assert_not_reached ();
	value = egg_asn1x_get_string_as_utf8 (asn, NULL);
	g_assert_cmpstr (value, ==, "explicit");
	g_free (value);

	egg_asn1x_destroy (asn);
}
