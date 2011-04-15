/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2011 Collabora Ltd.

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

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#include "config.h"

#include "gcr/gcr-colons.h"

#include "egg/egg-testing.h"

#include <glib.h>

typedef struct {
	GcrColons *colons;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	test->colons = _gcr_colons_parse ("one:tab\\there::four:f\xfc""nf:", -1);
}

static void
teardown (Test *test, gconstpointer unused)
{
	_gcr_colons_free (test->colons);
}

static void
test_parse (void)
{
	GcrColons *colons;

	colons = _gcr_colons_parse ("one:two::four::six", -1);
	g_assert (colons);

	g_assert_cmpstr (_gcr_colons_get_raw (colons, 0), ==, "one");
	g_assert_cmpstr (_gcr_colons_get_raw (colons, 1), ==, "two");
	g_assert_cmpstr (_gcr_colons_get_raw (colons, 2), ==, "");
	g_assert_cmpstr (_gcr_colons_get_raw (colons, 3), ==, "four");
	g_assert_cmpstr (_gcr_colons_get_raw (colons, 4), ==, "");
	g_assert_cmpstr (_gcr_colons_get_raw (colons, 5), ==, "six");
	g_assert (_gcr_colons_get_raw (colons, 6) == NULL);

	_gcr_colons_free (colons);
}

static void
test_parse_part (void)
{
	GcrColons *colons;

	colons = _gcr_colons_parse ("one:two::four::six", 8);
	g_assert (colons);

	g_assert_cmpstr (_gcr_colons_get_raw (colons, 0), ==, "one");
	g_assert_cmpstr (_gcr_colons_get_raw (colons, 1), ==, "two");
	g_assert_cmpstr (_gcr_colons_get_raw (colons, 2), ==, "");
	g_assert (_gcr_colons_get_raw (colons, 3) == NULL);

	_gcr_colons_free (colons);
}

static void
test_parse_too_long (void)
{
	GcrColons *colons;

	/* Too many columns */
	colons = _gcr_colons_parse (":::::::::::::::::::::::::::::::::::::::::::::::::::::", -1);
	g_assert (colons == NULL);
}

static void
test_find (void)
{
	GcrColons *uid, *pub, *one, *check;
	GPtrArray *dataset;

	dataset = g_ptr_array_new_with_free_func (_gcr_colons_free);

	one = _gcr_colons_parse ("one:two::four::six", -1);
	g_ptr_array_add (dataset, one);
	pub = _gcr_colons_parse ("pub:two", -1);
	g_ptr_array_add (dataset, pub);
	uid = _gcr_colons_parse ("uid:two", -1);
	g_ptr_array_add (dataset, uid);

	check = _gcr_colons_find (dataset, GCR_COLONS_SCHEMA_PUB);
	g_assert (check == pub);

	check = _gcr_colons_find (dataset, GCR_COLONS_SCHEMA_UID);
	g_assert (check == uid);

	g_ptr_array_unref (dataset);
}

static void
test_get_string (Test *test, gconstpointer unused)
{
	gchar *value = _gcr_colons_get_string (test->colons, 1);
	g_assert (value);

	g_assert_cmpstr (value, ==, "tab\there");
	g_free (value);
}

static void
test_get_string_null (Test *test, gconstpointer unused)
{
	gchar *value = _gcr_colons_get_string (test->colons, 35);
	g_assert (value == NULL);
}

static void
test_get_string_latin1 (Test *test, gconstpointer unused)
{
	gchar *value = _gcr_colons_get_string (test->colons, 4);
	g_assert (value);

	g_assert_cmpstr (value, ==, "f\xc3\xbc""nf");
	g_assert (g_utf8_validate (value, -1, NULL));
	g_free (value);
}

static void
test_free_null (void)
{
	_gcr_colons_free (NULL);
}

static void
test_get_schema (Test *test, gconstpointer unused)
{
	GQuark schema;
	GQuark check;

	/* Initialize this quark */
	check = g_quark_from_static_string ("one");

	schema = _gcr_colons_get_schema (test->colons);
	g_assert (check == schema);
	g_assert_cmpstr (g_quark_to_string (schema), ==, "one");
}

static void
test_schemas (void)
{
	GQuark check;

	check = _gcr_colons_get_schema_uid_quark ();
	g_assert_cmpstr (g_quark_to_string (check), ==, "uid");

	check = _gcr_colons_get_schema_pub_quark ();
	g_assert_cmpstr (g_quark_to_string (check), ==, "pub");
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/gcr/colons/parse", test_parse);
	g_test_add_func ("/gcr/colons/parse_part", test_parse_part);
	g_test_add_func ("/gcr/colons/parse_too_long", test_parse_too_long);
	g_test_add_func ("/gcr/colons/free_null", test_free_null);
	g_test_add_func ("/gcr/colons/schemas", test_schemas);
	g_test_add_func ("/gcr/colons/find", test_find);
	g_test_add ("/gcr/colons/get_string", Test, NULL, setup, test_get_string, teardown);
	g_test_add ("/gcr/colons/get_string_null", Test, NULL, setup, test_get_string_null, teardown);
	g_test_add ("/gcr/colons/get_string_latin1", Test, NULL, setup, test_get_string_latin1, teardown);
	g_test_add ("/gcr/colons/get_schema", Test, NULL, setup, test_get_schema, teardown);

	return g_test_run ();
}
