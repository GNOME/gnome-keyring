/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-armor.c: Test PEM and Armor parsing

   Copyright (C) 2012 Red Hat Inc.

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

   Author: Stef Walter <stefw@gnome.org>
*/

#include "config.h"

#include "egg/egg-armor.h"
#include "egg/egg-symkey.h"
#include "egg/egg-openssl.h"
#include "egg/egg-secure-memory.h"
#include "egg/egg-testing.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

static void
on_pem_get_contents (GQuark type,
                     GBytes *data,
                     GBytes *outer,
                     GHashTable *headers,
                     gpointer user_data)
{
	GBytes **contents = user_data;

	g_assert_cmpstr (g_quark_to_string (type), ==, "TEST");
	g_assert (*contents == NULL);
	*contents = g_bytes_ref (data);
}


static void
test_armor_parse (void)
{
	const char *pem_data = "-----BEGIN TEST-----\n"
	                       "Z29vZCBtb3JuaW5nIGV2ZXJ5b25lCg==\n"
	                       "-----END TEST-----\n";

	GBytes *contents = NULL;
	GBytes *check;
	GBytes *bytes;
	guint num;

	bytes = g_bytes_new_static (pem_data, strlen (pem_data));

	num = egg_armor_parse (bytes, on_pem_get_contents, &contents);
	g_assert_cmpint (num, ==, 1);
	g_assert (contents != NULL);

	check = g_bytes_new ("good morning everyone\n", 22);
	g_assert (g_bytes_equal (check, contents));

	g_bytes_unref (check);
	g_bytes_unref (contents);
	g_bytes_unref (bytes);
}

static void
test_armor_skip_checksum (void)
{
	const char *pem_data = "-----BEGIN TEST-----\n"
	                       "Z29vZCBtb3JuaW5nIGV2ZXJ5b25lCg==\n"
	                       "=checksum"
	                       "-----END TEST-----\n";

	GBytes *contents = NULL;
	GBytes *check;
	GBytes *bytes;
	guint num;

	/* Check that the (above invalid) OpenPGP checksum is skipped */

	bytes = g_bytes_new_static (pem_data, strlen (pem_data));

	num = egg_armor_parse (bytes, on_pem_get_contents, &contents);
	g_assert_cmpint (num, ==, 1);
	g_assert (contents != NULL);

	check = g_bytes_new ("good morning everyone\n", 22);
	g_assert (g_bytes_equal (check, contents));

	g_bytes_unref (check);
	g_bytes_unref (contents);
	g_bytes_unref (bytes);
}

static void
test_invalid (gconstpointer data)
{
	GBytes *bytes;
	guint num;

	/* Invalid opening line above */

	bytes = g_bytes_new_static (data, strlen (data));

	num = egg_armor_parse (bytes, NULL, NULL);
	g_assert_cmpint (num, ==, 0);

	g_bytes_unref (bytes);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/armor/parse", test_armor_parse);
	g_test_add_func ("/armor/skip-checksum", test_armor_skip_checksum);

	g_test_add_data_func ("/armor/invalid-start",
	                      "-----BEGIN TEST--",
	                      test_invalid);
	g_test_add_data_func ("/armor/invalid-end",
	                      "-----BEGIN TEST-----\n"
	                      "Z29vZCBtb3JuaW5nIGV2ZXJ5b25lCg==\n"
	                      "--END TEST-----\n",
	                      test_invalid);
	g_test_add_data_func ("/armor/invalid-mismatch",
	                      "-----BEGIN TEST-----\n"
	                      "Z29vZCBtb3JuaW5nIGV2ZXJ5b25lCg==\n"
	                      "-----END CERTIFICATE-----\n",
	                      test_invalid);
	g_test_add_data_func ("/armor/invalid-suffix",
	                      "-----BEGIN TEST-----\n"
	                      "Z29vZCBtb3JuaW5nIGV2ZXJ5b25lCg==\n"
	                      "-----END TEST--xxxxxxxx\n",
	                      test_invalid);
	g_test_add_data_func ("/armor/invalid-truncated",
	                      "-----BEGIN TEST-----\n"
	                      "Z29vZCBtb3JuaW5nIGV2ZXJ5b25lCg==\n"
	                      "-----END TEST--\n",
	                      test_invalid);

	return g_test_run ();
}
