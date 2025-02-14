/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-openssl.c: Test openssl

   Copyright (C) 2008 Stefan Walter

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

typedef struct {
	GBytes *input;
	GQuark reftype;
	guchar *refenc;
	guchar *refdata;
	gsize n_refenc;
	gsize n_refdata;
	GHashTable *refheaders;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	gchar *contents;
	gsize length;

	if (!g_file_get_contents (SRCDIR "/egg/fixtures/pem-rsa-enc.key", &contents, &length, NULL))
		g_assert_not_reached ();

	test->input = g_bytes_new_take (contents, length);
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_bytes_unref (test->input);
	g_free (test->refenc);
	egg_secure_free (test->refdata);
	g_hash_table_destroy (test->refheaders);
}

static void
copy_each_key_value (gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_insert ((GHashTable*)user_data, g_strdup ((gchar*)key), g_strdup ((gchar*)value));
}

static void
parse_reference (GQuark type,
                 GBytes *data,
                 GBytes *outer,
                 GHashTable *headers,
                 gpointer user_data)
{
	Test *test = user_data;
	const gchar *dekinfo;

	g_assert (type);
	test->reftype = type;

	g_assert ("no data in PEM callback" && data != NULL);
	g_assert ("no data in PEM callback" && g_bytes_get_size (data) > 0);
	test->refenc = g_memdup2 (g_bytes_get_data (data, NULL), g_bytes_get_size (data));
	test->n_refenc = g_bytes_get_size (data);

	g_assert ("no headers present in file" && headers != NULL);
	g_assert (!test->refheaders);
	test->refheaders = egg_armor_headers_new ();
	g_hash_table_foreach (headers, copy_each_key_value, test->refheaders);
	dekinfo = egg_openssl_get_dekinfo (headers);
	g_assert ("no dekinfo in headers" && dekinfo != NULL);

	test->refdata = egg_openssl_decrypt_block (dekinfo, "booo", 4, data, &test->n_refdata);
	g_assert ("no data returned from openssl decrypt" && test->refdata != NULL);
	g_assert ("invalid amount of data returned from openssl decrypt" && test->n_refdata == g_bytes_get_size (data));
}

static void
test_parse_reference (Test *test, gconstpointer unused)
{
	guint num;

	num = egg_armor_parse (test->input, parse_reference, test);
	g_assert ("couldn't PEM block in reference data" && num == 1);

	g_assert ("parse_reference() wasn't called" && test->refdata != NULL);
}

static void
test_write_reference (Test *test, gconstpointer unused)
{
	const gchar *dekinfo;
	guchar *encrypted;
	gsize n_encrypted;
	GBytes *data;
	guint num;

	num = egg_armor_parse (test->input, parse_reference, test);
	g_assert ("couldn't PEM block in reference data" && num == 1);

	dekinfo = egg_openssl_get_dekinfo (test->refheaders);
	g_assert ("no dekinfo in headers" && dekinfo != NULL);

	data = g_bytes_new_static (test->refdata, test->n_refdata);
	encrypted = egg_openssl_encrypt_block (dekinfo, "booo", 4, data, &n_encrypted);
	g_bytes_unref (data);

	g_assert ("no data returned from openssl encrypt" && encrypted != NULL);
	g_assert ("invalid amount of data returned from openssl encrypt" && test->n_refdata <= n_encrypted);

	g_assert ("data length doesn't match input length" && n_encrypted == test->n_refenc);
	g_assert ("data doesn't match input" && memcmp (encrypted, test->refenc, n_encrypted) == 0);

	g_free (encrypted);
}

static void
test_write_exactly_same (Test *test, gconstpointer unused)
{
	guchar *result;
	gsize n_result;
	guint num;

	num = egg_armor_parse (test->input, parse_reference, test);
	g_assert ("couldn't PEM block in reference data" && num == 1);

	result = egg_armor_write (test->refenc, test->n_refenc, test->reftype,
	                          test->refheaders, &n_result);

	/*
	 * Yes sirrr. Openssl's parser is so fragile, that we have to make it
	 * character for character identical. This includes line breaks, whitespace
	 * and line endings.
	 */

	egg_assert_cmpbytes (test->input, ==, result, n_result);
	g_free (result);
}

/* 29 bytes (prime number, so block length has bad chance of matching */
static const guchar *TEST_DATA = (guchar*)"ABCDEFGHIJKLMNOPQRSTUVWXYZ123";
const gsize TEST_DATA_L = 29;

static void
test_openssl_roundtrip (Test *test, gconstpointer unused)
{
	const gchar *dekinfo;
	guchar *encrypted, *decrypted;
	gsize n_encrypted, n_decrypted;
	GBytes *data;
	int i;
	guint num;

	num = egg_armor_parse (test->input, parse_reference, test);
	g_assert ("couldn't PEM block in reference data" && num == 1);

	dekinfo = egg_openssl_prep_dekinfo (test->refheaders);

	data = g_bytes_new_static (TEST_DATA, TEST_DATA_L);
	encrypted = egg_openssl_encrypt_block (dekinfo, "password", -1, data, &n_encrypted);
	g_bytes_unref (data);

	g_assert ("no data returned from openssl encrypt" && encrypted != NULL);
	g_assert ("invalid amount of data returned from openssl encrypt" && TEST_DATA_L <= n_encrypted);

	data = g_bytes_new_with_free_func (encrypted, n_encrypted, egg_secure_free, encrypted);
	decrypted = egg_openssl_decrypt_block (dekinfo, "password", 8, data, &n_decrypted);
	g_bytes_unref (data);

	g_assert ("no data returned from openssl decrypt" && decrypted != NULL);

	/* Check that the data was decrypted properly */
	g_assert ("decrypted data doesn't match length" && n_decrypted >= TEST_DATA_L);
	g_assert ("decrypted data doesn't match" && memcmp (TEST_DATA, decrypted, TEST_DATA_L) == 0);

	/* Check that the remainder is all zeros */
	for (i = TEST_DATA_L; i < n_decrypted; ++i)
		g_assert ("non null byte in padding" && decrypted[i] == 0);

	egg_secure_free (decrypted);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/openssl/parse_reference", Test, NULL, setup, test_parse_reference, teardown);
	g_test_add ("/openssl/write_reference", Test, NULL, setup, test_write_reference, teardown);
	g_test_add ("/openssl/write_exactly_same", Test, NULL, setup, test_write_exactly_same, teardown);
	g_test_add ("/openssl/openssl_roundtrip", Test, NULL, setup, test_openssl_roundtrip, teardown);

	return g_test_run ();
}
