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

#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#if 0
#include <libtasn1.h>
static void
build_personal_name (void)
{
	ASN1_TYPE asn1_pkix = NULL, asn;
	guchar buffer[10024];
	int res, len;

	res = asn1_array2tree ((ASN1_ARRAY_TYPE*)pkix_asn1_tab, &asn1_pkix, NULL);
	g_assert (res == ASN1_SUCCESS);

	res = asn1_create_element (asn1_pkix, "PKIX1.PersonalName", &asn);
	g_assert (res == ASN1_SUCCESS);

	asn1_write_value (asn, "surname", "Turanga", 7);
	asn1_write_value (asn, "given-name", "Leela", 5);
	asn1_write_value (asn, "initials", NULL, 0);
	asn1_write_value (asn, "generation-qualifier", "II", 2);

	len = sizeof (buffer);
	res = asn1_der_coding (asn, "", buffer, &len, NULL);
	g_assert (res == ASN1_SUCCESS);

	asn1_delete_structure (&asn);
	asn1_delete_structure (&asn1_pkix);

	if (!g_file_set_contents ("/tmp/personal-name.der", (gchar*)buffer, len, NULL))
		g_assert (FALSE);

}
#endif

typedef struct {
	GBytes *data;
} Test;

typedef struct {
	const EggAsn1xDef *defs;
	const gchar *filename;
	const gchar *identifier;
} Fixture;

static const Fixture parse_test_fixtures[] = {
	{ pkix_asn1_tab, SRCDIR "/egg/fixtures/test-certificate-1.der", "Certificate" },
	{ pkix_asn1_tab, SRCDIR "/egg/fixtures/test-pkcs8-1.der", "pkcs-8-PrivateKeyInfo" },
	{ pk_asn1_tab, SRCDIR "/egg/fixtures/test-rsakey-1.der", "RSAPrivateKey" },
	{ pkix_asn1_tab, SRCDIR "/egg/fixtures/test-pkcs7-1.der", "pkcs-7-ContentInfo" },
	{ pkix_asn1_tab, SRCDIR "/egg/fixtures/test-pkcs7-2.der", "pkcs-7-ContentInfo" },
};

static void
setup (Test *test,
       gconstpointer data)
{
	const gchar *filename = data;
	GError *error = NULL;
	gchar *contents;
	gsize length;

	g_file_get_contents (filename, (gchar**)&contents, &length, &error);
	g_assert_no_error (error);

	test->data = g_bytes_new_take (contents, length);
}

static void
setup_parsing (Test *test,
               gconstpointer data)
{
	const Fixture *fixture = data;
	setup (test, fixture->filename);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	g_bytes_unref (test->data);
}

static void
test_decode_encode (Test *test,
                    gconstpointer data)
{
	const Fixture *fixture = data;
	GNode *asn;
	GBytes *encoded;
	gboolean ret;

	asn = egg_asn1x_create (fixture->defs, fixture->identifier);

	if (g_test_verbose ())
		egg_asn1x_dump (asn);

	ret = egg_asn1x_decode (asn, test->data);
	egg_asn1x_assert (ret == TRUE, asn);

	encoded = egg_asn1x_encode (asn, NULL);
	egg_asn1x_assert (encoded != NULL, asn);

	/* Decode the encoding */
	ret = egg_asn1x_decode (asn, encoded);
	egg_asn1x_assert (ret == TRUE, asn);

	egg_asn1x_clear (asn);
	egg_asn1x_destroy (asn);
	g_bytes_unref (encoded);
}

static void
test_personal_name_invalid (Test *test,
                            gconstpointer unused)
{
	GNode *asn;
	gboolean ret;

	asn = egg_asn1x_create (pkix_asn1_tab, "PersonalName");

	if (g_test_verbose ())
		egg_asn1x_dump (asn);

	ret = egg_asn1x_decode (asn, test->data);
	g_assert (ret == FALSE);
	g_assert (strstr (egg_asn1x_message (asn), "content size is out of bounds") != NULL);

	egg_asn1x_destroy (asn);
}

static void
test_pkcs12_decode (Test *test,
                    gconstpointer unused)
{
	GNode *asn;
	gboolean ret;

	asn = egg_asn1x_create (pkix_asn1_tab, "pkcs-12-PFX");

	if (g_test_verbose ())
		egg_asn1x_dump (asn);

	ret = egg_asn1x_decode (asn, test->data);
	egg_asn1x_assert (ret == TRUE, asn);

	egg_asn1x_destroy (asn);
}

int
main (int argc, char **argv)
{
	gchar *name;
	gint i;

	g_test_init (&argc, &argv, NULL);

	for (i = 0; i < G_N_ELEMENTS (parse_test_fixtures); i++) {
		name = g_strdup_printf ("/asn1x/encode-decode-%d-%s", i, parse_test_fixtures[i].identifier);
		g_test_add (name, Test, &parse_test_fixtures[i], setup_parsing, test_decode_encode, teardown);
		g_free (name);
	}

	g_test_add ("/asn1x/pkcs12-decode/1", Test, SRCDIR "/egg/fixtures/test-pkcs12-1.der",
	            setup, test_pkcs12_decode, teardown);
	g_test_add ("/asn1x/pkcs5-personal-name/invalid", Test, SRCDIR "/egg/fixtures/test-personalname-invalid.der",
	            setup, test_personal_name_invalid, teardown);

	return g_test_run ();
}
