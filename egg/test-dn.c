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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "egg/egg-asn1-defs.h"
#include "egg/egg-asn1x.h"
#include "egg/egg-dn.h"
#include "egg/egg-oid.h"
#include "egg/egg-testing.h"

#include <glib.h>
#include <gcrypt.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
	GNode* asn1;
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
test_read_dn (Test* test, gconstpointer unused)
{
	gchar *dn;

	dn = egg_dn_read (egg_asn1x_node (test->asn1, "tbsCertificate", "issuer", "rdnSequence", NULL));
	g_assert (dn != NULL);
	g_assert_cmpstr (dn, ==, "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting, OU=Certification Services Division, CN=Thawte Personal Premium CA, EMAIL=personal-premium@thawte.com");

	g_free (dn);
}

static void
test_dn_value (Test* test, gconstpointer unused)
{
	const guchar value[] = { 0x13, 0x1a, 0x54, 0x68, 0x61, 0x77, 0x74, 0x65, 0x20, 0x50, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x50, 0x72, 0x65, 0x6d, 0x69, 0x75, 0x6d, 0x20, 0x43, 0x41 };
	gsize n_value = 28;
	GBytes *bytes;
	GNode *asn;
	GQuark oid;
	gchar *text;

	bytes = g_bytes_new_static (value, n_value);

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "AttributeValue", bytes);
	g_assert (asn != NULL);

	/* Some printable strings */
	oid = g_quark_from_static_string ("2.5.4.3");
	text = egg_dn_print_value (oid, asn);
	g_assert_cmpstr (text, ==, "Thawte Personal Premium CA");
	g_free (text);
	g_bytes_unref (bytes);

	/* Unknown oid */
	oid = g_quark_from_static_string ("1.1.1.1.1.1");
	bytes = g_bytes_new_static (value, n_value);
	text = egg_dn_print_value (oid, asn);
	g_assert_cmpstr (text, ==, "#131A54686177746520506572736F6E616C205072656D69756D204341");
	g_free (text);

	egg_asn1x_destroy (asn);
	g_bytes_unref (bytes);
}

static int last_index = 0;

static void
concatenate_dn (guint index,
                GQuark oid,
                GNode *value,
                gpointer user_data)
{
	GString *dn = user_data;
	gchar *text;

	g_assert (oid);
	g_assert (value != NULL);

	g_assert (index == last_index);
	++last_index;

	if (index != 1) {
		g_string_append (dn, ", ");
	}

	g_string_append (dn, egg_oid_get_name (oid));
	g_string_append_c (dn, '=');

	text = egg_dn_print_value (oid, value);
	g_string_append (dn, text);
	g_free (text);
}

static void
test_parse_dn (Test* test, gconstpointer unused)
{
	GString *dn = g_string_new ("");
	last_index = 1;

	if (!egg_dn_parse (egg_asn1x_node (test->asn1, "tbsCertificate", "issuer", "rdnSequence", NULL), concatenate_dn, dn))
		g_assert_not_reached ();

	g_assert_cmpstr (dn->str, ==, "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting, OU=Certification Services Division, CN=Thawte Personal Premium CA, EMAIL=personal-premium@thawte.com");
	g_string_free (dn, TRUE);
}

static void
test_read_dn_part (Test* test, gconstpointer unused)
{
	GNode *node;
	gchar *value;

	node = egg_asn1x_node (test->asn1, "tbsCertificate", "issuer", "rdnSequence", NULL);

	value = egg_dn_read_part (node, "CN");
	g_assert (value != NULL);
	g_assert_cmpstr (value, ==, "Thawte Personal Premium CA");
	g_free (value);

	value = egg_dn_read_part (node, "2.5.4.8");
	g_assert (value != NULL);
	g_assert_cmpstr (value, ==, "Western Cape");
	g_free (value);

	value = egg_dn_read_part (node, "DC");
	g_assert (value == NULL);

	value = egg_dn_read_part (node, "0.0.0.0");
	g_assert (value == NULL);

	value = egg_dn_read_part (node, "2.5.4.9");
	g_assert (value == NULL);
}

static void
test_add_dn_part (Test *test,
                  gconstpointer unused)
{
	GBytes *check;
	GBytes *dn;
	GNode *check_dn;
	GNode *asn;
	GNode *node;

	asn = egg_asn1x_create (pkix_asn1_tab, "Name");
	node = egg_asn1x_node (asn, "rdnSequence", NULL);
	egg_asn1x_set_choice (asn, node);
	egg_dn_add_string_part (node, g_quark_from_static_string ("2.5.4.6"), "ZA");
	egg_dn_add_string_part (node, g_quark_from_static_string ("2.5.4.8"), "Western Cape");
	egg_dn_add_string_part (node, g_quark_from_static_string ("2.5.4.7"), "Cape Town");
	egg_dn_add_string_part (node, g_quark_from_static_string ("2.5.4.10"), "Thawte Consulting");
	egg_dn_add_string_part (node, g_quark_from_static_string ("2.5.4.11"), "Certification Services Division");
	egg_dn_add_string_part (node, g_quark_from_static_string ("2.5.4.3"), "Thawte Personal Premium CA");
	egg_dn_add_string_part (node, g_quark_from_static_string ("1.2.840.113549.1.9.1"), "personal-premium@thawte.com");

	dn = egg_asn1x_encode (asn, NULL);
	if (dn == NULL) {
		g_warning ("couldn't encode dn: %s", egg_asn1x_message (asn));
		g_assert_not_reached ();
	}

	check_dn = egg_asn1x_node (test->asn1, "tbsCertificate", "issuer", "rdnSequence", NULL);
	check = egg_asn1x_encode (check_dn, NULL);
	egg_asn1x_destroy (asn);

	egg_assert_cmpbytes (dn, ==, g_bytes_get_data (check, NULL), g_bytes_get_size (check));

	g_bytes_unref (dn);
	g_bytes_unref (check);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/dn/read_dn", Test, NULL, setup, test_read_dn, teardown);
	g_test_add ("/dn/dn_value", Test, NULL, setup, test_dn_value, teardown);
	g_test_add ("/dn/parse_dn", Test, NULL, setup, test_parse_dn, teardown);
	g_test_add ("/dn/read_dn_part", Test, NULL, setup, test_read_dn_part, teardown);
	g_test_add ("/dn/add_dn_part", Test, NULL, setup, test_add_dn_part, teardown);

	return g_test_run ();
}
