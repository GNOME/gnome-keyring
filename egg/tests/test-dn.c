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

#include "test-suite.h"

#include "egg/egg-asn1.h"
#include "egg/egg-dn.h"
#include "egg/egg-oid.h"

#include <glib.h>
#include <gcrypt.h>
#include <libtasn1.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static ASN1_TYPE asn1_cert = NULL;
static guchar *data_cert = NULL;
static gsize n_data_cert = 0;

DEFINE_SETUP(dn_cert)
{
	ASN1_TYPE pkix;
	int res;

	data_cert = testing_data_read ("test-certificate-1.der", &n_data_cert);

	/* We'll be catching this error later */
	pkix = egg_asn1_get_pkix_asn1type ();
	if (!pkix) return;

	res = asn1_create_element (pkix, "PKIX1.Certificate", &asn1_cert);
	g_assert (res == ASN1_SUCCESS);

	res = asn1_der_decoding (&asn1_cert, data_cert, n_data_cert, NULL);
	g_assert (res == ASN1_SUCCESS);
}

DEFINE_TEARDOWN(dn_cert)
{
	asn1_delete_structure (&asn1_cert);
	g_free (data_cert);
	data_cert = NULL;
}

DEFINE_TEST(read_dn)
{
	gchar *dn;

	dn = egg_dn_read (asn1_cert, "tbsCertificate.issuer.rdnSequence");
	g_assert (dn != NULL);
	g_assert_cmpstr (dn, ==, "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting, OU=Certification Services Division, CN=Thawte Personal Premium CA, EMAIL=personal-premium@thawte.com");

	g_free (dn);

	dn = egg_dn_read (asn1_cert, "tbsCertificate.nonExistant");
	g_assert (dn == NULL);
}

DEFINE_TEST(dn_value)
{
	const guchar value[] = { 0x13, 0x1a, 0x54, 0x68, 0x61, 0x77, 0x74, 0x65, 0x20, 0x50, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x50, 0x72, 0x65, 0x6d, 0x69, 0x75, 0x6d, 0x20, 0x43, 0x41 };
	gsize n_value = 28;
	GQuark oid;
	gchar *text;

	/* Some printable strings */
	oid = g_quark_from_static_string ("2.5.4.3");
	text = egg_dn_print_value (oid, value, n_value);
	g_assert_cmpstr (text, ==, "Thawte Personal Premium CA");
	g_free (text);

	/* Unknown oid */
	oid = g_quark_from_static_string ("1.1.1.1.1.1");
	text = egg_dn_print_value (oid, value, n_value);
	g_assert_cmpstr (text, ==, "#131A54686177746520506572736F6E616C205072656D69756D204341");
	g_free (text);
}

static int last_index = 0;

static void
concatenate_dn (guint index, GQuark oid, const guchar *value, gsize n_value, gpointer user_data)
{
	GString *dn = user_data;
	gchar *text;

	g_assert (oid);
	g_assert (value);
	g_assert (n_value);

	g_assert (index == last_index);
	++last_index;

	if (index != 1) {
		g_string_append (dn, ", ");
	}

	g_string_append (dn, egg_oid_get_name (oid));
	g_string_append_c (dn, '=');

	text = egg_dn_print_value (oid, value, n_value);
	g_string_append (dn, text);
	g_free (text);
}

DEFINE_TEST(parse_dn)
{
	GString *dn = g_string_new ("");
	last_index = 1;

	if (!egg_dn_parse (asn1_cert, "tbsCertificate.issuer.rdnSequence", concatenate_dn, dn))
		g_assert_not_reached ();

	g_assert_cmpstr (dn->str, ==, "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting, OU=Certification Services Division, CN=Thawte Personal Premium CA, EMAIL=personal-premium@thawte.com");
	g_string_free (dn, TRUE);
}

DEFINE_TEST(read_dn_part)
{
	gchar *value;

	value = egg_dn_read_part (asn1_cert, "tbsCertificate.issuer.rdnSequence", "CN");
	g_assert (value != NULL);
	g_assert_cmpstr (value, ==, "Thawte Personal Premium CA");
	g_free (value);

	value = egg_dn_read_part (asn1_cert, "tbsCertificate.issuer.rdnSequence", "2.5.4.8");
	g_assert (value != NULL);
	g_assert_cmpstr (value, ==, "Western Cape");
	g_free (value);

	value = egg_dn_read_part (asn1_cert, "tbsCertificate.nonExistant", "CN");
	g_assert (value == NULL);

	value = egg_dn_read_part (asn1_cert, "tbsCertificate.issuer.rdnSequence", "DC");
	g_assert (value == NULL);

	value = egg_dn_read_part (asn1_cert, "tbsCertificate.issuer.rdnSequence", "0.0.0.0");
	g_assert (value == NULL);

	value = egg_dn_read_part (asn1_cert, "tbsCertificate.issuer.rdnSequence", "2.5.4.9");
	g_assert (value == NULL);
}
