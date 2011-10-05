/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2010 Collabora Ltd

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
#define GCR_COMPILATION 1

#include "gcr/gcr-base.h"
#include "gcr/gcr-internal.h"
#include "gcr/gcr-fingerprint.h"

#include "gck/gck-test.h"

#include "pkcs11/pkcs11n.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"
#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>

typedef struct {
	gpointer cert_rsa;
	gsize n_cert_rsa;
	gpointer key_rsa;
	gsize n_key_rsa;
	gpointer cert_dsa;
	gsize n_cert_dsa;
	gpointer key_dsa;
	gsize n_key_dsa;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	GError *error = NULL;

	g_file_get_contents (SRCDIR "/files/client.crt", (gchar**)&test->cert_rsa,
	                     &test->n_cert_rsa, &error);
	g_assert_no_error (error);
	g_assert (test->cert_rsa);

	g_file_get_contents (SRCDIR "/files/client.key", (gchar**)&test->key_rsa,
	                     &test->n_key_rsa, &error);
	g_assert_no_error (error);
	g_assert (test->key_rsa);

	g_file_get_contents (SRCDIR "/files/generic-dsa.crt", (gchar**)&test->cert_dsa,
	                     &test->n_cert_dsa, &error);
	g_assert_no_error (error);
	g_assert (test->cert_dsa);

	g_file_get_contents (SRCDIR "/files/generic-dsa.key", (gchar**)&test->key_dsa,
	                     &test->n_key_dsa, &error);
	g_assert_no_error (error);
	g_assert (test->key_dsa);
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_free (test->cert_rsa);
	g_free (test->key_rsa);
	g_free (test->cert_dsa);
	g_free (test->key_dsa);
}

static void
on_parser_parsed (GcrParser *parser,
                  gpointer user_data)
{
	GckAttributes **attrs = user_data;
	g_assert (!*attrs);
	*attrs = gcr_parser_get_parsed_attributes (parser);
	g_assert (*attrs);
	gck_attributes_ref (*attrs);
}

static GckAttributes*
parse_attributes_for_key (gpointer data, gsize n_data)
{
	GcrParser *parser;
	GckAttributes *attrs = NULL;
	GError *error = NULL;

	parser = gcr_parser_new ();
	g_signal_connect (parser, "parsed", G_CALLBACK (on_parser_parsed), &attrs);
	gcr_parser_parse_data (parser, data, n_data, &error);
	g_assert_no_error (error);
	g_object_unref (parser);

	g_assert (attrs);
	return attrs;
}

static GckAttributes *
build_attributes_for_cert (guchar *data,
                           gsize n_data)
{
	GckAttributes *attrs;

	attrs = gck_attributes_new ();
	gck_attributes_add_data (attrs, CKA_VALUE, data, n_data);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_CERTIFICATE);
	gck_attributes_add_ulong (attrs, CKA_CERTIFICATE_TYPE, CKC_X_509);

	return attrs;
}

static gconstpointer
parse_subject_public_key_info_for_cert (gpointer data, gsize n_data, gsize *n_info)
{
	gconstpointer info;
	GNode *asn;

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate", data, n_data);
	g_assert (asn);

	info = egg_asn1x_get_raw_element (egg_asn1x_node (asn, "tbsCertificate", "subjectPublicKeyInfo", NULL), n_info);
	g_assert (info);

	egg_asn1x_destroy (asn);
	return info;
}

static void
test_rsa (Test *test, gconstpointer unused)
{
	GckAttributes *key, *cert;
	gconstpointer info;
	gsize n_info;
	guchar *fingerprint1, *fingerprint2, *fingerprint3;
	gsize n_fingerprint1, n_fingerprint2, n_fingerprint3;

	key = parse_attributes_for_key (test->key_rsa, test->n_key_rsa);
	info = parse_subject_public_key_info_for_cert (test->cert_rsa, test->n_cert_rsa, &n_info);
	cert = build_attributes_for_cert (test->cert_rsa, test->n_cert_rsa);

	fingerprint1 = gcr_fingerprint_from_subject_public_key_info (info, n_info, G_CHECKSUM_SHA1, &n_fingerprint1);
	fingerprint2 = gcr_fingerprint_from_attributes (key, G_CHECKSUM_SHA1, &n_fingerprint2);
	fingerprint3 = gcr_fingerprint_from_attributes (cert, G_CHECKSUM_SHA1, &n_fingerprint3);

	egg_assert_cmpmem (fingerprint1, n_fingerprint1, ==, fingerprint2, n_fingerprint2);
	egg_assert_cmpmem (fingerprint1, n_fingerprint1, ==, fingerprint3, n_fingerprint3);

	g_free (fingerprint1);
	g_free (fingerprint2);
	g_free (fingerprint3);

	gck_attributes_unref (key);
	gck_attributes_unref (cert);
}

static void
test_dsa (Test *test, gconstpointer unused)
{
	GckAttributes *key, *cert;
	gconstpointer info;
	gsize n_info;
	guchar *fingerprint1, *fingerprint2, *fingerprint3;
	gsize n_fingerprint1, n_fingerprint2, n_fingerprint3;

	key = parse_attributes_for_key (test->key_dsa, test->n_key_dsa);
	info = parse_subject_public_key_info_for_cert (test->cert_dsa, test->n_cert_dsa, &n_info);
	cert = build_attributes_for_cert (test->cert_dsa, test->n_cert_dsa);

	fingerprint1 = gcr_fingerprint_from_subject_public_key_info (info, n_info, G_CHECKSUM_SHA1, &n_fingerprint1);
	fingerprint2 = gcr_fingerprint_from_attributes (key, G_CHECKSUM_SHA1, &n_fingerprint2);
	fingerprint3 = gcr_fingerprint_from_attributes (cert, G_CHECKSUM_SHA1, &n_fingerprint3);

	egg_assert_cmpmem (fingerprint1, n_fingerprint1, ==, fingerprint2, n_fingerprint2);
	egg_assert_cmpmem (fingerprint1, n_fingerprint1, ==, fingerprint3, n_fingerprint3);

	g_free (fingerprint1);
	g_free (fingerprint2);
	g_free (fingerprint3);

	gck_attributes_unref (key);
	gck_attributes_unref (cert);
}

int
main (int argc, char **argv)
{
	g_type_init ();
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/gcr/fingerprint/rsa", Test, NULL, setup, test_rsa, teardown);
	g_test_add ("/gcr/fingerprint/dsa", Test, NULL, setup, test_dsa, teardown);

	return g_test_run ();
}
