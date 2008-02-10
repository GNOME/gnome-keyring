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

#include "common/gkr-location.h"
#include "common/gkr-crypto.h"
#include "common/gkr-secure-memory.h"

#include "pkix/gkr-pkix-parser.h"

#include <glib.h>
#include <gcrypt.h>
#include <libtasn1.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void);
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void);
 * 
 * Tests be run in the order specified here.
 */

static GkrPkixParser *parser = NULL;

static GQuark last_type_parsed = 0;
static gcry_sexp_t last_sexp_parsed = NULL;
static ASN1_TYPE last_asn1_parsed = NULL;
static guint n_parsed = 0;

static CuTest *the_cu = NULL;

static gboolean
parsed_partial (GkrPkixParser *parser, GQuark location, gkrconstid unique, 
                GQuark type, gpointer user_data)
{
	CuTest *cu = the_cu;
	g_assert (cu);
		
	CuAssert (cu, "location is empty", location != 0);
	CuAssert (cu, "location is invalid", gkr_location_to_path (location) != NULL);
	CuAssert (cu, "unique is empty", unique != NULL);
	CuAssert (cu, "type is invalid", type != 0);
	
	g_print ("parsed partial at: %s\n", g_quark_to_string (location));
	last_sexp_parsed = NULL;
	last_type_parsed = type;
	++n_parsed;
	
	return TRUE;
}

static gboolean
parsed_sexp (GkrPkixParser *parser, GQuark location, gkrconstid unique, 
             GQuark type, gcry_sexp_t sexp, gpointer user_data)
{
	CuTest *cu = the_cu;
	g_assert (cu);

	CuAssert (cu, "location is empty", location != 0);
	CuAssert (cu, "location is invalid", gkr_location_to_path (location) != NULL);
	CuAssert (cu, "unique is empty", unique != NULL);
	CuAssert (cu, "type is invalid", type != 0);
	CuAssert (cu, "sexp is invalid", sexp != NULL);

	g_print ("parsed sexp at: %s\n", g_quark_to_string (location));
		
	last_sexp_parsed = sexp;
	last_type_parsed = type;
	++n_parsed;
	
	return TRUE;
}

static gboolean
parsed_asn1 (GkrPkixParser *parser, GQuark location, gkrconstid unique,
             GQuark type, ASN1_TYPE asn1, gpointer user_data)
{
	CuTest *cu = the_cu;
	g_assert (cu);

	CuAssert (cu, "location is empty", location != 0);
	CuAssert (cu, "location is invalid", gkr_location_to_path (location) != NULL);
	CuAssert (cu, "unique is empty", unique != NULL);
	CuAssert (cu, "type is invalid", type != 0);
	CuAssert (cu, "asn1 is invalid", asn1 != NULL);

	g_print ("parsed asn1 at: %s\n", g_quark_to_string (location));
		
	last_asn1_parsed = asn1;
	last_type_parsed = type;
	++n_parsed;
	
	return TRUE;
}

static gchar*
ask_password (GkrPkixParser *parser, GQuark loc, gkrconstid unique, 
              GQuark type, const gchar *details, guint n_prompts, 
              gpointer user_data) 
{
	CuTest *cu = the_cu;
	g_assert (cu);

	gchar *msg;
	
	/* Should only be asking once per location */
	if (n_prompts > 0) {
		msg = g_strdup_printf ("decryption didn't work for: %s", g_quark_to_string (loc));
		CuAssert (cu, msg, FALSE);
		return NULL;
	}
	
	CuAssert (cu, "location is empty", loc != 0);
	CuAssert (cu, "details is null", details != NULL);
	
	g_print ("getting password 'booo' for: %s\n", details); 	
	
	/* All our test encrypted stuff use this password */
	return gkr_secure_strdup ("booo");
}

static void
read_file (CuTest *cu, const gchar *filename, GQuark *location, guchar **contents, gsize *len)
{
	gchar *path;
	gboolean ret;
	
	the_cu = cu;
	
	path = g_build_filename (g_get_current_dir (), "test-data", filename, NULL);
	*location = gkr_location_from_path (path);
	CuAssert (cu, "location is empty", *location != 0);
	
	ret = g_file_get_contents (path, (gchar**)contents, len, NULL);
	CuAssert (cu, "couldn't read in file", ret);
	
	g_free (path);
}
	 

void unit_test_start_parser (CuTest *cu)
{
	parser = gkr_pkix_parser_new ();
	g_signal_connect (parser, "parsed-partial", G_CALLBACK (parsed_partial), NULL);
	g_signal_connect (parser, "parsed-sexp", G_CALLBACK (parsed_sexp), NULL);
	g_signal_connect (parser, "parsed-asn1", G_CALLBACK (parsed_asn1), NULL);
	g_signal_connect (parser, "ask-password", G_CALLBACK (ask_password), NULL);
}

void unit_test_pkix_parse_der_keys (CuTest* cu)
{
	guchar *contents;
	GkrPkixResult result;
	GQuark location;
	gsize len;
	
	the_cu = cu;

	/* First an RSA key */
	read_file (cu, "der-rsa-1024.key", &location, &contents, &len);
	
	last_sexp_parsed = NULL;
	result = gkr_pkix_parser_der_private_key (parser, location, contents, len);
	CuAssert (cu, "couldn't parse RSA key", result == GKR_PKIX_SUCCESS);
	CuAssert (cu, "parsed object is invalid", last_sexp_parsed != NULL);
	
	gkr_crypto_sexp_dump (last_sexp_parsed);

	/* Now a DSA key */	
	read_file (cu, "der-dsa-1024.key", &location, &contents, &len);
	
	last_sexp_parsed = NULL;
	result = gkr_pkix_parser_der_private_key (parser, location, contents, len);
	CuAssert (cu, "couldn't parse DSA key", result == GKR_PKIX_SUCCESS);
	CuAssert (cu, "parsed object is invalid", last_sexp_parsed != NULL);
	
	gkr_crypto_sexp_dump (last_sexp_parsed);
}

void unit_test_pkix_parse_der_pkcs8 (CuTest* cu)
{
	guchar *contents;
	GkrPkixResult result;
	GQuark location;
	gsize len;
	
	the_cu = cu;

	/* First an DSA key */
	read_file (cu, "der-pkcs8-dsa.key", &location, &contents, &len);
	
	last_sexp_parsed = NULL;
	result = gkr_pkix_parser_der_pkcs8_plain (parser, location, contents, len);
	CuAssert (cu, "couldn't parse PKCS8 key", result == GKR_PKIX_SUCCESS);
	CuAssert (cu, "parsed object is invalid", last_sexp_parsed != NULL);
	
	gkr_crypto_sexp_dump (last_sexp_parsed);
	
	/* Now an encrypted key */
	read_file (cu, "der-pkcs8-encrypted-pkcs5.key", &location, &contents, &len);
	
	last_sexp_parsed = NULL;
	result = gkr_pkix_parser_der_pkcs8_encrypted (parser, location, contents, len);
	CuAssert (cu, "couldn't parse PKCS8 key", result == GKR_PKIX_SUCCESS);
	CuAssert (cu, "parsed object is invalid", last_sexp_parsed != NULL);
	
	gkr_crypto_sexp_dump (last_sexp_parsed);	
}

void unit_test_pkix_parse_pem (CuTest *cu)
{
	guchar *contents;
	GkrPkixResult result;
	GQuark location;
	gsize len;
	
	the_cu = cu;

	/* First an RSA key */
	read_file (cu, "pem-dsa-1024.key", &location, &contents, &len);
	
	n_parsed = 0;
	result = gkr_pkix_parser_pem (parser, location, contents, len);
	CuAssert (cu, "couldn't parse PEM data", result == GKR_PKIX_SUCCESS);

	CuAssert (cu, "invalid number of items parsed", n_parsed == 1);
	CuAssert (cu, "invalid type of data parsed", last_sexp_parsed != NULL);
	
	gkr_crypto_sexp_dump (last_sexp_parsed);
}

void unit_test_pkix_parse_all (CuTest *cu)
{
	gchar *path, *filepath, *msg;
	guchar *contents;
	GError *err = NULL;
	gboolean result;
	const gchar *filename;
	GQuark location;
	gsize len;
	GDir *dir;
	
	the_cu = cu;
	path = g_build_filename (g_get_current_dir (), "test-data", NULL);
	
	dir = g_dir_open (path, 0, NULL);
	CuAssert (cu, "couldn't open directory", dir != NULL); 

	while (dir) {
		filename = g_dir_read_name (dir);
		if (!filename)
			break;
			
		filepath = g_build_filename (path, filename, NULL);
		if (!g_file_test (filepath, G_FILE_TEST_IS_REGULAR))
			continue;
		
		read_file (cu, filename, &location, &contents, &len);
		
		result = gkr_pkix_parser_parse (parser, location, contents, len, &err);
		if (!result) { 
			msg = g_strdup_printf ("couldn't parse file data: %s: %s", 
			                       filename, err && err->message ? err->message : "");
			g_error_free (err);
			err = NULL;
			CuAssert (cu, msg, FALSE);
		}
	}
}
