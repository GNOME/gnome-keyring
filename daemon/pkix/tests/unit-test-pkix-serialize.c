/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pkix-serialize.c: Test PKIX serialize

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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "run-auto-test.h"

#include "common/gkr-location.h"
#include "common/gkr-crypto.h"
#include "common/gkr-secure-memory.h"

#include "pkix/gkr-pkix-der.h"
#include "pkix/gkr-pkix-parser.h"
#include "pkix/gkr-pkix-serialize.h"

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

static void
read_file (CuTest *cu, const gchar *filename, guchar **contents, gsize *len)
{
	gchar *path;
	gboolean ret;
	
	path = g_build_filename (g_get_current_dir (), "test-data", filename, NULL);
	ret = g_file_get_contents (path, (gchar**)contents, len, NULL);
	CuAssert (cu, "couldn't read in file", ret);
	
	g_free (path);
}

static gboolean
ask_password (GkrPkixParser *parser, GQuark loc, gkrconstid unique, 
              GQuark type, const gchar *details, gint *state, 
              gchar **password, gpointer user_data) 
{
	CuTest *cu = (CuTest*)user_data;
	gchar *msg;
	
	/* Should only be asking once per location */
	if (*state > 0) {
		msg = g_strdup_printf ("decryption didn't work for: %s", g_quark_to_string (loc));
		CuAssert (cu, msg, FALSE);
		return FALSE;
	}
	
	(*state)++;
	
	CuAssert (cu, "type is zero", type != 0);
	CuAssert (cu, "details is null", details != NULL);
	
	g_print ("getting password 'booo' for: %s\n", details); 	
	
	/* All our test encrypted stuff use this password */
	*password = gkr_secure_strdup ("booo");
	return TRUE;
}

void unit_test_serialize_certificate (CuTest* cu)
{
	ASN1_TYPE asn, parsed;
	guchar *input, *output;
	gsize n_input, n_output;
	GkrPkixResult result;
	
	read_file (cu, "der-certificate.crt", &input, &n_input);
	result = gkr_pkix_der_read_certificate (input, n_input, &asn);
	CuAssert (cu, "couldn't parse certificate file", result == GKR_PKIX_SUCCESS);
	
	output = gkr_pkix_serialize_to_data (GKR_PKIX_CERTIFICATE, asn, "booo", &n_output);
	
	result = gkr_pkix_der_read_certificate (output, n_output, &parsed);
	CuAssert (cu, "couldn't parse encoded certificate", result == GKR_PKIX_SUCCESS);
}

void unit_test_serialize_pkcs8 (CuTest* cu)
{
	gcry_sexp_t key;
	guchar *input, *output;
	gsize n_input, n_output;
	GkrPkixParser* parser;
	GkrPkixResult result;

	read_file (cu, "der-dsa-1024.key", &input, &n_input);
	result = gkr_pkix_der_read_private_key_dsa (input, n_input, &key);
	CuAssert (cu, "couldn't parse key file", result == GKR_PKIX_SUCCESS);
	
	/* Serializes as PKCS8 */
	output = gkr_pkix_serialize_to_data (GKR_PKIX_PRIVATE_KEY, key, "booo", &n_output);
	
	parser = gkr_pkix_parser_new (FALSE);
	g_signal_connect (parser, "ask-password", G_CALLBACK (ask_password), cu);

	result = gkr_pkix_parser_der_pkcs8 (parser, 0, output, n_output);
	CuAssert (cu, "couldn't parse encrypted certificate", result == GKR_PKIX_SUCCESS);
}
