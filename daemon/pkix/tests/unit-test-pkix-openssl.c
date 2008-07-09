/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pkix-openssl.c: Test PKIX openssl

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

#include "pkix/gkr-pkix-openssl.h"
#include "pkix/gkr-pkix-pem.h"

#include <glib.h>

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

guchar *refenc = NULL;
guchar *refdata = NULL;
gsize n_refenc = 0;
gsize n_refdata = 0;
GHashTable *refheaders = NULL;

static void
copy_each_key_value (gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_insert ((GHashTable*)user_data, g_strdup ((gchar*)key), g_strdup ((gchar*)value));
}

static void
parse_reference (GQuark type, const guchar *data, gsize n_data,
                 GHashTable *headers, gpointer user_data)
{
	CuTest *cu = (CuTest*)user_data;
	GkrPkixResult res;
	const gchar *dekinfo;
	
	CuAssert (cu, "no data in PEM callback", data != NULL);
	CuAssert (cu, "no data in PEM callback", n_data > 0);
	refenc = g_memdup (data, n_data);
	n_refenc = n_data;
	
	CuAssert (cu, "no headers present in file", headers != NULL);
	refheaders = gkr_pkix_pem_headers_new ();
	g_hash_table_foreach (headers, copy_each_key_value, refheaders);
	dekinfo = gkr_pkix_openssl_get_dekinfo (headers);
	CuAssert (cu, "no dekinfo in headers", dekinfo != NULL);
	
	res = gkr_pkix_openssl_decrypt_block (dekinfo, "booo", data, n_data, &refdata, &n_refdata);
	CuAssert (cu, "couldn't openssl decrypt block", res == GKR_PKIX_SUCCESS);
	CuAssert (cu, "no data returned from openssl decrypt", refdata != NULL);
	CuAssert (cu, "invalid amount of data returned from openssl decrypt", n_refdata == n_data);
}

void unit_test_openssl_parse_reference (CuTest* cu)
{
	guchar *input;
	gsize n_input;
	guint num;
	
	read_file (cu, "pem-rsa-enc.key", &input, &n_input);

	num = gkr_pkix_pem_parse (input, n_input, parse_reference, NULL);
	CuAssert (cu, "couldn't PEM block in reference data", num == 1);
	
	CuAssert (cu, "parse_reference() wasn't called", refdata != NULL);
}

void unit_test_openssl_write_reference (CuTest* cu)
{
	const gchar *dekinfo;
	guchar *encrypted;
	gsize n_encrypted;
	gboolean ret;
	
	dekinfo = gkr_pkix_openssl_get_dekinfo (refheaders); 
	CuAssert (cu, "no dekinfo in headers", dekinfo != NULL);

	ret = gkr_pkix_openssl_encrypt_block (dekinfo, "booo", refdata, n_refdata, &encrypted, &n_encrypted);
	CuAssert (cu, "couldn't openssl encrypt block", ret == TRUE);
	CuAssert (cu, "no data returned from openssl encrypt", encrypted != NULL);
	CuAssert (cu, "invalid amount of data returned from openssl encrypt", n_refdata <= n_encrypted);
	
	CuAssert (cu, "data length doesn't match input length", n_encrypted == n_refenc);
	CuAssert (cu, "data doesn't match input", memcmp (encrypted, refenc, n_encrypted) == 0);
}

/* 29 bytes (prime number, so block length has bad chance of matching */
const static guchar *TEST_DATA = (guchar*)"ABCDEFGHIJKLMNOPQRSTUVWXYZ123";
const gsize TEST_DATA_L = 29;
	
void unit_test_openssl_roundtrip (CuTest* cu)
{
	const gchar *dekinfo;
	GkrPkixResult res;
	gboolean ret;
	guchar *encrypted, *decrypted;
	gsize n_encrypted, n_decrypted;
	int i;
	
	dekinfo = gkr_pkix_openssl_prep_dekinfo (refheaders);
	
	ret = gkr_pkix_openssl_encrypt_block (dekinfo, "password", TEST_DATA, TEST_DATA_L, &encrypted, &n_encrypted);
	CuAssert (cu, "couldn't openssl encrypt block", ret == TRUE);
	CuAssert (cu, "no data returned from openssl encrypt", encrypted != NULL);
	CuAssert (cu, "invalid amount of data returned from openssl encrypt", TEST_DATA_L <= n_encrypted);

	res = gkr_pkix_openssl_decrypt_block (dekinfo, "password", encrypted, n_encrypted, &decrypted, &n_decrypted);
	CuAssert (cu, "couldn't openssl decrypt block", res == GKR_PKIX_SUCCESS);
	CuAssert (cu, "no data returned from openssl decrypt", decrypted != NULL);

	/* Check that the data was decrypted properly */
	CuAssert (cu, "decrypted data doesn't match length", n_decrypted >= TEST_DATA_L);
	CuAssert (cu, "decrypted data doesn't match", memcmp (TEST_DATA, decrypted, TEST_DATA_L) == 0);
	
	/* Check that the remainder is all zeros */
	for (i = TEST_DATA_L; i < n_decrypted; ++i)
		CuAssert (cu, "non null byte in padding", decrypted[i] == 0);
}
