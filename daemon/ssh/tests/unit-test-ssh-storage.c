/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-ssh-storage.c: Test SSH storage

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
#include "egg/egg-secure-memory.h"

#include "ssh/gkr-ssh-storage.h"

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

static const gchar *TEST_DSA_KEY = "ssh-dss AAAAB3NzaC1kc3MAAACBAJhgJycWojhw+UkvgFTdrBnCyVAZZPbbGCJ9bvoVb8N75MAmsPZugNInz6j6Iz+sa1nsYlBZnrhg4mXfxeWOTiI6/YDbPdA65P/q4oNDjKIjgBiC135un40+Qz8JGq2JPrU5pElH4jb8NYA4PymuIL7vingUvFK3XJiWSb2ZepNXAAAAFQCWBBXsX/Vi3GpSlG88Z+P8NQqmQQAAAIB0JOhEstQgJKic5Vx+C1MtBS2DX8dQ1TLo4bgzDTbYU4mbqJDUkhhYP2IGFEpuWFxLaCGsWoBfWi98Wz9o1P9TYkbmCiDd8mt7Px5bUR09orMUvHiNaLM9kH0KxUxAifGcrAsATloLJ8ReNJkypB9frjjbN1b/7YDyEP0zSiwDwwAAAIA9syAP6aY0kIdv7yqC5biGJqY170cpJYOE/vFHDVUXrXaTgPsoEQuRMFwHZbhgrVcUTKLJsmIyrpqWZ41PxDHgk1SC9GYDLmb65Pn23NvUDAZKft6E09KGL49LNpitfzLxvZAMLcU+YVCrUJwT/NgPTJ70GFrLs3z8UsKeFFxEUA== Test Comment\n"; 
static const gchar *TEST_RSA_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAz8Ji7Z1/NK7tvHETqSuLWPyn4l0fF6lTTbYf9Jx21RtaNwmaCi9u1Id3wVQMtuuR+0NLoBPyVdDrWi6ap9TkKdNQnnqW4Ang+GZc+9sXzbgWmgXnjKTXo+EcpMJLqpTLXPcaxYtwGIL/K/BE7NJ9i43HPqUG5z8ezE1/iHkfHMk= stef@memberwebs.com\n"; 
static const gchar *TEST_COMMENT_KEY = "# a line that shouldn't be parsed \n\nssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAz8Ji7Z1/NK7tvHETqSuLWPyn4l0fF6lTTbYf9Jx21RtaNwmaCi9u1Id3wVQMtuuR+0NLoBPyVdDrWi6ap9TkKdNQnnqW4Ang+GZc+9sXzbgWmgXnjKTXo+EcpMJLqpTLXPcaxYtwGIL/K/BE7NJ9i43HPqUG5z8ezE1/iHkfHMk= stef@memberwebs.com\n# \n"; 

void unit_test_ssh_public_dsa (CuTest* cu)
{
	GkrPkixResult res;
	gcry_sexp_t sexp;
	gchar *comment;
	int algo;
	guchar *data;
	gsize n_data;
	gboolean ret, is_priv;
	
	res = gkr_ssh_storage_load_public_key ((guchar*)TEST_DSA_KEY, strlen (TEST_DSA_KEY), &sexp, &comment); 
	CuAssert (cu, "couldn't parse public SSH DSA key", res == GKR_PKIX_SUCCESS);
	CuAssert (cu, "Bad comment on public SSH DSA key", comment && strcmp (comment, "Test Comment") == 0);
	
	ret = gkr_crypto_skey_parse (sexp, &algo, &is_priv, NULL);
	CuAssert (cu, "bad SSH DSA key parsed", ret == TRUE);
	CuAssert (cu, "wrong algorithm in SSH DSA key parsed", algo == GCRY_PK_DSA);
	CuAssert (cu, "bad key type in SSH DSA key parsed", is_priv == FALSE);
	
	gkr_crypto_sexp_dump (sexp);
	
	data = gkr_ssh_storage_write_public_key (sexp, comment, &n_data);
	CuAssert (cu, "Couldn't write SSH DSA key", data != NULL);
	CuAssert (cu, "Written SSH key invalid length", n_data == strlen (TEST_DSA_KEY));
	CuAssert (cu, "Wrote invalid SSH DSA key", strncmp (TEST_DSA_KEY, (gchar*)data, n_data) == 0);
}

void unit_test_ssh_public_rsa (CuTest *cu)
{
	GkrPkixResult res;
	gcry_sexp_t sexp;
	gchar *comment;
	int algo;
	guchar *data, *data2;
	gsize n_data, n_data2;
	gboolean ret, is_priv;
	
	/* RSA */
	
	res = gkr_ssh_storage_load_public_key ((guchar*)TEST_RSA_KEY, strlen (TEST_RSA_KEY), &sexp, &comment); 
	CuAssert (cu, "couldn't parse public SSH RSA key", res == GKR_PKIX_SUCCESS);
	CuAssert (cu, "Bad comment on public SSH RSA key", comment && strcmp (comment, "stef@memberwebs.com") == 0);
	
	ret = gkr_crypto_skey_parse (sexp, &algo, &is_priv, NULL);
	CuAssert (cu, "bad SSH RSA key parsed", ret == TRUE);
	CuAssert (cu, "wrong algorithm in SSH RSA key parsed", algo == GCRY_PK_RSA);
	CuAssert (cu, "bad key type in SSH RSA key parsed", is_priv == FALSE);

	gkr_crypto_sexp_dump (sexp);

	data = gkr_ssh_storage_write_public_key (sexp, comment, &n_data);
	CuAssert (cu, "Couldn't write SSH RSA key", data != NULL);
	CuAssert (cu, "Written SSH key invalid length", n_data == strlen (TEST_RSA_KEY));
	CuAssert (cu, "Wrote invalid SSH RSA key", memcmp (TEST_RSA_KEY, data, n_data) == 0);

	/* The same RSA key with comments */
	
	res = gkr_ssh_storage_load_public_key ((guchar*)TEST_COMMENT_KEY, strlen (TEST_COMMENT_KEY), &sexp, &comment); 
	CuAssert (cu, "couldn't parse public SSH RSA key", res == GKR_PKIX_SUCCESS);
	
	gkr_crypto_sexp_dump (sexp);

	data2 = gkr_ssh_storage_write_public_key (sexp, comment, &n_data2);
	CuAssert (cu, "Couldn't write SSH RSA key", data != NULL);
	CuAssert (cu, "Written SSH key invalid length", n_data == n_data2);
	CuAssert (cu, "Wrote invalid SSH RSA key", memcmp (data, data2, n_data) == 0);	
}
