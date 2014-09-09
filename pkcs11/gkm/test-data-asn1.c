/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-data-asn1.c: Test ASN.1 routines

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

#include "gkm/gkm-data-asn1.h"

#include <glib.h>
#include <glib-object.h>
#include <gcrypt.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"
#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

typedef struct _EggAsn1xDef ASN1_ARRAY_TYPE;
typedef struct _EggAsn1xDef asn1_static_node;
#include "test.asn.h"

EGG_SECURE_DEFINE_GLIB_GLOBALS();

typedef struct {
	GNode *asn1_cert;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	GBytes *data;
	gchar *contents;
	gsize length;

	if (!g_file_get_contents (SRCDIR "/pkcs11/gkm/fixtures/test-certificate-1.der", &contents, &length, NULL))
		g_assert_not_reached ();

	data = g_bytes_new_take (contents, length);
	test->asn1_cert = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate", data);
	g_assert (test->asn1_cert);
	g_bytes_unref (data);
}

static void
teardown (Test *test, gconstpointer unused)
{
	egg_asn1x_destroy (test->asn1_cert);
}

static void
test_asn1_integers (Test *test, gconstpointer unused)
{
	GNode *asn;
	gcry_mpi_t mpi, mpt;
	GBytes *data;
	gboolean ret;

	asn = egg_asn1x_create (test_asn1_tab, "TestIntegers");
	g_assert ("asn test structure is null" && asn != NULL);

	/* Make a random number */
	mpi = gcry_mpi_new (512);
	g_return_if_fail (mpi);
	gcry_mpi_randomize (mpi, 512, GCRY_WEAK_RANDOM);

	/* Write the mpi out */
	ret = gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "mpi", NULL), mpi);

	/* Now encode the whole caboodle */
	data = egg_asn1x_encode (asn, NULL);
	g_assert ("encoding asn1 didn't work" && data != NULL);

	egg_asn1x_destroy (asn);

	/* Now decode it all nicely */
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestIntegers", data);
	g_assert (asn != NULL);

	ret = gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "mpi", NULL), &mpt);
	g_assert ("couldn't read mpi from asn1" && ret);
	g_assert ("mpi returned is null" && mpt != NULL);
	g_assert ("mpi is wrong number" && gcry_mpi_cmp (mpi, mpt) == 0);

	g_bytes_unref (data);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	egg_libgcrypt_initialize();

	g_test_init (&argc, &argv, NULL);

	g_test_add ("/gkm/data-asn1/integers", Test, NULL, setup, test_asn1_integers, teardown);

	return g_test_run ();
}
