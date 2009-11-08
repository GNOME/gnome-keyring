/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-dh.c: Test egg-dh.c

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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "run-auto-test.h"

#include "egg-dh.h"

#include <gcrypt.h>

DEFINE_TEST(dh_parse_pkcs3)
{
	gcry_mpi_t p, g;
	guchar *data;
	gsize n_data;
	gboolean ret;

	data = test_data_read ("dh-params.pem", &n_data);
	ret = egg_dh_parse_pkcs3 (data, n_data, &p, &g);
	g_assert (ret == TRUE);
	g_assert (gcry_mpi_get_nbits (p) == 1024);

#if 0
	guchar *output;
	gsize n_written;
	gcry_mpi_aprint (GCRYMPI_FMT_HEX, &output, &n_written, p);
	g_printerr ("\nprime: %s\n", output);
	gcry_mpi_aprint (GCRYMPI_FMT_HEX, &output, &n_written, g);
	g_printerr ("\nbase: %s\n", output);
#endif

	gcry_mpi_release (p);
	gcry_mpi_release (g);
	g_free (data);
}

DEFINE_TEST(dh_perform)
{
	guchar *data;
	gsize n_data;
	gcry_mpi_t p, g;
	gcry_mpi_t x1, X1, k1;
	gcry_mpi_t x2, X2, k2;
	gboolean ret;

	/* Load up the parameters */
	data = test_data_read ("dh-params.pem", &n_data);
	if (!egg_dh_parse_pkcs3 (data, n_data, &p, &g))
		g_assert_not_reached ();
	g_free (data);

	/* Generate secrets */
	ret = egg_dh_gen_secret (p, g, &X1, &x1);
	g_assert (ret);
	ret = egg_dh_gen_secret (p, g, &X2, &x2);
	g_assert (ret);

	/* Calculate keys */
	ret = egg_dh_gen_key (X2, x1, p, &k1);
	g_assert (ret);
	ret = egg_dh_gen_key (X1, x2, p, &k2);
	g_assert (ret);

	/* Keys must be the same */
	g_assert (gcry_mpi_cmp (k1, k2) == 0);

	gcry_mpi_release (p);
	gcry_mpi_release (g);
	gcry_mpi_release (x1);
	gcry_mpi_release (X1);
	gcry_mpi_release (k1);
	gcry_mpi_release (x2);
	gcry_mpi_release (X2);
	gcry_mpi_release (k2);
}

DEFINE_TEST(dh_defaults)
{
	gboolean ret;
	gcry_mpi_t p, g;

	ret = egg_dh_default_params (&p, &g);
	g_assert (ret);
	g_assert_cmpint (gcry_mpi_get_nbits (p), ==, 1024);
	g_assert_cmpint (gcry_mpi_get_nbits (g), <, gcry_mpi_get_nbits (p));

	gcry_mpi_release (p);
	gcry_mpi_release (g);
}
