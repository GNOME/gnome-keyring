/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "egg-asn1.h"
#include "egg-dh.h"
#include "egg-openssl.h"

/* Generated with openssl dhparam, same as contents of dh-params.pem */
#define DEFAULT_PRIME "00E9991CBC77057BEB3E8165025E8338722BDB00297A910EA441129EA84ED091AF9DA55681A192E7E7C283FF6FA9EC5A81E03A8C0999F66B19DF80BE867D0A79B1DB3E42AE7EC1FCA057889F3ED666E86C3C248AA47C8E699997183C7A8093242C0D741CE5D4E1BA99CB5ACE895C53B92D9B9FE6B0D8203B5A8286567B8E9C2A33"
#define DEFAULT_BASE  "02"
#define DEFAULT_BITS  1024

gboolean
egg_dh_default_params (gcry_mpi_t *prime, gcry_mpi_t *base)
{
	gcry_error_t gcry;

	g_return_val_if_fail (prime, FALSE);
	g_return_val_if_fail (base, FALSE);

	gcry = gcry_mpi_scan (prime, GCRYMPI_FMT_HEX, DEFAULT_PRIME, 0, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);
	g_return_val_if_fail (gcry_mpi_get_nbits (*prime) == DEFAULT_BITS, FALSE);

	gcry = gcry_mpi_scan (base, GCRYMPI_FMT_HEX, DEFAULT_BASE, 0, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	return TRUE;
}

gboolean
egg_dh_gen_secret (gcry_mpi_t p, gcry_mpi_t g,
                   gcry_mpi_t *X, gcry_mpi_t *x)
{
	gint bits;

	g_return_val_if_fail (g, FALSE);
	g_return_val_if_fail (p, FALSE);
	g_return_val_if_fail (X, FALSE);
	g_return_val_if_fail (x, FALSE);

	/* Secret key value must be less than half of p */
	bits = gcry_mpi_get_nbits (p) - 1;
	g_return_val_if_fail (bits >= 0, FALSE);

	/*
	 * Generate a strong random number of bits, and not zero.
	 * gcry_mpi_randomize bumps up to the next byte. Since we
	 * need to have a value less than half of p, we make sure
	 * we bump down.
	 */
	*x = gcry_mpi_snew (bits);
	g_return_val_if_fail (*x, FALSE);
	while (gcry_mpi_cmp_ui (*x, 0) == 0)
		gcry_mpi_randomize (*x, (bits / 8) * 8, GCRY_STRONG_RANDOM);

	*X = gcry_mpi_new (bits);
	g_return_val_if_fail (*X, FALSE);
	gcry_mpi_powm (*X, g, *x, p);

	return TRUE;
}

gboolean
egg_dh_gen_key (gcry_mpi_t Y, gcry_mpi_t x,
                gcry_mpi_t p, gcry_mpi_t *k)
{
	gint bits;

	g_return_val_if_fail (Y, FALSE);
	g_return_val_if_fail (x, FALSE);
	g_return_val_if_fail (p, FALSE);
	g_return_val_if_fail (k, FALSE);

	bits = gcry_mpi_get_nbits (p);
	g_return_val_if_fail (bits >= 0, FALSE);

	*k = gcry_mpi_snew (bits);
	g_return_val_if_fail (*k, FALSE);
	gcry_mpi_powm (*k, Y, x, p);

	return TRUE;
}

typedef struct _Parameters {
	gcry_mpi_t p;
	gcry_mpi_t g;
} Parameters;

static gboolean
parse_der_pkcs3 (const guchar *data, gsize n_data, Parameters *params)
{
	ASN1_TYPE asn;
	guchar *buf_p, *buf_g;
	gsize n_buf_p, n_buf_g;
	gcry_error_t gcry;

	asn = egg_asn1_decode ("PK.DHParameter", data, n_data);
	if (!asn)
		return FALSE;

	buf_p = egg_asn1_read_value (asn, "prime", &n_buf_p, (EggAllocator)g_realloc);
	buf_g = egg_asn1_read_value (asn, "base", &n_buf_g, (EggAllocator)g_realloc);
	g_return_val_if_fail (buf_p && buf_g, FALSE);
	gcry = gcry_mpi_scan (&params->p, GCRYMPI_FMT_STD, buf_p, n_buf_p, &n_buf_p);
	g_return_val_if_fail (gcry == 0, FALSE);
	gcry = gcry_mpi_scan (&params->g, GCRYMPI_FMT_STD, buf_g, n_buf_g, &n_buf_g);
	g_return_val_if_fail (gcry == 0, FALSE);

	g_free (buf_p);
	g_free (buf_g);
	return TRUE;
}

static void
parse_openssl_pkcs3 (GQuark type, const guchar *data, gsize n_data,
                     GHashTable *headers, gpointer user_data)
{
	Parameters *params = user_data;

	/* Only parse the first one */
	if (params->p != NULL)
		return;

	if (g_quark_try_string ("DH PARAMETERS") == type)
		parse_der_pkcs3 (data, n_data, params);
}

gboolean
egg_dh_parse_pkcs3 (const guchar *data, gsize n_data, gcry_mpi_t *p, gcry_mpi_t *g)
{
	Parameters params;

	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (p, FALSE);
	g_return_val_if_fail (g, FALSE);

	memset (&params, 0, sizeof (params));
	if (!parse_der_pkcs3 (data, n_data, &params))
		egg_openssl_pem_parse (data, n_data, parse_openssl_pkcs3, &params);

	if (!params.p || !params.g)
		return FALSE;
	*p = params.p;
	*g = params.g;
	return TRUE;
}
