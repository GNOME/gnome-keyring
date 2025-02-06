/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkm-data-der.c - parsing and serializing of common crypto DER structures

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

#include "gkm-data-asn1.h"
#include "gkm-data-der.h"
#include "gkm-data-types.h"
#include "gkm-sexp.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"
#include "egg/egg-secure-memory.h"
#include "egg/egg-symkey.h"

#include <glib.h>
#include <gcrypt.h>

EGG_SECURE_DECLARE (data_der);

/* -----------------------------------------------------------------------------
 * QUARKS
 */

static GQuark OID_PKIX1_RSA;
static GQuark OID_PKIX1_DSA;
static GQuark OID_PKIX1_ECDSA;
static GQuark OID_PKCS12_PBE_3DES_SHA1;
static GQuark OID_ANSI_SECP256R1;
static GQuark OID_ANSI_SECP384R1;
static GQuark OID_ANSI_SECP521R1;

static void
init_quarks (void)
{
	static gsize quarks_inited = 0;

	if (g_once_init_enter (&quarks_inited)) {

		#define QUARK(name, value) \
			name = g_quark_from_static_string(value)

		QUARK (OID_PKIX1_RSA, "1.2.840.113549.1.1.1");
		QUARK (OID_PKIX1_DSA, "1.2.840.10040.4.1");
		QUARK (OID_PKIX1_ECDSA, "1.2.840.10045.2.1");
		QUARK (OID_PKCS12_PBE_3DES_SHA1, "1.2.840.113549.1.12.1.3");
		QUARK (OID_ANSI_SECP256R1, "1.2.840.10045.3.1.7");
		QUARK (OID_ANSI_SECP384R1, "1.3.132.0.34");
		QUARK (OID_ANSI_SECP521R1, "1.3.132.0.35");

		#undef QUARK

		g_once_init_leave (&quarks_inited, 1);
	}
}

const gchar *
gkm_data_der_oid_to_curve (GQuark oid)
{
	if (oid == OID_ANSI_SECP256R1)
		return "NIST P-256";
	else if (oid == OID_ANSI_SECP384R1)
		return "NIST P-384";
	else if (oid == OID_ANSI_SECP521R1)
		return "NIST P-521";
	return NULL;
}

/*
 * Convert ecc->curve values from libgcrypt representation to internal one.
 * Ignore duplicates and alternative names, since S-expressions are created
 * only by us throught this code.
 */
static GQuark
gkm_data_der_curve_to_oid (const gchar *curve)
{
	if (g_str_equal (curve, "NIST P-256"))
		return OID_ANSI_SECP256R1;
	else if (g_str_equal (curve, "NIST P-384"))
		return OID_ANSI_SECP384R1;
	else if (g_str_equal (curve, "NIST P-521"))
		return OID_ANSI_SECP521R1;
	return 0;
}


GQuark
gkm_data_der_oid_from_ec_params (GBytes *params)
{
	GNode *asn;
	GQuark oid;

	init_quarks ();

	asn = egg_asn1x_create_and_decode (pk_asn1_tab, "Parameters", params);
	if (!asn)
		return 0;

	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "namedCurve", NULL));

	egg_asn1x_destroy (asn);
	return oid;
}

GBytes *
gkm_data_der_get_ec_params (GQuark oid)
{
	GNode *asn;
	GBytes *params = NULL;
	GNode *named_curve;

	asn = egg_asn1x_create (pk_asn1_tab, "Parameters");
	if (!asn)
		goto done;

	named_curve = egg_asn1x_node (asn, "namedCurve", NULL);

	if (!egg_asn1x_set_oid_as_quark (named_curve, oid))
		goto done;

	if (!egg_asn1x_set_choice (asn, named_curve))
		goto done;

	params = egg_asn1x_encode (asn, NULL);

done:
	egg_asn1x_destroy (asn);
	return params;
}

/* wrapper so we do not have to export the GQuark magic */
GBytes *
gkm_data_der_curve_to_ec_params (const gchar *curve_name)
{
	GQuark oid;

	init_quarks ();

	oid = gkm_data_der_curve_to_oid (curve_name);
	if (oid == 0)
		return NULL;

	return gkm_data_der_get_ec_params (oid);
}

GBytes *
gkm_data_der_encode_ecdsa_q_str (const guchar *data, gsize data_len)
{
	GNode *asn = NULL;
	g_autoptr(GBytes) bytes = NULL;
	GBytes *result = NULL;

	asn = egg_asn1x_create (pk_asn1_tab, "ECKeyQ");
	g_return_val_if_fail (asn, FALSE);

	bytes = g_bytes_new_static (data, data_len);
	if (!gkm_data_asn1_write_string (asn, bytes))
		goto done;

	result = egg_asn1x_encode (asn, g_realloc);
	if (result == NULL)
		g_warning ("couldn't encode Q into the PKCS#11 structure: %s", egg_asn1x_message (asn));
done:
	egg_asn1x_destroy (asn);
	return result;
}

gboolean
gkm_data_der_encode_ecdsa_q (gcry_mpi_t q, GBytes **result)
{
	gcry_error_t gcry;
	guchar data[1024];
	gsize data_len = 1024;
	gboolean rv = TRUE;

	g_assert (q);
	g_assert (result);

	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, data, data_len, &data_len, q);
	g_return_val_if_fail (gcry == 0, FALSE);

	*result = gkm_data_der_encode_ecdsa_q_str (data, data_len);
	if (*result == NULL)
		rv = FALSE;

	return rv;
}

gboolean
gkm_data_der_decode_ecdsa_q (GBytes *data, GBytes **result)
{
	GNode *asn = NULL;
	gboolean rv = TRUE;

	g_assert (data);
	g_assert (result);

	asn = egg_asn1x_create_and_decode (pk_asn1_tab, "ECKeyQ", data);
	/* workaround a bug in gcr (not DER encoding the MPI) */
	if (!asn) {
		*result = data;
		return rv;
	}

	rv = gkm_data_asn1_read_string (asn, result);

	egg_asn1x_destroy (asn);
	return rv;
}

/* -----------------------------------------------------------------------------
 * KEY PARSING
 */

#define SEXP_PUBLIC_RSA  \
	"(public-key"    \
	"  (rsa"         \
	"    (n %m)"     \
	"    (e %m)))"

GkmDataResult
gkm_data_der_read_public_key_rsa (GBytes *data,
                                  gcry_sexp_t *s_key)
{
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	GNode *asn = NULL;
	gcry_mpi_t n, e;
	int res;

	n = e = NULL;

	asn = egg_asn1x_create_and_decode (pk_asn1_tab, "RSAPublicKey", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (!gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "modulus", NULL), &n) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "publicExponent", NULL), &e))
		goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_RSA, n, e);
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);

	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid RSA public key");

	return ret;
}

#define SEXP_PRIVATE_RSA  \
	"(private-key"   \
	"  (rsa"         \
	"    (n %m)"     \
	"    (e %m)"     \
	"    (d %m)"     \
	"    (p %m)"     \
	"    (q %m)"     \
	"    (u %m)))"

GkmDataResult
gkm_data_der_read_private_key_rsa (GBytes *data,
                                   gcry_sexp_t *s_key)
{
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	gcry_mpi_t n, e, d, p, q, u;
	gcry_mpi_t tmp;
	gulong version;
	GNode *asn = NULL;
	int res;

	n = e = d = p = q = u = NULL;

	asn = egg_asn1x_create_and_decode (pk_asn1_tab, "RSAPrivateKey", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (!egg_asn1x_get_integer_as_ulong (egg_asn1x_node (asn, "version", NULL), &version))
		goto done;

	/* We only support simple version */
	if (version != 0) {
		ret = GKM_DATA_UNRECOGNIZED;
		g_message ("unsupported version of RSA key: %lu", version);
		goto done;
	}

	if (!gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "modulus", NULL), &n) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "publicExponent", NULL), &e) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "privateExponent", NULL), &d) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "prime1", NULL), &p) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "prime2", NULL), &q) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "coefficient", NULL), &u))
		goto done;

	/* Fix up the incoming key so gcrypt likes it */
	if (gcry_mpi_cmp (p, q) > 0) {
		/* P shall be smaller then Q!  Swap primes.  iqmp becomes u.  */
		tmp = p;
		p = q;
		q = tmp;
	} else {
		/* U needs to be recomputed.  */
		gcry_mpi_invm (u, p, q);
	}

	res = gcry_sexp_build (s_key, NULL, SEXP_PRIVATE_RSA, n, e, d, p, q, u);
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	gcry_mpi_release (d);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (u);

	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid RSA key");

	return ret;
}

#define SEXP_PUBLIC_DSA  \
	"(public-key"   \
	"  (dsa"         \
	"    (p %m)"     \
	"    (q %m)"     \
	"    (g %m)"     \
	"    (y %m)))"

GkmDataResult
gkm_data_der_read_public_key_dsa (GBytes *data,
                                  gcry_sexp_t *s_key)
{
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	GNode *asn = NULL;
	gcry_mpi_t p, q, g, y;
	int res;

	p = q = g = y = NULL;

	asn = egg_asn1x_create_and_decode (pk_asn1_tab, "DSAPublicKey", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (!gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "p", NULL), &p) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "q", NULL), &q) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "g", NULL), &g) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "Y", NULL), &y))
		goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_DSA, p, q, g, y);
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);

	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid public DSA key");

	return ret;
}

GkmDataResult
gkm_data_der_read_public_key_dsa_parts (GBytes *keydata,
                                        GBytes *params,
                                        gcry_sexp_t *s_key)
{
	gcry_mpi_t p, q, g, y;
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	GNode *asn_params = NULL;
	GNode *asn_key = NULL;
	int res;

	p = q = g = y = NULL;

	asn_params = egg_asn1x_create_and_decode (pk_asn1_tab, "DSAParameters", params);
	asn_key = egg_asn1x_create_and_decode (pk_asn1_tab, "DSAPublicPart", keydata);
	if (!asn_params || !asn_key)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (!gkm_data_asn1_read_mpi (egg_asn1x_node (asn_params, "p", NULL), &p) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn_params, "q", NULL), &q) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn_params, "g", NULL), &g))
		goto done;

	if (!gkm_data_asn1_read_mpi (asn_key, &y))
		goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_DSA, p, q, g, y);
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn_key);
	egg_asn1x_destroy (asn_params);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);

	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid DSA key");

	return ret;
}

#define SEXP_PRIVATE_DSA  \
	"(private-key"   \
	"  (dsa"         \
	"    (p %m)"     \
	"    (q %m)"     \
	"    (g %m)"     \
	"    (y %m)"     \
	"    (x %m)))"

GkmDataResult
gkm_data_der_read_private_key_dsa (GBytes *data,
                                   gcry_sexp_t *s_key)
{
	gcry_mpi_t p, q, g, y, x;
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	int res;
	GNode *asn = NULL;

	p = q = g = y = x = NULL;

	asn = egg_asn1x_create_and_decode (pk_asn1_tab, "DSAPrivateKey", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (!gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "p", NULL), &p) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "q", NULL), &q) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "g", NULL), &g) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "Y", NULL), &y) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn, "priv", NULL), &x))
		goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PRIVATE_DSA, p, q, g, y, x);
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (x);

	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid DSA key");

	return ret;
}

GkmDataResult
gkm_data_der_read_private_key_dsa_parts (GBytes *keydata,
                                         GBytes *params,
                                         gcry_sexp_t *s_key)
{
	gcry_mpi_t p, q, g, y, x;
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	int res;
	GNode *asn_params = NULL;
	GNode *asn_key = NULL;

	p = q = g = y = x = NULL;

	asn_params = egg_asn1x_create_and_decode (pk_asn1_tab, "DSAParameters", params);
	asn_key = egg_asn1x_create_and_decode (pk_asn1_tab, "DSAPrivatePart", keydata);
	if (!asn_params || !asn_key)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (!gkm_data_asn1_read_mpi (egg_asn1x_node (asn_params, "p", NULL), &p) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn_params, "q", NULL), &q) ||
	    !gkm_data_asn1_read_mpi (egg_asn1x_node (asn_params, "g", NULL), &g))
		goto done;

	if (!gkm_data_asn1_read_mpi (asn_key, &x))
		goto done;

	/* Now we calculate y */
	y = gcry_mpi_snew (1024);
	gcry_mpi_powm (y, g, x, p);

	res = gcry_sexp_build (s_key, NULL, SEXP_PRIVATE_DSA, p, q, g, y, x);
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn_key);
	egg_asn1x_destroy (asn_params);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (x);

	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid DSA key");

	return ret;
}

#define SEXP_PUBLIC_ECDSA  \
	"(public-key"   \
	"  (ecdsa"         \
	"    (curve %s)"     \
	"    (q %b)))"

GkmDataResult
gkm_data_der_read_public_key_ecdsa (GBytes *data,
                                     gcry_sexp_t *s_key)
{
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	int res;
	GNode *asn = NULL;
	GBytes *q = NULL;
	gsize q_bits;
	GQuark oid;
	const gchar *curve = NULL;

	init_quarks ();

	asn = egg_asn1x_create_and_decode (pk_asn1_tab, "ECPublicKey", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (!gkm_data_asn1_read_oid (egg_asn1x_node (asn, "parameters", "namedCurve", NULL), &oid) ||
	    !gkm_data_asn1_read_bit_string (egg_asn1x_node (asn, "q", NULL), &q, &q_bits))
		goto done;

	curve = gkm_data_der_oid_to_curve (oid);
	if (curve == NULL)
		goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_ECDSA,
                               curve,
                               g_bytes_get_size(q), g_bytes_get_data(q, NULL));
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn);
	g_bytes_unref (q);

	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid ECDSA key");

	return ret;
}

#define SEXP_PRIVATE_ECDSA  \
	"(private-key"   \
	"  (ecdsa"         \
	"    (curve %s)"     \
	"    (q %b)"     \
	"    (d %m)))"

GkmDataResult
gkm_data_der_read_private_key_ecdsa (GBytes *data,
                                     gcry_sexp_t *s_key)
{
	gcry_mpi_t d = NULL;
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	int res;
	GNode *asn = NULL;
	GBytes *q = NULL;
	gsize q_bits;
	GQuark oid;
	const gchar *curve = NULL;

	init_quarks ();

	asn = egg_asn1x_create_and_decode (pk_asn1_tab, "ECPrivateKey", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (!gkm_data_asn1_read_string_mpi (egg_asn1x_node (asn, "d", NULL), &d) ||
	    !gkm_data_asn1_read_oid (egg_asn1x_node (asn, "parameters", "namedCurve", NULL), &oid) ||
	    !gkm_data_asn1_read_bit_string (egg_asn1x_node (asn, "q", NULL), &q, &q_bits))
		goto done;

	curve = gkm_data_der_oid_to_curve (oid);
	if (curve == NULL)
		goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PRIVATE_ECDSA,
                               curve,
                               g_bytes_get_size(q), g_bytes_get_data(q, NULL), d);
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (d);
	g_bytes_unref (q);

	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid ECDSA key");

	return ret;
}

GkmDataResult
gkm_data_der_read_public_key (GBytes *data, gcry_sexp_t *s_key)
{
	GkmDataResult res;

	res = gkm_data_der_read_public_key_rsa (data, s_key);
	if (res == GKM_DATA_UNRECOGNIZED)
		res = gkm_data_der_read_public_key_ecdsa (data, s_key);
	if (res == GKM_DATA_UNRECOGNIZED)
		res = gkm_data_der_read_public_key_dsa (data, s_key);

	return res;
}

GkmDataResult
gkm_data_der_read_public_key_info (GBytes *data,
                                   gcry_sexp_t* s_key)
{
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	GQuark oid;
	GNode *asn = NULL;
	GBytes *params;
	GBytes *key = NULL;
	guint n_bits;

	init_quarks ();

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "SubjectPublicKeyInfo", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	/* Figure out the algorithm */
	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "algorithm", "algorithm", NULL));
	if (!oid)
		goto done;

	/* A bit string so we cannot process in place */
	key = egg_asn1x_get_bits_as_raw (egg_asn1x_node (asn, "subjectPublicKey", NULL), &n_bits);
	if (!key)
		goto done;
	if (n_bits % 8 != 0) {
		g_message ("invalid bit length for public key: %u", n_bits);
		goto done;
	}

	/* An RSA key is simple */
	if (oid == OID_PKIX1_RSA) {
		ret = gkm_data_der_read_public_key_rsa (key, s_key);

	/* A DSA key paramaters are stored separately */
	} else if (oid == OID_PKIX1_DSA) {
		params = egg_asn1x_get_element_raw (egg_asn1x_node (asn, "algorithm", "parameters", NULL));
		if (!params)
			goto done;
		ret = gkm_data_der_read_public_key_dsa_parts (key, params, s_key);
		g_bytes_unref (params);

	/* A ECDSA key */
	} else if (oid == OID_PKIX1_ECDSA) {
		ret = gkm_data_der_read_public_key_ecdsa (key, s_key);

	} else {
		g_message ("unsupported key algorithm in certificate: %s", g_quark_to_string (oid));
		ret = GKM_DATA_UNRECOGNIZED;
		goto done;
	}

done:
	egg_asn1x_destroy (asn);
	if (key)
		g_bytes_unref (key);

	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid subject public-key info");

	return ret;
}

GkmDataResult
gkm_data_der_read_private_key (GBytes *data,
                               gcry_sexp_t *s_key)
{
	GkmDataResult res;

	res = gkm_data_der_read_private_key_rsa (data, s_key);
	if (res == GKM_DATA_UNRECOGNIZED)
		res = gkm_data_der_read_private_key_dsa (data, s_key);
	if (res == GKM_DATA_UNRECOGNIZED)
		res = gkm_data_der_read_private_key_ecdsa (data, s_key);

	return res;
}

GkmDataResult
gkm_data_der_read_private_pkcs8_plain (GBytes *data,
                                       gcry_sexp_t *s_key)
{
	GNode *asn = NULL;
	GkmDataResult ret;
	int algorithm;
	GQuark key_algo;
	GBytes *keydata = NULL;
	GBytes *params = NULL;

	ret = GKM_DATA_UNRECOGNIZED;

	init_quarks ();

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "pkcs-8-PrivateKeyInfo", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;
	algorithm = 0;

	key_algo = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "privateKeyAlgorithm", "algorithm", NULL));
	if (!key_algo)
		goto done;
	else if (key_algo == OID_PKIX1_RSA)
		algorithm = GCRY_PK_RSA;
	else if (key_algo == OID_PKIX1_DSA)
		algorithm = GCRY_PK_DSA;
	else if (key_algo == OID_PKIX1_ECDSA)
		algorithm = GCRY_PK_ECC;

	if (!algorithm) {
		ret = GKM_DATA_UNRECOGNIZED;
		goto done;
	}

	keydata = egg_asn1x_get_string_as_bytes (egg_asn1x_node (asn, "privateKey", NULL));
	if (!keydata)
		goto done;

	params = egg_asn1x_get_element_raw (egg_asn1x_node (asn, "privateKeyAlgorithm", "parameters", NULL));

	ret = GKM_DATA_SUCCESS;

done:
	if (ret == GKM_DATA_SUCCESS) {
		switch (algorithm) {
		case GCRY_PK_RSA:
			ret = gkm_data_der_read_private_key_rsa (keydata, s_key);
			break;
		case GCRY_PK_DSA:
			/* Try the normal one block format */
			ret = gkm_data_der_read_private_key_dsa (keydata, s_key);

			/* Otherwise try the two part format that everyone seems to like */
			if (ret == GKM_DATA_UNRECOGNIZED && params)
				ret = gkm_data_der_read_private_key_dsa_parts (keydata, params, s_key);
			break;
		case GCRY_PK_ECC:
			ret = gkm_data_der_read_private_key_ecdsa (keydata, s_key);
			break;
		default:
			g_message ("invalid or unsupported key type in PKCS#8 key");
			ret = GKM_DATA_UNRECOGNIZED;
			break;
		};

	} else if (ret == GKM_DATA_FAILURE) {
		g_message ("invalid PKCS#8 key");
	}

	if (params)
		g_bytes_unref (params);
	if (keydata)
		g_bytes_unref (keydata);
	egg_asn1x_destroy (asn);
	return ret;
}

GkmDataResult
gkm_data_der_read_private_pkcs8_crypted (GBytes *data,
                                         const gchar *password,
                                         gsize n_password,
                                         gcry_sexp_t *s_key)
{
	GNode *asn = NULL;
	gcry_cipher_hd_t cih = NULL;
	gcry_error_t gcry;
	GkmDataResult ret, r;
	GQuark scheme;
	guchar *crypted = NULL;
	GNode *params;
	GBytes *bytes;
	gsize n_crypted;
	gint l;

	init_quarks ();

	ret = GKM_DATA_UNRECOGNIZED;

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "pkcs-8-EncryptedPrivateKeyInfo", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	/* Figure out the type of encryption */
	scheme = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "encryptionAlgorithm", "algorithm", NULL));
	if (!scheme)
		goto done;

	params = egg_asn1x_node (asn, "encryptionAlgorithm", "parameters", NULL);
	if (!params)
		goto done;

	/*
	 * Parse the encryption stuff into a cipher.
	 */
	r = egg_symkey_read_cipher (scheme, password, n_password, params, &cih);

	if (r == GKM_DATA_UNRECOGNIZED) {
		ret = GKM_DATA_FAILURE;
		goto done;
	} else if (r != GKM_DATA_SUCCESS) {
		ret = r;
		goto done;
	}

	crypted = egg_asn1x_get_string_as_raw (egg_asn1x_node (asn, "encryptedData", NULL),
	                                       egg_secure_realloc, &n_crypted);
	if (!crypted)
		goto done;

	gcry = gcry_cipher_decrypt (cih, crypted, n_crypted, NULL, 0);
	gcry_cipher_close (cih);
	cih = NULL;

	if (gcry != 0) {
		g_warning ("couldn't decrypt pkcs8 data: %s", gcry_strerror (gcry));
		goto done;
	}

	/* Unpad the DER data */
	l = egg_asn1x_element_length (crypted, n_crypted);
	if (l <= 0 || l > n_crypted) {
		ret = GKM_DATA_LOCKED;
		goto done;
	}
	n_crypted = l;

	bytes = g_bytes_new_with_free_func (crypted, n_crypted, egg_secure_free, crypted);
	crypted = NULL;

	/* Try to parse the resulting key */
	ret = gkm_data_der_read_private_pkcs8_plain (bytes, s_key);
	g_bytes_unref (bytes);

	/* If unrecognized we assume bad password */
	if (ret == GKM_DATA_UNRECOGNIZED)
		ret = GKM_DATA_LOCKED;

done:
	if (cih)
		gcry_cipher_close (cih);
	egg_asn1x_destroy (asn);
	egg_secure_free (crypted);

	return ret;
}

GkmDataResult
gkm_data_der_read_private_pkcs8 (GBytes *data,
                                 const gchar *password,
                                 gsize n_password,
                                 gcry_sexp_t *s_key)
{
	GkmDataResult res;

	res = gkm_data_der_read_private_pkcs8_crypted (data, password, n_password, s_key);
	if (res == GKM_DATA_UNRECOGNIZED)
		res = gkm_data_der_read_private_pkcs8_plain (data, s_key);

	return res;
}

GBytes *
gkm_data_der_write_public_key_rsa (gcry_sexp_t s_key)
{
	GNode *asn = NULL;
	gcry_mpi_t n, e;
	GBytes *result = NULL;

	n = e = NULL;

	asn = egg_asn1x_create (pk_asn1_tab, "RSAPublicKey");
	g_return_val_if_fail (asn, NULL);

	if (!gkm_sexp_extract_mpi (s_key, &n, "rsa", "n", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &e, "rsa", "e", NULL))
		goto done;

	if (!gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "modulus", NULL), n) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "publicExponent", NULL), e))
		goto done;

	result = egg_asn1x_encode (asn, NULL);
	if (result == NULL)
		g_warning ("couldn't encode public rsa key: %s", egg_asn1x_message (asn));

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);

	return result;
}

GBytes *
gkm_data_der_write_private_key_rsa (gcry_sexp_t s_key)
{
	GNode *asn = NULL;
	gcry_mpi_t n, e, d, p, q, u, e1, e2, tmp;
	GBytes *result = NULL;

	n = e = d = p = q = u = e1 = e2 = tmp = NULL;

	asn = egg_asn1x_create (pk_asn1_tab, "RSAPrivateKey");
	g_return_val_if_fail (asn, NULL);

	if (!gkm_sexp_extract_mpi (s_key, &n, "rsa", "n", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &e, "rsa", "e", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &d, "rsa", "d", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &p, "rsa", "p", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &q, "rsa", "q", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &u, "rsa", "u", NULL))
		goto done;

	if (!gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "modulus", NULL), n) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "publicExponent", NULL), e) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "privateExponent", NULL), d) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "prime1", NULL), p) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "prime2", NULL), q) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "coefficient", NULL), u))
		goto done;

	/* Calculate e1 and e2 */
	tmp = gcry_mpi_snew (1024);
	gcry_mpi_sub_ui (tmp, p, 1);
	e1 = gcry_mpi_snew (1024);
	gcry_mpi_mod (e1, d, tmp);
	gcry_mpi_sub_ui (tmp, q, 1);
	e2 = gcry_mpi_snew (1024);
	gcry_mpi_mod (e2, d, tmp);

	/* Write out calculated */
	if (!gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "exponent1", NULL), e1) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "exponent2", NULL), e2))
		goto done;

	/* Write out the version */
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "version", NULL), 0);

	result = egg_asn1x_encode (asn, egg_secure_realloc);
	if (result == NULL)
		g_warning ("couldn't encode private rsa key: %s", egg_asn1x_message (asn));

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	gcry_mpi_release (d);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (u);

	gcry_mpi_release (tmp);
	gcry_mpi_release (e1);
	gcry_mpi_release (e2);

	return result;
}

GBytes *
gkm_data_der_write_public_key_dsa (gcry_sexp_t s_key)
{
	GNode *asn = NULL;
	gcry_mpi_t p, q, g, y;
	GBytes *result = NULL;

	p = q = g = y = NULL;

	asn = egg_asn1x_create (pk_asn1_tab, "DSAPublicKey");
	g_return_val_if_fail (asn, NULL);

	if (!gkm_sexp_extract_mpi (s_key, &p, "dsa", "p", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &q, "dsa", "q", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &g, "dsa", "g", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &y, "dsa", "y", NULL))
		goto done;

	if (!gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "p", NULL), p) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "q", NULL), q) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "g", NULL), g) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "Y", NULL), y))
		goto done;

	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "version", NULL), 0);

	result = egg_asn1x_encode (asn, NULL);
	if (result == NULL)
		g_warning ("couldn't encode public dsa key: %s", egg_asn1x_message (asn));

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);

	return result;
}

GBytes *
gkm_data_der_write_private_key_dsa_part (gcry_sexp_t skey)
{
	GNode *asn = NULL;
	gcry_mpi_t x;
	GBytes *result = NULL;

	x = NULL;

	asn = egg_asn1x_create (pk_asn1_tab, "DSAPrivatePart");
	g_return_val_if_fail (asn, NULL);

	if (!gkm_sexp_extract_mpi (skey, &x, "dsa", "x", NULL))
		goto done;

	if (!gkm_data_asn1_write_mpi (asn, x))
		goto done;

	result = egg_asn1x_encode (asn, egg_secure_realloc);
	if (result == NULL)
		g_warning ("couldn't encode private dsa key: %s", egg_asn1x_message (asn));

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (x);

	return result;
}

GBytes *
gkm_data_der_write_private_key_dsa_params (gcry_sexp_t skey)
{
	GNode *asn = NULL;
	gcry_mpi_t p, q, g;
	GBytes *result = NULL;

	p = q = g = NULL;

	asn = egg_asn1x_create (pk_asn1_tab, "DSAParameters");
	g_return_val_if_fail (asn, NULL);

	if (!gkm_sexp_extract_mpi (skey, &p, "dsa", "p", NULL) ||
	    !gkm_sexp_extract_mpi (skey, &q, "dsa", "q", NULL) ||
	    !gkm_sexp_extract_mpi (skey, &g, "dsa", "g", NULL))
		goto done;

	if (!gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "p", NULL), p) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "q", NULL), q) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "g", NULL), g))
		goto done;

	result = egg_asn1x_encode (asn, egg_secure_realloc);
	if (result == NULL)
		g_warning ("couldn't encode private dsa params: %s", egg_asn1x_message (asn));

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);

	return result;
}

GBytes *
gkm_data_der_write_private_key_dsa (gcry_sexp_t s_key)
{
	GNode *asn = NULL;
	gcry_mpi_t p, q, g, y, x;
	GBytes *result = NULL;

	p = q = g = y = x = NULL;

	asn = egg_asn1x_create (pk_asn1_tab, "DSAPrivateKey");
	g_return_val_if_fail (asn, NULL);

	if (!gkm_sexp_extract_mpi (s_key, &p, "dsa", "p", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &q, "dsa", "q", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &g, "dsa", "g", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &y, "dsa", "y", NULL) ||
	    !gkm_sexp_extract_mpi (s_key, &x, "dsa", "x", NULL))
		goto done;

	if (!gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "p", NULL), p) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "q", NULL), q) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "g", NULL), g) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "Y", NULL), y) ||
	    !gkm_data_asn1_write_mpi (egg_asn1x_node (asn, "priv", NULL), x))
		goto done;

	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "version", NULL), 0);

	result = egg_asn1x_encode (asn, egg_secure_realloc);
	if (result == NULL)
		g_warning ("couldn't encode private dsa key: %s", egg_asn1x_message (asn));

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (x);

	return result;
}

GBytes *
gkm_data_der_write_public_key_ecdsa (gcry_sexp_t s_key)
{
	GNode *asn = NULL, *named_curve;
	gcry_mpi_t d = NULL;
	GBytes *result = NULL, *q = NULL;
	gchar *q_data = NULL;
	GQuark oid;
	gchar *curve = NULL;
	gsize q_size;

	init_quarks ();

	asn = egg_asn1x_create (pk_asn1_tab, "ECPublicKey");
	g_return_val_if_fail (asn, NULL);

	if (!gkm_sexp_extract_buffer (s_key, &q_data, &q_size, "ecdsa", "q", NULL) ||
	    !gkm_sexp_extract_string (s_key, &curve, "ecdsa", "curve", NULL))
		goto done;

	oid = gkm_data_der_curve_to_oid (curve);
	g_free (curve);
	if (oid == 0)
		goto done;

	q = g_bytes_new_take (q_data, q_size);
	if (q == NULL)
		goto done;

	named_curve = egg_asn1x_node (asn, "parameters", "namedCurve", NULL);

	/* XXX the bit size does not have to match byte size * 8 exactly
	 * it would be good to cover this with more tests
	 */
	if (!gkm_data_asn1_write_bit_string (egg_asn1x_node (asn, "q", NULL), q, q_size*8) ||
	    !gkm_data_asn1_write_oid (named_curve, oid))
		goto done;

	if (!egg_asn1x_set_choice (egg_asn1x_node (asn, "parameters", NULL), named_curve))
		goto done;

	result = egg_asn1x_encode (asn, egg_secure_realloc);
	if (result == NULL)
		g_warning ("couldn't encode public ecdsa key: %s", egg_asn1x_message (asn));

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (d);
	g_bytes_unref (q);

	return result;
}

GBytes *
gkm_data_der_write_private_key_ecdsa (gcry_sexp_t s_key)
{
	GNode *asn = NULL, *named_curve;
	gcry_mpi_t d = NULL;
	GBytes *result = NULL, *q = NULL;
	gchar *q_data = NULL;
	GQuark oid;
	gchar *curve = NULL;
	gsize q_size;

	init_quarks ();

	asn = egg_asn1x_create (pk_asn1_tab, "ECPrivateKey");
	g_return_val_if_fail (asn, NULL);

	if (!gkm_sexp_extract_mpi (s_key, &d, "ecdsa", "d", NULL) ||
	    !gkm_sexp_extract_buffer (s_key, &q_data, &q_size, "ecdsa", "q", NULL) ||
	    !gkm_sexp_extract_string (s_key, &curve, "ecdsa", "curve", NULL))
		goto done;

	oid = gkm_data_der_curve_to_oid (curve);
	g_free (curve);
	if (oid == 0)
		goto done;

	q = g_bytes_new_take (q_data, q_size);
	if (q == NULL)
		goto done;

	named_curve = egg_asn1x_node (asn, "parameters", "namedCurve", NULL);

	if (!gkm_data_asn1_write_string_mpi (egg_asn1x_node (asn, "d", NULL), d) ||
	    !gkm_data_asn1_write_bit_string (egg_asn1x_node (asn, "q", NULL), q, q_size*8) ||
	    !gkm_data_asn1_write_oid (named_curve, oid))
		goto done;

	if (!egg_asn1x_set_choice (egg_asn1x_node (asn, "parameters", NULL), named_curve))
		goto done;

	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "version", NULL), 1);

	result = egg_asn1x_encode (asn, egg_secure_realloc);
	if (result == NULL)
		g_warning ("couldn't encode private ecdsa key: %s", egg_asn1x_message (asn));

done:
	egg_asn1x_destroy (asn);
	gcry_mpi_release (d);
	g_bytes_unref (q);

	return result;
}

GBytes *
gkm_data_der_write_public_key (gcry_sexp_t s_key)
{
	gboolean is_priv;
	int algorithm;

	g_return_val_if_fail (s_key != NULL, NULL);

	if (!gkm_sexp_parse_key (s_key, &algorithm, &is_priv, NULL))
		g_return_val_if_reached (NULL);

	g_return_val_if_fail (!is_priv, NULL);

	switch (algorithm) {
	case GCRY_PK_RSA:
		return gkm_data_der_write_public_key_rsa (s_key);
	case GCRY_PK_DSA:
		return gkm_data_der_write_public_key_dsa (s_key);
	case GCRY_PK_ECC:
		return gkm_data_der_write_public_key_ecdsa (s_key);
	default:
		g_return_val_if_reached (NULL);
	}
}

GBytes *
gkm_data_der_write_private_key (gcry_sexp_t s_key)
{
	gboolean is_priv;
	int algorithm;

	g_return_val_if_fail (s_key != NULL, NULL);

	if (!gkm_sexp_parse_key (s_key, &algorithm, &is_priv, NULL))
		g_return_val_if_reached (NULL);

	g_return_val_if_fail (is_priv, NULL);

	switch (algorithm) {
	case GCRY_PK_RSA:
		return gkm_data_der_write_private_key_rsa (s_key);
	case GCRY_PK_DSA:
		return gkm_data_der_write_private_key_dsa (s_key);
	case GCRY_PK_ECC:
		return gkm_data_der_write_private_key_ecdsa (s_key);
	default:
		g_return_val_if_reached (NULL);
	}
}

static gcry_cipher_hd_t
prepare_and_encode_pkcs8_cipher (GNode *asn, const gchar *password,
                                 gsize n_password, gsize *n_block)
{
	GNode *asn1_params = NULL;
	gcry_cipher_hd_t cih;
	guchar *salt;
	gsize n_salt;
	gcry_error_t gcry;
	guchar *key, *iv;
	gsize n_key;
	int iterations;

	init_quarks ();

	/* Make sure the encryption algorithm works */
	g_return_val_if_fail (gcry_cipher_algo_info (gcry_cipher_map_name (g_quark_to_string (OID_PKCS12_PBE_3DES_SHA1)),
	                                             GCRYCTL_TEST_ALGO, NULL, 0) == 0, NULL);

	/* The encryption algorithm */
	if(!egg_asn1x_set_oid_as_quark (egg_asn1x_node (asn, "encryptionAlgorithm", "algorithm", NULL),
	                                OID_PKCS12_PBE_3DES_SHA1))
		g_return_val_if_reached (NULL);

	/* Randomize some input for the password based secret */
	iterations = g_random_int_range (1000, 4096);
	n_salt = 8;
	salt = g_malloc (n_salt);
	gcry_create_nonce (salt, n_salt);

	/* Allocate space for the key and iv */
	n_key = gcry_cipher_get_algo_keylen (GCRY_CIPHER_3DES);
	*n_block = gcry_cipher_get_algo_blklen (GCRY_MD_SHA1);
	g_return_val_if_fail (n_key && *n_block, NULL);

	if (!egg_symkey_generate_pkcs12 (GCRY_CIPHER_3DES, GCRY_MD_SHA1,
	                                        password, n_password, salt,
	                                        sizeof (salt), iterations, &key, &iv))
		g_return_val_if_reached (NULL);

	/* Now write out the parameters */
	asn1_params = egg_asn1x_create (pkix_asn1_tab, "pkcs-12-PbeParams");
	g_return_val_if_fail (asn1_params, NULL);
	egg_asn1x_set_string_as_raw (egg_asn1x_node (asn1_params, "salt", NULL), salt, n_salt, g_free);
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn1_params, "iterations", NULL), iterations);
	egg_asn1x_set_any_from (egg_asn1x_node (asn, "encryptionAlgorithm", "parameters", NULL), asn1_params);

	/* Now make a cipher that matches what we wrote out */
	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
	g_return_val_if_fail (gcry == 0, NULL);
	g_return_val_if_fail (cih, NULL);

	gcry_cipher_setiv (cih, iv, *n_block);
	gcry_cipher_setkey (cih, key, n_key);

	g_free (iv);
	egg_secure_free (key);
	egg_asn1x_destroy (asn1_params);

	return cih;
}

GBytes *
gkm_data_der_write_private_pkcs8_plain (gcry_sexp_t skey)
{
	GNode *asn = NULL;
	int algorithm;
	gboolean is_priv;
	GQuark oid;
	GBytes *params;
	GBytes *key;
	GBytes *data;

	init_quarks ();

	/* Parse and check that the key is for real */
	if (!gkm_sexp_parse_key (skey, &algorithm, &is_priv, NULL))
		g_return_val_if_reached (NULL);
	g_return_val_if_fail (is_priv == TRUE, NULL);

	asn = egg_asn1x_create (pkix_asn1_tab, "pkcs-8-PrivateKeyInfo");
	g_return_val_if_fail (asn, NULL);

	/* Write out the version */
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (asn, "version", NULL), 0);

	/* Per algorithm differences */
	switch (algorithm)
	{
	/* RSA gets encoded in a standard simple way */
	case GCRY_PK_RSA:
		oid = OID_PKIX1_RSA;
		params = NULL;
		key = gkm_data_der_write_private_key_rsa (skey);
		break;

	/* DSA gets incoded with the params seperate */
	case GCRY_PK_DSA:
		oid = OID_PKIX1_DSA;
		key = gkm_data_der_write_private_key_dsa_part (skey);
		params = gkm_data_der_write_private_key_dsa_params (skey);
		break;

	case GCRY_PK_ECC:
		oid = OID_PKIX1_ECDSA;
		params = NULL;
		key = gkm_data_der_write_private_key_ecdsa (skey);
		break;

	default:
		g_warning ("trying to serialize unsupported private key algorithm: %d", algorithm);
		return NULL;
	};

	/* Write out the algorithm */
	if (!egg_asn1x_set_oid_as_quark (egg_asn1x_node (asn, "privateKeyAlgorithm", "algorithm", NULL), oid))
		g_return_val_if_reached (NULL);

	/* Write out the parameters */
	if (params) {
		egg_asn1x_set_any_raw (egg_asn1x_node (asn, "privateKeyAlgorithm", "parameters", NULL), params);
		g_bytes_unref (params);
	}

	/* Write out the key portion */
	egg_asn1x_set_string_as_bytes (egg_asn1x_node (asn, "privateKey", NULL), key);
	g_bytes_unref (key);

	data = egg_asn1x_encode (asn, egg_secure_realloc);
	if (data == NULL)
		g_warning ("couldn't encode private pkcs8 key: %s", egg_asn1x_message (asn));

	egg_asn1x_destroy (asn);
	return data;
}

GBytes *
gkm_data_der_write_private_pkcs8_crypted (gcry_sexp_t skey,
                                          const gchar *password,
                                          gsize n_password)
{
	gcry_error_t gcry;
	gcry_cipher_hd_t cih;
	GNode *asn = NULL;
	GBytes *key, *data;
	guchar *raw;
	gsize n_raw, n_key;
	gsize block = 0;

	/* Encode the key in normal pkcs8 fashion */
	key = gkm_data_der_write_private_pkcs8_plain (skey);
	if (key == NULL)
		return NULL;

	asn = egg_asn1x_create (pkix_asn1_tab, "pkcs-8-EncryptedPrivateKeyInfo");
	g_return_val_if_fail (asn, NULL);

	/* Create a and write out a cipher used for encryption */
	cih = prepare_and_encode_pkcs8_cipher (asn, password, n_password, &block);
	g_return_val_if_fail (cih, NULL);

	n_key = g_bytes_get_size (key);

	/* Pad the block of data */
	if(block > 1) {
		gsize n_pad = block - (n_key % block);
		if (n_pad == 0)
			n_pad = block;
		raw = egg_secure_alloc (n_key + n_pad);
		memcpy (raw, g_bytes_get_data (key, NULL), n_key);
		memset (raw + n_key, (int)n_pad, n_pad);
		n_raw = n_key + n_pad;

	/* No padding, probably stream cipher */
	} else {
		raw = egg_secure_alloc (n_key);
		memcpy (raw, g_bytes_get_data (key, NULL), n_key);
		n_raw = n_key;
	}

	g_bytes_unref (key);

	gcry = gcry_cipher_encrypt (cih, raw, n_raw, NULL, 0);
	g_return_val_if_fail (gcry == 0, NULL);

	gcry_cipher_close (cih);
	key = g_bytes_new_with_free_func (raw, n_raw, egg_secure_free, raw);

	egg_asn1x_set_string_as_bytes (egg_asn1x_node (asn, "encryptedData", NULL), key);

	g_bytes_unref (key);

	data = egg_asn1x_encode (asn, NULL);
	if (data == NULL)
		g_warning ("couldn't encode encrypted pkcs8 key: %s", egg_asn1x_message (asn));

	egg_asn1x_destroy (asn);
	return data;
}

/* -----------------------------------------------------------------------------
 * CERTIFICATES
 */

GkmDataResult
gkm_data_der_read_certificate (GBytes *data,
                               GNode **asn1)
{
	*asn1 = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate", data);
	if (!*asn1)
		return GKM_DATA_UNRECOGNIZED;

	return GKM_DATA_SUCCESS;
}

GkmDataResult
gkm_data_der_read_basic_constraints (GBytes *data,
                                     gboolean *is_ca,
                                     gint *path_len)
{
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	GNode *asn = NULL;
	GNode *node;
	gulong value;

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "BasicConstraints", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (path_len) {
		node = egg_asn1x_node (asn, "pathLenConstraint", NULL);
		if (!egg_asn1x_have (node))
			*path_len = -1;
		else if (!egg_asn1x_get_integer_as_ulong (node, &value))
			goto done;
		else
			*path_len = value;
	}

	if (is_ca) {
		node = egg_asn1x_node (asn, "cA", NULL);
		if (!egg_asn1x_have (node))
			*is_ca = FALSE;
		else if (!egg_asn1x_get_boolean (node, is_ca))
			goto done;
	}

	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn);
	if (ret == GKM_DATA_FAILURE)
		g_message ("invalid basic constraints");

	return ret;
}

GkmDataResult
gkm_data_der_read_key_usage (GBytes *data,
                             gulong *key_usage)
{
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	GNode *asn = NULL;
	guint n_bits;

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "KeyUsage", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	if (!egg_asn1x_get_bits_as_ulong (asn, key_usage, &n_bits))
		goto done;

	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn);
	return ret;
}

GkmDataResult
gkm_data_der_read_enhanced_usage (GBytes *data,
                                  GQuark **usage_oids)
{
	GkmDataResult ret = GKM_DATA_UNRECOGNIZED;
	GNode *asn = NULL;
	GNode *node;
	GArray *array;
	GQuark oid;
	int i;

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "ExtKeyUsageSyntax", data);
	if (!asn)
		goto done;

	ret = GKM_DATA_FAILURE;

	array = g_array_new (TRUE, TRUE, sizeof (GQuark));
	for (i = 0; TRUE; ++i) {
		node = egg_asn1x_node (asn, i + 1, NULL);
		if (node == NULL)
			break;

		oid = egg_asn1x_get_oid_as_quark (node);
		g_array_append_val (array, oid);
	}

	*usage_oids = (GQuark*)g_array_free (array, FALSE);
	ret = GKM_DATA_SUCCESS;

done:
	egg_asn1x_destroy (asn);
	return ret;
}


GBytes *
gkm_data_der_write_certificate (GNode *asn1)
{
	GBytes *result;

	g_return_val_if_fail (asn1, NULL);

	result = egg_asn1x_encode (asn1, NULL);
	if (result == NULL)
		g_warning ("couldn't encode certificate: %s", egg_asn1x_message (asn1));

	return result;
}
