/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-der.c - parsing and serializing of common crypto DER structures 

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

#include "gkr-pkix-asn1.h"
#include "gkr-pkix-der.h"

#include "common/gkr-crypto.h"
#include "common/gkr-secure-memory.h"

#include <glib.h>
#include <gcrypt.h>
#include <libtasn1.h>

/* -----------------------------------------------------------------------------
 * QUARKS
 */

static gboolean quarks_inited = FALSE;

static GQuark OID_PKIX1_RSA;
static GQuark OID_PKIX1_DSA;

static GQuark OID_PBE_MD2_DES_CBC;
static GQuark OID_PBE_MD5_DES_CBC;
static GQuark OID_PBE_MD2_RC2_CBC;
static GQuark OID_PBE_MD5_RC2_CBC;
static GQuark OID_PBE_SHA1_DES_CBC;
static GQuark OID_PBE_SHA1_RC2_CBC;
static GQuark OID_PBES2;
static GQuark OID_PBKDF2;

static GQuark OID_DES_CBC;
static GQuark OID_DES_RC2_CBC;
static GQuark OID_DES_EDE3_CBC;
static GQuark OID_DES_RC5_CBC;

static GQuark OID_PKCS12_PBE_ARCFOUR_SHA1;
static GQuark OID_PKCS12_PBE_RC4_40_SHA1;
static GQuark OID_PKCS12_PBE_3DES_SHA1;
static GQuark OID_PKCS12_PBE_2DES_SHA1;
static GQuark OID_PKCS12_PBE_RC2_128_SHA1;
static GQuark OID_PKCS12_PBE_RC2_40_SHA1;

static void
init_quarks (void)
{
	if (quarks_inited)
		return;

	quarks_inited = TRUE;
	#define QUARK(name, value) \
		name = g_quark_from_static_string(value)

	QUARK (OID_PKIX1_RSA, "1.2.840.113549.1.1.1");
	QUARK (OID_PKIX1_DSA, "1.2.840.10040.4.1");

	QUARK (OID_PBE_MD2_DES_CBC, "1.2.840.113549.1.5.1");
	QUARK (OID_PBE_MD5_DES_CBC, "1.2.840.113549.1.5.3");
	QUARK (OID_PBE_MD2_RC2_CBC, "1.2.840.113549.1.5.4");
	QUARK (OID_PBE_MD5_RC2_CBC, "1.2.840.113549.1.5.6");
	QUARK (OID_PBE_SHA1_DES_CBC, "1.2.840.113549.1.5.10");
	QUARK (OID_PBE_SHA1_RC2_CBC, "1.2.840.113549.1.5.11");
	
	QUARK (OID_PBES2, "1.2.840.113549.1.5.13");
	
	QUARK (OID_PBKDF2, "1.2.840.113549.1.5.12");
	
	QUARK (OID_DES_CBC, "1.3.14.3.2.7");
	QUARK (OID_DES_RC2_CBC, "1.2.840.113549.3.2");
	QUARK (OID_DES_EDE3_CBC, "1.2.840.113549.3.7");
	QUARK (OID_DES_RC5_CBC, "1.2.840.113549.3.9");
	
	QUARK (OID_PKCS12_PBE_ARCFOUR_SHA1, "1.2.840.113549.1.12.1.1");
	QUARK (OID_PKCS12_PBE_RC4_40_SHA1, "1.2.840.113549.1.12.1.2");
	QUARK (OID_PKCS12_PBE_3DES_SHA1, "1.2.840.113549.1.12.1.3");
	QUARK (OID_PKCS12_PBE_2DES_SHA1, "1.2.840.113549.1.12.1.4");
	QUARK (OID_PKCS12_PBE_RC2_128_SHA1, "1.2.840.113549.1.12.1.5");
	QUARK (OID_PKCS12_PBE_RC2_40_SHA1, "1.2.840.113549.1.12.1.6");
	
	#undef QUARK
}

 
/* -----------------------------------------------------------------------------
 * KEY PARSING
 */

#define SEXP_PUBLIC_RSA  \
	"(public-key"    \
	"  (rsa"         \
	"    (n %m)"     \
	"    (e %m)))"

GkrParseResult
gkr_pkix_der_read_public_key_rsa (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t n, e;
	int res;

	n = e = NULL;
	
	asn = gkr_pkix_asn1_decode ("PK.RSAPublicKey", data, n_data);
	if (!asn)
		goto done;
		
	ret = GKR_PARSE_FAILURE;
    
	if (!gkr_pkix_asn1_read_mpi (asn, "modulus", &n) || 
	    !gkr_pkix_asn1_read_mpi (asn, "publicExponent", &e))
		goto done;
		
	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_RSA, n, e);
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GKR_PARSE_SUCCESS;

done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	
	if (ret == GKR_PARSE_FAILURE)
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

GkrParseResult
gkr_pkix_der_read_private_key_rsa (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	gcry_mpi_t n, e, d, p, q, u;
	gcry_mpi_t tmp;
	int res;
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;

	n = e = d = p = q = u = NULL;
	
	asn = gkr_pkix_asn1_decode ("PK.RSAPrivateKey", data, n_data);
	if (!asn)
		goto done;
		
	ret = GKR_PARSE_FAILURE;
    
	if (!gkr_pkix_asn1_read_mpi (asn, "modulus", &n) || 
	    !gkr_pkix_asn1_read_mpi (asn, "publicExponent", &e) ||
	    !gkr_pkix_asn1_read_mpi (asn, "privateExponent", &d) ||
	    !gkr_pkix_asn1_read_mpi (asn, "prime1", &p) ||
	    !gkr_pkix_asn1_read_mpi (asn, "prime2", &q) || 
	    !gkr_pkix_asn1_read_mpi (asn, "coefficient", &u))
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
	ret = GKR_PARSE_SUCCESS;

done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	gcry_mpi_release (d);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (u);
	
	if (ret == GKR_PARSE_FAILURE)
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

GkrParseResult
gkr_pkix_der_read_public_key_dsa (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t p, q, g, y;
	int res;

	p = q = g = y = NULL;
	
	asn = gkr_pkix_asn1_decode ("PK.DSAPublicKey", data, n_data);
	if (!asn)
		goto done;
	
	ret = GKR_PARSE_FAILURE;
    
	if (!gkr_pkix_asn1_read_mpi (asn, "p", &p) || 
	    !gkr_pkix_asn1_read_mpi (asn, "q", &q) ||
	    !gkr_pkix_asn1_read_mpi (asn, "g", &g) ||
	    !gkr_pkix_asn1_read_mpi (asn, "Y", &y))
	    	goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_DSA, p, q, g, y);
	if (res)
		goto done;
		
	g_assert (*s_key);
	ret = GKR_PARSE_SUCCESS;
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	
	if (ret == GKR_PARSE_FAILURE) 
		g_message ("invalid public DSA key");
		
	return ret;	
}

GkrParseResult
gkr_pkix_der_read_public_key_dsa_parts (const guchar *keydata, gsize n_keydata,
                                        const guchar *params, gsize n_params,
                                        gcry_sexp_t *s_key)
{
	gcry_mpi_t p, q, g, y;
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	ASN1_TYPE asn_params = ASN1_TYPE_EMPTY;
	ASN1_TYPE asn_key = ASN1_TYPE_EMPTY;
	int res;

	p = q = g = y = NULL;
	
	asn_params = gkr_pkix_asn1_decode ("PK.DSAParameters", params, n_params);
	asn_key = gkr_pkix_asn1_decode ("PK.DSAPublicPart", keydata, n_keydata);
	if (!asn_params || !asn_key)
		goto done;
	
	ret = GKR_PARSE_FAILURE;
    
	if (!gkr_pkix_asn1_read_mpi (asn_params, "p", &p) || 
	    !gkr_pkix_asn1_read_mpi (asn_params, "q", &q) ||
	    !gkr_pkix_asn1_read_mpi (asn_params, "g", &g))
	    	goto done;
	    	
	if (!gkr_pkix_asn1_read_mpi (asn_key, "", &y))
		goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_DSA, p, q, g, y);
	if (res)
		goto done;
		
	g_assert (*s_key);
	ret = GKR_PARSE_SUCCESS;
	
done:
	if (asn_key)
		asn1_delete_structure (&asn_key);
	if (asn_params)
		asn1_delete_structure (&asn_params);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	
	if (ret == GKR_PARSE_FAILURE) 
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

GkrParseResult
gkr_pkix_der_read_private_key_dsa (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	gcry_mpi_t p, q, g, y, x;
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	int res;
	ASN1_TYPE asn;

	p = q = g = y = x = NULL;
	
	asn = gkr_pkix_asn1_decode ("PK.DSAPrivateKey", data, n_data);
	if (!asn)
		goto done;
	
	ret = GKR_PARSE_FAILURE;
    
	if (!gkr_pkix_asn1_read_mpi (asn, "p", &p) || 
	    !gkr_pkix_asn1_read_mpi (asn, "q", &q) ||
	    !gkr_pkix_asn1_read_mpi (asn, "g", &g) ||
	    !gkr_pkix_asn1_read_mpi (asn, "Y", &y) ||
	    !gkr_pkix_asn1_read_mpi (asn, "priv", &x))
		goto done;
		
	res = gcry_sexp_build (s_key, NULL, SEXP_PRIVATE_DSA, p, q, g, y, x);
	if (res)
		goto done;
		
	g_assert (*s_key);
	ret = GKR_PARSE_SUCCESS;

done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (x);
	
	if (ret == GKR_PARSE_FAILURE) 
		g_message ("invalid DSA key");
		
	return ret;
}

GkrParseResult
gkr_pkix_der_read_private_key_dsa_parts (const guchar *keydata, gsize n_keydata,
                                         const guchar *params, gsize n_params, 
                                         gcry_sexp_t *s_key)
{
	gcry_mpi_t p, q, g, y, x;
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	int res;
	ASN1_TYPE asn_params = ASN1_TYPE_EMPTY;
	ASN1_TYPE asn_key = ASN1_TYPE_EMPTY;

	p = q = g = y = x = NULL;
	
	asn_params = gkr_pkix_asn1_decode ("PK.DSAParameters", params, n_params);
	asn_key = gkr_pkix_asn1_decode ("PK.DSAPrivatePart", keydata, n_keydata);
	if (!asn_params || !asn_key)
		goto done;
	
	ret = GKR_PARSE_FAILURE;
    
	if (!gkr_pkix_asn1_read_mpi (asn_params, "p", &p) || 
	    !gkr_pkix_asn1_read_mpi (asn_params, "q", &q) ||
	    !gkr_pkix_asn1_read_mpi (asn_params, "g", &g))
	    	goto done;
	    	
	if (!gkr_pkix_asn1_read_mpi (asn_key, "", &x))
		goto done;

	/* Now we calculate y */
	y = gcry_mpi_snew (1024);
  	gcry_mpi_powm (y, g, x, p);

	res = gcry_sexp_build (s_key, NULL, SEXP_PRIVATE_DSA, p, q, g, y, x);
	if (res)
		goto done;
		
	g_assert (*s_key);
	ret = GKR_PARSE_SUCCESS;
	
done:
	if (asn_key)
		asn1_delete_structure (&asn_key);
	if (asn_params)
		asn1_delete_structure (&asn_params);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (x);
	
	if (ret == GKR_PARSE_FAILURE) 
		g_message ("invalid DSA key");
		
	return ret;	
}

GkrParseResult  
gkr_pkix_der_read_public_key (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GkrParseResult res;
	
	res = gkr_pkix_der_read_public_key_rsa (data, n_data, s_key);
	if (res == GKR_PARSE_UNRECOGNIZED)
		res = gkr_pkix_der_read_public_key_dsa (data, n_data, s_key);
		
	return res;
}

GkrParseResult
gkr_pkix_der_read_public_key_info (const guchar* data, gsize n_data, gcry_sexp_t* s_key)
{
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	GQuark oid;
	ASN1_TYPE asn;
	gsize n_key, n_params;
	const guchar *params;
	guchar *key = NULL;
	
	init_quarks ();

	asn = gkr_pkix_asn1_decode ("PKIX1.SubjectPublicKeyInfo", data, n_data);
	if (!asn)
		goto done;
	
	ret = GKR_PARSE_FAILURE;
    
	/* Figure out the algorithm */
	oid = gkr_pkix_asn1_read_quark (asn, "algorithm.algorithm");
	if (!oid)
		goto done;
		
	/* A bit string so we cannot process in place */
	key = gkr_pkix_asn1_read_value (asn, "subjectPublicKey", &n_key, NULL);
	if (!key)
		goto done;
	n_key /= 8;
		
	/* An RSA key is simple */
	if (oid == OID_PKIX1_RSA) {
		ret = gkr_pkix_der_read_public_key_rsa (key, n_key, s_key);
		
	/* A DSA key paramaters are stored separately */
	} else if (oid == OID_PKIX1_DSA) {
		params = gkr_pkix_asn1_read_element (asn, data, n_data, "algorithm.parameters", &n_params);
		if (!params)
			goto done;
		ret = gkr_pkix_der_read_public_key_dsa_parts (key, n_key, params, n_params, s_key);
		
	} else {
		g_message ("unsupported key algorithm in certificate: %s", g_quark_to_string (oid));
		goto done;
	}
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	
	g_free (key);
		
	if (ret == GKR_PARSE_FAILURE)
		g_message ("invalid subject public-key info");
		
	return ret;
}

GkrParseResult
gkr_pkix_der_read_private_key (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GkrParseResult res;
	
	res = gkr_pkix_der_read_private_key_rsa (data, n_data, s_key);
	if (res == GKR_PARSE_UNRECOGNIZED)
		res = gkr_pkix_der_read_private_key_dsa (data, n_data, s_key);
		
	return res;
}

guchar*
gkr_pkix_der_write_public_key_rsa (gcry_sexp_t s_key, gsize *len)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t n, e;
	guchar *result = NULL;
	int res;

	n = e = NULL;

	res = asn1_create_element (gkr_pkix_asn1_get_pk_asn1type (), 
	                           "PK.RSAPublicKey", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);

	if (!gkr_crypto_sexp_extract_mpi (s_key, &n, "rsa", "n", NULL) || 
	    !gkr_crypto_sexp_extract_mpi (s_key, &e, "rsa", "e", NULL))
	    	goto done;
	
	if (!gkr_pkix_asn1_write_mpi (asn, "modulus", n) ||
	    !gkr_pkix_asn1_write_mpi (asn, "publicExponent", e))
	    	goto done;

	result = gkr_pkix_asn1_encode (asn, "", len, NULL);
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	
	return result;
}

guchar*
gkr_pkix_der_write_public_key_dsa (gcry_sexp_t s_key, gsize *len)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t p, q, g, y;
	guchar *result = NULL;
	int res;

	p = q = g = y = NULL;

	res = asn1_create_element (gkr_pkix_asn1_get_pk_asn1type (), 
	                           "PK.DSAPublicKey", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);

	if (!gkr_crypto_sexp_extract_mpi (s_key, &p, "dsa", "p", NULL) || 
	    !gkr_crypto_sexp_extract_mpi (s_key, &q, "dsa", "q", NULL) ||
	    !gkr_crypto_sexp_extract_mpi (s_key, &g, "dsa", "g", NULL) ||
	    !gkr_crypto_sexp_extract_mpi (s_key, &y, "dsa", "y", NULL))
	    	goto done;
	
	if (!gkr_pkix_asn1_write_mpi (asn, "p", p) ||
	    !gkr_pkix_asn1_write_mpi (asn, "q", q) ||
	    !gkr_pkix_asn1_write_mpi (asn, "g", g) ||
	    !gkr_pkix_asn1_write_mpi (asn, "Y", y))
	    	goto done;

	if (!gkr_pkix_asn1_write_uint (asn, "version", 0))
		goto done; 
		
	result = gkr_pkix_asn1_encode (asn, "", len, NULL);
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	
	return result;
}

guchar*
gkr_pkix_der_write_public_key (gcry_sexp_t s_key, gsize *len)
{
	gboolean is_priv;
	int algorithm;
	
	g_return_val_if_fail (s_key != NULL, NULL);
	
	if (!gkr_crypto_skey_parse (s_key, &algorithm, &is_priv, NULL))
		g_return_val_if_reached (NULL);
	
	g_return_val_if_fail (!is_priv, NULL);
		
	switch (algorithm) {
	case GCRY_PK_RSA:
		return gkr_pkix_der_write_public_key_rsa (s_key, len);
	case GCRY_PK_DSA:
		return gkr_pkix_der_write_public_key_dsa (s_key, len);
	default:
		g_return_val_if_reached (NULL);
	}
}

/* -----------------------------------------------------------------------------
 * CERTIFICATES
 */
 
GkrParseResult
gkr_pkix_der_read_certificate (const guchar *data, gsize n_data, ASN1_TYPE *asn1)
{
	*asn1 = gkr_pkix_asn1_decode ("PKIX1.Certificate", data, n_data);
	if (!*asn1)
		return GKR_PARSE_UNRECOGNIZED;
	
	return GKR_PARSE_SUCCESS;
}

GkrParseResult
gkr_pkix_der_read_basic_constraints (const guchar *data, gsize n_data, 
                                     gboolean *is_ca, guint *path_len)
{
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	ASN1_TYPE asn;

	asn = gkr_pkix_asn1_decode ("PKIX1.BasicConstraints", data, n_data);
	if (!asn)
		goto done;
	
	ret = GKR_PARSE_FAILURE;
    
    	if (path_len) {
    		if (!gkr_pkix_asn1_read_uint (asn, "pathLenConstraint", path_len))
    			goto done;
    	}
    	
    	if (is_ca) {
    		*is_ca = FALSE;
    		if (!gkr_pkix_asn1_read_boolean (asn, "cA", is_ca))
    			goto done;
    	}
    	
	ret = GKR_PARSE_SUCCESS;

done:
	if (asn)
		asn1_delete_structure (&asn);
	
	if (ret == GKR_PARSE_FAILURE) 
		g_message ("invalid basic constraints");
		
	return ret;
}

GkrParseResult
gkr_pkix_der_read_key_usage (const guchar *data, gsize n_data, guint *key_usage)
{
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	ASN1_TYPE asn;
	guchar buf[4];
	int res, len;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.KeyUsage", data, n_data);
	if (!asn)
		goto done;
		
	ret = GKR_PARSE_FAILURE;

	memset (buf, 0, sizeof (buf));
	len = sizeof (buf);
  	res = asn1_read_value (asn, "", buf, &len);
  	if (res != ASN1_SUCCESS)
  		goto done;

	*key_usage = buf[0] || (buf[1] << 8);
	ret = GKR_PARSE_SUCCESS;
	
done:
	if (asn)
		asn1_delete_structure (&asn);		
	return ret;
}

GkrParseResult
gkr_pkix_der_read_enhanced_usage (const guchar *data, gsize n_data, GSList **usage_oids)
{
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	ASN1_TYPE asn;
	GSList *results;
	gchar *part;
	GQuark oid;
	int i;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.ExtKeyUsageSyntax", data, n_data);
	if (!asn)
		goto done;
		
	ret = GKR_PARSE_FAILURE;
	
	results = NULL;
	for (i = 0; TRUE; ++i) {
		part = g_strdup_printf ("?%d", i + 1);
		oid = gkr_pkix_asn1_read_quark (asn, part);
		g_free (part);
		
		if (!oid) 
			break;
		
		results = g_slist_prepend (results, GUINT_TO_POINTER (oid));
	}
	
	*usage_oids = g_slist_reverse (results);
	ret = GKR_PARSE_SUCCESS;
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	return ret;
}

/* -----------------------------------------------------------------------------
 * CIPHER/KEY DESCRIPTIONS 
 */
 
GkrParseResult
gkr_pkix_der_read_cipher (GkrPkixParser *parser, GQuark oid_scheme, const gchar *password, 
                          const guchar *data, gsize n_data, gcry_cipher_hd_t *cih)
{
	GkrParseResult ret = GKR_PARSE_UNRECOGNIZED;
	
	g_return_val_if_fail (GKR_IS_PKIX_PARSER (parser), GKR_PARSE_FAILURE);
	g_return_val_if_fail (oid_scheme != 0, GKR_PARSE_FAILURE);
	g_return_val_if_fail (cih != NULL, GKR_PARSE_FAILURE);
	g_return_val_if_fail (data != NULL && n_data != 0, GKR_PARSE_FAILURE);
	g_return_val_if_fail (password != NULL, GKR_PARSE_FAILURE);
	
	init_quarks ();
	
	/* PKCS#5 PBE */
	if (oid_scheme == OID_PBE_MD2_DES_CBC)
		ret = gkr_pkix_der_read_cipher_pkcs5_pbe (parser, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC,
		                                          GCRY_MD_MD2, password, data, n_data, cih);

	else if (oid_scheme == OID_PBE_MD2_RC2_CBC)
		/* RC2-64 has no implementation in libgcrypt */
		ret = GKR_PARSE_UNRECOGNIZED;
	else if (oid_scheme == OID_PBE_MD5_DES_CBC)
		ret = gkr_pkix_der_read_cipher_pkcs5_pbe (parser, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC,
		                                          GCRY_MD_MD5, password, data, n_data, cih);
	else if (oid_scheme == OID_PBE_MD5_RC2_CBC)
		/* RC2-64 has no implementation in libgcrypt */
		ret = GKR_PARSE_UNRECOGNIZED;
	else if (oid_scheme == OID_PBE_SHA1_DES_CBC)
		ret = gkr_pkix_der_read_cipher_pkcs5_pbe (parser, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC,
		                                          GCRY_MD_SHA1, password, data, n_data, cih);
	else if (oid_scheme == OID_PBE_SHA1_RC2_CBC)
		/* RC2-64 has no implementation in libgcrypt */
		ret = GKR_PARSE_UNRECOGNIZED;

	
	/* PKCS#5 PBES2 */
	else if (oid_scheme == OID_PBES2)
		ret = gkr_pkix_der_read_cipher_pkcs5_pbes2 (parser, password, data, n_data, cih);

		
	/* PKCS#12 PBE */
	else if (oid_scheme == OID_PKCS12_PBE_ARCFOUR_SHA1)
		ret = gkr_pkix_der_read_cipher_pkcs12_pbe (parser, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 
	                                                   password, data, n_data, cih);
	else if (oid_scheme == OID_PKCS12_PBE_RC4_40_SHA1)
		/* RC4-40 has no implementation in libgcrypt */;

	else if (oid_scheme == OID_PKCS12_PBE_3DES_SHA1)
		ret = gkr_pkix_der_read_cipher_pkcs12_pbe (parser, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 
	                                                   password, data, n_data, cih);
	else if (oid_scheme == OID_PKCS12_PBE_2DES_SHA1) 
		/* 2DES has no implementation in libgcrypt */;
		
	else if (oid_scheme == OID_PKCS12_PBE_RC2_128_SHA1)
		ret = gkr_pkix_der_read_cipher_pkcs12_pbe (parser, GCRY_CIPHER_RFC2268_128, GCRY_CIPHER_MODE_CBC, 
	                                                   password, data, n_data, cih);

	else if (oid_scheme == OID_PKCS12_PBE_RC2_40_SHA1)
		ret = gkr_pkix_der_read_cipher_pkcs12_pbe (parser, GCRY_CIPHER_RFC2268_40, GCRY_CIPHER_MODE_CBC, 
	                                                   password, data, n_data, cih);

	if (ret == GKR_PARSE_UNRECOGNIZED)
    		g_message ("unsupported or unrecognized cipher oid: %s", g_quark_to_string (oid_scheme));
    	return ret;
}

GkrParseResult
gkr_pkix_der_read_cipher_pkcs5_pbe (GkrPkixParser *parser, int cipher_algo, int cipher_mode, 
                                    int hash_algo, const gchar *password, const guchar *data, 
                                    gsize n_data, gcry_cipher_hd_t *cih)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_error_t gcry;
	GkrParseResult ret;
	const guchar *salt;
	gsize n_salt;
	gsize n_block, n_key;
	guint iterations;
	guchar *key = NULL;
	guchar *iv = NULL;

	g_return_val_if_fail (GKR_IS_PKIX_PARSER (parser), GKR_PARSE_FAILURE);
	g_return_val_if_fail (cipher_algo != 0 && cipher_mode != 0, GKR_PARSE_FAILURE);
	g_return_val_if_fail (cih != NULL, GKR_PARSE_FAILURE);
	g_return_val_if_fail (data != NULL && n_data != 0, GKR_PARSE_FAILURE);
	g_return_val_if_fail (password != NULL, GKR_PARSE_FAILURE);

	*cih = NULL;	
	ret = GKR_PARSE_UNRECOGNIZED;
	
	/* Check if we can use this algorithm */
	if (gcry_cipher_algo_info (cipher_algo, GCRYCTL_TEST_ALGO, NULL, 0) != 0 ||
	    gcry_md_test_algo (hash_algo) != 0)
		goto done;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-5-PBE-params", data, n_data);
	if (!asn) 
		goto done;
		
	ret = GKR_PARSE_FAILURE;
		
	salt = gkr_pkix_asn1_read_content (asn, data, n_data, "salt", &n_salt);
	if (!salt)
		goto done;
	if (!gkr_pkix_asn1_read_uint (asn, "iterationCount", &iterations))
		iterations = 1;
		
	n_key = gcry_cipher_get_algo_keylen (cipher_algo);
	g_return_val_if_fail (n_key > 0, GKR_PARSE_FAILURE);
	n_block = gcry_cipher_get_algo_blklen (cipher_algo);
		
	if (!gkr_crypto_generate_symkey_pbe (cipher_algo, hash_algo, password, salt,
	                                     n_salt, iterations, &key, n_block > 1 ? &iv : NULL))
		goto done;
		
	gcry = gcry_cipher_open (cih, cipher_algo, cipher_mode, 0);
	if (gcry != 0) {
		g_warning ("couldn't create cipher: %s", gcry_strerror (gcry));
		goto done;
	}
	
	if (iv) 
		gcry_cipher_setiv (*cih, iv, n_block);
	gcry_cipher_setkey (*cih, key, n_key);
	
	ret = GKR_PARSE_SUCCESS;

done:
	gkr_secure_free (iv);
	gkr_secure_free (key);
	
	if (asn)
		asn1_delete_structure (&asn);
		
	return ret;
}

static gboolean
setup_pkcs5_rc2_params (GkrPkixParser *parser, const guchar *data, guchar n_data,
                        gcry_cipher_hd_t cih)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_error_t gcry;
	const guchar *iv;
	gsize n_iv;
	guint version;
	
	g_assert (data);

	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-5-rc2-CBC-params", data, n_data);
	if (!asn) 
		return GKR_PARSE_UNRECOGNIZED;
		
	if (!gkr_pkix_asn1_read_uint (asn, "rc2ParameterVersion", &version))
		return GKR_PARSE_FAILURE;
	
	iv = gkr_pkix_asn1_read_content (asn, data, n_data, "iv", &n_iv);
	asn1_delete_structure (&asn);

	if (!iv)
		return GKR_PARSE_FAILURE;
		
	gcry = gcry_cipher_setiv (cih, iv, n_iv);
			
	if (gcry != 0) {
		g_message ("couldn't set %lu byte iv on cipher", (gulong)n_iv);
		return GKR_PARSE_FAILURE;
	}
	
	return GKR_PARSE_SUCCESS;
}

static gboolean
setup_pkcs5_des_params (GkrPkixParser *parser, const guchar *data, guchar n_data,
                        gcry_cipher_hd_t cih)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_error_t gcry;
	const guchar *iv;
	gsize n_iv;
	
	g_assert (data);

	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-5-des-EDE3-CBC-params", data, n_data);
	if (!asn)
		asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-5-des-CBC-params", data, n_data);
	if (!asn) 
		return GKR_PARSE_UNRECOGNIZED;
	
	iv = gkr_pkix_asn1_read_content (asn, data, n_data, "", &n_iv);
	asn1_delete_structure (&asn);

	if (!iv)
		return GKR_PARSE_FAILURE;
		
	gcry = gcry_cipher_setiv (cih, iv, n_iv);
			
	if (gcry != 0) {
		g_message ("couldn't set %lu byte iv on cipher", (gulong)n_iv);
		return GKR_PARSE_FAILURE;
	}
	
	return GKR_PARSE_SUCCESS;
}

static GkrParseResult
setup_pkcs5_pbkdf2_params (GkrPkixParser *parser, const gchar *password, const guchar *data, 
                           gsize n_data, int cipher_algo, gcry_cipher_hd_t cih)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	GkrParseResult ret;
	gcry_error_t gcry;
	guchar *key = NULL; 
	const guchar *salt;
	gsize n_salt, n_key;
	guint iterations;
	
	g_assert (password);
	g_assert (cipher_algo);
	g_assert (data);
	
	ret = GKR_PARSE_UNRECOGNIZED;

	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-5-PBKDF2-params", data, n_data);
	if (!asn)
		goto done;
		
	ret = GKR_PARSE_FAILURE;
		
	if (!gkr_pkix_asn1_read_uint (asn, "iterationCount", &iterations))
		iterations = 1;
	salt = gkr_pkix_asn1_read_content (asn, data, n_data, "salt.specified", &n_salt);
	if (!salt)
		goto done;
				
	if (!gkr_crypto_generate_symkey_pbkdf2 (cipher_algo, GCRY_MD_SHA1, password, 
	                                        salt, n_salt, iterations, &key, NULL))
		goto done;

	n_key = gcry_cipher_get_algo_keylen (cipher_algo);
	g_return_val_if_fail (n_key > 0, GKR_PARSE_FAILURE);
	
	gcry = gcry_cipher_setkey (cih, key, n_key);
	if (gcry != 0) {
		g_message ("couldn't set %lu byte key on cipher", (gulong)n_key);
		goto done;
	}
	
	ret = GKR_PARSE_SUCCESS;
	                                         
done:
	gkr_secure_free (key);
	if (asn)
		asn1_delete_structure (&asn);
	return ret;
}

GkrParseResult
gkr_pkix_der_read_cipher_pkcs5_pbes2 (GkrPkixParser *parser, const gchar *password, const guchar *data, 
                                      gsize n_data, gcry_cipher_hd_t *cih)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	GkrParseResult r, ret;
	GQuark key_deriv_algo, enc_oid;
	gcry_error_t gcry;
	int algo, mode;
	int beg, end, res;

	g_return_val_if_fail (GKR_IS_PKIX_PARSER (parser), GKR_PARSE_FAILURE);
	g_return_val_if_fail (cih != NULL, GKR_PARSE_FAILURE);
	g_return_val_if_fail (data != NULL && n_data != 0, GKR_PARSE_FAILURE);
	g_return_val_if_fail (password != NULL, GKR_PARSE_FAILURE);
	
	init_quarks ();
	
	*cih = NULL;
	ret = GKR_PARSE_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-5-PBES2-params", data, n_data);
	if (!asn)
		goto done;
		
	res = GKR_PARSE_FAILURE;
	algo = mode = 0;
	
	/* Read in all the encryption type */
	enc_oid = gkr_pkix_asn1_read_quark (asn, "encryptionScheme.algorithm");
	if (!enc_oid)
		goto done;	
	if (enc_oid == OID_DES_EDE3_CBC)
		algo = GCRY_CIPHER_3DES;
	else if (enc_oid == OID_DES_CBC)
		algo = GCRY_CIPHER_DES;
	else if (enc_oid == OID_DES_RC2_CBC)
		algo = GCRY_CIPHER_RFC2268_128;
	else if (enc_oid == OID_DES_RC5_CBC)
		/* RC5 doesn't exist in libgcrypt */;
	
	/* Unsupported? */
	if (algo == 0 || gcry_cipher_algo_info (algo, GCRYCTL_TEST_ALGO, NULL, 0) != 0) {
		ret = GKR_PARSE_UNRECOGNIZED;
		goto done;
	}

	/* Instantiate our cipher */
	gcry = gcry_cipher_open (cih, algo, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry != 0) {
		g_warning ("couldn't create cipher: %s", gcry_cipher_algo_name (algo));
		goto done;
	}
		
	/* Read out the parameters */
	if (asn1_der_decoding_startEnd (asn, data, n_data, "encryptionScheme.parameters",
	                                &beg, &end) != ASN1_SUCCESS)
		goto done;
		
	switch (algo) {
	case GCRY_CIPHER_3DES:
	case GCRY_CIPHER_DES:
		r = setup_pkcs5_des_params (parser, data + beg, end - beg + 1, *cih);
		break;
	case GCRY_CIPHER_RFC2268_128:
		r = setup_pkcs5_rc2_params (parser, data + beg, end - beg + 1, *cih);
		break;
	default:
		/* Should have been caught on the oid check above */
		g_assert_not_reached ();
		r = GKR_PARSE_UNRECOGNIZED;
		break;
	};

	if (r != GKR_PARSE_SUCCESS) {
		ret = r;
		goto done;
	}

	/* Read out the key creation paramaters */
	key_deriv_algo = gkr_pkix_asn1_read_quark (asn, "keyDerivationFunc.algorithm");
	if (!key_deriv_algo)
		goto done;
	if (key_deriv_algo != OID_PBKDF2) {
		g_message ("unsupported key derivation algorithm: %s", g_quark_to_string (key_deriv_algo));
		ret = GKR_PARSE_UNRECOGNIZED;
		goto done;
	}

	if (asn1_der_decoding_startEnd (asn, data, n_data, "keyDerivationFunc.parameters",
	                                &beg, &end) != ASN1_SUCCESS)
		goto done;
	
	ret = setup_pkcs5_pbkdf2_params (parser, password, data + beg, 
	                                 end - beg + 1, algo, *cih);

done:
	if (ret != GKR_PARSE_SUCCESS && *cih) {
		gcry_cipher_close (*cih);
		*cih = NULL;
	}
	
	if (asn)
		asn1_delete_structure (&asn);
	
	return ret;
}

GkrParseResult
gkr_pkix_der_read_cipher_pkcs12_pbe (GkrPkixParser *parser, int cipher_algo, int cipher_mode, 
                                     const gchar *password, const guchar *data, gsize n_data, 
                                     gcry_cipher_hd_t *cih)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_error_t gcry;
	GkrParseResult ret;
	const guchar *salt;
	gsize n_salt;
	gsize n_block, n_key;
	guint iterations;
	guchar *key = NULL;
	guchar *iv = NULL;
	
	g_return_val_if_fail (GKR_IS_PKIX_PARSER (parser), GKR_PARSE_FAILURE);
	g_return_val_if_fail (cipher_algo != 0 && cipher_mode != 0, GKR_PARSE_FAILURE);
	g_return_val_if_fail (cih != NULL, GKR_PARSE_FAILURE);
	g_return_val_if_fail (data != NULL && n_data != 0, GKR_PARSE_FAILURE);
	g_return_val_if_fail (password != NULL, GKR_PARSE_FAILURE);
	
	*cih = NULL;
	ret = GKR_PARSE_UNRECOGNIZED;
	
	/* Check if we can use this algorithm */
	if (gcry_cipher_algo_info (cipher_algo, GCRYCTL_TEST_ALGO, NULL, 0) != 0)
		goto done;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-12-PbeParams", data, n_data);
	if (!asn)
		goto done;

	ret = GKR_PARSE_FAILURE;

	salt = gkr_pkix_asn1_read_content (asn, data, n_data, "salt", &n_salt);
	if (!salt)
		goto done;
	if (!gkr_pkix_asn1_read_uint (asn, "iterations", &iterations))
		goto done;
	
	n_block = gcry_cipher_get_algo_blklen (cipher_algo);
	n_key = gcry_cipher_get_algo_keylen (cipher_algo);
	
	/* Generate IV and key using salt read above */
	if (!gkr_crypto_generate_symkey_pkcs12 (cipher_algo, GCRY_MD_SHA1, password,
	                                        salt, n_salt, iterations, &key, 
	                                        n_block > 1 ? &iv : NULL))
		goto done;
		
	gcry = gcry_cipher_open (cih, cipher_algo, cipher_mode, 0);
	if (gcry != 0) {
		g_warning ("couldn't create encryption cipher: %s", gcry_strerror (gcry));
		goto done;
	}
	
	if (iv) 
		gcry_cipher_setiv (*cih, iv, n_block);
	gcry_cipher_setkey (*cih, key, n_key);
	
	ret = GKR_PARSE_SUCCESS;
	
done:
	if (ret != GKR_PARSE_SUCCESS && *cih) {
		gcry_cipher_close (*cih);
		*cih = NULL;
	}
	
	gkr_secure_free (iv);
	gkr_secure_free (key);
	
	if (asn)
		asn1_delete_structure (&asn);
	
	return ret;
}
