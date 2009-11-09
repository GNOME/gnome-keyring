/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-data-der.c - parsing and serializing of common crypto DER structures 

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

#include "gck-crypto.h"
#include "gck-data-asn1.h"
#include "gck-data-der.h"
#include "gck-data-types.h"

#include "egg/egg-secure-memory.h"
#include "egg/egg-symkey.h"

#include <glib.h>
#include <gcrypt.h>
#include <libtasn1.h>

/* -----------------------------------------------------------------------------
 * QUARKS
 */

static GQuark OID_PKIX1_RSA;
static GQuark OID_PKIX1_DSA;
static GQuark OID_PKCS12_PBE_3DES_SHA1;

static void
init_quarks (void)
{
	static volatile gsize quarks_inited = 0;

	if (g_once_init_enter (&quarks_inited)) {

		#define QUARK(name, value) \
			name = g_quark_from_static_string(value)

		QUARK (OID_PKIX1_RSA, "1.2.840.113549.1.1.1");
		QUARK (OID_PKIX1_DSA, "1.2.840.10040.4.1");
		QUARK (OID_PKCS12_PBE_3DES_SHA1, "1.2.840.113549.1.12.1.3");
		
		#undef QUARK
		
		g_once_init_leave (&quarks_inited, 1);
	}
}

/* -----------------------------------------------------------------------------
 * KEY PARSING
 */

#define SEXP_PUBLIC_RSA  \
	"(public-key"    \
	"  (rsa"         \
	"    (n %m)"     \
	"    (e %m)))"

GckDataResult
gck_data_der_read_public_key_rsa (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t n, e;
	int res;

	n = e = NULL;
	
	asn = egg_asn1_decode ("PK.RSAPublicKey", data, n_data);
	if (!asn)
		goto done;
		
	ret = GCK_DATA_FAILURE;
    
	if (!gck_data_asn1_read_mpi (asn, "modulus", &n) || 
	    !gck_data_asn1_read_mpi (asn, "publicExponent", &e))
		goto done;
		
	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_RSA, n, e);
	if (res)
		goto done;

	g_assert (*s_key);
	ret = GCK_DATA_SUCCESS;

done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	
	if (ret == GCK_DATA_FAILURE)
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

GckDataResult
gck_data_der_read_private_key_rsa (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	gcry_mpi_t n, e, d, p, q, u;
	gcry_mpi_t tmp;
	guint version;
	int res;
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;

	n = e = d = p = q = u = NULL;
	
	asn = egg_asn1_decode ("PK.RSAPrivateKey", data, n_data);
	if (!asn)
		goto done;
		
	ret = GCK_DATA_FAILURE;
	
	if (!egg_asn1_read_uint (asn, "version", &version))
		goto done;
	
	/* We only support simple version */
	if (version != 0) {
		ret = GCK_DATA_UNRECOGNIZED;
		g_message ("unsupported version of RSA key: %u", version);
		goto done;
	}
    
	if (!gck_data_asn1_read_secure_mpi (asn, "modulus", &n) || 
	    !gck_data_asn1_read_secure_mpi (asn, "publicExponent", &e) ||
	    !gck_data_asn1_read_secure_mpi (asn, "privateExponent", &d) ||
	    !gck_data_asn1_read_secure_mpi (asn, "prime1", &p) ||
	    !gck_data_asn1_read_secure_mpi (asn, "prime2", &q) || 
	    !gck_data_asn1_read_secure_mpi (asn, "coefficient", &u))
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
	ret = GCK_DATA_SUCCESS;

done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	gcry_mpi_release (d);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (u);
	
	if (ret == GCK_DATA_FAILURE)
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

GckDataResult
gck_data_der_read_public_key_dsa (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t p, q, g, y;
	int res;

	p = q = g = y = NULL;
	
	asn = egg_asn1_decode ("PK.DSAPublicKey", data, n_data);
	if (!asn)
		goto done;
	
	ret = GCK_DATA_FAILURE;
    
	if (!gck_data_asn1_read_mpi (asn, "p", &p) || 
	    !gck_data_asn1_read_mpi (asn, "q", &q) ||
	    !gck_data_asn1_read_mpi (asn, "g", &g) ||
	    !gck_data_asn1_read_mpi (asn, "Y", &y))
	    	goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_DSA, p, q, g, y);
	if (res)
		goto done;
		
	g_assert (*s_key);
	ret = GCK_DATA_SUCCESS;
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	
	if (ret == GCK_DATA_FAILURE) 
		g_message ("invalid public DSA key");
		
	return ret;	
}

GckDataResult
gck_data_der_read_public_key_dsa_parts (const guchar *keydata, gsize n_keydata,
                                        const guchar *params, gsize n_params,
                                        gcry_sexp_t *s_key)
{
	gcry_mpi_t p, q, g, y;
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	ASN1_TYPE asn_params = ASN1_TYPE_EMPTY;
	ASN1_TYPE asn_key = ASN1_TYPE_EMPTY;
	int res;

	p = q = g = y = NULL;
	
	asn_params = egg_asn1_decode ("PK.DSAParameters", params, n_params);
	asn_key = egg_asn1_decode ("PK.DSAPublicPart", keydata, n_keydata);
	if (!asn_params || !asn_key)
		goto done;
	
	ret = GCK_DATA_FAILURE;
    
	if (!gck_data_asn1_read_mpi (asn_params, "p", &p) || 
	    !gck_data_asn1_read_mpi (asn_params, "q", &q) ||
	    !gck_data_asn1_read_mpi (asn_params, "g", &g))
	    	goto done;
	    	
	if (!gck_data_asn1_read_mpi (asn_key, "", &y))
		goto done;

	res = gcry_sexp_build (s_key, NULL, SEXP_PUBLIC_DSA, p, q, g, y);
	if (res)
		goto done;
		
	g_assert (*s_key);
	ret = GCK_DATA_SUCCESS;
	
done:
	if (asn_key)
		asn1_delete_structure (&asn_key);
	if (asn_params)
		asn1_delete_structure (&asn_params);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	
	if (ret == GCK_DATA_FAILURE) 
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

GckDataResult
gck_data_der_read_private_key_dsa (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	gcry_mpi_t p, q, g, y, x;
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	int res;
	ASN1_TYPE asn;

	p = q = g = y = x = NULL;
	
	asn = egg_asn1_decode ("PK.DSAPrivateKey", data, n_data);
	if (!asn)
		goto done;
	
	ret = GCK_DATA_FAILURE;
    
	if (!gck_data_asn1_read_secure_mpi (asn, "p", &p) || 
	    !gck_data_asn1_read_secure_mpi (asn, "q", &q) ||
	    !gck_data_asn1_read_secure_mpi (asn, "g", &g) ||
	    !gck_data_asn1_read_secure_mpi (asn, "Y", &y) ||
	    !gck_data_asn1_read_secure_mpi (asn, "priv", &x))
		goto done;
		
	res = gcry_sexp_build (s_key, NULL, SEXP_PRIVATE_DSA, p, q, g, y, x);
	if (res)
		goto done;
		
	g_assert (*s_key);
	ret = GCK_DATA_SUCCESS;

done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (x);
	
	if (ret == GCK_DATA_FAILURE) 
		g_message ("invalid DSA key");
		
	return ret;
}

GckDataResult
gck_data_der_read_private_key_dsa_parts (const guchar *keydata, gsize n_keydata,
                                         const guchar *params, gsize n_params, 
                                         gcry_sexp_t *s_key)
{
	gcry_mpi_t p, q, g, y, x;
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	int res;
	ASN1_TYPE asn_params = ASN1_TYPE_EMPTY;
	ASN1_TYPE asn_key = ASN1_TYPE_EMPTY;

	p = q = g = y = x = NULL;
	
	asn_params = egg_asn1_decode ("PK.DSAParameters", params, n_params);
	asn_key = egg_asn1_decode ("PK.DSAPrivatePart", keydata, n_keydata);
	if (!asn_params || !asn_key)
		goto done;
	
	ret = GCK_DATA_FAILURE;
    
	if (!gck_data_asn1_read_secure_mpi (asn_params, "p", &p) || 
	    !gck_data_asn1_read_secure_mpi (asn_params, "q", &q) ||
	    !gck_data_asn1_read_secure_mpi (asn_params, "g", &g))
	    	goto done;
	    	
	if (!gck_data_asn1_read_secure_mpi (asn_key, "", &x))
		goto done;

	/* Now we calculate y */
	y = gcry_mpi_snew (1024);
  	gcry_mpi_powm (y, g, x, p);

	res = gcry_sexp_build (s_key, NULL, SEXP_PRIVATE_DSA, p, q, g, y, x);
	if (res)
		goto done;
		
	g_assert (*s_key);
	ret = GCK_DATA_SUCCESS;
	
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
	
	if (ret == GCK_DATA_FAILURE) 
		g_message ("invalid DSA key");
		
	return ret;	
}

GckDataResult  
gck_data_der_read_public_key (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GckDataResult res;
	
	res = gck_data_der_read_public_key_rsa (data, n_data, s_key);
	if (res == GCK_DATA_UNRECOGNIZED)
		res = gck_data_der_read_public_key_dsa (data, n_data, s_key);
		
	return res;
}

GckDataResult
gck_data_der_read_public_key_info (const guchar* data, gsize n_data, gcry_sexp_t* s_key)
{
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	GQuark oid;
	ASN1_TYPE asn;
	gsize n_key, n_params;
	const guchar *params;
	guchar *key = NULL;
	
	init_quarks ();

	asn = egg_asn1_decode ("PKIX1.SubjectPublicKeyInfo", data, n_data);
	if (!asn)
		goto done;
	
	ret = GCK_DATA_FAILURE;
    
	/* Figure out the algorithm */
	oid = egg_asn1_read_oid (asn, "algorithm.algorithm");
	if (!oid)
		goto done;
		
	/* A bit string so we cannot process in place */
	key = egg_asn1_read_value (asn, "subjectPublicKey", &n_key, NULL);
	if (!key)
		goto done;
	n_key /= 8;
		
	/* An RSA key is simple */
	if (oid == OID_PKIX1_RSA) {
		ret = gck_data_der_read_public_key_rsa (key, n_key, s_key);
		
	/* A DSA key paramaters are stored separately */
	} else if (oid == OID_PKIX1_DSA) {
		params = egg_asn1_read_element (asn, data, n_data, "algorithm.parameters", &n_params);
		if (!params)
			goto done;
		ret = gck_data_der_read_public_key_dsa_parts (key, n_key, params, n_params, s_key);
		
	} else {
		g_message ("unsupported key algorithm in certificate: %s", g_quark_to_string (oid));
		ret = GCK_DATA_UNRECOGNIZED;
		goto done;
	}
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	
	g_free (key);
		
	if (ret == GCK_DATA_FAILURE)
		g_message ("invalid subject public-key info");
		
	return ret;
}

GckDataResult
gck_data_der_read_private_key (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	GckDataResult res;
	
	res = gck_data_der_read_private_key_rsa (data, n_data, s_key);
	if (res == GCK_DATA_UNRECOGNIZED)
		res = gck_data_der_read_private_key_dsa (data, n_data, s_key);
		
	return res;
}

GckDataResult
gck_data_der_read_private_pkcs8_plain (const guchar *data, gsize n_data, gcry_sexp_t *s_key)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	GckDataResult ret;
	int algorithm;
	GQuark key_algo;
	const guchar *keydata;
	gsize n_keydata;
	const guchar *params;
	gsize n_params;
	
	ret = GCK_DATA_UNRECOGNIZED;
	
	init_quarks ();
	
	asn = egg_asn1_decode ("PKIX1.pkcs-8-PrivateKeyInfo", data, n_data);
	if (!asn)
		goto done;

	ret = GCK_DATA_FAILURE;
	algorithm = 0;
		
	key_algo = egg_asn1_read_oid (asn, "privateKeyAlgorithm.algorithm");
  	if (!key_algo)
  		goto done;
  	else if (key_algo == OID_PKIX1_RSA)
  		algorithm = GCRY_PK_RSA;
  	else if (key_algo == OID_PKIX1_DSA)
  		algorithm = GCRY_PK_DSA;
  		
  	if (!algorithm) {
  		ret = GCK_DATA_UNRECOGNIZED;
  		goto done;
  	}

	keydata = egg_asn1_read_content (asn, data, n_data, "privateKey", &n_keydata);
	if (!keydata)
		goto done;
		
	params = egg_asn1_read_element (asn, data, n_data, "privateKeyAlgorithm.parameters", 
	                                     &n_params);
		
	ret = GCK_DATA_SUCCESS;
	
done:
	if (ret == GCK_DATA_SUCCESS) {		
		switch (algorithm) {
		case GCRY_PK_RSA:
			ret = gck_data_der_read_private_key_rsa (keydata, n_keydata, s_key);
			break;
		case GCRY_PK_DSA:
			/* Try the normal one block format */
			ret = gck_data_der_read_private_key_dsa (keydata, n_keydata, s_key);
			
			/* Otherwise try the two part format that everyone seems to like */
			if (ret == GCK_DATA_UNRECOGNIZED && params && n_params)
				ret = gck_data_der_read_private_key_dsa_parts (keydata, n_keydata, 
				                                               params, n_params, s_key);
			break;
		default:
			g_message ("invalid or unsupported key type in PKCS#8 key");
			ret = GCK_DATA_UNRECOGNIZED;
			break;
		};
		
	} else if (ret == GCK_DATA_FAILURE) {
		g_message ("invalid PKCS#8 key");
	}
	
	if (asn)
		asn1_delete_structure (&asn);
	
	return ret;
}

GckDataResult
gck_data_der_read_private_pkcs8_crypted (const guchar *data, gsize n_data, const gchar *password, 
                                         gsize n_password, gcry_sexp_t *s_key)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_cipher_hd_t cih = NULL;
	gcry_error_t gcry;
	GckDataResult ret, r;
	GQuark scheme;
	guchar *crypted = NULL;
	const guchar *params;
	gsize n_crypted, n_params;
	gint l;

	init_quarks ();

	ret = GCK_DATA_UNRECOGNIZED;
	
	asn = egg_asn1_decode ("PKIX1.pkcs-8-EncryptedPrivateKeyInfo", data, n_data);
	if (!asn)
		goto done;

	ret = GCK_DATA_FAILURE;

	/* Figure out the type of encryption */
	scheme = egg_asn1_read_oid (asn, "encryptionAlgorithm.algorithm");
	if (!scheme)
		goto done;
		
	params = egg_asn1_read_element (asn, data, n_data, "encryptionAlgorithm.parameters", &n_params);
	if (!params)
		goto done;

	/* 
	 * Parse the encryption stuff into a cipher. 
	 */
	r = egg_symkey_read_cipher (scheme, password, n_password, params, n_params, &cih);
	if (r == GCK_DATA_UNRECOGNIZED) {
		ret = GCK_DATA_FAILURE;
		goto done;
	} else if (r != GCK_DATA_SUCCESS) {
		ret = r;
		goto done;
	}
			
	crypted = egg_asn1_read_value (asn, "encryptedData", &n_crypted, (EggAllocator)egg_secure_realloc);
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
	l = egg_asn1_element_length (crypted, n_crypted);
	if (l <= 0 || l > n_crypted) {
		ret = GCK_DATA_LOCKED;
		goto done;
	} 
	n_crypted = l;
		
	/* Try to parse the resulting key */
	ret = gck_data_der_read_private_pkcs8_plain (crypted, n_crypted, s_key);
	egg_secure_free (crypted);
	crypted = NULL;
		
	/* If unrecognized we assume bad password */
	if (ret == GCK_DATA_UNRECOGNIZED) 
		ret = GCK_DATA_LOCKED;

done:
	if (cih)
		gcry_cipher_close (cih);
	if (asn)
		asn1_delete_structure (&asn);
	egg_secure_free (crypted);
		
	return ret;
}

GckDataResult
gck_data_der_read_private_pkcs8 (const guchar *data, gsize n_data, const gchar *password, 
                                 gsize n_password, gcry_sexp_t *s_key)
{
	GckDataResult res;

	res = gck_data_der_read_private_pkcs8_crypted (data, n_data, password, n_password, s_key);
	if (res == GCK_DATA_UNRECOGNIZED) 
		res = gck_data_der_read_private_pkcs8_plain (data, n_data, s_key);

	return res;
}

guchar*
gck_data_der_write_public_key_rsa (gcry_sexp_t s_key, gsize *len)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t n, e;
	guchar *result = NULL;
	int res;

	n = e = NULL;

	res = asn1_create_element (egg_asn1_get_pk_asn1type (), 
	                           "PK.RSAPublicKey", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);

	if (!gck_crypto_sexp_extract_mpi (s_key, &n, "rsa", "n", NULL) || 
	    !gck_crypto_sexp_extract_mpi (s_key, &e, "rsa", "e", NULL))
	    	goto done;
	
	if (!gck_data_asn1_write_mpi (asn, "modulus", n) ||
	    !gck_data_asn1_write_mpi (asn, "publicExponent", e))
	    	goto done;

	result = egg_asn1_encode (asn, "", len, NULL);
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	
	return result;
}

guchar*
gck_data_der_write_private_key_rsa (gcry_sexp_t s_key, gsize *n_key)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t n, e, d, p, q, u, e1, e2, tmp;
	guchar *result = NULL;
	int res;

	n = e = d = p = q = u = e1 = e2 = tmp = NULL;

	res = asn1_create_element (egg_asn1_get_pk_asn1type (), 
	                           "PK.RSAPrivateKey", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);

	if (!gck_crypto_sexp_extract_mpi (s_key, &n, "rsa", "n", NULL) || 
	    !gck_crypto_sexp_extract_mpi (s_key, &e, "rsa", "e", NULL) ||
	    !gck_crypto_sexp_extract_mpi (s_key, &d, "rsa", "d", NULL) ||
	    !gck_crypto_sexp_extract_mpi (s_key, &p, "rsa", "p", NULL) ||
	    !gck_crypto_sexp_extract_mpi (s_key, &q, "rsa", "q", NULL) ||
	    !gck_crypto_sexp_extract_mpi (s_key, &u, "rsa", "u", NULL))
		goto done;
	
	if (!gck_data_asn1_write_mpi (asn, "modulus", n) ||
	    !gck_data_asn1_write_mpi (asn, "publicExponent", e) || 
	    !gck_data_asn1_write_mpi (asn, "privateExponent", d) ||
	    !gck_data_asn1_write_mpi (asn, "prime1", p) ||
	    !gck_data_asn1_write_mpi (asn, "prime2", q) ||
	    !gck_data_asn1_write_mpi (asn, "coefficient", u))
		goto done;
	
	/* Have to write out a null to delete OPTIONAL */
	if (!egg_asn1_write_value (asn, "otherPrimeInfos", NULL, 0))
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
	if (!gck_data_asn1_write_mpi (asn, "exponent1", e1) ||
	    !gck_data_asn1_write_mpi (asn, "exponent2", e2))
		goto done;

	/* Write out the version */
	if (!egg_asn1_write_uint (asn, "version", 0))
		goto done;

	result = egg_asn1_encode (asn, "", n_key, NULL);
	
done:
	if (asn)
		asn1_delete_structure (&asn);
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

guchar*
gck_data_der_write_public_key_dsa (gcry_sexp_t s_key, gsize *len)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t p, q, g, y;
	guchar *result = NULL;
	int res;

	p = q = g = y = NULL;

	res = asn1_create_element (egg_asn1_get_pk_asn1type (), 
	                           "PK.DSAPublicKey", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);

	if (!gck_crypto_sexp_extract_mpi (s_key, &p, "dsa", "p", NULL) || 
	    !gck_crypto_sexp_extract_mpi (s_key, &q, "dsa", "q", NULL) ||
	    !gck_crypto_sexp_extract_mpi (s_key, &g, "dsa", "g", NULL) ||
	    !gck_crypto_sexp_extract_mpi (s_key, &y, "dsa", "y", NULL))
	    	goto done;
	
	if (!gck_data_asn1_write_mpi (asn, "p", p) ||
	    !gck_data_asn1_write_mpi (asn, "q", q) ||
	    !gck_data_asn1_write_mpi (asn, "g", g) ||
	    !gck_data_asn1_write_mpi (asn, "Y", y))
	    	goto done;

	if (!egg_asn1_write_uint (asn, "version", 0))
		goto done; 
		
	result = egg_asn1_encode (asn, "", len, NULL);
	
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
gck_data_der_write_private_key_dsa_part (gcry_sexp_t skey, gsize *n_key)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t x;
	guchar *result = NULL;
	int res;

	x = NULL;

	res = asn1_create_element (egg_asn1_get_pk_asn1type (), 
	                           "PK.DSAPrivatePart", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);

	if (!gck_crypto_sexp_extract_mpi (skey, &x, "dsa", "x", NULL))
	    	goto done;
	
	if (!gck_data_asn1_write_mpi (asn, "", x))
	    	goto done;

	result = egg_asn1_encode (asn, "", n_key, NULL);
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (x);
	
	return result;		
}

guchar*
gck_data_der_write_private_key_dsa_params (gcry_sexp_t skey, gsize *n_params)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t p, q, g;
	guchar *result = NULL;
	int res;

	p = q = g = NULL;

	res = asn1_create_element (egg_asn1_get_pk_asn1type (), 
	                           "PK.DSAParameters", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);

	if (!gck_crypto_sexp_extract_mpi (skey, &p, "dsa", "p", NULL) || 
	    !gck_crypto_sexp_extract_mpi (skey, &q, "dsa", "q", NULL) ||
	    !gck_crypto_sexp_extract_mpi (skey, &g, "dsa", "g", NULL))
	    	goto done;
	
	if (!gck_data_asn1_write_mpi (asn, "p", p) ||
	    !gck_data_asn1_write_mpi (asn, "q", q) ||
	    !gck_data_asn1_write_mpi (asn, "g", g))
	    	goto done;

	result = egg_asn1_encode (asn, "", n_params, NULL);
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	
	return result;
}

guchar*
gck_data_der_write_private_key_dsa (gcry_sexp_t s_key, gsize *len)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_mpi_t p, q, g, y, x;
	guchar *result = NULL;
	int res;

	p = q = g = y = x = NULL;

	res = asn1_create_element (egg_asn1_get_pk_asn1type (), 
	                           "PK.DSAPrivateKey", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);

	if (!gck_crypto_sexp_extract_mpi (s_key, &p, "dsa", "p", NULL) || 
	    !gck_crypto_sexp_extract_mpi (s_key, &q, "dsa", "q", NULL) ||
	    !gck_crypto_sexp_extract_mpi (s_key, &g, "dsa", "g", NULL) ||
	    !gck_crypto_sexp_extract_mpi (s_key, &y, "dsa", "y", NULL) ||
	    !gck_crypto_sexp_extract_mpi (s_key, &x, "dsa", "x", NULL))
	    	goto done;
	
	if (!gck_data_asn1_write_mpi (asn, "p", p) ||
	    !gck_data_asn1_write_mpi (asn, "q", q) ||
	    !gck_data_asn1_write_mpi (asn, "g", g) ||
	    !gck_data_asn1_write_mpi (asn, "Y", y) ||
	    !gck_data_asn1_write_mpi (asn, "priv", x))
	    	goto done;

	if (!egg_asn1_write_uint (asn, "version", 0))
		goto done; 
		
	result = egg_asn1_encode (asn, "", len, NULL);
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (x);
	
	return result;
}

guchar*
gck_data_der_write_public_key (gcry_sexp_t s_key, gsize *len)
{
	gboolean is_priv;
	int algorithm;
	
	g_return_val_if_fail (s_key != NULL, NULL);
	
	if (!gck_crypto_sexp_parse_key (s_key, &algorithm, &is_priv, NULL))
		g_return_val_if_reached (NULL);
	
	g_return_val_if_fail (!is_priv, NULL);
		
	switch (algorithm) {
	case GCRY_PK_RSA:
		return gck_data_der_write_public_key_rsa (s_key, len);
	case GCRY_PK_DSA:
		return gck_data_der_write_public_key_dsa (s_key, len);
	default:
		g_return_val_if_reached (NULL);
	}
}

guchar*
gck_data_der_write_private_key (gcry_sexp_t s_key, gsize *len)
{
	gboolean is_priv;
	int algorithm;
	
	g_return_val_if_fail (s_key != NULL, NULL);
	
	if (!gck_crypto_sexp_parse_key (s_key, &algorithm, &is_priv, NULL))
		g_return_val_if_reached (NULL);
	
	g_return_val_if_fail (is_priv, NULL);
		
	switch (algorithm) {
	case GCRY_PK_RSA:
		return gck_data_der_write_private_key_rsa (s_key, len);
	case GCRY_PK_DSA:
		return gck_data_der_write_private_key_dsa (s_key, len);
	default:
		g_return_val_if_reached (NULL);
	}
}

static gcry_cipher_hd_t
prepare_and_encode_pkcs8_cipher (ASN1_TYPE asn, const gchar *password, 
                                 gsize n_password, gsize *n_block)
{
	ASN1_TYPE asn1_params;
	gcry_cipher_hd_t cih;
	guchar salt[8];
	gcry_error_t gcry;
	guchar *key, *iv, *portion;
	gsize n_key, n_portion;
	int iterations, res;
	
	init_quarks ();

	/* Make sure the encryption algorithm works */
	g_return_val_if_fail (gcry_cipher_algo_info (OID_PKCS12_PBE_3DES_SHA1, 
	                                             GCRYCTL_TEST_ALGO, NULL, 0), NULL);

	/* The encryption algorithm */
	if(!egg_asn1_write_oid (asn, "encryptionAlgorithm.algorithm", 
	                             OID_PKCS12_PBE_3DES_SHA1))
		g_return_val_if_reached (NULL); 

	/* Randomize some input for the password based secret */
	iterations = 1000 + (int) (1000.0 * rand () / (RAND_MAX + 1.0));
	gcry_create_nonce (salt, sizeof (salt));

	/* Allocate space for the key and iv */
	n_key = gcry_cipher_get_algo_keylen (GCRY_CIPHER_3DES);
	*n_block = gcry_cipher_get_algo_blklen (GCRY_MD_SHA1);
	g_return_val_if_fail (n_key && *n_block, NULL);
		
	if (!egg_symkey_generate_pkcs12 (GCRY_CIPHER_3DES, GCRY_MD_SHA1, 
	                                        password, n_password, salt, 
	                                        sizeof (salt), iterations, &key, &iv))
		g_return_val_if_reached (NULL);

	/* Now write out the parameters */	
	res = asn1_create_element (egg_asn1_get_pkix_asn1type (),
	                           "PKIX1.pkcs-12-PbeParams", &asn1_params);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	if (!egg_asn1_write_value (asn1_params, "salt", salt, sizeof (salt)))
		g_return_val_if_reached (NULL);
	if (!egg_asn1_write_uint (asn1_params, "iterations", iterations))
		g_return_val_if_reached (NULL);
	portion = egg_asn1_encode (asn1_params, "", &n_portion, NULL);
	g_return_val_if_fail (portion, NULL); 
	
	if (!egg_asn1_write_value (asn, "encryptionAlgorithm.parameters", portion, n_portion))
		g_return_val_if_reached (NULL);
	g_free (portion);
	
	/* Now make a cipher that matches what we wrote out */
	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
	g_return_val_if_fail (gcry == 0, NULL);
	g_return_val_if_fail (cih, NULL);
	
	gcry_cipher_setiv (cih, iv, *n_block);
	gcry_cipher_setkey (cih, key, n_key);
	
	g_free (iv);
	egg_secure_free (key);
	asn1_delete_structure (&asn1_params);
	
	return cih;
}

guchar*
gck_data_der_write_private_pkcs8_plain (gcry_sexp_t skey, gsize *n_data)
{
	ASN1_TYPE asn;
	int res, algorithm;
	gboolean is_priv;
	GQuark oid;
	guchar *params, *key, *data;
	gsize n_params, n_key;
	
	init_quarks ();

	/* Parse and check that the key is for real */
	if (!gck_crypto_sexp_parse_key (skey, &algorithm, &is_priv, NULL))
		g_return_val_if_reached (NULL);
	g_return_val_if_fail (is_priv == TRUE, NULL);
	
	res = asn1_create_element (egg_asn1_get_pkix_asn1type (), 
	                           "PKIX1.pkcs-8-PrivateKeyInfo", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	
	/* Write out the version */
	if (!egg_asn1_write_uint (asn, "version", 0))
		g_return_val_if_reached (NULL);
	
	/* Per algorithm differences */
	switch (algorithm)
	{
	/* RSA gets encoded in a standard simple way */
	case GCRY_PK_RSA:
		oid = OID_PKIX1_RSA;
		params = NULL;
		n_params = 0;
		key = gck_data_der_write_private_key_rsa (skey, &n_key);
		break;
		
	/* DSA gets incoded with the params seperate */
	case GCRY_PK_DSA:
		oid = OID_PKIX1_DSA;
		key = gck_data_der_write_private_key_dsa_part (skey, &n_key);
		params = gck_data_der_write_private_key_dsa_params (skey, &n_params);
		break;
		
	default:
		g_warning ("trying to serialize unsupported private key algorithm: %d", algorithm);
		return NULL;
	};
	
	/* Write out the algorithm */
	if (!egg_asn1_write_oid (asn, "privateKeyAlgorithm.algorithm", oid))
		g_return_val_if_reached (NULL);

	/* Write out the parameters */
	if (!egg_asn1_write_value (asn, "privateKeyAlgorithm.parameters", params, n_params))
		g_return_val_if_reached (NULL);
	egg_secure_free (params);
	
	/* Write out the key portion */
	if (!egg_asn1_write_value (asn, "privateKey", key, n_key))
		g_return_val_if_reached (NULL);
	egg_secure_free (key);
	
	/* Add an empty attributes field */
	if (!egg_asn1_write_value (asn, "attributes", NULL, 0))
		g_return_val_if_reached (NULL);
	
	data = egg_asn1_encode (asn, "", n_data, NULL);
	g_return_val_if_fail (data, NULL); 
	
	asn1_delete_structure (&asn);
	
	return data;
}

guchar*
gck_data_der_write_private_pkcs8_crypted (gcry_sexp_t skey, const gchar *password,
                                          gsize n_password, gsize *n_data)
{
	gcry_error_t gcry;
	gcry_cipher_hd_t cih;
	ASN1_TYPE asn;
	int res;
	guchar *key, *data; 
	gsize n_key, block = 0;

	/* Encode the key in normal pkcs8 fashion */
	key = gck_data_der_write_private_pkcs8_plain (skey, &n_key);
	
	res = asn1_create_element (egg_asn1_get_pkix_asn1type (), 
	                           "PKIX1.pkcs-8-EncryptedPrivateKeyInfo", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	
	/* Create a and write out a cipher used for encryption */
	cih = prepare_and_encode_pkcs8_cipher (asn, password, n_password, &block);
	g_return_val_if_fail (cih, NULL);
	
	/* Pad the block of data */
	if(block > 1) {
		gsize pad;
		guchar *padded;
		
		pad = block - (n_key % block);
		if (pad == 0)
			pad = block;
		padded = g_realloc (key, n_key + pad);
		memset (padded + n_key, pad, pad);
		key = padded;
		n_key += pad;
	}
	
	gcry = gcry_cipher_encrypt (cih, key, n_key, NULL, 0);
	g_return_val_if_fail (gcry == 0, NULL);
	
	gcry_cipher_close (cih);
	
	res = asn1_write_value (asn, "encryptedData", key, n_key);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	
	data = egg_asn1_encode (asn, "", n_data, NULL);
	g_return_val_if_fail (data, NULL); 

	asn1_delete_structure (&asn);
	
	return data;
}

/* -----------------------------------------------------------------------------
 * CERTIFICATES
 */
 
GckDataResult
gck_data_der_read_certificate (const guchar *data, gsize n_data, ASN1_TYPE *asn1)
{
	*asn1 = egg_asn1_decode ("PKIX1.Certificate", data, n_data);
	if (!*asn1)
		return GCK_DATA_UNRECOGNIZED;
	
	return GCK_DATA_SUCCESS;
}

GckDataResult
gck_data_der_read_basic_constraints (const guchar *data, gsize n_data, 
                                     gboolean *is_ca, gint *path_len)
{
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	ASN1_TYPE asn;
	guint value;

	asn = egg_asn1_decode ("PKIX1.BasicConstraints", data, n_data);
	if (!asn)
		goto done;
	
	ret = GCK_DATA_FAILURE;
    
    	if (path_len) {
    		if (!egg_asn1_read_uint (asn, "pathLenConstraint", &value))
    			*path_len = -1;
    		else
    			*path_len = value;
    	}
    	
    	if (is_ca) {
    		if (!egg_asn1_read_boolean (asn, "cA", is_ca))
    			*is_ca = FALSE;
    	}
    	
	ret = GCK_DATA_SUCCESS;

done:
	if (asn)
		asn1_delete_structure (&asn);
	
	if (ret == GCK_DATA_FAILURE) 
		g_message ("invalid basic constraints");
		
	return ret;
}

GckDataResult
gck_data_der_read_key_usage (const guchar *data, gsize n_data, guint *key_usage)
{
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	ASN1_TYPE asn;
	guchar buf[4];
	int res, len;
	
	asn = egg_asn1_decode ("PKIX1.KeyUsage", data, n_data);
	if (!asn)
		goto done;
		
	ret = GCK_DATA_FAILURE;

	memset (buf, 0, sizeof (buf));
	len = sizeof (buf);
	res = asn1_read_value (asn, "", buf, &len);
	if (res != ASN1_SUCCESS || len < 1 || len > 2)
		goto done;

	*key_usage = buf[0] | (buf[1] << 8);
	ret = GCK_DATA_SUCCESS;
	
done:
	if (asn)
		asn1_delete_structure (&asn);		
	return ret;
}

GckDataResult
gck_data_der_read_enhanced_usage (const guchar *data, gsize n_data, GQuark **usage_oids)
{
	GckDataResult ret = GCK_DATA_UNRECOGNIZED;
	ASN1_TYPE asn;
	gchar *part;
	GArray *array;
	GQuark oid;
	int i;
	
	asn = egg_asn1_decode ("PKIX1.ExtKeyUsageSyntax", data, n_data);
	if (!asn)
		goto done;
		
	ret = GCK_DATA_FAILURE;
	
	array = g_array_new (TRUE, TRUE, sizeof (GQuark));
	for (i = 0; TRUE; ++i) {
		part = g_strdup_printf ("?%d", i + 1);
		oid = egg_asn1_read_oid (asn, part);
		g_free (part);
		
		if (!oid) 
			break;
		
		g_array_append_val (array, oid);
	}
	
	*usage_oids = (GQuark*)g_array_free (array, FALSE);
	ret = GCK_DATA_SUCCESS;
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	return ret;
}


guchar*
gck_data_der_write_certificate (ASN1_TYPE asn1, gsize *n_data)
{
	g_return_val_if_fail (asn1, NULL);
	g_return_val_if_fail (n_data, NULL);
	
	return egg_asn1_encode (asn1, "", n_data, NULL);
}
