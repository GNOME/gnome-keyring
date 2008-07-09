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

#include "common/gkr-crypto.h"

#include "pkix/gkr-pkix-der.h"

#include <glib.h>
#include <gcrypt.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void)
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void)
 * 
 * Tests be run in the order specified here.
 */

const gchar *rsapub = "(public-key (rsa" \
" (n #00AE4B381CF43F7DC24CF90827325E2FB2EB57EDDE29562DF391C8942AA8E6423410E2D3FE26381F9DE0395E74BF2D17621AE46992C72CF895F6FA5FBE98054FBF#)" \
" (e #010001#)))";

const gchar *rsaprv = "(private-key (rsa" \
" (n #00B78758D55EBFFAB61D07D0DC49B5309A6F1DA2AE51C275DFC2370959BB81AC0C39093B1C618E396161A0DECEB8768D0FFB14F197B96C3DA14190EE0F20D51315#)" \
" (e #010001#)" \
" (d #108BCAC5FDD35812981E6EC5957D98E2AB76E4064C47B861D27C2CC322C50792313C852B4164A035B42D261F1A09F9FFE8F477F9F78FF2EABBDA6BA875C671D7#)" \
" (p #00C357F11B19A18C66573D25D1E466D9AB8BCDDCDFE0B2E80BD46712C4BEC18EB7#)" \
" (q #00F0843B90A60EF7034CA4BE80414ED9497CABCC685143B388013FF989CBB0E093#)" \
" (u #12F2555F52EB56329A991CF0404B51C68AC921AD370A797860F550415FF987BD#)))";

const gchar *dsapub = "(public-key (dsa" \
" (p #0090EC0B60735839C754EAF8F64BB03FC35398D69772BFAE540079DEA2D3A61FAFFB27630A038A01A3D0CD62A10745A574A27ECB462F4F0885B79C61BBE954A60A29668AD54BBA5C07A72FD8B1105249670B339DF2C59E64A47064EFCF0B7236C5C72CD55CEB32917430BEC9A003D4E484FBAA84D79571B38D6B5AC95BB73E3F7B#)" \
" (q #00FA214A1385C21BFEBAADAB240A2430C607D56271#)" \
" (g #2DE05751F5DAEE97F3D43C54595A3E94A080728F0C66C98AEBED5762F6AB155802D8359EAD1DE1EC36A459FBEEEA48E59B9E6A8CB4F5295936B3CC881A5D957C7339175E2CFFE0F30D3711E430DB6648C2EB474AA10A4A3297450531FF2C7C6951220C9D446B6B6B0F00262E1EBEB3CC861476AA518CC555C9ABF9E5F39023FC#)" \
" (y #54734451DB79D4EEDF0BBCEBD43BB6CBB7B8584603B957080075DD318EB5B0266D4B20DC5EFF376BDFC4EA2983B1F7F02A39ED4C619ED68712729FFF3B7C696ADD1B6D748F56A4B4BEC5C4385E528423A3B88AE65E6D5500F97839E7A486255982189C3B4FA8D94338C76F0E5CAFC9A30A1ED728BB9F2091D594E3250A09EA00#)))";

const gchar *dsaprv = "(private-key (dsa" \
"  (p #0090EC0B60735839C754EAF8F64BB03FC35398D69772BFAE540079DEA2D3A61FAFFB27630A038A01A3D0CD62A10745A574A27ECB462F4F0885B79C61BBE954A60A29668AD54BBA5C07A72FD8B1105249670B339DF2C59E64A47064EFCF0B7236C5C72CD55CEB32917430BEC9A003D4E484FBAA84D79571B38D6B5AC95BB73E3F7B#)" \
"  (q #00FA214A1385C21BFEBAADAB240A2430C607D56271#)" \
"  (g #2DE05751F5DAEE97F3D43C54595A3E94A080728F0C66C98AEBED5762F6AB155802D8359EAD1DE1EC36A459FBEEEA48E59B9E6A8CB4F5295936B3CC881A5D957C7339175E2CFFE0F30D3711E430DB6648C2EB474AA10A4A3297450531FF2C7C6951220C9D446B6B6B0F00262E1EBEB3CC861476AA518CC555C9ABF9E5F39023FC#)" \
"  (y #54734451DB79D4EEDF0BBCEBD43BB6CBB7B8584603B957080075DD318EB5B0266D4B20DC5EFF376BDFC4EA2983B1F7F02A39ED4C619ED68712729FFF3B7C696ADD1B6D748F56A4B4BEC5C4385E528423A3B88AE65E6D5500F97839E7A486255982189C3B4FA8D94338C76F0E5CAFC9A30A1ED728BB9F2091D594E3250A09EA00#)" \
"  (x #00876F84F709D51108DFB0CBFA1F1C569C09C413EC#)))";

static gboolean
compare_keys (CuTest *cu, gcry_sexp_t key, gcry_sexp_t sexp)
{
	guchar hash1[20], hash2[20];
	guchar *p;
	
	/* Now compare them */
	p = gcry_pk_get_keygrip (key, hash1);
	CuAssert (cu, "couldn't get key id for private key", p == hash1);
	p = gcry_pk_get_keygrip (key, hash2);
	CuAssert (cu, "couldn't get key id for parsed private key", p == hash2);

	return memcmp (hash1, hash2, 20) == 0;
}

static void
test_der_public (CuTest *cu, gcry_sexp_t key)
{
	guchar *data;
	gsize n_data;
	GkrPkixResult ret;
	gcry_sexp_t sexp;
		
	/* Encode it */
	data = gkr_pkix_der_write_public_key (key, &n_data);
	CuAssert (cu, "couldn't encode public key", data != NULL);
	CuAssert (cu, "encoding is empty", n_data > 0);
	
	/* Now parse it */
	ret = gkr_pkix_der_read_public_key (data, n_data, &sexp);
	CuAssert (cu, "couldn't decode public key", ret == GKR_PKIX_SUCCESS);
	CuAssert (cu, "parsed key is empty", sexp != NULL);
	
	/* Now compare them */
	CuAssert (cu, "key parsed differently", compare_keys (cu, key, sexp)); 	
}

void unit_test_der_rsa_public (CuTest* cu)
{
	gcry_sexp_t key;
	gcry_error_t gcry;
	
	gcry = gcry_sexp_sscan (&key, NULL, rsapub, strlen (rsapub));
	g_return_if_fail (gcry == 0);

	test_der_public (cu, key);	
}

void unit_test_der_dsa_public (CuTest* cu)
{
	gcry_sexp_t key;
	gcry_error_t gcry;
	
	gcry = gcry_sexp_sscan (&key, NULL, dsapub, strlen (dsapub));
	g_return_if_fail (gcry == 0);

	test_der_public (cu, key);	
}

static void
test_der_private (CuTest *cu, gcry_sexp_t key)
{
	guchar *data;
	gsize n_data;
	GkrPkixResult ret;
	gcry_sexp_t sexp;

	/* Encode it */
	data = gkr_pkix_der_write_private_key (key, &n_data);
	CuAssert (cu, "couldn't encode private key", data != NULL);
	CuAssert (cu, "encoding is empty", n_data > 0);
	
	/* Now parse it */
	ret = gkr_pkix_der_read_private_key (data, n_data, &sexp);
	CuAssert (cu, "couldn't decode private key", ret == GKR_PKIX_SUCCESS);
	CuAssert (cu, "parsed key is empty", sexp != NULL);
	
	/* Now compare them */
	CuAssert (cu, "key parsed differently", compare_keys (cu, key, sexp)); 	
}

void unit_test_der_rsa_private (CuTest* cu)
{
	gcry_sexp_t key;
	gcry_error_t gcry;
	
	gcry = gcry_sexp_sscan (&key, NULL, rsaprv, strlen (rsaprv));
	g_return_if_fail (gcry == 0);
	
	test_der_private (cu, key);
}

void unit_test_der_dsa_private (CuTest* cu)
{
	gcry_sexp_t key;
	gcry_error_t gcry;
	
	gcry = gcry_sexp_sscan (&key, NULL, dsaprv, strlen (dsaprv));
	g_return_if_fail (gcry == 0);
	
	test_der_private (cu, key);
}

void unit_test_der_dsa_private_parts (CuTest* cu)
{
	guchar *params, *key;
	gsize n_params, n_key;
	gcry_sexp_t skey, pkey;
	gcry_error_t gcry;
	GkrPkixResult result;
	
	gcry = gcry_sexp_sscan (&skey, NULL, dsaprv, strlen (dsaprv));
	g_return_if_fail (gcry == 0);
	
	/* Encode the the dsa key by parts */
	params = gkr_pkix_der_write_private_key_dsa_params (skey, &n_params);
	CuAssert (cu, "didn't encode dsa params", params != NULL);
	key = gkr_pkix_der_write_private_key_dsa_part (skey, &n_key);
	CuAssert (cu, "didn't encode dsa key", key != NULL);
	
	/* Parse the dsa key by parts */
	result = gkr_pkix_der_read_private_key_dsa_parts (key, n_key, params, n_params, &pkey);
	CuAssert (cu, "couldn't parse dsa parts", result == GKR_PKIX_SUCCESS);
	CuAssert (cu, "parsing dsa parts resulted in null key", pkey != NULL);
	
	/* Now compare them */
	CuAssert (cu, "key parsed differently", compare_keys (cu, skey, pkey)); 	
}
