/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-crypto.c: Test crypto stuff

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "run-auto-test.h"

#include "gck/gck-crypto.h"

#include <gcrypt.h>

#define TEST_RSA \
"(private-key (rsa " \
"(n  #00B78758D55EBFFAB61D07D0DC49B5309A6F1DA2AE51C275DFC2370959BB81AC0C39093B1C618E396161A0DECEB8768D0FFB14F197B96C3DA14190EE0F20D51315#)" \
"(e #010001#)" \
"(d #108BCAC5FDD35812981E6EC5957D98E2AB76E4064C47B861D27C2CC322C50792313C852B4164A035B42D261F1A09F9FFE8F477F9F78FF2EABBDA6BA875C671D7#)" \
"(p #00C357F11B19A18C66573D25D1E466D9AB8BCDDCDFE0B2E80BD46712C4BEC18EB7#)" \
"(q #00F0843B90A60EF7034CA4BE80414ED9497CABCC685143B388013FF989CBB0E093#)" \
"(u #12F2555F52EB56329A991CF0404B51C68AC921AD370A797860F550415FF987BD#)" \
"))"

#define TEST_DSA \
"(private-key (dsa " \
"  (p #0090EC0B60735839C754EAF8F64BB03FC35398D69772BFAE540079DEA2D3A61FAFFB27630A038A01A3D0CD62A10745A574A27ECB462F4F0885B79C61BBE954A60A29668AD54BBA5C07A72FD8B1105249670B339DF2C59E64A47064EFCF0B7236C5C72CD55CEB32917430BEC9A003D4E484FBAA84D79571B38D6B5AC95BB73E3F7B#)" \
"  (q #00FA214A1385C21BFEBAADAB240A2430C607D56271#)" \
"  (g #2DE05751F5DAEE97F3D43C54595A3E94A080728F0C66C98AEBED5762F6AB155802D8359EAD1DE1EC36A459FBEEEA48E59B9E6A8CB4F5295936B3CC881A5D957C7339175E2CFFE0F30D3711E430DB6648C2EB474AA10A4A3297450531FF2C7C6951220C9D446B6B6B0F00262E1EBEB3CC861476AA518CC555C9ABF9E5F39023FC#)" \
"  (y #54734451DB79D4EEDF0BBCEBD43BB6CBB7B8584603B957080075DD318EB5B0266D4B20DC5EFF376BDFC4EA2983B1F7F02A39ED4C619ED68712729FFF3B7C696ADD1B6D748F56A4B4BEC5C4385E528423A3B88AE65E6D5500F97839E7A486255982189C3B4FA8D94338C76F0E5CAFC9A30A1ED728BB9F2091D594E3250A09EA00#)" \
"  (x #00876F84F709D51108DFB0CBFA1F1C569C09C413EC#)))"

gcry_sexp_t rsakey = NULL;
gcry_sexp_t dsakey = NULL;

DEFINE_SETUP(crypto_setup)
{
	gcry_error_t gcry;
	
	gck_crypto_initialize ();
	
	gcry = gcry_sexp_new (&rsakey, TEST_RSA, strlen (TEST_RSA), 1);
	g_return_if_fail (gcry == 0);
	gcry = gcry_sexp_new (&dsakey, TEST_DSA, strlen (TEST_DSA), 1);
	g_return_if_fail (gcry == 0);
}

DEFINE_TEARDOWN(crypto_setup)
{
	gcry_sexp_release (rsakey);
	rsakey = NULL;
	gcry_sexp_release (dsakey);
	dsakey = NULL;
}

const static struct {
	const gchar *password;
	int cipher_algo;
	int hash_algo;
	int iterations;
	const gchar *salt;
	
	const gchar *result_simple;
	const gchar *result_pkcs12;
	const gchar *result_pbkdf2;
	const gchar *result_pbe;
} all_generation_tests[] = {
	
	{ /* 24 byte output */
		"booo", GCRY_CIPHER_3DES, GCRY_MD_MD5, 1, 
		"\x70\x4C\xFF\xD6\x2F\xBA\x03\xE9", 
		"\x84\x12\xBB\x34\x94\x8C\x40\xAD\x97\x57\x96\x74\x5B\x6A\xFB\xF8\xD6\x61\x33\x51\xEA\x8C\xCF\xD8", 
		NULL,
		NULL,
		NULL
        },

	{ /* 5 byte output */
		"booo", GCRY_CIPHER_RFC2268_40, GCRY_MD_SHA1, 2048, 
		"\x8A\x58\xC2\xE8\x7C\x1D\x80\x11",
		NULL,
		"\xD6\xA6\xF0\x76\x66",
		NULL,
		NULL
	},
	
	{ /* Null Password, 5 byte output */
		NULL, GCRY_CIPHER_RFC2268_40, GCRY_MD_SHA1, 2000,
		"\x04\xE0\x1C\x3E\xF8\xF2\xE9\xFD",
		NULL,
		"\x98\x7F\x20\x97\x1E",
		NULL,
		NULL
	},
        
	{ /* 24 byte output */
		"booo", GCRY_CIPHER_3DES, GCRY_MD_SHA1, 2048,
		"\xBD\xEE\x0B\xC6\xCF\x43\xAC\x25",
		NULL,
		"\x3F\x38\x1B\x0E\x87\xEB\x19\xBE\xD1\x39\xDC\x5B\xC2\xD2\xB3\x3C\x35\xA8\xB8\xF9\xEE\x66\x48\x94",
		"\x20\x25\x90\xD8\xD6\x98\x3E\x71\x10\x17\x1F\x51\x49\x87\x27\xCA\x97\x27\xD1\xC9\x72\xF8\x11\xBB",
		NULL
	},

	{ /* Empty password, 24 byte output */
		"", GCRY_CIPHER_3DES, GCRY_MD_SHA1, 2048,
		"\xF7\xCF\xD9\xCF\x1F\xF3\xAD\xF6",
		NULL,
		NULL,
		"\x53\xE3\x35\x9E\x5D\xC1\x85\x1A\x71\x3A\x67\x4E\x80\x56\x13\xD6\x4E\x3E\x89\x43\xB7\x1D\x5F\x7F",
		NULL
	},

	{ /* Empty password, 24 byte output */
		"", GCRY_CIPHER_3DES, GCRY_MD_SHA1, 2048,
		"\xD9\xB3\x2E\xC7\xBA\x1A\x8E\x15",
		NULL,
		"\x39\x70\x75\x7C\xF5\xE2\x13\x0B\x5D\xC2\x9D\x96\x8B\x71\xC7\xFC\x5B\x97\x1F\x79\x9F\x06\xFC\xA2",
		NULL,
		NULL
	},
	
	{ /* 8 byte output */
		"booo", GCRY_CIPHER_DES, GCRY_MD_MD5, 2048,
		"\x93\x4C\x3D\x29\xA2\x42\xB0\xF5",
		NULL, 
		NULL,
		NULL,
		"\x8C\x67\x19\x7F\xB9\x23\xE2\x8D"
	}
};

#define N_GENERATION_TESTS (sizeof (all_generation_tests) / sizeof (all_generation_tests[0]))

DEFINE_TEST(generate_key_simple)
{
	int i;
	gboolean ret;
	guchar *key;
	
	for (i = 0; i < N_GENERATION_TESTS; ++i) {
		
		if (!all_generation_tests[i].result_simple)
			continue;
		
		ret = gck_crypto_symkey_generate_simple (all_generation_tests[i].cipher_algo, 
                                                         all_generation_tests[i].hash_algo,
                                                         all_generation_tests[i].password, -1,
                                                         (guchar*)all_generation_tests[i].salt, 8,
                                                         all_generation_tests[i].iterations,
                                                         &key, NULL);
		g_assert (ret && "key generation failed");

		ret = (memcmp (key, all_generation_tests[i].result_simple, 
		               gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);

		g_assert (ret && "invalid simple key generated"); 
	}
}

DEFINE_TEST(generate_key_pkcs12)
{
	int i;
	gboolean ret;
	guchar *key;
	
	for (i = 0; i < N_GENERATION_TESTS; ++i) {
		
		if (!all_generation_tests[i].result_pkcs12)
			continue;
		
		ret = gck_crypto_symkey_generate_pkcs12 (all_generation_tests[i].cipher_algo, 
                                                         all_generation_tests[i].hash_algo,
                                                         all_generation_tests[i].password, -1,
                                                         (guchar*)all_generation_tests[i].salt, 8,
                                                         all_generation_tests[i].iterations,
                                                         &key, NULL);
		g_assert ("failed to generate pkcs12 key" && ret);
		
		ret = (memcmp (key, all_generation_tests[i].result_pkcs12, 
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);
			
		g_assert ("invalid pkcs12 key generated" && ret); 
	}
}

DEFINE_TEST(generate_key_pbkdf2)
{
	int i;
	gboolean ret;
	guchar *key;
	
	for (i = 0; i < N_GENERATION_TESTS; ++i) {
		
		if (!all_generation_tests[i].result_pbkdf2)
			continue;
		
		ret = gck_crypto_symkey_generate_pbkdf2 (all_generation_tests[i].cipher_algo, 
                                                         all_generation_tests[i].hash_algo,
                                                         all_generation_tests[i].password, -1,
                                                         (guchar*)all_generation_tests[i].salt, 8,
                                                         all_generation_tests[i].iterations,
                                                         &key, NULL);
		g_assert ("failed to generate pbkdf2 key" && ret);
			
		ret = (memcmp (key, all_generation_tests[i].result_pbkdf2, 
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);
		
		g_assert ("invalid pbkdf2 key generated" && ret); 
	}
}

DEFINE_TEST(generate_key_pbe)
{
	int i;
	gboolean ret;
	guchar *key;
	
	for (i = 0; i < N_GENERATION_TESTS; ++i) {
		
		if (!all_generation_tests[i].result_pbe)
			continue;
		
		ret = gck_crypto_symkey_generate_pbe (all_generation_tests[i].cipher_algo, 
                                                      all_generation_tests[i].hash_algo,
                                                      all_generation_tests[i].password, -1,
                                                      (guchar*)all_generation_tests[i].salt, 8,
                                                      all_generation_tests[i].iterations,
                                                      &key, NULL);
		g_assert ("failed to generate pbe key" && ret);
		
		ret = (memcmp (key, all_generation_tests[i].result_pbe, 
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);
			
		g_assert ("invalid pbe key generated" && ret); 
			
	}
}

DEFINE_TEST(parse_key)
{
	gcry_sexp_t sexp = NULL;
	gcry_mpi_t mpi = NULL;
	gboolean ret;
	gboolean is_priv = FALSE;
	int algorithm = 0;
	
	/* Get the private key out */
	ret = gck_crypto_sexp_parse_key (rsakey, &algorithm, &is_priv, &sexp);
	g_assert (ret);
	g_assert (algorithm == GCRY_PK_RSA);
	g_assert (is_priv == TRUE);
	g_assert (sexp != NULL);
	
	ret = gck_crypto_sexp_extract_mpi (rsakey, &mpi, "p", NULL);
	g_assert (ret);
	g_assert (mpi != NULL);
}

DEFINE_TEST(sexp_key_to_public)
{
	gcry_sexp_t pubkey = NULL;
	guchar id1[20], id2[20];
	gboolean ret;
	guchar *p;
	
	/* RSA */
	ret = gck_crypto_sexp_key_to_public (rsakey, &pubkey);
	g_assert (ret);
	g_assert (pubkey != NULL);
	
	p = gcry_pk_get_keygrip (rsakey, id1);
	g_return_if_fail (p == id1);
	p = gcry_pk_get_keygrip (pubkey, id2);
	g_return_if_fail (p == id2);

	g_assert (memcmp (id1, id2, sizeof (id1)) == 0);
	
	gcry_sexp_release (pubkey);


	/* DSA */
	ret = gck_crypto_sexp_key_to_public (dsakey, &pubkey);
	g_assert (ret);
	g_assert (pubkey != NULL);
	
	p = gcry_pk_get_keygrip (dsakey, id1);
	g_return_if_fail (p == id1);
	p = gcry_pk_get_keygrip (pubkey, id2);
	g_return_if_fail (p == id2);

	g_assert (memcmp (id1, id2, sizeof (id1)) == 0);
	
	gcry_sexp_release (pubkey);

}
