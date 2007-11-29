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

#include "common/gkr-crypto.h"

#include <gcrypt.h>

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
 
void unit_setup_crypto (void)
{
	gkr_crypto_setup ();
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
        	"\x97\xFD\xBC\xF2\x4B\x74\x73\x18\xA4\x32\x59\x9A\x55\xC6\x67\x70\xC0\x40\xD7\xFF\x1B\xDB\xBF\x6E",
        	"\x53\xE3\x35\x9E\x5D\xC1\x85\x1A\x71\x3A\x67\x4E\x80\x56\x13\xD6\x4E\x3E\x89\x43\xB7\x1D\x5F\x7F",
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

void unit_test_generate_key_simple (CuTest* cu)
{
	int i;
	gboolean ret;
	guchar *key;
	
	for (i = 0; i < N_GENERATION_TESTS; ++i) {
		
		if (!all_generation_tests[i].result_simple)
			continue;
		
		ret = gkr_crypto_generate_symkey_simple (all_generation_tests[i].cipher_algo, 
                                                         all_generation_tests[i].hash_algo,
                                                         all_generation_tests[i].password,
                                                         (guchar*)all_generation_tests[i].salt, 8,
                                                         all_generation_tests[i].iterations,
                                                         &key, NULL);
		CuAssert (cu, "failed to generate simple key", ret == TRUE);
			
		CuAssert (cu, "invalid simple key generated", 
			memcmp (key, all_generation_tests[i].result_simple, 
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);
	}
}

void unit_test_generate_key_pkcs12 (CuTest* cu)
{
	int i;
	gboolean ret;
	guchar *key;
	
	for (i = 0; i < N_GENERATION_TESTS; ++i) {
		
		if (!all_generation_tests[i].result_pkcs12)
			continue;
		
		ret = gkr_crypto_generate_symkey_pkcs12 (all_generation_tests[i].cipher_algo, 
                                                         all_generation_tests[i].hash_algo,
                                                         all_generation_tests[i].password,
                                                         (guchar*)all_generation_tests[i].salt, 8,
                                                         all_generation_tests[i].iterations,
                                                         &key, NULL);
		CuAssert (cu, "failed to generate pkcs12 key", ret == TRUE);
			
		CuAssert (cu, "invalid pkcs12 key generated", 
			memcmp (key, all_generation_tests[i].result_pkcs12, 
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);
	}
}

void unit_test_generate_key_pbkdf2 (CuTest* cu)
{
	int i;
	gboolean ret;
	guchar *key;
	
	for (i = 0; i < N_GENERATION_TESTS; ++i) {
		
		if (!all_generation_tests[i].result_pbkdf2)
			continue;
		
		ret = gkr_crypto_generate_symkey_pbkdf2 (all_generation_tests[i].cipher_algo, 
                                                         all_generation_tests[i].hash_algo,
                                                         all_generation_tests[i].password,
                                                         (guchar*)all_generation_tests[i].salt, 8,
                                                         all_generation_tests[i].iterations,
                                                         &key, NULL);
		CuAssert (cu, "failed to generate pbkdf2 key", ret == TRUE);
			
		CuAssert (cu, "invalid pbkdf2 key generated", 
			memcmp (key, all_generation_tests[i].result_pbkdf2, 
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);
	}
}

void unit_test_generate_key_pbe (CuTest* cu)
{
	int i;
	gboolean ret;
	guchar *key;
	
	for (i = 0; i < N_GENERATION_TESTS; ++i) {
		
		if (!all_generation_tests[i].result_pbe)
			continue;
		
		ret = gkr_crypto_generate_symkey_pbe (all_generation_tests[i].cipher_algo, 
                                                      all_generation_tests[i].hash_algo,
                                                      all_generation_tests[i].password,
                                                      (guchar*)all_generation_tests[i].salt, 8,
                                                      all_generation_tests[i].iterations,
                                                      &key, NULL);
		CuAssert (cu, "failed to generate pbe key", ret == TRUE);
			
		CuAssert (cu, "invalid pbe key generated", 
			memcmp (key, all_generation_tests[i].result_pbe, 
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);
	}
}

gcry_sexp_t thekey = NULL;

void unit_test_parse_key (CuTest *cu)
{
	gcry_sexp_t params = NULL;
	gcry_sexp_t sexp = NULL;
	gcry_error_t gcry;
	gcry_mpi_t mpi = NULL;
	gboolean ret;
	gboolean is_priv = FALSE;
	int algorithm = 0;
	
	gcry = gcry_sexp_build (&params, NULL, "(genkey (rsa (nbits 3:512)))");
	g_return_if_fail (gcry == 0);
	
	gcry = gcry_pk_genkey (&sexp, params);
	g_return_if_fail (gcry == 0);
	
	/* Get the private key out */
	thekey = gkr_crypto_sexp_get_child (sexp, "private-key", NULL);
	CuAssert (cu, "couldn't extract private key", sexp != NULL);
	
	ret = gkr_crypto_skey_parse (thekey, &algorithm, &is_priv, &sexp);
	CuAssert (cu, "couldn't parse rsa key", ret);
	CuAssert (cu, "parsed bad algorithm", algorithm == GCRY_PK_RSA);
	CuAssert (cu, "not a private-key", is_priv == TRUE);
	CuAssert (cu, "didn't get numbers", sexp != NULL);
	
	ret = gkr_crypto_sexp_extract_mpi (sexp, &mpi, "p", NULL);
	CuAssert (cu, "couldn't extract mpi from key", ret);
	CuAssert (cu, "no mpi returned from extract", mpi != NULL);
}

void unit_test_make_keyid (CuTest *cu)
{
	guchar hash[20];
	gkrunique uni;
	const guchar *p;
	gsize n;
	
	p = gcry_pk_get_keygrip (thekey, hash);
	g_return_if_fail (p == hash);
	
	uni = gkr_crypto_skey_make_id (thekey);
	CuAssert (cu, "no unique returned as key id", uni != NULL);
	
	p = gkr_unique_get_raw (uni, &n);
	CuAssert (cu, "key id is of wrong length", n == sizeof (hash));
	CuAssert (cu, "key grip doesn't match key id", memcmp (hash, p, n) == 0);	
}

void unit_test_key_to_public (CuTest *cu)
{
	gcry_sexp_t pubkey = NULL;
	gboolean ret;
	gkrunique u1, u2;
	
	ret = gkr_crypto_skey_private_to_public (thekey, &pubkey);
	CuAssert (cu, "couldn't make public key", ret);
	CuAssert (cu, "returned null public key", pubkey != NULL);
	
	u1 = gkr_crypto_skey_make_id (thekey);
	u2 = gkr_crypto_skey_make_id (pubkey);
	CuAssert (cu, "public and private keys are not equivalent", 
	          gkr_unique_equals (u1, u2)); 
}	

