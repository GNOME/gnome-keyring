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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"
#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"
#include "egg/egg-symkey.h"
#include "egg/egg-testing.h"

typedef struct _EggAsn1xDef ASN1_ARRAY_TYPE;
typedef struct _EggAsn1xDef asn1_static_node;
#include "test.asn.h"

#include <gcrypt.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

static const struct {
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

static void
test_generate_key_simple (void)
{
	int i;
	gboolean ret;
	guchar *key;

	for (i = 0; i < N_GENERATION_TESTS; ++i) {

		if (!all_generation_tests[i].result_simple)
			continue;

		ret = egg_symkey_generate_simple (all_generation_tests[i].cipher_algo,
		                                  all_generation_tests[i].hash_algo,
		                                  all_generation_tests[i].password, -1,
		                                  (guchar*)all_generation_tests[i].salt, 8,
		                                  all_generation_tests[i].iterations,
		                                  &key, NULL);
		g_assert (ret && "key generation failed");

		ret = (memcmp (key, all_generation_tests[i].result_simple,
		               gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);

		g_assert (ret && "invalid simple key generated");

		egg_secure_free (key);
	}
}

static void
test_generate_key_pkcs12 (void)
{
	int i;
	gboolean ret;
	guchar *key;

	for (i = 0; i < N_GENERATION_TESTS; ++i) {

		if (!all_generation_tests[i].result_pkcs12)
			continue;

		ret = egg_symkey_generate_pkcs12 (all_generation_tests[i].cipher_algo,
		                                  all_generation_tests[i].hash_algo,
		                                  all_generation_tests[i].password, -1,
		                                  (guchar*)all_generation_tests[i].salt, 8,
		                                  all_generation_tests[i].iterations,
		                                  &key, NULL);
		g_assert ("failed to generate pkcs12 key" && ret);

		ret = (memcmp (key, all_generation_tests[i].result_pkcs12,
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);

		g_assert ("invalid pkcs12 key generated" && ret);

		egg_secure_free (key);
	}
}

static void
test_generate_key_pbkdf2 (void)
{
	int i;
	gboolean ret;
	guchar *key;

	for (i = 0; i < N_GENERATION_TESTS; ++i) {

		if (!all_generation_tests[i].result_pbkdf2)
			continue;

		ret = egg_symkey_generate_pbkdf2 (all_generation_tests[i].cipher_algo,
		                                  all_generation_tests[i].hash_algo,
		                                  all_generation_tests[i].password, -1,
		                                  (guchar*)all_generation_tests[i].salt, 8,
		                                  all_generation_tests[i].iterations,
		                                  &key, NULL);
		g_assert ("failed to generate pbkdf2 key" && ret);

		ret = (memcmp (key, all_generation_tests[i].result_pbkdf2,
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);

		g_assert ("invalid pbkdf2 key generated" && ret);

		egg_secure_free (key);
	}
}

static void
test_generate_key_pbe (void)
{
	int i;
	gboolean ret;
	guchar *key;

	for (i = 0; i < N_GENERATION_TESTS; ++i) {

		if (!all_generation_tests[i].result_pbe)
			continue;

		ret = egg_symkey_generate_pbe (all_generation_tests[i].cipher_algo,
		                               all_generation_tests[i].hash_algo,
		                               all_generation_tests[i].password, -1,
		                               (guchar*)all_generation_tests[i].salt, 8,
		                               all_generation_tests[i].iterations,
		                               &key, NULL);
		g_assert ("failed to generate pbe key" && ret);

		ret = (memcmp (key, all_generation_tests[i].result_pbe,
			        gcry_cipher_get_algo_keylen (all_generation_tests[i].cipher_algo)) == 0);

		g_assert ("invalid pbe key generated" && ret);

		egg_secure_free (key);
	}
}

typedef struct {
	const gchar *name;
	const gchar *scheme;

	/* Info to use with cipher */
	const gchar *password;
	const gchar *salt;
	gsize iterations;

	/* DER representation of cipher */
	gsize n_der;
	const gchar *der;

	/* Data to encrypt and test with */
	gsize n_text_length;
	const gchar *plain_text;
	const gchar *cipher_text;
} ReadCipher;

static const ReadCipher cipher_tests[] = {
	{
		"pbe-sha1-des-cbc", "1.2.840.113549.1.5.10",
		"password", "saltsalt", 33,
		15, "\x30\x0D"
			"\x04\x08""saltsalt"
			"\x02\x01\x2A",
		8, "plaintex", "\x69\xe2\x88\x4c\x31\xcf\x0e\x2a"
	},
	{
		"pkcs12-pbe-3des-sha1", "1.2.840.113549.1.12.1.3",
		"password", "saltsalt", 33,
		15, "\x30\x0D"
			"\x04\x08""saltsalt"
			"\x02\x01\x2A",
		8, "plaintex", "\xcf\xfb\x49\x2e\x42\x75\x15\x56"
	},
	{
		"pkcs5-pbes2", "1.2.840.113549.1.5.13",
		"password", "salt", 33,
		48, "\x30\x2e"
			"\x30\x16"
				"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c"
				"\x30\x09"
					"\x04\x04\x73\x61\x6c\x74"
					"\x02\x01\x21"
			"\x30\x14"
				"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x03\x07"
				"\x04\x08\x73\x61\x6c\x74\x73\x61\x6c\x74",
		8, "plaintex", "\x46\x1A\x3A\x39\xD0\xF5\x21\x5C"
	},
	{
		"pkcs5-pbes2-des-cbc", "1.2.840.113549.1.5.13",
		"password", "salt", 33,
		0x2d, "\x30\x2b"
			"\x30\x16"
				"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c"
				"\x30\x09"
					"\x04\x04\x73\x61\x6c\x74"
					"\x02\x01\x21"
			"\x30\x11"
				"\x06\x05\x2b\x0e\x03\x02\x07"
				"\x04\x08\x73\x61\x6c\x74\x73\x61\x6c\x74",
		8, "plaintex", "\xB7\x7B\x54\xBF\x29\x4D\x31\x7D"
	}
};

typedef struct {
	const gchar *name;
	const gchar *scheme;

	/* Info to use with cipher */
	const gchar *password;

	/* DER representation of cipher */
	gsize n_der;
	const gchar *der;
} InvalidCipher;

#if 0
#include "egg/egg-hex.h"

static void
create_pkcs5_pbes2 (void)
{
	GNode *asn;
	GNode *param;
	GBytes *bytes;
	gconstpointer data;
	gsize size;

	asn = egg_asn1x_create (pkix_asn1_tab, "pkcs-5-PBES2-params");

	egg_asn1x_set_oid_as_string (egg_asn1x_node (asn, "keyDerivationFunc", "algorithm", NULL), "1.2.840.113549.1.5.12");
	param = egg_asn1x_create (pkix_asn1_tab, "pkcs-5-PBKDF2-params");
	egg_asn1x_set_integer_as_ulong (egg_asn1x_node (param, "iterationCount", NULL), 33);
#if 1
	egg_asn1x_set_choice (egg_asn1x_node (param, "salt", NULL), egg_asn1x_node (param, "salt", "specified", NULL));
	egg_asn1x_set_string_as_raw (egg_asn1x_node (param, "salt", "specified", NULL), (guchar *)"salt", 4, NULL);
#else
	egg_asn1x_set_choice (egg_asn1x_node (param, "salt", NULL), egg_asn1x_node (param, "salt", "otherSource", NULL)); */
	egg_asn1x_set_oid_as_string (egg_asn1x_node (param, "salt", "otherSource", "algorithm", NULL), "1.2.1"); */
#endif
	egg_asn1x_set_any_from (egg_asn1x_node (asn, "keyDerivationFunc", "parameters", NULL), param);
	egg_asn1x_destroy (param);

	egg_asn1x_set_oid_as_string (egg_asn1x_node (asn, "encryptionScheme", "algorithm", NULL), "1.3.14.3.2.7");
	param = egg_asn1x_create (pkix_asn1_tab, "pkcs-5-des-EDE3-CBC-params");
	egg_asn1x_set_string_as_raw (param, (guchar *)"saltsalt", 8, NULL);
	egg_asn1x_set_any_from (egg_asn1x_node (asn, "encryptionScheme", "parameters", NULL), param);
	egg_asn1x_destroy (param);

	bytes = egg_asn1x_encode (asn, NULL);
	egg_asn1x_assert (bytes != NULL, asn);
	egg_asn1x_destroy (asn);

	data = g_bytes_get_data (bytes, &size);
	g_printerr ("%s: \\x%s\n", __FUNCTION__, egg_hex_encode_full (data, size, FALSE, "\\x", 1));
	g_bytes_unref (bytes);
}
#endif

static void
test_read_cipher (gconstpointer data)
{
	const ReadCipher *test = data;
	gcry_cipher_hd_t cih;
	gcry_error_t gcry;
	GNode *asn;
	gboolean ret;
	GBytes *bytes;
	gpointer block;

	bytes = g_bytes_new_static (test->der, test->n_der);
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestAny", bytes);
	g_assert (asn != NULL);
	g_bytes_unref (bytes);

	ret = egg_symkey_read_cipher (g_quark_from_static_string (test->scheme),
	                              test->password, strlen (test->password),
	                              asn, &cih);

	egg_asn1x_destroy (asn);
	g_assert (ret == TRUE);

	block = g_memdup2 (test->plain_text, test->n_text_length);
	gcry = gcry_cipher_encrypt (cih, block, test->n_text_length, NULL, 0);
	g_assert_cmpint (gcry, ==, 0);

	egg_assert_cmpmem (test->cipher_text, test->n_text_length, ==,
	                   block, test->n_text_length);

	gcry_cipher_close (cih);
	g_free (block);
}

static const InvalidCipher cipher_invalid[] = {
	{
		"pbe-bad-der", "1.2.840.113549.1.12.1.3",
		"password",
		/* Valid DER, but not pkcs-12-PbeParams */
		11, "\x30\x09\x04\x07""invalid"
	},
	{
		"pkcs5-pbe-bad-der", "1.2.840.113549.1.5.10",
		"password",
		/* Valid DER, but not pkcs-5-PBE-params */
		11, "\x30\x09\x04\x07""invalid"
	},
	{
		"pkcs5-pbes2-bad-der", "1.2.840.113549.1.5.13",
		"password",
		/* Valid DER, but not pkcs-5-PBES2-params */
		11, "\x30\x09\x04\x07""invalid"
	},
	{
		"pkcs5-pbes2-missing-key-parameters", "1.2.840.113549.1.5.13",
		"password",
		0x25, "\x30\x23"
			"\x30\x0b"
				"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c"
				/* Missing OPTIONAL parameters here */
			"\x30\x14"
				"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x03\x07"
				"\x04\x08\x73\x61\x6c\x74\x73\x61\x6c\x74",
	},
	{
		"pkcs5-pbes2-missing-scheme-parameters", "1.2.840.113549.1.5.13",
		"password",
		0x26, "\x30\x24"
			"\x30\x16"
				"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c"
				"\x30\x09"
					"\x04\x04\x73\x61\x6c\x74"
					"\x02\x01\x21"
			"\x30\x0a"
				"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x03\x07"
				/* Missing OPTIONAL parameters here */
	},
	{
		"pkcs5-pbes2-bad-key-derivation-algo", "1.2.840.113549.1.5.13",
		"password",
		48, "\x30\x2e"
			"\x30\x16" /* An unsupported keyDerivation algorithm oid */
				"\x06\x09\x2a\x86\x48\x86\xf7\x0c\x01\x04\x0b"
				"\x30\x09"
					"\x04\x04\x73\x61\x6c\x74"
					"\x02\x01\x21"
			"\x30\x14"
				"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x03\x07"
				"\x04\x08\x73\x61\x6c\x74\x73\x61\x6c\x74",
	},
	{
		"pkcs5-pbes2-salt-not-specified", "1.2.840.113549.1.5.13",
		"password",
		0x30, "\x30\x2e"
			"\x30\x16"
				"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c"
				"\x30\x09"
					"\x30\x04"
						"\x06\x02\x2a\x01"
					"\x02\x01\x21"
			"\x30\x14"
				"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x03\x07"
				"\x04\x08\x73\x61\x6c\x74\x73\x61\x6c\x74"
	},
	{
		"pkcs5-pbes2-unsupported-des-rc5-cbc", "1.2.840.113549.1.5.13",
		"password",
		0x30, "\x30\x2e"
			"\x30\x16"
				"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c"
				"\x30\x09"
					"\x04\x04\x73\x61\x6c\x74"
					"\x02\x01\x21"
			"\x30\x14"
				"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x03\x09"
				"\x04\x08\x73\x61\x6c\x74\x73\x61\x6c\x74"
	}
};

static void
test_read_cipher_invalid (gconstpointer data)
{
	const InvalidCipher *test = data;
	gcry_cipher_hd_t cih;
	GNode *asn;
	gboolean ret;
	GBytes *bytes;

	bytes = g_bytes_new_static (test->der, test->n_der);
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestAny", bytes);
	g_assert (asn != NULL);
	g_bytes_unref (bytes);

	ret = egg_symkey_read_cipher (g_quark_from_static_string (test->scheme),
	                              test->password, strlen (test->password),
	                              asn, &cih);

	egg_asn1x_destroy (asn);
	g_assert (ret == FALSE);
}

static void
test_read_cipher_unsupported_pbe (void)
{
	gcry_cipher_hd_t cih;
	GNode *asn;
	gboolean ret;
	GBytes *bytes;

	/*
	 * On many test systems RC2 is no longer supported by libgcrypt, but
	 * in case these tests are run elsewhere, double check.
	 */
	if (gcry_cipher_algo_info (GCRY_CIPHER_RFC2268_128, GCRYCTL_TEST_ALGO, NULL, 0) == 0)
		return;

	bytes = g_bytes_new_static ("\x30\x09\x04\x07""invalid", 11);
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestAny", bytes);
	g_assert (asn != NULL);
	g_bytes_unref (bytes);

	ret = egg_symkey_read_cipher (g_quark_from_static_string ("1.2.840.113549.1.12.1.5"),
	                              "blah", 4, asn, &cih);

	g_assert (ret == FALSE);

	egg_asn1x_destroy (asn);
}

typedef struct {
	const gchar *name;
	const gchar *scheme;
	gsize digest_len;

	/* Info to use with cipher */
	const gchar *password;
	const gchar *salt;
	gsize iterations;

	/* DER representation of cipher */
	gsize n_der;
	const gchar *der;

	/* Data to encrypt and test with */
	gsize n_plain_length;
	const gchar *plain_text;
	const gchar *digest;
} ReadMac;

static const ReadMac mac_tests[] = {
	{
		"sha1", "1.3.14.3.2.26", 20,
		"password", "saltsalt", 33,
		31, "\x30\x1d"
			"\x30\x12"
				"\x30\x07"
					"\x06\x05\x2b\x0e\x03\x02\x1a"
				"\x04\x07""invalid"
			"\x04\x04""salt"
			"\x02\x01\x21",
		8, "plaintex", "\x8b\x96\x7f\xa2\xf4\x4f\x2d\x70\xcb\x59\x7e\x8f\xad\xf3\x92\x18\x70\x08\x5c\x57"
	}
};

static void
test_read_mac (gconstpointer data)
{
	const ReadMac *test = data;
	gcry_md_hd_t mdh;
	gpointer digest;
	gsize digest_len;
	GNode *asn;
	gboolean ret;
	GBytes *bytes;

	bytes = g_bytes_new_static (test->der, test->n_der);
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestAny", bytes);
	g_assert (asn != NULL);
	g_bytes_unref (bytes);

	ret = egg_symkey_read_mac (g_quark_from_static_string (test->scheme),
	                           test->password, strlen (test->password),
	                           asn, &mdh, &digest_len);

	g_assert_cmpint (digest_len, ==, test->digest_len);

	egg_asn1x_destroy (asn);
	g_assert (ret == TRUE);

	gcry_md_write (mdh, test->plain_text, test->n_plain_length);
	digest = gcry_md_read (mdh, 0);

	egg_assert_cmpmem (test->digest, digest_len, ==,
	                   digest, digest_len);

	gcry_md_close (mdh);
}

static void
test_read_mac_invalid (void)
{
	gcry_md_hd_t mdh;
	gsize digest_len;
	GNode *asn;
	gboolean ret;
	GBytes *bytes;

	bytes = g_bytes_new_static ("\x30\x09\x04\x07""invalid", 11);
	asn = egg_asn1x_create_and_decode (test_asn1_tab, "TestAny", bytes);
	g_assert (asn != NULL);
	g_bytes_unref (bytes);

	ret = egg_symkey_read_mac (g_quark_from_static_string ("1.3.14.3.2.26"),
	                           "blah", 4, asn, &mdh, &digest_len);

	g_assert (ret == FALSE);

	egg_asn1x_destroy (asn);
}

static void
null_log_handler (const gchar *log_domain, GLogLevelFlags log_level,
                  const gchar *message, gpointer user_data)
{

}

int
main (int argc, char **argv)
{
	gchar *name;
	gint i;

	g_test_init (&argc, &argv, NULL);
	egg_libgcrypt_initialize ();

	/* Suppress these messages in tests */
	g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO,
	                   null_log_handler, NULL);

	g_test_add_func ("/symkey/generate_key_simple", test_generate_key_simple);
	g_test_add_func ("/symkey/generate_key_pkcs12", test_generate_key_pkcs12);
	g_test_add_func ("/symkey/generate_key_pbkdf2", test_generate_key_pbkdf2);
	g_test_add_func ("/symkey/generate_key_pbe", test_generate_key_pbe);

	for (i = 0; i < G_N_ELEMENTS (cipher_tests); i++) {
		name = g_strdup_printf ("/symkey/read-cipher/%s", cipher_tests[i].name);
		g_test_add_data_func (name, cipher_tests + i, test_read_cipher);
		g_free (name);
	}

	for (i = 0; i < G_N_ELEMENTS (cipher_invalid); i++) {
		name = g_strdup_printf ("/symkey/read-cipher-invalid/%s", cipher_invalid[i].name);
		g_test_add_data_func (name, cipher_invalid + i, test_read_cipher_invalid);
		g_free (name);
	}

	g_test_add_func ("/symkey/read-cipher-unsupported/pbe", test_read_cipher_unsupported_pbe);

	for (i = 0; i < G_N_ELEMENTS (mac_tests); i++) {
		name = g_strdup_printf ("/symkey/read-mac/%s", mac_tests[i].name);
		g_test_add_data_func (name, mac_tests + i, test_read_mac);
		g_free (name);
	}

	g_test_add_func ("/symkey/read-mac-invalid", test_read_mac_invalid);

	return g_test_run ();
}
