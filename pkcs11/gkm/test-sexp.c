/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-sexp.c: Test sexp stuff

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mock-module.h"

#include "gkm/gkm-crypto.h"
#include "gkm/gkm-sexp.h"
#include "gkm/gkm-private-xsa-key.h"
#include "gkm/gkm-public-xsa-key.h"

#include "egg/egg-secure-memory.h"
#include "gkm/gkm-transaction.h"

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

#define TEST_ECDSA \
"(private-key (ecdsa " \
"  (curve \"NIST P-256\")" \
"  (q #04D4F6A6738D9B8D3A7075C1E4EE95015FC0C9B7E4272D2BEB6644D3609FC781B71F9A8072F58CB66AE2F89BB12451873ABF7D91F9E1FBF96BF2F70E73AAC9A283#)" \
"  (d #5A1EF0035118F19F3110FB81813D3547BCE1E5BCE77D1F744715E1D5BBE70378#)))"

/* test data 20 bytes for DSA */
#define TEST_DATA "Test data to sign..."
#define TEST_DATA_SIZE 20


typedef struct {
	gcry_sexp_t rsakey;
	gcry_sexp_t dsakey;
	gcry_sexp_t ecdsakey;
	GkmModule *module;
	GkmTransaction *transaction;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	gcry_error_t gcry;

	gkm_crypto_initialize ();

	gcry = gcry_sexp_new (&test->rsakey, TEST_RSA, strlen (TEST_RSA), 1);
	g_return_if_fail (gcry == 0);
	gcry = gcry_sexp_new (&test->dsakey, TEST_DSA, strlen (TEST_DSA), 1);
	g_return_if_fail (gcry == 0);
	gcry = gcry_sexp_new (&test->ecdsakey, TEST_ECDSA, strlen (TEST_ECDSA), 1);
	g_return_if_fail (gcry == 0);

	/* create a bogus module */
	test->module = mock_module_initialize_and_enter ();

	test->transaction = gkm_transaction_new ();
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_clear_object (&test->transaction);
	g_clear_pointer (&test->rsakey, gcry_sexp_release);
	g_clear_pointer (&test->dsakey, gcry_sexp_release);
	g_clear_pointer (&test->ecdsakey, gcry_sexp_release);

	mock_module_leave_and_finalize ();
}

static void
test_parse_key (Test *test, gconstpointer unused)
{
	gcry_sexp_t sexp = NULL;
	gcry_mpi_t mpi = NULL;
	gboolean ret;
	gboolean is_priv = FALSE;
	int algorithm = 0;

	/* RSA */
	/* Get the private key out */
	ret = gkm_sexp_parse_key (test->rsakey, &algorithm, &is_priv, &sexp);
	g_assert (ret);
	g_assert (algorithm == GCRY_PK_RSA);
	g_assert (is_priv == TRUE);
	g_assert (sexp != NULL);
	gcry_sexp_release (sexp);

	ret = gkm_sexp_extract_mpi (test->rsakey, &mpi, "p", NULL);
	g_assert (ret);
	g_assert (mpi != NULL);
	gcry_mpi_release (mpi);

	/* DSA */
	/* Get the private key out */
	ret = gkm_sexp_parse_key (test->dsakey, &algorithm, &is_priv, &sexp);
	g_assert (ret);
	g_assert (algorithm == GCRY_PK_DSA);
	g_assert (is_priv == TRUE);
	g_assert (sexp != NULL);
	gcry_sexp_release (sexp);

	ret = gkm_sexp_extract_mpi (test->dsakey, &mpi, "p", NULL);
	g_assert (ret);
	g_assert (mpi != NULL);
	gcry_mpi_release (mpi);

	/* ECDSA */
	/* Get the private key out */
	ret = gkm_sexp_parse_key (test->ecdsakey, &algorithm, &is_priv, &sexp);
	g_assert (ret);
	g_assert (algorithm == GCRY_PK_ECC);
	g_assert (is_priv == TRUE);
	g_assert (sexp != NULL);
	gcry_sexp_release (sexp);

	ret = gkm_sexp_extract_mpi (test->ecdsakey, &mpi, "d", NULL);
	g_assert (ret);
	g_assert (mpi != NULL);
	gcry_mpi_release (mpi);
}

static void
test_key_to_public (Test *test, gconstpointer unused)
{
	gcry_sexp_t pubkey = NULL;
	guchar id1[20], id2[20];
	gboolean ret;
	guchar *p;

	/* RSA */
	ret = gkm_sexp_key_to_public (test->rsakey, &pubkey);
	g_assert (ret);
	g_assert (pubkey != NULL);

	p = gcry_pk_get_keygrip (test->rsakey, id1);
	g_return_if_fail (p == id1);
	p = gcry_pk_get_keygrip (pubkey, id2);
	g_return_if_fail (p == id2);

	g_assert (memcmp (id1, id2, sizeof (id1)) == 0);

	gcry_sexp_release (pubkey);


	/* DSA */
	ret = gkm_sexp_key_to_public (test->dsakey, &pubkey);
	g_assert (ret);
	g_assert (pubkey != NULL);

	p = gcry_pk_get_keygrip (test->dsakey, id1);
	g_return_if_fail (p == id1);
	p = gcry_pk_get_keygrip (pubkey, id2);
	g_return_if_fail (p == id2);

	g_assert (memcmp (id1, id2, sizeof (id1)) == 0);

	gcry_sexp_release (pubkey);


	/* ECDSA */
	ret = gkm_sexp_key_to_public (test->ecdsakey, &pubkey);
	g_assert (ret);
	g_assert (pubkey != NULL);

	p = gcry_pk_get_keygrip (test->ecdsakey, id1);
	g_return_if_fail (p == id1);
	p = gcry_pk_get_keygrip (pubkey, id2);
	g_return_if_fail (p == id2);

	g_assert (memcmp (id1, id2, sizeof (id1)) == 0);

	gcry_sexp_release (pubkey);
}

static void
test_sign_verify (Test *test, gconstpointer unused)
{
	gcry_sexp_t pubkey = NULL;
	gboolean ret;
	CK_BYTE data[] = TEST_DATA;
	CK_ULONG data_size = TEST_DATA_SIZE;
	CK_BYTE signature[128];
	CK_ULONG signature_size = 128;

	/* RSA */
	/* sign some data */
	ret = gkm_crypto_sign_xsa (test->rsakey, CKM_RSA_PKCS, data, data_size, signature, &signature_size);
	g_assert (ret == CKR_OK);
	g_assert (signature_size != 0);
	g_assert (signature != NULL);

	/* create a public key */
	ret = gkm_sexp_key_to_public (test->rsakey, &pubkey);
	g_assert (ret);
	g_assert (pubkey != NULL);

	/* verify the signature */
	ret = gkm_crypto_verify_xsa (pubkey, CKM_RSA_PKCS, data, data_size, signature, signature_size);
	g_assert (ret == CKR_OK);

	/* reset for the next test */
	gcry_sexp_release (pubkey);
	signature_size = 512;

	/* DSA */
	/* sign some data */
	ret = gkm_crypto_sign_xsa (test->dsakey, CKM_DSA, data, data_size, signature, &signature_size);
	g_assert (ret == CKR_OK);
	g_assert (signature_size != 0);
	g_assert (signature != NULL);

	/* create a public key */
	ret = gkm_sexp_key_to_public (test->dsakey, &pubkey);
	g_assert (ret);
	g_assert (pubkey != NULL);

	/* verify the signature */
	ret = gkm_crypto_verify_xsa (pubkey, CKM_DSA, data, data_size, signature, signature_size);
	g_assert (ret == CKR_OK);

	/* reset for the next test */
	gcry_sexp_release (pubkey);
	signature_size = 512;

	/* ECDSA */
	/* sign some data */
	ret = gkm_crypto_sign_xsa (test->ecdsakey, CKM_ECDSA, data, data_size, signature, &signature_size);
	g_assert (ret == CKR_OK);
	g_assert (signature_size != 0);
	g_assert (signature != NULL);

	/* create a public key */
	ret = gkm_sexp_key_to_public (test->ecdsakey, &pubkey);
	g_assert (ret);
	g_assert (pubkey != NULL);

	/* verify the signature */
	ret = gkm_crypto_verify_xsa (pubkey, CKM_ECDSA, data, data_size, signature, signature_size);
	g_assert (ret == CKR_OK);

	gcry_sexp_release (pubkey);
}

static void
assert_get_attribute_ulong (GkmPrivateXsaKey *key, CK_ATTRIBUTE_TYPE type, CK_ULONG value,
			    CK_ATTRIBUTE_PTR attrs, CK_ULONG_PTR n_attrs)
{
	CK_ATTRIBUTE_PTR attr;
	CK_RV ret;
	GkmPrivateXsaKeyClass *key_class;
	GkmObject *base;

	base = GKM_OBJECT (key); /* cast */
	key_class = GKM_PRIVATE_XSA_KEY_GET_CLASS(key);

	attr = &attrs[(*n_attrs)++];
	attr->pValue = g_new (CK_ULONG, 1);
	attr->ulValueLen = sizeof (CK_ULONG);

	attr->type = type;
	ret = GKM_OBJECT_CLASS (key_class)->get_attribute (base, NULL, attr);
	g_assert (ret == CKR_OK);
	g_assert (attr->ulValueLen == sizeof (CK_ULONG));
	g_assert (*( (CK_ULONG *) attr->pValue) == value);
}

static void
assert_get_attribute_bool (GkmPrivateXsaKey *key, CK_ATTRIBUTE_TYPE type, CK_BBOOL value,
			   CK_ATTRIBUTE_PTR attrs, CK_ULONG_PTR n_attrs)
{
	CK_ATTRIBUTE_PTR attr;
	CK_RV ret;
	GkmPrivateXsaKeyClass *key_class;
	GkmObject *base;

	base = GKM_OBJECT (key); /* cast */
	key_class = GKM_PRIVATE_XSA_KEY_GET_CLASS(key);

	attr = &attrs[(*n_attrs)++];
	attr->pValue = g_new (CK_BBOOL, 1);
	attr->ulValueLen = sizeof (CK_BBOOL);

	attr->type = type;
	ret = GKM_OBJECT_CLASS (key_class)->get_attribute (base, NULL, attr);
	g_assert (ret == CKR_OK);
	g_assert (attr->ulValueLen == sizeof (CK_BBOOL));
	g_assert (*( (CK_BBOOL *) attr->pValue) == value);
}

static void
assert_get_attribute_buffer (GkmPrivateXsaKey *key, CK_ATTRIBUTE_TYPE type, const gchar *exp, gsize exp_len,
			     CK_ATTRIBUTE_PTR attrs, CK_ULONG_PTR n_attrs)
{
	CK_ATTRIBUTE_PTR attr;
	CK_RV ret;
	GkmPrivateXsaKeyClass *key_class;
	GkmObject *base;

	g_assert (exp_len < 512);

	base = GKM_OBJECT (key); /* cast */
	key_class = GKM_PRIVATE_XSA_KEY_GET_CLASS(key);

	attr = &attrs[(*n_attrs)++];
	attr->pValue = g_new (gchar, 512);
	attr->ulValueLen = 512;

	attr->type = type;
	ret = GKM_OBJECT_CLASS (key_class)->get_attribute (base, NULL, attr);
	g_assert (ret == CKR_OK);
	g_assert (attr->ulValueLen == exp_len);
	g_assert (memcmp (attr->pValue, exp, exp_len) == 0);
}

static void
assert_get_attribute_error (GkmPrivateXsaKey *key, CK_ATTRIBUTE_TYPE type, CK_RV expect)
{
	CK_ATTRIBUTE attr;
	CK_RV ret;
	GkmPrivateXsaKeyClass *key_class;
	GkmObject *base;

	base = GKM_OBJECT (key); /* cast */
	key_class = GKM_PRIVATE_XSA_KEY_GET_CLASS(key);

	attr.pValue = NULL;
	attr.ulValueLen = 0;

	attr.type = type;
	ret = GKM_OBJECT_CLASS (key_class)->get_attribute (base, NULL, &attr);
	g_assert (ret == expect);
}

static void
assert_sexp_compare_mpi (gcry_sexp_t s1, gcry_sexp_t s2, const gchar *field)
{
	gcry_mpi_t m1, m2;

	g_assert (gkm_sexp_extract_mpi (s1, &m1, field, NULL));
	g_assert (gkm_sexp_extract_mpi (s2, &m2, field, NULL));

	g_assert (gcry_mpi_cmp (m1, m2) == 0);
	gcry_mpi_release (m1);
	gcry_mpi_release (m2);
}

static void
assert_sexp_compare_bytes (gcry_sexp_t s1, gcry_sexp_t s2, const gchar *field)
{
	gchar *b1, *b2;
	gsize bs1, bs2;

	g_assert (gkm_sexp_extract_buffer (s1, &b1, &bs1, field, NULL));
	g_assert (gkm_sexp_extract_buffer (s2, &b2, &bs2, field, NULL));

	g_assert (bs1 == bs2);
	g_assert (memcmp (b1, b2, bs1) == 0);
	g_free (b1);
	g_free (b2);
}

/* Test sexp -> PKCS#11 attributes */
static void
test_rsa_attributes (Test *test, gconstpointer unused)
{
	GkmPrivateXsaKey *key;
	CK_ATTRIBUTE attrs[10];
	CK_ULONG n_attrs = 0;
	g_autoptr(GkmSexp) sexp = NULL;
	g_autoptr(GkmSexp) base_sexp = NULL;

	base_sexp = gkm_sexp_new (test->rsakey);
	key = g_object_new (GKM_TYPE_PRIVATE_XSA_KEY,
	                    "base-sexp", base_sexp,
	                    "module", test->module, /*"manager", NULL,*/ NULL);
	g_assert (key != NULL);

	assert_get_attribute_ulong (key, CKA_KEY_TYPE, CKK_RSA, attrs, &n_attrs);
	assert_get_attribute_ulong (key, CKA_CLASS, CKO_PRIVATE_KEY, attrs, &n_attrs);
	assert_get_attribute_bool (key, CKA_PRIVATE, TRUE, attrs, &n_attrs);
	assert_get_attribute_bool (key, CKA_SIGN, TRUE, attrs, &n_attrs);
	assert_get_attribute_bool (key, CKA_SIGN_RECOVER, FALSE, attrs, &n_attrs);
	assert_get_attribute_buffer (key, CKA_MODULUS,
				     "\xb7\x87\x58\xd5\x5e\xbf\xfa\xb6\x1d\x07\xd0\xdc\x49\xb5\x30\x9a"
				     "\x6f\x1d\xa2\xae\x51\xc2\x75\xdf\xc2\x37\x09\x59\xbb\x81\xac\x0c"
				     "\x39\x09\x3b\x1c\x61\x8e\x39\x61\x61\xa0\xde\xce\xb8\x76\x8d\x0f"
				     "\xfb\x14\xf1\x97\xb9\x6c\x3d\xa1\x41\x90\xee\x0f\x20\xd5\x13\x15",
				     64, attrs, &n_attrs);
	assert_get_attribute_buffer (key, CKA_PUBLIC_EXPONENT,
				     "\x01\x00\x01", 3, attrs, &n_attrs);
	assert_get_attribute_error (key, CKA_PRIVATE_EXPONENT, CKR_ATTRIBUTE_SENSITIVE);

	/* TODO to test parser and reader, there might be more tests */

	/* we have an object so lets recreate the sexp public key */
	sexp = gkm_public_xsa_key_create_sexp (NULL, test->transaction, attrs, n_attrs);
	g_assert (sexp != NULL);

	while (n_attrs > 0)
		g_free (attrs[--n_attrs].pValue);

	assert_sexp_compare_mpi (test->rsakey, gkm_sexp_get (sexp), "n");
	assert_sexp_compare_mpi (test->rsakey, gkm_sexp_get (sexp), "e");

	/* gcry_sexp_dump (gkm_sexp_get (sexp)); */

	g_clear_object (&key);
	/* base_sexp takes ownership, so avoid a dobule free in the test teardown */
	test->rsakey = NULL;
}

static void
test_dsa_attributes (Test *test, gconstpointer unused)
{
	GkmPrivateXsaKey *key;
	CK_ATTRIBUTE attrs[10];
	CK_ULONG n_attrs = 0;
	g_autoptr(GkmSexp) base_sexp = NULL;

	base_sexp = gkm_sexp_new (g_steal_pointer (&test->dsakey));
	key = g_object_new (GKM_TYPE_PRIVATE_XSA_KEY,
	                    "base-sexp", base_sexp,
	                    "module", test->module, /*"manager", NULL,*/ NULL);
	g_assert (key != NULL);

	assert_get_attribute_ulong (key, CKA_CLASS, CKO_PRIVATE_KEY, attrs, &n_attrs);
	assert_get_attribute_bool (key, CKA_PRIVATE, TRUE, attrs, &n_attrs);
	assert_get_attribute_bool (key, CKA_SIGN, TRUE, attrs, &n_attrs);
	assert_get_attribute_bool (key, CKA_SIGN_RECOVER, FALSE, attrs, &n_attrs);
	assert_get_attribute_ulong (key, CKA_KEY_TYPE, CKK_DSA, attrs, &n_attrs);
	assert_get_attribute_error (key, CKA_VALUE, CKR_ATTRIBUTE_SENSITIVE);
	assert_get_attribute_buffer (key, CKA_PRIME,
                                 "\x90\xec\x0b\x60\x73\x58\x39\xc7\x54\xea\xf8\xf6\x4b\xb0\x3f\xc3"
                                 "\x53\x98\xd6\x97\x72\xbf\xae\x54\x00\x79\xde\xa2\xd3\xa6\x1f\xaf"
                                 "\xfb\x27\x63\x0a\x03\x8a\x01\xa3\xd0\xcd\x62\xa1\x07\x45\xa5\x74"
                                 "\xa2\x7e\xcb\x46\x2f\x4f\x08\x85\xb7\x9c\x61\xbb\xe9\x54\xa6\x0a"
                                 "\x29\x66\x8a\xd5\x4b\xba\x5c\x07\xa7\x2f\xd8\xb1\x10\x52\x49\x67"
                                 "\x0b\x33\x9d\xf2\xc5\x9e\x64\xa4\x70\x64\xef\xcf\x0b\x72\x36\xc5"
                                 "\xc7\x2c\xd5\x5c\xeb\x32\x91\x74\x30\xbe\xc9\xa0\x03\xd4\xe4\x84"
                                 "\xfb\xaa\x84\xd7\x95\x71\xb3\x8d\x6b\x5a\xc9\x5b\xb7\x3e\x3f\x7b",
                                 128, attrs, &n_attrs);
	assert_get_attribute_buffer (key, CKA_SUBPRIME,
                                 "\xfa\x21\x4a\x13\x85\xc2\x1b\xfe\xba\xad\xab\x24"
                                 "\x0a\x24\x30\xc6\x07\xd5\x62\x71",
                                 20, attrs, &n_attrs);
	assert_get_attribute_buffer (key, CKA_BASE,
                                 "\x2d\xe0\x57\x51\xf5\xda\xee\x97\xf3\xd4\x3c\x54\x59\x5a\x3e\x94"
                                 "\xa0\x80\x72\x8f\x0c\x66\xc9\x8a\xeb\xed\x57\x62\xf6\xab\x15\x58"
                                 "\x02\xd8\x35\x9e\xad\x1d\xe1\xec\x36\xa4\x59\xfb\xee\xea\x48\xe5"
                                 "\x9b\x9e\x6a\x8c\xb4\xf5\x29\x59\x36\xb3\xcc\x88\x1a\x5d\x95\x7c"
                                 "\x73\x39\x17\x5e\x2c\xff\xe0\xf3\x0d\x37\x11\xe4\x30\xdb\x66\x48"
                                 "\xc2\xeb\x47\x4a\xa1\x0a\x4a\x32\x97\x45\x05\x31\xff\x2c\x7c\x69"
                                 "\x51\x22\x0c\x9d\x44\x6b\x6b\x6b\x0f\x00\x26\x2e\x1e\xbe\xb3\xcc"
                                 "\x86\x14\x76\xaa\x51\x8c\xc5\x55\xc9\xab\xf9\xe5\xf3\x90\x23\xfc",
                                 128, attrs, &n_attrs);

	/* TODO to test parser and reader, there might be more tests */

	while (n_attrs > 0)
		g_free (attrs[--n_attrs].pValue);

	/* can't recreate the public key, because CKA_VALUE is sensitive in private key*/
	g_clear_object (&key);
}

static void
test_ecdsa_attributes (Test *test, gconstpointer unused)
{
	GkmPrivateXsaKey *key;
	CK_ATTRIBUTE attrs[10];
	CK_ULONG n_attrs = 0;
	g_autoptr(GkmSexp) sexp = NULL;
	g_autoptr(GkmSexp) base_sexp = NULL;

	base_sexp = gkm_sexp_new (test->ecdsakey);
	key = g_object_new (GKM_TYPE_PRIVATE_XSA_KEY,
	                    "base-sexp", base_sexp,
	                    "module", test->module, /*"manager", NULL,*/ NULL);
	g_assert (key != NULL);

	assert_get_attribute_ulong (key, CKA_CLASS, CKO_PRIVATE_KEY, attrs, &n_attrs);
	assert_get_attribute_bool (key, CKA_PRIVATE, TRUE, attrs, &n_attrs);
	assert_get_attribute_bool (key, CKA_SIGN, TRUE, attrs, &n_attrs);
	assert_get_attribute_bool (key, CKA_SIGN_RECOVER, FALSE, attrs, &n_attrs);
	assert_get_attribute_ulong (key, CKA_KEY_TYPE, CKK_ECDSA, attrs, &n_attrs);
	assert_get_attribute_error (key, CKA_VALUE, CKR_ATTRIBUTE_SENSITIVE);
	assert_get_attribute_buffer (key, CKA_EC_PARAMS,
                                 "\x06" /* tag (OID) */
                                 "\x08" /* length (8 bytes) */
                                 "\x2a\x86\x48\xce\x3d\x03\x01\x07", /* DER encoded OID */
                                 10, attrs, &n_attrs);
	assert_get_attribute_buffer (key, CKA_EC_POINT,
                                 "\x04" /* tag (OCTET STRING) */
                                 "\x41" /* length (65 bytes) */
                                 "\x04\xd4\xf6\xa6\x73\x8d\x9b\x8d\x3a\x70\x75\xc1\xe4\xee\x95\x01\x5f\xc0\xc9\xb7\xe4\x27\x2d\x2b\xeb\x66\x44\xd3\x60\x9f\xc7\x81\xb7\x1f\x9a\x80\x72\xf5\x8c\xb6\x6a\xe2\xf8\x9b\xb1\x24\x51\x87\x3a\xbf\x7d\x91\xf9\xe1\xfb\xf9\x6b\xf2\xf7\x0e\x73\xaa\xc9\xa2\x83",
                                 67, attrs, &n_attrs);

	/* we have an object so lets recreate the sexp public key */
	sexp = gkm_public_xsa_key_create_sexp (NULL, test->transaction, attrs, n_attrs);
	g_assert (sexp != NULL);

	assert_sexp_compare_bytes (test->ecdsakey, gkm_sexp_get (sexp), "curve");
	assert_sexp_compare_bytes (test->ecdsakey, gkm_sexp_get (sexp), "q");

	/* gcry_sexp_dump (gkm_sexp_get (sexp)); */

	while (n_attrs > 0)
		g_free (attrs[--n_attrs].pValue);

	g_clear_object (&key);

	/* base_sexp takes ownership, so avoid a dobule free in the test teardown */
	test->ecdsakey = NULL;
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/gkm/sexp/parse_key", Test, NULL, setup, test_parse_key, teardown);
	g_test_add ("/gkm/sexp/key_to_public", Test, NULL, setup, test_key_to_public, teardown);
	g_test_add ("/gkm/sexp/sign_verify", Test, NULL, setup, test_sign_verify, teardown);
	g_test_add ("/gkm/sexp/rsa_attributes", Test, NULL, setup, test_rsa_attributes, teardown);
	g_test_add ("/gkm/sexp/dsa_attributes", Test, NULL, setup, test_dsa_attributes, teardown);
	g_test_add ("/gkm/sexp/ecdsa_attributes", Test, NULL, setup, test_ecdsa_attributes, teardown);

	return g_test_run ();
}
