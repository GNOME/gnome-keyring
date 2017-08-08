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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkm/gkm-crypto.h"
#include "gkm/gkm-data-asn1.h"
#include "gkm/gkm-data-der.h"
#include "gkm/gkm-sexp.h"

#include "egg/egg-armor.h"
#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"
#include "egg/egg-openssl.h"
#include "egg/egg-secure-memory.h"

#include <glib.h>
#include <gcrypt.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

typedef struct {
	GNode *certificate;
	gchar *certificate_data;
	gsize n_certificate_data;
	GNode *certificate2;
	gchar *certificate2_data;
	gsize n_certificate2_data;
} Test;

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

const gchar *ecdsaprv_256 =  "(private-key (ecdsa" \
"  (curve \"NIST P-256\")" \
"  (q #04A8EB59A5B601D839AC2373C3197440AD2DD72DFE0684E42BE15C5724722FECBF0EC3675695CEFD9D1D864A74B642C5C64559013803C7E5975FBD52EB235CCB9C#)" \
"  (d #C616A320E3839BC6946E432E8E849A7CD72B83867E703ED86ACBF69DF17EFBBE#)))";

const gchar *ecdsapub_256 =  "(public-key (ecdsa" \
"  (curve \"NIST P-256\")" \
"  (q #04A8EB59A5B601D839AC2373C3197440AD2DD72DFE0684E42BE15C5724722FECBF0EC3675695CEFD9D1D864A74B642C5C64559013803C7E5975FBD52EB235CCB9C#)))";

const gchar *ecdsaprv_384 = "(private-key (ecdsa" \
"  (curve \"NIST P-384\")" \
"  (q #04686B8127CAEEF00BA418AF03EB3A48539637E67A7FE9176C7B2DFF92942A405F9C3AF4A01771B34F8839DC5E972479C7D0BAC7FF280F4A00C1505DAFDE4265E4C993A38625A414A4F3E139250C5D9E841844F37AE264597E24095A40E70591AD#)" \
"  (d #4071072A7E023539CF6591CBAF0FBB505159A3236C35135DB610EEE8969179EB46A5BC093DFE186E7936690209771D1B#)))";

const gchar *ecdsaprv_521 = "(private-key (ecdsa" \
"  (curve \"NIST P-521\")" \
"  (q #04012E0837D1EA2ED34C8F7D3DE5FCE5C6C887368EDE1A3FB3D40874021EBADE726EB4D44E00DEA68DC0F8FC472E0030231320B6407AD0755213E34BE3B7B02945923800103F5E970568E9247B5366BB32DE17BE694C39EF6F2D0A3238FD33EA17A00D751C34163023ED0D1242F4D097D0AA056EBC6DE1137015CAF72F18B4EFA91E756660#)" \
"  (d #012CB68FE0D0DEEBFA4EEBD6C2F3147329C44A67F1C579B4A797A2187AB481BF5B974AE23084AE6CEB184551F79C502AC899961A0F0168781F296B90FAEAC8AA5ACC#)))";

static gboolean
compare_keys (gcry_sexp_t key, gcry_sexp_t sexp)
{
	guchar hash1[20], hash2[20];
	guchar *p;

	/* Now compare them */
	p = gcry_pk_get_keygrip (key, hash1);
	g_assert ("couldn't get key id for private key" && p == hash1);
	p = gcry_pk_get_keygrip (sexp, hash2);
	g_assert ("couldn't get key id for parsed private key" && p == hash2);

	return memcmp (hash1, hash2, 20) == 0;
}

static void
test_der_public (gcry_sexp_t key)
{
	GBytes *data;
	GkmDataResult ret;
	gcry_sexp_t sexp;

	/* Encode it */
	data = gkm_data_der_write_public_key (key);
	g_assert ("couldn't encode public key" && data != NULL);
	g_assert ("encoding is empty" && g_bytes_get_size (data) > 0);

	/* Now parse it */
	ret = gkm_data_der_read_public_key (data, &sexp);
	g_assert ("couldn't decode public key" && ret == GKM_DATA_SUCCESS);
	g_assert ("parsed key is empty" && sexp != NULL);

	/* Now compare them */
	g_assert ("key parsed differently" && compare_keys (key, sexp));

	gcry_sexp_release (sexp);
	g_bytes_unref (data);
}

static void
setup (Test *test, gconstpointer unused)
{
	GBytes *data;

	if (!g_file_get_contents (SRCDIR "/pkcs11/gkm/fixtures/test-certificate-1.der", &test->certificate_data, &test->n_certificate_data, NULL))
		g_assert_not_reached ();

	data = g_bytes_new (test->certificate_data, test->n_certificate_data);
	test->certificate = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate", data);
	g_assert (test->certificate != NULL);
	g_bytes_unref (data);

	if (!g_file_get_contents (SRCDIR "/pkcs11/gkm/fixtures/test-certificate-2.der", &test->certificate2_data, &test->n_certificate2_data, NULL))
		g_assert_not_reached ();
	data = g_bytes_new (test->certificate2_data, test->n_certificate2_data);
	test->certificate2 = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate", data);
	g_assert (test->certificate2 != NULL);
	g_bytes_unref (data);
}

static void
teardown (Test *test, gconstpointer unused)
{
	egg_asn1x_destroy (test->certificate);
	g_free (test->certificate_data);
	egg_asn1x_destroy (test->certificate2);
	g_free (test->certificate2_data);
}

static void
test_der_rsa_public (Test *test, gconstpointer unused)
{
	gcry_sexp_t key;
	gcry_error_t gcry;

	gcry = gcry_sexp_sscan (&key, NULL, rsapub, strlen (rsapub));
	g_return_if_fail (gcry == 0);

	test_der_public (key);

	gcry_sexp_release (key);
}

static void
test_der_dsa_public (Test *test, gconstpointer unused)
{
	gcry_sexp_t key;
	gcry_error_t gcry;

	gcry = gcry_sexp_sscan (&key, NULL, dsapub, strlen (dsapub));
	g_return_if_fail (gcry == 0);

	test_der_public (key);

	gcry_sexp_release (key);
}

static void
test_der_ecdsa_public (Test *test, gconstpointer unused)
{
	gcry_sexp_t key;
	gcry_error_t gcry;

	gcry = gcry_sexp_sscan (&key, NULL, ecdsapub_256, strlen (ecdsapub_256));
	g_return_if_fail (gcry == 0);

	test_der_public (key);

	gcry_sexp_release (key);
}

static void
test_der_private (gcry_sexp_t key)
{
	GBytes *data;
	GkmDataResult ret;
	gcry_sexp_t sexp;

	/* Encode it */
	data = gkm_data_der_write_private_key (key);
	g_assert ("couldn't encode private key" && data != NULL);
	g_assert ("encoding is empty" && g_bytes_get_size (data) > 0);

	/* Now parse it */
	ret = gkm_data_der_read_private_key (data, &sexp);
	g_assert ("couldn't decode private key" && ret == GKM_DATA_SUCCESS);
	g_assert ("parsed key is empty" && sexp != NULL);

	/* Now compare them */
	g_assert ("key parsed differently" && compare_keys (key, sexp));

	gcry_sexp_release (sexp);
	g_bytes_unref (data);
}

static void
test_der_rsa_private (Test *test, gconstpointer unused)
{
	gcry_sexp_t key;
	gcry_error_t gcry;

	gcry = gcry_sexp_sscan (&key, NULL, rsaprv, strlen (rsaprv));
	g_return_if_fail (gcry == 0);

	test_der_private (key);

	gcry_sexp_release (key);
}

static void
test_der_dsa_private (Test *test, gconstpointer unused)
{
	gcry_sexp_t key;
	gcry_error_t gcry;

	gcry = gcry_sexp_sscan (&key, NULL, dsaprv, strlen (dsaprv));
	g_return_if_fail (gcry == 0);

	test_der_private (key);

	gcry_sexp_release (key);
}

static void
test_der_dsa_private_parts (Test *test, gconstpointer unused)
{
	GBytes *params, *key;
	gcry_sexp_t skey, pkey;
	gcry_error_t gcry;
	GkmDataResult result;

	gcry = gcry_sexp_sscan (&skey, NULL, dsaprv, strlen (dsaprv));
	g_return_if_fail (gcry == 0);

	/* Encode the the dsa key by parts */
	params = gkm_data_der_write_private_key_dsa_params (skey);
	g_assert ("didn't encode dsa params" && params != NULL);
	key = gkm_data_der_write_private_key_dsa_part (skey);
	g_assert ("didn't encode dsa key" && key != NULL);

	/* Parse the dsa key by parts */
	result = gkm_data_der_read_private_key_dsa_parts (key, params, &pkey);
	g_assert ("couldn't parse dsa parts" && result == GKM_DATA_SUCCESS);
	g_assert ("parsing dsa parts resulted in null key" && pkey != NULL);

	/* Now compare them */
	g_assert ("key parsed differently" && compare_keys (skey, pkey));

	gcry_sexp_release (skey);
	g_bytes_unref (params);
	g_bytes_unref (key);
}

static void
test_der_ecdsa_private (Test *test, gconstpointer unused)
{
	gcry_sexp_t key;
	gcry_error_t gcry;

	gcry = gcry_sexp_sscan (&key, NULL, ecdsaprv_256, strlen (ecdsaprv_256));
	g_return_if_fail (gcry == 0);

	test_der_private (key);

	gcry_sexp_release (key);
}

const gchar *certpub = "(public-key (rsa " \
	"(n #00C966D9F80744CFB98C2EF0A1EF13456C05DFDE2716513641116C6C3BEDFE107D129EE59B429AFE6031C366B7733A48AE4ED032379488B50DB6D9F3F244D9D58812DD764DF21AFC6F231E7AF1D898454E0710EF1642D043756D4ADEE2AAC931FF1F00707C66CF102508BAFAEE00E94603662711153BAA5BF298DD3642B2DA8875#) " \
	"(e #010001#) ) )";

static void
test_read_public_key_info (Test *test, gconstpointer unused)
{
	GBytes *data;
	guchar hash[20];
	GkmDataResult res;
	gcry_sexp_t sexp, match;
	gcry_error_t gcry;

	data = egg_asn1x_get_element_raw (egg_asn1x_node (test->certificate, "tbsCertificate", "subjectPublicKeyInfo", NULL));
	g_assert (data != NULL);

	res = gkm_data_der_read_public_key_info (data, &sexp);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert (sexp != NULL);

	if (!gcry_pk_get_keygrip (sexp, hash))
		g_assert_not_reached ();

	gcry = gcry_sexp_sscan (&match, NULL, certpub, strlen (certpub));
	g_assert (gcry == 0);

	g_assert (compare_keys (sexp, match));

	gcry_sexp_release (sexp);
	gcry_sexp_release (match);
	g_bytes_unref (data);
}

static void
test_read_certificate (Test *test, gconstpointer unused)
{
	GNode *asn = NULL;
	GkmDataResult res;
	GBytes *data;

	data = g_bytes_new (test->certificate_data, test->n_certificate_data);
	res = gkm_data_der_read_certificate (data, &asn);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert (asn != NULL);

	g_bytes_unref (data);
	egg_asn1x_destroy (asn);
}

static void
test_write_certificate (Test *test, gconstpointer unused)
{
	GBytes *data;

	data = gkm_data_der_write_certificate (test->certificate);
	g_assert (g_bytes_get_size (data) == test->n_certificate_data);
	g_assert (memcmp (g_bytes_get_data (data, NULL), test->certificate_data, g_bytes_get_size (data)) == 0);
	g_bytes_unref (data);
}

static void
on_ca_certificate_public_key_info (GQuark type,
                                   GBytes *data,
                                   GBytes *outer,
                                   GHashTable *headers,
                                   gpointer user_data)
{
	GNode *asn1 = NULL;
	GkmDataResult res;
	GBytes *keydata;
	gcry_sexp_t sexp;

	g_assert (g_quark_try_string ("CERTIFICATE") == type);

	/* Parse the ASN1 data */
	res = gkm_data_der_read_certificate (data, &asn1);
	g_assert (res == GKM_DATA_SUCCESS);

	/* Generate a raw public key from our test->certificate */
	keydata = egg_asn1x_encode (egg_asn1x_node (asn1, "tbsCertificate", "subjectPublicKeyInfo", NULL), NULL);
	g_assert (keydata != NULL);

	/* Now create us a nice public key with that identifier */
	res = gkm_data_der_read_public_key_info (keydata, &sexp);
	g_assert (res == GKM_DATA_SUCCESS || res == GKM_DATA_UNRECOGNIZED);

	if (res == GKM_DATA_SUCCESS)
		gcry_sexp_release (sexp);

	egg_asn1x_destroy (asn1);
	g_bytes_unref (keydata);
}

static void
test_read_ca_certificates_public_key_info (Test *test, gconstpointer unused)
{
	GBytes *bytes;
	gchar *data;
	gsize n_data;

	if (!g_file_get_contents (SRCDIR "/pkcs11/gkm/fixtures/ca-certificates.crt", &data, &n_data, NULL))
		g_assert_not_reached ();

	bytes = g_bytes_new_take (data, n_data);
	egg_armor_parse (bytes, on_ca_certificate_public_key_info, NULL);
	g_bytes_unref (bytes);
}

static GBytes *
find_extension (GNode *asn,
                const gchar *oid)
{
	GBytes *value;
	GNode *node = NULL;
	gchar *exoid;
	guint index;

	for (index = 1; TRUE; ++index) {

		/* Make sure it is present */
		node = egg_asn1x_node (asn, "tbsCertificate", "extensions", index, "extnID", NULL);
		if (node == NULL)
			return NULL;

		exoid = egg_asn1x_get_oid_as_string (node);
		g_assert (exoid);

		if (strcmp (exoid, oid) == 0) {
			g_free (exoid);
			node = egg_asn1x_node (asn, "tbsCertificate", "extensions", index, "extnValue", NULL);
			value = egg_asn1x_get_string_as_bytes (node);
			g_assert (value);
			return value;
		}

		g_free (exoid);
	}

	g_assert_not_reached ();
}

static void
test_read_basic_constraints (Test *test, gconstpointer unused)
{
	GBytes *extension;
	gboolean is_ca;
	gint path_len;
	GkmDataResult res;

	extension = egg_asn1x_get_string_as_bytes (egg_asn1x_node (test->certificate, "tbsCertificate", "extensions", 1, "extnValue", NULL));
	g_assert (extension != NULL);

	res = gkm_data_der_read_basic_constraints (extension, &is_ca, &path_len);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert (is_ca == TRUE);
	g_assert (path_len == -1);

	g_bytes_unref (extension);
}

static void
test_read_key_usage (Test *test, gconstpointer unused)
{
	GBytes *extension;
	gulong key_usage;
	GkmDataResult res;

	extension = find_extension (test->certificate2, "2.5.29.15");
	g_assert (extension);

	res = gkm_data_der_read_key_usage (extension, &key_usage);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert_cmpuint (key_usage, ==, 0x01);

	g_bytes_unref (extension);
}

static void
test_read_enhanced_usage (Test *test, gconstpointer unused)
{
	GBytes *extension;
	GQuark *usages;
	GkmDataResult res;

	extension = find_extension (test->certificate2, "2.5.29.37");
	g_assert (extension);

	res = gkm_data_der_read_enhanced_usage (extension, &usages);
	g_assert (res == GKM_DATA_SUCCESS);

	g_bytes_unref (extension);
	g_free (usages);
}

static void
test_read_all_pkcs8 (Test *test, gconstpointer unused)
{
	GBytes *bytes;
	gcry_sexp_t sexp;
	GkmDataResult res;
	GDir *dir;
	const gchar *name;
	gchar *data;
	gsize n_data;
	gchar *path;

	dir = g_dir_open (SRCDIR "/pkcs11/gkm/fixtures", 0, NULL);
	g_assert (dir);

	for(;;) {
		name = g_dir_read_name (dir);
		if (!name)
			break;

		if (!g_pattern_match_simple ("der-key-*", name))
			continue;

		path = g_build_filename (SRCDIR "/pkcs11/gkm/fixtures", name, NULL);
		if (!g_file_get_contents (path, &data, &n_data, NULL))
			g_assert_not_reached ();
		g_free (path);

		bytes = g_bytes_new_take (data, n_data);
		res = gkm_data_der_read_private_pkcs8 (bytes, "booo", 4, &sexp);
		g_assert (res == GKM_DATA_SUCCESS);
		g_bytes_unref (bytes);

		g_assert (gkm_sexp_parse_key (sexp, NULL, NULL, NULL));
		gcry_sexp_release (sexp);
	}

	g_dir_close (dir);
}

static void
test_read_pkcs8_bad_password (Test *test, gconstpointer unused)
{
	gcry_sexp_t sexp;
	GkmDataResult res;
	GBytes *bytes;
	gchar *data;
	gsize n_data;

	if (!g_file_get_contents (SRCDIR "/pkcs11/gkm/fixtures/der-key-encrypted-pkcs5.p8", &data, &n_data, NULL))
		g_assert_not_reached ();

	bytes = g_bytes_new_take (data, n_data);
	res = gkm_data_der_read_private_pkcs8 (bytes, "wrong password", 4, &sexp);
	g_assert (res == GKM_DATA_LOCKED);

	g_bytes_unref (bytes);
}

static void
test_write_pkcs8_plain (Test *test, gconstpointer unused)
{
	gcry_sexp_t sexp, check;
	gcry_error_t gcry;
	GkmDataResult res;
	GBytes *data;

	/* RSA */

	gcry = gcry_sexp_sscan (&sexp, NULL, rsaprv, strlen (rsaprv));
	g_return_if_fail (gcry == 0);

	data = gkm_data_der_write_private_pkcs8_plain (sexp);
	g_assert (data != NULL);

	res = gkm_data_der_read_private_pkcs8_plain (data, &check);
	g_bytes_unref (data);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert (check != NULL);

	g_assert (compare_keys (sexp, check));
	gcry_sexp_release (sexp);
	gcry_sexp_release (check);


	/* DSA */

	gcry = gcry_sexp_sscan (&sexp, NULL, dsaprv, strlen (dsaprv));
	g_return_if_fail (gcry == 0);

	data = gkm_data_der_write_private_pkcs8_plain (sexp);
	g_assert (data != NULL);

	res = gkm_data_der_read_private_pkcs8_plain (data, &check);
	g_bytes_unref (data);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert (check != NULL);

	g_assert (compare_keys (sexp, check));
	gcry_sexp_release (sexp);
	gcry_sexp_release (check);


	/* ECDSA */

	gcry = gcry_sexp_sscan (&sexp, NULL, ecdsaprv_384, strlen (ecdsaprv_384));
	g_return_if_fail (gcry == 0);

	data = gkm_data_der_write_private_pkcs8_plain (sexp);
	g_assert (data != NULL);

	res = gkm_data_der_read_private_pkcs8_plain (data, &check);
	g_bytes_unref (data);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert (check != NULL);

	g_assert (compare_keys (sexp, check));
	gcry_sexp_release (sexp);
	gcry_sexp_release (check);
}


static void
test_write_pkcs8_encrypted (Test *test, gconstpointer unused)
{
	gcry_sexp_t sexp, check;
	gcry_error_t gcry;
	GkmDataResult res;
	GBytes *data;

	/* RSA */

	gcry = gcry_sexp_sscan (&sexp, NULL, rsaprv, strlen (rsaprv));
	g_return_if_fail (gcry == 0);

	data = gkm_data_der_write_private_pkcs8_crypted (sexp, "testo", 5);
	g_assert (data != NULL);

	res = gkm_data_der_read_private_pkcs8_crypted (data, "testo", 5, &check);
	g_bytes_unref (data);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert (check != NULL);

	g_assert (compare_keys (sexp, check));
	gcry_sexp_release (sexp);
	gcry_sexp_release (check);


	/* DSA */

	gcry = gcry_sexp_sscan (&sexp, NULL, dsaprv, strlen (dsaprv));
	g_return_if_fail (gcry == 0);

	data = gkm_data_der_write_private_pkcs8_crypted (sexp, "testo", 5);
	g_assert (data != NULL);

	res = gkm_data_der_read_private_pkcs8_crypted (data, "testo", 5, &check);
	g_bytes_unref (data);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert (check != NULL);

	g_assert (compare_keys (sexp, check));
	gcry_sexp_release (sexp);
	gcry_sexp_release (check);


	/* ECDSA */

	gcry = gcry_sexp_sscan (&sexp, NULL, ecdsaprv_521, strlen (ecdsaprv_521));
	g_return_if_fail (gcry == 0);

	data = gkm_data_der_write_private_pkcs8_crypted (sexp, "testo", 5);
	g_assert (data != NULL);

	res = gkm_data_der_read_private_pkcs8_crypted (data, "testo", 5, &check);
	g_bytes_unref (data);
	g_assert (res == GKM_DATA_SUCCESS);
	g_assert (check != NULL);

	g_assert (compare_keys (sexp, check));
	gcry_sexp_release (sexp);
	gcry_sexp_release (check);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/gkm/data-der/der_rsa_public", Test, NULL, setup, test_der_rsa_public, teardown);
	g_test_add ("/gkm/data-der/der_dsa_public", Test, NULL, setup, test_der_dsa_public, teardown);
	g_test_add ("/gkm/data-der/der_ecdsa_public", Test, NULL, setup, test_der_ecdsa_public, teardown);
	g_test_add ("/gkm/data-der/der_rsa_private", Test, NULL, setup, test_der_rsa_private, teardown);
	g_test_add ("/gkm/data-der/der_dsa_private", Test, NULL, setup, test_der_dsa_private, teardown);
	g_test_add ("/gkm/data-der/der_dsa_private_parts", Test, NULL, setup, test_der_dsa_private_parts, teardown);
	g_test_add ("/gkm/data-der/der_ecdsa_private", Test, NULL, setup, test_der_ecdsa_private, teardown);
	g_test_add ("/gkm/data-der/read_public_key_info", Test, NULL, setup, test_read_public_key_info, teardown);
	g_test_add ("/gkm/data-der/read_certificate", Test, NULL, setup, test_read_certificate, teardown);
	g_test_add ("/gkm/data-der/write_certificate", Test, NULL, setup, test_write_certificate, teardown);
	g_test_add ("/gkm/data-der/read_ca_certificates_public_key_info", Test, NULL, setup, test_read_ca_certificates_public_key_info, teardown);
	g_test_add ("/gkm/data-der/read_basic_constraints", Test, NULL, setup, test_read_basic_constraints, teardown);
	g_test_add ("/gkm/data-der/read_key_usage", Test, NULL, setup, test_read_key_usage, teardown);
	g_test_add ("/gkm/data-der/read_enhanced_usage", Test, NULL, setup, test_read_enhanced_usage, teardown);
	g_test_add ("/gkm/data-der/read_all_pkcs8", Test, NULL, setup, test_read_all_pkcs8, teardown);
	g_test_add ("/gkm/data-der/read_pkcs8_bad_password", Test, NULL, setup, test_read_pkcs8_bad_password, teardown);
	g_test_add ("/gkm/data-der/write_pkcs8_plain", Test, NULL, setup, test_write_pkcs8_plain, teardown);
	g_test_add ("/gkm/data-der/write_pkcs8_encrypted", Test, NULL, setup, test_write_pkcs8_encrypted, teardown);

	return g_test_run ();
}
