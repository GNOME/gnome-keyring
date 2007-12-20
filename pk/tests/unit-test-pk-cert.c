/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pk-cert.c: Test a certificate

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

#include "pk/gkr-pk-cert.h"
#include "pk/gkr-pk-index.h"
#include "pk/gkr-pk-object.h"
#include "pk/gkr-pk-object-manager.h"
#include "pk/gkr-pk-pubkey.h"
#include "pk/gkr-pk-privkey.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"

#include "pkix/gkr-pkix-der.h"

#include <glib.h>
#include <memory.h>

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

static GkrPkObjectManager *manager = NULL;

static GkrPkCert *certificate_1 = NULL;
static GkrPkCert *certificate_2 = NULL;
static GkrPkObject *privkey_1 = NULL;

void unit_setup_certificate (void)
{
	/* Our own object manager */
	manager = gkr_pk_object_manager_instance_for_client (1231); 
}

void unit_test_create_certificate (CuTest* cu)
{
	GkrParseResult res;
	ASN1_TYPE asn1;
	gcry_sexp_t sexp;
	gchar *data;
	const guchar *raw;
	gsize n_data, n_raw;
	
	if (!g_file_get_contents ("test-data/certificate-1.crt", &data, &n_data, NULL))
		g_error ("couldn't read certificate-1.crt");
	res = gkr_pkix_der_read_certificate ((const guchar*)data, n_data, &asn1);
	g_assert (res == GKR_PARSE_SUCCESS);
	
	certificate_1 = gkr_pk_cert_new (manager, 0, asn1);
	CuAssert (cu, "gkr_pk_cert_new returned bad object", GKR_IS_PK_CERT (certificate_1));
	
	if (!g_file_get_contents ("test-data/privkey-1.crt", &data, &n_data, NULL))
		g_error ("couldn't read privkey-1.crt");
	res = gkr_pkix_der_read_private_key ((const guchar*)data, n_data, &sexp);
	g_assert (res == GKR_PARSE_SUCCESS);
	
	privkey_1 = gkr_pk_privkey_new (manager, 0, sexp);
	g_assert (GKR_IS_PK_PRIVKEY (privkey_1));
	
	if (!g_file_get_contents ("test-data/certificate-2.crt", &data, &n_data, NULL))
		g_error ("couldn't read certificate-2.crt");
	res = gkr_pkix_der_read_certificate ((const guchar*)data, n_data, &asn1);
	g_assert (res == GKR_PARSE_SUCCESS);
	
	certificate_2 = gkr_pk_cert_new (manager, 0, asn1);
	CuAssert (cu, "gkr_pk_cert_new returned bad object", GKR_IS_PK_CERT (certificate_2));
	
	raw = gkr_pk_cert_get_raw (certificate_2, &n_raw);
	CuAssert (cu, "gkr_pk_cert_get_raw returned null", raw != NULL);
	CuAssert (cu, "bad raw length of certificate", n_raw == n_data);
	CuAssert (cu, "raw certificate does not equal original", memcmp (raw, data, n_raw) == 0);
}

#include "check-attribute.c"
		 
void unit_test_certificate_static (CuTest *cu)
{
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_TOKEN, CK_TRUE);
	CHECK_ULONG_ATTRIBUTE (cu, certificate_1, CKA_CLASS, CKO_CERTIFICATE);
	CHECK_ULONG_ATTRIBUTE (cu, certificate_1, CKA_CERTIFICATE_CATEGORY, 0);
}

void unit_test_certificate_related (CuTest *cu)
{
	GkrPkObject *obj;
	gkrconstunique keyid;
	gkrconstunique pubid;
	
	keyid = gkr_pk_cert_get_keyid (certificate_1);
	CuAssert (cu, "No key id returned from certificate", keyid != NULL);
	
	obj = gkr_pk_object_manager_find_by_id (manager, GKR_TYPE_PK_PUBKEY, keyid);
	CuAssert (cu, "No matching public key object found in manager", GKR_IS_PK_PUBKEY (obj));
	
	pubid = gkr_pk_pubkey_get_keyid (GKR_PK_PUBKEY (obj));
	CuAssert (cu, "No key id returned from public key", pubid != NULL);
	
	CuAssert (cu, "certificate and public key ids do not match", gkr_unique_equals (keyid, pubid));
}

void unit_test_certificate_extension (CuTest *cu)
{
	guchar *extension;
	gsize n_extension;
	gboolean ret, critical;
	GQuark oid;

	/* Enhanced key usage */	
	oid = g_quark_from_string ("2.5.29.37");
	ret = gkr_pk_cert_has_extension (certificate_1, oid, &critical);
	CuAssert (cu, "couldn't find extension in certificate", ret == TRUE);
	CuAssert (cu, "non critical extension marked critical", critical == FALSE);
	
	extension = gkr_pk_cert_get_extension (certificate_1, oid, &n_extension, &critical);
	CuAssert (cu, "couldn't get extension in certificate", extension != NULL);
	CuAssert (cu, "non critical extension marked critical", critical == FALSE);
	CuAssert (cu, "extension has bad size", n_extension > 8);
	
	/* Basic constraints, critical */
	oid = g_quark_from_string ("2.5.29.19");
	ret = gkr_pk_cert_has_extension (certificate_2, oid, &critical);
	CuAssert (cu, "couldn't find extension in certificate", ret == TRUE);
	CuAssert (cu, "critical extension not marked critical", critical == TRUE);
}

void unit_test_certificate_trust (CuTest *cu)
{
	/* Should be trusted because we have the private key */
	CHECK_ULONG_ATTRIBUTE (cu, certificate_1, CKA_GNOME_USER_TRUST, CKT_GNOME_TRUSTED);
	
	/* Should be unknown trust because it's just on its own */
	CHECK_ULONG_ATTRIBUTE (cu, certificate_2, CKA_GNOME_USER_TRUST, CKT_GNOME_UNKNOWN);	
	
	/* Mark as trusted */
	/* TODO: Should do this via attribute once writable */
	gkr_pk_index_set_string (GKR_PK_OBJECT (certificate_2), "user-trust", "trusted");
	CHECK_ULONG_ATTRIBUTE (cu, certificate_2, CKA_GNOME_USER_TRUST, CKT_GNOME_TRUSTED);
	
	/* Should return to previous state */	
	/* TODO: Should do this via attribute once writable */
	gkr_pk_index_delete (GKR_PK_OBJECT (certificate_2), "user-trust");
	CHECK_ULONG_ATTRIBUTE (cu, certificate_2, CKA_GNOME_USER_TRUST, CKT_GNOME_UNKNOWN);

	/* Mark as untrusted */
	/* TODO: Should do this via attribute once writable */
	gkr_pk_index_set_string (GKR_PK_OBJECT (certificate_1), "user-trust", "untrusted");
	CHECK_ULONG_ATTRIBUTE (cu, certificate_1, CKA_GNOME_USER_TRUST, CKT_GNOME_UNTRUSTED);	
}

void unit_test_certificate_purpose (CuTest *cu)
{
	CK_ATTRIBUTE attr;
	CK_RV ret;
	gchar *result;
	
	memset (&attr, 0, sizeof (attr));
	attr.type = CKA_GNOME_PURPOSE_OIDS;
	
	ret = gkr_pk_object_get_attribute (GKR_PK_OBJECT (certificate_1), &attr);
	CuAssert (cu, "Returned null attribute", attr.pValue != NULL);
	CuAssert (cu, "Returned empty attribute", attr.ulValueLen != 0);
	result = g_strndup (attr.pValue, attr.ulValueLen);
	g_strstrip (result);
	CuAssert (cu, "Returned invalid oid in purpose", g_str_equal (result, "1.3.6.1.5.5.7.3.4"));

	/* Only email protection is valid */
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_RESTRICTED, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_EMAIL_PROTECTION, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_SSH_AUTH, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_SERVER_AUTH, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_CLIENT_AUTH, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_CODE_SIGNING, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_IPSEC_END_SYSTEM, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_IPSEC_TUNNEL, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_IPSEC_USER, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_1, CKA_GNOME_PURPOSE_TIME_STAMPING, CK_FALSE);

	/* The second certificate has no purposes, all are valid */
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_RESTRICTED, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_EMAIL_PROTECTION, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_SSH_AUTH, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_SERVER_AUTH, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_CLIENT_AUTH, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_CODE_SIGNING, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_IPSEC_END_SYSTEM, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_IPSEC_TUNNEL, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_IPSEC_USER, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_TIME_STAMPING, CK_TRUE);

	
	/* Add a purpose */
	/* TODO: Should do this via attribute once writable */
	gkr_pk_index_set_string (GKR_PK_OBJECT (certificate_2), "purposes", "some-purpose");
	CHECK_BOOL_ATTRIBUTE (cu, certificate_2, CKA_GNOME_PURPOSE_RESTRICTED, CK_TRUE);
	
	memset (&attr, 0, sizeof (attr));
	attr.type = CKA_GNOME_PURPOSE_OIDS;
	
	ret = gkr_pk_object_get_attribute (GKR_PK_OBJECT (certificate_2), &attr);
	CuAssert (cu, "Returned null attribute", attr.pValue != NULL);
	CuAssert (cu, "Returned empty attribute", attr.ulValueLen != 0);
	result = g_strndup (attr.pValue, attr.ulValueLen);
	g_strstrip (result);
	CuAssert (cu, "Returned invalid oid in purpose", g_str_equal (result, "some-purpose"));
}
