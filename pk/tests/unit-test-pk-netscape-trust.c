/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pk-netscape-trust.c: Test a netscape trust object

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
#include "pk/gkr-pk-netscape-trust.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11n.h"

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
static GkrPkObject *trust_1 = NULL;
static GkrPkObject *trust_2 = NULL;

void unit_setup_trust (void)
{
	/* Our own object manager */
	manager = gkr_pk_object_manager_instance_for_client (12333); 
}

void unit_test_create_trust (CuTest* cu)
{
	gkrconstunique keyid;
	GkrPkixResult res;
	ASN1_TYPE asn1;
	gchar *data;
	gsize n_data;
	
	if (!g_file_get_contents ("test-data/certificate-1.crt", &data, &n_data, NULL))
		g_error ("couldn't read certificate-1.crt");
	res = gkr_pkix_der_read_certificate ((const guchar*)data, n_data, &asn1);
	g_assert (res == GKR_PKIX_SUCCESS);
	certificate_1 = gkr_pk_cert_new (manager, 0, asn1);
	CuAssert (cu, "gkr_pk_cert_new returned bad object", GKR_IS_PK_CERT (certificate_1));

	/* Make sure this is trusted */
	gkr_pk_index_set_string (GKR_PK_OBJECT (certificate_1), "user-trust", "trusted");
	gkr_pk_index_delete (GKR_PK_OBJECT (certificate_1), "purposes");
	
	/* Should have created netscape trust companion object */
	keyid = gkr_pk_cert_get_keyid (certificate_1);
	trust_1 = gkr_pk_object_manager_find_by_id (manager, GKR_TYPE_PK_NETSCAPE_TRUST, keyid);
	CuAssert (cu, "No matching netscape trust object found in manager", GKR_IS_PK_NETSCAPE_TRUST (trust_1));
	
	if (!g_file_get_contents ("test-data/certificate-2.crt", &data, &n_data, NULL))
		g_error ("couldn't read certificate-2.crt");
	res = gkr_pkix_der_read_certificate ((const guchar*)data, n_data, &asn1);
	g_assert (res == GKR_PKIX_SUCCESS);
	certificate_2 = gkr_pk_cert_new (manager, 0, asn1);
	CuAssert (cu, "gkr_pk_cert_new returned bad object", GKR_IS_PK_CERT (certificate_2));

	/* Make sure this is not trusted */
	gkr_pk_index_delete (GKR_PK_OBJECT (certificate_2), "user-trust");
	gkr_pk_index_delete (GKR_PK_OBJECT (certificate_2), "purposes");
	
	/* Should have created netscape trust companion object */
	keyid = gkr_pk_cert_get_keyid (certificate_2);
	trust_2 = gkr_pk_object_manager_find_by_id (manager, GKR_TYPE_PK_NETSCAPE_TRUST, keyid);
	CuAssert (cu, "No matching netscape trust object found in manager", GKR_IS_PK_NETSCAPE_TRUST (trust_2));
}

#include "check-attribute.c"

void unit_test_trust_static (CuTest *cu)
{
	CHECK_BOOL_ATTRIBUTE (cu, trust_1, CKA_TOKEN, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, trust_1, CKA_TRUST_STEP_UP_APPROVED, CK_FALSE);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_CLASS, CKO_NETSCAPE_TRUST);
}

void unit_test_trust_related (CuTest *cu)
{
	CK_ATTRIBUTE attr;
	gkrconstunique keyid;
	const guchar *id;
	gsize n_id;
	CK_RV ret;
	
	keyid = gkr_pk_cert_get_keyid (certificate_1);
	CuAssert (cu, "No key id returned from certificate", keyid != NULL);
	
	id = gkr_unique_get_raw (keyid, &n_id);
	
	memset (&attr, 0, sizeof (attr));
	attr.type = CKA_ID;
	
	ret = gkr_pk_object_get_attribute (GKR_PK_OBJECT (trust_1), &attr);
	CuAssert (cu, "Returned null attribute", attr.pValue != NULL);
	CuAssert (cu, "Returned empty attribute", attr.ulValueLen != 0);
	CuAssert (cu, "Trust and certificate ids different lengths", attr.ulValueLen == n_id);
	CuAssert (cu, "Trust and certificate id different", memcmp (attr.pValue, id, n_id) == 0);
}

void unit_test_trust_key_usage (CuTest *cu)
{
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_DIGITAL_SIGNATURE, CKT_NETSCAPE_TRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_NON_REPUDIATION, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_KEY_ENCIPHERMENT, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_DATA_ENCIPHERMENT, CKT_NETSCAPE_TRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_KEY_AGREEMENT, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_KEY_CERT_SIGN, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_CRL_SIGN, CKT_NETSCAPE_UNTRUSTED);
	
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_DIGITAL_SIGNATURE, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_NON_REPUDIATION, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_KEY_ENCIPHERMENT, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_DATA_ENCIPHERMENT, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_KEY_AGREEMENT, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_KEY_CERT_SIGN, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_CRL_SIGN, CKT_NETSCAPE_TRUST_UNKNOWN);
}

void unit_test_trust_purpose (CuTest *cu)
{
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_SERVER_AUTH, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_CLIENT_AUTH, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_CODE_SIGNING, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_EMAIL_PROTECTION, CKT_NETSCAPE_TRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_IPSEC_END_SYSTEM, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_IPSEC_TUNNEL, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_IPSEC_USER, CKT_NETSCAPE_UNTRUSTED);
	CHECK_ULONG_ATTRIBUTE (cu, trust_1, CKA_TRUST_TIME_STAMPING, CKT_NETSCAPE_UNTRUSTED);
	
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_SERVER_AUTH, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_CLIENT_AUTH, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_CODE_SIGNING, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_EMAIL_PROTECTION, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_IPSEC_END_SYSTEM, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_IPSEC_TUNNEL, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_IPSEC_USER, CKT_NETSCAPE_TRUST_UNKNOWN);
	CHECK_ULONG_ATTRIBUTE (cu, trust_2, CKA_TRUST_TIME_STAMPING, CKT_NETSCAPE_TRUST_UNKNOWN);
}

void unit_test_trust_hash (CuTest *cu)
{
	guchar md5[16];
	guchar sha1[20];
	const guchar *raw;
	gsize n_raw;
	
	raw = gkr_pk_cert_get_raw (certificate_1, &n_raw);
	CuAssert (cu, "cannot get raw certificate", raw != NULL); 
	
	gcry_md_hash_buffer (GCRY_MD_MD5, md5, raw, n_raw);
	gcry_md_hash_buffer (GCRY_MD_SHA1, sha1, raw, n_raw);
	
	CHECK_BYTE_ATTRIBUTE (cu, trust_1, CKA_CERT_MD5_HASH, md5, 16);
	CHECK_BYTE_ATTRIBUTE (cu, trust_1, CKA_CERT_SHA1_HASH, sha1, 20);
}
