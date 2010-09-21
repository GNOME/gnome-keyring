/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-trust.c: Test XDG trust objects.

   Copyright (C) 2010 Stefan Walter

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

#include "test-xdg-module.h"

#include "gkm/gkm-module.h"
#include "gkm/gkm-session.h"

#include "pkcs11/pkcs11n.h"

static GkmModule *module = NULL;
static GkmSession *session = NULL;

/*
 * C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting, OU=Certification Services Division,
 * CN=Thawte Personal Premium CA/emailAddress=personal-premium@thawte.com
 */

static const char DER_ISSUER[] =
	"\x30\x81\xCF\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x5A\x41"
	"\x31\x15\x30\x13\x06\x03\x55\x04\x08\x13\x0C\x57\x65\x73\x74\x65"
	"\x72\x6E\x20\x43\x61\x70\x65\x31\x12\x30\x10\x06\x03\x55\x04\x07"
	"\x13\x09\x43\x61\x70\x65\x20\x54\x6F\x77\x6E\x31\x1A\x30\x18\x06"
	"\x03\x55\x04\x0A\x13\x11\x54\x68\x61\x77\x74\x65\x20\x43\x6F\x6E"
	"\x73\x75\x6C\x74\x69\x6E\x67\x31\x28\x30\x26\x06\x03\x55\x04\x0B"
	"\x13\x1F\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x69\x6F\x6E\x20"
	"\x53\x65\x72\x76\x69\x63\x65\x73\x20\x44\x69\x76\x69\x73\x69\x6F"
	"\x6E\x31\x23\x30\x21\x06\x03\x55\x04\x03\x13\x1A\x54\x68\x61\x77"
	"\x74\x65\x20\x50\x65\x72\x73\x6F\x6E\x61\x6C\x20\x50\x72\x65\x6D"
	"\x69\x75\x6D\x20\x43\x41\x31\x2A\x30\x28\x06\x09\x2A\x86\x48\x86"
	"\xF7\x0D\x01\x09\x01\x16\x1B\x70\x65\x72\x73\x6F\x6E\x61\x6C\x2D"
	"\x70\x72\x65\x6D\x69\x75\x6D\x40\x74\x68\x61\x77\x74\x65\x2E\x63"
	"\x6F\x6D";

static const char SHA1_CHECKSUM[] =
	"\x36\x86\x35\x63\xfd\x51\x28\xc7\xbe\xa6\xf0\x05\xcf\xe9\xb4\x36"
	"\x68\x08\x6c\xce";

static const char MD5_CHECKSUM[] =
	"\x3a\xb2\xde\x22\x9a\x20\x93\x49\xf9\xed\xc8\xd2\x8a\xe7\x68\x0d";

static const char SERIAL_NUMBER[] =
	"\x01\x02\x03";

#define XL(x) G_N_ELEMENTS (x) - 1

#if 0

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"
#include "egg/egg-hex.h"

static void
debug_print_certificate_info (const gchar *path)
{
	gchar *contents;
	gchar *results;
	gconstpointer data;
	gsize length;
	GNode *asn;

	if (!g_file_get_contents (path, &contents, &length, NULL))
		g_assert_not_reached ();

	results = g_compute_checksum_for_data (G_CHECKSUM_SHA1, (gpointer)contents, length);
	g_assert (results);
	g_printerr ("SHA1: %s\n", results);
	g_free (results);

	results = g_compute_checksum_for_data (G_CHECKSUM_MD5, (gpointer)contents, length);
	g_assert (results);
	g_printerr ("MD5: %s\n", results);
	g_free (results);

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate", contents, length);
	g_assert (asn);

	data = egg_asn1x_get_raw_element (egg_asn1x_node (asn, "tbsCertificate", "issuer", NULL), &length);
	g_assert (data);

	results = egg_hex_encode_full (data, length, TRUE, '\\', 1);
	g_printerr ("ISSUER: %s\n", results);
	g_free (results);

	egg_asn1x_destroy (asn);
	g_free (contents);
}

#endif

DEFINE_SETUP (trust_setup)
{
	CK_RV rv;

	testing_data_to_scratch ("test-trust-1.der", "test-trust.trust");

	module = test_xdg_module_initialize_and_enter ();
	session = test_xdg_module_open_session (TRUE);

	rv = gkm_module_C_Login (module, gkm_session_get_handle (session), CKU_USER, NULL, 0);
	g_assert (rv == CKR_OK);
}

DEFINE_TEARDOWN (trust_teardown)
{
	test_xdg_module_leave_and_finalize ();
	module = NULL;
	session = NULL;
}

DEFINE_TEST (trust_load_object)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;
	CK_TRUST trusted = CKT_NETSCAPE_TRUSTED;
	CK_TRUST unknown = CKT_NETSCAPE_TRUST_UNKNOWN;

	/* This info matches what's in test-trust-1.der */
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SERIAL_NUMBER, "\x01\x02", 2 },
		{ CKA_TRUST_CLIENT_AUTH, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CODE_SIGNING, &unknown, sizeof (unknown) },
		{ CKA_TRUST_EMAIL_PROTECTION, &trusted, sizeof (trusted) },
	};

	CK_ULONG n_objects;
	CK_OBJECT_HANDLE objects[16];
	CK_RV rv;

	rv = gkm_session_C_FindObjectsInit (session, attrs, G_N_ELEMENTS (attrs));
	g_assert (rv == CKR_OK);

	rv = gkm_session_C_FindObjects (session, objects, G_N_ELEMENTS (objects), &n_objects);
	g_assert (rv == CKR_OK);

	rv = gkm_session_C_FindObjectsFinal (session);
	g_assert (rv == CKR_OK);

	gkm_assert_cmpulong (n_objects, ==, 1);
}

DEFINE_TEST (trust_create)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SERIAL_NUMBER, (void*)SERIAL_NUMBER, XL (SERIAL_NUMBER) }
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);

	rv = gkm_session_C_DestroyObject (session, handle);
	g_assert (rv == CKR_OK);
}


DEFINE_TEST (trust_create_invalid_attrs)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_TEMPLATE_INCOMPLETE);
}

DEFINE_TEST (trust_create_invalid_der)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, "test", 4 },
		{ CKA_SERIAL_NUMBER, (void*)SERIAL_NUMBER, XL (SERIAL_NUMBER) }
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_ATTRIBUTE_VALUE_INVALID);
}

DEFINE_TEST (trust_create_invalid_serial)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SERIAL_NUMBER, "", 0 }
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_ATTRIBUTE_VALUE_INVALID);
}

DEFINE_TEST (trust_create_with_sha1)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SERIAL_NUMBER, (void*)SERIAL_NUMBER, XL (SERIAL_NUMBER) },
		{ CKA_CERT_SHA1_HASH, (void*)SHA1_CHECKSUM, XL (SHA1_CHECKSUM) }
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
}

DEFINE_TEST (trust_create_with_md5)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SERIAL_NUMBER, (void*)SERIAL_NUMBER, XL (SERIAL_NUMBER) },
		{ CKA_CERT_MD5_HASH, (void*)MD5_CHECKSUM, XL (MD5_CHECKSUM) }
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
}

DEFINE_TEST (trust_create_with_subject)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SUBJECT, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SERIAL_NUMBER, (void*)SERIAL_NUMBER, XL (SERIAL_NUMBER) }
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
}

DEFINE_TEST (trust_create_invalid_checksum)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SERIAL_NUMBER, (void*)SERIAL_NUMBER, XL (SERIAL_NUMBER) },
		{ CKA_CERT_SHA1_HASH, "test", 4 }
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_ATTRIBUTE_VALUE_INVALID);
}

DEFINE_TEST (trust_create_with_trusted)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;
	CK_TRUST trust = CKT_NETSCAPE_TRUSTED;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SERIAL_NUMBER, (void*)SERIAL_NUMBER, XL (SERIAL_NUMBER) },
		{ CKA_TRUST_EMAIL_PROTECTION, &trust, sizeof (trust) }
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
}

DEFINE_TEST (trust_create_with_trusted_and_save)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;
	CK_TRUST trusted = CKT_NETSCAPE_TRUSTED;
	CK_TRUST untrusted = CKT_NETSCAPE_UNTRUSTED;
	CK_TRUST unknown = CKT_NETSCAPE_TRUST_UNKNOWN;
	CK_BBOOL true = CK_TRUE;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_ISSUER, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SUBJECT, (void*)DER_ISSUER, XL (DER_ISSUER) },
		{ CKA_SERIAL_NUMBER, (void*)SERIAL_NUMBER, XL (SERIAL_NUMBER) },
		{ CKA_TOKEN, &true, sizeof (true) },
		{ CKA_TRUST_DIGITAL_SIGNATURE, &trusted, sizeof (trusted) },
		{ CKA_TRUST_NON_REPUDIATION, &trusted, sizeof (trusted) },
		{ CKA_TRUST_KEY_ENCIPHERMENT, &trusted, sizeof (trusted) },
		{ CKA_TRUST_DATA_ENCIPHERMENT, &trusted, sizeof (trusted) },
		{ CKA_TRUST_KEY_AGREEMENT, &trusted, sizeof (trusted) },
		{ CKA_TRUST_KEY_CERT_SIGN, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CRL_SIGN, &trusted, sizeof (trusted) },
		{ CKA_TRUST_SERVER_AUTH, &untrusted, sizeof (untrusted) },
		{ CKA_TRUST_CLIENT_AUTH, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CODE_SIGNING, &unknown, sizeof (unknown) },
		{ CKA_TRUST_EMAIL_PROTECTION, &trusted, sizeof (trusted) },
		{ CKA_TRUST_TIME_STAMPING, &untrusted, sizeof (untrusted) },
		{ CKA_TRUST_IPSEC_END_SYSTEM, &untrusted, sizeof (untrusted) },
		{ CKA_TRUST_IPSEC_TUNNEL, &untrusted, sizeof (untrusted) },
		{ CKA_TRUST_IPSEC_USER, &untrusted, sizeof (untrusted) },
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gkm_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
}
