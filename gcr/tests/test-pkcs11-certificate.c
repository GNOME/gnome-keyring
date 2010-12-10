/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2010 Collabora Ltd

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

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#include "config.h"

#include "test-suite.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"

#include "gcr.h"

#include "gck/gck-mock.h"
#include "gck/gck-test.h"

#include "pkcs11/pkcs11n.h"

#include <glib.h>

static gpointer cert_data = NULL;
static gsize n_cert_data = 0;
static gpointer cert2_data = NULL;
static gsize n_cert2_data = 0;
static CK_FUNCTION_LIST funcs;

TESTING_SETUP (pkcs11_certificate)
{
	GList *modules = NULL;
	GckAttributes *attrs;
	CK_FUNCTION_LIST_PTR f;
	GckModule *module;
	gconstpointer subject;
	gsize n_subject;
	GNode *asn, *node;
	CK_RV rv;

	cert_data = testing_data_read ("der-certificate.crt", &n_cert_data);
	g_assert (cert_data);

	cert2_data = testing_data_read ("der-certificate-dsa.cer", &n_cert2_data);
	g_assert (cert2_data);

	rv = gck_mock_C_GetFunctionList (&f);
	gck_assert_cmprv (rv, ==, CKR_OK);
	memcpy (&funcs, f, sizeof (funcs));

	/* Open a session */
	rv = (funcs.C_Initialize) (NULL);
	gck_assert_cmprv (rv, ==, CKR_OK);

	g_assert (!modules);
	module = gck_module_new (&funcs, 0);
	modules = g_list_prepend (modules, module);
	gcr_pkcs11_set_modules (modules);
	gck_list_unref_free (modules);

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate", cert_data, n_cert_data);
	g_assert (asn);
	node = egg_asn1x_node (asn, "tbsCertificate", "subject", NULL);
	subject = egg_asn1x_get_raw_element (node, &n_subject);

	/* Add a certificate to the module */
	attrs = gck_attributes_new ();
	gck_attributes_add_data (attrs, CKA_VALUE, cert_data, n_cert_data);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_CERTIFICATE);
	gck_attributes_add_ulong (attrs, CKA_CERTIFICATE_TYPE, CKC_X_509);
	gck_attributes_add_data (attrs, CKA_SUBJECT, subject, n_subject);
	gck_mock_module_take_object (attrs);

	egg_asn1x_destroy (asn);
}

TESTING_TEARDOWN (pkcs11_certificate)
{
	CK_RV rv;

	g_free (cert_data);
	cert_data = NULL;
	n_cert_data = 0;

	g_free (cert2_data);
	cert2_data = NULL;
	n_cert2_data = 0;

	rv = (funcs.C_Finalize) (NULL);
	gck_assert_cmprv (rv, ==, CKR_OK);
}

TESTING_TEST (pkcs11_lookup_certificate_issuer)
{
	GcrCertificate *cert, *issuer;
	GError *error = NULL;
	GckAttributes *attrs;
	GckAttribute *attr;
	gconstpointer der;
	gsize n_der;

	cert = gcr_simple_certificate_new_static (cert_data, n_cert_data);
	g_assert (cert);

	/* Should be self-signed, so should find itself (added in setup) */
	issuer = gcr_pkcs11_certificate_lookup_issuer (cert, NULL, &error);
	g_assert (GCR_IS_PKCS11_CERTIFICATE (issuer));
	g_assert (error == NULL);

	/* Should be the same certificate */
	der = gcr_certificate_get_der_data (issuer, &n_der);
	g_assert_cmpsize (n_der, ==, n_cert_data);
	g_assert (memcmp (der, cert_data, n_cert_data) == 0);

	/* Should return the same certificate here too */
	attrs = gcr_pkcs11_certificate_get_attributes (GCR_PKCS11_CERTIFICATE (issuer));
	g_assert (attrs);
	attr = gck_attributes_find (attrs, CKA_VALUE);
	g_assert (attr);
	g_assert_cmpsize (attr->length, ==, n_cert_data);
	g_assert (memcmp (attr->value, cert_data, n_cert_data) == 0);

	/* Should return the same certificate here too */
	attrs = NULL;
	g_object_get (issuer, "attributes", &attrs, NULL);
	g_assert (attrs);
	attr = gck_attributes_find (attrs, CKA_VALUE);
	g_assert (attr);
	g_assert_cmpsize (attr->length, ==, n_cert_data);
	g_assert (memcmp (attr->value, cert_data, n_cert_data) == 0);
	gck_attributes_unref (attrs);

	g_object_unref (cert);
	g_object_unref (issuer);
}

TESTING_TEST (pkcs11_lookup_certificate_issuer_not_found)
{
	GcrCertificate *cert, *issuer;
	GError *error = NULL;

	cert = gcr_simple_certificate_new_static (cert2_data, n_cert2_data);
	g_assert (cert);

	/* Issuer shouldn't be found */
	issuer = gcr_pkcs11_certificate_lookup_issuer (cert, NULL, &error);
	g_assert (issuer == NULL);
	g_assert (error == NULL);

	g_object_unref (cert);
}

static void
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
	testing_wait_stop ();
}

TESTING_TEST (pkcs11_lookup_certificate_issuer_async)
{
	GAsyncResult *result = NULL;
	GcrCertificate *cert, *issuer;
	GError *error = NULL;
	gconstpointer der;
	gsize n_der;

	cert = gcr_simple_certificate_new_static (cert_data, n_cert_data);
	g_assert (cert);

	/* Should be self-signed, so should find itself (added in setup) */
	gcr_pkcs11_certificate_lookup_issuer_async (cert, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	issuer = gcr_pkcs11_certificate_lookup_issuer_finish (result, &error);
	g_assert (GCR_IS_PKCS11_CERTIFICATE (issuer));
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;

	/* Should be the same certificate */
	der = gcr_certificate_get_der_data (issuer, &n_der);
	g_assert_cmpsize (n_der, ==, n_cert_data);
	g_assert (memcmp (der, cert_data, n_cert_data) == 0);

	g_object_unref (cert);
	g_object_unref (issuer);
}

TESTING_TEST (pkcs11_lookup_certificate_issuer_failure)
{
	GcrCertificate *cert, *issuer;
	GError *error = NULL;

	cert = gcr_simple_certificate_new_static (cert_data, n_cert_data);
	g_assert (cert);

	/* Make the lookup fail */
	funcs.C_GetAttributeValue = gck_mock_fail_C_GetAttributeValue;

	issuer = gcr_pkcs11_certificate_lookup_issuer (cert, NULL, &error);
	g_assert (issuer == NULL);
	g_assert_error (error, GCK_ERROR, CKR_FUNCTION_FAILED);
	g_assert (error->message);
	g_clear_error (&error);

	g_object_unref (cert);
}

TESTING_TEST (pkcs11_lookup_certificate_issuer_fail_async)
{
	GAsyncResult *result = NULL;
	GcrCertificate *cert, *issuer;
	GError *error = NULL;

	cert = gcr_simple_certificate_new_static (cert_data, n_cert_data);
	g_assert (cert);

	/* Make the lookup fail */
	funcs.C_GetAttributeValue = gck_mock_fail_C_GetAttributeValue;

	/* Should be self-signed, so should find itself (added in setup) */
	gcr_pkcs11_certificate_lookup_issuer_async (cert, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	issuer = gcr_pkcs11_certificate_lookup_issuer_finish (result, &error);
	g_assert (issuer == NULL);
	g_assert_error (error, GCK_ERROR, CKR_FUNCTION_FAILED);
	g_assert (error->message);
	g_clear_error (&error);
	g_object_unref (result);
	result = NULL;

	g_object_unref (cert);
}
