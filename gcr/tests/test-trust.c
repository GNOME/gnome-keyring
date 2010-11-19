/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
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

#include "test-suite.h"

#include "gcr.h"
#include "gcr/gcr-internal.h"

#include "gck/gck-mock.h"
#include "gck/gck-test.h"

#include "pkcs11/pkcs11n.h"

#include <glib.h>

static CK_FUNCTION_LIST_PTR funcs;
static GList *modules = NULL;
static GcrCertificate *certificate = NULL;

DEFINE_SETUP (trust_setup)
{
	GckModule *module;
	guchar *contents;
	gsize len;
	CK_RV rv;

	contents = testing_data_read ("der-certificate.crt", &len);
	g_assert (contents);

	certificate = gcr_simple_certificate_new (contents, len);

	rv = gck_mock_C_GetFunctionList (&funcs);
	gck_assert_cmprv (rv, ==, CKR_OK);

	/* Open a session */
	rv = (funcs->C_Initialize) (NULL);
	gck_assert_cmprv (rv, ==, CKR_OK);

	g_assert (!modules);
	module = gck_module_new (funcs, 0);
	modules = g_list_prepend (modules, module);

	_gcr_set_test_pkcs11_modules (modules);
	_gcr_set_test_trust_slot (GCK_MOCK_SLOT_ONE_URI);
}

DEFINE_TEARDOWN (trust_setup)
{
	CK_RV rv;

	g_object_unref (certificate);
	certificate = NULL;

	g_assert (funcs);
	rv = (funcs->C_Finalize) (NULL);
	gck_assert_cmprv (rv, ==, CKR_OK);

	gck_list_unref_free (modules);
	modules = NULL;
}

DEFINE_TEST (trust_is_exception_none)
{
	GError *error = NULL;
	gboolean trust;

	trust = gcr_trust_is_certificate_exception (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert_cmpint (trust, ==, TRUE);
	g_assert (error == NULL);
}

DEFINE_TEST (trust_add_and_is_exception)
{
	GError *error = NULL;
	gboolean trust;
	gboolean ret;

	trust = gcr_trust_is_certificate_exception (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert_cmpint (trust, ==, TRUE);
	g_assert (error == NULL);

	ret = gcr_trust_add_certificate_exception (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);

	trust = gcr_trust_is_certificate_exception (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert_cmpint (trust, ==, TRUE);
	g_assert (error == NULL);
}

DEFINE_TEST (trust_add_and_remov_exception)
{
	GError *error = NULL;
	gboolean trust;
	gboolean ret;

	ret = gcr_trust_add_certificate_exception (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);

	trust = gcr_trust_is_certificate_exception (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert_cmpint (trust, ==, TRUE);
	g_assert (error == NULL);

	ret = gcr_trust_remove_certificate_exception (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);

	trust = gcr_trust_is_certificate_exception (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert_cmpint (trust, ==, FALSE);
	g_assert (error == NULL);
}

static void
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
	testing_wait_stop ();
}

DEFINE_TEST (trust_add_and_is_exception_async)
{
	GAsyncResult *result = NULL;
	GError *error = NULL;
	gboolean trust;
	gboolean ret;

	gcr_trust_is_certificate_exception_async (certificate, GCR_PURPOSE_EMAIL, "host", NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	trust = gcr_trust_is_certificate_exception_finish (result, &error);
	g_assert (trust == FALSE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;

	gcr_trust_add_certificate_exception_async (certificate, GCR_PURPOSE_EMAIL, "host",
	                                           NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	ret = gcr_trust_add_certificate_exception_finish (result, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;

	gcr_trust_is_certificate_exception_async (certificate, GCR_PURPOSE_EMAIL, "host", NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	trust = gcr_trust_is_certificate_exception_finish (result, &error);
	g_assert (trust == TRUE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;
}

DEFINE_TEST (trust_is_certificate_anchor_not)
{
	GError *error = NULL;
	gboolean ret;

	ret = gcr_trust_is_certificate_anchor (certificate, GCR_PURPOSE_CLIENT_AUTH, NULL, &error);
	g_assert (ret == FALSE);
	g_assert (error == NULL);
}

DEFINE_TEST (trust_is_certificate_anchor_yes)
{
	GError *error = NULL;
	GckAttributes *attrs;
	gpointer data;
	gsize n_data;
	gboolean ret;

	/* Create a certificate root trust */
	attrs = gck_attributes_new ();
	data = gcr_certificate_get_issuer_raw (certificate, &n_data);
	g_assert (data && n_data);
	gck_attributes_add_data (attrs, CKA_ISSUER, data, n_data);
	g_free (data);
	data = gcr_certificate_get_serial_number (certificate, &n_data);
	g_assert (data && n_data);
	gck_attributes_add_data (attrs, CKA_SERIAL_NUMBER, data, n_data);
	g_free (data);
	data = gcr_certificate_get_fingerprint (certificate, G_CHECKSUM_SHA1, &n_data);
	g_assert (data);
	gck_attributes_add_data (attrs, CKA_CERT_SHA1_HASH, data, n_data);
	g_free (data);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_NETSCAPE_TRUST);
	gck_attributes_add_ulong (attrs, CKA_TRUST_CLIENT_AUTH, CKT_NETSCAPE_TRUSTED_DELEGATOR);
	gck_mock_module_take_object (attrs);

	ret = gcr_trust_is_certificate_anchor (certificate, GCR_PURPOSE_CLIENT_AUTH, NULL, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);
}

DEFINE_TEST (trust_is_certificate_anchor_async)
{
	GAsyncResult *result = NULL;
	GError *error = NULL;
	gboolean ret;

	gcr_trust_is_certificate_anchor_async (certificate, GCR_PURPOSE_CLIENT_AUTH, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);

	ret = gcr_trust_is_certificate_anchor_finish (result, &error);
	g_assert (ret == FALSE);
	g_assert (error == NULL);

	g_object_unref (result);
}
