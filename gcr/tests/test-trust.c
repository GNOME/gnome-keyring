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

#include "gck/gck-mock.h"
#include "gck/gck-test.h"

#include "pkcs11/pkcs11n.h"

#include <glib.h>

static CK_FUNCTION_LIST funcs;
static GcrCertificate *certificate = NULL;

TESTING_SETUP (trust_setup)
{
	GList *modules = NULL;
	CK_FUNCTION_LIST_PTR f;
	GckModule *module;
	guchar *contents;
	gsize len;
	CK_RV rv;

	contents = testing_data_read ("der-certificate.crt", &len);
	g_assert (contents);

	certificate = gcr_simple_certificate_new (contents, len);

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

	gcr_pkcs11_set_trust_store_uri (GCK_MOCK_SLOT_ONE_URI);
}

TESTING_TEARDOWN (trust_setup)
{
	CK_RV rv;

	g_object_unref (certificate);
	certificate = NULL;

	rv = (funcs.C_Finalize) (NULL);
	gck_assert_cmprv (rv, ==, CKR_OK);
}

TESTING_TEST (trust_is_pinned_none)
{
	GError *error = NULL;
	gboolean trust;

	trust = gcr_trust_is_certificate_pinned (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert_cmpint (trust, ==, FALSE);
	g_assert (error == NULL);
}

TESTING_TEST (trust_add_and_is_pinned)
{
	GError *error = NULL;
	gboolean trust;
	gboolean ret;

	trust = gcr_trust_is_certificate_pinned (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert_cmpint (trust, ==, FALSE);
	g_assert (error == NULL);

	ret = gcr_trust_add_pinned_certificate (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);

	trust = gcr_trust_is_certificate_pinned (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert_cmpint (trust, ==, TRUE);
	g_assert (error == NULL);
}

TESTING_TEST (trust_add_certificate_pinned_fail)
{
	GError *error = NULL;
	gboolean ret;

	/* Make this function fail */
	funcs.C_CreateObject = gck_mock_fail_C_CreateObject;

	ret = gcr_trust_add_pinned_certificate (certificate, GCR_PURPOSE_CLIENT_AUTH, "peer", NULL, &error);
	g_assert (ret == FALSE);
	g_assert_error (error, GCK_ERROR, CKR_FUNCTION_FAILED);
}

TESTING_TEST (trust_add_and_remov_pinned)
{
	GError *error = NULL;
	gboolean trust;
	gboolean ret;

	ret = gcr_trust_add_pinned_certificate (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);

	trust = gcr_trust_is_certificate_pinned (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert_cmpint (trust, ==, TRUE);
	g_assert (error == NULL);

	ret = gcr_trust_remove_pinned_certificate (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);

	trust = gcr_trust_is_certificate_pinned (certificate, GCR_PURPOSE_EMAIL, "host", NULL, &error);
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

TESTING_TEST (trust_add_and_is_pinned_async)
{
	GAsyncResult *result = NULL;
	GError *error = NULL;
	gboolean trust;
	gboolean ret;

	gcr_trust_is_certificate_pinned_async (certificate, GCR_PURPOSE_EMAIL, "host", NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	trust = gcr_trust_is_certificate_pinned_finish (result, &error);
	g_assert (trust == FALSE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;

	gcr_trust_add_pinned_certificate_async (certificate, GCR_PURPOSE_EMAIL, "host",
	                                           NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	ret = gcr_trust_add_pinned_certificate_finish (result, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;

	gcr_trust_is_certificate_pinned_async (certificate, GCR_PURPOSE_EMAIL, "host", NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	trust = gcr_trust_is_certificate_pinned_finish (result, &error);
	g_assert (trust == TRUE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;
}

TESTING_TEST (trust_add_and_remov_pinned_async)
{
	GAsyncResult *result = NULL;
	GError *error = NULL;
	gboolean trust;
	gboolean ret;

	gcr_trust_add_pinned_certificate_async (certificate, GCR_PURPOSE_EMAIL, "host", NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	ret = gcr_trust_add_pinned_certificate_finish (result, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;

	gcr_trust_is_certificate_pinned_async (certificate, GCR_PURPOSE_EMAIL, "host", NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	trust = gcr_trust_is_certificate_pinned_finish (result, &error);
	g_assert (trust == TRUE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;

	gcr_trust_remove_pinned_certificate_async (certificate, GCR_PURPOSE_EMAIL, "host", NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	ret = gcr_trust_remove_pinned_certificate_finish (result, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;

	gcr_trust_is_certificate_pinned_async (certificate, GCR_PURPOSE_EMAIL, "host", NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);
	trust = gcr_trust_is_certificate_pinned_finish (result, &error);
	g_assert (trust == FALSE);
	g_assert (error == NULL);
	g_object_unref (result);
	result = NULL;
}

TESTING_TEST (trust_is_certificate_anchored_not)
{
	GError *error = NULL;
	gboolean ret;

	ret = gcr_trust_is_certificate_anchored (certificate, GCR_PURPOSE_CLIENT_AUTH, NULL, &error);
	g_assert (ret == FALSE);
	g_assert (error == NULL);
}

TESTING_TEST (trust_is_certificate_anchored_yes)
{
	GError *error = NULL;
	GckAttributes *attrs;
	gconstpointer der;
	gsize n_der;
	gboolean ret;

	/* Create a certificate root trust */
	attrs = gck_attributes_new ();
	der = gcr_certificate_get_der_data (certificate, &n_der);
	gck_attributes_add_data (attrs, CKA_G_CERTIFICATE_VALUE, der, n_der);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_G_TRUST_ASSERTION);
	gck_attributes_add_boolean (attrs, CKA_TOKEN, TRUE);
	gck_attributes_add_string (attrs, CKA_G_PURPOSE, GCR_PURPOSE_CLIENT_AUTH);
	gck_attributes_add_ulong (attrs, CKA_G_ASSERTION_TYPE, CKT_G_ANCHORED_CERTIFICATE);
	gck_mock_module_take_object (attrs);

	ret = gcr_trust_is_certificate_anchored (certificate, GCR_PURPOSE_CLIENT_AUTH, NULL, &error);
	g_assert (ret == TRUE);
	g_assert (error == NULL);
}

TESTING_TEST (trust_is_certificate_anchored_async)
{
	GAsyncResult *result = NULL;
	GError *error = NULL;
	gboolean ret;

	gcr_trust_is_certificate_anchored_async (certificate, GCR_PURPOSE_CLIENT_AUTH, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);

	ret = gcr_trust_is_certificate_anchored_finish (result, &error);
	g_assert (ret == FALSE);
	g_assert (error == NULL);

	g_object_unref (result);
}
