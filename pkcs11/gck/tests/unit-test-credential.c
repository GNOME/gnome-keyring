/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-timer.c: Test thread timer functionality

   Copyright (C) 2009 Stefan Walter

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

#include "run-auto-test.h"
#include "test-module.h"
#include "mock-locked-object.h"

#include "gck/gck-attributes.h"
#include "gck/gck-credential.h"
#include "gck/gck-object.h"
#include "gck/gck-secret.h"
#include "gck/gck-session.h"
#include "gck/gck-module.h"

#include "pkcs11g.h"

static GckModule *module = NULL;
static GckSession *session = NULL;
static GckObject *object = NULL;

DEFINE_SETUP(credential_setup)
{
	CK_RV rv;
	module = test_module_initialize_and_enter ();
	session = test_module_open_session (TRUE);

	rv = gck_module_C_Login (module, gck_session_get_handle (session), CKU_USER, NULL, 0);
	g_assert (rv == CKR_OK);

	object = mock_locked_object_new (module, gck_module_get_manager (module));
	gck_object_expose (object, TRUE);
}

DEFINE_TEARDOWN(credential_teardown)
{
	g_object_unref (object);
	object = NULL;

	test_module_leave_and_finalize ();
	module = NULL;
	session = NULL;
}

DEFINE_TEST(credential_create)
{
	CK_OBJECT_CLASS klass = CKO_G_CREDENTIAL;
	CK_OBJECT_HANDLE locked = gck_object_get_handle (object);

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_G_OBJECT, &locked, sizeof (locked) },
		{ CKA_VALUE, "mock", 4 },
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
	g_assert (handle != 0);

	rv = gck_session_C_DestroyObject (session, handle);
	g_assert (rv == CKR_OK);
}

DEFINE_TEST(credential_create_missing_pin)
{
	CK_OBJECT_CLASS klass = CKO_G_CREDENTIAL;
	CK_OBJECT_HANDLE locked = gck_object_get_handle (object);

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_G_OBJECT, &locked, sizeof (locked) },
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_USER_NOT_LOGGED_IN);
}

DEFINE_TEST(credential_create_no_object)
{
	CK_OBJECT_CLASS klass = CKO_G_CREDENTIAL;
	CK_BBOOL token = CK_FALSE;
	CK_OBJECT_HANDLE objhand = (CK_ULONG)-1;
	CK_ATTRIBUTE attr;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_CLASS, &klass, sizeof (klass) },
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
	g_assert (handle != 0);

	attr.type = CKA_G_OBJECT;
	attr.pValue = &objhand;
	attr.ulValueLen = sizeof (objhand);
	rv = gck_session_C_GetAttributeValue (session, handle, &attr, 1);
	g_assert (rv == CKR_OK);
	g_assert (objhand == 0);
}

DEFINE_TEST(credential_create_invalid_object)
{
	CK_OBJECT_CLASS klass = CKO_G_CREDENTIAL;
	CK_OBJECT_HANDLE locked = 0;
	CK_BBOOL token = CK_FALSE;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_G_OBJECT, &locked, sizeof (locked) },
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OBJECT_HANDLE_INVALID);
}

DEFINE_TEST(credential_get_attributes)
{
	CK_OBJECT_CLASS klass = CKO_G_CREDENTIAL;
	CK_OBJECT_HANDLE locked = gck_object_get_handle (object);

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_G_OBJECT, &locked, sizeof (locked) },
		{ CKA_VALUE, "mock", 4 },
	};

	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE check;
	CK_ULONG value;
	CK_RV rv;

	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
	g_assert (handle != 0);

	check.type = CKA_G_OBJECT;
	check.pValue = &value;
	check.ulValueLen = sizeof (value);

	rv = gck_session_C_GetAttributeValue (session, handle, &check, 1);
	g_assert (rv == CKR_OK);
	g_assert (check.ulValueLen == sizeof (value));
	g_assert (value == locked);

	check.type = CKA_G_USES_REMAINING;
	check.pValue = &value;
	check.ulValueLen = sizeof (value);

	rv = gck_session_C_GetAttributeValue (session, handle, &check, 1);
	g_assert (rv == CKR_OK);
	g_assert (check.ulValueLen == sizeof (value));
	g_assert (value == (CK_ULONG)-1);
}

DEFINE_TEST(credential_uses_property)
{
	GckCredential *auth;
	gint uses;
	CK_RV rv;

	rv = gck_credential_create (module, NULL, object, (guchar*)"mock", 4, &auth);
	g_assert (rv == CKR_OK);
	g_assert (auth);

	g_object_get (auth, "uses-remaining", &uses, NULL);
	g_assert (uses == -1);

	gck_credential_set_uses_remaining (auth, 5);

	uses = gck_credential_get_uses_remaining (auth);
	g_assert (uses == 5);

	gck_credential_throw_away_one_use (auth);
	uses = gck_credential_get_uses_remaining (auth);
	g_assert (uses == 4);

	g_object_unref (auth);
}

DEFINE_TEST(credential_object_property)
{
	GckCredential *auth;
	GckObject *check;
	CK_RV rv;

	rv = gck_credential_create (module, NULL, object, (guchar*)"mock", 4, &auth);
	g_assert (rv == CKR_OK);
	g_assert (auth);

	g_object_get (auth, "object", &check, NULL);
	g_assert (check == object);
	g_object_unref (check);

	check = gck_credential_get_object (auth);
	g_assert (check == object);

	g_object_unref (auth);
}

DEFINE_TEST(credential_login_property)
{
	GckCredential *cred;
	GckSecret *check, *secret;
	const gchar *password;
	gsize n_password;
	CK_RV rv;

	rv = gck_credential_create (module, NULL, object, (guchar*)"mock", 4, &cred);
	g_assert (rv == CKR_OK);
	g_assert (cred);

	g_object_get (cred, "secret", &check, NULL);
	g_assert (check);
	password = gck_secret_get_password (check, &n_password);
	g_assert (n_password == 4);
	g_assert (memcmp (password, "mock", 4) == 0);
	g_object_unref (check);

	check = gck_credential_get_secret (cred);
	g_assert (n_password == 4);
	g_assert (memcmp (password, "mock", 4) == 0);

	secret = gck_secret_new ((guchar*)"xxx", -1);
	gck_credential_set_secret (cred, secret);
	check = gck_credential_get_secret (cred);
	g_assert (check == secret);
	g_object_unref (secret);

	g_object_unref (cred);
}

DEFINE_TEST(credential_data)
{
	GckCredential *cred;
	CK_RV rv;

	rv = gck_credential_create (module, NULL, object, (guchar*)"mock", 4, &cred);
	g_assert (rv == CKR_OK);
	g_assert (cred);

	g_assert (gck_credential_get_data (cred) == NULL);

	gck_credential_set_data (cred, g_strdup ("one"), g_free);

	g_assert_cmpstr ("one", ==, gck_credential_get_data (cred));

	gck_credential_set_data (cred, g_strdup ("ONE"), g_free);
	g_assert_cmpstr ("ONE", ==, gck_credential_get_data (cred));

	gck_credential_set_data (cred, NULL, NULL);
	g_assert (gck_credential_get_data (cred) == NULL);

	g_object_unref (cred);
}

DEFINE_TEST(credential_connect_object)
{
	GckCredential *cred;
	CK_RV rv;

	rv = gck_credential_create (module, NULL, NULL, (guchar*)"mock", 4, &cred);
	g_assert (rv == CKR_OK);
	g_assert (cred);

	gck_credential_connect (cred, object);
	g_assert (gck_credential_get_object (cred) == object);

	g_object_unref (cred);
}
