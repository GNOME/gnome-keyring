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
#include "gck/gck-authenticator.h"
#include "gck/gck-login.h"
#include "gck/gck-object.h"
#include "gck/gck-session.h"
#include "gck/gck-module.h"

#include "pkcs11g.h"

static GckModule *module = NULL;
static GckSession *session = NULL;
static GckObject *object = NULL;

DEFINE_SETUP(authenticator_setup)
{
	CK_RV rv;
	module = test_module_initialize_and_enter ();
	session = test_module_open_session (TRUE);
	
	rv = gck_module_C_Login (module, gck_session_get_handle (session), CKU_USER, NULL, 0);
	g_assert (rv == CKR_OK);
	
	object = mock_locked_object_new (module);
	gck_manager_register_object (gck_module_get_manager (module), object);
}

DEFINE_TEARDOWN(authenticator_teardown)
{
	g_object_unref (object);
	object = NULL;
	
	test_module_leave_and_finalize ();
	module = NULL;
	session = NULL;
}

DEFINE_TEST(authenticator_create)
{
	CK_OBJECT_CLASS klass = CKO_GNOME_AUTHENTICATOR;
	CK_OBJECT_HANDLE locked = gck_object_get_handle (object);
	
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_GNOME_OBJECT, &locked, sizeof (locked) },
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

DEFINE_TEST(authenticator_create_missing_pin)
{
	CK_OBJECT_CLASS klass = CKO_GNOME_AUTHENTICATOR;
	CK_OBJECT_HANDLE locked = gck_object_get_handle (object);
	
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_GNOME_OBJECT, &locked, sizeof (locked) },
	};
	
	CK_OBJECT_HANDLE handle;
	CK_RV rv;
	
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_USER_NOT_LOGGED_IN);
}

DEFINE_TEST(authenticator_create_no_object)
{
	CK_OBJECT_CLASS klass = CKO_GNOME_AUTHENTICATOR;
	CK_BBOOL token = CK_FALSE;
	
	CK_ATTRIBUTE attrs[] = {
	        { CKA_TOKEN, &token, sizeof (token) },
		{ CKA_CLASS, &klass, sizeof (klass) },
	};
	
	CK_OBJECT_HANDLE handle;
	CK_RV rv;
	
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_TEMPLATE_INCOMPLETE);
}

DEFINE_TEST(authenticator_create_invalid_object)
{
	CK_OBJECT_CLASS klass = CKO_GNOME_AUTHENTICATOR;
	CK_OBJECT_HANDLE locked = 0;
	CK_BBOOL token = CK_FALSE;
	
	CK_ATTRIBUTE attrs[] = {
	        { CKA_TOKEN, &token, sizeof (token) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_GNOME_OBJECT, &locked, sizeof (locked) },
	};
	
	CK_OBJECT_HANDLE handle;
	CK_RV rv;
	
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OBJECT_HANDLE_INVALID);
}

DEFINE_TEST(authenticator_get_attributes)
{
	CK_OBJECT_CLASS klass = CKO_GNOME_AUTHENTICATOR;
	CK_OBJECT_HANDLE locked = gck_object_get_handle (object);
	
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_GNOME_OBJECT, &locked, sizeof (locked) },
		{ CKA_VALUE, "mock", 4 },
	};
	
	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE check;
	CK_ULONG value;
	CK_RV rv;
	
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
	g_assert (handle != 0);

	check.type = CKA_GNOME_OBJECT;
	check.pValue = &value;
	check.ulValueLen = sizeof (value);
	
	rv = gck_session_C_GetAttributeValue (session, handle, &check, 1);
	g_assert (rv == CKR_OK);
	g_assert (check.ulValueLen == sizeof (value));
	g_assert (value == locked);

	check.type = CKA_GNOME_USES_REMAINING;
	check.pValue = &value;
	check.ulValueLen = sizeof (value);
	
	rv = gck_session_C_GetAttributeValue (session, handle, &check, 1);
	g_assert (rv == CKR_OK);
	g_assert (check.ulValueLen == sizeof (value));
	g_assert (value == (CK_ULONG)-1);
}

DEFINE_TEST(authenticator_uses_property)
{
	GckAuthenticator *auth;
	gint uses;
	CK_RV rv;
	
	rv = gck_authenticator_create (object, (guchar*)"mock", 4, &auth);
	g_assert (rv == CKR_OK);
	g_assert (auth);
	
	g_object_get (auth, "uses-remaining", &uses, NULL);
	g_assert (uses == -1);

	gck_authenticator_set_uses_remaining (auth, 5);

	uses = gck_authenticator_get_uses_remaining (auth);
	g_assert (uses == 5);
	
	gck_authenticator_throw_away_one_use (auth);
	uses = gck_authenticator_get_uses_remaining (auth);
	g_assert (uses == 4);
	
	g_object_unref (auth);
}

DEFINE_TEST(authenticator_object_property)
{
	GckAuthenticator *auth;
	GckObject *check;
	CK_RV rv;
	
	rv = gck_authenticator_create (object, (guchar*)"mock", 4, &auth);
	g_assert (rv == CKR_OK);
	g_assert (auth);
	
	g_object_get (auth, "object", &check, NULL);
	g_assert (check == object);
	g_object_unref (check);

	check = gck_authenticator_get_object (auth);
	g_assert (check == object);
	
	g_object_unref (auth);
}

DEFINE_TEST(authenticator_login_property)
{
	GckAuthenticator *auth;
	GckLogin *check, *login;
	const gchar *password;
	gsize n_password;
	CK_RV rv;
	
	rv = gck_authenticator_create (object, (guchar*)"mock", 4, &auth);
	g_assert (rv == CKR_OK);
	g_assert (auth);
	
	g_object_get (auth, "login", &check, NULL);
	g_assert (check);
	password = gck_login_get_password (check, &n_password);
	g_assert (n_password == 4);
	g_assert (memcmp (password, "mock", 4) == 0);
	g_object_unref (check);

	check = gck_authenticator_get_login (auth);
	g_assert (n_password == 4);
	g_assert (memcmp (password, "mock", 4) == 0);
	
	login = gck_login_new ((guchar*)"xxx", -1);
	gck_authenticator_set_login (auth, login);
	check = gck_authenticator_get_login (auth);
	g_assert (n_password == 4);
	g_assert (memcmp (password, "mock", 4) == 0);
	g_object_unref (login);
	
	g_object_unref (auth);
}
