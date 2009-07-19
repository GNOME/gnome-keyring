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

#include "gck/gck-attributes.h"
#include "gck/gck-object.h"
#include "gck/gck-session.h"
#include "gck/gck-module.h"

#include "pkcs11g.h"

static GckModule *module = NULL;
static GckSession *session = NULL;
static guchar *certificate_data = NULL;
static gsize certificate_n_data = 0;

DEFINE_SETUP(object_setup)
{
	module = test_module_initialize_and_enter ();
	session = test_module_open_session (TRUE);
	certificate_data = test_read_testdata ("test-certificate-1.der", &certificate_n_data);
}

DEFINE_TEARDOWN(object_teardown)
{
	g_free (certificate_data);
	certificate_data = NULL;
	certificate_n_data = 0;
	
	test_module_leave_and_finalize ();
	module = NULL;
	session = NULL;
}

static gboolean
check_object_exists (CK_OBJECT_HANDLE handle)
{
	CK_BBOOL token;
	CK_ATTRIBUTE attr = { CKA_TOKEN, &token, sizeof (token) };
	CK_RV rv;
	
	rv = gck_session_C_GetAttributeValue (session, handle, &attr, 1);
	if (rv == CKR_OBJECT_HANDLE_INVALID)
		return FALSE;
	
	g_assert (rv == CKR_OK);
	return TRUE;
}

DEFINE_TEST(object_create_destroy_transient)
{
	CK_BBOOL transient = CK_TRUE;
	CK_BBOOL token = CK_TRUE;
	CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	
	CK_ATTRIBUTE attrs[] = {
	        { CKA_TOKEN, &token, sizeof (token) },
		{ CKA_GNOME_TRANSIENT, &transient, sizeof (transient) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_CERTIFICATE_TYPE, &type, sizeof (type) },
		{ CKA_VALUE, certificate_data, certificate_n_data },
	};
	
	CK_ATTRIBUTE lookup = { CKA_GNOME_TRANSIENT, &transient, sizeof (transient) };
	CK_OBJECT_HANDLE handle;
	CK_RV rv;
	
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
	g_assert (handle != 0);
	
	g_assert (check_object_exists (handle));
	
	transient = CK_FALSE;
	rv = gck_session_C_GetAttributeValue (session, handle, &lookup, 1);
	g_assert (rv == CKR_OK);
	g_assert (transient == CK_TRUE);
	
	rv = gck_session_C_DestroyObject (session, handle);
	g_assert (rv == CKR_OK);
	
	g_assert (!check_object_exists (handle));
}

DEFINE_TEST(object_transient_transacted_fail)
{
	CK_BBOOL transient = CK_TRUE;
	CK_BBOOL token = CK_TRUE;
	CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	CK_ULONG invalid = 4;
	
	CK_ATTRIBUTE attrs[] = {
	        { CKA_TOKEN, &token, sizeof (token) },
		{ CKA_GNOME_TRANSIENT, &transient, sizeof (transient) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_CERTIFICATE_TYPE, &type, sizeof (type) },
		{ CKA_VALUE, certificate_data, certificate_n_data },
		
		/* An invalid attribute, should cause transaction to fail */
		{ CKA_BITS_PER_PIXEL, &invalid, sizeof (invalid) }  
	};
	
	CK_OBJECT_HANDLE handle;
	CK_RV rv;
	
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_ATTRIBUTE_TYPE_INVALID);
}

DEFINE_TEST(object_create_transient_bad_value)
{
	CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	
	CK_ATTRIBUTE attrs[] = {
		{ CKA_GNOME_TRANSIENT, NULL, 0 },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_CERTIFICATE_TYPE, &type, sizeof (type) },
		{ CKA_VALUE, certificate_data, certificate_n_data },
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;
	
	/* Can't have a non-transient object that auto-destructs */
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_ATTRIBUTE_VALUE_INVALID);
}

DEFINE_TEST(object_create_auto_destruct)
{
	CK_BBOOL token = CK_FALSE;
	CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	gchar lifetime[16];
	gchar check[16];
	
	CK_ATTRIBUTE attrs[] = {
       		{ CKA_GNOME_AUTO_DESTRUCT, lifetime, sizeof (lifetime) },
	        { CKA_TOKEN, &token, sizeof (token) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_CERTIFICATE_TYPE, &type, sizeof (type) },
		{ CKA_VALUE, certificate_data, certificate_n_data },
	};
	
	CK_BBOOL transient;
	
	CK_ATTRIBUTE lookups[] = { 
		{ CKA_GNOME_AUTO_DESTRUCT, check, sizeof (check) },
		{ CKA_GNOME_TRANSIENT, &transient, sizeof (transient) }
	};
	
	CK_OBJECT_HANDLE handle;
	GTimeVal tv;
	CK_RV rv;
	
	/* Fill in the special attribute */
	g_get_current_time (&tv);
	rv = gck_attribute_set_time (&attrs[0], tv.tv_sec + 2);
	g_assert (rv == CKR_OK);
	
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_OK);
	g_assert (handle != 0);
	
	g_assert (check_object_exists (handle));
	
	transient = CK_FALSE;
	rv = gck_session_C_GetAttributeValue (session, handle, lookups, G_N_ELEMENTS (lookups));
	g_assert (rv == CKR_OK);
	g_assert (transient == TRUE);
	g_assert (memcmp (lifetime, check, 16) == 0);
	
	test_module_leave ();
	test_mainloop_run (2200);
	test_module_enter ();
	
	g_assert (!check_object_exists (handle));
}

DEFINE_TEST(object_create_auto_destruct_not_transient)
{
	CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	CK_BBOOL transient = CK_FALSE; 
	
	CK_ATTRIBUTE attrs[] = {
       		{ CKA_GNOME_AUTO_DESTRUCT, "1999010101010100", 16 },
		{ CKA_GNOME_TRANSIENT, &transient, sizeof (transient) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_CERTIFICATE_TYPE, &type, sizeof (type) },
		{ CKA_VALUE, certificate_data, certificate_n_data },
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;
	
	/* Can't have a non-transient object that auto-destructs */
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_TEMPLATE_INCONSISTENT);
}

DEFINE_TEST(object_create_auto_destruct_bad_value)
{
	CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	
	CK_ATTRIBUTE attrs[] = {
       		{ CKA_GNOME_AUTO_DESTRUCT, "1999", 4 },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_CERTIFICATE_TYPE, &type, sizeof (type) },
		{ CKA_VALUE, certificate_data, certificate_n_data },
	};

	CK_OBJECT_HANDLE handle;
	CK_RV rv;
	
	/* Can't have a non-transient object that auto-destructs */
	rv = gck_session_C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &handle);
	g_assert (rv == CKR_ATTRIBUTE_VALUE_INVALID);
}
