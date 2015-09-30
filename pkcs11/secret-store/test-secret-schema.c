/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2012 Red Hat Ltd.

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

   Author: Stef Walter <stefw@gnome.org>
*/

#include "config.h"

#include "mock-secret-module.h"

#include "secret-store/gkm-secret-collection.h"
#include "secret-store/gkm-secret-item.h"
#include "secret-store/gkm-secret-search.h"

#include "gkm/gkm-credential.h"
#include "gkm/gkm-secret.h"
#include "gkm/gkm-serializable.h"
#include "gkm/gkm-session.h"
#include "gkm/gkm-transaction.h"
#include "gkm/gkm-test.h"

#include "pkcs11/pkcs11i.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
	GkmModule *module;
	GkmSession *session;
	GkmSecretCollection *collection;
} Test;

static void
setup (Test *test,
       gconstpointer unused)
{
	GkmDataResult res;

	test->module = test_secret_module_initialize_and_enter ();
	test->session = test_secret_module_open_session (TRUE);

	test->collection = g_object_new (GKM_TYPE_SECRET_COLLECTION,
	                                 "module", test->module,
	                                 "manager", gkm_session_get_manager (test->session),
	                                 "identifier", "test-collection",
	                                 NULL);

	/*
	 * This file contains entries that don't actually have any xdg:schema
	 * entries. It does contain the old libgnome-keyring style item types,
	 * and these should be used to match the appropriate schemas.
	 */

	gkm_secret_collection_set_filename (test->collection,
	                                    SRCDIR "/pkcs11/secret-store/fixtures/schema1.keyring");

	/* Load the collection */
	res = gkm_secret_collection_load (test->collection);
	g_assert (res == GKM_DATA_SUCCESS);
	gkm_object_expose (GKM_OBJECT (test->collection), TRUE);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	g_object_unref (test->collection);
	test_secret_module_leave_and_finalize ();
}

static gint
count_number_of_matched (Test *test,
                         CK_ATTRIBUTE *attrs,
                         CK_ULONG n_attrs)
{
	GkmObject *object = NULL;
	gpointer vdata;
	gsize vsize;
	guint count;

	object = gkm_session_create_object_for_factory (test->session, GKM_FACTORY_SECRET_SEARCH, NULL, attrs, 2);
	g_assert (object != NULL);
	g_assert (GKM_IS_SECRET_SEARCH (object));

	/* One object matched */
	vdata = gkm_object_get_attribute_data (object, test->session, CKA_G_MATCHED, &vsize);
	g_assert (vdata);
	g_assert (vsize % sizeof (CK_OBJECT_HANDLE) == 0);
	count = vsize / sizeof (CK_OBJECT_HANDLE);
	g_free (vdata);

	g_object_unref (object);

	return count;
}

static void
test_match_network_xdg_schema_without_schema_unlocked (Test *test,
                                                       gconstpointer unused)
{
	GkmCredential *cred;
	CK_RV rv;

	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "xdg:schema\0org.gnome.keyring.NetworkPassword\0", 45 },
	        { CKA_G_COLLECTION, "test-collection", 15 },
	};

	/* Unlock the collection */
	rv = gkm_credential_create (test->module, gkm_session_get_manager (test->session),
	                            GKM_OBJECT (test->collection), (CK_UTF8CHAR_PTR)"booo", 4, &cred);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	g_assert_cmpint (count_number_of_matched (test, attrs, 2), ==, 1);

	g_object_unref (cred);
}

static void
test_match_note_xdg_schema_without_schema_unlocked (Test *test,
                                                    gconstpointer unused)
{
	GkmCredential *cred;
	CK_RV rv;

	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "xdg:schema\0org.gnome.keyring.Note\0", 34 },
	        { CKA_G_COLLECTION, "test-collection", 15 },
	};

	/* Unlock the collection */
	rv = gkm_credential_create (test->module, gkm_session_get_manager (test->session),
	                            GKM_OBJECT (test->collection), (CK_UTF8CHAR_PTR)"booo", 4, &cred);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	g_assert_cmpint (count_number_of_matched (test, attrs, 2), ==, 1);

	g_object_unref (cred);
}

static void
test_match_network_xdg_schema_without_schema_locked (Test *test,
                                                     gconstpointer unused)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "xdg:schema\0org.gnome.keyring.NetworkPassword\0", 45 },
	        { CKA_G_COLLECTION, "test-collection", 15 },
	};

	g_assert_cmpint (count_number_of_matched (test, attrs, 2), ==, 1);
}

static void
test_match_note_xdg_schema_without_schema_locked (Test *test,
                                                  gconstpointer unused)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "xdg:schema\0org.gnome.keyring.Note\0", 34 },
	        { CKA_G_COLLECTION, "test-collection", 15 },
	};

	g_assert_cmpint (count_number_of_matched (test, attrs, 2), ==, 1);
}

static void
test_match_unknown_xdg_schema_without_schema_unlocked (Test *test,
                                                       gconstpointer unused)
{
	GkmCredential *cred;
	CK_RV rv;

	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "xdg:schema\0org.gnome.Unknown\0", 29 },
	        { CKA_G_COLLECTION, "test-collection", 15 },
	};

	/* Unlock the collection */
	rv = gkm_credential_create (test->module, gkm_session_get_manager (test->session),
	                            GKM_OBJECT (test->collection), (CK_UTF8CHAR_PTR)"booo", 4, &cred);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	g_assert_cmpint (count_number_of_matched (test, attrs, 2), ==, 0);

	g_object_unref (cred);
}

static void
test_match_unknown_xdg_schema_without_schema_locked (Test *test,
                                                     gconstpointer unused)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "xdg:schema\0org.gnome.Unknown\0", 29 },
	        { CKA_G_COLLECTION, "test-collection", 15 },
	};

	g_assert_cmpint (count_number_of_matched (test, attrs, 2), ==, 0);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/secret-store/schema/network-xdg-schema-without-schema-unlocked",
	            Test, NULL, setup, test_match_network_xdg_schema_without_schema_unlocked, teardown);
	g_test_add ("/secret-store/schema/network-xdg-schema-without-schema-locked",
	            Test, NULL, setup, test_match_network_xdg_schema_without_schema_locked, teardown);
	g_test_add ("/secret-store/schema/note-xdg-schema-without-schema-unlocked",
	            Test, NULL, setup, test_match_note_xdg_schema_without_schema_unlocked, teardown);
	g_test_add ("/secret-store/schema/note-xdg-schema-without-schema-locked",
	            Test, NULL, setup, test_match_note_xdg_schema_without_schema_locked, teardown);
	g_test_add ("/secret-store/schema/unknown-schema-without-schema-unlocked",
	            Test, NULL, setup, test_match_unknown_xdg_schema_without_schema_unlocked, teardown);
	g_test_add ("/secret-store/schema/unknown-schema-without-schema-locked",
	            Test, NULL, setup, test_match_unknown_xdg_schema_without_schema_locked, teardown);

	return g_test_run ();
}
