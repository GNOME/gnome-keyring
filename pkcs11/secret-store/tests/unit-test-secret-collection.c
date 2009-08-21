/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-secret-collection.c: Test the collection keyring

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

#include "config.h"

#include "run-auto-test.h"
#include "test-secret-module.h"

#include "gck-secret-data.h"
#include "gck-secret-collection.h"

#include "gck/gck-authenticator.h"
#include "gck/gck-session.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static GckModule *module = NULL;
static GckSession *session = NULL;
static GckSecretCollection *collection = NULL;

DEFINE_SETUP(secret_collection)
{
	module = test_secret_module_initialize_and_enter ();
	session = test_secret_module_open_session (TRUE);

	collection = g_object_new (GCK_TYPE_SECRET_COLLECTION,
	                           "module", module,
	                           "identifier", "test",
	                           NULL);

	g_assert (GCK_IS_SECRET_COLLECTION (collection));
}

DEFINE_TEARDOWN(secret_collection)
{
	if (collection)
		g_object_unref (collection);
	collection = NULL;

	test_secret_module_leave_and_finalize ();
	module = NULL;
	session = NULL;

}

DEFINE_TEST(secret_collection_is_locked)
{
	gboolean locked;

	/* By default is locked */
	locked = gck_secret_object_is_locked (GCK_SECRET_OBJECT (collection), session);
	g_assert (locked == TRUE);
}

DEFINE_TEST(secret_collection_unlocked_data)
{
	GckAuthenticator *auth;
	GckSecretData *sdata;
	CK_RV rv;

	/* Create authenticator, which unlocks collection */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session), NULL, 0, &auth); 
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (auth));
	g_object_unref (auth);

	/* Collection should now be unlocked */
	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (GCK_IS_SECRET_DATA (sdata));
	g_assert (!gck_secret_object_is_locked (GCK_SECRET_OBJECT (collection), session));
}

DEFINE_TEST(secret_collection_get_filename)
{
	GckSecretCollection *other;
	const gchar *filename;

	other = g_object_new (GCK_TYPE_SECRET_COLLECTION,
	                      "module", module,
	                      "identifier", "test",
	                      "filename", "/tmp/filename.keyring",
	                      NULL);

	filename = gck_secret_collection_get_filename (other);
	g_assert_cmpstr (filename, ==, "/tmp/filename.keyring");

	g_object_unref (other);
}

DEFINE_TEST(secret_collection_set_filename)
{
	const gchar *filename;

	gck_secret_collection_set_filename (collection, "/tmp/filename.keyring");

	filename = gck_secret_collection_get_filename (collection);
	g_assert_cmpstr (filename, ==, "/tmp/filename.keyring");
}

DEFINE_TEST(secret_collection_load_unlock_plain)
{
	GckAuthenticator *auth;
	GckSecretData *sdata;
	GckDataResult res;
	gchar *filename;
	CK_RV rv;

	filename = g_build_filename (test_dir_testdata (), "plain.keyring", NULL);
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session), NULL, 0, &auth);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (auth));
	g_object_unref (auth);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_load_unlock_encrypted)
{
	GckAuthenticator *auth;
	GckSecretData *sdata;
	GckDataResult res;
	gchar *filename;
	CK_RV rv;

	filename = g_build_filename (test_dir_testdata (), "encrypted.keyring", NULL);
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session), 
	                               (guchar*)"my-keyring-password", 19, &auth);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (auth));
	g_object_unref (auth);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_load_unlock_bad_password)
{
	GckAuthenticator *auth;
	GckDataResult res;
	gchar *filename;
	CK_RV rv;

	filename = g_build_filename (test_dir_testdata (), "encrypted.keyring", NULL);
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session), 
	                               (guchar*)"wrong", 5, &auth);
	g_assert (rv == CKR_PIN_INCORRECT);
}

DEFINE_TEST(secret_collection_unlock_without_load)
{
	GckAuthenticator *auth;
	GckSecretData *sdata;
	gchar *filename;
	CK_RV rv;

	filename = g_build_filename (test_dir_testdata (), "encrypted.keyring", NULL);
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Unlock the keyring, which should load it */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session), 
	                               (guchar*)"my-keyring-password", 19, &auth);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (auth));
	g_object_unref (auth);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_twice_unlock)
{
	GckAuthenticator *auth;
	GckSecretData *sdata;
	gchar *filename;
	CK_RV rv;

	filename = g_build_filename (test_dir_testdata (), "encrypted.keyring", NULL);
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Unlock the keyring, which should load */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session), 
	                               (guchar*)"my-keyring-password", 19, &auth);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (auth));
	g_object_unref (auth);

	/* Unlock the keyring again, which should not reload */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session), 
	                               (guchar*)"my-keyring-password", 19, &auth);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (auth));
	g_object_unref (auth);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_twice_unlock_bad_password)
{
	GckAuthenticator *auth;
	GckSecretData *sdata;
	gchar *filename;
	CK_RV rv;

	filename = g_build_filename (test_dir_testdata (), "encrypted.keyring", NULL);
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Unlock the keyring, which should load */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                               (guchar*)"my-keyring-password", 19, &auth);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (auth));
	g_object_unref (auth);

	/* Unlock the keyring again, wrong password */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                               (guchar*)"wrong", 5, &auth);
	g_assert (rv == CKR_PIN_INCORRECT);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_memory_unlock)
{
	GckAuthenticator *auth;
	GckDataResult res;
	CK_RV rv;

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                               NULL, 0, &auth);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (auth));
	g_object_unref (auth);
}

DEFINE_TEST(secret_collection_memory_unlock_bad_password)
{
	GckAuthenticator *auth;
	GckDataResult res;
	CK_RV rv;

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_authenticator_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                               (guchar*)"wrong", 5, &auth);
	g_assert (rv == CKR_PIN_INCORRECT);
}
