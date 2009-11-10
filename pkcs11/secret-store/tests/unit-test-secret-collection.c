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
#include "gck-secret-item.h"

#include "gck/gck-credential.h"
#include "gck/gck-session.h"
#include "gck/gck-transaction.h"

#include "pkcs11/pkcs11i.h"

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
	GckCredential *cred;
	GckSecretData *sdata;
	CK_RV rv;

	/* Create credential, which unlocks collection */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session), NULL, 0, &cred);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (cred));
	g_object_unref (cred);

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

DEFINE_TEST(secret_collection_has_item)
{
	GckSecretItem *item;

	item = gck_secret_collection_new_item (collection, "testo");
	g_assert (gck_secret_collection_has_item (collection, item));
}

DEFINE_TEST(secret_collection_load_unlock_plain)
{
	GckCredential *cred;
	GckSecretData *sdata;
	GckDataResult res;
	gchar *filename;
	CK_RV rv;

	filename = test_data_filename ("plain.keyring");
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session), NULL, 0, &cred);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (cred));
	g_object_unref (cred);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_load_unlock_encrypted)
{
	GckCredential *cred;
	GckSecretData *sdata;
	GckDataResult res;
	gchar *filename;
	CK_RV rv;

	filename = test_data_filename ("encrypted.keyring");
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                            (guchar*)"my-keyring-password", 19, &cred);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (cred));
	g_object_unref (cred);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_load_unlock_bad_password)
{
	GckCredential *cred;
	GckDataResult res;
	gchar *filename;
	CK_RV rv;

	filename = test_data_filename ("encrypted.keyring");
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                            (guchar*)"wrong", 5, &cred);
	g_assert (rv == CKR_PIN_INCORRECT);
}

DEFINE_TEST(secret_collection_unlock_without_load)
{
	GckCredential *cred;
	GckSecretData *sdata;
	gchar *filename;
	CK_RV rv;

	filename = test_data_filename ("encrypted.keyring");
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Unlock the keyring, which should load it */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                            (guchar*)"my-keyring-password", 19, &cred);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (cred));
	g_object_unref (cred);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_twice_unlock)
{
	GckCredential *cred;
	GckSecretData *sdata;
	gchar *filename;
	CK_RV rv;

	filename = test_data_filename ("encrypted.keyring");
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Unlock the keyring, which should load */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                            (guchar*)"my-keyring-password", 19, &cred);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (cred));
	g_object_unref (cred);

	/* Unlock the keyring again, which should not reload */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                            (guchar*)"my-keyring-password", 19, &cred);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (cred));
	g_object_unref (cred);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_twice_unlock_bad_password)
{
	GckCredential *cred;
	GckSecretData *sdata;
	gchar *filename;
	CK_RV rv;

	filename = test_data_filename ("encrypted.keyring");
	gck_secret_collection_set_filename (collection, filename);
	g_free (filename);

	/* Unlock the keyring, which should load */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                               (guchar*)"my-keyring-password", 19, &cred);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (cred));
	g_object_unref (cred);

	/* Unlock the keyring again, wrong password */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                            (guchar*)"wrong", 5, &cred);
	g_assert (rv == CKR_PIN_INCORRECT);

	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (sdata != NULL && GCK_IS_SECRET_DATA (sdata));
	test_secret_collection_validate (collection, sdata);
}

DEFINE_TEST(secret_collection_memory_unlock)
{
	GckCredential *cred;
	GckDataResult res;
	CK_RV rv;

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                            NULL, 0, &cred);
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (cred));
	g_object_unref (cred);
}

DEFINE_TEST(secret_collection_memory_unlock_bad_password)
{
	GckCredential *cred;
	GckDataResult res;
	CK_RV rv;

	/* Load the data in the file */
	res = gck_secret_collection_load (collection);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Unlock the keyring, which should load again */
	rv = gck_credential_create (GCK_OBJECT (collection), gck_session_get_manager (session),
	                            (guchar*)"wrong", 5, &cred);
	g_assert (rv == CKR_PIN_INCORRECT);
}

DEFINE_TEST(secret_collection_factory)
{
	CK_OBJECT_CLASS klass = CKO_G_COLLECTION;
	GckObject *object;
	CK_RV rv;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_LABEL, "blah", 4 },
	};

	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_COLLECTION,
	                                            attrs, G_N_ELEMENTS (attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_COLLECTION (object));

	g_assert_cmpstr (gck_secret_object_get_label (GCK_SECRET_OBJECT (object)), ==, "blah");
}

DEFINE_TEST(secret_collection_factory_unnamed)
{
	CK_OBJECT_CLASS klass = CKO_G_COLLECTION;
	const gchar *identifier;
	GckObject *object;
	CK_RV rv;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
	};

	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_COLLECTION,
	                                            attrs, G_N_ELEMENTS (attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_COLLECTION (object));

	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (object));
	g_assert_cmpstr (identifier, !=, "");
}

DEFINE_TEST(secret_collection_factory_token)
{
	CK_OBJECT_CLASS klass = CKO_G_COLLECTION;
	const gchar *identifier;
	GckObject *object;
	CK_BBOOL token = CK_TRUE;
	CK_RV rv;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_LABEL, "blah", 4 },
	};

	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_COLLECTION,
	                                            attrs, G_N_ELEMENTS (attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_COLLECTION (object));

	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (object));
	g_assert (strstr (identifier, "blah"));
}

DEFINE_TEST(secret_collection_factory_duplicate)
{
	CK_OBJECT_CLASS klass = CKO_G_COLLECTION;
	const gchar *identifier1, *identifier2;
	GckObject *object;
	CK_RV rv;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_LABEL, "blah", 4 },
	};

	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_COLLECTION,
	                                            attrs, G_N_ELEMENTS (attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_COLLECTION (object));

	identifier1 = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (object));
	g_assert (strstr (identifier1, "blah"));

	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_COLLECTION,
	                                            attrs, G_N_ELEMENTS (attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_COLLECTION (object));

	identifier2 = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (object));
	g_assert (strstr (identifier2, "blah"));

	g_assert_cmpstr (identifier1, !=, identifier2);
}

DEFINE_TEST(secret_collection_factory_item)
{
	CK_OBJECT_CLASS c_klass = CKO_G_COLLECTION;
	CK_OBJECT_CLASS i_klass = CKO_SECRET_KEY;
	const gchar *identifier;
	GckObject *object;
	CK_BBOOL token = CK_TRUE;
	CK_RV rv;

	CK_ATTRIBUTE c_attrs[] = {
		{ CKA_CLASS, &c_klass, sizeof (c_klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_LABEL, "three", 5 },
	};

	CK_ATTRIBUTE i_attrs[] = {
		{ CKA_G_COLLECTION, NULL, 0 }, /* Filled below */
		{ CKA_CLASS, &i_klass, sizeof (i_klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_LABEL, "Item", 4 },
	};

	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_COLLECTION,
	                                            c_attrs, G_N_ELEMENTS (c_attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_COLLECTION (object));

	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (object));
	i_attrs[0].pValue = (gpointer)identifier;
	i_attrs[0].ulValueLen = strlen (identifier);
	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_ITEM,
	                                            i_attrs, G_N_ELEMENTS (i_attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_ITEM (object));
}

DEFINE_TEST(secret_collection_token_remove)
{
	CK_OBJECT_CLASS klass = CKO_G_COLLECTION;
	GckTransaction *transaction;
	GckObject *object;
	CK_BBOOL token = CK_TRUE;
	CK_RV rv;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_LABEL, "blah", 4 },
	};

	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_COLLECTION,
	                                            attrs, G_N_ELEMENTS (attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_COLLECTION (object));

	transaction = gck_transaction_new ();
	gck_module_remove_token_object (module, transaction, object);
	g_assert (!gck_transaction_get_failed (transaction));
	gck_transaction_complete (transaction);
	g_object_unref (transaction);
}

DEFINE_TEST(secret_collection_token_item_remove)
{
	CK_OBJECT_CLASS c_klass = CKO_G_COLLECTION;
	CK_OBJECT_CLASS i_klass = CKO_SECRET_KEY;
	GckTransaction *transaction;
	const gchar *identifier;
	GckObject *object;
	CK_BBOOL token = CK_TRUE;
	CK_RV rv;

	CK_ATTRIBUTE c_attrs[] = {
		{ CKA_CLASS, &c_klass, sizeof (c_klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_LABEL, "three", 5 },
	};

	CK_ATTRIBUTE i_attrs[] = {
		{ CKA_G_COLLECTION, NULL, 0 }, /* Filled below */
		{ CKA_CLASS, &i_klass, sizeof (i_klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_LABEL, "Item", 4 },
	};

	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_COLLECTION,
	                                            c_attrs, G_N_ELEMENTS (c_attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_COLLECTION (object));

	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (object));
	i_attrs[0].pValue = (gpointer)identifier;
	i_attrs[0].ulValueLen = strlen (identifier);
	rv = gck_session_create_object_for_factory (session, GCK_FACTORY_SECRET_ITEM,
	                                            i_attrs, G_N_ELEMENTS (i_attrs), &object);
	g_assert (rv == CKR_OK);
	g_assert (GCK_IS_SECRET_ITEM (object));

	transaction = gck_transaction_new ();
	gck_module_remove_token_object (module, transaction, object);
	g_assert (!gck_transaction_get_failed (transaction));
	gck_transaction_complete (transaction);
	g_object_unref (transaction);
}
