/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-file-store.c: Test file store functionality

   Copyright (C) 2008 Stefan Walter

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

#include "gck/gck-file-store.h"
#include "gck/gck-object.h"
#include "gck/gck-transaction.h"

/* Both point to the same thing */
static GckStore *store = NULL;
static GckFileStore *file_store = NULL;
static GckTransaction *transaction = NULL;
static GckObject *object = NULL;
static GckObject *prv_object = NULL;
static gchar *test_filename = NULL;

static void
copy_file (const gchar *from, const gchar *to)
{
	gchar *contents;
	gsize length;
	gboolean ret;
	
	ret = g_file_get_contents (from, &contents, &length, NULL);
	g_assert (ret == TRUE);
	ret = g_file_set_contents (to, contents, length, NULL);
	g_assert (ret == TRUE);
	g_free (contents);
}

DEFINE_SETUP(file_store)
{
	CK_ATTRIBUTE attr;
	CK_ULONG twentyfour = 24;
	
	test_filename = test_build_filename ("unit-test-file-store");

	copy_file ("./test-data/test-file-store.store", test_filename);
	file_store = gck_file_store_new (test_filename);
	store = GCK_STORE (file_store);

	attr.type = CKA_LABEL;
	attr.pValue = "label";
	attr.ulValueLen = 5;
	
	gck_store_register_schema (store, &attr, NULL, 0);
	g_assert (gck_store_lookup_schema (store, CKA_LABEL, NULL));

	attr.type = CKA_VALUE;
	attr.pValue = NULL;
	attr.ulValueLen = 0;
	
	gck_store_register_schema (store, &attr, NULL, GCK_STORE_IS_SENSITIVE);
	
	attr.type = CKA_BITS_PER_PIXEL;
	attr.pValue = &twentyfour;
	attr.ulValueLen = sizeof (twentyfour);
	
	gck_store_register_schema (store, &attr, NULL, GCK_STORE_IS_INTERNAL);
	
	transaction = gck_transaction_new ();
	object = g_object_new (GCK_TYPE_OBJECT, NULL);
	prv_object = g_object_new (GCK_TYPE_OBJECT, NULL);
	
	gck_file_store_connect_entry (file_store, "unique-one", object);
	gck_file_store_connect_entry (file_store, "unique-private", prv_object);
}

DEFINE_TEARDOWN(file_store)
{
	g_free (test_filename);
	
	gck_file_store_disconnect_entry (file_store, "unique-private", prv_object);
	
	if (prv_object != NULL)
		g_object_unref (prv_object);
	prv_object = NULL;

	g_object_unref (file_store);
	file_store = NULL;
	store = NULL;
	
	g_object_unref (transaction);
	transaction = NULL;
	
	if (object != NULL)
		g_object_unref (object);
	object = NULL;
}

DEFINE_TEST(test_properties)
{
	const gchar *filename;
	gboolean locked;
	gchar *name;
		
	filename = gck_file_store_get_filename (file_store);
	g_assert_cmpstr (filename, ==, test_filename);
	
	locked = gck_file_store_get_locked (file_store);
	g_assert (locked == TRUE);
	
	/* Try properties */
	locked = FALSE;
	g_object_get (file_store, "filename", &name, "locked", &locked, NULL);
	g_assert_cmpstr (name, ==, test_filename);
	g_assert (locked == TRUE);
}

DEFINE_TEST(test_store_read)
{
	gboolean ret;
	
	ret = gck_file_store_refresh (file_store);
	g_assert (ret);
}

DEFINE_TEST(test_unlock)
{
	gchar *str;
	CK_RV rv;
	
	/* We shouldn't be able to read from private object */
	g_assert (!gck_file_store_have_entry (file_store, "unique-private"));

	/* Try with wrong password */
	rv = gck_file_store_unlock (file_store, (guchar*)"password", 8);
	g_assert (rv == CKR_PIN_INCORRECT);
	g_assert (gck_file_store_get_locked (file_store) == TRUE);

	/* A valid unlock */
	rv = gck_file_store_unlock (file_store, (guchar*)"booo", 4);
	g_assert (rv == CKR_OK);
	g_assert (gck_file_store_get_locked (file_store) == FALSE);

	/* Unlocking twice should result in this code */
	rv = gck_file_store_unlock (file_store, (guchar*)"booo", 4);
	g_assert (rv == CKR_USER_ALREADY_LOGGED_IN);
	g_assert (gck_file_store_get_locked (file_store) == FALSE);

	/* Now we should be able to read from private object */
	g_assert (gck_file_store_have_entry (file_store, "unique-private"));
	str = gck_store_read_string (store, prv_object, CKA_LABEL);
	g_assert_cmpstr (str, ==, "private-label");
	g_free (str);
	
	/* Now lock again */
	rv = gck_file_store_lock (file_store);
	g_assert (rv == CKR_OK);

	/* Locking twice should result in this code */
	rv = gck_file_store_lock (file_store);
	g_assert (rv == CKR_USER_NOT_LOGGED_IN);

	/* We should get default attributes */
	str = gck_store_read_string (store, prv_object, CKA_LABEL);
	g_assert_cmpstr (str, ==, "label");
	g_free (str);
}

DEFINE_TEST(write_encrypted)
{
	CK_ATTRIBUTE attr;
	gboolean ret;
	gchar *str;
	CK_RV rv;
	
	rv = gck_file_store_unlock (file_store, (guchar*)"booo", 4);
	g_assert (rv == CKR_OK);

	attr.type = CKA_LABEL;
	attr.pValue = "private-label-two";
	attr.ulValueLen = 17;
	
	gck_store_set_attribute (store, transaction, prv_object, &attr);
	
	gck_transaction_complete (transaction);
	g_assert (gck_transaction_get_result (transaction) == CKR_OK);
	
	ret = gck_file_store_refresh (file_store);
	g_assert (ret);
	
	str = gck_store_read_string (store, prv_object, CKA_LABEL);
	g_assert_cmpstr (str, ==, "private-label-two");
	g_free (str);
}

DEFINE_TEST(file_set_get_attribute)
{
	gchar buffer[16];
	CK_ATTRIBUTE attr;
	CK_RV rv;
	
	attr.type = CKA_LABEL;
	attr.pValue = "booyah";
	attr.ulValueLen = 6;
	
	gck_store_set_attribute (store, transaction, object, &attr);
	
	gck_transaction_complete (transaction);
	g_assert (gck_transaction_get_result (transaction) == CKR_OK);
	
	attr.pValue = buffer;
	attr.ulValueLen = 7;
	rv = gck_store_get_attribute (store, object, &attr);
	g_assert (rv == CKR_OK);
	g_assert (attr.ulValueLen == 6);
	g_assert (memcmp (attr.pValue, "booyah", 6) == 0);
}

DEFINE_TEST(file_write_read_value)
{
	CK_ATTRIBUTE attr;
	CK_ULONG five = 5;
	gconstpointer value;
	gsize n_value;
	
	attr.type = CKA_BITS_PER_PIXEL;
	attr.pValue = &five;
	attr.ulValueLen = sizeof (five);
	
	gck_store_write_value (store, transaction, object, &attr);

	gck_transaction_complete (transaction);
	g_assert (gck_transaction_get_result (transaction) == CKR_OK);

	value = gck_store_read_value (store, object, CKA_BITS_PER_PIXEL, &n_value);
	g_assert (value);
	g_assert (n_value == sizeof (five));
	g_assert (memcmp (value, &five, sizeof (five)) == 0);
}

DEFINE_TEST(destroy_entry)
{
	gboolean ret;
	gchar *str;
	
	str = gck_store_read_string (store, object, CKA_LABEL);
	g_assert_cmpstr (str, ==, "public-label");
	g_free (str);

	gck_file_store_destroy_entry (file_store, transaction, "unique-one");
	gck_transaction_complete (transaction);
	
	g_assert (gck_transaction_get_result (transaction) == CKR_OK);
	g_assert (!gck_transaction_get_failed (transaction));
	
	ret = gck_file_store_refresh (file_store);
	g_assert (ret);
	
	str = gck_store_read_string (store, object, CKA_LABEL);
	g_assert_cmpstr (str, ==, "label");
	g_free (str);
}

DEFINE_TEST(refresh_modifications)
{
	GckFileStore *fs;
	gboolean ret;
	gchar *str;

	/* Check that our label is correct */
	str = gck_store_read_string (store, object, CKA_LABEL);
	g_assert_cmpstr (str, ==, "public-label");
	g_free (str);

	/* Open a second file store on the same file */
	fs = gck_file_store_new (test_filename);
	ret = gck_file_store_refresh (fs);
	g_assert (ret);
	
	/* Delete something from other store */
	gck_file_store_destroy_entry (fs, transaction, "unique-one");
	gck_transaction_complete (transaction);
	g_assert (gck_transaction_get_result (transaction) == CKR_OK);
	g_assert (!gck_transaction_get_failed (transaction));

	/* Refresh first file store */
	ret = gck_file_store_refresh (file_store);
	g_assert (ret);
	
	/* Should be gone, we should see default label */
	str = gck_store_read_string (store, object, CKA_LABEL);
	g_assert_cmpstr (str, ==, "label");
	g_free (str);
	
	g_object_unref (fs);
}

DEFINE_TEST(file_store_revert_first)
{
	CK_ATTRIBUTE attr, prev;
	gconstpointer value;
	gsize n_value;
	
	prev.type = CKA_LABEL;
	prev.pValue = "numberone";
	prev.ulValueLen = 9;

	/* Change the attribute */
	gck_store_set_attribute (store, transaction, object, &prev);
	gck_transaction_complete (transaction);
	g_assert (gck_transaction_get_failed (transaction) == FALSE);

	/* Value should be new value */
	value = gck_store_read_value (store, object, CKA_LABEL, &n_value);
	g_assert (value && n_value == prev.ulValueLen);
	g_assert (memcmp (prev.pValue, value, n_value) == 0);

	/* A new transaction */
	g_object_unref (transaction);
	transaction = gck_transaction_new ();

	attr.type = CKA_LABEL;
	attr.pValue = "second";
	attr.ulValueLen = 6;

	gck_store_set_attribute (store, transaction, object, &attr);
	g_assert (gck_transaction_get_failed (transaction) == FALSE);

	/* Should get new value */
	value = gck_store_read_value (store, object, CKA_LABEL, &n_value);
	g_assert (value && n_value == attr.ulValueLen);
	g_assert (memcmp (attr.pValue, value, n_value) == 0);

	attr.type = CKA_LABEL;
	attr.pValue = "third";
	attr.ulValueLen = 5;

	gck_store_set_attribute (store, transaction, object, &attr);
	g_assert (gck_transaction_get_failed (transaction) == FALSE);

	/* Should get new value */
	value = gck_store_read_value (store, object, CKA_LABEL, &n_value);
	g_assert (value && n_value == attr.ulValueLen);
	g_assert (memcmp (attr.pValue, value, n_value) == 0);
	
	/* Fail for some arbitrary reason */
	gck_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
	
	/* Value should not have changed yet */
	value = gck_store_read_value (store, object, CKA_LABEL, &n_value);
	g_assert (value && n_value == attr.ulValueLen);
	g_assert (memcmp (attr.pValue, value, n_value) == 0);
	
	/* Now complete the transaction */
	gck_transaction_complete (transaction);
	g_assert (gck_transaction_get_failed (transaction) == TRUE);

	/* Value should now have changed, back to default */
	value = gck_store_read_value (store, object, CKA_LABEL, &n_value);
	g_assert (value && n_value == prev.ulValueLen);
	g_assert (memcmp (prev.pValue, value, n_value) == 0);
}

DEFINE_TEST(file_store_nonexistant)
{
	GckFileStore *fs;
	gboolean ret;

	/* Should be able to read from a nonexistant file store */
	fs = gck_file_store_new ("./nonexistant");
	ret = gck_file_store_refresh (fs);
	g_assert (ret);
		
	g_object_unref (fs);
}
