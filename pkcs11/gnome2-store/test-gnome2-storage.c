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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "mock-gnome2-module.h"

#include "gnome2-store/gkm-gnome2-storage.h"

#include "gkm/gkm-certificate.h"
#include "gkm/gkm-module.h"
#include "gkm/gkm-serializable.h"
#include "gkm/gkm-test.h"

#include "egg/egg-libgcrypt.h"
#include "egg/egg-testing.h"

#include <glib/gstdio.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
	gchar *directory;
	GkmModule *module;
	GkmGnome2Storage *storage;
	GkmObject *new_object;
	gchar *new_filename;
	GkmObject *old_object;
} Test;

#define MSEC(x) ((x) * 1000)

static void
setup_directory (Test *test,
                 gconstpointer unused)
{
	test->directory = egg_tests_create_scratch_directory (
		SRCDIR "/pkcs11/gnome2-store/fixtures/Thawte_Personal_Premium_CA.cer",
		SRCDIR "/pkcs11/gnome2-store/fixtures/user.keystore",
		NULL);
}

static void
setup_module (Test *test,
              gconstpointer unused)
{
	CK_ATTRIBUTE url = { CKA_URL, NULL, 0 };
	gchar *contents;
	gsize length;
	GBytes *bytes;
	GkmManager *manager;
	GError *error = NULL;
	GkmSession *session;
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS klass;
	CK_RV rv;

	g_assert (test->directory != NULL);

	test->module = mock_gnome2_module_initialize_and_enter ();
	manager = gkm_module_get_manager (test->module);
	session = mock_gnome2_module_open_session (TRUE);

	test->storage = gkm_gnome2_storage_new (test->module, test->directory);
	rv = gkm_gnome2_storage_refresh (test->storage);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	g_object_add_weak_pointer (G_OBJECT (test->storage), (gpointer *)&test->storage);

	/* We already have the CKA_LABEL attribute */
	gkm_store_register_schema (GKM_STORE (test->storage), &url, NULL, 0);

	/*
	 * Create a new object that hasn't yet been stored in the storage.
	 * It's a certificate because that's easiest.
	 */
	test->new_object = g_object_new (GKM_TYPE_CERTIFICATE,
	                                 "unique", "test.cer",
	                                 "module", test->module,
	                                 "manager", manager,
	                                 NULL);
	g_file_get_contents (SRCDIR "/pkcs11/gnome2-store/fixtures/test-certificate.cer", &contents, &length, &error);
	g_assert_no_error (error);

	bytes = g_bytes_new_take (contents, length);
	if (!gkm_serializable_load (GKM_SERIALIZABLE (test->new_object), NULL, bytes))
		g_assert_not_reached ();
	g_bytes_unref (bytes);

	/* We happen to know this certificate will get named */
	test->new_filename = g_build_filename (test->directory, "CA_Cert_Signing_Authority.cer", NULL);

	/*
	 * Find the object stored in the storage, it's a certificate, and we happen to
	 * know there's only one
	 */
	klass = CKO_CERTIFICATE;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	test->old_object = gkm_manager_find_one_by_attributes (manager, session, &attr, 1);
	g_assert (GKM_IS_OBJECT (test->old_object));
	g_object_ref (test->old_object);
}

static void
setup_all (Test *test,
           gconstpointer unused)
{
	setup_directory (test, unused);
	setup_module (test, unused);
}

static void
teardown_directory (Test *test,
                    gconstpointer unused)
{
	egg_tests_remove_scratch_directory (test->directory);
	g_free (test->directory);
}

static void
teardown_module (Test *test,
                 gconstpointer unused)
{
	g_assert (test->directory);

	g_object_unref (test->new_object);
	g_object_unref (test->old_object);
	g_object_unref (test->storage);
	g_assert (test->storage == NULL);

	mock_gnome2_module_leave_and_finalize ();

	g_free (test->new_filename);
}

static void
teardown_all (Test *test,
              gconstpointer unused)
{
	teardown_module (test, unused);
	teardown_directory (test, unused);
}

static void
test_create (Test *test,
             gconstpointer unused)
{
	GkmTransaction *transaction;

	transaction = gkm_transaction_new ();

	gkm_gnome2_storage_create (test->storage, transaction, test->new_object);
	gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

	gkm_transaction_complete_and_unref (transaction);

	g_assert (g_file_test (test->new_filename, G_FILE_TEST_EXISTS));
}

static void
test_create_and_fail (Test *test,
                      gconstpointer unused)
{
	GkmTransaction *transaction;

	transaction = gkm_transaction_new ();

	gkm_gnome2_storage_create (test->storage, transaction, test->new_object);
	gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

	gkm_transaction_fail (transaction, CKR_FUNCTION_FAILED);
	gkm_transaction_complete_and_unref (transaction);

	g_assert (!g_file_test (test->new_filename, G_FILE_TEST_EXISTS));
}

static void
test_write_value (Test *test,
                  gconstpointer unused)
{
	CK_ATTRIBUTE label = { CKA_LABEL, "Hello", 5 };
	CK_ATTRIBUTE url = { CKA_URL, "http://example.com", 18 };
	GkmTransaction *transaction;
	gchar *string;

	transaction = gkm_transaction_new ();

	gkm_store_write_value (GKM_STORE (test->storage), transaction,
	                       test->old_object, &label);
	gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

	gkm_store_write_value (GKM_STORE (test->storage), transaction,
	                       test->old_object, &url);
	gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

	gkm_transaction_complete_and_unref (transaction);

	string = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_URL);
	g_assert_cmpstr (string, ==, "http://example.com");
	g_free (string);

	string = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_LABEL);
	g_assert_cmpstr (string, ==, "Hello");
	g_free (string);

}

static void
test_locking_transaction (Test *test,
                          gconstpointer unused)
{
	guint iterations = 30;
	guint i;
	pid_t pid;

	/* Fork before setting up the model, as it may start threads */
	pid = fork ();
	g_assert (pid >= 0);

	/*
	 * This is the child. It initializes, writes a value, waits 100 ms,
	 * writes a second value, and then writes another value.
	 */
	if (pid == 0) {
		CK_ATTRIBUTE attr;
		GkmTransaction *transaction;
		gchar *string;

		setup_module (test, unused);

		for (i = 0; i < iterations; i++) {
			g_printerr ("c");

			transaction = gkm_transaction_new ();

			string = g_strdup_printf ("%d", i);

			attr.type = CKA_LABEL;
			attr.pValue = string;
			attr.ulValueLen = strlen (string);

			gkm_store_write_value (GKM_STORE (test->storage), transaction,
			                       test->old_object, &attr);
			gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

			g_usleep (100 * 1000);

			attr.type = CKA_URL;
			attr.pValue = string;
			attr.ulValueLen = strlen (string);

			gkm_store_write_value (GKM_STORE (test->storage), transaction,
			                       test->old_object, &attr);
			gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

			g_free (string);

			gkm_transaction_complete_and_unref (transaction);

			g_usleep (10 * 1000);
		}

		teardown_module (test, unused);
		_exit (0);
		g_assert_not_reached ();

	/*
	 * This is the parent. it initializes, waits 100 ms, writes a value that
	 * should override the one from the child, because the file is locked
	 * when it tries to write, so it waits for the child to finish. The other
	 * attribute from the child (the label) should come through.
	 */
	} else {
		gchar *string1;
		gchar *string2;
		pid_t wpid;
		int status;
		CK_RV rv;

		g_assert (pid != -1);

		setup_module (test, unused);

		for (i = 0; i < iterations; i++) {
			g_printerr ("p");

			string1 = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_URL);

			g_usleep (g_random_int_range (1, 200) * 1000);

			string2 = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_LABEL);

			g_assert_cmpstr (string1, ==, string2);
			g_free (string1);
			g_free (string2);

			rv = gkm_gnome2_storage_refresh (test->storage);
			gkm_assert_cmprv (rv, ==, CKR_OK);
		}

		/* wait for the child to finish */
		wpid = waitpid (pid, &status, 0);
		g_assert_cmpint (wpid, ==, pid);
		g_assert_cmpint (status, ==, 0);

		teardown_module (test, unused);
	}
}

static void
test_lock_writes (Test *test,
                  gconstpointer unused)
{
	pid_t pid;

	/* Fork before setting up the model, as it may start threads */
	pid = fork ();
	g_assert (pid >= 0);

	/*
	 * This is the child. It initializes, writes a value, waits 100 ms,
	 * writes a second value, and then writes another value.
	 */
	if (pid == 0) {
		CK_ATTRIBUTE label = { CKA_LABEL, "Hello from child", 16 };
		CK_ATTRIBUTE url = { CKA_URL, "http://child.example.com", 24 };
		GkmTransaction *transaction;

		setup_module (test, unused);

		transaction = gkm_transaction_new ();

		gkm_store_write_value (GKM_STORE (test->storage), transaction,
		                       test->old_object, &label);
		gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

		g_usleep (MSEC (100));

		gkm_store_write_value (GKM_STORE (test->storage), transaction,
		                       test->old_object, &url);
		gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

		gkm_transaction_complete_and_unref (transaction);

		teardown_module (test, unused);
		_exit (0);
		g_assert_not_reached ();

	/*
	 * This is the parent. it initializes, waits 100 ms, writes a value that
	 * should override the one from the child, because the file is locked
	 * when it tries to write, so it waits for the child to finish. The other
	 * attribute from the child (the label) should come through.
	 */
	} else {
		CK_ATTRIBUTE url = { CKA_URL, "http://parent.example.com", 25 };
		GkmTransaction *transaction;
		gchar *string;
		pid_t wpid;
		int status;
		CK_RV rv;

		g_assert (pid != -1);

		setup_module (test, unused);

		/* Refresh the store, and check values are not set */
		string = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_URL);
		g_assert (string == NULL);

		string = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_LABEL);
		g_assert (string == NULL);

		g_usleep (MSEC (1000));

		transaction = gkm_transaction_new ();

		gkm_store_write_value (GKM_STORE (test->storage), transaction,
		                       test->old_object, &url);
		gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

		/* wait for the child to finish */
		wpid = waitpid (pid, &status, 0);
		g_assert_cmpint (wpid, ==, pid);
		g_assert_cmpint (status, ==, 0);

		gkm_transaction_complete_and_unref (transaction);

		g_usleep (MSEC (1000));

		rv = gkm_gnome2_storage_refresh (test->storage);
		gkm_assert_cmprv (rv, ==, CKR_OK);

		string = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_URL);
		g_assert_cmpstr (string, ==, "http://parent.example.com");
		g_free (string);

		string = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_LABEL);
		g_assert_cmpstr (string, ==, "Hello from child");
		g_free (string);

		teardown_module (test, unused);
	}
}

static void
test_relock (Test *test,
             gconstpointer unused)
{
	GkmTransaction *transaction;
	GkmSecret *old_login;
	GkmSecret *new_login;

	transaction = gkm_transaction_new ();

	old_login = NULL;
	new_login = gkm_secret_new_from_password ("blah");

	gkm_gnome2_storage_relock (test->storage, transaction, old_login, new_login);
	gkm_assert_cmprv (gkm_transaction_complete_and_unref (transaction), ==, CKR_OK);

	g_object_unref (new_login);
}

static void
null_log_handler (const gchar *log_domain,
                  GLogLevelFlags log_level,
                  const gchar *message,
                  gpointer user_data)
{

}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	egg_libgcrypt_initialize ();

	/* Suppress these messages in tests */
	g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                   null_log_handler, NULL);

	g_test_add ("/gnome2-store/storage/create", Test, NULL,
	            setup_all, test_create, teardown_all);
	g_test_add ("/gnome2-store/storage/create_and_fail", Test, NULL,
	            setup_all, test_create_and_fail, teardown_all);
	g_test_add ("/gnome2-store/storage/write_value", Test, NULL,
	            setup_all, test_write_value, teardown_all);
	g_test_add ("/gnome2-store/storage/relock", Test, NULL,
	            setup_all, test_relock, teardown_all);

	if (!g_test_quick ()) {
		g_test_add ("/gnome2-store/storage/locking_transaction", Test, NULL,
		            setup_directory, test_locking_transaction, teardown_directory);
		g_test_add ("/gnome2-store/storage/lock_writes", Test, NULL,
		            setup_directory, test_lock_writes, teardown_directory);
	}

	return g_test_run ();
}
