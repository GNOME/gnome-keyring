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

#include "config.h"

#include "mock-gnome2-module.h"

#include "gnome2-store/gkm-gnome2-storage.h"

#include "gkm/gkm-certificate.h"
#include "gkm/gkm-module.h"
#include "gkm/gkm-serializable.h"
#include "gkm/gkm-test.h"

#include "egg/egg-libgcrypt.h"
#include "egg/egg-mkdtemp.h"

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

static void
copy_scratch_file (Test *test,
                   const gchar *name)
{
	GError *error = NULL;
	gchar *filename;
	gchar *contents;
	gsize length;

	g_assert (test->directory);

	filename = g_build_filename (SRCDIR, "files", name, NULL);
	g_file_get_contents (filename, &contents, &length, &error);
	g_assert_no_error (error);
	g_free (filename);

	filename = g_build_filename (test->directory, name, NULL);
	g_file_set_contents (filename, contents, length, &error);
	g_assert_no_error (error);
	g_free (filename);
}

static void
setup_directory (Test *test,
                 gconstpointer unused)
{
	test->directory = g_strdup ("/tmp/gkd-test.XXXXXX");
	if (!egg_mkdtemp (test->directory))
		g_assert_not_reached ();

	/* Copy in a valid set of storage data */
	copy_scratch_file (test, "Thawte_Personal_Premium_CA.cer");
	copy_scratch_file (test, "user.keystore");
}

static void
setup_module (Test *test,
              gconstpointer unused)
{
	CK_ATTRIBUTE label = { CKA_LABEL, NULL, 0 };
	CK_ATTRIBUTE url = { CKA_URL, NULL, 0 };
	gchar *contents;
	gsize length;
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

	gkm_store_register_schema (GKM_STORE (test->storage), &url, NULL, 0);
	gkm_store_register_schema (GKM_STORE (test->storage), &label, NULL, 0);

	/*
	 * Create a new object that hasn't yet been stored in the storage.
	 * It's a certificate because that's easiest.
	 */
	test->new_object = g_object_new (GKM_TYPE_CERTIFICATE,
	                                 "unique", "test.cer",
	                                 "module", test->module,
	                                 "manager", manager,
	                                 NULL);
	g_file_get_contents (SRCDIR "/files/test-certificate.cer", &contents, &length, &error);
	g_assert_no_error (error);
	if (!gkm_serializable_load (GKM_SERIALIZABLE (test->new_object), NULL, contents, length))
		g_assert_not_reached ();
	g_free (contents);
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
	GDir *dir;
	GError *error = NULL;
	const gchar *name;
	gchar *filename;

	dir = g_dir_open (test->directory, 0, &error);
	g_assert_no_error (error);

	while ((name = g_dir_read_name (dir)) != NULL) {
		filename = g_build_filename (test->directory, name, NULL);
		if (g_unlink (filename) < 0)
			g_assert_not_reached ();
	}

	g_dir_close (dir);

	if (g_rmdir (test->directory) < 0)
		g_assert_not_reached ();

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
	g_assert (!G_IS_OBJECT (test->storage));

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
test_lock_contention (Test *test,
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
		CK_ATTRIBUTE label = { CKA_LABEL, "Hello", 5 };
		CK_ATTRIBUTE url = { CKA_URL, "http://example.com", 18 };
		GkmTransaction *transaction;

		setup_module (test, unused);

		transaction = gkm_transaction_new ();

		gkm_store_write_value (GKM_STORE (test->storage), transaction,
		                       test->old_object, &label);
		gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

		g_usleep (300 * 1000);

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

		g_assert (pid != -1);

		g_usleep (100 * 1000);

		setup_module (test, unused);

		transaction = gkm_transaction_new ();

		gkm_store_write_value (GKM_STORE (test->storage), transaction,
		                       test->old_object, &url);
		gkm_assert_cmprv (gkm_transaction_get_result (transaction), ==, CKR_OK);

		gkm_transaction_complete_and_unref (transaction);

		/* wait for the child to finish */
		wpid = waitpid (pid, &status, 0);
		g_assert_cmpint (wpid, ==, pid);
		g_assert_cmpint (status, ==, 0);

		string = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_URL);
		g_assert_cmpstr (string, ==, "http://parent.example.com");
		g_free (string);

		string = gkm_store_read_string (GKM_STORE (test->storage), test->old_object, CKA_LABEL);
		g_assert_cmpstr (string, ==, "Hello");
		g_free (string);

		teardown_module (test, unused);
	}
}

int
main (int argc, char **argv)
{
	g_type_init ();
	g_test_init (&argc, &argv, NULL);

	egg_libgcrypt_initialize ();

	g_test_add ("/gnome2-store/storage/create", Test, NULL,
	            setup_all, test_create, teardown_all);
	g_test_add ("/gnome2-store/storage/create_and_fail", Test, NULL,
	            setup_all, test_create_and_fail, teardown_all);
	g_test_add ("/gnome2-store/storage/write_value", Test, NULL,
	            setup_all, test_write_value, teardown_all);

	if (g_test_thorough ())
		g_test_add ("/gnome2-store/storage/lock_contention", Test, NULL,
		            setup_directory, test_lock_contention, teardown_directory);

	return g_test_run ();
}
