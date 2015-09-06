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

#include "egg/egg-testing.h"

#include "gkm/gkm-module.h"
#include "gkm/gkm-test.h"

#include "gnome2-store/gkm-gnome2-store.h"

#include <gck/gck.h>
#include <gcr/gcr-base.h>

#include <p11-kit/p11-kit.h>

#include <glib/gstdio.h>

#include <string.h>

typedef struct {
	CK_FUNCTION_LIST_PTR funcs;
	GList *importers;
	gchar *directory;
} Test;

static void
setup (Test *test,
       gconstpointer unused)
{
	CK_C_INITIALIZE_ARGS args;
	CK_SESSION_HANDLE session;
	GckModule *module;
	GList *modules;
	CK_RV rv;

	test->directory = egg_tests_create_scratch_directory (NULL, NULL);

	memset (&args, 0, sizeof (args));
	args.flags = CKF_OS_LOCKING_OK;
	args.pReserved = g_strdup_printf ("directory='%s'", test->directory);

	test->funcs = gkm_gnome2_store_get_functions ();
	rv = (test->funcs->C_Initialize) (&args);
	g_free (args.pReserved);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* And now need to log in */
	rv = (test->funcs->C_OpenSession) (GKM_SLOT_ID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
	                                   NULL, NULL, &session);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* The directory is empty, so we need to initialize */
	rv = (test->funcs->C_SetPIN) (session, NULL, 0, (CK_BYTE_PTR)"mypin", 5);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Login so the importer doesn't have to */
	rv = (test->funcs->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"mypin", 5);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	module = gck_module_new (test->funcs);
	modules = g_list_prepend (NULL, module);
	gcr_pkcs11_set_modules (modules);
	g_list_free (modules);
	g_object_unref (module);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	CK_RV rv;

	g_list_free_full (test->importers, g_object_unref);

	gcr_pkcs11_set_modules (NULL);

	rv = (test->funcs->C_Finalize) (NULL);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Cleanup the directory */
	egg_tests_remove_scratch_directory (test->directory);
	g_free (test->directory);
}

static void
on_parser_parsed (GcrParser *parser,
                  gpointer user_data)
{
	Test *test = user_data;
	GcrParsed *parsed;
	GList *importers;

	parsed = gcr_parser_get_parsed (parser);

	if (test->importers == NULL)
		importers = gcr_importer_create_for_parsed (parsed);
	else
		importers = gcr_importer_queue_and_filter_for_parsed (test->importers, parsed);

	g_list_free_full (test->importers, g_object_unref);
	test->importers = importers;
}

static void
test_pkcs12_import (Test *test,
                    gconstpointer unused)
{
	GcrParser *parser;
	GError *error;
	gchar *contents;
	gsize length;
	GList *l;

	error = NULL;
	g_file_get_contents (SRCDIR "/pkcs11/gnome2-store/fixtures/personal.p12", &contents, &length, &error);
	g_assert_no_error (error);

	/* Parse the pkcs12 file */
	parser = gcr_parser_new ();
	gcr_parser_add_password (parser, "booo");
	gcr_parser_format_enable (parser, GCR_FORMAT_DER_PKCS12);
	g_signal_connect (parser, "parsed", G_CALLBACK (on_parser_parsed), test);
	gcr_parser_parse_data (parser, (const guchar *)contents, length, &error);
	g_assert_no_error (error);
	g_object_unref (parser);
	g_free (contents);

	/* Should have found importers */
	g_assert (test->importers != NULL);

	for (l = test->importers; l != NULL; l = g_list_next (l)) {
		gcr_importer_import (l->data, NULL, &error);
		g_assert_no_error (error);
	}
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

	g_set_prgname ("test-import");

	/* Suppress these messages in tests */
	g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
	                   null_log_handler, NULL);

	g_test_add ("/gnome2-store/import/pkcs12", Test, NULL,
	            setup, test_pkcs12_import, teardown);

	return g_test_run ();
}
