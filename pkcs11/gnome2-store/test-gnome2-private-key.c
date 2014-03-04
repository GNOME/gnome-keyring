/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-object.c: Test GkmObject

   Copyright (C) 2012 Stefan Walter

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

#include "mock-gnome2-module.h"

#include "gnome2-store/gkm-gnome2-private-key.h"

#if 0
#include "gkm/gkm-attributes.h"
#include "gkm/gkm-certificate.h"
#include "gkm/gkm-object.h"
#endif
#include "gkm/gkm-data-der.h"
#include "gkm/gkm-module.h"
#include "gkm/gkm-serializable.h"
#include "gkm/gkm-session.h"
#include "gkm/gkm-test.h"

#include "egg/egg-testing.h"

#include "pkcs11i.h"

typedef struct {
	GkmModule *module;
	GkmSession *session;
	GBytes *key_data;
	GkmGnome2PrivateKey *key;
} Test;

static void
setup_basic (Test* test,
             gconstpointer unused)
{
	gchar *data;
	gsize length;

	test->module = mock_gnome2_module_initialize_and_enter ();
	test->session = mock_gnome2_module_open_session (TRUE);

	if (!g_file_get_contents (SRCDIR "/pkcs11/gnome2-store/fixtures/der-key-v2-des3.p8", &data, &length, NULL))
		g_assert_not_reached ();

	test->key_data = g_bytes_new_take (data, length);
}

static void
teardown_basic (Test* test,
                gconstpointer unused)
{
	g_bytes_unref (test->key_data);
	mock_gnome2_module_leave_and_finalize ();
}

static void
setup (Test *test,
       gconstpointer unused)
{
	GkmSecret *login;

	setup_basic (test, unused);

	test->key = g_object_new (GKM_TYPE_GNOME2_PRIVATE_KEY,
	                          "unique", "test-key",
	                          "module", gkm_session_get_module (test->session),
	                          "manager", gkm_session_get_manager (test->session),
	                          NULL);

	login = gkm_secret_new_from_password ("booo");
	if (!gkm_serializable_load (GKM_SERIALIZABLE (test->key), login, test->key_data))
		g_assert_not_reached ();
	g_object_unref (login);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	g_clear_object (&test->key);
	teardown_basic (test, unused);
}

static void
test_load_private_key (Test *test,
                       gconstpointer unused)
{
	GkmGnome2PrivateKey *key;
	GkmSecret *login;

	key = g_object_new (GKM_TYPE_GNOME2_PRIVATE_KEY,
	                    "unique", "test-key",
	                    "module", gkm_session_get_module (test->session),
	                    "manager", gkm_session_get_manager (test->session),
	                    NULL);

	/* It's encrypted, this should fail */
	if (gkm_serializable_load (GKM_SERIALIZABLE (key), NULL, test->key_data))
		g_assert_not_reached ();

	login = gkm_secret_new_from_password ("booo");
	if (!gkm_serializable_load (GKM_SERIALIZABLE (key), login, test->key_data))
		g_assert_not_reached ();
	g_object_unref (login);

	g_object_unref (key);
}

static void
test_save_private_key (Test *test,
                       gconstpointer unused)
{
	GkmSecret *login;
	GBytes *data;
	gcry_sexp_t sexp;

	/* Save unencrypted */
	data = gkm_serializable_save (GKM_SERIALIZABLE (test->key), NULL);
	g_assert (data != NULL);
	g_assert (gkm_data_der_read_private_pkcs8_plain (data, &sexp) == GKM_DATA_SUCCESS);
	g_bytes_unref (data);
	gcry_sexp_release (sexp);

	/* Save encrypted */
	login = gkm_secret_new_from_password ("booo");
	data = gkm_serializable_save (GKM_SERIALIZABLE (test->key), login);
	g_assert (data != NULL);
	g_assert (gkm_data_der_read_private_pkcs8_crypted (data, "booo", 4, &sexp) == GKM_DATA_SUCCESS);
	g_bytes_unref (data);
	gcry_sexp_release (sexp);
	g_object_unref (login);
}

#if 0
static void
test_attribute_check_value (Test* test,
                            gconstpointer unused)
{
	gpointer data;
	gsize n_data;

	data = gkm_object_get_attribute_data (GKM_OBJECT (test->certificate),
	                                      test->session, CKA_CHECK_VALUE, &n_data);

	egg_assert_cmpmem (data, n_data, ==, "\x36\x86\x35", 3);
	g_free (data);
}

static void
test_attribute_issuer (Test* test,
                       gconstpointer unused)
{
	gpointer data;
	gsize n_data;

	data = gkm_object_get_attribute_data (GKM_OBJECT (test->certificate),
	                                      test->session, CKA_ISSUER, &n_data);

	egg_assert_cmpmem (data, n_data, ==, "\x30\x81\xCF\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x5A\x41\x31\x15\x30\x13\x06\x03\x55\x04\x08\x13\x0C\x57\x65\x73\x74\x65\x72\x6E\x20\x43\x61\x70\x65\x31\x12\x30\x10\x06\x03\x55\x04\x07\x13\x09\x43\x61\x70\x65\x20\x54\x6F\x77\x6E\x31\x1A\x30\x18\x06\x03\x55\x04\x0A\x13\x11\x54\x68\x61\x77\x74\x65\x20\x43\x6F\x6E\x73\x75\x6C\x74\x69\x6E\x67\x31\x28\x30\x26\x06\x03\x55\x04\x0B\x13\x1F\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x69\x6F\x6E\x20\x53\x65\x72\x76\x69\x63\x65\x73\x20\x44\x69\x76\x69\x73\x69\x6F\x6E\x31\x23\x30\x21\x06\x03\x55\x04\x03\x13\x1A\x54\x68\x61\x77\x74\x65\x20\x50\x65\x72\x73\x6F\x6E\x61\x6C\x20\x50\x72\x65\x6D\x69\x75\x6D\x20\x43\x41\x31\x2A\x30\x28\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01\x16\x1B\x70\x65\x72\x73\x6F\x6E\x61\x6C\x2D\x70\x72\x65\x6D\x69\x75\x6D\x40\x74\x68\x61\x77\x74\x65\x2E\x63\x6F\x6D", 210);
	g_free (data);
}

static void
test_attribute_subject (Test* test,
                        gconstpointer unused)
{
	gpointer data;
	gsize n_data;

	data = gkm_object_get_attribute_data (GKM_OBJECT (test->certificate),
	                                      test->session, CKA_SUBJECT, &n_data);

	egg_assert_cmpmem (data, n_data, ==, "\x30\x81\xCF\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x5A\x41\x31\x15\x30\x13\x06\x03\x55\x04\x08\x13\x0C\x57\x65\x73\x74\x65\x72\x6E\x20\x43\x61\x70\x65\x31\x12\x30\x10\x06\x03\x55\x04\x07\x13\x09\x43\x61\x70\x65\x20\x54\x6F\x77\x6E\x31\x1A\x30\x18\x06\x03\x55\x04\x0A\x13\x11\x54\x68\x61\x77\x74\x65\x20\x43\x6F\x6E\x73\x75\x6C\x74\x69\x6E\x67\x31\x28\x30\x26\x06\x03\x55\x04\x0B\x13\x1F\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x69\x6F\x6E\x20\x53\x65\x72\x76\x69\x63\x65\x73\x20\x44\x69\x76\x69\x73\x69\x6F\x6E\x31\x23\x30\x21\x06\x03\x55\x04\x03\x13\x1A\x54\x68\x61\x77\x74\x65\x20\x50\x65\x72\x73\x6F\x6E\x61\x6C\x20\x50\x72\x65\x6D\x69\x75\x6D\x20\x43\x41\x31\x2A\x30\x28\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01\x16\x1B\x70\x65\x72\x73\x6F\x6E\x61\x6C\x2D\x70\x72\x65\x6D\x69\x75\x6D\x40\x74\x68\x61\x77\x74\x65\x2E\x63\x6F\x6D", 210);
	g_free (data);
}

static void
test_attribute_serial_number (Test* test,
                              gconstpointer unused)
{
	gpointer data;
	gsize n_data;

	data = gkm_object_get_attribute_data (GKM_OBJECT (test->certificate),
	                                      test->session, CKA_SERIAL_NUMBER, &n_data);

	egg_assert_cmpmem (data, n_data, ==, "\x02\x01\x00", 3);
	g_free (data);
}

static void
test_attribute_value (Test* test,
                      gconstpointer unused)
{
	gconstpointer raw;
	gpointer data;
	gsize n_data, n_raw;

	data = gkm_object_get_attribute_data (GKM_OBJECT (test->certificate),
	                                      test->session, CKA_VALUE, &n_data);

	raw = egg_bytes_get_data (test->certificate_data);
	n_raw = egg_bytes_get_size (test->certificate_data);
	egg_assert_cmpmem (data, n_data, ==, raw, n_raw);
	g_free (data);
}

static void
test_hash (Test* test,
           gconstpointer unused)
{
	gpointer hash;
	gsize n_hash;

	hash = gkm_certificate_hash (test->certificate, GCRY_MD_SHA1, &n_hash);

	egg_assert_cmpmem (hash, n_hash, ==, "\x36\x86\x35\x63\xFD\x51\x28\xC7\xBE\xA6\xF0\x05\xCF\xE9\xB4\x36\x68\x08\x6C\xCE", 20);
	g_free (hash);
}
#endif

static void
null_log_handler (const gchar *log_domain, GLogLevelFlags log_level,
                  const gchar *message, gpointer user_data)
{

}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	/* Suppress these messages in tests */
	g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO | G_LOG_LEVEL_DEBUG,
	                   null_log_handler, NULL);

	g_test_add ("/gnome2-store/private-key/load", Test, NULL, setup_basic, test_load_private_key, teardown_basic);
	g_test_add ("/gnome2-store/private-key/save", Test, NULL, setup, test_save_private_key, teardown);

	return egg_tests_run_in_thread_with_loop ();
}
