/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-secret-portal.c: Test secret portal

   Copyright (C) 2013-2019 Red Hat, Inc

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

   Author: Stef Walter <stefw@gnome.org>, Daiki Ueno
*/

#include "config.h"

#include "test-service.h"

#include "gkd-secret-types.h"

#include "egg/egg-testing.h"

#include <gcr/gcr-base.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <glib-unix.h>
#include <gio/gunixfdlist.h>
#include <gio/gunixinputstream.h>
#include <fcntl.h>

typedef struct {
	TestService service;
	guint8 buffer[128];
	gsize bytes_read;
} Test;

static void
setup (Test *test,
       gconstpointer unused)
{
	GVariant *retval;
	GError *error = NULL;

	test->service.mock_prompter = gcr_mock_prompter_start ();
	g_assert (test->service.mock_prompter != NULL);

	test_service_setup (&test->service);

	/* Unlock the test collection */
	retval = g_dbus_connection_call_sync (test->service.connection,
	                                      test->service.bus_name,
	                                      SECRET_SERVICE_PATH,
	                                      INTERNAL_SERVICE_INTERFACE,
	                                      "UnlockWithMasterPassword",
	                                      g_variant_new ("(o@(oayays))",
	                                                     "/org/freedesktop/secrets/collection/test",
	                                                     test_service_build_secret (&test->service, "booo")),
	                                      G_VARIANT_TYPE ("()"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                                      -1, NULL, &error);
	g_assert_no_error (error);
	g_variant_unref (retval);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	test_service_teardown (&test->service);

	gcr_mock_prompter_stop ();
}

static void
setup_locked (Test *test,
              gconstpointer unused)
{
	GVariant *element;
	GVariant *retval;
	GError *error = NULL;
	const gchar *prompt;
	GVariant *locked;

	/* Main setup */
	setup (test, unused);

	element = g_variant_new_object_path ("/org/freedesktop/secrets/collection/test");
	retval = g_dbus_connection_call_sync (test->service.connection,
					      test->service.bus_name,
					      SECRET_SERVICE_PATH,
					      SECRET_SERVICE_INTERFACE,
					      "Lock",
					      g_variant_new ("(@ao)",
							     g_variant_new_array (G_VARIANT_TYPE ("o"), &element, 1)),
					      G_VARIANT_TYPE ("(aoo)"),
					      G_DBUS_CALL_FLAGS_NO_AUTO_START,
					      -1,
					      NULL,
					      &error);
	g_assert_no_error (error);

	/* Not expecting a prompt */
	g_variant_get (retval, "(@ao&o)", &locked, &prompt);
	g_assert_cmpstr (prompt, ==, "/");
	g_variant_unref (locked);
	g_variant_unref (retval);
}

static void
call_retrieve_secret (Test *test)
{
	GUnixFDList *fd_list;
	gint fds[2];
	gint fd_index;
	GError *error = NULL;
	gboolean ret;
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GInputStream) stream = NULL;
	GVariantBuilder options;

	ret = g_unix_open_pipe (fds, FD_CLOEXEC, &error);
	g_assert_true (ret);
	g_assert_no_error (error);

	fd_list = g_unix_fd_list_new ();
	fd_index = g_unix_fd_list_append (fd_list, fds[1], &error);
	g_assert_no_error (error);
	close (fds[1]);

	g_variant_builder_init (&options, G_VARIANT_TYPE ("a{sv}"));
	reply = g_dbus_connection_call_with_unix_fd_list_sync (test->service.connection,
							       test->service.bus_name,
							       PORTAL_SERVICE_PATH,
							       PORTAL_SERVICE_INTERFACE,
							       "RetrieveSecret",
							       g_variant_new ("(osh@a{sv})",
									      "/org/gnome/keyring/Portal/Request",
									      "org.gnome.keyring.Test",
									      fd_index,
									      g_variant_builder_end (&options)),
							       G_VARIANT_TYPE ("(ua{sv})"),
							       G_DBUS_CALL_FLAGS_NONE,
							       30000,
							       fd_list, NULL,
							       NULL,
							       &error);
	g_object_unref (fd_list);
	g_assert_no_error (error);
	g_assert_nonnull (reply);

	stream = g_unix_input_stream_new (fds[0], TRUE);
	ret = g_input_stream_read_all (stream, test->buffer, sizeof(test->buffer),
				       &test->bytes_read, NULL, &error);
	g_assert_no_error (error);
	g_assert_true (ret);
}

static void
test_portal_retrieve_secret (Test *test,
			     gconstpointer unused)
{
	guint8 buffer[128];
	gsize bytes_read;

	call_retrieve_secret (test);
	memcpy (buffer, test->buffer, sizeof(test->buffer));
	bytes_read = test->bytes_read;

	call_retrieve_secret (test);
	g_assert_cmpmem (buffer, bytes_read, test->buffer, test->bytes_read);
}

static void
test_portal_retrieve_secret_locked (Test *test,
				    gconstpointer unused)
{
	guint8 buffer[128];
	gsize bytes_read;

	gcr_mock_prompter_expect_password_ok ("booo", NULL);

	call_retrieve_secret (test);
	memcpy (buffer, test->buffer, sizeof(test->buffer));
	bytes_read = test->bytes_read;

	call_retrieve_secret (test);
	g_assert_cmpmem (buffer, bytes_read, test->buffer, test->bytes_read);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/secret-portal/portal-retrieve-secret", Test, NULL,
	            setup, test_portal_retrieve_secret, teardown);
	g_test_add ("/secret-portal/portal-retrieve-secret-locked", Test, NULL,
	            setup_locked, test_portal_retrieve_secret_locked, teardown);

	return egg_tests_run_with_loop ();
}
