/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-service.c: Common service code

   Copyright (C) 2013 Red Hat Inc

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

   Author: Stef Walter <stefw@gnome.org>
*/

#include "config.h"

#include "test-service.h"

#include "gkd-secret-types.h"

#include "egg/egg-testing.h"

#include <gcr/gcr-base.h>

#include <glib/gstdio.h>

#include <fcntl.h>

static void
on_test_service_appeared (GDBusConnection *connection,
                          const gchar *name,
                          const gchar *name_owner,
                          gpointer user_data)
{
	TestService *test = user_data;
	if (!test->connection)
		test->connection = g_object_ref (connection);
	test->available = TRUE;
	egg_test_wait_stop ();
}

static void
on_test_service_vanished (GDBusConnection *connection,
                          const gchar *name,
                          gpointer user_data)
{
	TestService *test = user_data;
	if (test->available) {
		test->available = FALSE;
		egg_test_wait_stop ();
	}
}

static void
on_service_spawned (gpointer user_data)
{
	TestService *test = user_data;
	int fd;

	g_setenv ("GNOME_KEYRING_TEST_PATH", test->directory, TRUE);
	g_setenv ("GNOME_KEYRING_TEST_SERVICE", test->bus_name, TRUE);
	if (test->mock_prompter)
		g_setenv ("GNOME_KEYRING_TEST_PROMPTER", test->mock_prompter, TRUE);

	fd = g_open ("/dev/null", O_WRONLY, 0);
	if (fd != -1)
		dup2 (fd, 1);
}

void
test_service_setup (TestService *test)
{
	GError *error = NULL;
	GVariant *retval;
	GVariant *output;

	gchar *args[] = {
		TOP_BUILDDIR "/daemon/gnome-keyring-daemon",
		"--foreground",
		"--control-directory",
		"/tmp/keyring-test",
		"--components",
		"secrets",
		NULL,
	};

	test->bus_name = g_strdup_printf ("org.gnome.keyring.Test.t%d", getpid ());

	test->watch_id = g_bus_watch_name (G_BUS_TYPE_SESSION, test->bus_name,
	                                   G_BUS_NAME_WATCHER_FLAGS_NONE,
	                                   on_test_service_appeared,
	                                   on_test_service_vanished,
	                                   test, NULL);

	test->directory = egg_tests_create_scratch_directory (
		SRCDIR "/files/test.keyring",
		NULL);

	if (!g_spawn_async (NULL, args, NULL,
	                    G_SPAWN_LEAVE_DESCRIPTORS_OPEN | G_SPAWN_DO_NOT_REAP_CHILD,
	                    on_service_spawned, test, &test->pid, &error)) {
		g_error ("couldn't start gnome-keyring-daemon for testing: %s", error->message);
		g_assert_not_reached ();
	}

	if (!test->available) {
		egg_test_wait ();

		if (!test->available) {
			g_warning ("Couldn't start gnome-keyring-daemon test service. ");
			g_assert_not_reached ();
		}
	}

	/* Set by on_test_service_appeared */
	g_assert (test->connection != NULL);

	/* Establish a plain session with the daemon */
	retval = g_dbus_connection_call_sync (test->connection,
	                                      test->bus_name,
	                                      SECRET_SERVICE_PATH,
	                                      SECRET_SERVICE_INTERFACE,
	                                      "OpenSession",
	                                      g_variant_new ("(s@v)", "plain",
	                                                     g_variant_new_variant (g_variant_new_string (""))),
	                                      G_VARIANT_TYPE ("(vo)"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                                      -1, NULL, &error);
	g_assert_no_error (error);

	g_variant_get (retval, "(@vo)", &output, &test->session);
	g_variant_unref (output);
	g_variant_unref (retval);
}

void
test_service_teardown (TestService *test)
{
	if (test->pid)
		kill (test->pid, SIGTERM);

	if (test->available) {
		egg_test_wait ();
		if (test->available) {
			g_warning ("Couldn't stop gnome-keyring-daemon test service.");
			g_assert_not_reached ();
		}
	}

	if (test->watch_id)
		g_bus_unwatch_name (test->watch_id);

	g_free (test->bus_name);
	g_free (test->session);

	if (test->connection)
		g_object_unref (test->connection);

	egg_tests_remove_scratch_directory (test->directory);
	g_free (test->directory);
}


GVariant *
test_service_build_secret (TestService *test,
                           const gchar *value)
{
	return g_variant_new ("(o@ay@ays)", test->session,
	                      g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, "", 0, 1),
	                      g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, value, strlen (value), 1),
	                      "text/plain");
}
