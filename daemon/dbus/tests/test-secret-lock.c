/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-secret-lock.c: Test secret lock

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stefw@gnome.org>
*/

#include "config.h"

#include "gkd-secret-types.h"

#include "test-service.h"

#include "egg/egg-testing.h"

typedef struct {
	TestService service;
} Test;

static void
setup (Test *test,
       gconstpointer unused)
{
	test_service_setup (&test->service);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	test_service_teardown (&test->service);
}

static gboolean
get_locked (Test *test,
            const gchar *path,
            const gchar *interface)
{
	GVariant *retval;
	GVariant *prop;
	GError *error = NULL;
	gboolean locked;

	retval = g_dbus_connection_call_sync (test->service.connection,
	                                      test->service.bus_name,
	                                      path, "org.freedesktop.DBus.Properties",
	                                      "Get", g_variant_new ("(ss)", interface, "Locked"),
	                                      G_VARIANT_TYPE ("(v)"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START, -1, NULL, &error);
	g_assert_no_error (error);

	g_variant_get (retval, "(v)", &prop);
	g_variant_unref (retval);

	locked = g_variant_get_boolean (prop);
	g_variant_unref (prop);

	return locked;
}


static void
test_lock_service (Test *test,
                   gconstpointer unused)
{
	GError *error = NULL;
	GVariant *retval;

	g_assert (get_locked (test, "/org/freedesktop/secrets/collection/test", SECRET_COLLECTION_INTERFACE) == TRUE);

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

	/* Check not locked */
	g_assert (get_locked (test, "/org/freedesktop/secrets/collection/test", SECRET_COLLECTION_INTERFACE) == FALSE);

	/* Lock everything */
	retval = g_dbus_connection_call_sync (test->service.connection,
	                                      test->service.bus_name,
	                                      "/org/freedesktop/secrets",
	                                      SECRET_SERVICE_INTERFACE,
	                                      "LockService",
	                                      g_variant_new ("()"),
	                                      G_VARIANT_TYPE ("()"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                                      -1, NULL, &error);
	g_assert_no_error (error);
	g_variant_unref (retval);

	/* Check locked */
	g_assert (get_locked (test, "/org/freedesktop/secrets/collection/test", SECRET_COLLECTION_INTERFACE) == TRUE);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/secret-lock/service", Test, NULL,
	            setup, test_lock_service, teardown);

	return egg_tests_run_with_loop ();
}
