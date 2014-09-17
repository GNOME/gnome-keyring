/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-secret-items.c: Test secret items

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

#include "test-service.h"

#include "gkd-secret-types.h"

#include "egg/egg-testing.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <fcntl.h>

typedef struct {
	TestService service;
} Test;

static void
setup (Test *test,
       gconstpointer unused)
{
	GVariant *retval;
	GError *error = NULL;

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
}

static GVariant *
get_all_properties (Test *test,
                    const gchar *path,
                    const gchar *interface)
{
	GVariant *retval;
	GVariant *props;
	GError *error = NULL;

	retval = g_dbus_connection_call_sync (test->service.connection,
	                                      test->service.bus_name,
	                                      path, "org.freedesktop.DBus.Properties",
	                                      "GetAll", g_variant_new ("(s)", interface),
	                                      G_VARIANT_TYPE ("(a{sv})"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START, -1, NULL, &error);
	g_assert_no_error (error);

	g_variant_get (retval, "(@a{sv})", &props);
	g_variant_unref (retval);

	return props;
}

static void
set_property (Test *test,
              const gchar *path,
              const gchar *interface,
              const gchar *property,
              GVariant *value)
{
	GVariant *retval;
	GError *error = NULL;

	retval = g_dbus_connection_call_sync (test->service.connection,
	                                      test->service.bus_name,
	                                      path, "org.freedesktop.DBus.Properties",
	                                      "Set", g_variant_new ("(ssv)", interface, property, value),
	                                      G_VARIANT_TYPE ("()"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START, -1, NULL, &error);
	g_assert_no_error (error);
	g_variant_unref (retval);
}

static void
test_created_modified_properties (Test *test,
                                  gconstpointer unused)
{
	GVariantBuilder builder;
	GError *error = NULL;
	GVariant *retval;
	gchar *item;
	gchar *prompt;
	guint64 created;
	guint64 modified;
	GVariant *props;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&builder, "{sv}", SECRET_ITEM_INTERFACE ".Label", g_variant_new_string ("The Label"));
	props = g_variant_builder_end (&builder);

	retval = g_dbus_connection_call_sync (test->service.connection,
	                                      test->service.bus_name,
	                                      "/org/freedesktop/secrets/collection/test",
	                                      SECRET_COLLECTION_INTERFACE,
	                                      "CreateItem",
	                                      g_variant_new ("(@a{sv}@(oayays)b)", props,
	                                                     test_service_build_secret (&test->service, "the secret"), TRUE),
	                                      G_VARIANT_TYPE ("(oo)"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START, -1, NULL, &error);
	g_assert_no_error (error);

	g_variant_get (retval, "(oo)", &item, &prompt);
	g_assert_cmpstr (prompt, ==, "/");
	g_assert_cmpstr (item, !=, "/");
	g_variant_unref (retval);
	g_free (prompt);

	props = get_all_properties (test, item, SECRET_ITEM_INTERFACE);
	if (!g_variant_lookup (props, "Created", "t", &created))
		g_assert_not_reached ();
	if (!g_variant_lookup (props, "Modified", "t", &modified))
		g_assert_not_reached ();
	g_variant_unref (props);

	/* Created and modified within the last 10 seconds */
	g_assert_cmpuint (created, >, (g_get_real_time () / G_TIME_SPAN_SECOND) - 10);
	g_assert_cmpuint (modified, >, (g_get_real_time () / G_TIME_SPAN_SECOND) - 10);
	g_assert_cmpuint (created, ==, modified);

	if (!g_test_thorough ()) {
		g_free (item);
		return;
	}

	/* Unfortunately have to wait 1.25 seconds here */
	g_usleep (G_TIME_SPAN_SECOND + (G_TIME_SPAN_SECOND / 4));

	/* Now modify the item */
	set_property (test, item, SECRET_ITEM_INTERFACE, "Label", g_variant_new_string ("New Label"));

	/* Check the properties again */
	props = get_all_properties (test, item, SECRET_ITEM_INTERFACE);
	if (!g_variant_lookup (props, "Created", "t", &created))
		g_assert_not_reached ();
	if (!g_variant_lookup (props, "Modified", "t", &modified))
		g_assert_not_reached ();
	g_variant_unref (props);

	/* Modified should have changed */
	g_assert_cmpuint (modified, >, (g_get_real_time () / G_TIME_SPAN_SECOND) - 10);
	g_assert_cmpuint (created, !=, modified);

	g_free (item);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/secret-item/created-modified-properties", Test, NULL,
	            setup, test_created_modified_properties, teardown);

	return egg_tests_run_with_loop ();
}
