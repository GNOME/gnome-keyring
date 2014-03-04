/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-secret-search.c: Test secret search

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
	test_service_setup (&test->service);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	test_service_teardown (&test->service);
}

static void
test_service_search_items_unlocked_separate (Test *test,
                                             gconstpointer unused)
{
	GVariantBuilder builder;
	GError *error = NULL;
	GVariant *retval;
	GVariant *attrs;
	GVariant *unlocked;
	GVariant *locked;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	attrs = g_variant_builder_end (&builder);

	retval = g_dbus_connection_call_sync (test->service.connection,
	                                      test->service.bus_name,
	                                      "/org/freedesktop/secrets",
	                                      SECRET_SERVICE_INTERFACE,
	                                      "SearchItems",
	                                      g_variant_new ("(@a{ss})", attrs),
	                                      G_VARIANT_TYPE ("(aoao)"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                                      -1, NULL, &error);
	g_assert_no_error (error);

	g_variant_get (retval, "(@ao@ao)", &unlocked, &locked);
	g_variant_unref (retval);

	g_assert_cmpuint (g_variant_n_children (unlocked), ==, 0);
	g_assert_cmpuint (g_variant_n_children (locked), ==, 1);

	g_variant_unref (unlocked);
	g_variant_unref (locked);
}

static void
test_collection_search_items_combined (Test *test,
                                       gconstpointer unused)
{
	GVariantBuilder builder;
	GError *error = NULL;
	GVariant *retval;
	GVariant *attrs;
	GVariant *items;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	attrs = g_variant_builder_end (&builder);

	retval = g_dbus_connection_call_sync (test->service.connection,
	                                      test->service.bus_name,
	                                      "/org/freedesktop/secrets/collection/test",
	                                      SECRET_COLLECTION_INTERFACE,
	                                      "SearchItems",
	                                      g_variant_new ("(@a{ss})", attrs),
	                                      G_VARIANT_TYPE ("(ao)"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                                      -1, NULL, &error);
	g_assert_no_error (error);

	g_variant_get (retval, "(@ao)", &items);
	g_variant_unref (retval);

	g_assert_cmpuint (g_variant_n_children (items), ==, 1);
	g_variant_unref (items);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/secret-search/service-search-items-unlocked-separate", Test, NULL,
	            setup, test_service_search_items_unlocked_separate, teardown);
	g_test_add ("/secret-search/collection-search-items-combined", Test, NULL,
	            setup, test_collection_search_items_combined, teardown);

	return egg_tests_run_with_loop ();
}
