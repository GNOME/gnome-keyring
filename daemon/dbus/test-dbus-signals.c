/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-secret-util.c: Test secret utils

   Copyright (C) 2012 Red Hat Inc

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

#include <gcr/gcr-base.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <fcntl.h>

typedef struct {
	gchar *path;
	gchar *iface;
	gchar *name;
	GVariant *parameters;
} ReceivedSignal;

typedef struct {
	TestService service;
	guint signal_id;
	GList *received_signals;
	gboolean expecting_properties;
} Test;

static void
on_signal_received (GDBusConnection *connection,
                    const gchar *sender_name,
                    const gchar *object_path,
                    const gchar *interface_name,
                    const gchar *signal_name,
                    GVariant *parameters,
                    gpointer user_data)
{
	Test *test = user_data;
	ReceivedSignal *sig;

	g_assert (object_path != NULL);
	g_assert (interface_name != NULL);
	g_assert (signal_name != NULL);
	g_assert (parameters != NULL);

	sig = g_slice_new0 (ReceivedSignal);
	sig->path = g_strdup (object_path);
	sig->iface = g_strdup (interface_name);
	sig->name = g_strdup (signal_name);
	sig->parameters = g_variant_ref (parameters);
	test->received_signals = g_list_prepend (test->received_signals, sig);

	if (test->expecting_properties &&
	    g_str_equal ("org.freedesktop.DBus.Properties", interface_name) &&
	    g_str_equal ("PropertiesChanged", signal_name)) {
		egg_test_wait_stop ();
	}
}

static void
received_signal_free (gpointer data)
{
	ReceivedSignal *sig = data;
	g_free (sig->path);
	g_free (sig->iface);
	g_free (sig->name);
	g_variant_unref (sig->parameters);
	g_slice_free (ReceivedSignal, sig);
}

static void
received_signals_flush (Test *test)
{
	g_list_free_full (test->received_signals, received_signal_free);
	test->received_signals = NULL;
}

static void
expect_signal_with_path (Test *test,
                         const gchar *signal_path,
                         const gchar *signal_iface,
                         const gchar *signal_name,
                         const gchar *param_path)
{
	ReceivedSignal *sig;
	const gchar *path;
	GList *l;

	g_assert (signal_path != NULL);
	g_assert (signal_iface != NULL);
	g_assert (signal_name != NULL);
	g_assert (param_path != NULL);

	for (l = test->received_signals; l != NULL; l = g_list_next (l)) {
		sig = l->data;

		if (g_str_equal (signal_path, sig->path) &&
		    g_str_equal (signal_iface, sig->iface) &&
		    g_str_equal (signal_name, sig->name)) {
			g_assert (g_variant_is_of_type (sig->parameters, G_VARIANT_TYPE ("(o)")));
			g_variant_get (sig->parameters, "(&o)", &path);
			if (!g_str_equal (path, param_path)) {
				g_critical ("received invalid path from signal %s on interface %s at object %s: "
				            "expected path %s but got %s",
				            sig->name, sig->iface, sig->path, param_path, path);
			}

			return;
		}
	}

	g_critical ("didn't receive signal %s on interface %s at object %s",
	            signal_name, signal_iface, signal_path);
}

static gboolean
has_property_changed (Test *test,
		      const gchar *signal_path,
		      const gchar *property_iface,
		      const gchar *property_name)
{
	ReceivedSignal *sig;
	const gchar *iface;
	GVariant *properties;
	GVariant *invalidated;
	GVariant *value;
	GList *l;

	g_assert (signal_path != NULL);
	g_assert (property_iface != NULL);
	g_assert (property_name != NULL);

	for (l = test->received_signals; l != NULL; l = g_list_next (l)) {
		sig = l->data;

		if (g_str_equal (signal_path, sig->path) &&
		    g_str_equal ("org.freedesktop.DBus.Properties", sig->iface) &&
		    g_str_equal ("PropertiesChanged", sig->name)) {
			value = NULL;
			g_assert (g_variant_is_of_type (sig->parameters, G_VARIANT_TYPE ("(sa{sv}as)")));

			g_variant_get (sig->parameters, "(&s@a{sv}@as)", &iface, &properties, &invalidated);
			if (g_str_equal (iface, property_iface)) {
				value = g_variant_lookup_value (properties, property_name, NULL);
				g_variant_unref (value);
			}

			g_variant_unref (properties);
			g_variant_unref (invalidated);

			if (value != NULL)
				return TRUE;
		}
	}

	return FALSE;
}

static void
expect_property_changed (Test *test,
                         const gchar *signal_path,
                         const gchar *property_iface,
                         const gchar *property_name)
{
	/* GDBus queues property change signal emissions in an idle,
	 * so we cannot rely on PropertiesChanged to have arrived by
	 * the time we have returned from the method call - but we cannot
	 * rely on it *not* having arrived either!
	 * If the property notification hasn't been received, we set up
	 * ourselves to wake up at every property change.
	 * Eventually, if we don't receive any that match our arguments,
	 * we're going to fail.
	 */
	while (!has_property_changed (test, signal_path, property_iface, property_name)) {
		test->expecting_properties = TRUE;
		egg_test_wait_until (2000);
		test->expecting_properties = FALSE;
	}

	if (!has_property_changed (test, signal_path, property_iface, property_name))
		g_critical ("didn't receive PropertiesChanged for %s property on interface %s at object %s",
			    property_name, property_iface, signal_path);
}

static void
on_complete_get_result (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	GAsyncResult **res = user_data;
	g_assert (res != NULL);
	g_assert (*res == NULL);
	*res = g_object_ref (result);
	egg_test_wait_stop ();
}

static GVariant *
dbus_call_perform (Test *test,
                   const gchar *object_path,
                   const gchar *interface,
                   const gchar *member,
                   GVariant *parameters,
                   const GVariantType *restype,
                   GError **error)
{
	GAsyncResult *result = NULL;
	GVariant *retval;

	/*
	 * Do an async call with a full main loop, so that the signals
	 * arrive before the method result.
	 */

	g_dbus_connection_call (test->service.connection,
	                        test->service.bus_name,
	                        object_path,
	                        interface,
	                        member,
	                        parameters,
	                        restype,
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        -1, NULL,
	                        on_complete_get_result,
	                        &result);

	g_assert (result == NULL);
	egg_test_wait ();
	g_assert (result != NULL);

	retval = g_dbus_connection_call_finish (test->service.connection,
	                                        result, error);
	g_object_unref (result);

	return retval;
}

static void
setup (Test *test,
       gconstpointer unused)
{
	GError *error = NULL;
	GVariant *retval;

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

	/* Wait for the prompt's completed signal */
	test->signal_id = g_dbus_connection_signal_subscribe (test->service.connection,
	                                                      test->service.bus_name,
	                                                      NULL, NULL, NULL, NULL,
	                                                      G_DBUS_SIGNAL_FLAGS_NONE,
	                                                      on_signal_received,
	                                                      test, NULL);

	received_signals_flush (test);
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
	retval = dbus_call_perform (test,
	                            SECRET_SERVICE_PATH,
	                            SECRET_SERVICE_INTERFACE,
	                            "Lock",
	                            g_variant_new ("(@ao)",
	                                           g_variant_new_array (G_VARIANT_TYPE ("o"), &element, 1)),
	                            G_VARIANT_TYPE ("(aoo)"),
	                            &error);
	g_assert_no_error (error);

	/* Not expecting a prompt */
	g_variant_get (retval, "(@ao&o)", &locked, &prompt);
	g_assert_cmpstr (prompt, ==, "/");
	g_variant_unref (locked);
	g_variant_unref (retval);

	/* Don't carry over any received signals into test */
	received_signals_flush (test);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	received_signals_flush (test);

	g_dbus_connection_signal_unsubscribe (test->service.connection, test->signal_id);

	test_service_teardown (&test->service);

	gcr_mock_prompter_stop ();
}

static void
on_prompt_completed (GDBusConnection *connection,
                     const gchar *sender_name,
                     const gchar *object_path,
                     const gchar *interface_name,
                     const gchar *signal_name,
                     GVariant *parameters,
                     gpointer user_data)
{
	GVariant **prompt_result = user_data;
	gboolean dismissed;
	GVariant *result;

	g_assert (prompt_result != NULL);
	g_assert (*prompt_result == NULL);

	g_assert (g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(bv)")));
	g_variant_get (parameters, "(b@v)", &dismissed, &result);

	if (dismissed)
		*prompt_result = NULL;
	else
		*prompt_result = g_variant_ref (result);
	g_variant_unref (result);

	egg_test_wait_stop ();
}

static GVariant *
prompt_password_perform (Test *test,
                         const gchar *prompt_path,
                         const gchar *password,
                         const GVariantType *type)
{
	GVariant *prompt_result = NULL;
	GError *error = NULL;
	GVariant *inside;
	GVariant *retval;
	guint sig;

	/* Tell the mock prompter which password to use */
	gcr_mock_prompter_expect_password_ok (password, NULL);

	/* Wait for the prompt's completed signal */
	sig = g_dbus_connection_signal_subscribe (test->service.connection,
	                                          test->service.bus_name,
	                                          SECRET_PROMPT_INTERFACE,
	                                          "Completed",
	                                          prompt_path,
	                                          NULL,
	                                          G_DBUS_SIGNAL_FLAGS_NONE,
	                                          on_prompt_completed,
	                                          &prompt_result,
	                                          NULL);

	/* Perform the prompt, this will use the mock prompter */
	retval = g_dbus_connection_call_sync (test->service.connection,
	                                      test->service.bus_name,
	                                      prompt_path,
	                                      SECRET_PROMPT_INTERFACE,
	                                      "Prompt",
	                                      g_variant_new ("(s)", ""),
	                                      G_VARIANT_TYPE ("()"),
	                                      G_DBUS_CALL_FLAGS_NONE,
	                                      -1, NULL, &error);
	g_assert_no_error (error);
	g_variant_unref (retval);

	egg_test_wait ();

	/* Done, now stop waiting for the prompts signal, make sure mock was used */
	g_dbus_connection_signal_unsubscribe (test->service.connection, sig);
	g_assert (!gcr_mock_prompter_is_expecting ());

	/* Check prompt result for right type */
	g_assert (prompt_result != NULL);
	inside = g_variant_get_variant (prompt_result);
	g_assert (g_variant_is_of_type (inside, type));
	g_variant_unref (prompt_result);

	return inside;
}

static void
test_collection_created (Test *test,
                         gconstpointer unused)
{
	const gchar *collection;
	GError *error = NULL;
	const gchar *prompt;
	GVariant *properties;
	GVariant *retval;
	GVariant *result;
	GVariant *label;

	/* Create a new collection */
	label = g_variant_new_dict_entry (g_variant_new_string ("org.freedesktop.Secret.Collection.Label"),
	                                  g_variant_new_variant (g_variant_new_string ("My Collection")));
	properties = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), &label, 1);

	retval = dbus_call_perform (test,
	                            SECRET_SERVICE_PATH,
	                            SECRET_SERVICE_INTERFACE,
	                            "CreateCollection",
	                            g_variant_new ("(@a{sv}s)", properties, ""),
	                            G_VARIANT_TYPE ("(oo)"),
	                            &error);
	g_assert_no_error (error);

	/* We expect that a prompt is necessary */
	g_variant_get (retval, "(&o&o)", &collection, &prompt);
	g_assert_cmpstr (collection, ==, "/");
	g_assert_cmpstr (prompt, !=, "/");

	/*
	 * Perform the password prompt to create the collection, which returns
	 * the new collection path
	 */
	result = prompt_password_perform (test, prompt, "booo", G_VARIANT_TYPE_OBJECT_PATH);
	g_variant_unref (retval);

	expect_signal_with_path (test, SECRET_SERVICE_PATH, SECRET_SERVICE_INTERFACE,
	                         "CollectionCreated", g_variant_get_string (result, NULL));
	expect_property_changed (test, SECRET_SERVICE_PATH,
	                         SECRET_SERVICE_INTERFACE, "Collections");

	g_variant_unref (result);
}

static void
test_collection_created_no_prompt (Test *test,
                                   gconstpointer unused)
{
	const gchar *collection;
	GError *error = NULL;
	GVariant *properties;
	GVariant *retval;
	GVariant *label;

	/* Create a new collection */
	label = g_variant_new_dict_entry (g_variant_new_string ("org.freedesktop.Secret.Collection.Label"),
	                                  g_variant_new_variant (g_variant_new_string ("Without Prompt")));
	properties = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), &label, 1);

	retval = dbus_call_perform (test,
	                            SECRET_SERVICE_PATH,
	                            INTERNAL_SERVICE_INTERFACE,
	                            "CreateWithMasterPassword",
	                            g_variant_new ("(@a{sv}@(oayays))",
	                                           properties,
	                                           test_service_build_secret (&test->service, "booo")),
	                            G_VARIANT_TYPE ("(o)"),
	                            &error);
	g_assert_no_error (error);

	g_variant_get (retval, "(&o)", &collection);
	g_assert_cmpstr (collection, !=, "/");

	expect_signal_with_path (test, SECRET_SERVICE_PATH, SECRET_SERVICE_INTERFACE,
	                         "CollectionCreated", collection);
	expect_property_changed (test, SECRET_SERVICE_PATH,
	                         SECRET_SERVICE_INTERFACE, "Collections");

	g_variant_unref (retval);
}

static void
test_collection_deleted (Test *test,
                         gconstpointer unused)
{
	const gchar *prompt;
	GError *error = NULL;
	GVariant *retval;

	/* Delete a collection */
	retval = dbus_call_perform (test,
	                            "/org/freedesktop/secrets/collection/test",
	                            SECRET_COLLECTION_INTERFACE,
	                            "Delete",
	                            g_variant_new ("()"),
	                            G_VARIANT_TYPE ("(o)"),
	                            &error);
	g_assert_no_error (error);

	/* Expect that no prompt is returned */
	g_variant_get (retval, "(&o)", &prompt);
	g_assert_cmpstr (prompt, ==, "/");

	expect_signal_with_path (test, SECRET_SERVICE_PATH, SECRET_SERVICE_INTERFACE,
	                         "CollectionDeleted", "/org/freedesktop/secrets/collection/test");
	expect_property_changed (test, SECRET_SERVICE_PATH,
	                         SECRET_SERVICE_INTERFACE, "Collections");

	g_variant_unref (retval);
}

static void
test_collection_changed (Test *test,
                         gconstpointer unused)
{
	GError *error = NULL;
	GVariant *retval;

	retval = dbus_call_perform (test,
	                            "/org/freedesktop/secrets/collection/test",
	                            "org.freedesktop.DBus.Properties",
	                            "Set",
	                            g_variant_new ("(ssv)",
	                                           SECRET_COLLECTION_INTERFACE,
	                                           "Label",
	                                           g_variant_new_string ("New label")),
	                            G_VARIANT_TYPE ("()"),
	                            &error);
	g_assert_no_error (error);

	expect_signal_with_path (test, SECRET_SERVICE_PATH,
	                         SECRET_SERVICE_INTERFACE, "CollectionChanged",
	                         "/org/freedesktop/secrets/collection/test");
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "Label");

	g_variant_unref (retval);
}

static void
test_collection_lock (Test *test,
                      gconstpointer unused)
{
	GError *error = NULL;
	const gchar *prompt;
	GVariant *element;
	GVariant *locked;
	GVariant *retval;

	element = g_variant_new_object_path ("/org/freedesktop/secrets/collection/test");
	retval = dbus_call_perform (test,
	                            SECRET_SERVICE_PATH,
	                            SECRET_SERVICE_INTERFACE,
	                            "Lock",
	                            g_variant_new ("(@ao)",
	                                           g_variant_new_array (G_VARIANT_TYPE ("o"), &element, 1)),
	                            G_VARIANT_TYPE ("(aoo)"),
	                            &error);
	g_assert_no_error (error);

	/* Not expecting a prompt */
	g_variant_get (retval, "(@ao&o)", &locked, &prompt);
	g_assert_cmpstr (prompt, ==, "/");
	g_variant_unref (locked);

	expect_signal_with_path (test, SECRET_SERVICE_PATH,
	                         SECRET_SERVICE_INTERFACE, "CollectionChanged",
	                         "/org/freedesktop/secrets/collection/test");
	expect_signal_with_path (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "ItemChanged",
	                         "/org/freedesktop/secrets/collection/test/1");
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "Locked");
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test/1",
	                         SECRET_ITEM_INTERFACE, "Locked");

	g_variant_unref (retval);
}

static void
test_collection_unlock (Test *test,
                        gconstpointer unused)
{
	GError *error = NULL;
	const gchar *prompt;
	GVariant *unlocked;
	GVariant *retval;
	GVariant *element;

	element = g_variant_new_object_path ("/org/freedesktop/secrets/collection/test");
	retval = dbus_call_perform (test,
	                            SECRET_SERVICE_PATH,
	                            SECRET_SERVICE_INTERFACE,
	                            "Unlock",
	                            g_variant_new ("(@ao)",
	                                           g_variant_new_array (G_VARIANT_TYPE ("o"), &element, 1)),
	                            G_VARIANT_TYPE ("(aoo)"),
	                            &error);
	g_assert_no_error (error);

	/* Not expecting a prompt */
	g_variant_get (retval, "(@ao&o)", &unlocked, &prompt);
	g_assert_cmpstr (prompt, !=, "/");
	g_variant_unref (unlocked);

	unlocked = prompt_password_perform (test, prompt, "booo", G_VARIANT_TYPE ("ao"));
	g_variant_unref (unlocked);

	expect_signal_with_path (test, SECRET_SERVICE_PATH,
	                         SECRET_SERVICE_INTERFACE, "CollectionChanged",
	                         "/org/freedesktop/secrets/collection/test");
	expect_signal_with_path (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "ItemChanged",
	                         "/org/freedesktop/secrets/collection/test/1");
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "Locked");
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test/1",
	                         SECRET_ITEM_INTERFACE, "Locked");

	g_variant_unref (retval);
}

static void
test_collection_unlock_no_prompt (Test *test,
                                  gconstpointer unused)
{
	GError *error = NULL;
	GVariant *retval;

	retval = dbus_call_perform (test,
	                            SECRET_SERVICE_PATH,
	                            INTERNAL_SERVICE_INTERFACE,
	                            "UnlockWithMasterPassword",
	                            g_variant_new ("(o@(oayays))",
	                                           "/org/freedesktop/secrets/collection/test",
	                                           test_service_build_secret (&test->service, "booo")),
	                            G_VARIANT_TYPE ("()"),
	                            &error);
	g_assert_no_error (error);

	expect_signal_with_path (test, SECRET_SERVICE_PATH,
	                         SECRET_SERVICE_INTERFACE, "CollectionChanged",
	                         "/org/freedesktop/secrets/collection/test");
	expect_signal_with_path (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "ItemChanged",
	                         "/org/freedesktop/secrets/collection/test/1");
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "Locked");
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test/1",
	                         SECRET_ITEM_INTERFACE, "Locked");

	g_variant_unref (retval);
}

static void
test_item_created (Test *test,
                   gconstpointer unused)
{
	const gchar *item;
	const gchar *prompt;
	GError *error = NULL;
	GVariant *properties;
	GVariant *retval;
	GVariant *label;

	/* Create a new collection */
	label = g_variant_new_dict_entry (g_variant_new_string ("org.freedesktop.Secret.Item.Label"),
	                                  g_variant_new_variant (g_variant_new_string ("My Item")));
	properties = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), &label, 1);

	retval = dbus_call_perform (test,
	                            "/org/freedesktop/secrets/collection/test",
	                            SECRET_COLLECTION_INTERFACE,
	                            "CreateItem",
	                            g_variant_new ("(@a{sv}@(oayays)b)",
	                                           properties,
	                                           test_service_build_secret (&test->service, "booo"),
	                                           FALSE),
	                            G_VARIANT_TYPE ("(oo)"),
	                            &error);
	g_assert_no_error (error);

	/* Not expecting a prompt */
	g_variant_get (retval, "(&o&o)", &item, &prompt);
	g_assert_cmpstr (item, !=, "/");
	g_assert_cmpstr (prompt, ==, "/");

	expect_signal_with_path (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "ItemCreated", item);
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "Items");

	g_variant_unref (retval);
}

static void
test_item_deleted (Test *test,
                   gconstpointer unused)
{
	const gchar *prompt;
	GError *error = NULL;
	GVariant *retval;

	retval = dbus_call_perform (test,
	                            "/org/freedesktop/secrets/collection/test/1",
	                            SECRET_ITEM_INTERFACE,
	                            "Delete",
	                            g_variant_new ("()"),
	                            G_VARIANT_TYPE ("(o)"),
	                            &error);
	g_assert_no_error (error);

	/* Not expecting a prompt */
	g_variant_get (retval, "(&o)", &prompt);
	g_assert_cmpstr (prompt, ==, "/");

	expect_signal_with_path (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "ItemDeleted",
	                         "/org/freedesktop/secrets/collection/test/1");
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "Items");

	g_variant_unref (retval);
}

static void
test_item_changed (Test *test,
                   gconstpointer unused)
{
	GError *error = NULL;
	GVariant *retval;

	retval = dbus_call_perform (test,
	                            "/org/freedesktop/secrets/collection/test/1",
	                            "org.freedesktop.DBus.Properties",
	                            "Set",
	                            g_variant_new ("(ssv)",
	                                           SECRET_ITEM_INTERFACE,
	                                           "Label",
	                                           g_variant_new_string ("New label")),
	                            G_VARIANT_TYPE ("()"),
	                            &error);
	g_assert_no_error (error);

	expect_signal_with_path (test, "/org/freedesktop/secrets/collection/test",
	                         SECRET_COLLECTION_INTERFACE, "ItemChanged",
	                         "/org/freedesktop/secrets/collection/test/1");
	expect_property_changed (test, "/org/freedesktop/secrets/collection/test/1",
	                         SECRET_ITEM_INTERFACE, "Label");

	g_variant_unref (retval);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/secret-signals/collection-created", Test, NULL,
	            setup, test_collection_created, teardown);
	g_test_add ("/secret-signals/collection-created-no-prompt", Test, NULL,
	            setup, test_collection_created_no_prompt, teardown);
	g_test_add ("/secret-signals/collection-changed", Test, NULL,
	            setup, test_collection_changed, teardown);
	g_test_add ("/secret-signals/collection-deleted", Test, NULL,
	            setup, test_collection_deleted, teardown);
	g_test_add ("/secret-signals/collection-lock", Test, NULL,
	            setup, test_collection_lock, teardown);
	g_test_add ("/secret-signals/collection-unlock", Test, NULL,
	            setup_locked, test_collection_unlock, teardown);
	g_test_add ("/secret-signals/collection-unlock-no-prompt", Test, NULL,
	            setup_locked, test_collection_unlock_no_prompt, teardown);
	g_test_add ("/secret-signals/item-created", Test, NULL,
	            setup, test_item_created, teardown);
	g_test_add ("/secret-signals/item-changed", Test, NULL,
	            setup, test_item_changed, teardown);
	g_test_add ("/secret-signals/item-deleted", Test, NULL,
	            setup, test_item_deleted, teardown);

	return egg_tests_run_with_loop ();
}
