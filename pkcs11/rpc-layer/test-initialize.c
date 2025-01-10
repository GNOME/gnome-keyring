/*
   Copyright (C) 2014 Red Hat Inc

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

#include "daemon/gkd-test.h"

#include "egg/egg-testing.h"

#include <gck/gck.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>

typedef struct {
	GTestDBus *dbus;
	gchar *directory;
	GPid pid;
} Test;

static void
setup (Test *test,
       gconstpointer unused)
{
	test->dbus = g_test_dbus_new (G_TEST_DBUS_NONE);
	g_test_dbus_up (test->dbus);

	test->directory = egg_tests_create_scratch_directory (NULL, NULL);

	g_unsetenv ("GNOME_KEYRING_CONTROL");
	g_setenv ("XDG_RUNTIME_DIR", test->directory, TRUE);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	if (test->pid) {
		if (waitpid (test->pid, NULL, WNOHANG) != test->pid) {
			kill (test->pid, SIGTERM);
			g_assert_cmpint (waitpid (test->pid, NULL, 0), ==, test->pid);
		}
		g_spawn_close_pid (test->pid);
	}

	egg_tests_remove_scratch_directory (test->directory);
	g_free (test->directory);

	g_test_dbus_down (test->dbus);
	g_object_unref (test->dbus);
}

static void
test_initialize_normal (Test *test,
                        gconstpointer unused)
{
	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--components=pkcs11", NULL
	};

	const gchar *control;
	gchar **output;
	GckModule *module;
	GckModuleInfo *info;
	GError *error = NULL;

	/* Start the first daemon */
	output = gkd_test_launch_daemon (test->directory, argv, &test->pid, NULL);
	control = g_environ_getenv (output, "GNOME_KEYRING_CONTROL");
	g_assert_cmpstr (control, ==, NULL);
	g_strfreev (output);

	module = gck_module_initialize (TEST_GKR_PKCS11_MODULE,
	                                NULL, &error);
	g_assert_no_error (error);

	info = gck_module_get_info (module);
	g_assert (info != NULL);
	g_assert_cmpstr (info->library_description, ==, "GNOME Keyring Daemon Core");
	gck_module_info_free (info);

	g_object_unref (module);
}

static void
test_initialize_control (Test *test,
                         gconstpointer unused)
{
	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--control-directory", test->directory,
		"--components=pkcs11", NULL
	};

	const gchar *control;
	gchar **output;
	GckModule *module;
	GckModuleInfo *info;
	GError *error = NULL;

	/* Start the first daemon */
	output = gkd_test_launch_daemon (test->directory, argv, &test->pid, NULL);
	control = g_environ_getenv (output, "GNOME_KEYRING_CONTROL");
	g_assert_cmpstr (control, ==, test->directory);
	g_setenv ("GNOME_KEYRING_CONTROL", control, TRUE);
	g_strfreev (output);

	module = gck_module_initialize (TEST_GKR_PKCS11_MODULE,
	                                NULL, &error);
	g_assert_no_error (error);

	info = gck_module_get_info (module);
	g_assert (info != NULL);
	g_assert_cmpstr (info->library_description, ==, "GNOME Keyring Daemon Core");
	gck_module_info_free (info);

	g_object_unref (module);
}

static void
test_initialize_no_daemon (Test *test,
                           gconstpointer unused)
{
	GckModule *module;
	GckModuleInfo *info;
	GError *error = NULL;

	/* No daemon to connect to */
	g_unsetenv ("GNOME_KEYRING_CONTROL");
	g_unsetenv ("XDG_RUNTIME_DIR");

	module = gck_module_initialize (TEST_GKR_PKCS11_MODULE,
	                                NULL, &error);
	g_assert_no_error (error);

	info = gck_module_get_info (module);
	g_assert (info != NULL);
	g_assert_cmpstr (info->library_description, ==, "GNOME Keyring (without daemon)");
	gck_module_info_free (info);

	g_object_unref (module);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/pkcs11/rpc-layer/initialize/normal", Test, NULL,
	            setup, test_initialize_normal, teardown);
	g_test_add ("/pkcs11/rpc-layer/initialize/control", Test, NULL,
	            setup, test_initialize_control, teardown);
	g_test_add ("/pkcs11/rpc-layer/initialize/no-daemon", Test, NULL,
	            setup, test_initialize_no_daemon, teardown);

	return g_test_run ();
}
