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

#include "gkd-test.h"

#include "daemon/control/gkd-control.h"

#include "egg/egg-testing.h"

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

	test->directory = egg_tests_create_scratch_directory (
		SRCDIR "/daemon/dbus/fixtures/test.keyring",
		NULL);
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
test_control_valid (Test *test,
                     gconstpointer unused)
{
	gchar *fixed = g_strdup_printf ("%s/xxxx", test->directory);

	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--control-directory", fixed,
		"--components=", NULL
	};

	gchar **output;
	gint status;
	GPid pid;

	output = gkd_test_launch_daemon (test->directory, argv, &pid, NULL);

	g_assert_cmpstr (g_environ_getenv (output, "GNOME_KEYRING_CONTROL"), ==, fixed);
	g_strfreev (output);

	g_assert (gkd_control_quit (fixed, 0));
	g_assert_cmpint (waitpid (pid, &status, 0), ==, pid);
	g_assert_cmpint (status, ==, 0);

	g_free (fixed);
}

static void
test_control_creates (Test *test,
                      gconstpointer unused)
{
	gchar *directory = g_build_filename (test->directory, "under", NULL);

	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--control-directory", directory,
		"--components=", NULL
	};

	gchar **output;

	output = gkd_test_launch_daemon (test->directory, argv, &test->pid, NULL);
	g_assert_cmpstr (g_environ_getenv (output, "GNOME_KEYRING_CONTROL"), ==, directory);
	g_strfreev (output);

	g_assert (g_file_test (directory, G_FILE_TEST_IS_DIR));
	g_free (directory);
}

static void
test_control_noaccess (Test *test,
                      gconstpointer unused)
{
	gchar *noaccess = g_build_filename (test->directory, "under", NULL);
	gchar *directory = g_build_filename (test->directory, "under", "subdir", NULL);

	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--control-directory", directory,
		"--components=", NULL
	};

	gchar **output;

	if (g_mkdir_with_parents (noaccess, 0000) < 0)
		g_assert_not_reached ();

	/* Should choose a different directory */
	output = gkd_test_launch_daemon (test->directory, argv, &test->pid, NULL);
	g_assert_cmpstr (g_environ_getenv (output, "GNOME_KEYRING_CONTROL"), !=, directory);
	g_strfreev (output);

	g_assert (!g_file_test (directory, G_FILE_TEST_IS_DIR));
	g_free (directory);

	if (chmod (noaccess, 0700) < 0)
		g_assert_not_reached ();
	g_free (noaccess);
}

static void
test_control_badperm (Test *test,
                      gconstpointer unused)
{
	gchar *directory = g_build_filename (test->directory, "under", NULL);

	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--control-directory", directory,
		"--components=", NULL
	};

	gchar **output;

	if (g_mkdir_with_parents (directory, 0777) < 0)
		g_assert_not_reached ();

	/* Should choose a different directory */
	output = gkd_test_launch_daemon (test->directory, argv, &test->pid, NULL);
	g_assert_cmpstr (g_environ_getenv (output, "GNOME_KEYRING_CONTROL"), !=, directory);
	g_strfreev (output);

	g_free (directory);
}

static void
test_control_xdghome (Test *test,
                     gconstpointer unused)
{
	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--components=", NULL
	};

	gchar *directory;
	gchar *expected;
	GPid pid;
	gchar **output;
	gint status;

	/* Control directory not printed when default */
	directory = g_build_filename (test->directory, "different", NULL);
	output = gkd_test_launch_daemon (test->directory, argv, &pid,
	                                 "XDG_RUNTIME_DIR", directory,
	                                 NULL);

	expected = g_build_filename (directory, "/keyring", NULL);
	g_assert_cmpstr (g_environ_getenv (output, "GNOME_KEYRING_CONTROL"), ==, NULL);
	g_strfreev (output);

	g_assert (gkd_control_quit (expected, 0));
	g_assert_cmpint (waitpid (pid, &status, 0), ==, pid);
	g_assert_cmpint (status, ==, 0);

	g_free (directory);
	g_free (expected);
}

static void
test_daemon_replace (Test *test,
                     gconstpointer unused)
{
	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--components=", NULL
	};

	const gchar *replace[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--replace", "--components=", NULL
	};

	gchar **output;
	gint status;
	GPid pid;

	/* Start the first daemon */
	output = gkd_test_launch_daemon (test->directory, argv, &pid,
	                                 "XDG_RUNTIME_DIR", "/tmp/keyring-test-two",
	                                 NULL);
	g_strfreev (output);

	/* Replace with the second daemon */
	output = gkd_test_launch_daemon (test->directory, replace, &test->pid,
	                                 "XDG_RUNTIME_DIR", "/tmp/keyring-test-two",
	                                 NULL);
	g_strfreev (output);

	/* The first daemon should have exited cleanly here */
	g_assert_cmpint (waitpid (pid, &status, 0), ==, pid);
	g_assert_cmpint (status, ==, 0);
}

#ifdef WITH_SSH
static void
test_ssh_agent (Test *test,
                        gconstpointer unused)
{
	gchar *auth_sock = g_build_filename (test->directory, "keyring", "ssh", NULL);

	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--components=ssh-agent", NULL
	};

	gchar **output;

	output = gkd_test_launch_daemon (test->directory, argv, &test->pid, NULL);
	g_assert_cmpstr (g_environ_getenv (output, "SSH_AUTH_SOCK"), ==, auth_sock);
	g_strfreev (output);

	g_assert (g_file_test (auth_sock, G_FILE_TEST_EXISTS));
	g_free (auth_sock);
}
#endif

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/daemon/startup/control/valid", Test, NULL,
	            setup, test_control_valid, teardown);
	g_test_add ("/daemon/startup/control/creates", Test, NULL,
	            setup, test_control_creates, teardown);
	g_test_add ("/daemon/startup/control/noaccess", Test, NULL,
	            setup, test_control_noaccess, teardown);
	g_test_add ("/daemon/startup/control/badperm", Test, NULL,
	            setup, test_control_badperm, teardown);
	g_test_add ("/daemon/startup/control/xdghome", Test, NULL,
	            setup, test_control_xdghome, teardown);

	g_test_add ("/daemon/startup/replace", Test, NULL,
	            setup, test_daemon_replace, teardown);
#ifdef WITH_SSH
	g_test_add ("/daemon/startup/ssh-agent", Test, NULL,
	            setup, test_ssh_agent, teardown);
#endif

	return g_test_run ();
}
