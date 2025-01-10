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

	test->directory = egg_tests_create_scratch_directory (NULL, NULL);
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

	if (test->dbus) {
		g_test_dbus_down (test->dbus);
		g_object_unref (test->dbus);
	}
}

static void
test_sigterm (Test *test,
              gconstpointer unused)
{
	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--control-directory", test->directory,
		"--components=secrets,pkcs11", NULL
	};

	gchar **output;
	gint status;
	GPid pid;

	output = gkd_test_launch_daemon (test->directory, argv, &pid, NULL);

	g_assert (gkd_control_unlock (test->directory, "booo"));
	g_strfreev (output);

	/* Terminate the daemon */
	g_assert_cmpint (kill (pid, SIGTERM), ==, 0);

	/* Daemon should exit cleanly */
	g_assert_cmpint (waitpid (pid, &status, 0), ==, pid);
	g_assert_cmpint (status, ==, 0);
}

static void
test_close_connection (Test *test,
                       gconstpointer unused)
{
	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground",
		"--control-directory", test->directory,
		"--components=secrets,pkcs11", NULL
	};

	gchar **output;
	gint status;
	GPid pid;

	output = gkd_test_launch_daemon (test->directory, argv, &pid, NULL);

	g_assert (gkd_control_unlock (test->directory, "booo"));
	g_strfreev (output);

	/* Now close the dbus connection */
	g_test_dbus_down (test->dbus);
	g_object_unref (test->dbus);
	test->dbus = NULL;

	/* Daemon should exit */
	g_assert_cmpint (waitpid (pid, &status, 0), ==, pid);
	g_assert_cmpint (status, ==, 0);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/daemon/shutdown/dbus-connection", Test, NULL,
	            setup, test_close_connection, teardown);
	g_test_add ("/daemon/shutdown/sigterm", Test, NULL,
	            setup, test_sigterm, teardown);

	return g_test_run ();
}
