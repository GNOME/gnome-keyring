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

#include "daemon/control/gkd-control.h"
#include "daemon/gkd-test.h"

#include "egg/egg-testing.h"
#include "egg/egg-secure-memory.h"

#include <security/pam_appl.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

typedef struct {
	GTestDBus *dbus;
	GDBusConnection *connection;
	gchar *directory;
	GPid pid;
	gboolean skipping;
	pam_handle_t *ph;
	struct pam_conv conv;
	const gchar *password;
	const gchar *new_password;
} Test;

const gchar *PASS_ENVIRON[] = {
	"DBUS_SESSION_ADDRESS",
	"XDG_RUNTIME_DIR",
	"XDG_DATA_HOME",
	NULL
};

static void
skip_test (Test *test,
           const gchar *reason)
{
	test->skipping = TRUE;
#if GLIB_CHECK_VERSION(2, 40, 0)
	g_test_skip (reason);
#else
	if (g_test_verbose ())
		g_print ("GTest: skipping: %s\n", reason);
	else
		g_print ("SKIP: %s ", reason);
#endif
}

static int
conv_func (int n,
           const struct pam_message **msg,
           struct pam_response **resp,
           void *arg)
{
	struct pam_response *aresp;
	Test *test = arg;
	int i;

	g_assert (n > 0 && n < PAM_MAX_NUM_MSG);
	aresp = g_new0(struct pam_response, n);

	for (i = 0; i < n; ++i) {
		aresp[i].resp_retcode = 0;
		aresp[i].resp = NULL;
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			if (test->password) {
				aresp[i].resp = strdup (test->password);
				test->password = NULL;
			} else if (test->new_password) {
				aresp[i].resp = strdup (test->new_password);
				test->new_password = NULL;
			}
			g_assert (aresp[i].resp != NULL);
			break;
		case PAM_PROMPT_ECHO_ON:
			aresp[i].resp = strdup (test->password);
			g_assert (aresp[i].resp != NULL);
			break;
		case PAM_ERROR_MSG:
			fputs(msg[i]->msg, stderr);
			if (strlen(msg[i]->msg) > 0 &&
			    msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
				fputc('\n', stderr);
			break;
		case PAM_TEXT_INFO:
			fprintf(stdout, "# %s", msg[i]->msg);
			if (strlen(msg[i]->msg) > 0 &&
			    msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
				fputc('\n', stdout);
			break;
		default:
			return PAM_CONV_ERR;
		}
	}
	*resp = aresp;
	return PAM_SUCCESS;
}

static void
setup (Test *test,
       gconstpointer user_data)
{
	const gchar *pam_conf = user_data;
	GError *error = NULL;
	gchar *contents;
	gboolean found;
	gchar *filename;
	gchar *env;
	int ret;

	/* First check if we have the right pam config */
	filename = g_build_filename (SYSCONFDIR, "pam.d", pam_conf, NULL);
	g_file_get_contents (filename, &contents, NULL, &error);
	g_free (filename);

	if (error == NULL) {
		found = (strstr (contents, BUILDDIR) &&
		         strstr (contents, "pam_gnome_keyring.so"));
		g_free (contents);
		if (!found) {
			skip_test (test, "test pam config contents invalid");
			return;
		}
	} else if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
		g_error_free (error);
		skip_test (test, "missing test pam config");
		return;
	}

	g_assert_no_error (error);

	test->directory = egg_tests_create_scratch_directory (NULL, NULL);

	g_setenv ("XDG_RUNTIME_DIR", test->directory, TRUE);

	test->dbus = g_test_dbus_new (G_TEST_DBUS_NONE);
	g_test_dbus_up (test->dbus);

	test->conv.conv = conv_func;
	test->conv.appdata_ptr = test;
	ret = pam_start (pam_conf, g_get_user_name (), &test->conv, &test->ph);
	g_assert_cmpint (ret, ==, PAM_SUCCESS);

	g_unsetenv ("GNOME_KEYRING_CONTROL");

	g_assert_cmpint (pam_putenv (test->ph, "GSETTINGS_SCHEMA_DIR=" BUILDDIR "/schema"), ==, PAM_SUCCESS);
	g_assert_cmpint (pam_putenv (test->ph, "G_DEBUG=fatal-warnings,fatal-criticals"), ==, PAM_SUCCESS);

	env = g_strdup_printf ("GNOME_KEYRING_TEST_PATH=%s", test->directory);
	g_assert_cmpint (pam_putenv (test->ph, env), ==, PAM_SUCCESS);
	g_free (env);

	env = g_strdup_printf ("DBUS_SESSION_BUS_ADDRESS=%s", g_test_dbus_get_bus_address (test->dbus));
	g_assert_cmpint (pam_putenv (test->ph, env), ==, PAM_SUCCESS);
	g_free (env);

	test->connection = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
	g_assert_no_error (error);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	if (test->skipping)
		return;

	g_object_unref (test->connection);

	pam_end (test->ph, PAM_SUCCESS);

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

static gboolean
check_if_login_keyring_locked (Test *test)
{
	GVariant *retval;
	GError *error = NULL;
	GVariant *prop;
	gboolean ret;

	retval = g_dbus_connection_call_sync (test->connection,
	                                      "org.gnome.keyring",
	                                      "/org/freedesktop/secrets/collection/login",
	                                      "org.freedesktop.DBus.Properties",
	                                      "Get",
	                                      g_variant_new ("(ss)",
	                                                     "org.freedesktop.Secret.Collection", "Locked"),
	                                      G_VARIANT_TYPE ("(v)"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                                      NULL, &error);
	g_assert_no_error (error);
	g_variant_get (retval, "(@v)", &prop);
	ret = g_variant_get_boolean (g_variant_get_variant (prop));
	g_variant_unref (retval);

	return ret;
}

static gboolean
check_if_login_item_1_exists (Test *test)
{
	GVariant *retval;
	GError *error = NULL;
	gchar *remote;

	retval = g_dbus_connection_call_sync (test->connection,
	                                      "org.gnome.keyring",
	                                      "/org/freedesktop/secrets/collection/login/1",
	                                      "org.freedesktop.DBus.Properties",
	                                      "Get",
	                                      g_variant_new ("(ss)",
	                                                     "org.freedesktop.Secret.Item", "Locked"),
	                                      G_VARIANT_TYPE ("(v)"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                                      NULL, &error);

	if (error) {
		remote = g_dbus_error_get_remote_error (error);
		if (!remote || !g_str_equal (remote, "org.freedesktop.Secret.Error.NoSuchObject"))
			g_assert_no_error (error);
		g_error_free (error);
		return FALSE;
	}

	g_variant_unref (retval);
	return TRUE;
}

static void
test_starts_creates (Test *test,
                     gconstpointer user_data)
{
	const char *pam_conf = user_data;
	gboolean start_in_session;
	const gchar *control;
	gchar *login_keyring;

	if (test->skipping)
		return;

	/* We're testing that we create the directory appropriately */
	g_unsetenv ("XDG_RUNTIME_DIR");

	start_in_session = (strstr (pam_conf, "session") != NULL);

	login_keyring = g_build_filename (test->directory, "login.keyring", NULL);
	g_assert (!g_file_test (login_keyring, G_FILE_TEST_EXISTS));

	test->password = "booo";
	g_assert_cmpint (pam_authenticate (test->ph, 0), ==, PAM_SUCCESS);

	if (start_in_session)
		g_assert_cmpint (pam_open_session (test->ph, 0), ==, PAM_SUCCESS);

	g_assert (pam_getenv (test->ph, "GNOME_KEYRING_CONTROL") != NULL);
	control = pam_getenv (test->ph, "GNOME_KEYRING_CONTROL");

	/* Initialize the daemon for real */
	g_assert (gkd_control_initialize (control, "secrets", PASS_ENVIRON));

	/* The keyring was created */
	g_assert (g_file_test (login_keyring, G_FILE_TEST_IS_REGULAR));
	g_free (login_keyring);

	g_assert (check_if_login_keyring_locked (test) == FALSE);
	g_assert (check_if_login_item_1_exists (test) == FALSE);

	if (!start_in_session)
		g_assert_cmpint (pam_open_session (test->ph, 0), ==, PAM_SUCCESS);

	g_assert (gkd_control_quit (control, 0));
}

static void
test_starts_only_session (Test *test,
		          gconstpointer user_data)
{
	const char *pam_conf = user_data;
	const gchar *control;
	gchar *login_keyring;

	if (test->skipping)
		return;

	/* This is the PAM config that starts the daemon from session handler */
	g_assert (strstr (pam_conf, "session-start") != NULL);

	/* We're testing that we create the directory appropriately */
	g_unsetenv ("XDG_RUNTIME_DIR");

	login_keyring = g_build_filename (test->directory, "login.keyring", NULL);
	g_assert (!g_file_test (login_keyring, G_FILE_TEST_EXISTS));

	g_assert_cmpint (pam_open_session (test->ph, 0), ==, PAM_SUCCESS);

	g_assert (pam_getenv (test->ph, "GNOME_KEYRING_CONTROL") != NULL);
	control = pam_getenv (test->ph, "GNOME_KEYRING_CONTROL");

	/* These verify that the daemon was started */
	g_assert (gkd_control_quit (control, 0));
}

static void
test_starts_exists (Test *test,
                    gconstpointer user_data)
{
	const gchar *pam_conf = user_data;
	const gchar *control;
	gboolean start_in_session;

	if (test->skipping)
		return;

	/* We're testing that we create the directory appropriately */
	g_unsetenv ("XDG_RUNTIME_DIR");

	start_in_session = (strstr (pam_conf, "session") != NULL);

	egg_tests_copy_scratch_file (test->directory, SRCDIR "/pam/fixtures/login.keyring");

	test->password = "booo";
	g_assert_cmpint (pam_authenticate (test->ph, 0), ==, PAM_SUCCESS);

	if (start_in_session)
		g_assert_cmpint (pam_open_session (test->ph, 0), ==, PAM_SUCCESS);

	g_assert (pam_getenv (test->ph, "GNOME_KEYRING_CONTROL") != NULL);
	control = pam_getenv (test->ph, "GNOME_KEYRING_CONTROL");

	/* Initialize the daemon for real */
	g_assert (gkd_control_initialize (control, "secrets", PASS_ENVIRON));

	/* Lookup the item */
	g_assert (check_if_login_keyring_locked (test) == FALSE);
	g_assert (check_if_login_item_1_exists (test) == TRUE);

	if (!start_in_session)
		g_assert_cmpint (pam_open_session (test->ph, 0), ==, PAM_SUCCESS);

	g_assert (gkd_control_quit (control, 0));
}

static void
test_auth_nostart (Test *test,
                   gconstpointer user_data)
{
	gchar *login_keyring;

	if (test->skipping)
		return;

	test->password = "booo";
	g_assert_cmpint (pam_authenticate (test->ph, 0), ==, PAM_SUCCESS);

	g_assert (pam_getenv (test->ph, "GNOME_KEYRING_CONTROL") == NULL);

	login_keyring = g_build_filename (test->directory, "login.keyring", NULL);
	g_assert (!g_file_test (login_keyring, G_FILE_TEST_EXISTS));
	g_free (login_keyring);
}

static void
test_auth_running_unlocks (Test *test,
                           gconstpointer user_data)
{
	gchar *control;
	gchar **env;
	GPid pid;

	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground", NULL,
	};

	if (test->skipping)
		return;

	egg_tests_copy_scratch_file (test->directory, SRCDIR "/pam/fixtures/login.keyring");

	env = gkd_test_launch_daemon (test->directory, argv, &pid, NULL);

	g_assert (check_if_login_keyring_locked (test) == TRUE);

	test->password = "booo";
	g_assert_cmpint (pam_authenticate (test->ph, 0), ==, PAM_SUCCESS);

	/* Lookup the item */
	g_assert (check_if_login_keyring_locked (test) == FALSE);
	g_assert (check_if_login_item_1_exists (test) == TRUE);

	control = g_strdup_printf ("%s/keyring", test->directory);
	g_assert (gkd_control_quit (control, 0));
	g_assert_cmpint (waitpid (pid, NULL, 0), ==, pid);

	g_strfreev (env);
}

static void
test_password_changes_running (Test *test,
                               gconstpointer user_data)
{
	gchar *control;
	gchar **env;
	GPid pid;

	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground", NULL
	};

	if (test->skipping)
		return;

	egg_tests_copy_scratch_file (test->directory, SRCDIR "/pam/fixtures/login.keyring");
	control = g_strdup_printf ("%s/keyring", test->directory);

	env = gkd_test_launch_daemon (test->directory, argv, &pid, NULL);
	g_strfreev (env);

	test->password = "booo";
	test->new_password = "changed";
	g_assert_cmpint (pam_chauthtok (test->ph, 0), ==, PAM_SUCCESS);

	/* Quit the daemon */
	g_assert (gkd_control_quit (control, 0));
	g_assert_cmpint (waitpid (pid, NULL, 0), ==, pid);

	/* Start it again */
	env = gkd_test_launch_daemon (test->directory, argv, &pid, NULL);
	g_strfreev (env);

	g_assert (gkd_control_unlock (control, "changed"));
	g_assert (gkd_control_quit (control, 0));
	g_assert_cmpint (waitpid (pid, NULL, 0), ==, pid);

	g_free (control);
}

static void
test_password_changes_starts (Test *test,
                              gconstpointer user_data)
{
	gchar *control;
	gchar **env;
	GPid pid;

	const gchar *argv[] = {
		TEST_GKR_DAEMON_BIN, "--foreground", NULL,
	};

	if (test->skipping)
		return;

	egg_tests_copy_scratch_file (test->directory, SRCDIR "/pam/fixtures/login.keyring");
	control = g_strdup_printf ("%s/keyring", test->directory);

	test->password = "booo";
	test->new_password = "changed";
	g_assert_cmpint (pam_chauthtok (test->ph, 0), ==, PAM_SUCCESS);

	/* Start it again */
	env = gkd_test_launch_daemon (test->directory, argv, &pid,
	                              "GNOME_KEYRING_TEST_SERVICE", "another.Bus.Name",
	                              NULL);

	g_assert (gkd_control_unlock (control, "changed"));
	g_assert (gkd_control_quit (control, 0));
	g_assert_cmpint (waitpid (pid, NULL, 0), ==, pid);

	g_strfreev (env);
	g_free (control);
}

static void
test_password_change_start_in_session (Test *test,
                                       gconstpointer user_data)
{
	const char *pam_conf = user_data;
	gchar *control;

	if (test->skipping)
		return;

	/* This is the PAM config that starts the daemon from session handler */
	g_assert (strstr (pam_conf, "session-start") != NULL);

	egg_tests_copy_scratch_file (test->directory, SRCDIR "/pam/fixtures/login.keyring");
	control = g_strdup_printf ("%s/keyring", test->directory);

	/* First we authenticate, but don't start the keyring here */
	test->password = "booo";
	g_assert_cmpint (pam_authenticate (test->ph, 0), ==, PAM_SUCCESS);

	test->password = "booo";
	test->new_password = "changed";
	g_assert_cmpint (pam_chauthtok (test->ph, 0), ==, PAM_SUCCESS);

	/* No daemon should be running, chauthtok started/stopped it */
	g_assert (gkd_control_quit (control, GKD_CONTROL_QUIET_IF_NO_PEER) == FALSE);

	/* Now session should be able to start and unlock the keyring */
	g_assert_cmpint (pam_open_session (test->ph, 0), ==, PAM_SUCCESS);

	/* Initialize the daemon */
	g_assert (gkd_control_initialize (control, "secrets", PASS_ENVIRON));

	/* Lookup the item */
	g_assert (check_if_login_keyring_locked (test) == FALSE);
	g_assert (check_if_login_item_1_exists (test) == TRUE);

	g_assert (gkd_control_quit (control, 0));
	g_free (control);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/pam/auth-no-start", Test,
	            "gnome-keyring-test-no-start",
	            setup, test_auth_nostart, teardown);

	g_test_add ("/pam/auth-starts-creates-keyring", Test,
	            "gnome-keyring-test-auth-start",
	            setup, test_starts_creates, teardown);
	g_test_add ("/pam/session-starts-creates-keyring", Test,
	            "gnome-keyring-test-session-start",
	            setup, test_starts_creates, teardown);

	g_test_add ("/pam/auth-starts-unlocks-existing", Test,
	            "gnome-keyring-test-auth-start",
	            setup, test_starts_exists, teardown);
	g_test_add ("/pam/session-starts-unlocks-existing", Test,
	            "gnome-keyring-test-session-start",
	            setup, test_starts_exists, teardown);

	g_test_add ("/pam/session-starts-without-auth", Test,
	            "gnome-keyring-test-session-start",
	            setup, test_starts_only_session, teardown);

	g_test_add ("/pam/auth-running-unlocks-existing", Test,
	            "gnome-keyring-test-no-start",
	            setup, test_auth_running_unlocks, teardown);

	g_test_add ("/pam/password-changes-running", Test,
	            "gnome-keyring-test-no-start",
	            setup, test_password_changes_running, teardown);
	g_test_add ("/pam/password-changes-starts", Test,
	            "gnome-keyring-test-no-start",
	            setup, test_password_changes_starts, teardown);

	g_test_add ("/pam/password-change-start-in-session", Test,
	            "gnome-keyring-test-session-start",
	            setup, test_password_change_start_in_session, teardown);

	return g_test_run ();
}
