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

#include "egg/egg-testing.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <errno.h>

gchar **
gkd_test_launch_daemon (const gchar *directory,
                        const gchar **argv,
                        GPid *pid,
                        ...)
{
	GError *error = NULL;
	GString *output;
	gchar **env;
	gsize len;
	gssize ret;
	int out_fd;
	gchar **result;
	gchar *cmd;
	va_list va;
	const gchar *name;
	const gchar *value;

	env = g_get_environ ();
	env = g_environ_setenv (env, "GSETTINGS_SCHEMA_DIR", BUILDDIR "/schema", TRUE);
	env = g_environ_setenv (env, "GNOME_KEYRING_TEST_PATH", directory, TRUE);
	env = g_environ_setenv (env, "XDG_RUNTIME_DIR", directory, TRUE);
	env = g_environ_setenv (env, "G_DEBUG", "fatal-warnings,fatal-criticals", FALSE);

	va_start (va, pid);
	for (;;) {
		name = va_arg (va, const gchar *);
		if (!name)
			break;
		value = va_arg (va, const gchar *);
		if (value)
			env = g_environ_setenv (env, name, value, TRUE);
		else
			env = g_environ_unsetenv (env, name);
	}
	va_end (va);

	if (g_test_verbose ()) {
		cmd = g_strjoinv (" ", (gchar **)argv);
		g_print ("$ %s\n", cmd);
		g_free (cmd);
	}

	if (!g_spawn_async_with_pipes (NULL, (gchar **)argv, env,
	                               G_SPAWN_LEAVE_DESCRIPTORS_OPEN | G_SPAWN_DO_NOT_REAP_CHILD,
	                               NULL, NULL, pid, NULL, &out_fd, NULL, &error)) {
		g_error ("couldn't start gnome-keyring-daemon for testing: %s", error->message);
	}

	g_strfreev (env);

	/* The entire stdout of the daemon is environment variables */
	output = g_string_new ("");
	for (;;) {
		len = output->len;
		g_string_set_size (output, len + 1024);
		ret = read (out_fd, output->str + len, 1024);
		if (ret < 0)
			g_assert_cmpint (ret, ==, EAGAIN);
		if (g_test_verbose ())
			g_print ("%.*s", (int)ret, output->str + len);
		g_string_set_size (output, len + ret);
		if (ret == 0)
			break;
	}
	close (out_fd);

	result = g_strsplit (output->str, "\n", -1);
	g_string_free (output, TRUE);
	return result;
}
