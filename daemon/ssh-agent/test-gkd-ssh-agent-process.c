/*
 * gnome-keyring
 *
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daiki Ueno
 */

#include "config.h"

#include "gkd-ssh-agent-private.h"
#include "gkd-ssh-agent-process.h"
#include "gkd-ssh-agent-util.h"
#include "test-common.h"
#include "egg/egg-testing.h"

#include <glib.h>

typedef struct {
	gchar *directory;
	EggBuffer req;
	EggBuffer resp;
	GkdSshAgentProcess *process;
	GSocketConnection *connection;
	GMainLoop *loop;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	gchar *path;

	test->directory = egg_tests_create_scratch_directory (NULL, NULL);

	egg_buffer_init_full (&test->req, 128, (EggBufferAllocator)g_realloc);
	egg_buffer_init_full (&test->resp, 128, (EggBufferAllocator)g_realloc);

	path = g_strdup_printf ("%s/.ssh.sock", test->directory);
	test->process = gkd_ssh_agent_process_new (path);
	g_free (path);
	g_assert_nonnull (test->process);
	test->connection = NULL;
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_clear_object (&test->process);
	g_clear_object (&test->connection);

	egg_buffer_uninit (&test->req);
	egg_buffer_uninit (&test->resp);

	egg_tests_remove_scratch_directory (test->directory);
	free (test->directory);
}

static void
connect_to_process (Test *test)
{
	GError *error;

	error = NULL;
	test->connection = gkd_ssh_agent_process_connect (test->process, NULL, &error);
	g_assert_nonnull (test->connection);
	g_assert_no_error (error);
}

static void
test_connect (Test *test, gconstpointer unused)
{
	connect_to_process (test);
}

static void
call (Test *test)
{
	GError *error;
	gboolean ret;

	error = NULL;
	ret = _gkd_ssh_agent_call (test->connection, &test->req, &test->resp, NULL, &error);
	g_assert_true (ret);
	g_assert_no_error (error);
}

DEFINE_CALL_FUNCS(Test, call)

static void
test_list (Test *test, gconstpointer unused)
{
	connect_to_process (test);
	call_request_identities(test, 0);
}

static void
test_add (Test *test, gconstpointer unused)
{
	connect_to_process (test);
	call_add_identity (test);
	call_request_identities (test, 1);
}

static void
test_remove (Test *test, gconstpointer unused)
{
	connect_to_process (test);
	call_add_identity (test);
	call_request_identities (test, 1);

	call_remove_identity (test);
	call_request_identities (test, 0);
}

static void
test_remove_all (Test *test, gconstpointer unused)
{
	connect_to_process (test);
	call_add_identity (test);
	call_request_identities (test, 1);

	call_remove_all_identities (test);
	call_request_identities (test, 0);
}

static void
test_sign (Test *test, gconstpointer unused)
{
	connect_to_process (test);
	call_add_identity (test);
	call_request_identities (test, 1);

	call_sign (test);

	call_remove_all_identities (test);
	call_request_identities (test, 0);
}

static gpointer
kill_thread (gpointer data)
{
	Test *test = data;
	GPid pid;

	pid = gkd_ssh_agent_process_get_pid (test->process);
	g_assert_cmpint (-1, !=, pid);

	kill (pid, SIGTERM);

	return NULL;
}

static void
on_closed (GkdSshAgentProcess *self, gpointer data)
{
	GMainLoop *loop = data;

	g_main_loop_quit (loop);
	g_main_loop_unref (loop);
}

static void
test_restart (Test *test, gconstpointer unused)
{
	GPid pid;
	GMainLoop *loop;
	GThread *thread;

	connect_to_process (test);

	pid = gkd_ssh_agent_process_get_pid (test->process);
	g_assert_cmpint (0, !=, pid);

	thread = g_thread_new ("kill", kill_thread, test);

	loop = g_main_loop_new (NULL, FALSE);
	g_signal_connect (test->process, "closed", G_CALLBACK (on_closed), loop);
	g_main_loop_run (loop);

	g_thread_join (thread);

	pid = gkd_ssh_agent_process_get_pid (test->process);
	g_assert_cmpint (0, ==, pid);

	connect_to_process (test);

	pid = gkd_ssh_agent_process_get_pid (test->process);
	g_assert_cmpint (0, !=, pid);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/ssh-agent/process/connect", Test, NULL, setup, test_connect, teardown);
	g_test_add ("/ssh-agent/process/list", Test, NULL, setup, test_list, teardown);
	g_test_add ("/ssh-agent/process/add", Test, NULL, setup, test_add, teardown);
	g_test_add ("/ssh-agent/process/remove", Test, NULL, setup, test_remove, teardown);
	g_test_add ("/ssh-agent/process/remove_all", Test, NULL, setup, test_remove_all, teardown);
	g_test_add ("/ssh-agent/process/sign", Test, NULL, setup, test_sign, teardown);
	g_test_add ("/ssh-agent/process/restart", Test, NULL, setup, test_restart, teardown);

	return g_test_run ();
}
