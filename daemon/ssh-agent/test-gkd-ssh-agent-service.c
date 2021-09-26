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

#include "gkd-ssh-agent-service.h"
#include "gkd-ssh-agent-private.h"
#include "gkd-ssh-agent-util.h"
#include "test-common.h"
#include "egg/egg-testing.h"
#include "egg/mock-interaction.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gunixsocketaddress.h>

typedef struct {
	gchar *directory;
	EggBuffer req;
	EggBuffer resp;
	GkdSshAgentService *service;
	GMainContext *server_thread_context;
	gint server_thread_stop;  /* (atomic) */
	GSocketConnection *connection;
	GThread *thread;
	GMutex lock;
	GCond cond;
} Test;

static gpointer
server_thread (gpointer data)
{
	Test *test = data;
	gboolean ret;

	g_main_context_push_thread_default (test->server_thread_context);

	ret = gkd_ssh_agent_service_start (test->service);
	g_assert_true (ret);

	g_mutex_lock (&test->lock);
	g_cond_signal (&test->cond);
	g_mutex_unlock (&test->lock);

	while (g_atomic_int_get (&test->server_thread_stop) == 0)
		g_main_context_iteration (test->server_thread_context, TRUE);

	g_main_context_pop_thread_default (test->server_thread_context);

	return NULL;
}

static void
connect_to_server (Test *test)
{
	const gchar *envvar;
	GSocketClient *client;
	GSocketAddress *address;
	GError *error;

	envvar = g_getenv ("SSH_AUTH_SOCK");
	g_assert_nonnull (envvar);
	address = g_unix_socket_address_new (envvar);

	client = g_socket_client_new ();

	error = NULL;
	test->connection = g_socket_client_connect (client,
						    G_SOCKET_CONNECTABLE (address),
						    NULL,
						    &error);
	g_assert_nonnull (test->connection);
	g_assert_no_error (error);

	g_object_unref (address);
	g_object_unref (client);
}

static void
setup (Test *test, gconstpointer unused)
{
	GTlsInteraction *interaction;
	GkdSshAgentPreload *preload;
	gchar *sockets_path;
	gchar *preload_path;
	gchar *path;

	test->directory = egg_tests_create_scratch_directory (NULL, NULL);

	sockets_path = g_build_filename (test->directory, "sockets", NULL);
	g_mkdir (sockets_path, 0700);

	preload_path = g_build_filename (test->directory, "preload", NULL);
	g_mkdir (preload_path, 0700);

	egg_tests_copy_scratch_file (preload_path, SRCDIR "/pkcs11/ssh-store/fixtures/id_rsa_plain");
	egg_tests_copy_scratch_file (preload_path, SRCDIR "/pkcs11/ssh-store/fixtures/id_rsa_plain.pub");

	path = g_build_filename (preload_path, "id_rsa_plain", NULL);
	g_chmod (path, 0600);
	g_free (path);

	egg_buffer_init_full (&test->req, 128, (EggBufferAllocator)g_realloc);
	egg_buffer_init_full (&test->resp, 128, (EggBufferAllocator)g_realloc);

	interaction = mock_interaction_new ("password");
	preload = gkd_ssh_agent_preload_new (preload_path);
	g_free (preload_path);

	test->service = gkd_ssh_agent_service_new (sockets_path, interaction, preload);
	g_free (sockets_path);

	g_object_unref (interaction);
	g_object_unref (preload);

	g_mutex_init (&test->lock);
	g_cond_init (&test->cond);
	test->server_thread_context = g_main_context_new ();

	test->thread = g_thread_new ("ssh-agent", server_thread, test);

	/* Wait until the server is up */
	g_mutex_lock (&test->lock);
	g_cond_wait (&test->cond, &test->lock);
	g_mutex_unlock (&test->lock);
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_atomic_int_set (&test->server_thread_stop, 1);
	g_main_context_wakeup (test->server_thread_context);
	g_thread_join (test->thread);

	g_main_context_unref (test->server_thread_context);

	g_clear_object (&test->connection);

	gkd_ssh_agent_service_stop (test->service);
	g_object_unref (test->service);

	egg_buffer_uninit (&test->req);
	egg_buffer_uninit (&test->resp);

	egg_tests_remove_scratch_directory (test->directory);
	g_free (test->directory);

	g_cond_clear (&test->cond);
	g_mutex_clear (&test->lock);
}

static void
call (Test *test)
{
	GError *error;
	gboolean ret;

	error = NULL;
	ret = _gkd_ssh_agent_write_packet (test->connection, &test->req, NULL, &error);
	g_assert_true (ret);
	g_assert_no_error (error);

	error = NULL;
	ret = _gkd_ssh_agent_read_packet (test->connection, &test->resp, NULL, &error);
	g_assert_true (ret);
	g_assert_no_error (error);
}

static void
call_error_or_failure (Test *test, gint dom, gint code)
{
	GError *error;
	gboolean ret;

	error = NULL;
	ret = _gkd_ssh_agent_write_packet (test->connection, &test->req, NULL, &error);
	g_assert_true (ret);
	g_assert_no_error (error);

	error = NULL;
	ret = _gkd_ssh_agent_read_packet (test->connection, &test->resp, NULL, &error);
	if (ret)
		check_failure (&test->resp);
	else {
		g_assert_false (ret);
		g_assert_error (error, dom, code);
	}
}

DEFINE_CALL_FUNCS(Test, call)

static void
call_unparseable_add (Test *test)
{
	egg_buffer_reset (&test->req);
	egg_buffer_reset (&test->resp);

	prepare_add_identity (&test->req);
	egg_buffer_set_uint32 (&test->req, 5, 0x80000000);
	call_error_or_failure (test, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED);
}

static void
call_unparseable_remove (Test *test)
{
	egg_buffer_reset (&test->req);
	egg_buffer_reset (&test->resp);

	prepare_remove_identity (&test->req);
	egg_buffer_set_uint32 (&test->req, 5, 0x80000000);
	call_error_or_failure (test, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED);
}

static void
call_unparseable_sign (Test *test)
{
	egg_buffer_reset (&test->req);
	egg_buffer_reset (&test->resp);

	prepare_sign_request (&test->req);
	egg_buffer_set_uint32 (&test->req, 5, 0x80000000);
	call_error_or_failure (test, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED);
}

static void
prepare_sign_request_unknown (EggBuffer *req)
{
	GBytes *public_key;
	gchar *comment;
	gsize length;
	const guchar *blob;
	gboolean ret;

	public_key = public_key_from_file (SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_plain.pub", &comment);
	g_free (comment);
	blob = g_bytes_get_data (public_key, &length);

	egg_buffer_reset (req);
	ret = egg_buffer_add_uint32 (req, 0);
	g_assert_true (ret);

	ret = egg_buffer_add_byte (req, GKD_SSH_OP_SIGN_REQUEST);
	g_assert_true (ret);

	ret = egg_buffer_add_byte_array (req, blob, length);
	g_assert_true (ret);

	ret = egg_buffer_add_string (req, "data");
	g_assert_true (ret);

	ret = egg_buffer_add_uint32 (req, 0);
	g_assert_true (ret);

	ret = egg_buffer_set_uint32 (req, 0, req->len - 4);
	g_assert_true (ret);

	g_bytes_unref (public_key);
}

static void
call_sign_unknown (Test *test)
{
	egg_buffer_reset (&test->req);
	egg_buffer_reset (&test->resp);

	prepare_sign_request_unknown (&test->req);
	call (test);
	check_failure (&test->resp);
}

static void
call_empty (Test *test)
{
	GError *error;
	gboolean ret;

	egg_buffer_reset (&test->req);
	egg_buffer_reset (&test->resp);

	ret = egg_buffer_add_uint32 (&test->req, 0);
	g_assert_true (ret);

	error = NULL;
	ret = _gkd_ssh_agent_write_packet (test->connection, &test->req, NULL, &error);
	g_assert_true (ret);
	g_assert_no_error (error);

	error = NULL;
	ret = _gkd_ssh_agent_read_packet (test->connection, &test->resp, NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED);
}

static void
call_unknown (Test *test)
{
	GError *error;
	gboolean ret;

	egg_buffer_reset (&test->req);
	egg_buffer_reset (&test->resp);

	ret = egg_buffer_add_uint32 (&test->req, 0);
	g_assert_true (ret);

	ret = egg_buffer_add_byte (&test->req, 255);
	g_assert_true (ret);

	error = NULL;
	ret = _gkd_ssh_agent_write_packet (test->connection, &test->req, NULL, &error);
	g_assert_true (ret);
	g_assert_no_error (error);

	error = NULL;
	ret = _gkd_ssh_agent_read_packet (test->connection, &test->resp, NULL, &error);
	g_assert_true (ret);
	g_assert_no_error (error);

	check_failure (&test->resp);
}

static void
call_lock (Test *test)
{
	gboolean ret;

	egg_buffer_reset (&test->req);
	egg_buffer_reset (&test->resp);

	ret = egg_buffer_add_uint32 (&test->req, 0);
	g_assert_true (ret);

	ret = egg_buffer_add_byte (&test->req, GKD_SSH_OP_LOCK);
	g_assert_true (ret);

	ret = egg_buffer_add_string (&test->req, "password");
	g_assert_true (ret);

	ret = egg_buffer_set_uint32 (&test->req, 0, test->req.len - 4);
	g_assert_true (ret);

	call (test);

	check_success (&test->resp);
}

static void
call_unlock (Test *test)
{
	gboolean ret;

	egg_buffer_reset (&test->req);
	egg_buffer_reset (&test->resp);

	ret = egg_buffer_add_uint32 (&test->req, 0);
	g_assert_true (ret);

	ret = egg_buffer_add_byte (&test->req, GKD_SSH_OP_UNLOCK);
	g_assert_true (ret);

	ret = egg_buffer_add_string (&test->req, "password");
	g_assert_true (ret);

	ret = egg_buffer_set_uint32 (&test->req, 0, test->req.len - 4);
	g_assert_true (ret);

	call (test);

	check_success (&test->resp);
}

static void
test_startup_shutdown (Test *test, gconstpointer unused)
{
}

static void
test_list (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	call_request_identities (test, 1);
}

static void
test_add (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	/* Adding an identity from the preloaded location doesn't
	 * change the total number of keys returned from
	 * GKD_SSH_OP_REQUEST_IDENTITIES */
	call_add_identity (test);
	call_request_identities (test, 1);
}

static void
test_unparseable_add (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	call_unparseable_add (test);
}

static void
test_unparseable_remove (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	call_unparseable_remove (test); /* This closes the connection */
}

static void
test_unparseable_sign (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	call_unparseable_sign (test); /* This closes the connection */
}

static void
test_remove (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	/* Adding an identity from the preloaded location doesn't
	 * change the total number of keys returned from
	 * GKD_SSH_OP_REQUEST_IDENTITIES */
	call_add_identity (test);
	call_request_identities (test, 1);

	/* Removing an identity from the preloaded location doesn't
	 * change the total number of keys returned from
	 * GKD_SSH_OP_REQUEST_IDENTITIES */
	call_remove_identity (test);
	call_request_identities (test, 1);
}

static void
test_remove_all (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	/* Adding an identity from the preloaded location doesn't
	 * change the total number of keys returned from
	 * GKD_SSH_OP_REQUEST_IDENTITIES */
	call_add_identity (test);
	call_request_identities (test, 1);

	/* Removing an identity from the preloaded location doesn't
	 * change the total number of keys returned from
	 * GKD_SSH_OP_REQUEST_IDENTITIES */
	call_remove_all_identities (test);
	call_request_identities (test, 1);
}

static void
test_sign_loaded (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	/* Adding an identity from the preloaded location doesn't
	 * change the total number of keys returned from
	 * GKD_SSH_OP_REQUEST_IDENTITIES */
	call_add_identity (test);
	call_request_identities (test, 1);

	call_sign (test);
}

static void
test_sign (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	call_sign (test);
}

static void
test_sign_unknown (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	call_sign_unknown (test);
}

static gpointer
kill_thread (gpointer data)
{
	Test *test = data;
	GkdSshAgentProcess *process;
	GPid pid;

	process = gkd_ssh_agent_service_get_process (test->service);
	pid = gkd_ssh_agent_process_get_pid (process);
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
	GkdSshAgentProcess *process;
	GThread *thread;
	GMainLoop *loop;
	GBytes *public_key;
	gchar *comment;

	connect_to_server (test);

	public_key = public_key_from_file (SRCDIR "/pkcs11/ssh-store/fixtures/id_rsa_plain.pub", &comment);
	g_free (comment);

	call_add_identity (test);
	call_request_identities (test, 1);

	g_assert_true (gkd_ssh_agent_service_lookup_key (test->service, public_key));

	thread = g_thread_new ("kill", kill_thread, test);

	loop = g_main_loop_new (NULL, FALSE);

	process = gkd_ssh_agent_service_get_process (test->service);
	g_signal_connect (process, "closed", G_CALLBACK (on_closed), loop);
	g_main_loop_run (loop);

	g_thread_join (thread);

	g_assert_false (gkd_ssh_agent_service_lookup_key (test->service, public_key));

	call_add_identity (test);
	call_request_identities (test, 1);

	g_assert_true (gkd_ssh_agent_service_lookup_key (test->service, public_key));
	g_bytes_unref (public_key);
}

static void
test_empty (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	call_empty (test);
}

static void
test_unknown (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	call_unknown (test);
}

static void
test_lock (Test *test, gconstpointer unused)
{
	connect_to_server (test);

	call_lock (test);
	call_unlock (test);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/ssh-agent/service/startup_shutdown", Test, NULL, setup, test_startup_shutdown, teardown);
	g_test_add ("/ssh-agent/service/list", Test, NULL, setup, test_list, teardown);
	g_test_add ("/ssh-agent/service/add", Test, NULL, setup, test_add, teardown);
	g_test_add ("/ssh-agent/service/remove", Test, NULL, setup, test_remove, teardown);
	g_test_add ("/ssh-agent/service/remove_all", Test, NULL, setup, test_remove_all, teardown);
	g_test_add ("/ssh-agent/service/sign_loaded", Test, NULL, setup, test_sign_loaded, teardown);
	g_test_add ("/ssh-agent/service/sign", Test, NULL, setup, test_sign, teardown);
	g_test_add ("/ssh-agent/service/sign_unknown", Test, NULL, setup, test_sign_unknown, teardown);
	g_test_add ("/ssh-agent/service/empty", Test, NULL, setup, test_empty, teardown);
	g_test_add ("/ssh-agent/service/unknown", Test, NULL, setup, test_unknown, teardown);
	g_test_add ("/ssh-agent/service/unparseable_add", Test, NULL, setup, test_unparseable_add, teardown);
	g_test_add ("/ssh-agent/service/unparseable_remove", Test, NULL, setup, test_unparseable_remove, teardown);
	g_test_add ("/ssh-agent/service/unparseable_sign", Test, NULL, setup, test_unparseable_sign, teardown);
	g_test_add ("/ssh-agent/service/restart", Test, NULL, setup, test_restart, teardown);
	g_test_add ("/ssh-agent/service/lock", Test, NULL, setup, test_lock, teardown);

	return g_test_run ();
}
