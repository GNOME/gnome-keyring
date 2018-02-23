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

#include "gkd-ssh-agent-preload.h"
#include "egg/egg-testing.h"

#include <glib/gstdio.h>
#include <unistd.h>

typedef struct {
	gchar *directory;
	GkdSshAgentPreload *preload;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	test->directory = egg_tests_create_scratch_directory (NULL, NULL);

	egg_tests_copy_scratch_file (test->directory, SRCDIR "/pkcs11/ssh-store/fixtures/id_rsa_plain");
	egg_tests_copy_scratch_file (test->directory, SRCDIR "/pkcs11/ssh-store/fixtures/id_rsa_plain.pub");

	test->preload = gkd_ssh_agent_preload_new (test->directory);
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_object_unref (test->preload);

	egg_tests_remove_scratch_directory (test->directory);
	g_free (test->directory);
}

static void
test_list (Test *test, gconstpointer unused)
{
	GList *keys;

	keys = gkd_ssh_agent_preload_get_keys (test->preload);
	g_assert_cmpint (1, ==, g_list_length (keys));
	g_list_free_full (keys, (GDestroyNotify)gkd_ssh_agent_key_info_free);
}

static void
test_added (Test *test, gconstpointer unused)
{
	GList *keys;

	keys = gkd_ssh_agent_preload_get_keys (test->preload);
	g_assert_cmpint (1, ==, g_list_length (keys));
	g_list_free_full (keys, (GDestroyNotify)gkd_ssh_agent_key_info_free);

	/* Mtime must change so wait between tests */
	sleep (1);

	egg_tests_copy_scratch_file (test->directory, SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_plain");
	egg_tests_copy_scratch_file (test->directory, SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_plain.pub");

	keys = gkd_ssh_agent_preload_get_keys (test->preload);
	g_assert_cmpint (2, ==, g_list_length (keys));
	g_list_free_full (keys, (GDestroyNotify)gkd_ssh_agent_key_info_free);
}

static void
test_removed (Test *test, gconstpointer unused)
{
	GList *keys;
	gchar *path;

	keys = gkd_ssh_agent_preload_get_keys (test->preload);
	g_assert_cmpint (1, ==, g_list_length (keys));
	g_list_free_full (keys, (GDestroyNotify)gkd_ssh_agent_key_info_free);

	/* Mtime must change so wait between tests */
	sleep (1);

	path = g_build_filename (test->directory, "id_rsa_plain.pub", NULL);
	g_unlink (path);
	g_free (path);

	path = g_build_filename (test->directory, "id_rsa_plain", NULL);
	g_unlink (path);
	g_free (path);

	keys = gkd_ssh_agent_preload_get_keys (test->preload);
	g_assert_cmpint (0, ==, g_list_length (keys));
	g_list_free_full (keys, (GDestroyNotify)gkd_ssh_agent_key_info_free);
}

static void
test_changed (Test *test, gconstpointer unused)
{
	GList *keys;
	gchar *path;
	gchar *contents;
	gsize length;
	GError *error;
	gchar *p;
	gboolean ret;

	keys = gkd_ssh_agent_preload_get_keys (test->preload);
	g_assert_cmpint (1, ==, g_list_length (keys));
	g_list_free_full (keys, (GDestroyNotify)gkd_ssh_agent_key_info_free);

	/* Mtime must change so wait between tests */
	sleep (1);

	path = g_build_filename (test->directory, "id_rsa_plain.pub", NULL);
	error = NULL;
	ret = g_file_get_contents (path, &contents, &length, &error);
	g_assert_true (ret);
	g_assert_no_error (error);

#define COMMENT "comment"
	contents = g_realloc (contents, length + strlen (COMMENT) + 1);
	p = strchr (contents, '\n');
	g_assert_nonnull (p);
	memcpy (p, " " COMMENT "\n", strlen (COMMENT) + 2);
	error = NULL;
	ret = g_file_set_contents (path, contents, length + strlen (COMMENT), &error);
	g_assert_true (ret);
	g_assert_no_error (error);
	g_free (path);
	g_free (contents);

	keys = gkd_ssh_agent_preload_get_keys (test->preload);
	g_assert_cmpint (1, ==, g_list_length (keys));
	g_assert_cmpstr (COMMENT, ==, ((GkdSshAgentKeyInfo *)keys->data)->comment);
	g_list_free_full (keys, (GDestroyNotify)gkd_ssh_agent_key_info_free);
#undef COMMENT
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/ssh-agent/preload/list", Test, NULL, setup, test_list, teardown);
	g_test_add ("/ssh-agent/preload/added", Test, NULL, setup, test_added, teardown);
	g_test_add ("/ssh-agent/preload/removed", Test, NULL, setup, test_removed, teardown);
	g_test_add ("/ssh-agent/preload/changed", Test, NULL, setup, test_changed, teardown);

	return g_test_run ();
}
