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
#include "gkd-ssh-agent-interaction.h"
#include "daemon/login/gkd-login-password.h"
#include "egg/egg-testing.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gcr/gcr-base.h>

typedef struct {
	const gchar *prompter_name;
	GTlsPassword *password;
} Test;

static void
setup (Test *test, gboolean login_available)
{
	GTlsPassword *password;

	password = g_tls_password_new (G_TLS_PASSWORD_NONE, "");
	test->password = g_object_new (GKD_TYPE_LOGIN_PASSWORD,
				       "base", password,
				       "login-available", login_available,
				       "description", "ssh-key",
				       NULL);
	g_object_unref (password);

	test->prompter_name = gcr_mock_prompter_start ();
}

static void
setup_no_login (Test *test, gconstpointer unused)
{
	setup (test, FALSE);
}

static void
setup_login (Test *test, gconstpointer unused)
{
	setup (test, TRUE);
}

static void
teardown (Test *test, gconstpointer unused)
{
	gcr_mock_prompter_stop ();

	g_object_unref (test->password);
}

static void
on_async_result (GObject *source_object,
		 GAsyncResult *result,
		 gpointer user_data)
{
        GAsyncResult **ret = user_data;
        *ret = g_object_ref (result);
	egg_test_wait_stop ();
}

static void
test_ask_password_no_login (Test *test, gconstpointer unused)
{
	GTlsInteraction *interaction;
	GAsyncResult *result = NULL;
	GError *error = NULL;
	const guchar *value;
	gsize length;
	GTlsInteractionResult ret;

	interaction = gkd_ssh_agent_interaction_new (test->prompter_name);
	gcr_mock_prompter_expect_password_ok ("password", NULL);
	g_tls_interaction_ask_password_async (interaction,
					      test->password,
					      NULL,
					      on_async_result,
					      &result);
	g_assert (result == NULL);

	egg_test_wait ();

	g_assert (result != NULL);

	ret = g_tls_interaction_ask_password_finish (interaction, result, &error);
	g_assert_cmpint (ret, ==, G_TLS_INTERACTION_HANDLED);
	g_assert_no_error (error);

	value = g_tls_password_get_value (test->password, &length);
	g_assert_cmpmem ("password", 8, value, length);
	g_assert_false (gkd_login_password_get_store_password (GKD_LOGIN_PASSWORD (test->password)));
	g_object_unref (interaction);
	g_object_unref (result);
}

static void
test_ask_password_login (Test *test, gconstpointer unused)
{
	GTlsInteraction *interaction;
	GAsyncResult *result = NULL;
	GError *error = NULL;
	const guchar *value;
	gsize length;
	GTlsInteractionResult ret;

	interaction = gkd_ssh_agent_interaction_new (test->prompter_name);
	gcr_mock_prompter_expect_password_ok ("password", "choice-chosen", TRUE, NULL);
	g_tls_interaction_ask_password_async (interaction,
					      test->password,
					      NULL,
					      on_async_result,
					      &result);
	g_assert (result == NULL);

	egg_test_wait ();

	ret = g_tls_interaction_ask_password_finish (interaction, result, &error);
	g_assert_cmpint (ret, ==, G_TLS_INTERACTION_HANDLED);
	g_assert_no_error (error);

	value = g_tls_password_get_value (test->password, &length);
	g_assert_cmpmem ("password", 8, value, length);
	g_assert_true (gkd_login_password_get_store_password (GKD_LOGIN_PASSWORD (test->password)));
	g_object_unref (interaction);
	g_object_unref (result);
}

static void
test_ask_password_cancel (Test *test, gconstpointer unused)
{
	GTlsInteraction *interaction;
	GAsyncResult *result = NULL;
	GError *error = NULL;
	const guchar *value;
	gsize length;
	GTlsInteractionResult ret;

	interaction = gkd_ssh_agent_interaction_new (test->prompter_name);
	gcr_mock_prompter_expect_password_cancel ();
	g_tls_interaction_ask_password_async (interaction,
					      test->password,
					      NULL,
					      on_async_result,
					      &result);
	g_assert (result == NULL);

	egg_test_wait ();

	g_assert (result != NULL);


	ret = g_tls_interaction_ask_password_finish (interaction, result, &error);
	g_assert_cmpint (ret, ==, G_TLS_INTERACTION_FAILED);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);

	value = g_tls_password_get_value (test->password, &length);
	g_assert_cmpmem ("", 0, value, length);
	g_assert_false (gkd_login_password_get_store_password (GKD_LOGIN_PASSWORD (test->password)));
	g_object_unref (interaction);
	g_object_unref (result);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/ssh-agent/interaction/ask_password_no_login", Test, NULL, setup_no_login, test_ask_password_no_login, teardown);
	g_test_add ("/ssh-agent/interaction/ask_password_login", Test, NULL, setup_login, test_ask_password_login, teardown);
	g_test_add ("/ssh-agent/interaction/ask_password_cancel", Test, NULL, setup_no_login, test_ask_password_cancel, teardown);

	return egg_tests_run_with_loop ();
}
