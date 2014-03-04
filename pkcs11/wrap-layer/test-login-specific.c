/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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
 */

#include "config.h"

#include "wrap-layer/gkm-wrap-layer.h"
#include "wrap-layer/gkm-wrap-prompt.h"

#include "egg/egg-testing.h"

#include "gkm/gkm-mock.h"
#include "gkm/gkm-test.h"

#include <gcr/gcr-base.h>

#include <glib-object.h>

typedef struct {
	CK_FUNCTION_LIST prompt_login_functions;
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	CK_FUNCTION_LIST_PTR funcs;
	CK_OBJECT_HANDLE key;
	CK_SLOT_ID slot_id;
	CK_ULONG n_slots = 1;
	const gchar *prompter;
	CK_ULONG count;
	CK_RV rv;

	CK_BBOOL always = TRUE;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_ALWAYS_AUTHENTICATE, &always, sizeof (always) }
	};

	CK_MECHANISM mech = { CKM_MOCK_PREFIX, NULL, 0 };

	/* Always start off with test functions */
	rv = gkm_mock_C_GetFunctionList (&funcs);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	memcpy (&test->prompt_login_functions, funcs, sizeof (test->prompt_login_functions));

	gkm_wrap_layer_reset_modules ();
	gkm_wrap_layer_add_module (&test->prompt_login_functions);
	test->module = gkm_wrap_layer_get_functions ();

	prompter = gcr_mock_prompter_start ();
	gkm_wrap_prompt_set_prompter_name (prompter);

	/* Open a test->session */
	rv = (test->module->C_Initialize) (NULL);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	rv = (test->module->C_GetSlotList) (CK_TRUE, &slot_id, &n_slots);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	rv = (test->module->C_OpenSession) (slot_id, CKF_SERIAL_SESSION, NULL, NULL, &test->session);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Find the always authenticate object */
	rv = (test->module->C_FindObjectsInit) (test->session, attrs, 1);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	rv = (test->module->C_FindObjects) (test->session, &key, 1, &count);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	gkm_assert_cmpulong (count, ==, 1);
	gkm_assert_cmpulong (key, !=, 0);

	rv = (test->module->C_FindObjectsFinal) (test->session);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Start a signing operation, that needs to be authenticated */
	rv = (test->module->C_SignInit) (test->session, &mech, key);
	gkm_assert_cmprv (rv, ==, CKR_OK);
}

static void
teardown (Test *test, gconstpointer unused)
{
	CK_RV rv;

	g_assert (!gcr_mock_prompter_is_expecting ());
	gcr_mock_prompter_stop ();

	rv = (test->module->C_CloseSession) (test->session);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	test->session = 0;

	rv = (test->module->C_Finalize) (NULL);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	test->module = NULL;
}

static void
test_ok_password (Test *test, gconstpointer unused)
{
	CK_RV rv;

	gcr_mock_prompter_expect_password_ok ("booo", NULL);

	rv = (test->module->C_Login) (test->session, CKU_CONTEXT_SPECIFIC, NULL, 0);
	gkm_assert_cmprv (rv, ==, CKR_OK);
}

static void
test_bad_password_then_cancel (Test *test, gconstpointer unused)
{
	CK_RV rv;

	gcr_mock_prompter_expect_password_ok ("bad password", NULL);
	gcr_mock_prompter_expect_password_cancel ();

	rv = (test->module->C_Login) (test->session, CKU_CONTEXT_SPECIFIC, NULL, 0);
	gkm_assert_cmprv (rv, ==, CKR_PIN_INCORRECT);
}

static void
test_cancel_immediately (Test *test, gconstpointer unused)
{
	CK_RV rv;

	gcr_mock_prompter_expect_password_cancel ();

	rv = (test->module->C_Login) (test->session, CKU_CONTEXT_SPECIFIC, NULL, 0);
	gkm_assert_cmprv (rv, ==, CKR_PIN_INCORRECT);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/wrap-layer/login-specific/ok_password", Test, NULL, setup, test_ok_password, teardown);
	g_test_add ("/wrap-layer/login-specific/bad_password_then_cancel", Test, NULL, setup, test_bad_password_then_cancel, teardown);
	g_test_add ("/wrap-layer/login-specific/cancel_immediately", Test, NULL, setup, test_cancel_immediately, teardown);

	return egg_tests_run_in_thread_with_loop ();
}
