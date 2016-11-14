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

#include <string.h>

extern CK_FUNCTION_LIST mock_secret_store;

typedef struct {
	CK_FUNCTION_LIST functions;
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;
	CK_OBJECT_HANDLE collection;
	CK_MECHANISM mech;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	CK_SLOT_ID slot_id;
	CK_ULONG n_slots = 1;
	CK_ULONG count;
	const gchar *prompter;
	CK_RV rv;

	CK_BBOOL always = TRUE;
	CK_ATTRIBUTE kattrs[] = {
		{ CKA_ALWAYS_AUTHENTICATE, &always, sizeof (always) }
	};

	CK_OBJECT_CLASS fklass = CKO_G_COLLECTION;
	CK_ATTRIBUTE fattrs[] = {
		{ CKA_CLASS, &fklass, sizeof (fklass) },
		{ CKA_ID, "other", 5 },
	};

	test->mech.mechanism = CKM_MOCK_PREFIX;

	/* Always start off with test test->functions */
	memcpy (&test->functions, &mock_secret_store, sizeof (test->functions));

	gkm_wrap_layer_reset_modules ();
	gkm_wrap_layer_add_module (&test->functions);
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

	/* Find keyring object */
	rv = (test->module->C_FindObjectsInit) (test->session, fattrs, 1);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	rv = (test->module->C_FindObjects) (test->session, &test->collection, 1, &count);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	gkm_assert_cmpulong (count, ==, 1);
	gkm_assert_cmpulong (test->collection, !=, 0);
	rv = (test->module->C_FindObjectsFinal) (test->session);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Find the test->key object */
	rv = (test->module->C_FindObjectsInit) (test->session, kattrs, 1);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	rv = (test->module->C_FindObjects) (test->session, &test->key, 1, &count);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	gkm_assert_cmpulong (count, ==, 1);
	gkm_assert_cmpulong (test->key, !=, 0);
	rv = (test->module->C_FindObjectsFinal) (test->session);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Start a signing operation, that needs to be authenticated */
	rv = (test->module->C_SignInit) (test->session, &test->mech, test->key);
	gkm_assert_cmprv (rv, ==, CKR_OK);
}

static void
teardown (Test *test, gconstpointer unused)
{
	CK_RV rv;

	g_assert (!gcr_mock_prompter_is_expecting ());
	gcr_mock_prompter_stop ();

	test->key = 0;
	test->collection = 0;

	rv = (test->module->C_CloseSession) (test->session);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	test->session = 0;

	rv = (test->module->C_Finalize) (NULL);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	test->module = NULL;
}

static void
test_specific (Test *test, gconstpointer unused)
{
	CK_RV rv;

	/* Login with prompt */
	gcr_mock_prompter_expect_password_ok ("booo",
	                                      "choice-label", "Automatically unlock this key whenever I’m logged in",
	                                      "choice-chosen", TRUE,
	                                      NULL);

	rv = (test->module->C_Login) (test->session, CKU_CONTEXT_SPECIFIC, NULL, 0);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Start a signing operation, that needs to be authenticated */
	rv = (test->module->C_SignInit) (test->session, &test->mech, test->key);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* No further prompting should be shown, uses stored password */
	g_assert (!gcr_mock_prompter_is_expecting ());

	rv = (test->module->C_Login) (test->session, CKU_CONTEXT_SPECIFIC, NULL, 0);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Change the password */
	gkm_mock_module_set_pin ("other");

	/* Start a signing operation, that needs to be authenticated */
	rv = (test->module->C_SignInit) (test->session, &test->mech, test->key);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* This should prompt again, as stored password is now wrong */
	gcr_mock_prompter_expect_password_ok ("other", NULL);

	rv = (test->module->C_Login) (test->session, CKU_CONTEXT_SPECIFIC, NULL, 0);
	gkm_assert_cmprv (rv, ==, CKR_OK);
}

static void
test_user_token (Test *test, gconstpointer unused)
{
	CK_RV rv;

	/* Login with prompt */
	gcr_mock_prompter_expect_password_ok ("booo",
	                                      "choice-label", "Automatically unlock whenever I’m logged in",
	                                      "choice-chosen", TRUE,
	                                      NULL);

	rv = (test->module->C_Login) (test->session, CKU_USER, NULL, 0);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	rv = (test->module->C_Logout) (test->session);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* No further prompting should be shown, uses stored password */
	g_assert (!gcr_mock_prompter_is_expecting ());

	rv = (test->module->C_Login) (test->session, CKU_USER, NULL, 0);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	rv = (test->module->C_Logout) (test->session);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Change the password */
	gkm_mock_module_set_pin ("other");

	/* This should prompt again, as stored password is now wrong */
	gcr_mock_prompter_expect_password_ok ("other", NULL);

	rv = (test->module->C_Login) (test->session, CKU_USER, NULL, 0);
	gkm_assert_cmprv (rv, ==, CKR_OK);
}

static void
test_unlock_keyring (Test *test, gconstpointer unused)
{
	CK_OBJECT_HANDLE credential;
	CK_RV rv;

	CK_OBJECT_CLASS klass = CKO_G_CREDENTIAL;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_VALUE, NULL, 0 },
		{ CKA_G_OBJECT, &test->collection, sizeof (test->collection) },
	};

	/* Create credential with prompt */
	gcr_mock_prompter_expect_password_ok ("booo",
	                                      "choice-label", "Automatically unlock this keyring whenever I’m logged in",
	                                      "choice-chosen", TRUE,
	                                      NULL);

	rv = (test->module->C_CreateObject) (test->session, attrs, G_N_ELEMENTS (attrs), &credential);
	gkm_assert_cmprv (rv, ==, CKR_OK);
	rv = (test->module->C_DestroyObject) (test->session, credential);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* No further prompting should be shown, uses stored password */
	g_assert (!gcr_mock_prompter_is_expecting ());

	rv = (test->module->C_CreateObject) (test->session, attrs, G_N_ELEMENTS (attrs), &credential);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	/* Change the password */
	gkm_mock_module_set_pin ("other");

	/* This should prompt again, as stored password is now wrong */
	gcr_mock_prompter_expect_password_ok ("other", NULL);

	rv = (test->module->C_CreateObject) (test->session, attrs, G_N_ELEMENTS (attrs), &credential);
	gkm_assert_cmprv (rv, ==, CKR_OK);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/wrap-layer/login-auto/specific", Test, NULL, setup, test_specific, teardown);
	g_test_add ("/wrap-layer/login-auto/user_token", Test, NULL, setup, test_user_token, teardown);
	g_test_add ("/wrap-layer/login-auto/unlock_keyring", Test, NULL, setup, test_unlock_keyring, teardown);

	return egg_tests_run_in_thread_with_loop ();
}
