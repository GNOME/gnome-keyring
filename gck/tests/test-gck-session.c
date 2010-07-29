#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test-suite.h"

#include <glib.h>

#include "gck-test.h"

static GckModule *module = NULL;
static GckSlot *slot = NULL;
static GckSession *session = NULL;

DEFINE_SETUP(load_session)
{
	GError *err = NULL;
	GList *slots;

	/* Successful load */
	module = gck_module_initialize (".libs/libgck-test-module.so", NULL, &err);
	SUCCESS_RES (module, err);

	slots = gck_module_get_slots (module, TRUE);
	g_assert (slots != NULL);

	slot = GCK_SLOT (slots->data);
	g_object_ref (slot);
	gck_list_unref_free (slots);

	session = gck_slot_open_session (slot, 0, &err);
	SUCCESS_RES(session, err);
}

DEFINE_TEARDOWN(load_session)
{
	g_object_unref (session);
	g_object_unref (slot);
	g_object_unref (module);
}

DEFINE_TEST(session_props)
{
	GckModule *mod;
	GckSlot *sl;
	gulong handle;

	g_object_get (session, "module", &mod, "handle", &handle, "slot", &sl, NULL);
	g_assert (mod == module);
	g_assert (sl == slot);
	g_object_unref (mod);
	g_object_unref (sl);

	g_assert (handle != 0);
	g_assert (gck_session_get_handle (session) == handle);
}

DEFINE_TEST(session_info)
{
	GckSessionInfo *info;

	info = gck_session_get_info (session);
	g_assert (info != NULL && "no session info");

	g_assert (info->slot_id == gck_slot_get_handle (slot));
	g_assert ((info->flags & CKF_SERIAL_SESSION) == CKF_SERIAL_SESSION);
	g_assert (info->device_error == 1414);
	gck_session_info_free (info);
}

static void
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
	testing_wait_stop ();
}

DEFINE_TEST(open_close_session)
{
	GckSession *sess;
	GAsyncResult *result = NULL;
	GError *err = NULL;

	sess = gck_slot_open_session_full (slot, 0, NULL, NULL, NULL, &err);
	SUCCESS_RES (sess, err);

	g_object_unref (sess);

	/* Test opening async */
	gck_slot_open_session_async (slot, 0, NULL, NULL, NULL, fetch_async_result, &result);

	testing_wait_until (500);
	g_assert (result != NULL);

	/* Get the result */
	sess = gck_slot_open_session_finish (slot, result, &err);
	SUCCESS_RES (sess, err);

	g_object_unref (result);
	g_object_unref (sess);
}

DEFINE_TEST(open_reused)
{
	CK_OBJECT_HANDLE handle;
	GckSession *sess, *sess2;
	GAsyncResult *result = NULL;
	GError *err = NULL;
	gboolean value;

	g_assert (gck_module_get_pool_sessions (module) == FALSE);
	gck_module_set_pool_sessions (module, TRUE);
	g_assert (gck_module_get_pool_sessions (module) == TRUE);
	g_object_get (module, "pool-sessions", &value, NULL);
	g_assert (value == TRUE);

	sess = gck_slot_open_session (slot, 0, &err);
	SUCCESS_RES (sess, err);
	if (!sess) return;

	/* Make note of the handle we saw */
	handle = gck_session_get_handle (sess);
	g_object_unref (sess);

	/* Open again, and see if the same handle */
	sess = gck_slot_open_session (slot, 0, &err);
	SUCCESS_RES (sess, err);
	if (!sess) return;
	g_assert (handle == gck_session_get_handle (sess));
	g_object_unref (sess);

	/* Test opening async */
	gck_slot_open_session_async (slot, 0, NULL, NULL, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	sess = gck_slot_open_session_finish (slot, result, &err);
	SUCCESS_RES (sess, err);
	if (!sess) return;
	g_assert (handle == gck_session_get_handle (sess));
	g_object_unref (result);
	g_object_unref (sess);

	/* Test opening with different flags, a different session should be returned */
	sess = gck_slot_open_session (slot, CKF_RW_SESSION, &err);
	SUCCESS_RES (sess, err);
	if (!sess) return;
	g_assert (handle != gck_session_get_handle (sess));

	/* Now open a second session, with same flags, shouldn't return the same */
	sess2 = gck_slot_open_session (slot, CKF_RW_SESSION, &err);
	SUCCESS_RES (sess2, err);
	if (!sess2) return;
	g_assert (gck_session_get_handle (sess) != gck_session_get_handle (sess2));

	g_object_set (module, "pool-sessions", FALSE, NULL);
	g_assert (gck_module_get_pool_sessions (module) == FALSE);

	g_object_unref (sess);
	g_object_unref (sess2);
}


DEFINE_TEST(init_set_pin)
{
	GAsyncResult *result = NULL;
	GError *err = NULL;
	gboolean ret;

	/* init pin */
	ret = gck_session_init_pin (session, (guchar*)"booo", 4, &err);
	SUCCESS_RES (ret, err);

	/* set pin */
	ret = gck_session_set_pin (session, (guchar*)"booo", 4, (guchar*)"tooo", 4, &err);
	SUCCESS_RES (ret, err);

	/* init pin async */
	gck_session_init_pin_async (session, (guchar*)"booo", 4, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	ret = gck_session_init_pin_finish (session, result, &err);
	SUCCESS_RES (ret, err);
	g_object_unref (result);
	result = NULL;

	/* set pin async */
	gck_session_set_pin_async (session, (guchar*)"booo", 4, (guchar*)"tooo", 4, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	ret = gck_session_set_pin_finish (session, result, &err);
	SUCCESS_RES (ret, err);
	g_object_unref (result);
	result = NULL;
}


DEFINE_TEST(login_logout)
{
	GAsyncResult *result = NULL;
	GError *err = NULL;
	gboolean ret;

	/* login/logout */
	ret = gck_session_login (session, CKU_USER, (guchar*)"booo", 4, &err);
	SUCCESS_RES (ret, err);

	ret = gck_session_logout (session, &err);
	SUCCESS_RES (ret, err);

	/* login/logout full */
	ret = gck_session_login_full (session, CKU_USER, (guchar*)"booo", 4, NULL, &err);
	SUCCESS_RES (ret, err);

	ret = gck_session_logout_full (session, NULL, &err);
	SUCCESS_RES (ret, err);

	/* login async */
	gck_session_login_async (session, CKU_USER, (guchar*)"booo", 4, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);

	ret = gck_session_login_finish (session, result, &err);
	SUCCESS_RES (ret, err);

	g_object_unref (result);
	result = NULL;

	/* logout async */
	gck_session_logout_async (session, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);

	ret = gck_session_logout_finish (session, result, &err);
	SUCCESS_RES (ret, err);

	g_object_unref (result);
	result = NULL;

}

static gboolean
authenticate_token (GckModule *module, GckSlot *slot, gchar *label, gchar **password, gpointer unused)
{
	g_assert (unused == GUINT_TO_POINTER (35));
	g_assert (password != NULL);
	g_assert (*password == NULL);
	g_assert (GCK_IS_MODULE (module));
	g_assert (GCK_IS_SLOT (slot));

	*password = g_strdup ("booo");
	return TRUE;
}

DEFINE_TEST(auto_login)
{
	GckObject *object;
	GckSession *new_session;
	GAsyncResult *result = NULL;
	GError *err = NULL;
	GckAttributes *attrs;
	gboolean ret;
	gint value;

	attrs = gck_attributes_newv (CKA_CLASS, GCK_ULONG, CKO_DATA,
	                              CKA_LABEL, GCK_STRING, "TEST OBJECT",
	                              CKA_PRIVATE, GCK_BOOLEAN, CK_TRUE,
	                              GCK_INVALID);

	/* Try to do something that requires a login */
	object = gck_session_create_object_full (session, attrs, NULL, &err);
	g_assert (!object);
	g_assert (err && err->code == CKR_USER_NOT_LOGGED_IN);
	g_clear_error (&err);

	/* Setup for auto login */
	g_assert (gck_module_get_auto_authenticate (module) == 0);
	gck_module_set_auto_authenticate (module, TRUE);
	g_assert (gck_module_get_auto_authenticate (module) == (GCK_AUTHENTICATE_TOKENS | GCK_AUTHENTICATE_OBJECTS));
	g_object_get (module, "auto-authenticate", &value, NULL);
	g_assert (value == (GCK_AUTHENTICATE_TOKENS | GCK_AUTHENTICATE_OBJECTS));

	g_signal_connect (module, "authenticate-slot", G_CALLBACK (authenticate_token), GUINT_TO_POINTER (35));

	/* Create a new session */
	new_session = gck_slot_open_session (slot, CKF_RW_SESSION, &err);
	SUCCESS_RES (new_session, err);
	g_object_unref (new_session);

	/* Try again to do something that requires a login */
	object = gck_session_create_object_full (session, attrs, NULL, &err);
	SUCCESS_RES (object, err);
	g_object_unref (object);

	/* We should now be logged in, try to log out */
	ret = gck_session_logout (session, &err);
	SUCCESS_RES (ret, err);

	/* Now try the same thing, but asyncronously */
	gck_slot_open_session_async (slot, CKF_RW_SESSION, NULL, NULL, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	new_session = gck_slot_open_session_finish (slot, result, &err);
	SUCCESS_RES (new_session, err);
	g_object_unref (result);
	g_object_unref (new_session);

	result = NULL;
	gck_session_create_object_async (session, attrs, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	object = gck_session_create_object_finish (session, result, &err);
	SUCCESS_RES (object, err);
	g_object_unref (result);
	g_object_unref (object);

	/* We should now be logged in, try to log out */
	ret = gck_session_logout (session, &err);
	SUCCESS_RES (ret, err);

	g_object_set (module, "auto-authenticate", FALSE, NULL);
	g_assert (gck_module_get_auto_authenticate (module) == FALSE);
}
