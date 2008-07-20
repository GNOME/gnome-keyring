#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "run-auto-test.h"

#include <glib.h>

#include "gp11-test.h"

static GP11Module *module = NULL;
static GP11Slot *slot = NULL;
static GP11Session *session = NULL;

DEFINE_SETUP(load_session)
{
	GError *err = NULL;
	GList *slots;
	
	/* Successful load */
	module = gp11_module_initialize (".libs/libgp11-test-module.so", &err);
	SUCCESS_RES (module, err);
	
	slots = gp11_module_get_slots (module, TRUE);
	g_assert (slots != NULL);
	
	slot = GP11_SLOT (slots->data);
	g_object_ref (slot);
	gp11_list_unref_free (slots);

	session = gp11_slot_open_session (slot, 0, &err);
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
	GP11Module *mod;
	guint handle;
	
	g_object_get (session, "module", &mod, "handle", &handle, NULL);
	g_assert (mod == module);
	g_object_unref (mod);
	
	g_assert (handle != 0);
	g_assert (session->handle == handle);
}

DEFINE_TEST(session_info)
{
	GP11SessionInfo *info;
	
	info = gp11_session_get_info (session);
	g_assert (info != NULL && "no session info");
	
	g_assert (info->slot_id == slot->handle); 
	g_assert ((info->flags & CKF_SERIAL_SESSION) == CKF_SERIAL_SESSION); 
	g_assert (info->device_error == 1414); 
	gp11_session_info_free (info);
}

static void 
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
}

DEFINE_TEST(open_close_session)
{
	GP11Session *sess;
	GAsyncResult *result = NULL;
	GError *err = NULL;
	
	sess = gp11_slot_open_session_full (slot, 0, NULL, &err);
	SUCCESS_RES (sess, err);
	
	g_object_unref (sess);
	
	/* Test opening async */
	gp11_slot_open_session_async (slot, 0, NULL, fetch_async_result, &result);
	
	WAIT_UNTIL (result);
	g_assert (result != NULL);
	
	/* Get the result */
	sess = gp11_slot_open_session_finish (slot, result, &err);
	SUCCESS_RES (sess, err);
	
	g_object_unref (result);
	g_object_unref (sess);
}

DEFINE_TEST(open_reused)
{
	CK_OBJECT_HANDLE handle;
	GP11Session *sess, *sess2;
	GAsyncResult *result = NULL;
	GError *err = NULL;
	
	g_assert (gp11_slot_get_reuse_sessions (slot) == FALSE);
	gp11_slot_set_reuse_sessions (slot, TRUE);
	g_assert (gp11_slot_get_reuse_sessions (slot) == TRUE);
	
	sess = gp11_slot_open_session (slot, 0, &err);
	SUCCESS_RES (sess, err);
	if (!sess) return;

	/* Make note of the handle we saw */
	handle = sess->handle;
	g_object_unref (sess);
	
	/* Open again, and see if the same handle */
	sess = gp11_slot_open_session (slot, 0, &err);
	SUCCESS_RES (sess, err);
	if (!sess) return;
	g_assert (handle == sess->handle);
	g_object_unref (sess);
	
	/* Test opening async */
	gp11_slot_open_session_async (slot, 0, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);
	sess = gp11_slot_open_session_finish (slot, result, &err);
	SUCCESS_RES (sess, err);
	if (!sess) return;
	g_assert (handle == sess->handle);
	g_object_unref (result);
	g_object_unref (sess);
	
	/* Test opening with different flags, a different session should be returned */
	sess = gp11_slot_open_session (slot, CKF_RW_SESSION, &err);
	SUCCESS_RES (sess, err);
	if (!sess) return;
	g_assert (handle != sess->handle);
	
	/* Now open a second session, with same flags, shouldn't return the same */
	sess2 = gp11_slot_open_session (slot, CKF_RW_SESSION, &err);
	SUCCESS_RES (sess2, err);
	if (!sess2) return;
	g_assert (sess->handle != sess2->handle);
	
	g_object_unref (sess);
	g_object_unref (sess2);
}


DEFINE_TEST(login_logout)
{
	GAsyncResult *result = NULL;
	GError *err = NULL;
	gboolean ret;

	/* login/logout */
	ret = gp11_session_login (session, CKU_USER, (guchar*)"booo", 4, &err);
	SUCCESS_RES (ret, err);
	
	ret = gp11_session_logout (session, &err);
	SUCCESS_RES (ret, err);

	/* login/logout full */
	ret = gp11_session_login_full (session, CKU_USER, (guchar*)"booo", 4, NULL, &err);
	SUCCESS_RES (ret, err);
	
	ret = gp11_session_logout_full (session, NULL, &err);
	SUCCESS_RES (ret, err);

	/* login async */
	gp11_session_login_async (session, CKU_USER, (guchar*)"booo", 4, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);
	
	ret = gp11_session_login_finish (session, result, &err);
	SUCCESS_RES (ret, err);
	
	g_object_unref (result);
	result = NULL;
	
	/* logout async */
	gp11_session_logout_async (session, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);
	
	ret = gp11_session_logout_finish (session, result, &err);
	SUCCESS_RES (ret, err);
	
	g_object_unref (result);
	result = NULL;

}

static gboolean
authenticate_token (GP11Slot *slot, gchar **password, gpointer unused)
{
	g_assert (unused == GUINT_TO_POINTER (35));
	g_assert (password != NULL);
	g_assert (*password == NULL);
	g_assert (GP11_IS_SLOT (slot));
	
	*password = g_strdup ("booo");
	return TRUE;
}

DEFINE_TEST(auto_login)
{
	GP11Object *object;
	GAsyncResult *result = NULL;
	GError *err = NULL;
	GP11Attributes *attrs;
	gboolean ret;
	
	attrs = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, CKO_DATA,
	                              CKA_LABEL, GP11_STRING, "TEST OBJECT",
	                              CKA_PRIVATE, GP11_BOOLEAN, CK_TRUE,
	                              -1);
	
	/* Try to do something that requires a login */
	object = gp11_session_create_object_full (session, attrs, NULL, &err); 
	g_assert (!object);
	g_assert (err && err->code == CKR_USER_NOT_LOGGED_IN);
	g_clear_error (&err);
	
	/* Setup for auto login */
	g_assert (gp11_slot_get_auto_login (slot) == FALSE);
	gp11_slot_set_auto_login (slot, TRUE);
	g_assert (gp11_slot_get_auto_login (slot) == TRUE);
	
	g_signal_connect (slot, "authenticate-token", G_CALLBACK (authenticate_token), GUINT_TO_POINTER (35));

	/* Try again to do something that requires a login */
	object = gp11_session_create_object_full (session, attrs, NULL, &err); 
	SUCCESS_RES (object, err);
	g_object_unref (object);
	
	/* We should now be logged in, try to log out */
	ret = gp11_session_logout (session, &err);
	SUCCESS_RES (ret, err);
	
	/* Now try the same thing, but asyncronously */
	gp11_session_create_object_async (session, attrs, NULL, fetch_async_result, &result); 
	WAIT_UNTIL (result);
	g_assert (result != NULL);
	object = gp11_session_create_object_finish (session, result, &err);
	SUCCESS_RES (object, err);
	g_object_unref (result);
	g_object_unref (object);

	/* We should now be logged in, try to log out */
	ret = gp11_session_logout (session, &err);
	SUCCESS_RES (ret, err);
}
