#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test-suite.h"

#include <glib.h>

#include "gck-test.h"

static GckModule *module = NULL;
static GckSlot *slot = NULL;
static GckSession *session = NULL;
static GckObject *object = NULL;

DEFINE_SETUP(prep_object)
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

	/* Our module always exports a token object with this */
	object = gck_object_from_handle (session, 2);
	g_assert (object != NULL);
}

DEFINE_TEARDOWN(prep_object)
{
	g_object_unref (object);
	g_object_unref (session);
	g_object_unref (slot);
	g_object_unref (module);
}

DEFINE_TEST(object_props)
{
	GckSession *sess;
	GckModule *mod;
	CK_OBJECT_HANDLE handle;
	g_object_get (object, "session", &sess, "module", &mod, "handle", &handle, NULL);
	g_assert (session == sess);
	g_object_unref (sess);
	g_assert (module == mod);
	g_object_unref (mod);
	g_assert (handle == 2);
}

DEFINE_TEST(object_equals_hash)
{
	GckSlot *other_slot;
	GckSession *other_session;
	GckObject *other_object;
	GObject *obj;
	GError *err = NULL;
	guint hash;

	hash = gck_object_hash (object);
	g_assert (hash != 0);

	g_assert (gck_object_equal (object, object));

	other_slot = g_object_new (GCK_TYPE_SLOT, "module", module, "handle", GCK_TEST_SLOT_TWO, NULL);
	other_session = gck_slot_open_session (other_slot, 0, &err);
	SUCCESS_RES (other_session, err);
	other_object = gck_object_from_handle (other_session, gck_object_get_handle (object));
	g_assert (!gck_object_equal (object, other_object));
	g_object_unref (other_slot);
	g_object_unref (other_session);
	g_object_unref (other_object);

	obj = g_object_new (G_TYPE_OBJECT, NULL);
	g_assert (!gck_object_equal (object, obj));
	g_object_unref (obj);

	other_object = gck_object_from_handle (session, 383838);
	g_assert (!gck_object_equal (object, other_object));
	g_object_unref (other_object);

	other_object = gck_object_from_handle (session, gck_object_get_handle (object));
	g_assert (gck_object_equal (object, other_object));
	g_object_unref (other_object);
}

static void
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
	testing_wait_stop ();
}

DEFINE_TEST(create_object)
{
	GAsyncResult *result = NULL;
	GckAttributes *attrs;
	GckObject *object;
	CK_OBJECT_HANDLE last_handle;
	GError *err = NULL;

	/* Using simple */
	object = gck_session_create_object (session, &err,
	                                     CKA_CLASS, GCK_ULONG, CKO_DATA,
	                                     CKA_LABEL, GCK_STRING, "TEST LABEL",
	                                     CKA_TOKEN, GCK_BOOLEAN, CK_FALSE,
	                                     CKA_VALUE, 4UL, "BLAH",
	                                     GCK_INVALID);
	SUCCESS_RES (object, err);
	g_assert (GCK_IS_OBJECT (object));

	if (object) {
		last_handle = gck_object_get_handle (object);
		g_object_unref (object);
	}

	/* Using full */
	attrs = gck_attributes_newv (CKA_CLASS, GCK_ULONG, CKO_DATA,
	                              CKA_LABEL, GCK_STRING, "TEST LABEL",
	                              CKA_TOKEN, GCK_BOOLEAN, CK_FALSE,
	                              CKA_VALUE, 4UL, "BLAH",
	                              GCK_INVALID);

	object = gck_session_create_object_full (session, attrs, NULL, &err);
	g_assert (GCK_IS_OBJECT (object));
	SUCCESS_RES (object, err);

	if (object) {
		g_assert (last_handle != gck_object_get_handle (object));
		last_handle = gck_object_get_handle (object);
		g_object_unref (object);
	}

	/* Using async */
	gck_session_create_object_async (session, attrs, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);

	object = gck_session_create_object_finish (session, result, &err);
	g_object_unref (result);
	SUCCESS_RES (object, err);
	g_assert (GCK_IS_OBJECT (object));

	if (object)
		g_object_unref (object);
	gck_attributes_unref (attrs);
}

DEFINE_TEST(destroy_object)
{
	GAsyncResult *result = NULL;
	GckObject *object;
	GError *err = NULL;
	gboolean ret;

	/* Using simple */
	object = gck_session_create_object (session, &err,
	                                     CKA_CLASS, GCK_ULONG, CKO_DATA,
	                                     CKA_LABEL, GCK_STRING, "TEST OBJECT",
	                                     CKA_TOKEN, GCK_BOOLEAN, CK_TRUE,
	                                     GCK_INVALID);
	SUCCESS_RES (object, err);
	g_assert (GCK_IS_OBJECT (object));

	if (!object)
		return;

	ret = gck_object_destroy (object, &err);
	SUCCESS_RES (ret, err);
	g_object_unref (object);

	/* Using full */
	object = gck_session_create_object (session, &err,
	                                     CKA_CLASS, GCK_ULONG, CKO_DATA,
	                                     CKA_LABEL, GCK_STRING, "TEST OBJECT",
	                                     CKA_TOKEN, GCK_BOOLEAN, CK_TRUE,
	                                     GCK_INVALID);
	SUCCESS_RES (object, err);
	g_assert (GCK_IS_OBJECT (object));

	if (!object)
		return;

	ret = gck_object_destroy_full (object, NULL, &err);
	SUCCESS_RES (ret, err);
	g_object_unref (object);

	/* Using async */
	object = gck_session_create_object (session, &err,
	                                     CKA_CLASS, GCK_ULONG, CKO_DATA,
	                                     CKA_LABEL, GCK_STRING, "TEST OBJECT",
	                                     CKA_TOKEN, GCK_BOOLEAN, CK_TRUE,
	                                     GCK_INVALID);
	SUCCESS_RES (object, err);
	g_assert (GCK_IS_OBJECT (object));

	if (!object)
		return;

	/* Using async */
	gck_object_destroy_async (object, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);

	ret = gck_object_destroy_finish (object, result, &err);
	g_object_unref (result);
	SUCCESS_RES (object, err);
	g_object_unref (object);
}

DEFINE_TEST(get_attributes)
{
	GAsyncResult *result = NULL;
	GckAttributes *attrs, *attrs_ret;
	GError *err = NULL;
	gulong klass;
	gchar *value = NULL;

	/* Simple */
	attrs = gck_object_get (object, &err, CKA_CLASS, CKA_LABEL, GCK_INVALID);
	SUCCESS_RES (attrs, err);
	if (attrs != NULL) {
		g_assert (gck_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == CKO_DATA);
		g_assert (gck_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "TEST LABEL") == 0);
		g_free (value); value = NULL;
	}
	gck_attributes_unref (attrs);

	/* Full */
	attrs = gck_attributes_new_empty (CKA_CLASS, CKA_LABEL, GCK_INVALID);
	attrs_ret = gck_object_get_full (object, attrs, NULL, &err);
	SUCCESS_RES (attrs_ret, err);
	if (attrs_ret != NULL) {
		g_assert (attrs_ret == attrs);
		g_assert (gck_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == CKO_DATA);
		g_assert (gck_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "TEST LABEL") == 0);
		g_free (value); value = NULL;
	}
	gck_attributes_unref (attrs);

	/* Async */
	attrs = gck_attributes_new_empty (CKA_CLASS, CKA_LABEL, GCK_INVALID);
	gck_object_get_async (object, attrs, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);

	attrs_ret = gck_object_get_finish (object, result, &err);
	g_object_unref (result);
	SUCCESS_RES (attrs, err);
	if (attrs != NULL) {
		g_assert (attrs_ret == attrs);
		g_assert (gck_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == CKO_DATA);
		g_assert (gck_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "TEST LABEL") == 0);
		g_free (value); value = NULL;
	}
	gck_attributes_unref (attrs);
}

DEFINE_TEST(get_data_attribute)
{
	GAsyncResult *result = NULL;
	CK_OBJECT_CLASS_PTR klass;
	gsize n_data;
	GError *err = NULL;

	/* Simple */
	klass = gck_object_get_data (object, CKA_CLASS, &n_data, &err);
	SUCCESS_RES (klass, err);
	if (klass != NULL) {
		g_assert (n_data == sizeof (CK_OBJECT_CLASS));
		g_assert (*klass == CKO_DATA);
		g_free (klass);
	}

	/* Full */
	klass = gck_object_get_data_full (object, CKA_CLASS, NULL, NULL, &n_data, &err);
	SUCCESS_RES (klass, err);
	if (klass != NULL) {
		g_assert (n_data == sizeof (CK_OBJECT_CLASS));
		g_assert (*klass == CKO_DATA);
		g_free (klass);
	}

	/* Async */
	gck_object_get_data_async (object, CKA_CLASS, NULL, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);

	klass = gck_object_get_data_finish (object, result, &n_data, &err);
	g_object_unref (result);
	SUCCESS_RES (klass, err);
	if (klass != NULL) {
		g_assert (n_data == sizeof (CK_OBJECT_CLASS));
		g_assert (*klass == CKO_DATA);
		g_free (klass);
	}

}

DEFINE_TEST(set_attributes)
{
	GAsyncResult *result = NULL;
	GckAttributes *attrs, *templ;
	GError *err = NULL;
	gulong klass;
	gchar *value = NULL;
	gboolean ret;

	/* Simple */
	ret = gck_object_set (object, &err,
	                       CKA_CLASS, GCK_ULONG, 5,
	                       CKA_LABEL, GCK_STRING, "CHANGE ONE",
	                       GCK_INVALID);
	SUCCESS_RES (ret, err);
	if (ret) {
		attrs = gck_object_get (object, &err, CKA_CLASS, CKA_LABEL, GCK_INVALID);
		g_assert (gck_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == 5);
		g_assert (gck_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "CHANGE ONE") == 0);
		g_free (value); value = NULL;
		gck_attributes_unref (attrs);
	}

	templ = gck_attributes_newv (CKA_CLASS, GCK_ULONG, 6,
	                              CKA_LABEL, GCK_STRING, "CHANGE TWO",
	                              GCK_INVALID);

	/* Full */
	ret = gck_object_set_full (object, templ, NULL, &err);
	gck_attributes_unref (templ);
	SUCCESS_RES (ret, err);
	if (ret) {
		attrs = gck_object_get (object, &err, CKA_CLASS, CKA_LABEL, GCK_INVALID);
		g_assert (gck_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == 6);
		g_assert (gck_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "CHANGE TWO") == 0);
		g_free (value); value = NULL;
		gck_attributes_unref (attrs);
	}

	templ = gck_attributes_newv (CKA_CLASS, GCK_ULONG, 7,
	                              CKA_LABEL, GCK_STRING, "CHANGE THREE",
	                              GCK_INVALID);

	/* Async */
	gck_object_set_async (object, templ, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);

	ret = gck_object_set_finish (object, result, &err);
	g_object_unref (result);
	SUCCESS_RES (ret, err);
	if (ret) {
		attrs = gck_object_get (object, &err, CKA_CLASS, CKA_LABEL, GCK_INVALID);
		g_assert (gck_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == 7);
		g_assert (gck_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "CHANGE THREE") == 0);
		g_free (value); value = NULL;
		gck_attributes_unref (attrs);
	}
}

DEFINE_TEST(find_objects)
{
	GAsyncResult *result = NULL;
	GckAttributes *templ;
	GList *objects;
	GckObject *testobj;
	GError *err = NULL;

	testobj = gck_session_create_object (session, &err,
	                                      CKA_CLASS, GCK_ULONG, CKO_DATA,
	                                      CKA_LABEL, GCK_STRING, "UNIQUE LABEL",
	                                      GCK_INVALID);
	g_object_unref (testobj);

	testobj = gck_session_create_object (session, &err,
	                                      CKA_CLASS, GCK_ULONG, CKO_DATA,
	                                      CKA_LABEL, GCK_STRING, "OTHER LABEL",
	                                      GCK_INVALID);
	g_object_unref (testobj);

	/* Simple, "TEST LABEL" */
	objects = gck_session_find_objects (session, &err, CKA_LABEL, GCK_STRING, "UNIQUE LABEL", GCK_INVALID);
	SUCCESS_RES (objects, err);
	g_assert (g_list_length (objects) == 1);
	gck_list_unref_free (objects);

	/* Full, All */
	templ = gck_attributes_new ();
	objects = gck_session_find_objects_full (session, templ, NULL, &err);
	SUCCESS_RES (objects, err);
	g_assert (g_list_length (objects) > 1);
	gck_list_unref_free (objects);

	/* Async, None */
	gck_attributes_add_string (templ, CKA_LABEL, "blah blah");
	gck_session_find_objects_async (session, templ, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);

	objects = gck_session_find_objects_finish (session, result, &err);
	g_object_unref (result);
	g_assert (objects == NULL);
	gck_list_unref_free (objects);
}
