#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "run-auto-test.h"

#include <glib.h>

#include "gp11-test.h"

static GP11Module *module = NULL;
static GP11Slot *slot = NULL;
static GP11Session *session = NULL;
static GP11Object *object = NULL;

DEFINE_SETUP(prep_object)
{
	GError *err = NULL;
	GList *slots;
	
	/* Successful load */
	module = gp11_module_initialize (".libs/libgp11-test-module.so", NULL, &err);
	SUCCESS_RES (module, err);
	
	slots = gp11_module_get_slots (module, TRUE);
	g_assert (slots != NULL);
	
	slot = GP11_SLOT (slots->data);
	g_object_ref (slot);
	gp11_list_unref_free (slots);

	session = gp11_slot_open_session (slot, 0, &err);
	SUCCESS_RES(session, err);
	
	/* Our module always exports a token object with this */
	object = gp11_object_from_handle (session->slot, 2);
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
	GP11Slot *slot;
	GP11Module *mod;
	CK_OBJECT_HANDLE handle;
	g_object_get (object, "slot", &slot, "module", &mod, "handle", &handle, NULL);
	g_assert (slot == session->slot);
	g_object_unref (slot);
	g_assert (module == mod);
	g_object_unref (mod);
	g_assert (handle == 2);
}

static void 
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
}

DEFINE_TEST(create_object)
{
	GAsyncResult *result = NULL;
	GP11Attributes *attrs;
	GP11Object *object;
	CK_OBJECT_HANDLE last_handle;
	GError *err = NULL;
	
	/* Using simple */
	object = gp11_session_create_object (session, &err, 
	                                     CKA_CLASS, GP11_ULONG, CKO_DATA,
	                                     CKA_LABEL, GP11_STRING, "TEST LABEL",
	                                     CKA_TOKEN, GP11_BOOLEAN, CK_FALSE,
	                                     CKA_VALUE, 4, "BLAH",
	                                     -1);
	SUCCESS_RES (object, err);
	g_assert (GP11_IS_OBJECT (object));
	
	if (object) {
		last_handle = object->handle;
		g_object_unref (object);
	}
	
	/* Using full */
	attrs = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, CKO_DATA,
	                              CKA_LABEL, GP11_STRING, "TEST LABEL",
	                              CKA_TOKEN, GP11_BOOLEAN, CK_FALSE,
	                              CKA_VALUE, 4, "BLAH",
	                              -1);
	
	object = gp11_session_create_object_full (session, attrs, NULL, &err);
	g_assert (GP11_IS_OBJECT (object));
	SUCCESS_RES (object, err);
	
	if (object) {
		g_assert (last_handle != object->handle);
		last_handle = object->handle;
		g_object_unref (object);
	}

	/* Using async */
	gp11_session_create_object_async (session, attrs, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);
	
	object = gp11_session_create_object_finish (session, result, &err);
	g_object_unref (result);
	SUCCESS_RES (object, err);
	g_assert (GP11_IS_OBJECT (object));
	
	if (object)
		g_object_unref (object);
	gp11_attributes_unref (attrs);
}

DEFINE_TEST(destroy_object)
{
	GAsyncResult *result = NULL;
	GP11Object *object;
	GError *err = NULL;
	gboolean ret;
	
	/* Using simple */
	object = gp11_session_create_object (session, &err, 
	                                     CKA_CLASS, GP11_ULONG, CKO_DATA,
	                                     CKA_LABEL, GP11_STRING, "TEST OBJECT",
	                                     CKA_TOKEN, GP11_BOOLEAN, CK_TRUE,
	                                     -1);
	SUCCESS_RES (object, err);
	g_assert (GP11_IS_OBJECT (object));
	
	if (!object)
		return;
	
	ret = gp11_object_destroy (object, &err);
	SUCCESS_RES (ret, err);
	g_object_unref (object);

	/* Using full */
	object = gp11_session_create_object (session, &err, 
	                                     CKA_CLASS, GP11_ULONG, CKO_DATA,
	                                     CKA_LABEL, GP11_STRING, "TEST OBJECT",
	                                     CKA_TOKEN, GP11_BOOLEAN, CK_TRUE,
	                                     -1);
	SUCCESS_RES (object, err);
	g_assert (GP11_IS_OBJECT (object));
	
	if (!object)
		return;
	
	ret = gp11_object_destroy_full (object, NULL, &err);
	SUCCESS_RES (ret, err);
	g_object_unref (object);
	
	/* Using async */
	object = gp11_session_create_object (session, &err, 
	                                     CKA_CLASS, GP11_ULONG, CKO_DATA,
	                                     CKA_LABEL, GP11_STRING, "TEST OBJECT",
	                                     CKA_TOKEN, GP11_BOOLEAN, CK_TRUE,
	                                     -1);
	SUCCESS_RES (object, err);
	g_assert (GP11_IS_OBJECT (object));
	
	if (!object)
		return;
	
	/* Using async */
	gp11_object_destroy_async (object, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);

	ret = gp11_object_destroy_finish (object, result, &err);
	g_object_unref (result);
	SUCCESS_RES (object, err);
	g_object_unref (object);
}

DEFINE_TEST(get_attributes)
{
	GAsyncResult *result = NULL;
	GP11Attributes *attrs;
	GError *err = NULL;
	gulong klass;
	gchar *value = NULL;
	gulong types[2] = { CKA_CLASS, CKA_LABEL };
	
	/* Simple */
	attrs = gp11_object_get (object, &err, CKA_CLASS, CKA_LABEL, -1);
	SUCCESS_RES (attrs, err);
	if (attrs != NULL) {
		g_assert (gp11_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == CKO_DATA);
		g_assert (gp11_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "TEST LABEL") == 0);
		g_free (value); value = NULL;
		gp11_attributes_unref (attrs);
	}

	/* Full */
	attrs = gp11_object_get_full (object, types, 2, NULL, &err);
	SUCCESS_RES (attrs, err);
	if (attrs != NULL) {
		g_assert (gp11_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == CKO_DATA);
		g_assert (gp11_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "TEST LABEL") == 0);
		g_free (value); value = NULL;
		gp11_attributes_unref (attrs);
	}

	/* Async */
	gp11_object_get_async (object, types, 2, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);

	attrs = gp11_object_get_finish (object, result, &err);
	g_object_unref (result);
	SUCCESS_RES (attrs, err);
	if (attrs != NULL) {
		g_assert (gp11_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == CKO_DATA);
		g_assert (gp11_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "TEST LABEL") == 0);
		g_free (value); value = NULL;
		gp11_attributes_unref (attrs);
	}
}

DEFINE_TEST(get_one_attribute)
{
	GAsyncResult *result = NULL;
	GP11Attribute *attr;
	GError *err = NULL;
	
	/* Simple */
	attr = gp11_object_get_one (object, CKA_CLASS, &err);
	SUCCESS_RES (attr, err);
	if (attr != NULL) {
		g_assert (attr->type == CKA_CLASS && gp11_attribute_get_ulong (attr) == CKO_DATA);
		gp11_attribute_free (attr);
	}

	/* Full */
	attr = gp11_object_get_one_full (object, CKA_CLASS, NULL, &err);
	SUCCESS_RES (attr, err);
	if (attr != NULL) {
		g_assert (attr->type == CKA_CLASS && gp11_attribute_get_ulong (attr) == CKO_DATA);
		gp11_attribute_free (attr);
	}

	/* Async */
	gp11_object_get_one_async (object, CKA_CLASS, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);

	attr = gp11_object_get_one_finish (object, result, &err);
	g_object_unref (result);
	SUCCESS_RES (attr, err);
	if (attr != NULL) {
		g_assert (attr->type == CKA_CLASS && gp11_attribute_get_ulong (attr) == CKO_DATA);
		gp11_attribute_free (attr);
	}
}

DEFINE_TEST(set_attributes)
{
	GAsyncResult *result = NULL;
	GP11Attributes *attrs, *templ;
	GError *err = NULL;
	gulong klass;
	gchar *value = NULL;
	gboolean ret;
	
	/* Simple */
	ret = gp11_object_set (object, &err, 
	                       CKA_CLASS, GP11_ULONG, 5, 
	                       CKA_LABEL, GP11_STRING, "CHANGE ONE", 
	                       -1);
	SUCCESS_RES (ret, err);
	if (ret) {
		attrs = gp11_object_get (object, &err, CKA_CLASS, CKA_LABEL, -1);
		g_assert (gp11_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == 5);
		g_assert (gp11_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "CHANGE ONE") == 0);
		g_free (value); value = NULL;
		gp11_attributes_unref (attrs);
	}

	templ = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, 6,
	                              CKA_LABEL, GP11_STRING, "CHANGE TWO",
	                              -1);
	
	/* Full */
	ret = gp11_object_set_full (object, templ, NULL, &err);
	gp11_attributes_unref (templ);
	SUCCESS_RES (ret, err);
	if (ret) {
		attrs = gp11_object_get (object, &err, CKA_CLASS, CKA_LABEL, -1);
		g_assert (gp11_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == 6);
		g_assert (gp11_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "CHANGE TWO") == 0);
		g_free (value); value = NULL;
		gp11_attributes_unref (attrs);
	}

	templ = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, 7,
	                              CKA_LABEL, GP11_STRING, "CHANGE THREE",
	                              -1);

	/* Async */
	gp11_object_set_async (object, templ, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);

	ret = gp11_object_set_finish (object, result, &err);
	g_object_unref (result);
	SUCCESS_RES (ret, err);
	if (ret) {
		attrs = gp11_object_get (object, &err, CKA_CLASS, CKA_LABEL, -1);
		g_assert (gp11_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == 7);
		g_assert (gp11_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "CHANGE THREE") == 0);
		g_free (value); value = NULL;
		gp11_attributes_unref (attrs);
	}
}

DEFINE_TEST(find_objects)
{
	GAsyncResult *result = NULL;
	GP11Attributes *templ;
	GList *objects;
	GP11Object *testobj;
	GError *err = NULL;
	
	testobj = gp11_session_create_object (session, &err, 
	                                      CKA_CLASS, GP11_ULONG, CKO_DATA,
	                                      CKA_LABEL, GP11_STRING, "UNIQUE LABEL",
	                                      -1);
	g_object_unref (testobj);

	testobj = gp11_session_create_object (session, &err, 
	                                      CKA_CLASS, GP11_ULONG, CKO_DATA,
	                                      CKA_LABEL, GP11_STRING, "OTHER LABEL",
	                                      -1);
	g_object_unref (testobj);

	/* Simple, "TEST LABEL" */
	objects = gp11_session_find_objects (session, &err, CKA_LABEL, GP11_STRING, "UNIQUE LABEL", -1);
	SUCCESS_RES (objects, err);
	g_assert (g_list_length (objects) == 1);
	gp11_list_unref_free (objects);

	/* Full, All */
	templ = gp11_attributes_new ();
	objects = gp11_session_find_objects_full (session, templ, NULL, &err);
	SUCCESS_RES (objects, err);
	g_assert (g_list_length (objects) > 1);
	gp11_list_unref_free (objects);
	
	/* Async, None */
	gp11_attributes_add_string (templ, CKA_LABEL, "blah blah");
	gp11_session_find_objects_async (session, templ, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);

	objects = gp11_session_find_objects_finish (session, result, &err);
	g_object_unref (result);
	g_assert (objects == NULL);
	gp11_list_unref_free (objects);
}

DEFINE_TEST(explicit_sessions)
{
	GP11Session *sess;
	GAsyncResult *result = NULL;
	GP11Attributes *attrs;
	GError *err = NULL;
	gulong klass;
	gchar *value = NULL;
	gulong types[2] = { CKA_CLASS, CKA_LABEL };
	
	/* Set an explicit session */
	gp11_object_set_session (object, session);
	g_assert (gp11_object_get_session (object) == session);
	g_object_get (object, "session", &sess, NULL);
	g_assert (sess == session);
	
	/* Simple */
	attrs = gp11_object_get (object, &err, CKA_CLASS, CKA_LABEL, -1);
	SUCCESS_RES (attrs, err);
	if (attrs != NULL) {
		g_assert (gp11_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == CKO_DATA);
		g_assert (gp11_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "TEST LABEL") == 0);
		g_free (value); value = NULL;
		gp11_attributes_unref (attrs);
	}

	/* Async */
	gp11_object_get_async (object, types, 2, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);

	attrs = gp11_object_get_finish (object, result, &err);
	g_object_unref (result);
	SUCCESS_RES (attrs, err);
	if (attrs != NULL) {
		g_assert (gp11_attributes_find_ulong (attrs, CKA_CLASS, &klass) && klass == CKO_DATA);
		g_assert (gp11_attributes_find_string (attrs, CKA_LABEL, &value) && strcmp (value, "TEST LABEL") == 0);
		g_free (value); value = NULL;
		gp11_attributes_unref (attrs);
	}

	/* Set it to null and make sure taht works */
	gp11_object_set_session (object, NULL);
	g_assert (gp11_object_get_session (object) == NULL);
	g_object_get (object, "session", &sess, NULL);
	g_assert (sess == NULL);
}
