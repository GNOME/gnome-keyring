
#include <glib.h>
#include <string.h>

#include "test-suite.h"
#include "gck-test.h"
#include "gck-private.h"

static GList *modules = NULL;
static GckModule *module = NULL;

TESTING_SETUP(enumerator)
{
	GError *err = NULL;

	/* Successful load */
	module = gck_module_initialize (".libs/libmock-test-module.so", NULL, 0, &err);
	SUCCESS_RES (module, err);

	modules = g_list_append (NULL, g_object_ref (module));
}

TESTING_TEARDOWN(enumerator)
{
	gck_list_unref_free (modules);
	modules = NULL;

	g_object_unref (module);
	module = NULL;
}

TESTING_TEST(enumerator_create)
{
	GckUriInfo *uri_info;
	GckEnumerator *en;

	uri_info = _gck_uri_info_new ();
	en = _gck_enumerator_new (modules, 0, uri_info);
	g_assert (GCK_IS_ENUMERATOR (en));
	g_object_unref (en);
}

TESTING_TEST(enumerator_create_slots)
{
	GckUriInfo *uri_info;
	GckEnumerator *en;
	GList *slots;

	uri_info = _gck_uri_info_new ();
	slots = gck_module_get_slots (module, FALSE);
	en = _gck_enumerator_new (slots, 0, uri_info);
	g_assert (GCK_IS_ENUMERATOR (en));
	g_object_unref (en);
	gck_list_unref_free (slots);
}

TESTING_TEST(enumerator_next)
{
	GckUriInfo *uri_info;
	GError *error = NULL;
	GckEnumerator *en;
	GckObject *obj;

	uri_info = _gck_uri_info_new ();
	en = _gck_enumerator_new (modules, 0, uri_info);
	g_assert (GCK_IS_ENUMERATOR (en));

	obj = gck_enumerator_next (en, NULL, &error);
	g_assert (GCK_IS_OBJECT (obj));

	g_object_unref (obj);
	g_object_unref (en);
}

TESTING_TEST(enumerator_next_slots)
{
	GckUriInfo *uri_info;
	GError *error = NULL;
	GList *slots = NULL;
	GckEnumerator *en;
	GckObject *obj;

	uri_info = _gck_uri_info_new ();
	slots = gck_module_get_slots (module, FALSE);
	en = _gck_enumerator_new (slots, 0, uri_info);
	g_assert (GCK_IS_ENUMERATOR (en));

	obj = gck_enumerator_next (en, NULL, &error);
	g_assert (GCK_IS_OBJECT (obj));

	g_object_unref (obj);
	g_object_unref (en);
	gck_list_unref_free (slots);
}

TESTING_TEST(enumerator_next_and_resume)
{
	GckUriInfo *uri_info;
	GError *error = NULL;
	GckEnumerator *en;
	GckObject *obj, *obj2;

	uri_info = _gck_uri_info_new ();
	en = _gck_enumerator_new (modules, 0, uri_info);
	g_assert (GCK_IS_ENUMERATOR (en));

	obj = gck_enumerator_next (en, NULL, &error);
	SUCCESS_RES (obj, error);
	g_assert (GCK_IS_OBJECT (obj));

	obj2 = gck_enumerator_next (en, NULL, &error);
	SUCCESS_RES (obj2, error);
	g_assert (GCK_IS_OBJECT (obj2));

	g_assert (!gck_object_equal (obj, obj2));

	g_object_unref (obj);
	g_object_unref (obj2);
	g_object_unref (en);
}

TESTING_TEST(enumerator_next_n)
{
	GckUriInfo *uri_info;
	GError *error = NULL;
	GckEnumerator *en;
	GList *objects, *l;

	uri_info = _gck_uri_info_new ();
	en = _gck_enumerator_new (modules, 0, uri_info);
	g_assert (GCK_IS_ENUMERATOR (en));

	objects = gck_enumerator_next_n (en, -1, NULL, &error);
	SUCCESS_RES (objects, error);
	g_assert_cmpint (g_list_length (objects), ==, 5);
	for (l = objects; l; l = g_list_next (l))
		g_assert (GCK_IS_OBJECT (l->data));

	gck_list_unref_free (objects);
	g_object_unref (en);
}

static void
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
	testing_wait_stop ();
}

TESTING_TEST(enumerator_next_async)
{
	GckUriInfo *uri_info;
	GAsyncResult *result = NULL;
	GError *error = NULL;
	GckEnumerator *en;
	GList *objects, *l;

	uri_info = _gck_uri_info_new ();
	en = _gck_enumerator_new (modules, 0, uri_info);
	g_assert (GCK_IS_ENUMERATOR (en));

	gck_enumerator_next_async (en, -1, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result);

	objects = gck_enumerator_next_finish (en, result, &error);
	SUCCESS_RES (objects, error);
	g_assert_cmpint (g_list_length (objects), ==, 5);
	for (l = objects; l; l = g_list_next (l))
		g_assert (GCK_IS_OBJECT (l->data));

	g_object_unref (result);
	gck_list_unref_free (objects);
	g_object_unref (en);
}

TESTING_TEST(enumerator_attributes)
{
	GckUriInfo *uri_info;
	GError *error = NULL;
	GckEnumerator *en;
	GList *objects;

	uri_info = _gck_uri_info_new ();
	uri_info->attributes = gck_attributes_new ();
	gck_attributes_add_string (uri_info->attributes, CKA_LABEL, "Private Capitalize Key");
	en = _gck_enumerator_new (modules, 0, uri_info);
	g_assert (GCK_IS_ENUMERATOR (en));

	objects = gck_enumerator_next_n (en, -1, NULL, &error);
	SUCCESS_RES (objects, error);
	g_assert_cmpint (g_list_length (objects), ==, 1);
	g_assert (GCK_IS_OBJECT (objects->data));

	gck_list_unref_free (objects);
	g_object_unref (en);
}

TESTING_TEST(enumerator_token_match)
{
	GckUriInfo *uri_info;
	GError *error = NULL;
	GckEnumerator *en;
	GList *objects;

	uri_info = _gck_uri_info_new ();
	uri_info->token_info = g_new0 (GckTokenInfo, 1);
	uri_info->token_info->label = g_strdup ("Invalid token name");
	en = _gck_enumerator_new (modules, 0, uri_info);
	g_assert (GCK_IS_ENUMERATOR (en));

	objects = gck_enumerator_next_n (en, -1, NULL, &error);
	g_assert_cmpint (g_list_length (objects), ==, 0);
	g_assert (error == NULL);

	gck_list_unref_free (objects);
	g_object_unref (en);
}
