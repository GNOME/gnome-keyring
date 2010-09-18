#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test-suite.h"

#include <glib.h>

#include "gck-test.h"

static GckModule *module = NULL;
static GckModule *module_with_auth = NULL;
static GckSession *session = NULL;
static GckSession *session_with_auth = NULL;

DEFINE_SETUP(crypto_session)
{
	GError *err = NULL;
	GList *slots;
	GckSlot *slot;

	/* Successful load */
	module = gck_module_initialize (".libs/libmock-test-module.so", NULL, 0, &err);
	SUCCESS_RES (module, err);

	slots = gck_module_get_slots (module, TRUE);
	g_assert (slots != NULL);

	session = gck_slot_open_session (slots->data, 0, &err);
	SUCCESS_RES(session, err);

	module_with_auth = gck_module_new (gck_module_get_functions (module), GCK_AUTHENTICATE_OBJECTS);
	g_assert (module_with_auth);

	slot = gck_slot_from_handle (module_with_auth, gck_slot_get_handle (slots->data));
	g_assert (slot);

	session_with_auth = gck_session_from_handle (slot, gck_session_get_handle (session));
	g_assert (session_with_auth);

	g_object_unref (slot);
	gck_list_unref_free (slots);
}

DEFINE_TEARDOWN(crypto_session)
{
	g_object_unref (session);
	g_object_unref (module);
}

static void
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
	testing_wait_stop ();
}

static GckObject*
find_key (GckSession *session, CK_ATTRIBUTE_TYPE method, CK_MECHANISM_TYPE mech)
{
	GList *objects, *l;
	GckAttributes *attrs;
	GckObject *object = NULL;
	CK_MECHANISM_TYPE_PTR mechs;
	gsize n_mechs;

	attrs = gck_attributes_new ();
	gck_attributes_add_boolean (attrs, method, TRUE);
	objects = gck_session_find_objects (session, attrs, NULL, NULL);
	gck_attributes_unref (attrs);
	g_assert (objects);

	for (l = objects; l; l = g_list_next (l)) {
		if (mech) {
			mechs = gck_object_get_data (l->data, CKA_ALLOWED_MECHANISMS, &n_mechs, NULL);
			g_assert (mechs);
			g_assert (n_mechs == sizeof (CK_MECHANISM_TYPE));
			/* We know all of them only have one allowed mech */
			if (*mechs != mech)
				continue;
		}
		object = l->data;
		g_object_ref (object);
		break;
	}

	gck_list_unref_free (objects);
	return object;
}

static GckObject*
find_key_with_value (GckSession *session, const gchar *value)
{
	GList *objects;
	GckAttributes *attrs;
	GckObject *object;

	attrs = gck_attributes_new ();
	gck_attributes_add_string (attrs, CKA_VALUE, value);
	objects = gck_session_find_objects (session, attrs, NULL, NULL);
	gck_attributes_unref (attrs);
	g_assert (objects);

	object = g_object_ref (objects->data);
	gck_list_unref_free (objects);
	return object;
}

static void
check_key_with_value (GckSession *session, GckObject *key, CK_OBJECT_CLASS klass, const gchar *value)
{
	GckAttributes *attrs;
	GckAttribute *attr;
	gulong check;

	attrs = gck_object_get (key, NULL, CKA_CLASS, CKA_VALUE, GCK_INVALID);
	g_assert (attrs);

	if (!gck_attributes_find_ulong (attrs, CKA_CLASS, &check))
		g_assert_not_reached ();
	g_assert (check == klass);

	attr = gck_attributes_find (attrs, CKA_VALUE);
	g_assert (attr);
	g_assert (!gck_attribute_is_invalid (attr));
	g_assert_cmpsize (attr->length, ==, strlen (value));
	g_assert (memcmp (attr->value, value, attr->length) == 0);

	gck_attributes_unref (attrs);
}

static gboolean
authenticate_object (GckSlot *module, GckObject *object, gchar *label, gchar **password)
{
	g_assert (GCK_IS_MODULE (module));
	g_assert (GCK_IS_OBJECT (object));
	g_assert (password);
	g_assert (!*password);

	*password = g_strdup ("booo");
	return TRUE;
}

DEFINE_TEST(encrypt)
{
	GckMechanism *mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GckObject *key;
	guchar *output;
	gsize n_output;

	mech = gck_mechanism_new (CKM_MOCK_CAPITALIZE);

	/* Find the right key */
	key = find_key (session, CKA_ENCRYPT, CKM_MOCK_CAPITALIZE);
	g_assert (key);

	/* Simple one */
	output = gck_session_encrypt (session, key, CKM_MOCK_CAPITALIZE, (const guchar*)"blah blah", 10, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 10);
	g_assert_cmpstr ((gchar*)output, ==, "BLAH BLAH");
	g_free (output);

	/* Full one */
	output = gck_session_encrypt_full (session, key, mech, (const guchar*)"blah blah", 10, &n_output, NULL, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 10);
	g_assert_cmpstr ((gchar*)output, ==, "BLAH BLAH");
	g_free (output);

	/* Asynchronous one */
	gck_session_encrypt_async (session, key, mech, (const guchar*)"second chance", 14, NULL, fetch_async_result, &result);

	testing_wait_until (500);
	g_assert (result != NULL);

	/* Get the result */
	output = gck_session_encrypt_finish (session, result, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 14);
	g_assert_cmpstr ((gchar*)output, ==, "SECOND CHANCE");
	g_free (output);

	gck_mechanism_unref (mech);
	g_object_unref (result);
	g_object_unref (key);
}

DEFINE_TEST(decrypt)
{
	GckMechanism *mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GckObject *key;
	guchar *output;
	gsize n_output;

	mech = gck_mechanism_new (CKM_MOCK_CAPITALIZE);

	/* Find the right key */
	key = find_key (session, CKA_DECRYPT, CKM_MOCK_CAPITALIZE);
	g_assert (key);

	/* Simple one */
	output = gck_session_decrypt (session, key, CKM_MOCK_CAPITALIZE, (const guchar*)"FRY???", 7, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 7);
	g_assert_cmpstr ((gchar*)output, ==, "fry???");
	g_free (output);

	/* Full one */
	output = gck_session_decrypt_full (session, key, mech, (const guchar*)"TENNIS instructor", 18, &n_output, NULL, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 18);
	g_assert_cmpstr ((gchar*)output, ==, "tennis instructor");
	g_free (output);

	/* Asynchronous one */
	gck_session_decrypt_async (session, key, mech, (const guchar*)"FAT CHANCE", 11, NULL, fetch_async_result, &result);

	testing_wait_until (500);
	g_assert (result != NULL);

	/* Get the result */
	output = gck_session_decrypt_finish (session, result, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 11);
	g_assert_cmpstr ((gchar*)output, ==, "fat chance");
	g_free (output);

	gck_mechanism_unref (mech);
	g_object_unref (result);
	g_object_unref (key);
}

DEFINE_TEST(login_context_specific)
{
	/* The test module won't let us sign without doing a login, check that */

	GError *error = NULL;
	GckObject *key;
	guchar *output;
	gsize n_output;

	/* Find the right key */
	key = find_key (session, CKA_SIGN, CKM_MOCK_PREFIX);
	g_assert (key);

	/* Simple one */
	output = gck_session_sign (session, key, CKM_MOCK_PREFIX, (const guchar*)"TV Monster", 11, &n_output, &error);
	g_assert (error && error->code == CKR_USER_NOT_LOGGED_IN);
	FAIL_RES (output, error);
	g_assert (output == NULL);

	g_object_unref (key);
}

DEFINE_TEST(sign)
{
	GckMechanism *mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GckObject *key;
	guchar *output;
	gsize n_output;

	mech = gck_mechanism_new_with_param (CKM_MOCK_PREFIX, "my-prefix:", 10);

	/* Enable auto-login on this session, see previous test */
	g_signal_connect (module_with_auth, "authenticate-object", G_CALLBACK (authenticate_object), NULL);

	/* Find the right key */
	key = find_key (session_with_auth, CKA_SIGN, CKM_MOCK_PREFIX);
	g_assert (key);

	/* Simple one */
	output = gck_session_sign (session_with_auth, key, CKM_MOCK_PREFIX, (const guchar*)"Labarbara", 10, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert_cmpuint (n_output, ==, 24);
	g_assert_cmpstr ((gchar*)output, ==, "signed-prefix:Labarbara");
	g_free (output);

	/* Full one */
	output = gck_session_sign_full (session_with_auth, key, mech, (const guchar*)"Labarbara", 10, &n_output, NULL, &error);
	SUCCESS_RES (output, error);
	g_assert_cmpuint (n_output, ==, 20);
	g_assert_cmpstr ((gchar*)output, ==, "my-prefix:Labarbara");
	g_free (output);

	/* Asynchronous one */
	gck_session_sign_async (session_with_auth, key, mech, (const guchar*)"Conrad", 7, NULL, fetch_async_result, &result);

	testing_wait_until (500);
	g_assert (result != NULL);

	/* Get the result */
	output = gck_session_sign_finish (session_with_auth, result, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert_cmpuint (n_output, ==, 17);
	g_assert_cmpstr ((gchar*)output, ==, "my-prefix:Conrad");
	g_free (output);

	gck_mechanism_unref (mech);
	g_object_unref (result);
	g_object_unref (key);
}

DEFINE_TEST(verify)
{
	GckMechanism *mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GckObject *key;
	gboolean ret;

	mech = gck_mechanism_new_with_param (CKM_MOCK_PREFIX, "my-prefix:", 10);

	/* Enable auto-login on this session, shouldn't be needed */
	g_signal_connect (module, "authenticate-object", G_CALLBACK (authenticate_object), NULL);

	/* Find the right key */
	key = find_key (session, CKA_VERIFY, CKM_MOCK_PREFIX);
	g_assert (key);

	/* Simple one */
	ret = gck_session_verify (session, key, CKM_MOCK_PREFIX, (const guchar*)"Labarbara", 10,
	                           (const guchar*)"signed-prefix:Labarbara", 24, &error);
	SUCCESS_RES (ret, error);

	/* Full one */
	ret = gck_session_verify_full (session, key, mech, (const guchar*)"Labarbara", 10,
	                                (const guchar*)"my-prefix:Labarbara", 20, NULL, &error);
	SUCCESS_RES (ret, error);

	/* Failure one */
	ret = gck_session_verify_full (session, key, mech, (const guchar*)"Labarbara", 10,
	                                (const guchar*)"my-prefix:Loborboro", 20, NULL, &error);
	FAIL_RES (ret, error);

	/* Asynchronous one */
	gck_session_verify_async (session, key, mech, (const guchar*)"Labarbara", 10,
	                           (const guchar*)"my-prefix:Labarbara", 20, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	ret = gck_session_verify_finish (session, result, &error);
	SUCCESS_RES (ret, error);
	g_object_unref (result);

	/* Asynchronous failure */
	result = NULL;
	gck_session_verify_async (session, key, mech, (const guchar*)"Labarbara", 10,
	                           (const guchar*)"my-prefix:Labarxoro", 20, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	ret = gck_session_verify_finish (session, result, &error);
	FAIL_RES (ret, error);
	g_object_unref (result);

	gck_mechanism_unref (mech);
	g_object_unref (key);
}

DEFINE_TEST(generate_key_pair)
{
	GckAttributes *pub_attrs, *prv_attrs;
	GckMechanism *mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GckObject *pub_key, *prv_key;
	gboolean ret;

	mech = gck_mechanism_new_with_param (CKM_MOCK_GENERATE, "generate", 9);

	pub_attrs = gck_attributes_new ();
	gck_attributes_add_ulong (pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	prv_attrs = gck_attributes_new ();
	gck_attributes_add_ulong (prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);

	/* Full One*/
	ret = gck_session_generate_key_pair_full (session, mech, pub_attrs, prv_attrs,
	                                           &pub_key, &prv_key, NULL, &error);
	SUCCESS_RES (ret, error);
	g_object_unref (pub_key);
	g_object_unref (prv_key);

	/* Failure one */
	mech->type = 0;
	pub_key = prv_key = NULL;
	ret = gck_session_generate_key_pair_full (session, mech, pub_attrs, prv_attrs,
	                                           &pub_key, &prv_key, NULL, &error);
	FAIL_RES (ret, error);
	g_assert (pub_key == NULL);
	g_assert (prv_key == NULL);

	/* Asynchronous one */
	mech->type = CKM_MOCK_GENERATE;
	gck_session_generate_key_pair_async (session, mech, pub_attrs, prv_attrs, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	ret = gck_session_generate_key_pair_finish (session, result, &pub_key, &prv_key, &error);
	SUCCESS_RES (ret, error);
	g_object_unref (result);
	g_object_unref (pub_key);
	g_object_unref (prv_key);

	/* Asynchronous failure */
	result = NULL;
	mech->type = 0;
	pub_key = prv_key = NULL;
	gck_session_generate_key_pair_async (session, mech, pub_attrs, prv_attrs, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	ret = gck_session_generate_key_pair_finish (session, result, &pub_key, &prv_key, &error);
	FAIL_RES (ret, error);
	g_object_unref (result);
	g_assert (pub_key == NULL);
	g_assert (prv_key == NULL);

	gck_mechanism_unref (mech);
	gck_attributes_unref (pub_attrs);
	gck_attributes_unref (prv_attrs);
}

DEFINE_TEST(wrap_key)
{
	GckMechanism *mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GckObject *wrapper, *wrapped;
	gpointer output;
	gsize n_output;

	mech = gck_mechanism_new_with_param (CKM_MOCK_WRAP, "wrap", 4);
	wrapper = find_key (session, CKA_WRAP, 0);
	wrapped = find_key_with_value (session, "value");

	/* Simple One */
	output = gck_session_wrap_key (session, wrapper, CKM_MOCK_WRAP, wrapped, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert (output);
	g_assert_cmpsize (n_output, ==, 5);
	g_assert (memcmp (output, "value", 5) == 0);
	g_free (output);

	/* Full One*/
	output = gck_session_wrap_key_full (session, wrapper, mech, wrapped, &n_output, NULL, &error);
	SUCCESS_RES (output, error);
	g_assert_cmpsize (n_output, ==, 5);
	g_assert (memcmp (output, "value", 5) == 0);
	g_free (output);

	/* Failure one */
	mech->type = 0;
	n_output = 0;
	output = gck_session_wrap_key_full (session, wrapper, mech, wrapped, &n_output, NULL, &error);
	FAIL_RES (output, error);
	g_assert_cmpsize (n_output, ==, 0);

	/* Asynchronous one */
	mech->type = CKM_MOCK_WRAP;
	gck_session_wrap_key_async (session, wrapper, mech, wrapped, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	output = gck_session_wrap_key_finish (session, result, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert_cmpsize (n_output, ==, 5);
	g_assert (memcmp (output, "value", 5) == 0);
	g_object_unref (result);
	g_free (output);

	/* Asynchronous failure */
	result = NULL;
	mech->type = 0;
	n_output = 0;
	gck_session_wrap_key_async (session, wrapper, mech, wrapped, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	output = gck_session_wrap_key_finish (session, result, &n_output, &error);
	FAIL_RES (output, error);
	g_assert_cmpsize (n_output, ==, 0);
	g_object_unref (result);

	g_object_unref (wrapper);
	g_object_unref (wrapped);
	gck_mechanism_unref (mech);
}

DEFINE_TEST(unwrap_key)
{
	GckMechanism *mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GckObject *wrapper, *unwrapped;
	GckAttributes *attrs;

	mech = gck_mechanism_new_with_param (CKM_MOCK_WRAP, "wrap", 4);
	wrapper = find_key (session, CKA_UNWRAP, 0);
	attrs = gck_attributes_new ();
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_SECRET_KEY);

	/* Full One*/
	unwrapped = gck_session_unwrap_key (session, wrapper, mech, "special", 7, attrs, NULL, &error);
	SUCCESS_RES (unwrapped, error);
	g_assert (GCK_IS_OBJECT (unwrapped));
	check_key_with_value (session, unwrapped, CKO_SECRET_KEY, "special");
	g_object_unref (unwrapped);

	/* Failure one */
	mech->type = 0;
	unwrapped = gck_session_unwrap_key (session, wrapper, mech, "special", 7, attrs, NULL, &error);
	FAIL_RES (unwrapped, error);

	/* Asynchronous one */
	mech->type = CKM_MOCK_WRAP;
	gck_session_unwrap_key_async (session, wrapper, mech, "special", 7, attrs, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	unwrapped = gck_session_unwrap_key_finish (session, result, &error);
	SUCCESS_RES (unwrapped, error);
	g_assert (GCK_IS_OBJECT (unwrapped));
	check_key_with_value (session, unwrapped, CKO_SECRET_KEY, "special");
	g_object_unref (unwrapped);
	g_object_unref (result);

	/* Asynchronous failure */
	result = NULL;
	mech->type = 0;
	gck_session_unwrap_key_async (session, wrapper, mech, "special", 6, attrs, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	unwrapped = gck_session_unwrap_key_finish (session, result, &error);
	FAIL_RES (unwrapped, error);
	g_object_unref (result);

	g_object_unref (wrapper);
	gck_attributes_unref (attrs);
	gck_mechanism_unref (mech);
}

DEFINE_TEST(derive_key)
{
	GckMechanism *mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GckObject *wrapper, *derived;
	GckAttributes *attrs;

	mech = gck_mechanism_new_with_param (CKM_MOCK_DERIVE, "derive", 6);
	wrapper = find_key (session, CKA_DERIVE, 0);
	attrs = gck_attributes_new ();
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_SECRET_KEY);

	/* Full One*/
	derived = gck_session_derive_key (session, wrapper, mech, attrs, NULL, &error);
	SUCCESS_RES (derived, error);
	g_assert (GCK_IS_OBJECT (derived));
	check_key_with_value (session, derived, CKO_SECRET_KEY, "derived");
	g_object_unref (derived);

	/* Failure one */
	mech->type = 0;
	derived = gck_session_derive_key (session, wrapper, mech, attrs, NULL, &error);
	FAIL_RES (derived, error);

	/* Asynchronous one */
	mech->type = CKM_MOCK_DERIVE;
	gck_session_derive_key_async (session, wrapper, mech, attrs, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	derived = gck_session_derive_key_finish (session, result, &error);
	SUCCESS_RES (derived, error);
	g_assert (GCK_IS_OBJECT (derived));
	check_key_with_value (session, derived, CKO_SECRET_KEY, "derived");
	g_object_unref (derived);
	g_object_unref (result);

	/* Asynchronous failure */
	result = NULL;
	mech->type = 0;
	gck_session_derive_key_async (session, wrapper, mech, attrs, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	g_assert (result != NULL);
	derived = gck_session_derive_key_finish (session, result, &error);
	FAIL_RES (derived, error);
	g_object_unref (result);

	g_object_unref (wrapper);
	gck_attributes_unref (attrs);
	gck_mechanism_unref (mech);
}
