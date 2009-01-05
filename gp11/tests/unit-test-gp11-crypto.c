#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "run-auto-test.h"

#include <glib.h>

#include "gp11-test.h"

static GP11Module *module = NULL;
static GP11Slot *slot = NULL;
static GP11Session *session = NULL;

DEFINE_SETUP(crypto_session)
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
}

DEFINE_TEARDOWN(crypto_session)
{
	g_object_unref (session); 
	g_object_unref (slot);
	g_object_unref (module);
}

static void 
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
}

static GP11Object*
find_key (GP11Session *session, CK_ATTRIBUTE_TYPE method, CK_MECHANISM_TYPE mech)
{
	GList *objects, *l;
	GP11Object *object = NULL;
	CK_MECHANISM_TYPE_PTR mechs;
	gsize n_mechs;
	
	objects = gp11_session_find_objects (session, NULL, method, GP11_BOOLEAN, TRUE, GP11_INVALID);
	g_assert (objects);
	
	for (l = objects; l; l = g_list_next (l)) {
		gp11_object_set_session (l->data, session);
		mechs = gp11_object_get_data (l->data, CKA_ALLOWED_MECHANISMS, &n_mechs, NULL);
		g_assert (mechs);
		g_assert (n_mechs == sizeof (CK_MECHANISM_TYPE));
		
		/* We know all of them only have one allowed mech */
		if (*mechs == mech) {
			object = l->data;
			g_object_ref (object);
			break;
		}
	}
	
	gp11_list_unref_free (objects);
	return object;
}

static gboolean
authenticate_object (GP11Slot *module, GP11Object *object, gchar *label, gchar **password)
{
	g_assert (GP11_IS_MODULE (module));
	g_assert (GP11_IS_OBJECT (object));
	g_assert (password);
	g_assert (!*password);
	
	*password = g_strdup ("booo");
	return TRUE;
}

DEFINE_TEST(encrypt)
{
	GP11Mechanism mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GP11Object *key;
	guchar *output;
	gsize n_output;

	mech.type = CKM_CAPITALIZE;
	mech.n_parameter = 0;
	mech.parameter = NULL;

	/* Find the right key */
	key = find_key (session, CKA_ENCRYPT, CKM_CAPITALIZE);
	g_assert (key);
	
	/* Simple one */
	output = gp11_session_encrypt (session, key, CKM_CAPITALIZE, (const guchar*)"blah blah", 10, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 10);
	g_assert_cmpstr ((gchar*)output, ==, "BLAH BLAH");
	g_free (output);
	
	/* Full one */
	output = gp11_session_encrypt_full (session, key, &mech, (const guchar*)"blah blah", 10, &n_output, NULL, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 10);
	g_assert_cmpstr ((gchar*)output, ==, "BLAH BLAH");
	g_free (output);
	
	/* Asynchronous one */
	gp11_session_encrypt_async (session, key, &mech, (const guchar*)"second chance", 14, NULL, fetch_async_result, &result);

	WAIT_UNTIL (result);
	g_assert (result != NULL);
	
	/* Get the result */
	output = gp11_session_encrypt_finish (session, result, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 14);
	g_assert_cmpstr ((gchar*)output, ==, "SECOND CHANCE");
	g_free (output);

	g_object_unref (result);
	g_object_unref (key);
}

DEFINE_TEST(decrypt)
{
	GP11Mechanism mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GP11Object *key;
	guchar *output;
	gsize n_output;

	mech.type = CKM_CAPITALIZE;
	mech.n_parameter = 0;
	mech.parameter = NULL;

	/* Find the right key */
	key = find_key (session, CKA_DECRYPT, CKM_CAPITALIZE);
	g_assert (key);
	
	/* Simple one */
	output = gp11_session_decrypt (session, key, CKM_CAPITALIZE, (const guchar*)"FRY???", 7, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 7);
	g_assert_cmpstr ((gchar*)output, ==, "fry???");
	g_free (output);
	
	/* Full one */
	output = gp11_session_decrypt_full (session, key, &mech, (const guchar*)"TENNIS instructor", 18, &n_output, NULL, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 18);
	g_assert_cmpstr ((gchar*)output, ==, "tennis instructor");
	g_free (output);
	
	/* Asynchronous one */
	gp11_session_decrypt_async (session, key, &mech, (const guchar*)"FAT CHANCE", 11, NULL, fetch_async_result, &result);

	WAIT_UNTIL (result);
	g_assert (result != NULL);
	
	/* Get the result */
	output = gp11_session_decrypt_finish (session, result, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert (n_output == 11);
	g_assert_cmpstr ((gchar*)output, ==, "fat chance");
	g_free (output);

	g_object_unref (result);
	g_object_unref (key);
}

DEFINE_TEST(login_context_specific)
{
	/* The test module won't let us sign without doing a login, check that */
	
	GError *error = NULL;
	GP11Object *key;
	guchar *output;
	gsize n_output;

	/* Find the right key */
	key = find_key (session, CKA_SIGN, CKM_PREFIX);
	g_assert (key);
	
	/* Simple one */
	output = gp11_session_sign (session, key, CKM_PREFIX, (const guchar*)"TV Monster", 11, &n_output, &error);
	g_assert (error && error->code == CKR_USER_NOT_LOGGED_IN);
	FAIL_RES (output, error);
	g_assert (output == NULL);
	
	g_object_unref (key);
}

DEFINE_TEST(sign)
{
	GP11Mechanism mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GP11Object *key;
	guchar *output;
	gsize n_output;

	mech.type = CKM_PREFIX;
	mech.n_parameter = 10;
	mech.parameter = "my-prefix:";
	
	/* Enable auto-login on this session, see previous test */
	gp11_module_set_auto_authenticate (module, TRUE);
	g_signal_connect (module, "authenticate-object", G_CALLBACK (authenticate_object), NULL);

	/* Find the right key */
	key = find_key (session, CKA_SIGN, CKM_PREFIX);
	g_assert (key);
	
	/* Simple one */
	output = gp11_session_sign (session, key, CKM_PREFIX, (const guchar*)"Labarbara", 10, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert_cmpuint (n_output, ==, 24);
	g_assert_cmpstr ((gchar*)output, ==, "signed-prefix:Labarbara");
	g_free (output);
	
	/* Full one */
	output = gp11_session_sign_full (session, key, &mech, (const guchar*)"Labarbara", 10, &n_output, NULL, &error);
	SUCCESS_RES (output, error);
	g_assert_cmpuint (n_output, ==, 20);
	g_assert_cmpstr ((gchar*)output, ==, "my-prefix:Labarbara");
	g_free (output);
	
	/* Asynchronous one */
	gp11_session_sign_async (session, key, &mech, (const guchar*)"Conrad", 7, NULL, fetch_async_result, &result);

	WAIT_UNTIL (result);
	g_assert (result != NULL);
	
	/* Get the result */
	output = gp11_session_sign_finish (session, result, &n_output, &error);
	SUCCESS_RES (output, error);
	g_assert_cmpuint (n_output, ==, 17);
	g_assert_cmpstr ((gchar*)output, ==, "my-prefix:Conrad");
	g_free (output);

	g_object_unref (result);
	g_object_unref (key);
}

DEFINE_TEST(verify)
{
	GP11Mechanism mech;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GP11Object *key;
	gboolean ret;

	mech.type = CKM_PREFIX;
	mech.n_parameter = 10;
	mech.parameter = "my-prefix:";
	
	/* Enable auto-login on this session, shouldn't be needed */
	gp11_module_set_auto_authenticate (module, TRUE);
	g_signal_connect (module, "authenticate-object", G_CALLBACK (authenticate_object), NULL);

	/* Find the right key */
	key = find_key (session, CKA_VERIFY, CKM_PREFIX);
	g_assert (key);
	
	/* Simple one */
	ret = gp11_session_verify (session, key, CKM_PREFIX, (const guchar*)"Labarbara", 10, 
	                           (const guchar*)"signed-prefix:Labarbara", 24, &error);
	SUCCESS_RES (ret, error);
	
	/* Full one */
	ret = gp11_session_verify_full (session, key, &mech, (const guchar*)"Labarbara", 10, 
	                                (const guchar*)"my-prefix:Labarbara", 20, NULL, &error);
	SUCCESS_RES (ret, error);

	/* Failure one */
	ret = gp11_session_verify_full (session, key, &mech, (const guchar*)"Labarbara", 10, 
	                                (const guchar*)"my-prefix:Loborboro", 20, NULL, &error);
	FAIL_RES (ret, error);

	/* Asynchronous one */
	gp11_session_verify_async (session, key, &mech, (const guchar*)"Labarbara", 10, 
	                           (const guchar*)"my-prefix:Labarbara", 20, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);
	ret = gp11_session_verify_finish (session, result, &error);
	SUCCESS_RES (ret, error);
	g_object_unref (result);
	
	/* Asynchronous failure */
	result = NULL;
	gp11_session_verify_async (session, key, &mech, (const guchar*)"Labarbara", 10, 
	                           (const guchar*)"my-prefix:Labarxoro", 20, NULL, fetch_async_result, &result);
	WAIT_UNTIL (result);
	g_assert (result != NULL);
	ret = gp11_session_verify_finish (session, result, &error);
	FAIL_RES (ret, error);
	g_object_unref (result);

	g_object_unref (key);
}
