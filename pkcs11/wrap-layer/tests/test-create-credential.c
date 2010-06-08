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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

#include "gkm/gkm-test.h"
#include "gkm/gkm-util.h"

#include "pkcs11/pkcs11.h"

#include "wrap-layer/gkm-wrap-layer.h"

#include "ui/gku-prompt.h"

#include <glib-object.h>

CK_FUNCTION_LIST create_credential_functions = {
	{ 2, 11 },	/* version */
	gkm_test_C_Initialize,
	gkm_test_C_Finalize,
	gkm_test_C_GetInfo,
	gkm_test_C_GetFunctionList,
	gkm_test_C_GetSlotList,
	gkm_test_C_GetSlotInfo,
	gkm_test_C_GetTokenInfo,
	gkm_test_C_GetMechanismList,
	gkm_test_C_GetMechanismInfo,
	gkm_test_C_InitToken,
	gkm_test_C_InitPIN,
	gkm_test_C_SetPIN,
	gkm_test_C_OpenSession,
	gkm_test_C_CloseSession,
	gkm_test_C_CloseAllSessions,
	gkm_test_C_GetSessionInfo,
	gkm_test_C_GetOperationState,
	gkm_test_C_SetOperationState,
	gkm_test_C_Login,
	gkm_test_C_Logout,
	gkm_test_C_CreateObject,
	gkm_test_C_CopyObject,
	gkm_test_C_DestroyObject,
	gkm_test_C_GetObjectSize,
	gkm_test_C_GetAttributeValue,
	gkm_test_C_SetAttributeValue,
	gkm_test_C_FindObjectsInit,
	gkm_test_C_FindObjects,
	gkm_test_C_FindObjectsFinal,
	gkm_test_C_EncryptInit,
	gkm_test_C_Encrypt,
	gkm_test_C_EncryptUpdate,
	gkm_test_C_EncryptFinal,
	gkm_test_C_DecryptInit,
	gkm_test_C_Decrypt,
	gkm_test_C_DecryptUpdate,
	gkm_test_C_DecryptFinal,
	gkm_test_C_DigestInit,
	gkm_test_C_Digest,
	gkm_test_C_DigestUpdate,
	gkm_test_C_DigestKey,
	gkm_test_C_DigestFinal,
	gkm_test_C_SignInit,
	gkm_test_C_Sign,
	gkm_test_C_SignUpdate,
	gkm_test_C_SignFinal,
	gkm_test_C_SignRecoverInit,
	gkm_test_C_SignRecover,
	gkm_test_C_VerifyInit,
	gkm_test_C_Verify,
	gkm_test_C_VerifyUpdate,
	gkm_test_C_VerifyFinal,
	gkm_test_C_VerifyRecoverInit,
	gkm_test_C_VerifyRecover,
	gkm_test_C_DigestEncryptUpdate,
	gkm_test_C_DecryptDigestUpdate,
	gkm_test_C_SignEncryptUpdate,
	gkm_test_C_DecryptVerifyUpdate,
	gkm_test_C_GenerateKey,
	gkm_test_C_GenerateKeyPair,
	gkm_test_C_WrapKey,
	gkm_test_C_UnwrapKey,
	gkm_test_C_DeriveKey,
	gkm_test_C_SeedRandom,
	gkm_test_C_GenerateRandom,
	gkm_test_C_GetFunctionStatus,
	gkm_test_C_CancelFunction,
	gkm_test_C_WaitForSlotEvent
};

EGG_SECURE_GLIB_DEFINITIONS()

static gpointer
test (gpointer loop)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
	CK_SLOT_ID slot_id;
	CK_ULONG n_slots = 1;
	CK_RV rv;

	gku_prompt_queue_dummy_ok_password ("booo");

	gkm_wrap_layer_add_module (&create_credential_functions);
	module = gkm_wrap_layer_get_functions ();

	/* Open a session */
	rv = (module->C_Initialize) (NULL);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	rv = (module->C_GetSlotList) (CK_TRUE, &slot_id, &n_slots);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	rv = (module->C_OpenSession) (slot_id, CKF_SERIAL_SESSION, NULL, NULL, &session);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	rv = (module->C_Login) (session, CKU_USER, NULL, 0);
	if (rv == CKR_PIN_INCORRECT) {
		g_message ("pin incorrect");
	} else {
		gkm_assert_cmprv (rv, ==, CKR_OK);
		g_message ("pin correct");
	}

	rv = (module->C_CloseSession) (session);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	rv = (module->C_Finalize) (NULL);
	gkm_assert_cmprv (rv, ==, CKR_OK);

	g_main_loop_quit (loop);
	return NULL;
}

int
main(void)
{
	GThread *thread;
	GMainLoop *loop;

	g_type_init ();
	g_thread_init (NULL);
	egg_libgcrypt_initialize ();

	loop = g_main_loop_new (NULL, FALSE);
	thread = g_thread_create (test, loop, TRUE, NULL);
	g_assert (thread);

	g_main_loop_run (loop);

	g_thread_join (thread);
	g_main_loop_unref (loop);

	return 0;
}
