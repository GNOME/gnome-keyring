/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "gkd-pkcs11-auth.h"
#include "gkd-pkcs11-data.h"

#include "egg/egg-secure-memory.h"

#include "login/gkd-login.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"
#include "pkcs11/pkcs11i.h"

#include "prompt/gkd-prompt.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <string.h>

/*
 * All these function entry points operate outside of any threading locks.
 * Only calls that may be made to gkd_*() functions are to gkd_pkcs11_auth_*()
 * functions.
 */

static CK_FUNCTION_LIST_PTR pkcs11_lower = NULL;

typedef struct _AuthObject {
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_CLASS klass;
	CK_SLOT_ID slot;
	CK_BBOOL token;
	gchar *label;
	gchar *unique;
	gchar *digest;
} AuthObject;

static void
auth_object_free (gpointer data)
{
	AuthObject *object = data;
	g_assert (object);
	g_free (object->label);
	g_free (object->unique);
	g_free (object->digest);
	g_free (object);
}

/* --------------------------------------------------------------------------------------
 * HELPERS
 */

static AuthObject*
auth_object_for_context_specific (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object)
{
	AuthObject *info = NULL;
	CK_SESSION_INFO session_info;
	CK_ATTRIBUTE attrs[6];
	CK_OBJECT_CLASS klass;
	gchar *label = NULL;
	gchar *unique = NULL;
	gchar *digest = NULL;
	CK_BBOOL token, always;
	CK_ULONG n_attrs;
	CK_RV rv;

	/* Lookup information about the specific object */
	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label = NULL;
	attrs[0].ulValueLen = 0;

	attrs[1].type = CKA_GNOME_UNIQUE;
	attrs[1].pValue = unique = NULL;
	attrs[1].ulValueLen = 0;

	/* COMPAT: Loaded for compatibility with old gnome-keyrings */
	attrs[2].type = CKA_GNOME_INTERNAL_SHA1;
	attrs[2].pValue = digest = NULL;
	attrs[2].ulValueLen = 0;

	attrs[3].type = CKA_CLASS;
	attrs[3].pValue = &klass;
	attrs[3].ulValueLen = sizeof (klass);

	always = CK_FALSE;
	attrs[4].type = CKA_ALWAYS_AUTHENTICATE;
	attrs[4].pValue = &always;
	attrs[4].ulValueLen = sizeof (always);

	token = CK_FALSE;
	attrs[5].type = CKA_TOKEN;
	attrs[5].pValue = &token;
	attrs[5].ulValueLen = sizeof (token);

	n_attrs = 6;

	/* Get attribute sizes */
	rv = (pkcs11_lower->C_GetAttributeValue) (handle, object, attrs, n_attrs);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID)
		return NULL;

	/* If this isn't an always auth object, then skip */
	if (always != CK_TRUE)
		return NULL;

	/* Make sure we can get the session info */
	rv = (pkcs11_lower->C_GetSessionInfo) (handle, &session_info);
	if (rv != CKR_OK)
		return NULL;

	/* Allocate memory for big attributes */
	if (attrs[0].ulValueLen != (CK_ULONG)-1)
		attrs[0].pValue = label = g_malloc0 (attrs[0].ulValueLen + 1);
	if (attrs[1].ulValueLen != (CK_ULONG)-1)
		attrs[1].pValue = unique = g_malloc0 (attrs[1].ulValueLen + 1);
	if (attrs[2].ulValueLen != (CK_ULONG)-1)
		attrs[2].pValue = digest = g_malloc0 (attrs[2].ulValueLen + 1);

	/* Get actual attributes */
	rv = (pkcs11_lower->C_GetAttributeValue) (handle, object, attrs, n_attrs);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		g_free (label);
		g_free (unique);
		g_free (digest);
		return NULL;
	}

	info = g_new0 (AuthObject, 1);

	if (attrs[0].ulValueLen != (CK_ULONG)-1) {
		info->label = label;
		label = NULL;
	}

	if (attrs[1].ulValueLen != (CK_ULONG)-1) {
		info->unique = unique;
		unique = NULL;
	}

	if (attrs[2].ulValueLen != (CK_ULONG)-1) {
		info->digest = digest;
		digest = NULL;
	}

	info->token = token;
	info->klass = klass;
	info->handle = object;
	info->slot = session_info.slotID;

	g_free (label);
	g_free (unique);
	g_free (digest);

	return info;
}

static void
auth_create_credential (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                         CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	CK_OBJECT_CLASS klass = CKO_G_CREDENTIAL;
	CK_BBOOL transient = CK_TRUE;
	CK_BBOOL token = CK_FALSE;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_G_OBJECT, &object, sizeof (object) },
		{ CKA_GNOME_TRANSIENT, &transient, sizeof (transient) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_VALUE, pin, n_pin }
	};

	CK_OBJECT_HANDLE credential;
	CK_RV rv;

	rv = pkcs11_lower->C_CreateObject (session, attrs, G_N_ELEMENTS (attrs), &credential);
	if (rv != CKR_OK)
		g_message ("failed to create credential object (code: %lu)", (gulong)rv);
}

static void
password_to_pin (const gchar *password, CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len)
{
	g_assert (pin);
	g_assert (pin_len);

	if (password == NULL) {
		*pin = NULL;
		*pin_len = 0;
	} else {
		*pin = (CK_UTF8CHAR_PTR)password;
		*pin_len = strlen (password);
	}
}

static void
convert_upper_case (gchar *str)
{
	for (; *str; ++str)
		*str = g_ascii_toupper (*str);
}

static GkdPrompt*
on_prompt_attention (gpointer user_data)
{
	/* We were passed the prompt */
	return g_object_ref (user_data);
}

static void
clear_user_login (CK_TOKEN_INFO *info)
{
	gchar *manufacturer;
	gchar *serial;

	g_assert (info);

	if (gkd_login_is_usable ()) {
		/*
		 * The manufacturer and serial number together uniquely identify token
		 * They're stored with space padded in the token info structure.
		 */

		manufacturer = g_strndup ((gchar*)info->manufacturerID, sizeof (info->manufacturerID));
		g_strchomp (manufacturer);

		serial = g_strndup ((gchar*)info->serialNumber, sizeof (info->serialNumber));
		g_strchomp (serial);

		gkd_login_remove_secret ("manufacturer", manufacturer,
		                         "serial-number", serial,
		                         NULL);

		g_free (manufacturer);
		g_free (serial);
	}
}

static gboolean
init_user_prompt (CK_SESSION_HANDLE handle, CK_TOKEN_INFO *info,
                  CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len)
{
	GkdPrompt *prompt;
	gchar *password;
	gchar *label;
	gchar *secondary;
	gchar *manufacturer;
	gchar *serial;
	gboolean ret = TRUE;

	g_assert (info);
	g_assert (pin);
	g_assert (pin_len);

	/*
	 * The manufacturer and serial number together uniquely identify token
	 * They're stored with space padded in the token info structure.
	 */

	manufacturer = g_strndup ((gchar*)info->manufacturerID, sizeof (info->manufacturerID));
	g_strchomp (manufacturer);

	serial = g_strndup ((gchar*)info->serialNumber, sizeof (info->serialNumber));
	g_strchomp (serial);

	label = g_strndup ((gchar*)info->label, sizeof (info->label));
	g_strchomp (label);

	/* Build up the prompt */
	prompt = gkd_prompt_new ();
	gkd_prompt_show_widget (prompt, "password_area");
	gkd_prompt_show_widget (prompt, "confirm_area");
	gkd_prompt_set_title (prompt, _("New Password Required"));
	gkd_prompt_set_primary_text (prompt, _("New password required for secure storage"));

	secondary = g_strdup_printf (_("In order to prepare '%s' for storage of certificates or keys, a password is required"), label);
	gkd_prompt_set_secondary_text (prompt, secondary);
	g_free (secondary);

	if (gkd_login_is_usable ()) {
		gkd_prompt_show_widget (prompt, "details_area");
		gkd_prompt_show_widget (prompt, "lock_area");
		gkd_prompt_hide_widget (prompt, "options_area");
	}

	/* Prompt the user */
	gkd_prompt_request_attention_async (NULL, on_prompt_attention, prompt, NULL);

	if (!gkd_prompt_has_response (prompt)) {
		ret = FALSE;

	} else if (gkd_prompt_get_response (prompt) != GKD_RESPONSE_OK) {
		ret = FALSE;

	/* Successful response */
	} else {
		password = gkd_prompt_get_password (prompt, "password");

		if (gkd_prompt_get_unlock_auto (prompt)) {
			gkd_login_attach_secret (label, password,
			                         "manufacturer", manufacturer,
			                         "serial-number", serial,
			                         NULL);
		}

		password_to_pin (password, pin, pin_len);
		ret = TRUE;
	}

	g_free (manufacturer);
	g_free (serial);
	g_free (label);

	g_object_unref (prompt);
	return ret;
}

static void
init_user_done (CK_SESSION_HANDLE handle, CK_TOKEN_INFO *token_info,
                CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len, CK_RV rv)
{
	g_assert (pin);
	g_assert (pin_len);

	if (rv != CKR_OK)
		clear_user_login (token_info);

	egg_secure_strfree ((gchar*)*pin);

	*pin = NULL;
	*pin_len = 0;
}

static const gchar*
prepare_specific_title (CK_OBJECT_CLASS klass)
{
	switch (klass) {
	case CKO_PRIVATE_KEY:
		return _("Unlock private key");
	case CKO_CERTIFICATE:
		return _("Unlock certificate");
	case CKO_PUBLIC_KEY:
		return _("Unlock public key");
	default:
		return _("Unlock");
	}
}

static const gchar*
prepare_specific_primary (CK_OBJECT_CLASS klass)
{
	switch (klass) {
	case CKO_PRIVATE_KEY:
		return _("Enter password to unlock the private key");
	case CKO_CERTIFICATE:
		return _("Enter password to unlock the certificate");
	case CKO_PUBLIC_KEY:
		return _("Enter password to unlock the public key");
	default:
		return _("Enter password to unlock");
	}
}

static gchar*
prepare_specific_secondary (CK_OBJECT_CLASS klass, const gchar *label)
{
	switch (klass) {
	case CKO_PRIVATE_KEY:
		/* TRANSLATORS: The private key is locked */
		return g_strdup_printf (_("An application wants access to the private key '%s', but it is locked"), label);
	case CKO_CERTIFICATE:
		/* TRANSLATORS: The certificate is locked */
		return g_strdup_printf (_("An application wants access to the certificate '%s', but it is locked"), label);
	case CKO_PUBLIC_KEY:
		/* TRANSLATORS: The public key is locked */
		return g_strdup_printf (_("An application wants access to the public key '%s', but it is locked"), label);
	default:
		/* TRANSLATORS: The object '%s' is locked */
		return g_strdup_printf (_("An application wants access to '%s', but it is locked"), label);
	}
}

static void
login_specific_prepare (CK_SESSION_HANDLE handle, AuthObject *object)
{
	gkd_pkcs11_data_session_store (object->slot, handle, object, auth_object_free);
}

static gboolean
login_specific_prompt (CK_SESSION_HANDLE handle, CK_SESSION_INFO *info,
                       CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len,
                       CK_OBJECT_HANDLE_PTR specific)
{
	AuthObject *object;
	const gchar *password;
	GkdPrompt *prompt;
	gchar *secondary;
	gboolean ret;

	g_assert (info);
	g_assert (pin);
	g_assert (pin_len);

	/* Because we should have been notified of open session */
	object = gkd_pkcs11_data_session_lookup (info->slotID, handle);
	if (object == NULL)
		return FALSE;

	if (specific)
		*specific = object->handle;

	/* See if we can just use the login keyring password for this */
	if (object->unique && object->token) {
		password = gkd_login_lookup_secret ("unique", object->unique, NULL);
		if (password != NULL) {
			password_to_pin (password, pin, pin_len);
			return TRUE;
		}
	}

	/* COMPAT: Check old method of storing secrets for objects in login keyring */
	if (object->digest) {
		convert_upper_case (object->digest);
		password = gkd_login_lookup_secret ("object-digest", object->digest, NULL);
		if (password != NULL) {
			if (object->unique)
				gkd_login_attach_secret (object->label, password,
				                         "unique", object->unique, NULL);
			password_to_pin (password, pin, pin_len);
			return TRUE;
		}
	}

	/* Build up the prompt */
	prompt = gkd_prompt_new ();
	gkd_prompt_show_widget (prompt, "password_area");
	gkd_prompt_hide_widget (prompt, "confirm_area");
	gkd_prompt_hide_widget (prompt, "original_area");
	gkd_prompt_set_title (prompt, prepare_specific_title (object->klass));
	gkd_prompt_set_primary_text (prompt, prepare_specific_primary (object->klass));

	secondary = prepare_specific_secondary (object->klass, object->label);
	gkd_prompt_set_secondary_text (prompt, secondary);
	g_free (secondary);

	if (object->unique && gkd_login_is_usable ()) {
		gkd_prompt_show_widget (prompt, "details_area");
		gkd_prompt_show_widget (prompt, "lock_area");
		gkd_prompt_hide_widget (prompt, "options_area");
	}

	/* Prompt the user */
	gkd_prompt_request_attention_sync (NULL, on_prompt_attention, prompt, NULL);

	if (!gkd_prompt_has_response (prompt))
		ret = FALSE;

	/* Successful response */
	else if (gkd_prompt_get_response (prompt) == GKD_RESPONSE_OK) {
		password = gkd_prompt_get_password (prompt, "password");

		/* Store forever */
		if (gkd_prompt_get_unlock_auto (prompt) && object->unique && object->token) {
			gkd_login_attach_secret (object->label, password,
			                         "unique", object->unique, NULL);
		}

		password_to_pin (password, pin, pin_len);
		ret = TRUE;

	/* Other failures etc... */
	} else {
		ret = FALSE;
	}

	g_object_unref (prompt);
	return ret;
}

static void
login_specific_done (CK_SESSION_HANDLE handle, CK_SESSION_INFO *info,
                     CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len, CK_RV rv)
{
	AuthObject *object;

	g_assert (pin);
	g_assert (pin_len);

	/* Because we should have been notified of open session */
	object = gkd_pkcs11_data_session_lookup (info->slotID, handle);
	g_return_if_fail (object);

	switch (rv) {
	case CKR_PIN_INCORRECT:
	case CKR_PIN_EXPIRED:
	case CKR_PIN_INVALID:
	case CKR_PIN_LEN_RANGE:
	case CKR_PIN_LOCKED:
		/* Clear out any stored secret */
		if (object->unique && object->token)
			gkd_login_remove_secret ("unique", object->unique, NULL);

		/* COMPAT: Clear old method of storing secrets for objects in login keyring */
		if (object->digest) {
			convert_upper_case (object->digest);
			gkd_login_remove_secret ("object-digest", object->digest, NULL);
		}
		break;

	case CKR_OK:
		gkd_pkcs11_data_session_remove (info->slotID, handle);
		break;

	default:
		break;
	}

	egg_secure_strfree ((gchar*)*pin);

	*pin = NULL;
	*pin_len = 0;
}


static gboolean
login_user_prompt (CK_SESSION_HANDLE handle, CK_TOKEN_INFO *info,
                   CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len)
{
	GkdPrompt *prompt;
	gchar *label;
	gchar *secondary;
	gchar *manufacturer;
	gchar *serial;
	const gchar *password;
	gboolean ret = TRUE;

	g_assert (info);
	g_assert (pin);
	g_assert (pin_len);

	/*
	 * The manufacturer and serial number together uniquely identify token
	 * They're stored with space padded in the token info structure.
	 */

	manufacturer = g_strndup ((gchar*)info->manufacturerID, sizeof (info->manufacturerID));
	g_strchomp (manufacturer);

	serial = g_strndup ((gchar*)info->serialNumber, sizeof (info->serialNumber));
	g_strchomp (serial);

	label = g_strndup ((gchar*)info->label, sizeof (info->label));
	g_strchomp (label);

	if (gkd_login_is_usable ()) {

		password = gkd_login_lookup_secret ("manufacturer", manufacturer,
		                                    "serial-number", serial,
		                                    NULL);
		if (password != NULL) {
			password_to_pin (password, pin, pin_len);
			g_free (manufacturer);
			g_free (serial);
			g_free (label);
			return TRUE;
		}
	}

	/* Build up the prompt */
	prompt = gkd_prompt_new ();
	gkd_prompt_show_widget (prompt, "password_area");
	gkd_prompt_hide_widget (prompt, "confirm_area");
	gkd_prompt_hide_widget (prompt, "original_area");
	gkd_prompt_set_title (prompt, _("Unlock certificate/key storage"));
	gkd_prompt_set_primary_text (prompt, _("Enter password to unlock the certificate/key storage"));

	/* TRANSLATORS: The storage is locked, and needs unlocking before the application can use it. */
	secondary = g_strdup_printf (_("An application wants access to the certificate/key storage '%s', but it is locked"), label);
	gkd_prompt_set_secondary_text (prompt, secondary);
	g_free (secondary);

	if (gkd_login_is_usable ()) {
		gkd_prompt_show_widget (prompt, "details_area");
		gkd_prompt_show_widget (prompt, "lock_area");
		gkd_prompt_hide_widget (prompt, "options_area");
	}

	/* Prompt the user */
	gkd_prompt_request_attention_sync (NULL, on_prompt_attention, prompt, NULL);

	if (!gkd_prompt_has_response (prompt)) {
		ret = FALSE;

	/* User cancelled or failure */
	} else if (gkd_prompt_get_response (prompt) != GKD_RESPONSE_OK) {
		ret = FALSE;

	/* Successful response */
	} else {
		password = gkd_prompt_get_password (prompt, "password");

		/* Store forever */
		if (gkd_prompt_get_unlock_auto (prompt)) {
			gkd_login_attach_secret (label, password,
			                         "manufacturer", manufacturer,
			                         "serial-number", serial,
			                         NULL);
		}

		password_to_pin (password, pin, pin_len);
		ret = TRUE;
	}

	g_free (manufacturer);
	g_free (serial);
	g_free (label);

	g_object_unref (prompt);
	return ret;
}


static void
login_user_done (CK_SESSION_HANDLE handle, CK_TOKEN_INFO *info,
                 CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len, CK_RV rv)
{
	g_assert (pin);
	g_assert (pin_len);

	switch (rv) {
	case CKR_PIN_INCORRECT:
	case CKR_PIN_EXPIRED:
	case CKR_PIN_INVALID:
	case CKR_PIN_LEN_RANGE:
	case CKR_PIN_LOCKED:
		clear_user_login (info);
		break;
	}

	egg_secure_strfree ((gchar*)*pin);

	*pin = NULL;
	*pin_len = 0;
}

/* --------------------------------------------------------------------------------------
 * PKCS#11 ENTRY POINTS
 */

static CK_RV
auth_C_Initialize (CK_VOID_PTR init_args)
{
	CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)init_args;
	gboolean supplied_ok;
	CK_RV rv;

	if (args) {

		/* ALL supplied function pointers need to have the value either NULL or non-NULL. */
		supplied_ok = (args->CreateMutex == NULL && args->DestroyMutex == NULL &&
		               args->LockMutex == NULL && args->UnlockMutex == NULL) ||
		              (args->CreateMutex != NULL && args->DestroyMutex != NULL &&
		               args->LockMutex != NULL && args->UnlockMutex != NULL);

		if (!supplied_ok) {
			g_message ("invalid set of mutex calls supplied");
			return CKR_ARGUMENTS_BAD;
		}

		if (!(args->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)) {
			g_message ("must be able to create our own threads");
			return CKR_NEED_TO_CREATE_THREADS;
		}

		if (!(args->flags & CKF_OS_LOCKING_OK)) {
			g_message ("must be able to use our own locking and multi-thread primitives");
			return CKR_CANT_LOCK;
		}
	}

	rv = pkcs11_lower->C_Initialize (init_args);

	/* Let our auth caches/storage know we're initializing */
	if (rv == CKR_OK)
		gkd_pkcs11_data_initialized ();

	return rv;
}

static CK_RV
auth_C_Finalize (CK_VOID_PTR reserved)
{
	CK_RV rv;

	rv = (pkcs11_lower->C_Finalize) (reserved);

	/* Let our auth caches/storage know we're initializing */
	if (rv == CKR_OK)
		gkd_pkcs11_data_finalized ();

	return rv;
}

static CK_RV
auth_C_GetInfo (CK_INFO_PTR info)
{
	return (pkcs11_lower->C_GetInfo) (info);
}

static CK_RV
auth_C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	if (!list)
		return CKR_ARGUMENTS_BAD;
	*list = gkd_pkcs11_auth_get_functions ();
	return CKR_OK;
}

static CK_RV
auth_C_GetSlotList (CK_BBOOL token_present, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR count)
{
	return (pkcs11_lower->C_GetSlotList) (token_present, slot_list, count);
}

static CK_RV
auth_C_GetSlotInfo (CK_SLOT_ID id, CK_SLOT_INFO_PTR info)
{
	return (pkcs11_lower->C_GetSlotInfo) (id, info);
}

static CK_RV
auth_C_GetTokenInfo (CK_SLOT_ID id, CK_TOKEN_INFO_PTR info)
{
	CK_RV rv = (pkcs11_lower->C_GetTokenInfo) (id, info);
	if (rv == CKR_OK)
		info->flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
	return rv;
}

static CK_RV
auth_C_GetMechanismList (CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR mechanism_list, CK_ULONG_PTR count)
{
	return (pkcs11_lower->C_GetMechanismList) (id, mechanism_list, count);
}

static CK_RV
auth_C_GetMechanismInfo (CK_SLOT_ID id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
{
	return (pkcs11_lower->C_GetMechanismInfo) (id, type, info);
}

static CK_RV
auth_C_InitToken (CK_SLOT_ID id, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
{
	/* TODO: Implement prompting for auth here */
	return (pkcs11_lower->C_InitToken) (id, pin, pin_len, label);
}

static CK_RV
auth_C_WaitForSlotEvent (CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved)
{
	return (pkcs11_lower->C_WaitForSlotEvent) (flags, slot, reserved);
}

static CK_RV
auth_C_OpenSession (CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR user_data,
                    CK_NOTIFY callback, CK_SESSION_HANDLE_PTR handle)
{
	CK_SESSION_INFO session_info;
	CK_RV rv;

	rv = (pkcs11_lower->C_OpenSession) (id, flags, user_data, callback, handle);
	if (rv == CKR_OK) {
		/* Track this session in our auth layer */
		if ((pkcs11_lower->C_GetSessionInfo) (*handle, &session_info) == CKR_OK)
			gkd_pkcs11_data_session_opened (session_info.slotID, *handle);
	}

	return rv;
}

static CK_RV
auth_C_CloseSession (CK_SESSION_HANDLE handle)
{
	gboolean have_session_info = FALSE;
	CK_SESSION_INFO session_info;
	CK_RV rv;

	if ((pkcs11_lower->C_GetSessionInfo) (handle, &session_info) == CKR_OK)
		have_session_info = TRUE;

	rv = (pkcs11_lower->C_CloseSession) (handle);

	/* Track this session closure in our auth cache/store */
	if (rv == CKR_OK && have_session_info)
		gkd_pkcs11_data_session_closed (session_info.slotID, handle);

	return rv;
}

static CK_RV
auth_C_CloseAllSessions (CK_SLOT_ID id)
{
	CK_RV rv = (pkcs11_lower->C_CloseAllSessions) (id);

	/* Track this session closure in our auth cache/store */
	if (rv == CKR_OK)
		gkd_pkcs11_data_session_closed_all (id);

	return rv;
}

static CK_RV
auth_C_GetFunctionStatus (CK_SESSION_HANDLE handle)
{
	return (pkcs11_lower->C_GetFunctionStatus) (handle);
}

static CK_RV
auth_C_CancelFunction (CK_SESSION_HANDLE handle)
{
	return (pkcs11_lower->C_CancelFunction) (handle);
}

static CK_RV
auth_C_GetSessionInfo (CK_SESSION_HANDLE handle, CK_SESSION_INFO_PTR info)
{
	return (pkcs11_lower->C_GetSessionInfo) (handle, info);
}

static CK_RV
auth_C_InitPIN (CK_SESSION_HANDLE handle, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	CK_SESSION_INFO session_info;
	CK_TOKEN_INFO token_info;
	gboolean init_auth = FALSE;
	CK_RV rv;

	/* Dig up the information we'll need, and don't prompt if protected auth path */
	if ((pkcs11_lower->C_GetSessionInfo) (handle, &session_info) == CKR_OK &&
	    (pkcs11_lower->C_GetTokenInfo) (session_info.slotID, &token_info) == CKR_OK &&
	    !(token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
		init_auth = init_user_prompt (handle, &token_info, &pin, &n_pin);
	}

	rv = (pkcs11_lower->C_InitPIN) (handle, pin, n_pin);

	if (init_auth)
		init_user_done (handle, &token_info, &pin, &n_pin, rv);

	return rv;
}

static CK_RV
auth_C_SetPIN (CK_SESSION_HANDLE handle, CK_UTF8CHAR_PTR old_pin, CK_ULONG n_old_pin,
               CK_UTF8CHAR_PTR new_pin, CK_ULONG n_new_pin)
{
	CK_SESSION_INFO session_info;
	CK_TOKEN_INFO token_info;
	gboolean init_auth = FALSE;
	CK_RV rv;

	/* Dig up the information we'll need, and don't prompt if protected auth path */
	if ((pkcs11_lower->C_GetSessionInfo) (handle, &session_info) == CKR_OK &&
	    (pkcs11_lower->C_GetTokenInfo) (session_info.slotID, &token_info) == CKR_OK &&
	    !(token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
		if (!(token_info.flags & CKF_USER_PIN_INITIALIZED))
			init_auth = init_user_prompt (handle, &token_info, &new_pin, &n_new_pin);
		/* TODO: Prompt for other 'change password' case */
	}

	rv = (pkcs11_lower->C_SetPIN) (handle, old_pin, n_old_pin, new_pin, n_new_pin);

	if (init_auth) {
		init_user_done (handle, &token_info, &new_pin, &n_new_pin, rv);
		/* TODO: Done for other case */
	}

	return rv;
}

static CK_RV
auth_C_GetOperationState (CK_SESSION_HANDLE handle, CK_BYTE_PTR operation_state, CK_ULONG_PTR operation_state_len)
{
	return (pkcs11_lower->C_GetOperationState) (handle, operation_state, operation_state_len);
}

static CK_RV
auth_C_SetOperationState (CK_SESSION_HANDLE handle, CK_BYTE_PTR operation_state,
                          CK_ULONG operation_state_len, CK_OBJECT_HANDLE encryption_key,
                          CK_OBJECT_HANDLE authentication_key)
{
	return (pkcs11_lower->C_SetOperationState) (handle, operation_state, operation_state_len, encryption_key, authentication_key);
}

static CK_RV
auth_C_Login (CK_SESSION_HANDLE handle, CK_USER_TYPE user_type,
              CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	CK_SESSION_INFO session_info;
	CK_TOKEN_INFO token_info;
	CK_OBJECT_HANDLE object = 0;
	gboolean auth = FALSE;
	CK_RV rv;

	/* Try the login first, this allows NULL logins to be tried */
	rv = (pkcs11_lower->C_Login) (handle, user_type, pin, pin_len);

	/* See if we can help the login to work */
	if (rv != CKR_PIN_INCORRECT)
		return rv;

	/* Dig up the information we'll need */
	if ((pkcs11_lower->C_GetSessionInfo) (handle, &session_info) != CKR_OK)
		return rv;
	if ((pkcs11_lower->C_GetTokenInfo) (session_info.slotID, &token_info) != CKR_OK)
		return rv;

	/* If lower level is a protected authentication path, then don't bother */
	if (token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		return rv;

	/* Loop until logged in or user cancels */
	while (rv == CKR_PIN_INCORRECT) {
		switch (user_type) {
		case CKU_CONTEXT_SPECIFIC:
			auth = login_specific_prompt (handle, &session_info, &pin, &pin_len, &object);
			break;
		case CKU_USER:
			auth = login_user_prompt (handle, &token_info, &pin, &pin_len);
			break;
		default:
			break;
		};

		if (!auth) {
			rv = CKR_FUNCTION_CANCELED;
			break;
		}

		/* Try the login again */
		rv = (pkcs11_lower->C_Login) (handle, user_type, pin, pin_len);

		/* If that was successful, then we can create an authenticator object */
		if (user_type == CKU_CONTEXT_SPECIFIC && rv == CKR_OK && object != 0)
			auth_create_credential (handle, object, pin, pin_len);

		/* Wrap things up */
		switch (user_type) {
		case CKU_CONTEXT_SPECIFIC:
			login_specific_done (handle, &session_info, &pin, &pin_len, rv);
			break;
		case CKU_USER:
			login_user_done (handle, &token_info, &pin, &pin_len, rv);
			break;
		default:
			break;
		};
	}

	return rv;
}

static CK_RV
auth_C_Logout (CK_SESSION_HANDLE handle)
{
	return (pkcs11_lower->C_Logout) (handle);
}

static CK_RV
auth_C_CreateObject (CK_SESSION_HANDLE handle, CK_ATTRIBUTE_PTR template,
                     CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object)
{
	return (pkcs11_lower->C_CreateObject) (handle, template, count, new_object);
}

static CK_RV
auth_C_CopyObject (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                   CK_ATTRIBUTE_PTR template, CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR new_object)
{
	return (pkcs11_lower->C_CopyObject) (handle, object, template, count, new_object);
}

static CK_RV
auth_C_DestroyObject (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object)
{
	return (pkcs11_lower->C_DestroyObject) (handle, object);
}

static CK_RV
auth_C_GetObjectSize (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                      CK_ULONG_PTR size)
{
	return (pkcs11_lower->C_GetObjectSize) (handle, object, size);
}

static CK_RV
auth_C_GetAttributeValue (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                          CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	return (pkcs11_lower->C_GetAttributeValue) (handle, object, template, count);
}

static CK_RV
auth_C_SetAttributeValue (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                          CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	return (pkcs11_lower->C_SetAttributeValue) (handle, object, template, count);
}

static CK_RV
auth_C_FindObjectsInit (CK_SESSION_HANDLE handle, CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	return (pkcs11_lower->C_FindObjectsInit) (handle, template, count);
}

static CK_RV
auth_C_FindObjects (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE_PTR objects,
                    CK_ULONG max_count, CK_ULONG_PTR count)
{
	return (pkcs11_lower->C_FindObjects) (handle, objects, max_count, count);
}

static CK_RV
auth_C_FindObjectsFinal (CK_SESSION_HANDLE handle)
{
	return (pkcs11_lower->C_FindObjectsFinal) (handle);
}

static CK_RV
auth_C_EncryptInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	AuthObject *object = NULL;
	CK_RV rv;

	rv = (pkcs11_lower->C_EncryptInit) (handle, mechanism, key);
	if (rv == CKR_OK) {
		object = auth_object_for_context_specific (handle, key);
		if (object != NULL)
			login_specific_prepare (handle, object);
	}

	return rv;
}

static CK_RV
auth_C_Encrypt (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len)
{
	CK_RV rv = (pkcs11_lower->C_Encrypt) (handle, data, data_len, encrypted_data, encrypted_data_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_Encrypt) (handle, data, data_len, encrypted_data, encrypted_data_len);
	}
	return rv;
}

static CK_RV
auth_C_EncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                      CK_ULONG part_len, CK_BYTE_PTR encrypted_part,
                      CK_ULONG_PTR encrypted_part_len)
{
	CK_RV rv = (pkcs11_lower->C_EncryptUpdate) (handle, part, part_len, encrypted_part, encrypted_part_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_EncryptUpdate) (handle, part, part_len, encrypted_part, encrypted_part_len);
	}
	return rv;
}

static CK_RV
auth_C_EncryptFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR last_part,
                     CK_ULONG_PTR last_part_len)
{
	return (pkcs11_lower->C_EncryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
auth_C_DecryptInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	AuthObject *object = NULL;
	CK_RV rv;

	rv = (pkcs11_lower->C_DecryptInit) (handle, mechanism, key);
	if (rv == CKR_OK) {
		object = auth_object_for_context_specific (handle, key);
		if (object != NULL)
			login_specific_prepare (handle, object);
	}

	return rv;
}

static CK_RV
auth_C_Decrypt (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_data,
                CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	CK_RV rv = (pkcs11_lower->C_Decrypt) (handle, enc_data, enc_data_len, data, data_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_Decrypt) (handle, enc_data, enc_data_len, data, data_len);
	}
	return rv;
}

static CK_RV
auth_C_DecryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                      CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len)
{
	CK_RV rv = (pkcs11_lower->C_DecryptUpdate) (handle, enc_part, enc_part_len, part, part_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_DecryptUpdate) (handle, enc_part, enc_part_len, part, part_len);
	}
	return rv;
}

static CK_RV
auth_C_DecryptFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR last_part,
                    CK_ULONG_PTR last_part_len)
{
	return (pkcs11_lower->C_DecryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
auth_C_DigestInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism)
{
	return (pkcs11_lower->C_DigestInit) (handle, mechanism);
}

static CK_RV
auth_C_Digest (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
               CK_BYTE_PTR digest, CK_ULONG_PTR digest_len)
{
	return (pkcs11_lower->C_Digest) (handle, data, data_len, digest, digest_len);
}

static CK_RV
auth_C_DigestUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	return (pkcs11_lower->C_DigestUpdate) (handle, part, part_len);
}

static CK_RV
auth_C_DigestKey (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE key)
{
	return (pkcs11_lower->C_DigestKey) (handle, key);
}

static CK_RV
auth_C_DigestFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR digest,
                    CK_ULONG_PTR digest_len)
{
	return (pkcs11_lower->C_DigestFinal) (handle, digest, digest_len);
}

static CK_RV
auth_C_SignInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE key)
{
	AuthObject *object = NULL;
	CK_RV rv;

	rv = (pkcs11_lower->C_SignInit) (handle, mechanism, key);
	if (rv == CKR_OK) {
		object = auth_object_for_context_specific (handle, key);
		if (object != NULL)
			login_specific_prepare (handle, object);
	}

	return rv;
}

static CK_RV
auth_C_Sign (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
             CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	CK_RV rv = (pkcs11_lower->C_Sign) (handle, data, data_len, signature, signature_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_Sign) (handle, data, data_len, signature, signature_len);
	}
	return rv;
}

static CK_RV
auth_C_SignUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	CK_RV rv = (pkcs11_lower->C_SignUpdate) (handle, part, part_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_SignUpdate) (handle, part, part_len);
	}
	return rv;
}

static CK_RV
auth_C_SignFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                  CK_ULONG_PTR signature_len)
{
	return (pkcs11_lower->C_SignFinal) (handle, signature, signature_len);
}

static CK_RV
auth_C_SignRecoverInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                        CK_OBJECT_HANDLE key)
{
	AuthObject *object = NULL;
	CK_RV rv;

	rv = (pkcs11_lower->C_SignRecoverInit) (handle, mechanism, key);
	if (rv == CKR_OK) {
		object = auth_object_for_context_specific (handle, key);
		if (object != NULL)
			login_specific_prepare (handle, object);
	}

	return rv;
}

static CK_RV
auth_C_SignRecover (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                    CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	CK_RV rv = (pkcs11_lower->C_SignRecover) (handle, data, data_len, signature, signature_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_SignRecover) (handle, data, data_len, signature, signature_len);
	}
	return rv;
}

static CK_RV
auth_C_VerifyInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	AuthObject *object = NULL;
	CK_RV rv;

	rv = (pkcs11_lower->C_VerifyInit) (handle, mechanism, key);
	if (rv == CKR_OK) {
		object = auth_object_for_context_specific (handle, key);
		if (object != NULL)
			login_specific_prepare (handle, object);
	}

	return rv;
}

static CK_RV
auth_C_Verify (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
               CK_BYTE_PTR signature, CK_ULONG signature_len)
{
	CK_RV rv = (pkcs11_lower->C_Verify) (handle, data, data_len, signature, signature_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_Verify) (handle, data, data_len, signature, signature_len);
	}
	return rv;
}

static CK_RV
auth_C_VerifyUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	CK_RV rv = (pkcs11_lower->C_VerifyUpdate) (handle, part, part_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_VerifyUpdate) (handle, part, part_len);
	}
	return rv;
}

static CK_RV
auth_C_VerifyFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                    CK_ULONG signature_len)
{
	return (pkcs11_lower->C_VerifyFinal) (handle, signature, signature_len);
}

static CK_RV
auth_C_VerifyRecoverInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	AuthObject *object = NULL;
	CK_RV rv;

	rv = (pkcs11_lower->C_VerifyRecoverInit) (handle, mechanism, key);
	if (rv == CKR_OK) {
		object = auth_object_for_context_specific (handle, key);
		if (object != NULL)
			login_specific_prepare (handle, object);
	}

	return rv;
}

static CK_RV
auth_C_VerifyRecover (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                      CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	CK_RV rv = (pkcs11_lower->C_VerifyRecover) (handle, signature, signature_len, data, data_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_VerifyRecover) (handle, signature, signature_len, data, data_len);
	}
	return rv;
}

static CK_RV
auth_C_DigestEncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                            CK_ULONG part_len, CK_BYTE_PTR enc_part,
                            CK_ULONG_PTR enc_part_len)
{
	CK_RV rv = (pkcs11_lower->C_DigestEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_DigestEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
	}
	return rv;
}

static CK_RV
auth_C_DecryptDigestUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                            CK_ULONG enc_part_len, CK_BYTE_PTR part,
                            CK_ULONG_PTR part_len)
{
	CK_RV rv = (pkcs11_lower->C_DecryptDigestUpdate) (handle, enc_part, enc_part_len, part, part_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_DecryptDigestUpdate) (handle, enc_part, enc_part_len, part, part_len);
	}
	return rv;
}

static CK_RV
auth_C_SignEncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                          CK_ULONG part_len, CK_BYTE_PTR enc_part,
                          CK_ULONG_PTR enc_part_len)
{
	CK_RV rv = (pkcs11_lower->C_SignEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_SignEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
	}
	return rv;
}

static CK_RV
auth_C_DecryptVerifyUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part, CK_ULONG enc_part_len,
                            CK_BYTE_PTR part, CK_ULONG_PTR part_len)
{
	CK_RV rv = (pkcs11_lower->C_DecryptVerifyUpdate) (handle, enc_part, enc_part_len, part, part_len);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		if (auth_C_Login (handle, CKU_CONTEXT_SPECIFIC, NULL, 0) == CKR_OK)
			rv = (pkcs11_lower->C_DecryptVerifyUpdate) (handle, enc_part, enc_part_len, part, part_len);
	}
	return rv;
}

static CK_RV
auth_C_GenerateKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                    CK_ATTRIBUTE_PTR template, CK_ULONG count,
                    CK_OBJECT_HANDLE_PTR key)
{
	return (pkcs11_lower->C_GenerateKey) (handle, mechanism, template, count, key);
}

static CK_RV
auth_C_GenerateKeyPair (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                        CK_ATTRIBUTE_PTR pub_template, CK_ULONG pub_count,
                        CK_ATTRIBUTE_PTR priv_template, CK_ULONG priv_count,
                        CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key)
{
	return (pkcs11_lower->C_GenerateKeyPair) (handle, mechanism, pub_template, pub_count, priv_template, priv_count, pub_key, priv_key);
}

static CK_RV
auth_C_WrapKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
                CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len)
{
	return (pkcs11_lower->C_WrapKey) (handle, mechanism, wrapping_key, key, wrapped_key, wrapped_key_len);
}

static CK_RV
auth_C_UnwrapKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key,
                  CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template,
                  CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	return (pkcs11_lower->C_UnwrapKey) (handle, mechanism, unwrapping_key, wrapped_key, wrapped_key_len, template, count, key);
}

static CK_RV
auth_C_DeriveKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR template,
                  CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	return (pkcs11_lower->C_DeriveKey) (handle, mechanism, base_key, template, count, key);
}

static CK_RV
auth_C_SeedRandom (CK_SESSION_HANDLE handle, CK_BYTE_PTR seed, CK_ULONG seed_len)
{
	return (pkcs11_lower->C_SeedRandom) (handle, seed, seed_len);
}

static CK_RV
auth_C_GenerateRandom (CK_SESSION_HANDLE handle, CK_BYTE_PTR random_data,
                       CK_ULONG random_len)
{
	return (pkcs11_lower->C_GenerateRandom) (handle, random_data, random_len);
}

/* --------------------------------------------------------------------
 * MODULE ENTRY POINT
 */

/*
 * PKCS#11 is broken here. It states that Unix compilers automatically byte
 * pack structures. This is wrong. GCC on Linux aligns to 4 by default.
 *
 * This results in incompatibilities. Where this structure's first version
 * members take up too much or too little space depending on how this module
 * is compiled.
 */

static CK_FUNCTION_LIST auth_function_list = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	auth_C_Initialize,
	auth_C_Finalize,
	auth_C_GetInfo,
	auth_C_GetFunctionList,
	auth_C_GetSlotList,
	auth_C_GetSlotInfo,
	auth_C_GetTokenInfo,
	auth_C_GetMechanismList,
	auth_C_GetMechanismInfo,
	auth_C_InitToken,
	auth_C_InitPIN,
	auth_C_SetPIN,
	auth_C_OpenSession,
	auth_C_CloseSession,
	auth_C_CloseAllSessions,
	auth_C_GetSessionInfo,
	auth_C_GetOperationState,
	auth_C_SetOperationState,
	auth_C_Login,
	auth_C_Logout,
	auth_C_CreateObject,
	auth_C_CopyObject,
	auth_C_DestroyObject,
	auth_C_GetObjectSize,
	auth_C_GetAttributeValue,
	auth_C_SetAttributeValue,
	auth_C_FindObjectsInit,
	auth_C_FindObjects,
	auth_C_FindObjectsFinal,
	auth_C_EncryptInit,
	auth_C_Encrypt,
	auth_C_EncryptUpdate,
	auth_C_EncryptFinal,
	auth_C_DecryptInit,
	auth_C_Decrypt,
	auth_C_DecryptUpdate,
	auth_C_DecryptFinal,
	auth_C_DigestInit,
	auth_C_Digest,
	auth_C_DigestUpdate,
	auth_C_DigestKey,
	auth_C_DigestFinal,
	auth_C_SignInit,
	auth_C_Sign,
	auth_C_SignUpdate,
	auth_C_SignFinal,
	auth_C_SignRecoverInit,
	auth_C_SignRecover,
	auth_C_VerifyInit,
	auth_C_Verify,
	auth_C_VerifyUpdate,
	auth_C_VerifyFinal,
	auth_C_VerifyRecoverInit,
	auth_C_VerifyRecover,
	auth_C_DigestEncryptUpdate,
	auth_C_DecryptDigestUpdate,
	auth_C_SignEncryptUpdate,
	auth_C_DecryptVerifyUpdate,
	auth_C_GenerateKey,
	auth_C_GenerateKeyPair,
	auth_C_WrapKey,
	auth_C_UnwrapKey,
	auth_C_DeriveKey,
	auth_C_SeedRandom,
	auth_C_GenerateRandom,
	auth_C_GetFunctionStatus,
	auth_C_CancelFunction,
	auth_C_WaitForSlotEvent
};

CK_FUNCTION_LIST_PTR
gkd_pkcs11_auth_get_functions (void)
{
	return &auth_function_list;
}

void
gkd_pkcs11_auth_chain_functions (CK_FUNCTION_LIST_PTR funcs)
{
	g_assert (funcs);
	g_assert (!pkcs11_lower);
	pkcs11_lower = funcs;
}
