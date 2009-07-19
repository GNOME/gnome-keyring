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

#include "gkr-pkcs11-auth.h"

#include "egg/egg-cleanup.h"
#include "egg/egg-secure-memory.h"

#include "keyrings/gkr-keyring-login.h"

#include "ui/gkr-ask-request.h"
#include "ui/gkr-ask-daemon.h"

#include "pkcs11/pkcs11.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <unistd.h>

typedef struct _SlotData {
	gint open_sessions;
	GHashTable *session_to_specific;
	GHashTable *session_to_filter;
} SlotData;

/* A hash table of CK_SLOT_ID_PTR to SlotData */
static GHashTable *per_slot_data = NULL;

static gulong*
ulong_alloc (CK_ULONG value)
{
	return g_slice_dup (CK_ULONG, &value);
}

static void
ulong_free (gpointer ptr_to_ulong)
{
	g_slice_free (CK_ULONG, ptr_to_ulong);
}

static guint
ulong_hash (gconstpointer v)
{
	const signed char *p = v;
	guint32 i, h = *p;
	for(i = 0; i < sizeof (CK_ULONG); ++i)
		h = (h << 5) - h + *(p++);
	return h;
}

static gboolean
ulong_equal (gconstpointer v1, gconstpointer v2)
{
	return *((const CK_ULONG*)v1) == *((const CK_ULONG*)v2);
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
		*pin = (CK_UTF8CHAR_PTR)egg_secure_strdup (password);
		*pin_len = strlen (password);
	}
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

static const gchar*
prepare_specific_check (CK_OBJECT_CLASS klass)
{
	switch (klass) {
	case CKO_PRIVATE_KEY:
		return _("Automatically unlock this private key when I log in.");
	case CKO_CERTIFICATE:
		return _("Automatically unlock this certificate when I log in.");
	case CKO_PUBLIC_KEY:
		return _("Automatically unlock this public key when I log in.");
	default:
		return _("Automatically unlock this when I log in");
	}
}

void
gkr_pkcs11_auth_login_specific_prepare (CK_SESSION_HANDLE handle, GkrPkcs11AuthObject *object)
{
	SlotData *slot;
	
	g_assert (object);
	
	/* Because we should have been notified when a session was opened */
	g_return_if_fail (per_slot_data);
	
	slot = g_hash_table_lookup (per_slot_data, &object->slot);
	g_return_if_fail (slot);

	/* Delayed allocation because we may never use this on a slot */
	if (slot->session_to_specific == NULL)
		slot->session_to_specific = g_hash_table_new_full (ulong_hash, ulong_equal, ulong_free, 
		                                                   (GDestroyNotify)gkr_pkcs11_auth_free_object);
	
	/* Store the object info for a later prompt */
	g_hash_table_replace (slot->session_to_specific, ulong_alloc (handle), object);
}

static void
convert_upper_case (gchar *str)
{
	for (; *str; ++str)
		*str = g_ascii_toupper (*str);
}

gboolean 
gkr_pkcs11_auth_login_specific_prompt (CK_SESSION_HANDLE handle, CK_SESSION_INFO *info,
                                       CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len)
{
	GkrPkcs11AuthObject *object;
	const gchar *password;
	SlotData *slot;
	gchar *secondary;
	GkrAskRequest *ask;
	gboolean ret;
	guint flags;
	
	g_assert (info);
	g_assert (pin);
	g_assert (pin_len);	

	/* Because we should have been notified of open session */
	g_return_val_if_fail (per_slot_data, FALSE);
	
	/* Lookup the structure for this slot */
	slot = g_hash_table_lookup (per_slot_data, &info->slotID);
	if (slot == NULL || slot->session_to_specific == NULL)
		return FALSE;

	/* Find the object we're authenticating */
	object = g_hash_table_lookup (slot->session_to_specific, &handle);
	if (object == NULL)
		return FALSE;

	/* See if we can just use the login keyring password for this */
	if (object->unique && object->token) {
		password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD,
		                                            "unique", object->unique, NULL);
		if (password != NULL) { 
			password_to_pin (password, pin, pin_len);
			return TRUE;
		}
	}
	
	/* COMPAT: Check old method of storing secrets for objects in login keyring */
	if (object->digest) {
		convert_upper_case (object->digest);
		password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_PK_STORAGE,
		                                            "object-digest", object->digest, NULL);
		if (password != NULL) {
			if (object->unique)
				gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD, 
				                                 object->label, password, 
		                                                 "unique", object->unique, NULL);
			password_to_pin (password, pin, pin_len);
			return TRUE;
		}
	}

	/* Build up the prompt */
	flags = GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_OK_DENY_BUTTONS;
	ask = gkr_ask_request_new (prepare_specific_title (object->klass), 
	                           prepare_specific_primary (object->klass), flags);

	secondary = prepare_specific_secondary (object->klass, object->label); 
	gkr_ask_request_set_secondary (ask, secondary);
	g_free (secondary);

	if (object->unique && gkr_keyring_login_is_usable ())
		gkr_ask_request_set_check_option (ask, prepare_specific_check (object->klass));

	/* Prompt the user */
	gkr_ask_daemon_process (ask);

	/* If the user denied ... */
	if (ask->response == GKR_ASK_RESPONSE_DENY) {
		ret = FALSE;
		
	/* User cancelled or failure */
	} else if (ask->response < GKR_ASK_RESPONSE_ALLOW) {
		ret = FALSE;
			
	/* Successful response */
	} else {
		password_to_pin (ask->typed_password, pin, pin_len);
		ret = TRUE;
		
		/* Store forever */
		if (ask->checked && object->unique && object->token) {
			gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD, 
			                                 object->label, ask->typed_password, 
			                                 "unique", object->unique, NULL);
		}
	}
	
	g_object_unref (ask);
	return ret;
}

CK_OBJECT_HANDLE
gkr_pkcs11_auth_login_specific_object (CK_SESSION_HANDLE handle, CK_SESSION_INFO *info)
{
	GkrPkcs11AuthObject *object;
	SlotData *slot;

	/* Because we should have been notified of open session */
	g_return_val_if_fail (per_slot_data, 0);

	/* Lookup the structure for this slot */
	slot = g_hash_table_lookup (per_slot_data, &info->slotID);
	if (slot == NULL || slot->session_to_specific == NULL)
		return 0;

	/* Find the object we're authenticating */
	object = g_hash_table_lookup (slot->session_to_specific, &handle);
	if (object == NULL)
		return 0;

	return object->handle;
}

void
gkr_pkcs11_auth_login_specific_done (CK_SESSION_HANDLE handle, CK_SESSION_INFO *info, 
                                     CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len, CK_RV rv)
{
	GkrPkcs11AuthObject *object;
	SlotData *slot;
	
	g_assert (pin);
	g_assert (pin_len);

	/* Because we should have been notified of open session */
	g_return_if_fail (per_slot_data);

	slot = g_hash_table_lookup (per_slot_data, &info->slotID);
	g_assert (slot != NULL && slot->session_to_specific != NULL);

	object = g_hash_table_lookup (slot->session_to_specific, &handle);
	g_assert (object);

	switch (rv) {
	case CKR_PIN_INCORRECT:
	case CKR_PIN_EXPIRED:
	case CKR_PIN_INVALID:
	case CKR_PIN_LEN_RANGE:
	case CKR_PIN_LOCKED:
		if (object->unique && object->token)
			gkr_keyring_login_remove_secret (GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD,
			                                 "unique", object->unique, NULL);
		break;
		
	case CKR_OK:
		g_hash_table_remove (slot->session_to_specific, &handle);
		break;
		
	default:
		break;
	}
	
	egg_secure_strfree ((gchar*)*pin);
	
	*pin = NULL;
	*pin_len = 0;
}

gboolean
gkr_pkcs11_auth_login_user_prompt (CK_SESSION_HANDLE handle, CK_TOKEN_INFO *info,
                                   CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len)
{
	GkrAskRequest *ask;
	gchar *label;
	gchar *secondary;
	gchar *manufacturer;
	gchar *serial;
	const gchar *password;
	gboolean ret = TRUE;
	guint flags;
	
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
	
	if (gkr_keyring_login_is_usable ()) {

		password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD, 
		                                            "manufacturer", manufacturer,
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
	flags = GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_OK_DENY_BUTTONS;
	ask = gkr_ask_request_new (_("Unlock certificate/key storage"), 
	                           _("Enter password to unlock the certificate/key storage"), flags); 
	
	/* TRANSLATORS: The storage is locked, and needs unlocking before the application can use it. */
	secondary = g_strdup_printf (_("An application wants access to the certificate/key storage '%s', but it is locked"), label);
	gkr_ask_request_set_secondary (ask, secondary);
	g_free (secondary);
	
	if (gkr_keyring_login_is_usable ())
		gkr_ask_request_set_check_option (ask, _("Automatically unlock secure storage when I log in."));

	/* Prompt the user */
	gkr_ask_daemon_process (ask);

	/* If the user denied ... */
	if (ask->response == GKR_ASK_RESPONSE_DENY) {
		ret = FALSE;
		
	/* User cancelled or failure */
	} else if (ask->response < GKR_ASK_RESPONSE_ALLOW) {
		ret = FALSE;
			
	/* Successful response */
	} else {
		password_to_pin (ask->typed_password, pin, pin_len);
		ret = TRUE;
		
		/* Store forever */
		if (ask->checked) {
			gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD, 
			                                 label, ask->typed_password,
			                                 "manufacturer", manufacturer, 
			                                 "serial-number", serial,
			                                 NULL);
		}
	}
	
	g_free (manufacturer);
	g_free (serial);
	g_free (label);
	
	g_object_unref (ask);
	return ret;
}

static void
clear_user_login (CK_TOKEN_INFO *info)
{
	gchar *manufacturer;
	gchar *serial;
	
	g_assert (info);
	
	if (gkr_keyring_login_is_usable ()) {
		/* 
		 * The manufacturer and serial number together uniquely identify token 
		 * They're stored with space padded in the token info structure.
		 */
		
		manufacturer = g_strndup ((gchar*)info->manufacturerID, sizeof (info->manufacturerID));
		g_strchomp (manufacturer);

		serial = g_strndup ((gchar*)info->serialNumber, sizeof (info->serialNumber));
		g_strchomp (serial);

		gkr_keyring_login_remove_secret (GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD,
						 "manufacturer", manufacturer, 
						 "serial-number", serial, 
						 NULL);
		
		g_free (manufacturer);
		g_free (serial);
	}
}

void 
gkr_pkcs11_auth_login_user_done (CK_SESSION_HANDLE handle, CK_TOKEN_INFO *info,
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

gboolean
gkr_pkcs11_auth_init_user_prompt (CK_SESSION_HANDLE handle, CK_TOKEN_INFO *info,
                                  CK_UTF8CHAR_PTR *pin, CK_ULONG *pin_len)
{
	GkrAskRequest *ask;
	gchar *label;
	gchar *secondary;
	gchar *manufacturer;
	gchar *serial;
	const gchar *password;
	gboolean ret = TRUE;
	guint flags;
	
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

	/* We try to use the login keyring password if available */
	password = gkr_keyring_login_master ();
	if (password != NULL) {
		password_to_pin (password, pin, pin_len);
		
		/* Save this away in case the main password changes without us being aware */
		if (gkr_keyring_login_is_usable ())
			gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD, 
			                                 label, password,
			                                 "manufacturer", manufacturer, 
			                                 "serial-number", serial,
			                                 NULL);
		
		g_free (manufacturer);
		g_free (serial);
		g_free (label);
		return TRUE;
	}

	/* Otherwise we have to prompt for it */
	
	/* Build up the prompt */
	flags = GKR_ASK_REQUEST_NEW_PASSWORD;
	ask = gkr_ask_request_new (_("New Password Required"), 
	                           _("New password required for secure storage"), flags);

	secondary = g_strdup_printf (_("In order to prepare '%s' for storage of certificates or keys, a password is required"), label);
	gkr_ask_request_set_secondary (ask, secondary);
	g_free (secondary);

	if (gkr_keyring_login_is_usable ())
		gkr_ask_request_set_check_option (ask, _("Automatically unlock secure storage when I log in."));

	/* Prompt the user */
	gkr_ask_daemon_process (ask);

	/* If the user denied ... */
	if (ask->response == GKR_ASK_RESPONSE_DENY) {
		ret = FALSE;
		
	/* User cancelled or failure */
	} else if (ask->response < GKR_ASK_RESPONSE_ALLOW) {
		ret = FALSE;
			
	/* Successful response */
	} else {
		password_to_pin (ask->typed_password, pin, pin_len);
		
		if (ask->checked) {
			gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD, 
			                                 label, ask->typed_password,
			                                 "manufacturer", manufacturer, 
			                                 "serial-number", serial,
			                                 NULL);
		}
		
		ret = TRUE;
	}
	
	g_free (manufacturer);
	g_free (serial);
	g_free (label);
	g_object_unref (ask);
	
	return ret;
}

void
gkr_pkcs11_auth_init_user_done (CK_SESSION_HANDLE handle, CK_TOKEN_INFO *token_info, 
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

/* ---------------------------------------------------------------------------------
 * SLOT / SESSION TRACKING
 */

static void
free_slot_data (SlotData *slot)
{
	g_assert (slot);
	if (slot->session_to_specific)
		g_hash_table_destroy (slot->session_to_specific);
	g_slice_free (SlotData, slot);
}

void
gkr_pkcs11_auth_initialized (void)
{
	g_return_if_fail (!per_slot_data);
	
	/* Remove information stored about this session */
	per_slot_data = g_hash_table_new_full (ulong_hash, ulong_equal, ulong_free, 
	                                       (GDestroyNotify)free_slot_data);
}

void
gkr_pkcs11_auth_session_opened (CK_SESSION_HANDLE handle, CK_SESSION_INFO *info)
{
	SlotData *slot;
	
	g_assert (info);
	
	slot = g_hash_table_lookup (per_slot_data, &info->slotID);
	if (slot == NULL) {
		slot = g_slice_new0 (SlotData);
		g_hash_table_replace (per_slot_data, ulong_alloc (info->slotID), slot);
	}

	/* Track how many open sessions there are */
	++slot->open_sessions;
}

void
gkr_pkcs11_auth_session_closed (CK_SESSION_HANDLE handle, CK_SESSION_INFO *info)
{
	SlotData *slot;
	
	g_assert (info);
	g_return_if_fail (per_slot_data);
	
	slot = g_hash_table_lookup (per_slot_data, &info->slotID);
	g_return_if_fail (slot);
	g_assert (slot->open_sessions > 0);

	/* Track how many open sessions there are */
	--(slot->open_sessions);
	if (slot->open_sessions == 0) 
		g_hash_table_remove (per_slot_data, &info->slotID);
}

void
gkr_pkcs11_auth_session_closed_all (CK_SLOT_ID id)
{
	g_return_if_fail (per_slot_data);

	/* Remove all information about this slot */
	g_hash_table_remove (per_slot_data, &id);
}

void
gkr_pkcs11_auth_finalized (void)
{
	g_return_if_fail (per_slot_data);
	g_hash_table_destroy (per_slot_data);
	per_slot_data = NULL;
}

void
gkr_pkcs11_auth_free_object (GkrPkcs11AuthObject *info)
{
	g_assert (info);
	g_free (info->label);
	g_free (info->unique);
	g_free (info);
}
