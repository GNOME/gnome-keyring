/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
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

#include "gkd-login.h"

#include "egg/egg-secure-memory.h"

#include "pkcs11/gkd-pkcs11.h"
#include "pkcs11/pkcs11i.h"

#include <string.h>

static gint unlock_failures = 0;

static void
note_that_unlock_failed (void)
{
	g_atomic_int_inc (&unlock_failures);
}

static GP11Module*
module_instance (void)
{
	GP11Module *module = gp11_module_new (gkd_pkcs11_get_base_functions ());
	gp11_module_set_pool_sessions (module, FALSE);
	gp11_module_set_auto_authenticate (module, FALSE);
	g_return_val_if_fail (module, NULL);
	return module;
}

static GP11Session*
open_and_login_session (GP11Slot *slot, CK_USER_TYPE user_type, GError **error)
{
	GP11Session *session;
	GError *err = NULL;

	g_return_val_if_fail (GP11_IS_SLOT (slot), NULL);

	if (!error)
		error = &err;

	session = gp11_slot_open_session (slot, CKF_RW_SESSION, error);
	if (session != NULL) {
		if (!gp11_session_login (session, user_type, NULL, 0, error)) {
			if ((*error)->code != CKR_USER_ALREADY_LOGGED_IN) {
				g_object_unref (session);
				session = NULL;
			}
		}
	}

	return session;
}

static GP11Session*
lookup_login_session (GP11Module *module)
{
	GP11Slot *slot = NULL;
	GError *error = NULL;
	GP11Session *session;
	GP11SlotInfo *info;
	GList *slots;
	GList *l;

	g_assert (GP11_IS_MODULE (module));

	/*
	 * Find the right slot.
	 *
	 * TODO: This isn't necessarily the best way to do this.
	 * A good function could be added to gp11 library.
	 * But needs more thought on how to do this.
	 */
	slots = gp11_module_get_slots (module, TRUE);
	for (l = slots; !slot && l; l = g_list_next (l)) {
		info = gp11_slot_get_info (l->data);
		if (g_ascii_strcasecmp ("Secret Store", info->slot_description) == 0)
			slot = g_object_ref (l->data);
		gp11_slot_info_free (info);
	}
	gp11_list_unref_free (slots);

	g_return_val_if_fail (slot, NULL);

	session = open_and_login_session (slot, CKU_USER, &error);
	if (session == NULL) {
		g_warning ("couldn't open pkcs11 session for login: %s", error->message);
		g_clear_error (&error);
	}

	g_object_unref (slot);

	return session;
}

static GP11Object*
lookup_login_keyring (GP11Session *session)
{
	GError *error = NULL;
	GP11Object *login = NULL;
	GList *objects;
	guint length;

	g_return_val_if_fail (GP11_IS_SESSION (session), NULL);

	objects = gp11_session_find_objects (session, &error,
	                                     CKA_CLASS, GP11_ULONG, CKO_G_COLLECTION,
	                                     CKA_TOKEN, GP11_BOOLEAN, TRUE,
	                                     CKA_ID, (gsize)5, "login",
	                                     GP11_INVALID);

	if (error) {
		g_warning ("couldn't search for login keyring: %s", error->message);
		g_clear_error (&error);
		return NULL;
	}

	length = g_list_length (objects);
	if (length == 1) {
		login = g_object_ref (objects->data);
		gp11_object_set_session (login, session);
	} else if (length > 1) {
		g_warning ("more than one login keyring exists");
	}

	gp11_list_unref_free (objects);
	return login;
}

static GP11Object*
create_login_keyring (GP11Session *session, GP11Object *cred, GError **error)
{
	GP11Object *login;

	g_return_val_if_fail (GP11_IS_SESSION (session), NULL);
	g_return_val_if_fail (GP11_IS_OBJECT (cred), NULL);

	login = gp11_session_create_object (session, error,
	                                    CKA_CLASS, GP11_ULONG, CKO_G_COLLECTION,
	                                    CKA_ID, (gsize)5, "login",
	                                    CKA_G_CREDENTIAL, GP11_ULONG, gp11_object_get_handle (cred),
	                                    CKA_TOKEN, GP11_BOOLEAN, TRUE,
	                                    GP11_INVALID);

	if (login != NULL)
		gp11_object_set_session (login, session);
	return login;
}

static GP11Object*
create_credential (GP11Session *session, GP11Object *object,
                   const gchar *secret, GError **error)
{
	GP11Attributes *attrs;
	GP11Object *cred;

	g_return_val_if_fail (GP11_IS_SESSION (session), NULL);
	g_return_val_if_fail (!object || GP11_IS_OBJECT (object), NULL);

	if (!secret)
		secret = "";

	attrs = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, CKO_G_CREDENTIAL,
	                              CKA_VALUE, strlen (secret), secret,
	                              CKA_GNOME_TRANSIENT, GP11_BOOLEAN, TRUE,
	                              CKA_TOKEN, GP11_BOOLEAN, TRUE,
	                              GP11_INVALID);

	if (object)
		gp11_attributes_add_ulong (attrs, CKA_G_OBJECT,
		                           gp11_object_get_handle (object));

	cred = gp11_session_create_object_full (session, attrs, NULL, error);
	gp11_attributes_unref (attrs);

	if (cred != NULL)
		gp11_object_set_session (cred, session);

	return cred;
}

static gboolean
unlock_or_create_login (GP11Module *module, const gchar *master)
{
	GError *error = NULL;
	GP11Session *session;
	GP11Object *login;
	GP11Object *cred;

	g_return_val_if_fail (GP11_IS_MODULE (module), FALSE);
	g_return_val_if_fail (master, FALSE);

	/* Find the login object */
	session = lookup_login_session (module);
	login = lookup_login_keyring (session);

	/* Create credentials for login object */
	cred = create_credential (session, login, master, &error);

	/* Failure, bad password? */
	if (cred == NULL) {
		if (login && error->code == CKR_PIN_INCORRECT)
			note_that_unlock_failed ();
		else
			g_warning ("couldn't create login credential: %s", error->message);
		g_clear_error (&error);

	/* Non login keyring, create it */
	} else if (!login) {
		login = create_login_keyring (session, cred, &error);
		if (login == NULL) {
			g_warning ("couldn't create login keyring: %s", error->message);
			g_clear_error (&error);
		}
	}

	if (cred)
		g_object_unref (cred);
	if (login)
		g_object_unref (login);
	if (session)
		g_object_unref (session);

	return cred && login;
}

static gboolean
init_pin_for_uninitialized_slots (GP11Module *module, const gchar *master)
{
	GError *error = NULL;
	GList *slots, *l;
	gboolean initialize;
	GP11TokenInfo *info;
	GP11Session *session;

	g_return_val_if_fail (GP11_IS_MODULE (module), FALSE);
	g_return_val_if_fail (master, FALSE);

	slots = gp11_module_get_slots (module, TRUE);
	for (l = slots; l; l = g_list_next (l)) {
		info = gp11_slot_get_token_info (l->data);
		initialize = (info && !(info->flags & CKF_USER_PIN_INITIALIZED));

		if (initialize) {
			session = open_and_login_session (l->data, CKU_SO, NULL);
			if (session != NULL) {
				if (gp11_session_init_pin (session, (const guchar*)master, strlen (master), &error)) {
					gkd_login_attach_secret (info->label, master,
					                         "manufacturer", info->manufacturer_id,
					                         "serial-number", info->serial_number,
					                         NULL);
				} else {
					if (error->code != CKR_FUNCTION_NOT_SUPPORTED)
						g_warning ("couldn't initialize slot with master password: %s", error->message);
					g_clear_error (&error);
				}
				g_object_unref (session);
			}
		}

		gp11_token_info_free (info);
	}
	gp11_list_unref_free (slots);
	return TRUE;
}

gboolean
gkd_login_unlock (const gchar *master)
{
	GP11Module *module;
	gboolean result;

	/* We don't support null or empty master passwords */
	if (!master || !master[0])
		return FALSE;

	module = module_instance ();

	result = unlock_or_create_login (module, master);
	if (result == TRUE)
		init_pin_for_uninitialized_slots (module, master);

	g_object_unref (module);
	return result;
}

static gboolean
change_or_create_login (GP11Module *module, const gchar *original, const gchar *master)
{
	GError *error = NULL;
	GP11Session *session;
	GP11Object *login = NULL;
	GP11Object *ocred = NULL;
	GP11Object *mcred = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (GP11_IS_MODULE (module), FALSE);
	g_return_val_if_fail (original, FALSE);
	g_return_val_if_fail (master, FALSE);

	/* Find the login object */
	session = lookup_login_session (module);
	login = lookup_login_keyring (session);

	/* Create the new credential we'll be changing to */
	mcred = create_credential (session, NULL, master, &error);
	if (mcred == NULL) {
		g_warning ("couldn't create new login credential: %s", error->message);
		g_clear_error (&error);

	/* Create original credentials */
	} else if (login) {
		ocred = create_credential (session, login, original, &error);
		if (ocred == NULL) {
			if (error->code == CKR_PIN_INCORRECT) {
				g_message ("couldn't change login master password, "
				           "original password was wrong: %s", error->message);
				note_that_unlock_failed ();
			} else {
				g_warning ("couldn't create original login credential: %s", error->message);
			}
			g_clear_error (&error);
		}
	}

	/* No keyring? try to create */
	if (!login && mcred) {
		login = create_login_keyring (session, mcred, &error);
		if (login == NULL) {
			g_warning ("couldn't create login keyring: %s", error->message);
			g_clear_error (&error);
		} else {
			success = TRUE;
		}

	/* Change the master password */
	} else if (login && ocred && mcred) {
		if (!gp11_object_set (login, &error,
		                      CKA_G_CREDENTIAL, GP11_ULONG, gp11_object_get_handle (mcred),
		                      GP11_INVALID)) {
			g_warning ("couldn't change login master password: %s", error->message);
			g_clear_error (&error);
		} else {
			success = TRUE;
		}
	}

	if (ocred) {
		gp11_object_destroy (ocred, NULL);
		g_object_unref (ocred);
	}
	if (mcred)
		g_object_unref (mcred);
	if (login)
		g_object_unref (login);
	if (session)
		g_object_unref (session);

	return success;
}

static gboolean
set_pin_for_any_slots (GP11Module *module, const gchar *original, const gchar *master)
{
	GError *error = NULL;
	GList *slots, *l;
	gboolean initialize;
	GP11TokenInfo *info;
	GP11Session *session;

	g_return_val_if_fail (GP11_IS_MODULE (module), FALSE);
	g_return_val_if_fail (original, FALSE);
	g_return_val_if_fail (master, FALSE);

	slots = gp11_module_get_slots (module, TRUE);
	for (l = slots; l; l = g_list_next (l)) {

		/* Set pin for any that are initialized, and not pap */
		info = gp11_slot_get_token_info (l->data);
		initialize = (info && (info->flags & CKF_USER_PIN_INITIALIZED));

		if (initialize) {
			session = open_and_login_session (l->data, CKU_USER, NULL);
			if (session != NULL) {
				if (gp11_session_set_pin (session, (const guchar*)original, strlen (original),
				                          (const guchar*)master, strlen (master), &error)) {
					gkd_login_attach_secret (info->label, master,
					                         "manufacturer", info->manufacturer_id,
					                         "serial-number", info->serial_number,
					                         NULL);
				} else {
					if (error->code != CKR_PIN_INCORRECT && error->code != CKR_FUNCTION_NOT_SUPPORTED)
						g_warning ("couldn't change slot master password: %s", error->message);
					g_clear_error (&error);
				}
				g_object_unref (session);
			}
		}

		gp11_token_info_free (info);
	}
	gp11_list_unref_free (slots);
	return TRUE;
}

gboolean
gkd_login_change_lock (const gchar *original, const gchar *master)
{
	GP11Module *module;
	gboolean result;

	/* We don't support null or empty master passwords */
	if (!master || !master[0])
		return FALSE;
	if (original == NULL)
		original = "";

	module = module_instance ();

	result = change_or_create_login (module, original, master);
	if (result == TRUE)
		set_pin_for_any_slots (module, original, master);

	g_object_unref (module);
	return result;
}

gboolean
gkd_login_is_usable (void)
{
	GP11Module *module;
	GP11Session *session;
	GP11Object *login;
	gboolean usable = FALSE;
	gpointer data;
	gsize n_data;

	module = module_instance ();
	if (!module)
		return FALSE;

	session = lookup_login_session (module);
	if (session) {
		login = lookup_login_keyring (session);
		if (login) {
			data = gp11_object_get_data (login, CKA_G_LOCKED, &n_data, NULL);
			usable = (data && n_data == sizeof (CK_BBOOL) && !*((CK_BBOOL*)data));
			g_free (data);
			g_object_unref (login);
		}
		g_object_unref (session);
	}

	g_object_unref (module);
	return usable;
}

static void
string_attribute_list_va (va_list args, const gchar *name, GP11Attribute *attr)
{
	GString *fields = g_string_sized_new(128);
	gsize length;

	while (name != NULL) {
		g_string_append (fields, name);
		g_string_append_c (fields, '\0');
		g_string_append (fields, va_arg (args, const gchar*));
		g_string_append_c (fields, '\0');
		name = va_arg (args, const gchar*);
	}

	length = fields->len;
	gp11_attribute_init (attr, CKA_G_FIELDS, g_string_free (fields, FALSE), length);
}

static GP11Object*
find_login_keyring_item (GP11Session *session, GP11Attribute *fields)
{
	GP11Object *search;
	GP11Object *item = NULL;
	GList *objects;
	GError *error = NULL;
	gpointer data;
	gsize n_data;

	g_return_val_if_fail (GP11_IS_SESSION (session), FALSE);

	/* Create a search object */
	search = gp11_session_create_object (session, &error,
	                                     CKA_CLASS, GP11_ULONG, CKO_G_SEARCH,
	                                     CKA_G_COLLECTION, (gsize)5, "login",
	                                     CKA_TOKEN, GP11_BOOLEAN, FALSE,
	                                     CKA_G_FIELDS, fields->length, fields->value,
	                                     GP11_INVALID);

	if (!search) {
		g_warning ("couldn't create search for login keyring: %s", error->message);
		g_clear_error (&error);
		return NULL;
	}

	/* Get the data from the search */
	gp11_object_set_session (search, session);
	data = gp11_object_get_data (search, CKA_G_MATCHED, &n_data, &error);
	gp11_object_destroy (search, NULL);
	g_object_unref (search);

	if (data == NULL) {
		g_warning ("couldn't read search in login keyring: %s", error->message);
		g_clear_error (&error);
		return NULL;
	}

	n_data /= sizeof (CK_OBJECT_HANDLE);
	objects = gp11_objects_from_handle_array (gp11_session_get_slot (session), data,
	                                          MIN (sizeof (CK_OBJECT_HANDLE), n_data));
	g_free (data);

	if (objects) {
		item = g_object_ref (objects->data);
		gp11_object_set_session (item, session);
	}

	gp11_list_unref_free (objects);
	return item;
}

void
gkd_login_attach_secret (const gchar *display_name, const gchar *secret,
                         const gchar *first, ...)
{
	GError *error = NULL;
	GP11Attribute fields;
	GP11Session *session;
	GP11Module *module;
	GP11Object* item;
	va_list va;

	if (display_name == NULL)
		display_name = "";
	if (secret == NULL)
		secret = "";

	module = module_instance ();
	session = lookup_login_session (module);

	va_start(va, first);
	gp11_attribute_init_empty (&fields, CKA_G_FIELDS);
	string_attribute_list_va (va, first, &fields);
	va_end(va);

	item = find_login_keyring_item (session, &fields);
	if (item) {
		gp11_object_set (item, &error,
		                 CKA_LABEL, strlen (display_name), display_name,
		                 CKA_VALUE, strlen (secret), secret,
		                 GP11_INVALID);
	} else {
		item = gp11_session_create_object (session, &error,
		                                   CKA_CLASS, GP11_ULONG, CKO_SECRET_KEY,
		                                   CKA_LABEL, strlen (display_name), display_name,
		                                   CKA_VALUE, strlen (secret), secret,
		                                   CKA_G_COLLECTION, (gsize)5, "login",
		                                   CKA_G_FIELDS, fields.length, fields.value,
		                                   GP11_INVALID);
	}

	if (error != NULL) {
		g_warning ("couldn't store secret in login keyring: %s", error->message);
		g_clear_error (&error);
	}

	if (item)
		g_object_unref (item);
	g_object_unref (session);
	g_object_unref (module);
}

gchar*
gkd_login_lookup_secret (const gchar *first, ...)
{
	GP11Attribute fields;
	GP11Session *session;
	GP11Module *module;
	GP11Object* item;
	gpointer data = NULL;
	gsize n_data;
	va_list va;

	module = module_instance ();
	session = lookup_login_session (module);

	va_start(va, first);
	gp11_attribute_init_empty (&fields, CKA_G_FIELDS);
	string_attribute_list_va (va, first, &fields);
	va_end(va);

	item = find_login_keyring_item (session, &fields);
	if (item != NULL) {
		data = gp11_object_get_data_full (item, CKA_VALUE, egg_secure_realloc, NULL, &n_data, NULL);
		if (data && !g_utf8_validate (data, n_data, NULL)) {
			g_warning ("expected string, but found binary secret in login keyring");
			egg_secure_clear (data, n_data);
			egg_secure_free (data);
			data = NULL;
		}
		g_object_unref (item);
	}

	g_object_unref (session);
	g_object_unref (module);

	/* Memory returned from gp11_object_get_data is null terminated */
	return data;
}

void
gkd_login_remove_secret (const gchar *first, ...)
{
	GError *error = NULL;
	GP11Attribute fields;
	GP11Session *session;
	GP11Module *module;
	GP11Object* item;
	va_list va;

	module = module_instance ();
	session = lookup_login_session (module);

	va_start(va, first);
	gp11_attribute_init_empty (&fields, CKA_G_FIELDS);
	string_attribute_list_va (va, first, &fields);
	va_end(va);

	item = find_login_keyring_item (session, &fields);
	if (item != NULL) {
		if (!gp11_object_destroy (item, &error)) {
			if (error->code != CKR_OBJECT_HANDLE_INVALID)
				g_warning ("couldn't remove stored secret from login keyring: %s", error->message);
			g_clear_error (&error);
		}
		g_object_unref (item);
	}

	g_object_unref (session);
	g_object_unref (module);
}

GP11Attributes*
gkd_login_attributes_for_secret (const gchar *first, ...)
{
	GP11Attributes *attrs;
	GP11Attribute *fields;
	va_list va;

	attrs = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, CKO_SECRET_KEY,
	                              CKA_G_COLLECTION, (gsize)5, "login",
	                              GP11_INVALID);

	va_start(va, first);
	fields = gp11_attributes_add_empty (attrs, CKA_G_FIELDS);
	string_attribute_list_va (va, first, fields);
	va_end(va);

	return attrs;
}
