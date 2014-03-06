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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkd-login.h"

#include "daemon/gkd-pkcs11.h"

#include "egg/egg-error.h"
#include "egg/egg-secure-memory.h"

#include "pkcs11/pkcs11i.h"
#include "pkcs11/wrap-layer/gkm-wrap-layer.h"

#include <gck/gck.h>

#include <glib/gi18n.h>

#include <string.h>

static GList*
module_instances (void)
{
	CK_FUNCTION_LIST_PTR funcs;
	GckModule *module;

	funcs = gkd_pkcs11_get_base_functions ();
	g_return_val_if_fail (funcs != NULL && "instances", NULL);

	module = gck_module_new (funcs);
	g_return_val_if_fail (module, NULL);
	return g_list_append (NULL, module);
}

static GckSession*
open_and_login_session (GckSlot *slot, CK_USER_TYPE user_type, GError **error)
{
	GckSession *session;
	GError *err = NULL;

	g_return_val_if_fail (GCK_IS_SLOT (slot), NULL);

	if (!error)
		error = &err;

	session = gck_slot_open_session (slot, GCK_SESSION_READ_WRITE, NULL, error);
	if (session != NULL) {
		if (!gck_session_login (session, user_type, NULL, 0, NULL, error)) {
			if (g_error_matches (*error, GCK_ERROR, CKR_USER_ALREADY_LOGGED_IN)) {
				g_clear_error (error);
			} else {
				g_object_unref (session);
				session = NULL;
			}
		}
	}

	return session;
}

static GckSession*
lookup_login_session (GList *modules)
{
	GckSlot *slot = NULL;
	GError *error = NULL;
	GckSession *session;

	slot = gck_modules_token_for_uri (modules, "pkcs11:token=Secret%20Store", &error);
	if (!slot) {
		g_warning ("couldn't find secret store module: %s", egg_error_message (error));
		return NULL;
	}

	session = open_and_login_session (slot, CKU_USER, &error);
	if (error) {
		g_warning ("couldn't open pkcs11 session for login: %s", egg_error_message (error));
		g_clear_error (&error);
	}

	g_object_unref (slot);

	return session;
}

static GckObject*
lookup_login_keyring (GckSession *session)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GError *error = NULL;
	GckObject *login = NULL;
	GList *objects;
	guint length;

	g_return_val_if_fail (GCK_IS_SESSION (session), NULL);

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_COLLECTION);
	gck_builder_add_boolean (&builder, CKA_TOKEN, TRUE);
	gck_builder_add_string (&builder, CKA_ID, "login");

	objects = gck_session_find_objects (session, gck_builder_end (&builder), NULL, &error);

	if (error) {
		g_warning ("couldn't search for login keyring: %s", egg_error_message (error));
		g_clear_error (&error);
		return NULL;
	}

	length = g_list_length (objects);
	if (length == 1)
		login = g_object_ref (objects->data);
	else if (length > 1)
		g_warning ("more than one login keyring exists");

	gck_list_unref_free (objects);
	return login;
}

static GckObject*
create_login_keyring (GckSession *session, GckObject *cred, GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;

	g_return_val_if_fail (GCK_IS_SESSION (session), NULL);
	g_return_val_if_fail (GCK_IS_OBJECT (cred), NULL);

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_COLLECTION);
	gck_builder_add_string (&builder, CKA_ID, "login");
	gck_builder_add_ulong (&builder, CKA_G_CREDENTIAL, gck_object_get_handle (cred));
	gck_builder_add_boolean (&builder, CKA_TOKEN, TRUE);

	/* TRANSLATORS: This is the display label for the login keyring */
	gck_builder_add_string (&builder, CKA_LABEL, _("Login"));

	return gck_session_create_object (session, gck_builder_end (&builder), NULL, error);
}

static GckObject*
create_credential (GckSession *session, GckObject *object,
                   const gchar *secret, GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;

	g_return_val_if_fail (GCK_IS_SESSION (session), NULL);
	g_return_val_if_fail (!object || GCK_IS_OBJECT (object), NULL);

	if (!secret)
		secret = "";

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_CREDENTIAL);
	gck_builder_add_string (&builder, CKA_VALUE, secret);
	gck_builder_add_boolean (&builder, CKA_GNOME_TRANSIENT, TRUE);
	gck_builder_add_boolean (&builder, CKA_TOKEN, TRUE);

	if (object)
		gck_builder_add_ulong (&builder, CKA_G_OBJECT,
		                       gck_object_get_handle (object));

	return gck_session_create_object (session, gck_builder_end (&builder), NULL, error);
}

static gboolean
unlock_or_create_login (GList *modules, const gchar *master)
{
	GError *error = NULL;
	GckSession *session;
	GckObject *login;
	GckObject *cred;

	g_return_val_if_fail (master, FALSE);

	/* Find the login object */
	session = lookup_login_session (modules);
	login = lookup_login_keyring (session);

	/* Create credentials for login object */
	cred = create_credential (session, login, master, &error);

	/* Failure, bad password? */
	if (cred == NULL) {
		if (login && g_error_matches (error, GCK_ERROR, CKR_PIN_INCORRECT))
			gkm_wrap_layer_mark_login_unlock_failure (master);
		else
			g_warning ("couldn't create login credential: %s", egg_error_message (error));
		g_clear_error (&error);

	/* Non login keyring, create it */
	} else if (!login) {
		login = create_login_keyring (session, cred, &error);
		if (login == NULL && error) {
			g_warning ("couldn't create login keyring: %s", egg_error_message (error));
			g_clear_error (&error);
		}

	/* The unlock succeeded yay */
	} else {
		gkm_wrap_layer_mark_login_unlock_success ();
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
init_pin_for_uninitialized_slots (GList *modules, const gchar *master)
{
	GError *error = NULL;
	GList *slots, *l;
	gboolean initialize;
	GckTokenInfo *info;
	GckSession *session;

	g_return_val_if_fail (master, FALSE);

	slots = gck_modules_get_slots (modules, TRUE);
	for (l = slots; l; l = g_list_next (l)) {
		info = gck_slot_get_token_info (l->data);
		initialize = (info && !(info->flags & CKF_USER_PIN_INITIALIZED));

		if (initialize) {
			session = open_and_login_session (l->data, CKU_SO, NULL);
			if (session != NULL) {
				if (!gck_session_init_pin (session, (const guchar*)master, strlen (master), NULL, &error)) {
					if (!g_error_matches (error, GCK_ERROR, CKR_FUNCTION_NOT_SUPPORTED))
						g_warning ("couldn't initialize slot with master password: %s",
						           egg_error_message (error));
					g_clear_error (&error);
				}
				g_object_unref (session);
			}
		}

		gck_token_info_free (info);
	}
	gck_list_unref_free (slots);
	return TRUE;
}

gboolean
gkd_login_unlock (const gchar *master)
{
	GList *modules;
	gboolean result;

	/* We don't support null or empty master passwords */
	if (!master || !master[0])
		return FALSE;

	modules = module_instances ();

	result = unlock_or_create_login (modules, master);
	if (result == TRUE)
		init_pin_for_uninitialized_slots (modules, master);

	gck_list_unref_free (modules);
	return result;
}

static gboolean
change_or_create_login (GList *modules, const gchar *original, const gchar *master)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GError *error = NULL;
	GckSession *session;
	GckObject *login = NULL;
	GckObject *ocred = NULL;
	GckObject *mcred = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (original, FALSE);
	g_return_val_if_fail (master, FALSE);

	/* Find the login object */
	session = lookup_login_session (modules);
	login = lookup_login_keyring (session);

	/* Create the new credential we'll be changing to */
	mcred = create_credential (session, NULL, master, &error);
	if (mcred == NULL) {
		g_warning ("couldn't create new login credential: %s", egg_error_message (error));
		g_clear_error (&error);

	/* Create original credentials */
	} else if (login) {
		ocred = create_credential (session, login, original, &error);
		if (ocred == NULL) {
			if (g_error_matches (error, GCK_ERROR, CKR_PIN_INCORRECT)) {
				g_message ("couldn't change login master password, "
				           "original password was wrong: %s",
				           egg_error_message (error));
			} else {
				g_warning ("couldn't create original login credential: %s",
				           egg_error_message (error));
			}
			g_clear_error (&error);
		}
	}

	/* No keyring? try to create */
	if (!login && mcred) {
		login = create_login_keyring (session, mcred, &error);
		if (login == NULL) {
			g_warning ("couldn't create login keyring: %s", egg_error_message (error));
			g_clear_error (&error);
		} else {
			success = TRUE;
		}

	/* Change the master password */
	} else if (login && ocred && mcred) {
		gck_builder_add_ulong (&builder, CKA_G_CREDENTIAL, gck_object_get_handle (mcred));
		if (!gck_object_set (login, gck_builder_end (&builder), NULL, &error)) {
			g_warning ("couldn't change login master password: %s", egg_error_message (error));
			g_clear_error (&error);
		} else {
			success = TRUE;
		}
	}

	if (ocred) {
		gck_object_destroy (ocred, NULL, NULL);
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
set_pin_for_any_slots (GList *modules, const gchar *original, const gchar *master)
{
	GError *error = NULL;
	GList *slots, *l;
	gboolean initialize;
	GckTokenInfo *info;
	GckSession *session;

	g_return_val_if_fail (original, FALSE);
	g_return_val_if_fail (master, FALSE);

	slots = gck_modules_get_slots (modules, TRUE);
	for (l = slots; l; l = g_list_next (l)) {

		/* Set pin for any that are initialized, and not pap */
		info = gck_slot_get_token_info (l->data);
		initialize = (info && (info->flags & CKF_USER_PIN_INITIALIZED));

		if (initialize) {
			session = open_and_login_session (l->data, CKU_USER, NULL);
			if (session != NULL) {
				if (!gck_session_set_pin (session, (const guchar*)original, strlen (original),
				                          (const guchar*)master, strlen (master), NULL, &error)) {
					if (!g_error_matches (error, GCK_ERROR, CKR_PIN_INCORRECT) &&
					    !g_error_matches (error, GCK_ERROR, CKR_FUNCTION_NOT_SUPPORTED))
						g_warning ("couldn't change slot master password: %s",
						           egg_error_message (error));
					g_clear_error (&error);
				}
				g_object_unref (session);
			}
		}

		gck_token_info_free (info);
	}
	gck_list_unref_free (slots);
	return TRUE;
}

gboolean
gkd_login_change_lock (const gchar *original, const gchar *master)
{
	GList *modules;
	gboolean result;

	/* We don't support null or empty master passwords */
	if (!master || !master[0])
		return FALSE;
	if (original == NULL)
		original = "";

	modules = module_instances ();

	result = change_or_create_login (modules, original, master);
	if (result == TRUE)
		set_pin_for_any_slots (modules, original, master);

	gck_list_unref_free (modules);
	return result;
}
