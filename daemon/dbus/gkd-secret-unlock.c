/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
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

#include "gkd-secret-objects.h"
#include "gkd-secret-service.h"
#include "gkd-secret-prompt.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"
#include "gkd-secret-unlock.h"
#include "gkd-secret-util.h"

#include "egg/egg-secure-memory.h"

#include "login/gkd-login.h"

#include "pkcs11/pkcs11i.h"

#include <glib/gi18n.h>

#include <gp11/gp11.h>

#include <string.h>

struct _GkdSecretUnlock {
	GkdSecretPrompt parent;
	GQueue *queued;
	gchar *current;
	GArray *results;
};

G_DEFINE_TYPE (GkdSecretUnlock, gkd_secret_unlock, GKD_SECRET_TYPE_PROMPT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar*
location_string_for_collection (GP11Object *collection)
{
	gpointer identifier;
	gsize n_identifier;
	gchar *location;

	/* Figure out the identifier */
	identifier = gp11_object_get_data (collection, CKA_ID, &n_identifier, NULL);
	if (!identifier || !g_utf8_validate (identifier, n_identifier, NULL)) {
		g_free (identifier);
		return NULL;
	}

	/*
	 * COMPAT: Format it into a string. This is done this way for compatibility
	 * with old gnome-keyring releases. In the future this may change.
	 *
	 * FYI: gp11_object_get_data() null terminates
	 */
	location = g_strdup_printf ("LOCAL:/keyrings/%s.keyring", (gchar*)identifier);
	g_free (identifier);
	return location;
}

static void
prepare_unlock_prompt (GkdSecretUnlock *self, GP11Object *coll)
{
	GError *error = NULL;
	GkdPrompt *prompt;
	gpointer data;
	gsize n_data;
	gchar *label;
	gchar *text;

	g_assert (GKD_SECRET_IS_UNLOCK (self));
	g_assert (coll);

	prompt = GKD_PROMPT (self);

	data = gp11_object_get_data (coll, CKA_LABEL, &n_data, &error);
	if (!data) {
		g_warning ("couldn't get label for collection: %s", error->message);
		g_clear_error (&error);
	}

	if (!data || !n_data)
		label = g_strdup (_("Unnamed"));
	else
		label = g_strndup (data, n_data);
	g_free (data);

	gkd_prompt_reset (prompt);

	gkd_prompt_set_title (prompt, _("Unlock Keyring"));

	text = g_markup_printf_escaped (_("Enter password for keyring '%s' to unlock"), label);
	gkd_prompt_set_primary_text (prompt, text);
	g_free (text);

	text = g_markup_printf_escaped (_("An application wants access to the keyring '%s', but it is locked"), label);
	gkd_prompt_set_secondary_text (prompt, text);
	g_free (text);

	gkd_prompt_hide_widget (prompt, "name_area");
	gkd_prompt_hide_widget (prompt, "confirm_area");
	gkd_prompt_hide_widget (prompt, "details_area");
	gkd_prompt_show_widget (prompt, "password_area");

	g_free (label);
}

static void
set_warning_wrong (GkdSecretUnlock *self)
{
	g_assert (GKD_SECRET_IS_UNLOCK (self));
	gkd_prompt_set_warning (GKD_PROMPT (self), _("The unlock password was incorrect"));
}

static gboolean
check_locked_collection (GP11Object *collection, gboolean *locked)
{
	GError *error = NULL;
	gpointer value;
	gsize n_value;

	value = gp11_object_get_data (collection, CKA_G_LOCKED, &n_value, &error);
	if (value == NULL) {
		if (error->code != CKR_OBJECT_HANDLE_INVALID)
			g_warning ("couldn't check locked status of collection: %s",
			           error->message);
		return FALSE;
	}

	*locked = (value && n_value == sizeof (CK_BBOOL) && *(CK_BBOOL*)value);
	g_free (value);
	return TRUE;
}

static gboolean
authenticate_collection (GkdSecretUnlock *self, GP11Object *collection, gboolean *locked)
{
	DBusError derr = DBUS_ERROR_INIT;
	GkdSecretSecret *master;
	gboolean result;

	g_assert (GKD_SECRET_IS_UNLOCK (self));
	g_assert (GP11_IS_OBJECT (collection));
	g_assert (locked);

	/* Bail out early, just checking locked status */
	if (!gkd_prompt_has_response (GKD_PROMPT (self))) {
		return check_locked_collection (collection, locked);
	}

	master = gkd_secret_prompt_get_secret (GKD_SECRET_PROMPT (self), "password");
	if (master == NULL) {
		g_warning ("couldn't get password from prompt");
		return FALSE;
	}

	result = gkd_secret_unlock_with_secret (collection, master, &derr);
	gkd_secret_secret_free (master);

	if (result) {
		*locked = FALSE;
		return TRUE; /* Operation succeeded, and unlocked */

	} else {
		if (dbus_error_has_name (&derr, INTERNAL_ERROR_DENIED)) {
			dbus_error_free (&derr);
			*locked = TRUE;
			return TRUE; /* Operation succeded, although not unlocked*/

		} else {
			g_warning ("couldn't create credential for collection: %s",
			           derr.message);
			dbus_error_free (&derr);
			return FALSE; /* Operation failed */
		}
	}
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkd_secret_unlock_prompt_ready (GkdSecretPrompt *prompt)
{
	GkdSecretUnlock *self = GKD_SECRET_UNLOCK (prompt);
	GP11Object *coll;
	gboolean locked;
	gchar *objpath;

	/* Already prompted for an item */
	if (self->current) {
		coll = gkd_secret_prompt_lookup_collection (prompt, self->current);

		/* If the object or collection is gone, no need to unlock */
		if (coll == NULL) {
			g_free (self->current);
			self->current = NULL;

		} else {
			/* Try to unlock the collection */
			if (!authenticate_collection (self, coll, &locked)) {
				g_free (self->current);
				self->current = NULL;

			/* Collection still locked, prompt again */
			} else if (locked) {
				prepare_unlock_prompt (self, coll);
				set_warning_wrong (self);

			/* Collection not locked, done with this one */
			} else {
				g_array_append_val (self->results, self->current);
				self->current = NULL;
			}

			g_object_unref (coll);
		}
	}

	/* Queue the next item? */
	while (!self->current) {
		objpath = g_queue_pop_head (self->queued);

		/* Nothing more to prompt for? */
		if (!objpath) {
			gkd_secret_prompt_complete (prompt);
			break;
		}

		/* Find the collection, make sure it's still around */
		coll = gkd_secret_prompt_lookup_collection (prompt, objpath);
		if (coll == NULL) {
			g_free (objpath);
			continue;
		}

		/* Make sure this collection still needs unlocking */
		if (!authenticate_collection (self, coll, &locked)) {
			g_object_unref (coll);
			g_free (objpath);
			continue;
		} else if (!locked) {
			g_array_append_val (self->results, objpath);
			g_object_unref (coll);
			continue;
		}

		prepare_unlock_prompt (self, coll);
		g_object_unref (coll);
		self->current = objpath;
	}
}

static void
gkd_secret_unlock_encode_result (GkdSecretPrompt *base, DBusMessageIter *iter)
{
	GkdSecretUnlock *self = GKD_SECRET_UNLOCK (base);
	DBusMessageIter variant;
	DBusMessageIter array;
	const char *value;
	gint i;

	dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, "ao", &variant);
	dbus_message_iter_open_container (&variant, DBUS_TYPE_ARRAY, "o", &array);

	for (i = 0; i < self->results->len; ++i) {
		value = g_array_index (self->results, gchar*, i);
		dbus_message_iter_append_basic (&array, DBUS_TYPE_OBJECT_PATH, &value);
	}

	dbus_message_iter_close_container (&variant, &array);
	dbus_message_iter_close_container (iter, &variant);
}

static void
gkd_secret_unlock_init (GkdSecretUnlock *self)
{
	self->queued = g_queue_new ();
	self->results = g_array_new (TRUE, TRUE, sizeof (gchar*));
}

static void
gkd_secret_unlock_finalize (GObject *obj)
{
	GkdSecretUnlock *self = GKD_SECRET_UNLOCK (obj);

	if (self->queued) {
		while (!g_queue_is_empty (self->queued))
			g_free (g_queue_pop_head (self->queued));
		g_queue_free (self->queued);
		self->queued = NULL;
	}

	if (self->results) {
		gkd_secret_unlock_reset_results (self);
		g_array_free (self->results, TRUE);
		self->results = NULL;
	}

	g_free (self->current);
	self->current = NULL;

	G_OBJECT_CLASS (gkd_secret_unlock_parent_class)->finalize (obj);
}

static void
gkd_secret_unlock_class_init (GkdSecretUnlockClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkdSecretPromptClass *prompt_class = GKD_SECRET_PROMPT_CLASS (klass);

	gobject_class->finalize = gkd_secret_unlock_finalize;
	prompt_class->prompt_ready = gkd_secret_unlock_prompt_ready;
	prompt_class->encode_result = gkd_secret_unlock_encode_result;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkdSecretUnlock*
gkd_secret_unlock_new (GkdSecretService *service, const gchar *caller)
{
	return g_object_new (GKD_SECRET_TYPE_UNLOCK, "service", service, "caller", caller, NULL);
}

void
gkd_secret_unlock_queue (GkdSecretUnlock *self, const gchar *objpath)
{
	gboolean locked = TRUE;
	GP11Object *coll;
	gchar *password;
	gchar *location;
	gchar *path;

	g_return_if_fail (GKD_SECRET_IS_UNLOCK (self));
	g_return_if_fail (objpath);

	coll = gkd_secret_prompt_lookup_collection (GKD_SECRET_PROMPT (self), objpath);
	if (coll == NULL)
		return;

	/* Try to unlock with an empty password */
	if (gkd_secret_unlock_with_password (coll, NULL, 0, NULL)) {
		locked = FALSE;

	/* Or try to use login keyring's passwords */
	} else {
		location = location_string_for_collection (coll);
		if (location) {
			password = gkd_login_lookup_secret ("keyring", location, NULL);
			g_free (location);

			if (password) {
				if (gkd_secret_unlock_with_password (coll, (guchar*)password, strlen (password), NULL))
					locked = FALSE;
				egg_secure_strfree (password);
			}
		}
	}

	path = g_strdup (objpath);
	if (locked)
		g_queue_push_tail (self->queued, path);
	else
		g_array_append_val (self->results, path);

	g_object_unref (coll);
}

gboolean
gkd_secret_unlock_have_queued (GkdSecretUnlock *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_UNLOCK (self), FALSE);
	return !g_queue_is_empty (self->queued) || self->current;
}

gchar**
gkd_secret_unlock_get_results (GkdSecretUnlock *self, gint *n_results)
{
	g_return_val_if_fail (GKD_SECRET_IS_UNLOCK (self), NULL);
	g_return_val_if_fail (n_results, NULL);
	*n_results = self->results->len;
	return (gchar**)self->results->data;
}

void
gkd_secret_unlock_reset_results (GkdSecretUnlock *self)
{
	gint i;

	g_return_if_fail (GKD_SECRET_IS_UNLOCK (self));

	for (i = 0; i < self->results->len; ++i)
		g_free (g_array_index (self->results, gchar*, i));
	g_array_set_size (self->results, 0);
}

gboolean
gkd_secret_unlock_with_secret (GP11Object *collection, GkdSecretSecret *master,
                               DBusError *derr)
{
	GP11Attributes *attrs;
	GP11Object *cred;
	gboolean locked;

	g_return_val_if_fail (GP11_IS_OBJECT (collection), FALSE);
	g_return_val_if_fail (master, FALSE);

	/* Shortcut if already unlocked */
	if (check_locked_collection (collection, &locked) && !locked)
		return TRUE;

	attrs = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, CKO_G_CREDENTIAL,
	                              CKA_G_OBJECT, GP11_ULONG, gp11_object_get_handle (collection),
	                              CKA_GNOME_TRANSIENT, GP11_BOOLEAN, TRUE,
	                              CKA_TOKEN, GP11_BOOLEAN, TRUE,
	                              GP11_INVALID);

	cred = gkd_secret_session_create_credential (master->session, NULL, attrs, master, derr);

	gp11_attributes_unref (attrs);

	if (cred != NULL)
		g_object_unref (cred);
	return (cred != NULL);
}

gboolean
gkd_secret_unlock_with_password (GP11Object *collection, const guchar *password,
                                 gsize n_password, DBusError *derr)
{
	GError *error = NULL;
	GP11Session *session;
	GP11Object *cred;
	gboolean locked;

	g_return_val_if_fail (GP11_IS_OBJECT (collection), FALSE);

	/* Shortcut if already unlocked */
	if (check_locked_collection (collection, &locked) && !locked)
		return TRUE;

	session = gp11_object_get_session (collection);
	g_return_val_if_fail (session, FALSE);

	cred = gp11_session_create_object (session, &error, CKA_CLASS, GP11_ULONG, CKO_G_CREDENTIAL,
	                                   CKA_G_OBJECT, GP11_ULONG, gp11_object_get_handle (collection),
	                                   CKA_GNOME_TRANSIENT, GP11_BOOLEAN, TRUE,
	                                   CKA_TOKEN, GP11_BOOLEAN, TRUE,
	                                   CKA_VALUE, n_password, password,
	                                   GP11_INVALID);

	if (cred == NULL) {
		if (error->code == CKR_PIN_INCORRECT) {
			dbus_set_error_const (derr, INTERNAL_ERROR_DENIED, "The password was incorrect.");
		} else {
			g_message ("couldn't create credential: %s", error->message);
			dbus_set_error_const (derr, DBUS_ERROR_FAILED, "Couldn't use credentials");
		}
		g_clear_error (&error);
		return FALSE;
	}

	g_object_unref (cred);
	return TRUE;
}
