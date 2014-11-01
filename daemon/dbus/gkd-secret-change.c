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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkd-secret-change.h"
#include "gkd-secret-prompt.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"

#include "egg/egg-error.h"
#include "egg/egg-secure-memory.h"

#include "pkcs11/pkcs11i.h"

#include <glib/gi18n.h>

#include <gck/gck.h>
#include <gcr/gcr-base.h>

#include <string.h>

enum {
	PROP_0,
	PROP_COLLECTION_PATH
};

struct _GkdSecretChange {
	GkdSecretPrompt parent;
	gchar *collection_path;
	GckSession *session;
	GkdSecretSecret *master;
	GckObject *ocred;
	gboolean unlocked;
	gboolean confirmed;
};

struct _GkdSecretChangeClass {
	GkdSecretPromptClass parent_class;
};

static void      perform_prompting     (GkdSecretChange *self,
                                        GckObject *collection);

G_DEFINE_TYPE (GkdSecretChange, gkd_secret_change, GKD_SECRET_TYPE_PROMPT);

static void
setup_original_prompt (GkdSecretChange *self,
                       GckObject *collection)
{
	GcrPrompt *prompt = GCR_PROMPT (self);
	GError *error = NULL;
	gpointer data;
	gsize n_data;
	gchar *label;
	gchar *text;

	data = gck_object_get_data (collection, CKA_LABEL, NULL, &n_data, &error);
	if (!data) {
		g_warning ("couldn't get label for collection: %s", egg_error_message (error));
		g_clear_error (&error);
	}

	if (!data || !n_data)
		label = g_strdup (_("Unnamed"));
	else
		label = g_strndup (data, n_data);
	g_free (data);

	text = g_strdup_printf (_("Enter the old password for the '%s' keyring"), label);
	gcr_prompt_set_message (prompt, text);
	g_free (text);

	text = g_strdup_printf (_("An application wants to change the password for the '%s' keyring. "
	                          "Enter the old password for it."), label);
	gcr_prompt_set_description (prompt, text);
	g_free (text);

	gcr_prompt_set_password_new (prompt, FALSE);
	gcr_prompt_set_continue_label (prompt, _("Continue"));
}

static void
setup_password_prompt (GkdSecretChange *self,
                       GckObject *collection)
{
	GcrPrompt *prompt = GCR_PROMPT (self);
	GError *error = NULL;
	gpointer data;
	gsize n_data;
	gchar *label;
	gchar *text;

	data = gck_object_get_data (collection, CKA_LABEL, NULL, &n_data, &error);
	if (!data) {
		g_warning ("couldn't get label for collection: %s", egg_error_message (error));
		g_clear_error (&error);
	}

	if (!data || !n_data)
		label = g_strdup (_("Unnamed"));
	else
		label = g_strndup (data, n_data);
	g_free (data);

	text = g_strdup_printf (_("Choose a new password for the '%s' keyring"), label);
	gcr_prompt_set_message (prompt, text);
	g_free (text);

	text = g_strdup_printf (_("An application wants to change the password for the '%s' keyring. "
	                          "Choose the new password you want to use for it."), label);
	gcr_prompt_set_description (prompt, text);
	g_free (text);

	gcr_prompt_set_password_new (prompt, TRUE);
	gcr_prompt_set_continue_label (prompt, _("Continue"));
	gcr_prompt_set_warning (prompt, NULL);
}

static void
setup_confirmation_prompt (GkdSecretChange *self)
{
	gcr_prompt_set_message (GCR_PROMPT (self), _("Store passwords unencrypted?"));
	gcr_prompt_set_description (GCR_PROMPT (self),
	                            _("By choosing to use a blank password, your stored passwords will not be safely encrypted. "
	                              "They will be accessible by anyone with access to your files."));
	gcr_prompt_set_continue_label (GCR_PROMPT (self), _("Continue"));
}

static void
set_warning_wrong (GkdSecretChange *self)
{
	gcr_prompt_set_warning (GCR_PROMPT (self), _("The original password was incorrect"));
}

static void
on_prompt_original_complete (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GkdSecretChange *self = GKD_SECRET_CHANGE (source);
	GkdSecretPrompt *prompt = GKD_SECRET_PROMPT (source);
	GckBuilder builder = GCK_BUILDER_INIT;
	gboolean continue_prompting = TRUE;
	GkdSecretSecret *original;
	GckAttributes *attrs;
	GError *error = NULL;
	GckObject *collection;

	gcr_prompt_password_finish (GCR_PROMPT (source), result, &error);
	if (error != NULL) {
		gkd_secret_prompt_dismiss_with_error (prompt, error);
		g_error_free (error);
		return;
	}

	/* The prompt was cancelled */
	original = gkd_secret_prompt_take_secret (prompt);
	if (original == NULL) {
		gkd_secret_prompt_dismiss (prompt);
		return;
	}

	collection = gkd_secret_prompt_lookup_collection (prompt, self->collection_path);
	if (collection != NULL) {
		gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_CREDENTIAL);
		gck_builder_add_boolean (&builder, CKA_TOKEN, FALSE);
		gck_builder_add_ulong (&builder, CKA_G_OBJECT, gck_object_get_handle (collection));

		attrs = gck_attributes_ref_sink (gck_builder_end (&builder));

		/* Create the original credential, in order to make sure we can unlock the collection */
		self->ocred = gkd_secret_session_create_credential (original->session,
		                                                    self->session, attrs,
		                                                    original, &error);

		gck_attributes_unref (attrs);

		/* The unlock failed because password was bad */
		if (g_error_matches (error, GCK_ERROR, CKR_PIN_INCORRECT)) {
			set_warning_wrong (self);
			g_error_free (error);

		/* The unlock failed for some other reason */
		} else if (error != NULL) {
			continue_prompting = FALSE;
			gkd_secret_prompt_dismiss_with_error (prompt, error);
			g_error_free (error);

		/* The unlock succeeded */
		} else {
			if (self->session == NULL)
				self->session = gck_object_get_session (self->ocred);
			self->unlocked = TRUE;
		}
	}

	if (continue_prompting)
		perform_prompting (self, collection);

	gkd_secret_secret_free (original);
	g_clear_object (&collection);
}

static void
on_prompt_password_complete (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GkdSecretChange *self = GKD_SECRET_CHANGE (source);
	GkdSecretPrompt *prompt = GKD_SECRET_PROMPT (source);
	GError *error = NULL;
	GckObject *collection;

	gcr_prompt_password_finish (GCR_PROMPT (source), result, &error);
	if (error != NULL) {
		gkd_secret_prompt_dismiss_with_error (prompt, error);
		g_error_free (error);
		return;
	}

	self->master = gkd_secret_prompt_take_secret (prompt);
	if (self->master == NULL) {
		gkd_secret_prompt_dismiss (prompt);
		return;
	}

	/* If the password strength is greater than zero, then don't confirm */
	if (gcr_prompt_get_password_strength (GCR_PROMPT (source)) > 0)
		self->confirmed = TRUE;

	collection = gkd_secret_prompt_lookup_collection (prompt, self->collection_path);
	perform_prompting (self, collection);
	g_clear_object (&collection);
}

static void
on_prompt_confirmation_complete (GObject *source,
                                 GAsyncResult *result,
                                 gpointer user_data)
{
	GkdSecretChange *self = GKD_SECRET_CHANGE (source);
	GkdSecretPrompt *prompt = GKD_SECRET_PROMPT (source);
	GError *error = NULL;
	GckObject *collection;

	self->confirmed = gcr_prompt_confirm_finish (GCR_PROMPT (source), result, &error);
	if (error != NULL) {
		gkd_secret_prompt_dismiss_with_error (prompt, error);
		g_error_free (error);
		return;
	}

	/* If not confirmed, then prompt again */
	if (!self->confirmed) {
		gkd_secret_secret_free (self->master);
		self->master = NULL;
	}

	collection = gkd_secret_prompt_lookup_collection (prompt, self->collection_path);
	perform_prompting (self, collection);
	g_clear_object (&collection);
}

static void
perform_prompting (GkdSecretChange *self,
                   GckObject *collection)
{
	GkdSecretPrompt *prompt = GKD_SECRET_PROMPT (self);
	GError *error = NULL;

	/* Collection doesn't exist, just go away */
	if (collection == NULL) {
		gkd_secret_prompt_dismiss (prompt);

	/* Get the original password and unlock */
	} else if (!self->unlocked) {
		setup_original_prompt (self, collection);
		gcr_prompt_password_async (GCR_PROMPT (self),
		                           gkd_secret_prompt_get_cancellable (prompt),
		                           on_prompt_original_complete, NULL);

	/* Get the new password */
	} else if (self->master == NULL) {
		setup_password_prompt (self, collection);
		gcr_prompt_password_async (GCR_PROMPT (self),
		                           gkd_secret_prompt_get_cancellable (prompt),
		                           on_prompt_password_complete, NULL);

	/* Check that the password is not empty */
	} else if (!self->confirmed) {
		setup_confirmation_prompt (self);
		gcr_prompt_confirm_async (GCR_PROMPT (self),
		                          gkd_secret_prompt_get_cancellable (prompt),
		                          on_prompt_confirmation_complete, NULL);

	/* Actually create the keyring */
	} else if (gkd_secret_change_with_secrets (collection, self->session,
	                                           NULL, self->master, &error)) {
		gkd_secret_prompt_complete (prompt);

	/* Failed */
	} else {
		gkd_secret_prompt_dismiss_with_error (prompt, error);
		g_error_free (error);
	}
}

static void
gkd_secret_change_prompt_ready (GkdSecretPrompt *prompt)
{
	GkdSecretChange *self = GKD_SECRET_CHANGE (prompt);
	GckObject *collection;

	collection = gkd_secret_prompt_lookup_collection (prompt, self->collection_path);
	perform_prompting (self, collection);
	g_clear_object (&collection);
}

static GVariant *
gkd_secret_change_encode_result (GkdSecretPrompt *base)
{
        return g_variant_new_variant (g_variant_new_string (""));
}

static void
gkd_secret_change_init (GkdSecretChange *self)
{
	gcr_prompt_set_title (GCR_PROMPT (self), _("Change Keyring Password"));
}

static void
gkd_secret_change_dispose (GObject *obj)
{
	GkdSecretChange *self = GKD_SECRET_CHANGE (obj);

	if (self->ocred) {
		gck_object_destroy (self->ocred, NULL, NULL);
		g_object_unref (self->ocred);
		self->ocred = NULL;
	}

	G_OBJECT_CLASS (gkd_secret_change_parent_class)->dispose (obj);
}

static void
gkd_secret_change_finalize (GObject *obj)
{
	GkdSecretChange *self = GKD_SECRET_CHANGE (obj);

	g_free (self->collection_path);
	if (self->master)
		gkd_secret_secret_free (self->master);
	if (self->session)
		g_object_unref (self->session);

	G_OBJECT_CLASS (gkd_secret_change_parent_class)->finalize (obj);
}

static void
gkd_secret_change_set_property (GObject *obj, guint prop_id, const GValue *value,
                                GParamSpec *pspec)
{
	GkdSecretChange *self = GKD_SECRET_CHANGE (obj);

	switch (prop_id) {
	case PROP_COLLECTION_PATH:
		g_return_if_fail (!self->collection_path);
		self->collection_path = g_value_dup_string (value);
		g_return_if_fail (self->collection_path);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_change_get_property (GObject *obj, guint prop_id, GValue *value,
                                GParamSpec *pspec)
{
	GkdSecretChange *self = GKD_SECRET_CHANGE (obj);

	switch (prop_id) {
	case PROP_COLLECTION_PATH:
		g_value_set_string (value, self->collection_path);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_change_class_init (GkdSecretChangeClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkdSecretPromptClass *prompt_class = GKD_SECRET_PROMPT_CLASS (klass);

	gobject_class->dispose = gkd_secret_change_dispose;
	gobject_class->finalize = gkd_secret_change_finalize;
	gobject_class->get_property = gkd_secret_change_get_property;
	gobject_class->set_property = gkd_secret_change_set_property;

	prompt_class->prompt_ready = gkd_secret_change_prompt_ready;
	prompt_class->encode_result = gkd_secret_change_encode_result;

	g_object_class_install_property (gobject_class, PROP_COLLECTION_PATH,
		g_param_spec_string ("collection-path", "Collection Path", "Collection Path",
		                     "/", G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkdSecretChange*
gkd_secret_change_new (GkdSecretService *service, const gchar *caller,
                       const gchar *path)
{
	const gchar *prompter_name;

	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (caller, NULL);
	g_return_val_if_fail (path, NULL);

	prompter_name = g_getenv ("GNOME_KEYRING_TEST_PROMPTER");
	return g_object_new (GKD_SECRET_TYPE_CHANGE,
	                     "service", service,
	                     "caller", caller,
	                     "collection-path", path,
	                     "bus-name", prompter_name,
	                     NULL);
}

gboolean
gkd_secret_change_with_secrets (GckObject *collection,
                                GckSession *session,
                                GkdSecretSecret *original,
                                GkdSecretSecret *master,
                                GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckAttributes *attrs = NULL;
	gboolean result = FALSE;
	GckObject *ocred = NULL;
	GckObject *mcred = NULL;

	g_assert (GCK_IS_OBJECT (collection));
	g_assert (session == NULL || GCK_IS_SESSION (session));
	g_assert (master != NULL);
	g_assert (error == NULL || *error == NULL);

	/* Create the new credential */
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_CREDENTIAL);
	gck_builder_add_boolean (&builder, CKA_TOKEN, FALSE);
	attrs = gck_attributes_ref_sink (gck_builder_end (&builder));
	mcred = gkd_secret_session_create_credential (master->session, session, attrs, master, error);
	gck_builder_add_all (&builder, attrs);
	gck_attributes_unref (attrs);

	if (mcred == NULL)
		goto cleanup;

	/* Create the original credential, in order to make sure we can the collection */
	if (original) {
		gck_builder_add_ulong (&builder, CKA_G_OBJECT, gck_object_get_handle (collection));
		attrs = gck_attributes_ref_sink (gck_builder_end (&builder));
		ocred = gkd_secret_session_create_credential (original->session, session, attrs, original, error);
		gck_attributes_unref (attrs);

		if (ocred == NULL)
			goto cleanup;
	}

	gck_builder_clear (&builder);
	gck_builder_add_ulong (&builder, CKA_G_CREDENTIAL, gck_object_get_handle (mcred));

	/* Now set the collection credentials to the first one */
	result = gck_object_set (collection, gck_builder_end (&builder), NULL, error);

cleanup:
	if (ocred) {
		/* Always destroy the original credential */
		gck_object_destroy (ocred, NULL, NULL);
		g_object_unref (ocred);
	}
	if (mcred) {
		/* Always destroy the master credential */
		gck_object_destroy (mcred, NULL, NULL);
		g_object_unref (mcred);
	}

	gck_builder_clear (&builder);
	return result;
}
