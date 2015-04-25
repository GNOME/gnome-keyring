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

#include "gkd-secret-create.h"
#include "gkd-secret-dispatch.h"
#include "gkd-secret-error.h"
#include "gkd-secret-objects.h"
#include "gkd-secret-prompt.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"
#include "gkd-secret-unlock.h"
#include "gkd-secret-util.h"

#include "egg/egg-error.h"
#include "egg/egg-secure-memory.h"

#include "pkcs11/pkcs11i.h"

#include <glib/gi18n.h>

#include <gck/gck.h>

#include <string.h>

enum {
	STATE_BEGIN,
	STATE_PROMPTING,
	STATE_PROMPTED
};

enum {
	PROP_0,
	PROP_PKCS11_ATTRIBUTES,
	PROP_ALIAS
};

struct _GkdSecretCreate {
	GkdSecretPrompt parent;
	GckAttributes *attributes;
	GkdSecretSecret *master;
	gchar *result_path;
	gchar *alias;
	gboolean confirmed;
};

static void    perform_prompting     (GkdSecretCreate *self);

G_DEFINE_TYPE (GkdSecretCreate, gkd_secret_create, GKD_SECRET_TYPE_PROMPT);

static void
setup_password_prompt (GkdSecretCreate *self)
{
	gchar *label;
	gchar *text;

	if (!gck_attributes_find_string (self->attributes, CKA_LABEL, &label))
		label = g_strdup (_("Unnamed"));

	text = g_strdup_printf (_("An application wants to create a new keyring called '%s'. "
				  "Choose the password you want to use for it."), label);
	g_free (label);

	gcr_prompt_set_message (GCR_PROMPT (self), _("Choose password for new keyring"));
	gcr_prompt_set_description (GCR_PROMPT (self), text);
	gcr_prompt_set_password_new (GCR_PROMPT (self), TRUE);

	g_free (text);
}

static void
setup_confirmation_prompt (GkdSecretCreate *self)
{
	gcr_prompt_set_message (GCR_PROMPT (self), _("Store passwords unencrypted?"));
	gcr_prompt_set_description (GCR_PROMPT (self),
				    _("By choosing to use a blank password, your stored passwords will not be safely encrypted. "
				      "They will be accessible by anyone with access to your files."));
}

static gboolean
create_collection_with_secret (GkdSecretCreate *self, GkdSecretSecret *master)
{
	GError *error = NULL;
	GkdSecretService *service;
	gchar *identifier;

	g_assert (GKD_SECRET_IS_CREATE (self));
	g_assert (master);
	g_assert (!self->result_path);

	self->result_path = gkd_secret_create_with_secret (self->attributes, master, &error);

	if (!self->result_path) {
		g_warning ("couldn't create new collection: %s", error->message);
		g_error_free (error);
		return FALSE;
	}

	service = gkd_secret_prompt_get_service (GKD_SECRET_PROMPT (self));

	if (self->alias) {
		if (!gkd_secret_util_parse_path (self->result_path, &identifier, NULL))
			g_assert_not_reached ();
		gkd_secret_service_set_alias (service, self->alias, identifier);
		g_free (identifier);
	}

	/* Notify the callers that a collection was created */
	gkd_secret_service_emit_collection_created (service, self->result_path);

	return TRUE;
}

static gboolean
locate_alias_collection_if_exists (GkdSecretCreate *self)
{
	GkdSecretService *service;
	GkdSecretObjects *objects;
	GckObject *collection;
	const gchar *identifier;
	const gchar *caller;
	gchar *path;

	if (!self->alias)
		return FALSE;

	g_assert (!self->result_path);

	service = gkd_secret_prompt_get_service (GKD_SECRET_PROMPT (self));
	caller = gkd_secret_prompt_get_caller (GKD_SECRET_PROMPT (self));
	objects = gkd_secret_prompt_get_objects (GKD_SECRET_PROMPT (self));

	identifier = gkd_secret_service_get_alias (service, self->alias);
	if (!identifier)
		return FALSE;

	/* Make sure it actually exists */
	path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX, identifier, -1);
	collection = gkd_secret_objects_lookup_collection (objects, caller, path);

	if (collection) {
		self->result_path = path;
		g_object_unref (collection);
		return TRUE;
	} else {
		g_free (path);
		return FALSE;
	}
}

static void
unlock_or_complete_this_prompt (GkdSecretCreate *self)
{
	GkdSecretUnlock *unlock;
	GkdSecretPrompt *prompt;

	g_object_ref (self);
	prompt = GKD_SECRET_PROMPT (self);

	unlock = gkd_secret_unlock_new (gkd_secret_prompt_get_service (prompt),
					gkd_secret_prompt_get_caller (prompt),
					gkd_secret_dispatch_get_object_path (GKD_SECRET_DISPATCH (self)));
	gkd_secret_unlock_queue (unlock, self->result_path);

	/*
	 * If any need to be unlocked, then replace this prompt
	 * object with an unlock prompt object, and call the prompt
	 * method.
	 */
	if (gkd_secret_unlock_have_queued (unlock)) {
		gkd_secret_service_publish_dispatch (gkd_secret_prompt_get_service (prompt),
						     gkd_secret_prompt_get_caller (prompt),
						     GKD_SECRET_DISPATCH (unlock));
		gkd_secret_unlock_call_prompt (unlock, gkd_secret_prompt_get_window_id (prompt));
	}

	g_object_unref (unlock);
	g_object_unref (self);
}

static void
on_prompt_password_complete (GObject *source,
			     GAsyncResult *result,
			     gpointer user_data)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (source);
	GkdSecretPrompt *prompt = GKD_SECRET_PROMPT (source);
	GError *error = NULL;

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

	perform_prompting (self);
}

static void
on_prompt_confirmation_complete (GObject *source,
				 GAsyncResult *result,
				 gpointer user_data)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (source);
	GkdSecretPrompt *prompt = GKD_SECRET_PROMPT (source);
	GError *error = NULL;

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

	perform_prompting (self);
}

static void
perform_prompting (GkdSecretCreate *self)
{
	GkdSecretPrompt *prompt = GKD_SECRET_PROMPT (self);

	/* Does the alias exist? */
	if (locate_alias_collection_if_exists (self)) {
		unlock_or_complete_this_prompt (self);

	/* Have we gotten a password yet? */
	} else if (self->master == NULL) {
		setup_password_prompt (self);
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
	} else  if (create_collection_with_secret (self, self->master)) {
		gkd_secret_prompt_complete (prompt);

	/* Failed */
	} else {
		gkd_secret_prompt_dismiss (prompt);
	}
}

static void
gkd_secret_create_prompt_ready (GkdSecretPrompt *prompt)
{
	perform_prompting (GKD_SECRET_CREATE (prompt));
}

static GVariant *
gkd_secret_create_encode_result (GkdSecretPrompt *base)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (base);
	const gchar *path;

	path = self->result_path ? self->result_path : "/";
	return g_variant_new_variant (g_variant_new_object_path (path));
}

static void
gkd_secret_create_init (GkdSecretCreate *self)
{
	gcr_prompt_set_title (GCR_PROMPT (self), _("New Keyring Password"));
}

static void
gkd_secret_create_finalize (GObject *obj)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (obj);

	gkd_secret_secret_free (self->master);
	gck_attributes_unref (self->attributes);
	g_free (self->result_path);
	g_free (self->alias);

	G_OBJECT_CLASS (gkd_secret_create_parent_class)->finalize (obj);
}

static void
gkd_secret_create_set_property (GObject *obj, guint prop_id, const GValue *value,
				GParamSpec *pspec)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (obj);

	switch (prop_id) {
	case PROP_PKCS11_ATTRIBUTES:
		g_return_if_fail (!self->attributes);
		self->attributes = g_value_dup_boxed (value);
		g_return_if_fail (self->attributes);
		break;
	case PROP_ALIAS:
		g_return_if_fail (!self->alias);
		self->alias = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_create_get_property (GObject *obj, guint prop_id, GValue *value,
				GParamSpec *pspec)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (obj);

	switch (prop_id) {
	case PROP_PKCS11_ATTRIBUTES:
		g_value_set_boxed (value, self->attributes);
		break;
	case PROP_ALIAS:
		g_value_set_string (value, self->alias);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_create_class_init (GkdSecretCreateClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkdSecretPromptClass *prompt_class = GKD_SECRET_PROMPT_CLASS (klass);

	gobject_class->finalize = gkd_secret_create_finalize;
	gobject_class->get_property = gkd_secret_create_get_property;
	gobject_class->set_property = gkd_secret_create_set_property;

	prompt_class->prompt_ready = gkd_secret_create_prompt_ready;
	prompt_class->encode_result = gkd_secret_create_encode_result;

	g_object_class_install_property (gobject_class, PROP_PKCS11_ATTRIBUTES,
		g_param_spec_boxed ("pkcs11-attributes", "PKCS11 Attributes", "PKCS11 Attributes",
				     GCK_TYPE_ATTRIBUTES, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_ALIAS,
		g_param_spec_string ("alias", "Alias", "Collection Alias",
				     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkdSecretCreate*
gkd_secret_create_new (GkdSecretService *service, const gchar *caller,
		       GckAttributes *attrs, const gchar *alias)
{
	const gchar *prompter_name;

	prompter_name = g_getenv ("GNOME_KEYRING_TEST_PROMPTER");
	return g_object_new (GKD_SECRET_TYPE_CREATE,
			     "service", service,
			     "caller", caller,
			     "pkcs11-attributes", attrs,
			     "alias", alias,
			     "bus-name", prompter_name,
			     NULL);
}

GckObject*
gkd_secret_create_with_credential (GckSession *session, GckAttributes *attrs,
				   GckObject *cred, GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	const GckAttribute *attr;
	gboolean token;

	gck_builder_add_ulong (&builder, CKA_G_CREDENTIAL, gck_object_get_handle (cred));
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_COLLECTION);

	attr = gck_attributes_find (attrs, CKA_LABEL);
	if (attr != NULL)
		gck_builder_add_attribute (&builder, attr);
	if (!gck_attributes_find_boolean (attrs, CKA_TOKEN, &token))
		token = FALSE;
	gck_builder_add_boolean (&builder, CKA_TOKEN, token);

	return gck_session_create_object (session, gck_builder_end (&builder), NULL, error);
}

gchar*
gkd_secret_create_with_secret (GckAttributes *attrs,
			       GkdSecretSecret *master,
			       GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckAttributes *atts;
	GckObject *cred;
	GckObject *collection;
	GckSession *session;
	gpointer identifier;
	gsize n_identifier;
	gboolean token;
	gchar *path;

	if (!gck_attributes_find_boolean (attrs, CKA_TOKEN, &token))
		token = FALSE;

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_CREDENTIAL);
	gck_builder_add_boolean (&builder, CKA_GNOME_TRANSIENT, TRUE);
	gck_builder_add_boolean (&builder, CKA_TOKEN, token);

	session = gkd_secret_session_get_pkcs11_session (master->session);
	g_return_val_if_fail (session, NULL);

	/* Create ourselves some credentials */
	atts = gck_attributes_ref_sink (gck_builder_end (&builder));
	cred = gkd_secret_session_create_credential (master->session, session,
						     atts, master, error);
	gck_attributes_unref (atts);

	if (cred == NULL)
		return FALSE;

	collection = gkd_secret_create_with_credential (session, attrs, cred, error);

	g_object_unref (cred);

	if (collection == NULL)
		return FALSE;

	identifier = gck_object_get_data (collection, CKA_ID, NULL, &n_identifier, error);
	g_object_unref (collection);

	if (!identifier)
		return FALSE;

	path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX, identifier, n_identifier);
	g_free (identifier);
	return path;
}
