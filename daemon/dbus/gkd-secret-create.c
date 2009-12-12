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

#include "gkd-secret-create.h"
#include "gkd-secret-prompt.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"
#include "gkd-secret-util.h"

#include "egg/egg-secure-memory.h"

#include "pkcs11/pkcs11i.h"

#include <glib/gi18n.h>

#include <gp11/gp11.h>

#include <string.h>

enum {
	PROP_0,
	PROP_PKCS11_ATTRIBUTES
};

struct _GkdSecretCreate {
	GkdSecretPrompt parent;
	GP11Attributes *pkcs11_attrs;
	gchar *result_path;
};

G_DEFINE_TYPE (GkdSecretCreate, gkd_secret_create, GKD_SECRET_TYPE_PROMPT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
prepare_create_prompt (GkdSecretCreate *self)
{
	GkdPrompt *prompt;
	gchar *label;
	gchar *text;

	g_assert (GKD_SECRET_IS_CREATE (self));
	g_assert (self->pkcs11_attrs);

	prompt = GKD_PROMPT (self);

	if (!gp11_attributes_find_string (self->pkcs11_attrs, CKA_LABEL, &label))
		label = g_strdup (_("Unnamed"));

	gkd_prompt_reset (prompt);

	gkd_prompt_set_title (prompt, _("New Keyring Password"));
	gkd_prompt_set_primary_text (prompt, _("Choose password for new keyring"));

	text = g_markup_printf_escaped (_("An application wants to create a new keyring called '%s'. "
	                                  "Choose the password you want to use for it."), label);
	gkd_prompt_set_secondary_text (prompt, text);
	g_free (text);

	gkd_prompt_hide_widget (prompt, "name_area");
	gkd_prompt_hide_widget (prompt, "confirm_area");
	gkd_prompt_hide_widget (prompt, "details_area");

	g_free (label);
}

static gboolean
create_collection_with_credential (GkdSecretCreate *self, GP11Object *cred)
{
	GError *error = NULL;
	GP11Object *collection;
	GP11Session *session;
	gpointer identifier;
	gsize n_identifier;

	g_assert (GKD_SECRET_IS_CREATE (self));
	g_return_val_if_fail (self->pkcs11_attrs, FALSE);
	g_return_val_if_fail (!self->result_path, FALSE);
	g_return_val_if_fail (GP11_IS_OBJECT (cred), FALSE);

	session =  gkd_secret_prompt_get_pkcs11_session (GKD_SECRET_PROMPT (self));
	g_return_val_if_fail (session, FALSE);

	/* Setup remainder of attributes on collection */
	gp11_attributes_add_ulong (self->pkcs11_attrs, CKA_G_CREDENTIAL,
	                           gp11_object_get_handle (cred));

	collection = gp11_session_create_object_full (session, self->pkcs11_attrs, NULL, &error);
	if (!collection) {
		g_warning ("couldn't create collection: %s", error->message);
		g_clear_error (&error);
		return FALSE;
	}

	gp11_object_set_session (collection, session);
	identifier = gp11_object_get_data (collection, CKA_ID, &n_identifier, &error);
	g_object_unref (collection);

	if (!identifier) {
		g_warning ("couldn't lookup new collection identifier: %s", error->message);
		g_clear_error (&error);
		return FALSE;
	}

	self->result_path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX, identifier, n_identifier);
	g_free (identifier);

	return TRUE;
}

static gboolean
create_collection_with_password (GkdSecretCreate *self, const gchar *password)
{
	GError *error = NULL;
	GP11Session *session;
	GP11Object *cred;
	gsize n_password;
	gboolean token;
	gboolean result;

	g_assert (GKD_SECRET_IS_CREATE (self));

	if (gp11_attributes_find_boolean (self->pkcs11_attrs, CKA_TOKEN, &token))
		token = FALSE;
	n_password = password ? strlen (password) : 0;

	session =  gkd_secret_prompt_get_pkcs11_session (GKD_SECRET_PROMPT (self));
	g_return_val_if_fail (session, FALSE);

	cred = gp11_session_create_object (session, &error,
	                                   CKA_CLASS, GP11_ULONG, CKO_G_CREDENTIAL,
	                                   CKA_GNOME_TRANSIENT, GP11_BOOLEAN, TRUE,
	                                   CKA_TOKEN, GP11_BOOLEAN, token,
	                                   CKA_VALUE, n_password, password,
	                                   GP11_INVALID);

	if (!cred) {
		g_warning ("couldn't create credential for new collection: %s", error->message);
		g_clear_error (&error);
		return FALSE;
	}

	result = create_collection_with_credential (self, cred);
	g_object_unref (cred);

	return result;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkd_secret_create_prompt_ready (GkdSecretPrompt *base)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (base);
	GkdPrompt *prompt = GKD_PROMPT (self);
	gchar *password;

	if (!gkd_prompt_has_response (prompt)) {
		prepare_create_prompt (self);
		return;
	}

	/* Already prompted, create collection */
	g_return_if_fail (gkd_prompt_get_response (prompt) == GKD_RESPONSE_OK);
	password = gkd_prompt_get_password (prompt, "password");

	if (create_collection_with_password (self, password))
		gkd_secret_prompt_complete (GKD_SECRET_PROMPT (self));
	else
		gkd_secret_prompt_dismiss (GKD_SECRET_PROMPT (self));

	egg_secure_strfree (password);
}

static void
gkd_secret_create_encode_result (GkdSecretPrompt *base, DBusMessageIter *iter)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (base);
	DBusMessageIter variant;
	const gchar *path;

	dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, "o", &variant);
	path = self->result_path ? self->result_path : "/";
	dbus_message_iter_append_basic (&variant, DBUS_TYPE_OBJECT_PATH, &path);
	dbus_message_iter_close_container (iter, &variant);
}

static void
gkd_secret_create_init (GkdSecretCreate *self)
{

}

static void
gkd_secret_create_finalize (GObject *obj)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (obj);

	if (self->pkcs11_attrs)
		gp11_attributes_unref (self->pkcs11_attrs);
	self->pkcs11_attrs = NULL;

	G_OBJECT_CLASS (gkd_secret_create_parent_class)->finalize (obj);
}

static void
gkd_secret_create_set_property (GObject *obj, guint prop_id, const GValue *value,
                                GParamSpec *pspec)
{
	GkdSecretCreate *self = GKD_SECRET_CREATE (obj);

	switch (prop_id) {
	case PROP_PKCS11_ATTRIBUTES:
		g_return_if_fail (!self->pkcs11_attrs);
		self->pkcs11_attrs = g_value_dup_boxed (value);
		gp11_attributes_add_ulong (self->pkcs11_attrs, CKA_CLASS, CKO_G_COLLECTION);
		g_return_if_fail (self->pkcs11_attrs);
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
		g_value_set_boxed (value, self->pkcs11_attrs);
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
		                     GP11_TYPE_ATTRIBUTES, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkdSecretCreate*
gkd_secret_create_new (GkdSecretService *service, const gchar *caller,
                       GP11Attributes *attrs)
{
	return g_object_new (GKD_SECRET_TYPE_CREATE,
	                     "service", service,
	                     "caller", caller,
	                     "pkcs11-attributes", attrs,
	                     NULL);
}

DBusMessage*
gkd_secret_create_without_prompting (GkdSecretService *service, DBusMessage *message,
                                     GP11Attributes *attrs, GkdSecretSecret *master)
{
	DBusError derr = DBUS_ERROR_INIT;
	GkdSecretSession *session;
	GP11Attributes *atts;
	GP11Attribute *label;
	DBusMessage *reply;
	GP11Object *cred;
	GP11Object *collection;
	GP11Session *pkcs11_session;
	GError *error = NULL;
	gpointer identifier;
	gsize n_identifier;
	gchar *path;

	/* Figure out the session */
	session = gkd_secret_service_lookup_session (service, master->path,
	                                             dbus_message_get_sender (message));
	if (session == NULL)
		return dbus_message_new_error (message, SECRET_ERROR_NO_SESSION,
		                               "No such session exists");

	atts = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, CKO_G_CREDENTIAL,
	                             CKA_GNOME_TRANSIENT, GP11_BOOLEAN, TRUE,
	                             CKA_TOKEN, GP11_BOOLEAN, TRUE,
	                             GP11_INVALID);

	/* Create ourselves some credentials */
	cred = gkd_secret_session_create_credential (session, atts, master, &derr);
	gp11_attributes_unref (atts);

	if (cred == NULL) {
		reply = dbus_message_new_error (message, derr.name, derr.message);
		dbus_error_free (&derr);
		return reply;
	}

	/* The only thing we actually use from the properties right now is the label */
	atts = gp11_attributes_newv (CKA_TOKEN, GP11_BOOLEAN, TRUE,
	                             CKA_G_CREDENTIAL, GP11_ULONG, gp11_object_get_handle (cred),
	                             CKA_CLASS, GP11_ULONG, CKO_G_COLLECTION,
	                             GP11_INVALID);

	label = gp11_attributes_find (attrs, CKA_LABEL);
	if (label != NULL)
		gp11_attributes_add (atts, label);

	g_object_unref (cred);

	pkcs11_session = gkd_secret_service_get_pkcs11_session (service, dbus_message_get_sender (message));
	g_return_val_if_fail (pkcs11_session, NULL);

	collection = gp11_session_create_object_full (pkcs11_session, atts, NULL, &error);
	gp11_attributes_unref (atts);

	if (collection == NULL) {
		g_warning ("couldn't create collection: %s", error->message);
		g_clear_error (&error);
		return dbus_message_new_error (message, DBUS_ERROR_FAILED,
		                               "Couldn't create new collection");
	}

	gp11_object_set_session (collection, pkcs11_session);
	identifier = gp11_object_get_data (collection, CKA_ID, &n_identifier, &error);
	g_object_unref (collection);

	if (!identifier) {
		g_warning ("couldn't lookup new collection identifier: %s", error->message);
		g_clear_error (&error);
		return dbus_message_new_error (message, DBUS_ERROR_FAILED,
		                               "Couldn't find new collection just created");
	}

	path = gkd_secret_util_build_path (SECRET_COLLECTION_PREFIX, identifier, n_identifier);
	g_free (identifier);

	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply,
	                          DBUS_TYPE_OBJECT_PATH, &path,
	                          DBUS_TYPE_INVALID);
	g_free (path);

	return reply;
}
