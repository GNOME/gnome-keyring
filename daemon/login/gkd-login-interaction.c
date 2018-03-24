/*
 * gnome-keyring
 *
 * Copyright (C) 2018 Red Hat, Inc.
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
 *
 * Author: Daiki Ueno
 */

#include "config.h"

#include "gkd-login-interaction.h"
#include "gkd-login-password.h"

#include <gcr/gcr-unlock-options.h>
#include "gkd-login.h"

#include "egg/egg-secure-memory.h"
#include <glib/gi18n.h>
#include <string.h>

static const gchar *XDG_SCHEMA = "xdg:schema";
static const gchar *GENERIC_SCHEMA_VALUE = "org.freedesktop.Secret.Generic";

enum {
	PROP_0,
	PROP_BASE,
	PROP_SESSION,
	PROP_LABEL,
	PROP_FIELDS
};

struct _GkdLoginInteraction
{
	GTlsInteraction interaction;

	GTlsInteraction *base;
	GckSession *session;
	gchar *label;
	GHashTable *lookup_fields;
	GHashTable *store_fields;
	gboolean login_available;
	gboolean login_checked;
};

G_DEFINE_TYPE (GkdLoginInteraction, gkd_login_interaction, G_TYPE_TLS_INTERACTION);

EGG_SECURE_DECLARE (gkd_login_interaction);

static void
gkd_login_interaction_init (GkdLoginInteraction *self)
{
}

static void
gkd_login_interaction_constructed (GObject *object)
{
	GkdLoginInteraction *self = GKD_LOGIN_INTERACTION (object);

	self->login_available = gkd_login_available (self->session);

	if (g_hash_table_contains (self->lookup_fields, (gpointer) XDG_SCHEMA))
		self->store_fields = g_hash_table_ref (self->lookup_fields);
	else {
		GHashTableIter iter;
		gpointer key, value;

		self->store_fields = g_hash_table_new (g_str_hash, g_str_equal);
		g_hash_table_iter_init (&iter, self->lookup_fields);
		while (g_hash_table_iter_next (&iter, &key, &value))
			g_hash_table_insert (self->store_fields, key, value);
		g_hash_table_insert (self->store_fields, (gpointer) XDG_SCHEMA, (gpointer) GENERIC_SCHEMA_VALUE);
	}

	G_OBJECT_CLASS (gkd_login_interaction_parent_class)->constructed (object);
}

static GkdLoginPassword *
wrap_password (GkdLoginInteraction *self,
	       GTlsPassword *password)
{
	GkdLoginPassword *wrapped;

	wrapped = g_object_new (GKD_TYPE_LOGIN_PASSWORD,
				"base", password,
				"login-available", self->login_available,
				NULL);
	g_tls_password_set_description (G_TLS_PASSWORD (wrapped), self->label);

	return wrapped;
}

static void
on_ask_password_ready (GObject *source_object,
		       GAsyncResult *res,
		       gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GkdLoginInteraction *self = g_task_get_source_object (task);
	GTlsInteractionResult result;
	GError *error = NULL;

	result = g_tls_interaction_ask_password_finish (self->base, res, &error);
	if (result == G_TLS_INTERACTION_FAILED && error != NULL)
		g_task_return_error (task, error);
	else
		g_task_return_int (task, result);
	g_object_unref (task);
}

static void
gkd_login_interaction_ask_password_async (GTlsInteraction *interaction,
                                          GTlsPassword *password,
                                          GCancellable *cancellable,
                                          GAsyncReadyCallback callback,
                                          gpointer user_data)
{
	GkdLoginInteraction *self = GKD_LOGIN_INTERACTION (interaction);
	GkdLoginPassword *login_password;
	GTask *task;

	login_password = wrap_password (self, password);
	task = g_task_new (interaction, cancellable, callback, user_data);
	g_task_set_task_data (task, g_object_ref (login_password), g_object_unref);

	/* If the login keyring is available, look for the password there */
	if (self->login_available) {
		if (self->login_checked)
			g_message ("already attempted to use password from login keyring");
		else {
			gchar *value = gkd_login_lookup_passwordv (self->session, self->lookup_fields);
			self->login_checked = TRUE;
			if (value) {
				g_tls_password_set_value_full (G_TLS_PASSWORD (login_password), (guchar *)value, strlen (value), (GDestroyNotify)egg_secure_free);
				g_object_unref (login_password);
				g_task_return_int (task, G_TLS_INTERACTION_HANDLED);
				g_object_unref (task);
				return;
			}
		}
	}

	/* Otherwise, call out to the base interaction */
	g_tls_interaction_ask_password_async (self->base,
					      G_TLS_PASSWORD (login_password),
					      cancellable,
					      on_ask_password_ready,
					      task);
	g_object_unref (login_password);
}

static GTlsInteractionResult
gkd_login_interaction_ask_password_finish (GTlsInteraction *interaction,
					   GAsyncResult *res,
					   GError **error)
{
	GkdLoginInteraction *self = GKD_LOGIN_INTERACTION (interaction);
	GTask *task = G_TASK (res);
	GkdLoginPassword *login_password = g_task_get_task_data (task);
	GTlsInteractionResult result;

	result = g_task_propagate_int (task, error);
	if (result == -1)
		result = G_TLS_INTERACTION_FAILED;

	if (self->login_available &&
	    result == G_TLS_INTERACTION_HANDLED &&
	    gkd_login_password_get_store_password (login_password)) {
		const guchar *value;
		gsize length;
		gchar *password;
		gchar *label;

		value = g_tls_password_get_value (G_TLS_PASSWORD (login_password),
						  &length);

		password = egg_secure_strndup ((const gchar *)value, length);
		label = g_strdup_printf (_("Unlock password for: %s"), self->label);
		gkd_login_store_passwordv (self->session,
					   password,
					   label,
					   GCR_UNLOCK_OPTION_ALWAYS, -1,
					   self->store_fields);
		egg_secure_free (password);
		g_free (label);
	}

	return result;
}

static void
gkd_login_interaction_set_property (GObject *object,
                                    guint prop_id,
                                    const GValue *value,
                                    GParamSpec *pspec)
{
	GkdLoginInteraction *self = GKD_LOGIN_INTERACTION (object);

	switch (prop_id)
	{
	case PROP_BASE:
		self->base = g_value_dup_object (value);
		break;
	case PROP_SESSION:
		self->session = g_value_dup_object (value);
		break;
	case PROP_LABEL:
		self->label = g_value_dup_string (value);
		break;
	case PROP_FIELDS:
		self->lookup_fields = g_value_dup_boxed (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gkd_login_interaction_dispose (GObject *object)
{
	GkdLoginInteraction *self = GKD_LOGIN_INTERACTION (object);

	g_clear_object (&self->base);
	g_clear_object (&self->session);

	G_OBJECT_CLASS (gkd_login_interaction_parent_class)->dispose (object);
}

static void
gkd_login_interaction_finalize (GObject *object)
{
	GkdLoginInteraction *self = GKD_LOGIN_INTERACTION (object);

	g_free (self->label);
	g_hash_table_unref (self->lookup_fields);
	g_hash_table_unref (self->store_fields);

	G_OBJECT_CLASS (gkd_login_interaction_parent_class)->finalize (object);
}

static void
gkd_login_interaction_class_init (GkdLoginInteractionClass *klass)
{
	GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	interaction_class->ask_password_async = gkd_login_interaction_ask_password_async;
	interaction_class->ask_password_finish = gkd_login_interaction_ask_password_finish;

	gobject_class->constructed = gkd_login_interaction_constructed;
	gobject_class->set_property = gkd_login_interaction_set_property;
	gobject_class->dispose = gkd_login_interaction_dispose;
	gobject_class->finalize = gkd_login_interaction_finalize;

	g_object_class_install_property (gobject_class, PROP_BASE,
					 g_param_spec_object ("base", "Base", "Base",
							      G_TYPE_TLS_INTERACTION,
							      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
	g_object_class_install_property (gobject_class, PROP_SESSION,
					 g_param_spec_object ("session", "Session", "Session",
							      GCK_TYPE_SESSION,
							      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
	g_object_class_install_property (gobject_class, PROP_LABEL,
					 g_param_spec_string ("label", "Label", "Label",
							      "",
							      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
	g_object_class_install_property (gobject_class, PROP_FIELDS,
					 g_param_spec_boxed ("fields", "Fields", "Fields",
							     G_TYPE_HASH_TABLE,
							     G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
}

GTlsInteraction *
gkd_login_interaction_new (GTlsInteraction  *base,
			   GckSession *session,
			   const gchar *label,
			   GHashTable *fields)
{
	return g_object_new (GKD_TYPE_LOGIN_INTERACTION,
			     "base", base,
			     "session", session,
			     "label", label,
			     "fields", fields,
			     NULL);
}
