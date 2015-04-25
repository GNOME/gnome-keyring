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

#include "gkd-secret-dispatch.h"
#include "gkd-secret-error.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"

#include "egg/egg-secure-memory.h"

#include <glib-object.h>

#include <string.h>

GkdSecretSecret *
gkd_secret_secret_new (GkdSecretSession *session,
		       gconstpointer parameter,
		       gsize n_parameter,
		       gconstpointer value,
		       gsize n_value)
{
	return gkd_secret_secret_new_take_memory (session,
						  g_memdup (parameter, n_parameter),
						  n_parameter,
						  g_memdup (value, n_value),
						  n_value);
}

static void
destroy_with_owned_memory (gpointer data)
{
	GkdSecretSecret *secret = data;
	g_free (secret->parameter);
	g_free (secret->value);
}

GkdSecretSecret*
gkd_secret_secret_new_take_memory (GkdSecretSession *session,
				   gpointer parameter, gsize n_parameter,
				   gpointer value, gsize n_value)
{
	GkdSecretSecret *secret;

	g_return_val_if_fail (GKD_SECRET_IS_SESSION (session), NULL);

	secret = g_slice_new0 (GkdSecretSecret);
	secret->session = g_object_ref (session);
	secret->parameter = parameter;
	secret->n_parameter = n_parameter;
	secret->value = value;
	secret->n_value = n_value;

	secret->destroy_func = destroy_with_owned_memory;
	secret->destroy_data = secret;

	return secret;
}

GkdSecretSecret*
gkd_secret_secret_parse (GkdSecretService *service,
			 const char *sender,
			 GVariant *variant,
			 GError **error)
{
	GkdSecretSecret *secret = NULL;
	GkdSecretSession *session;
	const char *parameter, *value, *path, *content_type;
	gsize n_parameter, n_value;
	GVariant *parameter_variant, *value_variant;

	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (variant, NULL);
	g_return_val_if_fail (sender, NULL);

	g_variant_get (variant, "(&o^&ay^&ay&s)", &path, NULL, NULL, &content_type);

	/* parameter */
	parameter_variant = g_variant_get_child_value (variant, 1);
	parameter = g_variant_get_fixed_array (parameter_variant, &n_parameter, sizeof (guint8));

	/* value */
	value_variant = g_variant_get_child_value (variant, 2);
	value = g_variant_get_fixed_array (value_variant, &n_value, sizeof (guint8));

	/* Try to lookup the session */
	session = gkd_secret_service_lookup_session (service, path, sender);
	if (session == NULL) {
		g_set_error_literal (error, GKD_SECRET_ERROR,
				     GKD_SECRET_ERROR_NO_SESSION,
				     "The session wrapping the secret does not exist");
		goto out;
	}

	secret = g_slice_new0 (GkdSecretSecret);
	secret->session = g_object_ref (session);
	secret->parameter = g_strndup (parameter, n_parameter);
	secret->n_parameter = n_parameter;
	secret->value = g_strndup (value, n_value);
	secret->n_value = n_value;

 out:
	g_variant_unref (parameter_variant);
	g_variant_unref (value_variant);

	return secret;
}

GVariant *
gkd_secret_secret_append (GkdSecretSecret *secret)
{
	GVariantBuilder builder;
	const gchar *content_type = "text/plain";
	const gchar *path;
	GVariant *parameter, *value;

	path = gkd_secret_dispatch_get_object_path (GKD_SECRET_DISPATCH (secret->session));
	g_return_val_if_fail (path, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
	g_variant_builder_add (&builder, "y", secret->parameter);
	parameter = g_variant_builder_end (&builder);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
	g_variant_builder_add (&builder, "y", secret->value);
	value = g_variant_builder_end (&builder);

	return g_variant_new ("(o@ay@ays)", path, parameter, value, content_type);
}

void
gkd_secret_secret_free (gpointer data)
{
	GkdSecretSecret *secret;

	if (!data)
		return;

	secret = data;

	/*
	 * These are not usually actual plain text secrets. However in
	 * the case that they are, we want to clear them from memory.
	 *
	 * This is not foolproof in any way. If they're plaintext, they would
	 * have been sent over DBus, and through all sorts of processes.
	 */

	egg_secure_clear (secret->parameter, secret->n_parameter);
	egg_secure_clear (secret->value, secret->n_value);

	g_object_unref (secret->session);

	/* Call the destructor of memory */
	if (secret->destroy_func)
		(secret->destroy_func) (secret->destroy_data);

	g_slice_free (GkdSecretSecret, secret);
}
