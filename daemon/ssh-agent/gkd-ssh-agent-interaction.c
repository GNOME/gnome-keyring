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

#include "gkd-ssh-agent-interaction.h"
#include "gkd-ssh-agent-private.h"
#include "daemon/login/gkd-login-password.h"

#include <gcr/gcr-base.h>
#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_PROMPTER_NAME
};

struct _GkdSshAgentInteraction {
	GTlsInteraction interaction;
	gchar *prompter_name;
};

G_DEFINE_TYPE (GkdSshAgentInteraction, gkd_ssh_agent_interaction, G_TYPE_TLS_INTERACTION);

static void
gkd_ssh_agent_interaction_init (GkdSshAgentInteraction *self)
{
}

static void
on_prompt_password (GObject *source_object,
		    GAsyncResult *result,
		    gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GTlsPassword *password = g_task_get_task_data (task);
	GkdLoginPassword *login_password = GKD_LOGIN_PASSWORD (password);
	GcrPrompt *prompt = GCR_PROMPT (source_object);
	GError *error = NULL;
	const gchar *value;

	value = gcr_prompt_password_finish (prompt, result, &error);
	if (!value) {
		g_object_unref (prompt);
		if (error)
			g_task_return_error (task, error);
		else
			g_task_return_new_error (task, G_IO_ERROR, G_IO_ERROR_CANCELLED, "cancelled");
		g_object_unref (task);
		return;
	}
	g_tls_password_set_value (password, (const guchar *)value, strlen (value));
	gkd_login_password_set_store_password (login_password,
					       gcr_prompt_get_choice_chosen (prompt));
	g_object_unref (prompt);

	g_task_return_int (task, G_TLS_INTERACTION_HANDLED);
	g_object_unref (task);
}

static void
on_prompt_open (GObject *source_object,
                GAsyncResult *result,
                gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GTlsPassword *password = g_task_get_task_data (task);
	GkdLoginPassword *login_password = GKD_LOGIN_PASSWORD (password);
	GError *error = NULL;
	GcrPrompt *prompt;
	const gchar *choice;
	gchar *text;

	prompt = gcr_system_prompt_open_finish (result, &error);
	if (!prompt) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	gcr_prompt_set_title (prompt, _("Unlock private key"));
	gcr_prompt_set_message (prompt, _("Enter password to unlock the private key"));

	/* TRANSLATORS: The private key is locked */
	text = g_strdup_printf (_("An application wants access to the private key “%s”, but it is locked"),
				g_tls_password_get_description (password));
	gcr_prompt_set_description (prompt, text);
	g_free (text);

	choice = NULL;
	if (gkd_login_password_get_login_available (login_password))
		choice = _("Automatically unlock this key whenever I’m logged in");
	gcr_prompt_set_choice_label (prompt, choice);
	gcr_prompt_set_continue_label (prompt, _("Unlock"));

	if (g_tls_password_get_flags (password) & G_TLS_PASSWORD_RETRY)
		gcr_prompt_set_warning (prompt, _("The unlock password was incorrect"));

	gcr_prompt_password_async (prompt, g_task_get_cancellable (task), on_prompt_password, task);
}

static void
gkd_ssh_agent_interaction_ask_password_async (GTlsInteraction *interaction,
                                        GTlsPassword *password,
                                        GCancellable *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
	GkdSshAgentInteraction *self = GKD_SSH_AGENT_INTERACTION (interaction);
	GTask *task;

	task = g_task_new (interaction, cancellable, callback, user_data);
	g_task_set_task_data (task, g_object_ref (password), g_object_unref);

	gcr_system_prompt_open_for_prompter_async (self->prompter_name, 60,
						   cancellable,
						   on_prompt_open,
						   task);
}

static GTlsInteractionResult
gkd_ssh_agent_interaction_ask_password_finish (GTlsInteraction *interaction,
                                         GAsyncResult *res,
                                         GError **error)
{
	GTask *task = G_TASK (res);
	GTlsInteractionResult result;

	result = g_task_propagate_int (task, error);
	if (result == -1)
		return G_TLS_INTERACTION_FAILED;
	return result;
}

static void
gkd_ssh_agent_interaction_set_property (GObject *object,
                                  guint prop_id,
                                  const GValue *value,
                                  GParamSpec *pspec)
{
	GkdSshAgentInteraction *self = GKD_SSH_AGENT_INTERACTION (object);

	switch (prop_id) {
	case PROP_PROMPTER_NAME:
		self->prompter_name = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gkd_ssh_agent_interaction_finalize (GObject *object)
{
	GkdSshAgentInteraction *self = GKD_SSH_AGENT_INTERACTION (object);

	g_free (self->prompter_name);

	G_OBJECT_CLASS (gkd_ssh_agent_interaction_parent_class)->finalize (object);
}

static void
gkd_ssh_agent_interaction_class_init (GkdSshAgentInteractionClass *klass)
{
	GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	interaction_class->ask_password_async = gkd_ssh_agent_interaction_ask_password_async;
	interaction_class->ask_password_finish = gkd_ssh_agent_interaction_ask_password_finish;

	gobject_class->set_property = gkd_ssh_agent_interaction_set_property;
	gobject_class->finalize = gkd_ssh_agent_interaction_finalize;

	g_object_class_install_property (gobject_class, PROP_PROMPTER_NAME,
		 g_param_spec_string ("prompter-name", "Prompter-name", "Prompter-name",
				      NULL,
				      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
}

GTlsInteraction *
gkd_ssh_agent_interaction_new (const gchar *prompter_name)
{
	return g_object_new (GKD_TYPE_SSH_AGENT_INTERACTION, "prompter-name", prompter_name, NULL);
}
