/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-ssh-interaction.c

   Copyright (C) 2014 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   see <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stefw@gnome.org>
*/

#include "config.h"

#include "gkd-ssh-interaction.h"

#include "daemon/login/gkd-login.h"

#include <gcr/gcr-base.h>

#include <glib/gi18n-lib.h>

#define GKD_SSH_INTERACTION_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_SSH_TYPE_INTERACTION, GkdSshInteraction))
#define GKD_SSH_IS_INTERACTION_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_SSH_TYPE_INTERACTION))
#define GKD_SSH_INTERACTION_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_SSH_TYPE_INTERACTION, GkdSshInteractionClass))

typedef struct _GkdSshInteractionClass GkdSshInteractionClass;

struct _GkdSshInteraction {
	GTlsInteraction interaction;
	GBytes *key;
	gchar *label;
};

struct _GkdSshInteractionClass {
	GTlsInteractionClass parent;
};

G_DEFINE_TYPE (GkdSshInteraction, gkd_ssh_interaction, G_TYPE_TLS_INTERACTION);

static void
gkd_ssh_interaction_init (GkdSshInteraction *self)
{
	self->label = g_strdup ("XXXXX");
}

static void
gkd_ssh_interaction_finalize (GObject *obj)
{
	GkdSshInteraction *self = GKD_SSH_INTERACTION (obj);

	g_free (self->label);

	G_OBJECT_CLASS (gkd_ssh_interaction_parent_class)->finalize (obj);
}

static void
on_prompt_open (GObject *source_object,
                GAsyncResult *result,
                gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GTlsPassword *password = g_task_get_task_data (task);
	GkdSshInteraction *self = GKD_SSH_INTERACTION (g_task_get_source_object (task));
	GError *error = NULL;
	GcrPrompt *prompt;
	const gchar *choice;
	gchar *text;

	prompt = gcr_system_prompt_open_finish (result, &error);
	if (error != NULL) {
		g_task_return_error (task, error);

	} else {
		gcr_prompt_set_title (prompt, _("Unlock private key"));
		gcr_prompt_set_message (prompt, _("Enter password to unlock the private key"));

		/* TRANSLATORS: The private key is locked */
		text = g_strdup_printf (_("An application wants access to the private key '%s', but it is locked"),
		                        self->label);
		gcr_prompt_set_description (prompt, text);
		g_free (text);

		choice = NULL;
		if (gkd_login_available (NULL))
			choice = _("Automatically unlock this key whenever I'm logged in");
		gcr_prompt_set_choice_label (prompt, choice);
		gcr_prompt_set_continue_label (prompt, _("Unlock"));
	}

	if (g_tls_password_get_flags (password) & G_TLS_PASSWORD_RETRY)
		gcr_prompt_set_warning (prompt, _("The unlock password was incorrect"));

	g_object_unref (task);
}

static void
gkd_ssh_interaction_ask_password_async (GTlsInteraction *interaction,
                                        GTlsPassword *password,
                                        GCancellable *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
	GTask *task;

	task = g_task_new (interaction, cancellable, callback, user_data);
	g_task_set_task_data (task, g_object_ref (password), g_object_unref);

#if 0
	{'unique': 'ssh-store:/data/.ssh/id_rsa', 'xdg:schema': 'org.freedesktop.Secret.Generic'}
	if (gkd_login_available() && self->keyid) {
		xxxx = gkd_login_lookup (self->keyid);
		g_tls_password_set_value (password, xxxx);

	}
#endif


	gcr_system_prompt_open_async (60, cancellable, on_prompt_open,
	                              g_object_ref (task));

	g_object_unref (task);
}

static GTlsInteractionResult
gkd_ssh_interaction_ask_password_finish (GTlsInteraction *interaction,
                                         GAsyncResult *result,
                                         GError **error)
{
	GTask *task = G_TASK (result);
	if (!g_task_propagate_boolean (task, error))
		return G_TLS_INTERACTION_FAILED;
	return G_TLS_INTERACTION_HANDLED;
}

static void
gkd_ssh_interaction_class_init (GkdSshInteractionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);

	object_class->finalize = gkd_ssh_interaction_finalize;

	interaction_class->ask_password_async = gkd_ssh_interaction_ask_password_async;
	interaction_class->ask_password_finish = gkd_ssh_interaction_ask_password_finish;
}

GTlsInteraction *
gkd_ssh_interaction_new (GBytes *key)
{
	GkdSshInteraction *result;

	result = g_object_new (GKD_TYPE_SSH_INTERACTION, NULL);

	return G_TLS_INTERACTION (result);
}
