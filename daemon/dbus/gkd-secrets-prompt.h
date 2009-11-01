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

#ifndef __GKD_SECRETS_PROMPT_H__
#define __GKD_SECRETS_PROMPT_H__

#include <glib-object.h>

#include "gkd-secrets-types.h"

#include "prompt/gkd-prompt.h"

#define GKD_SECRETS_TYPE_PROMPT               (gkd_secrets_prompt_get_type ())
#define GKD_SECRETS_PROMPT(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_SECRETS_TYPE_PROMPT, GkdSecretsPrompt))
#define GKD_SECRETS_PROMPT_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_SECRETS_TYPE_PROMPT, GkdSecretsPromptClass))
#define GKD_SECRETS_IS_PROMPT(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_SECRETS_TYPE_PROMPT))
#define GKD_SECRETS_IS_PROMPT_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_SECRETS_TYPE_PROMPT))
#define GKD_SECRETS_PROMPT_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_SECRETS_TYPE_PROMPT, GkdSecretsPromptClass))

typedef struct _GkdSecretsPromptClass GkdSecretsPromptClass;
typedef struct _GkdSecretsPromptPrivate GkdSecretsPromptPrivate;

struct _GkdSecretsPrompt {
	GkdPrompt parent;
	GkdSecretsPromptPrivate *pv;
};

struct _GkdSecretsPromptClass {
	GObjectClass parent_class;

	/* virtual methods */
	void (*prompt_ready) (GkdSecretsPrompt *self);
	void (*encode_result) (GkdSecretsPrompt *self, DBusMessageIter *iter);
};

GType               gkd_secrets_prompt_get_type               (void);

DBusMessage*        gkd_secrets_prompt_dispatch               (GkdSecretsPrompt *self,
                                                               DBusMessage *message);

const gchar*        gkd_secrets_prompt_get_caller             (GkdSecretsPrompt *self);

const gchar*        gkd_secrets_prompt_get_object_path        (GkdSecretsPrompt *self);

GP11Object*         gkd_secrets_prompt_lookup_collection      (GkdSecretsPrompt *self,
                                                               const gchar *objpath);

void                gkd_secrets_prompt_complete               (GkdSecretsPrompt *self);

void                gkd_secrets_prompt_dismiss                (GkdSecretsPrompt *self);

#endif /* __GKD_SECRETS_PROMPT_H__ */
