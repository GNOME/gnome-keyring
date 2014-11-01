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

#ifndef __GKD_SECRET_PROMPT_H__
#define __GKD_SECRET_PROMPT_H__

#include <glib-object.h>

#include "gkd-secret-types.h"

#include <gck/gck.h>
#include <gcr/gcr-base.h>

#define GKD_SECRET_TYPE_PROMPT               (gkd_secret_prompt_get_type ())
#define GKD_SECRET_PROMPT(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_SECRET_TYPE_PROMPT, GkdSecretPrompt))
#define GKD_SECRET_PROMPT_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_SECRET_TYPE_PROMPT, GkdSecretPromptClass))
#define GKD_SECRET_IS_PROMPT(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_SECRET_TYPE_PROMPT))
#define GKD_SECRET_IS_PROMPT_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_SECRET_TYPE_PROMPT))
#define GKD_SECRET_PROMPT_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_SECRET_TYPE_PROMPT, GkdSecretPromptClass))

typedef struct _GkdSecretPromptClass GkdSecretPromptClass;
typedef struct _GkdSecretPromptPrivate GkdSecretPromptPrivate;

struct _GkdSecretPrompt {
	GcrSystemPrompt parent;
	GkdSecretPromptPrivate *pv;
};

struct _GkdSecretPromptClass {
	GcrSystemPromptClass parent_class;

	void       (*prompt_ready)       (GkdSecretPrompt *self);

	GVariant * (*encode_result)      (GkdSecretPrompt *self);
};

GType               gkd_secret_prompt_get_type                (void) G_GNUC_CONST;

const gchar*        gkd_secret_prompt_get_caller              (GkdSecretPrompt *self);

const gchar*        gkd_secret_prompt_get_window_id           (GkdSecretPrompt *self);

GckSession*         gkd_secret_prompt_get_pkcs11_session      (GkdSecretPrompt *self);

GkdSecretService*   gkd_secret_prompt_get_service             (GkdSecretPrompt *self);

GkdSecretObjects*   gkd_secret_prompt_get_objects             (GkdSecretPrompt *self);

GCancellable *      gkd_secret_prompt_get_cancellable         (GkdSecretPrompt *self);

GkdSecretSecret *   gkd_secret_prompt_take_secret             (GkdSecretPrompt *self);

GckObject*          gkd_secret_prompt_lookup_collection       (GkdSecretPrompt *self,
                                                               const gchar *path);

void                gkd_secret_prompt_complete                (GkdSecretPrompt *self);

void                gkd_secret_prompt_dismiss                 (GkdSecretPrompt *self);

void                gkd_secret_prompt_dismiss_with_error      (GkdSecretPrompt *self,
                                                               GError *error);

#endif /* __GKD_SECRET_PROMPT_H__ */
