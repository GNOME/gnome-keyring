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

#ifndef __GKD_SECRETS_UNLOCK_H__
#define __GKD_SECRETS_UNLOCK_H__

#include <glib-object.h>

#include "gkd-secrets-types.h"

#define GKD_SECRETS_TYPE_UNLOCK               (gkd_secrets_unlock_get_type ())
#define GKD_SECRETS_UNLOCK(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_SECRETS_TYPE_UNLOCK, GkdSecretsUnlock))
#define GKD_SECRETS_UNLOCK_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_SECRETS_TYPE_UNLOCK, GkdSecretsUnlockClass))
#define GKD_SECRETS_IS_UNLOCK(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_SECRETS_TYPE_UNLOCK))
#define GKD_SECRETS_IS_UNLOCK_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_SECRETS_TYPE_UNLOCK))
#define GKD_SECRETS_UNLOCK_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_SECRETS_TYPE_UNLOCK, GkdSecretsUnlockClass))

typedef struct _GkdSecretsUnlockClass GkdSecretsUnlockClass;

struct _GkdSecretsUnlockClass {
	GObjectClass parent_class;
};

GType               gkd_secrets_unlock_get_type               (void);

GkdSecretsUnlock*   gkd_secrets_unlock_new                    (GkdSecretsService *service,
                                                               const gchar *caller);

void                gkd_secrets_unlock_queue                  (GkdSecretsUnlock *self,
                                                               const gchar *objpath);

gboolean            gkd_secrets_unlock_have_queued            (GkdSecretsUnlock *self);

gchar**             gkd_secrets_unlock_get_results            (GkdSecretsUnlock *self);

void                gkd_secrets_unlock_reset_results          (GkdSecretsUnlock *self);

#endif /* __GKD_SECRETS_UNLOCK_H__ */
