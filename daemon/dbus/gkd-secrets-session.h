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

#ifndef __GKD_SECRETS_SESSION_H__
#define __GKD_SECRETS_SESSION_H__

#include <glib-object.h>

#include "gkd-secrets-types.h"

#define GKD_SECRETS_TYPE_SESSION               (gkd_secrets_session_get_type ())
#define GKD_SECRETS_SESSION(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_SECRETS_TYPE_SESSION, GkdSecretsSession))
#define GKD_SECRETS_SESSION_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_SECRETS_TYPE_SESSION, GkdSecretsSessionClass))
#define GKD_SECRETS_IS_SESSION(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_SECRETS_TYPE_SESSION))
#define GKD_SECRETS_IS_SESSION_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_SECRETS_TYPE_SESSION))
#define GKD_SECRETS_SESSION_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_SECRETS_TYPE_SESSION, GkdSecretsSessionClass))

typedef struct _GkdSecretsSessionClass GkdSecretsSessionClass;

struct _GkdSecretsSessionClass {
	GObjectClass parent_class;
	DBusObjectPathVTable dbus_vtable;
};

GType               gkd_secrets_session_get_type               (void);

const gchar*        gkd_secrets_session_get_caller             (GkdSecretsSession *self);

const gchar*        gkd_secrets_session_get_caller_executable  (GkdSecretsSession *self);

const gchar*        gkd_secrets_session_get_object_path        (GkdSecretsSession *self);

#endif /* __GKD_SECRETS_SESSION_H__ */
