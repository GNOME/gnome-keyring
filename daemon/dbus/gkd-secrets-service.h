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

#ifndef __GKD_SECRETS_SERVICE_H__
#define __GKD_SECRETS_SERVICE_H__

#include "gkd-secrets-types.h"

#include "gp11/gp11.h"

#include <dbus/dbus.h>

#include <glib-object.h>

#define GKD_SECRETS_TYPE_SERVICE               (gkd_secrets_service_get_type ())
#define GKD_SECRETS_SERVICE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_SECRETS_TYPE_SERVICE, GkdSecretsService))
#define GKD_SECRETS_SERVICE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_SECRETS_TYPE_SERVICE, GkdSecretsServiceClass))
#define GKD_SECRETS_IS_SERVICE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_SECRETS_TYPE_SERVICE))
#define GKD_SECRETS_IS_SERVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_SECRETS_TYPE_SERVICE))
#define GKD_SECRETS_SERVICE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_SECRETS_TYPE_SERVICE, GkdSecretsServiceClass))

typedef struct _GkdSecretsServiceClass GkdSecretsServiceClass;

struct _GkdSecretsServiceClass {
	GObjectClass parent_class;
#if 0
	/* signals --------------------------------------------------------- */

	void (*signal) (GkdSecretsService *self);
#endif
};

GType                   gkd_secrets_service_get_type               (void);

DBusConnection*         gkd_secrets_service_get_connection         (GkdSecretsService *self);

GP11Slot*               gkd_secrets_service_get_pkcs11_slot        (GkdSecretsService *self);

GP11Session*            gkd_secrets_service_get_pkcs11_session     (GkdSecretsService *self,
                                                                    const gchar *caller);

GkdSecretsObjects*      gkd_secrets_service_get_objects            (GkdSecretsService *self);

#if 0
void                    gkd_secrets_service_refresh                (GkdSecretsService *self);
#endif

void                    gkd_secrets_service_close_session          (GkdSecretsService *self,
                                                                    GkdSecretsSession *sess);

void                    gkd_secrets_service_send                   (GkdSecretsService *self,
                                                                    DBusMessage *message);

#if 0
GkdSecretsCollection*   gkd_secrets_service_get_default_collection (GkdSecretsService *self);
#endif

#endif /* ___SECRETS_SERVICE_H__ */
