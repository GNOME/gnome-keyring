/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef __GCK_CREDENTIAL_H__
#define __GCK_CREDENTIAL_H__

#include <glib-object.h>

#include "gck-object.h"
#include "gck-types.h"

#define GCK_FACTORY_CREDENTIAL            (gck_credential_get_factory ())

#define GCK_TYPE_CREDENTIAL               (gck_credential_get_type ())
#define GCK_CREDENTIAL(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_CREDENTIAL, GckCredential))
#define GCK_CREDENTIAL_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_CREDENTIAL, GckCredentialClass))
#define GCK_IS_CREDENTIAL(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_CREDENTIAL))
#define GCK_IS_CREDENTIAL_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_CREDENTIAL))
#define GCK_CREDENTIAL_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_CREDENTIAL, GckCredentialClass))

typedef struct _GckCredentialClass GckCredentialClass;
typedef struct _GckCredentialPrivate GckCredentialPrivate;

struct _GckCredential {
	GckObject parent;
	GckCredentialPrivate *pv;
};

struct _GckCredentialClass {
	GckObjectClass parent_class;
};

GType                      gck_credential_get_type               (void);

GckFactory*                gck_credential_get_factory            (void);

CK_RV                      gck_credential_create                 (GckObject *object,
                                                                  GckManager *manager,
                                                                  CK_UTF8CHAR_PTR pin,
                                                                  CK_ULONG n_pin,
                                                                  GckCredential **result);

GckSecret*                 gck_credential_get_secret             (GckCredential *self);

void                       gck_credential_set_secret             (GckCredential *self,
                                                                  GckSecret *login);

const gchar*               gck_credential_get_password           (GckCredential *self,
                                                                  gsize *n_password);

GckObject*                 gck_credential_get_object             (GckCredential *self);

gint                       gck_credential_get_uses_remaining     (GckCredential *self);

void                       gck_credential_set_uses_remaining     (GckCredential *self,
                                                                  gint use_count);

void                       gck_credential_throw_away_one_use     (GckCredential *self);

#endif /* __GCK_CREDENTIAL_H__ */
