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

#ifndef __GKD_SECRETS_OBJECTS_H__
#define __GKD_SECRETS_OBJECTS_H__

#include "gkd-secrets-types.h"

#include "gp11/gp11.h"

#include <glib-object.h>

#define GKD_SECRETS_TYPE_OBJECTS               (gkd_secrets_objects_get_type ())
#define GKD_SECRETS_OBJECTS(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_SECRETS_TYPE_OBJECTS, GkdSecretsObjects))
#define GKD_SECRETS_OBJECTS_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_SECRETS_TYPE_OBJECTS, GkdSecretsObjectsClass))
#define GKD_SECRETS_IS_OBJECTS(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_SECRETS_TYPE_OBJECTS))
#define GKD_SECRETS_IS_OBJECTS_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_SECRETS_TYPE_OBJECTS))
#define GKD_SECRETS_OBJECTS_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_SECRETS_TYPE_OBJECTS, GkdSecretsObjectsClass))

typedef struct _GkdSecretsObjectsClass GkdSecretsObjectsClass;

struct _GkdSecretsObjectsClass {
	GObjectClass parent_class;
};

GType               gkd_secrets_objects_get_type                 (void);

DBusMessage*        gkd_secrets_objects_dispatch                 (GkdSecretsObjects *self,
                                                                  DBusMessage *message);

DBusMessage*        gkd_secrets_objects_handle_search_items      (GkdSecretsObjects *self,
                                                                  DBusMessage *message,
                                                                  const gchar *coll_id);

void                gkd_secrets_objects_append_collection_paths  (GkdSecretsObjects *self,
                                                                  DBusMessageIter *iter,
                                                                  DBusMessage *message);

void                gkd_secrets_objects_append_item_paths        (GkdSecretsObjects *self, 
                                                                  DBusMessageIter *iter,
                                                                  DBusMessage *message, 
                                                                  const gchar *coll_id);

GP11Slot*           gkd_secrets_objects_get_pkcs11_slot          (GkdSecretsObjects *self);

GP11Object*         gkd_secrets_objects_lookup_collection        (GkdSecretsObjects *self,
                                                                  const gchar *caller,
                                                                  const gchar *objpath);

#endif /* __GKD_SECRETS_OBJECTS_H__ */
