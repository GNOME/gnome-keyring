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

#ifndef __GKD_SECRET_OBJECTS_H__
#define __GKD_SECRET_OBJECTS_H__

#include "gkd-secret-types.h"

#include <gck/gck.h>

#include <glib-object.h>

#define GKD_SECRET_TYPE_OBJECTS               (gkd_secret_objects_get_type ())
#define GKD_SECRET_OBJECTS(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_SECRET_TYPE_OBJECTS, GkdSecretObjects))
#define GKD_SECRET_OBJECTS_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_SECRET_TYPE_OBJECTS, GkdSecretObjectsClass))
#define GKD_SECRET_IS_OBJECTS(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_SECRET_TYPE_OBJECTS))
#define GKD_SECRET_IS_OBJECTS_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_SECRET_TYPE_OBJECTS))
#define GKD_SECRET_OBJECTS_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_SECRET_TYPE_OBJECTS, GkdSecretObjectsClass))

typedef struct _GkdSecretObjectsClass GkdSecretObjectsClass;

struct _GkdSecretObjectsClass {
	GObjectClass parent_class;
};

typedef void        (*GkdSecretObjectsForeach)                  (GkdSecretObjects *self,
                                                                 const gchar *path,
                                                                 GckObject *object,
                                                                 gpointer user_data);

GType               gkd_secret_objects_get_type                 (void);

gboolean            gkd_secret_objects_handle_search_items       (GkdSecretObjects *self,
                                                                  GDBusMethodInvocation *invocation,
                                                                  GVariant *attributes,
                                                                  const gchar *base,
                                                                  gboolean separate_locked);

gboolean            gkd_secret_objects_handle_get_secrets        (GkdSecretObjects *self,
                                                                  GDBusMethodInvocation *invocation,
                                                                  const gchar **paths,
                                                                  const gchar *session_path);

void                gkd_secret_objects_foreach_collection        (GkdSecretObjects *self,
                                                                  const gchar *caller,
                                                                  GkdSecretObjectsForeach callback,
                                                                  gpointer user_data);

void                gkd_secret_objects_foreach_item              (GkdSecretObjects *self,
                                                                  const gchar *caller,
                                                                  const gchar *base,
                                                                  GkdSecretObjectsForeach callback,
                                                                  gpointer user_data);

GVariant*           gkd_secret_objects_append_collection_paths   (GkdSecretObjects *self,
                                                                  const gchar *caller);

GckSlot*            gkd_secret_objects_get_pkcs11_slot           (GkdSecretObjects *self);

GckObject*          gkd_secret_objects_lookup_collection         (GkdSecretObjects *self,
                                                                  const gchar *caller,
                                                                  const gchar *path);

GckObject*          gkd_secret_objects_lookup_item               (GkdSecretObjects *self,
                                                                  const gchar *caller,
                                                                  const gchar *path);

void                gkd_secret_objects_emit_collection_locked    (GkdSecretObjects *self,
                                                                  GckObject *collection);

void                gkd_secret_objects_emit_item_created         (GkdSecretObjects *self,
                                                                  GckObject *collection,
                                                                  const gchar *item_path);

void                gkd_secret_objects_emit_item_changed         (GkdSecretObjects *self,
                                                                  GckObject *item);

void                gkd_secret_objects_emit_item_deleted         (GkdSecretObjects *self,
                                                                  GckObject *collection,
                                                                  const gchar *item_path);

void                gkd_secret_objects_register_collection       (GkdSecretObjects *self,
                                                                  const gchar *collection_path);

void                gkd_secret_objects_unregister_collection     (GkdSecretObjects *self,
                                                                  const gchar *collection_path);

#endif /* __GKD_SECRET_OBJECTS_H__ */
