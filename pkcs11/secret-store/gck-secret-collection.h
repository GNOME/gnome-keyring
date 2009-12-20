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

#ifndef __GCK_SECRET_COLLECTION_H__
#define __GCK_SECRET_COLLECTION_H__

#include <glib-object.h>

#include "gck-secret-object.h"

#define GCK_FACTORY_SECRET_COLLECTION            (gck_secret_collection_get_factory ())

#define GCK_TYPE_SECRET_COLLECTION               (gck_secret_collection_get_type ())
#define GCK_SECRET_COLLECTION(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SECRET_COLLECTION, GckSecretCollection))
#define GCK_SECRET_COLLECTION_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_SECRET_COLLECTION, GckSecretCollectionClass))
#define GCK_IS_SECRET_COLLECTION(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SECRET_COLLECTION))
#define GCK_IS_SECRET_COLLECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_SECRET_COLLECTION))
#define GCK_SECRET_COLLECTION_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_SECRET_COLLECTION, GckSecretCollectionClass))

typedef struct _GckSecretCollectionClass GckSecretCollectionClass;

struct _GckSecretCollectionClass {
	GckSecretObjectClass parent_class;
	GHashTable *identifiers;
};

GType                gck_secret_collection_get_type        (void);

GckFactory*          gck_secret_collection_get_factory     (void) G_GNUC_CONST;

GckSecretCollection* gck_secret_collection_find            (CK_ATTRIBUTE_PTR attr,
                                                            ...) G_GNUC_NULL_TERMINATED;

GckDataResult        gck_secret_collection_load            (GckSecretCollection *self);

void                 gck_secret_collection_save            (GckSecretCollection *self,
                                                            GckTransaction *transaction);

void                 gck_secret_collection_destroy         (GckSecretCollection *self,
                                                            GckTransaction *transaction);

const gchar*         gck_secret_collection_get_filename    (GckSecretCollection *self);

void                 gck_secret_collection_set_filename    (GckSecretCollection *self,
                                                            const gchar *filename);

GList*               gck_secret_collection_get_items       (GckSecretCollection *self);

GckSecretItem*       gck_secret_collection_get_item        (GckSecretCollection *self,
                                                            const gchar *identifier);

gboolean             gck_secret_collection_has_item        (GckSecretCollection *self,
                                                            GckSecretItem *item);

GckSecretItem*       gck_secret_collection_new_item        (GckSecretCollection *self,
                                                            const gchar *identifier);

void                 gck_secret_collection_remove_item     (GckSecretCollection *self,
                                                            GckSecretItem *item);

GckSecretItem*       gck_secret_collection_create_item     (GckSecretCollection *self,
                                                            GckTransaction *transaction);

void                 gck_secret_collection_destroy_item    (GckSecretCollection *self,
                                                            GckTransaction *transaction,
                                                            GckSecretItem *item);

void                 gck_secret_collection_unlocked_clear  (GckSecretCollection *self);

GckSecretData*       gck_secret_collection_unlocked_use    (GckSecretCollection *self,
                                                            GckSession *session);

gboolean             gck_secret_collection_unlocked_have   (GckSecretCollection *self,
                                                            GckSession *session);

gint                 gck_secret_collection_get_lock_idle   (GckSecretCollection *self);

void                 gck_secret_collection_set_lock_idle   (GckSecretCollection *self,
                                                            gint lock_timeout);

#endif /* __GCK_SECRET_COLLECTION_H__ */
