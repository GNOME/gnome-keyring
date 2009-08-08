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

#define GCK_TYPE_SECRET_COLLECTION               (gck_secret_collection_get_type ())
#define GCK_SECRET_COLLECTION(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SECRET_COLLECTION, GckSecretCollection))
#define GCK_SECRET_COLLECTION_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_SECRET_COLLECTION, GckSecretCollectionClass))
#define GCK_IS_SECRET_COLLECTION(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SECRET_COLLECTION))
#define GCK_IS_SECRET_COLLECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_SECRET_COLLECTION))
#define GCK_SECRET_COLLECTION_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_SECRET_COLLECTION, GckSecretCollectionClass))

typedef struct _GckSecretCollectionClass GckSecretCollectionClass;

struct _GckSecretCollectionClass {
	GckSecretObjectClass parent_class;
};

typedef enum _GckSecretState {
	GCK_SECRET_EMPTY = 0,
	GCK_SECRET_PARTIAL = 1,
	GCK_SECRET_COMPLETE = 2
} GckSecretState;

GType                gck_secret_collection_get_type        (void);

GckSecretState       gck_secret_collection_get_state       (GckSecretCollection *self);

GList*               gck_secret_collection_get_items       (GckSecretCollection *self);

GckSecretItem*       gck_secret_collection_get_item        (GckSecretCollection *self,
                                                            const gchar *identifier);

GckSecretItem*       gck_secret_collection_create_item     (GckSecretCollection *self,
                                                            const gchar *identifier);

void                 gck_secret_collection_remove_item     (GckSecretCollection *self,
                                                            GckSecretItem *item);

GckSecretData*       gck_secret_collection_get_data        (GckSecretCollection *self);

void                 gck_secret_collection_set_data        (GckSecretCollection *self,
                                                            GckSecretData *data);

const gchar*         gck_secret_collection_get_master_password (GckSecretCollection *self);

#endif /* __GCK_SECRET_COLLECTION_H__ */
