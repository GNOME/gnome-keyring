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

#ifndef __GCK_SECRET_ITEM_H__
#define __GCK_SECRET_ITEM_H__

#include <glib-object.h>

#include "gck-secret-object.h"
#include "gck-secret-collection.h"

#define GCK_TYPE_SECRET_ITEM               (gck_secret_item_get_type ())
#define GCK_SECRET_ITEM(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SECRET_ITEM, GckSecretItem))
#define GCK_SECRET_ITEM_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_SECRET_ITEM, GckSecretItemClass))
#define GCK_IS_SECRET_ITEM(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SECRET_ITEM))
#define GCK_IS_SECRET_ITEM_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_SECRET_ITEM))
#define GCK_SECRET_ITEM_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_SECRET_ITEM, GckSecretItemClass))

typedef struct _GckSecretItemClass GckSecretItemClass;

struct _GckSecretItemClass {
	GckSecretObjectClass parent_class;
};

GType                  gck_secret_item_get_type               (void);

GckSecretCollection*   gck_secret_item_get_collection         (GckSecretItem *self);

GHashTable*            gck_secret_item_get_fields             (GckSecretItem *self);

void                   gck_secret_item_set_fields             (GckSecretItem *self,
                                                               GHashTable *fields);

#endif /* __GCK_SECRET_ITEM_H__ */
