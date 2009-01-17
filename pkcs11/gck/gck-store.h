/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
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

#ifndef __GCK_STORE_H__
#define __GCK_STORE_H__

#include <glib-object.h>

#include "gck-types.h"

#include "pkcs11/pkcs11.h"

enum {
	GCK_STORE_IS_INTERNAL = 0x01,
	GCK_STORE_IS_SENSITIVE = 0x02
};

#define GCK_TYPE_STORE               (gck_store_get_type ())
#define GCK_STORE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_STORE, GckStore))
#define GCK_STORE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_STORE, GckStoreClass))
#define GCK_IS_STORE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_STORE))
#define GCK_IS_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_STORE))
#define GCK_STORE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_STORE, GckStoreClass))

typedef struct _GckStoreClass GckStoreClass;
typedef struct _GckStorePrivate GckStorePrivate;

struct _GckStore {
	GObject parent;
	GckStorePrivate *pv;
};

struct _GckStoreClass {
	GObjectClass parent_class;
	
	/* Virtual methods */
    
	CK_RV (*read_value) (GckStore *self, GckObject *object, CK_ATTRIBUTE_PTR attr);
	
	void (*write_value) (GckStore *self, GckTransaction *transaction, GckObject *object, CK_ATTRIBUTE_PTR attr); 
};

typedef CK_RV         (*GckStoreValidator)                (GckObject *object,
                                                           CK_ATTRIBUTE_PTR attr);

GType                 gck_store_get_type                  (void);

gboolean              gck_store_lookup_schema             (GckStore *self,
                                                           CK_ATTRIBUTE_TYPE type,
                                                           guint *flags);

void                  gck_store_register_schema           (GckStore *self,
                                                           CK_ATTRIBUTE_PTR type_and_default,
                                                           GckStoreValidator validator,
                                                           guint flags);

void                  gck_store_set_attribute             (GckStore *self,
                                                           GckTransaction *transaction,
                                                           GckObject *object,
                                                           CK_ATTRIBUTE_PTR attr);

void                  gck_store_write_value               (GckStore *self,
                                                           GckTransaction *transaction,
                                                           GckObject *object,
                                                           CK_ATTRIBUTE_PTR attr);

CK_RV                 gck_store_get_attribute             (GckStore *self,
                                                           GckObject *object,
                                                           CK_ATTRIBUTE_PTR attr);

gconstpointer         gck_store_read_value                (GckStore *self,
                                                           GckObject *object,
                                                           CK_ATTRIBUTE_TYPE type,
                                                           gsize *n_value);

gchar*                gck_store_read_string               (GckStore *self,
                                                           GckObject *object,
                                                           CK_ATTRIBUTE_TYPE type);

void                  gck_store_notify_attribute          (GckStore *self,
                                                           GckObject *object,
                                                           CK_ATTRIBUTE_TYPE type);

#endif /* __GCK_STORE_H__ */
