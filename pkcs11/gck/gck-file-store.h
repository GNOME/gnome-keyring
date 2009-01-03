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

#ifndef __GCK_FILE_STORE_H__
#define __GCK_FILE_STORE_H__

#include <glib-object.h>

#include "gck-store.h"
#include "gck-types.h"

#define GCK_TYPE_FILE_STORE               (gck_file_store_get_type ())
#define GCK_FILE_STORE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_FILE_STORE, GckFileStore))
#define GCK_FILE_STORE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_FILE_STORE, GckFileStoreClass))
#define GCK_IS_FILE_STORE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_FILE_STORE))
#define GCK_IS_FILE_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_FILE_STORE))
#define GCK_FILE_STORE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_FILE_STORE, GckFileStoreClass))

typedef struct _GckFileStore GckFileStore;
typedef struct _GckFileStoreClass GckFileStoreClass;
    
struct _GckFileStoreClass {
	GckStoreClass parent_class;
	
	/* signals */
	
	void (*entry_created) (GckFileStore *store, const gchar *unique_id);
	
	void (*entry_destroyed) (GckFileStore *store, const gchar *unique_id);
};

GType                     gck_file_store_get_type               (void);

GckFileStore*             gck_file_store_new                    (const gchar *filename);

const gchar*              gck_file_store_get_filename           (GckFileStore *self);

gboolean                  gck_file_store_refresh                (GckFileStore *self);

CK_RV                     gck_file_store_unlock                 (GckFileStore *self,
                                                                 guchar *password,
                                                                 gsize n_password);

CK_RV                     gck_file_store_lock                   (GckFileStore *self);

gboolean                  gck_file_store_get_locked             (GckFileStore *self);

gboolean                  gck_file_store_have_entry             (GckFileStore *self,
                                                                 const gchar *unique_id);

void                      gck_file_store_create_entry           (GckFileStore *self, 
                                                                 GckTransaction *transaction,
                                                                 const gchar *unique_id,
                                                                 gboolean is_private);

void                      gck_file_store_connect_entry          (GckFileStore *self, 
                                                                 const gchar *unique_id,
                                                                 GckObject *object);

void                      gck_file_store_disconnect_entry       (GckFileStore *self, 
                                                                 const gchar *unique_id,
                                                                 GckObject *object);

void                      gck_file_store_destroy_entry          (GckFileStore *self, 
                                                                 GckTransaction *transaction,
                                                                 const gchar *unique_id);

#endif /* __GCK_FILE_STORE_H__ */
