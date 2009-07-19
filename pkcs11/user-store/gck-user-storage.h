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

#ifndef __GCK_USER_STORAGE_H__
#define __GCK_USER_STORAGE_H__

#include <glib-object.h>

#include "gck/gck-login.h"
#include "gck/gck-manager.h"
#include "gck/gck-store.h"
#include "gck/gck-transaction.h"

#define GCK_TYPE_USER_STORAGE               (gck_user_storage_get_type ())
#define GCK_USER_STORAGE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_USER_STORAGE, GckUserStorage))
#define GCK_USER_STORAGE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_USER_STORAGE, GckUserStorageClass))
#define GCK_IS_USER_STORAGE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_USER_STORAGE))
#define GCK_IS_USER_STORAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_USER_STORAGE))
#define GCK_USER_STORAGE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_USER_STORAGE, GckUserStorageClass))

typedef struct _GckUserStorage GckUserStorage;
typedef struct _GckUserStorageClass GckUserStorageClass;
    
struct _GckUserStorageClass {
	GckStoreClass parent_class;
};

GType                       gck_user_storage_get_type               (void);

GckUserStorage*             gck_user_storage_new                    (GckModule *module,
                                                                     const gchar *directory);

GckManager*                 gck_user_storage_get_manager            (GckUserStorage *self);

const gchar*                gck_user_storage_get_directory          (GckUserStorage *self);

GckLogin*                   gck_user_storage_get_login              (GckUserStorage *self);

gulong                      gck_user_storage_token_flags            (GckUserStorage *self);

CK_RV                       gck_user_storage_refresh                (GckUserStorage *self);

void                        gck_user_storage_create                 (GckUserStorage *self, 
                                                                     GckTransaction *transaction, 
                                                                     GckObject *object);

void                        gck_user_storage_destroy                (GckUserStorage *self, 
                                                                     GckTransaction *transaction, 
                                                                     GckObject *object);

void                        gck_user_storage_relock                 (GckUserStorage *self, 
                                                                     GckTransaction *transaction, 
                                                                     GckLogin *old_login, 
                                                                     GckLogin *new_login);

CK_RV                       gck_user_storage_unlock                 (GckUserStorage *self,
                                                                     GckLogin *login);

CK_RV                       gck_user_storage_lock                   (GckUserStorage *self);

#endif /* __GCK_USER_STORAGE_H__ */
