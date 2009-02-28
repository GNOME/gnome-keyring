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

#ifndef __GCR_TOKEN_MANAGER_H__
#define __GCR_TOKEN_MANAGER_H__

#include "gcr-types.h"

#include <glib-object.h>

G_BEGIN_DECLS

#define GCR_TYPE_TOKEN_MANAGER               (gcr_token_manager_get_type ())
#define GCR_TOKEN_MANAGER(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_TOKEN_MANAGER, GcrTokenManager))
#define GCR_TOKEN_MANAGER_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_TOKEN_MANAGER, GcrTokenManagerClass))
#define GCR_IS_TOKEN_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_TOKEN_MANAGER))
#define GCR_IS_TOKEN_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_TOKEN_MANAGER))
#define GCR_TOKEN_MANAGER_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_TOKEN_MANAGER, GcrTokenManagerClass))

typedef struct _GcrTokenManager GcrTokenManager;
typedef struct _GcrTokenManagerClass GcrTokenManagerClass;
typedef struct _GcrTokenManagerPrivate GcrTokenManagerPrivate;

struct _GcrTokenManager {
	GObject parent;
	GcrTokenManagerPrivate *pv;
};

struct _GcrTokenManagerClass {
	GObjectClass parent_class;
};

GType                     gcr_token_manager_get_type             (void);

GcrTokenManager*          gcr_token_manager_new                  (struct _GP11Slot *slot);

struct _GP11Slot*         gcr_token_manager_get_slot             (GcrTokenManager *self);

gboolean                  gcr_token_manager_initialize           (GcrTokenManager *self,
                                                                  GCancellable *cancel,
                                                                  GError **error);

void                      gcr_token_manager_initialize_async     (GcrTokenManager *self,
                                                                  GCancellable *cancel,
                                                                  GAsyncReadyCallback callback,
                                                                  gpointer user_data);

gboolean                  gcr_token_manager_initialize_finish    (GcrTokenManager *self,
                                                                  GAsyncResult *res,
                                                                  GError **error);

gboolean                  gcr_token_manager_change_pin           (GcrTokenManager *self,
                                                                  GCancellable *cancel,
                                                                  GError **error);

void                      gcr_token_manager_change_pin_async     (GcrTokenManager *self,
                                                                  GCancellable *cancel,
                                                                  GAsyncReadyCallback callback,
                                                                  gpointer user_data);

gboolean                  gcr_token_manager_change_pin_finish    (GcrTokenManager *self,
                                                                  GAsyncResult *res,
                                                                  GError **error);

G_END_DECLS

#endif /* __GCR_TOKEN_MANAGER_H__ */
