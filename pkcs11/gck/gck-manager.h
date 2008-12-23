/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
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

#ifndef __GCK_MANAGER_H__
#define __GCK_MANAGER_H__

#include <gcrypt.h>
#include <glib-object.h>

#include "gck-object.h"

/* 
 * GckManager
 * 
 * A GckManager tracks a set of GckObject objects. It does not own 
 * those objects. Once an object is registered with the manager it gets 
 * an identifier.  
 * 
 * An object will unregister itself from the manager when it is destroyed or 
 * it can be done explicitely.  
 * 
 * A singleton GckManager exists for token objects, those stored in 
 * persistent storage. This manager lasts for the lifetime of the daemon.
 * 
 * Other GckManager objects can exist per client for session or 
 * temporary objects. Multiple requests for a manager for the same client
 * will return the same manager. Once all references dissappear this 
 * manager will go away.
 */

G_BEGIN_DECLS

#include "gck-object.h"

#include "pkcs11/pkcs11.h"

#define GCK_TYPE_MANAGER             (gck_manager_get_type ())
#define GCK_MANAGER(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_MANAGER, GckManager))
#define GCK_MANAGER_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_MANAGER, GckManager))
#define GCK_IS_MANAGER(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_MANAGER))
#define GCK_IS_MANAGER_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_MANAGER))
#define GCK_MANAGER_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_MANAGER, GckManagerClass))

typedef struct _GckManagerClass GckManagerClass;
typedef struct _GckManagerPrivate GckManagerPrivate;

struct _GckManager {
	 GObject parent;
	 GckManagerPrivate *pv;
};

struct _GckManagerClass {
	GObjectClass parent_class;
};

GType                   gck_manager_get_type            (void) G_GNUC_CONST;

gboolean                gck_manager_get_for_token       (GckManager *self);

#if 0
GType                   gck_manager_type_from_string    (const gchar *type);
#endif

void                    gck_manager_register_object     (GckManager *self, 
                                                         GckObject *object);

void                    gck_manager_unregister_object   (GckManager *self, 
                                                         GckObject *object);

GckObject*              gck_manager_lookup_handle       (GckManager *self,
                                                         CK_OBJECT_HANDLE obj);

CK_RV                   gck_manager_find_handles        (GckManager *self,
                                                         gboolean also_private,
                                                         CK_ATTRIBUTE_PTR template,
                                                         CK_ULONG count,
                                                         GArray *found);

#if 0
GList*                  gck_manager_find                (GckManager *self,
                                                         GType type, GArray *attrs);
                                                                  
GList*                  gck_manager_findv               (GckManager *self,
                                                           GType gtype, ...) G_GNUC_NULL_TERMINATED;

GckObject*              gck_manager_find_by_id         (GckManager *self,
                                                           GType gtype, gkrconstid id);

GckObject*              gck_manager_find_by_digest     (GckManager *self,
                                                           gkrconstid digest);
#endif

G_END_DECLS

#endif /* __GCK_MANAGER_H__ */

