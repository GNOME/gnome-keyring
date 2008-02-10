/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-object-manager.h - Manage all 'token' PK objects

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef __GKR_PK_OBJECT_MANAGER_H__
#define __GKR_PK_OBJECT_MANAGER_H__

#include <gcrypt.h>
#include <glib-object.h>

#include "gkr-pk-object.h"

/* 
 * GkrPkObjectManager
 * 
 * A GkrPkObjectManager tracks a set of GkrPkObject objects. It does not own 
 * those objects. Once an object is registered with the manager it gets 
 * an identifier.  
 * 
 * An object will unregister itself from the manager when it is destroyed or 
 * it can be done explicitely.  
 * 
 * A singleton GkrPkObjectManager exists for token objects, those stored in 
 * persistent storage. This manager lasts for the lifetime of the daemon.
 * 
 * Other GkrPkObjectManager objects can exist per client for session or 
 * temporary objects. Multiple requests for a manager for the same client
 * will return the same manager. Once all references dissappear this 
 * manager will go away.
 */

G_BEGIN_DECLS

#define GKR_TYPE_PK_OBJECT_MANAGER             (gkr_pk_object_manager_get_type ())
#define GKR_PK_OBJECT_MANAGER(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_PK_OBJECT_MANAGER, GkrPkObjectManager))
#define GKR_PK_OBJECT_MANAGER_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_PK_OBJECT_MANAGER, GObject))
#define GKR_IS_PK_OBJECT_MANAGER(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_PK_OBJECT_MANAGER))
#define GKR_IS_PK_OBJECT_MANAGER_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_PK_OBJECT_MANAGER))
#define GKR_PK_OBJECT_MANAGER_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_PK_OBJECT_MANAGER, GkrPkObjectManagerClass))

typedef struct _GkrPkObjectManagerClass GkrPkObjectManagerClass;

struct _GkrPkObjectManager {
	 GObject parent;
	 GList *objects;
};

struct _GkrPkObjectManagerClass {
	GObjectClass parent_class;
};

GType                   gkr_pk_object_manager_get_type            (void) G_GNUC_CONST;

GType                   gkr_pk_object_manager_type_from_string    (const gchar *type);

GkrPkObjectManager*     gkr_pk_object_manager_for_token           (void);

GkrPkObjectManager*     gkr_pk_object_manager_for_client          (pid_t pid);

GkrPkObjectManager*     gkr_pk_object_manager_instance_for_client (pid_t pid);

void                    gkr_pk_object_manager_register           (GkrPkObjectManager *objmgr, 
                                                                  GkrPkObject *object);

void                    gkr_pk_object_manager_unregister         (GkrPkObjectManager *objmgr, 
                                                                  GkrPkObject *object);

GkrPkObject*            gkr_pk_object_manager_lookup             (GkrPkObjectManager *objmgr,
                                                                  CK_OBJECT_HANDLE obj);

GList*                  gkr_pk_object_manager_find               (GkrPkObjectManager *objmgr,
                                                                  GType type, GArray *attrs);
                                                                  
GList*                  gkr_pk_object_manager_findv              (GkrPkObjectManager *objmgr,
                                                                  GType gtype, ...) G_GNUC_NULL_TERMINATED;

GkrPkObject*            gkr_pk_object_manager_find_by_id         (GkrPkObjectManager *objmgr,
                                                                  GType gtype, gkrconstid id);

GkrPkObject*            gkr_pk_object_manager_find_by_unique     (GkrPkObjectManager *objmgr,
                                                                  gkrconstid unique);

G_END_DECLS

#endif /* __GKR_PK_OBJECT_MANAGER_H__ */

