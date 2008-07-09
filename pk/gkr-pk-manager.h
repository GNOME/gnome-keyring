/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-manager.h - Manage a set of PK objects

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

#ifndef __GKR_PK_MANAGER_H__
#define __GKR_PK_MANAGER_H__

#include <gcrypt.h>
#include <glib-object.h>

#include "gkr-pk-object.h"

/* 
 * GkrPkManager
 * 
 * A GkrPkManager tracks a set of GkrPkObject objects. It does not own 
 * those objects. Once an object is registered with the manager it gets 
 * an identifier.  
 * 
 * An object will unregister itself from the manager when it is destroyed or 
 * it can be done explicitely.  
 * 
 * A singleton GkrPkManager exists for token objects, those stored in 
 * persistent storage. This manager lasts for the lifetime of the daemon.
 * 
 * Other GkrPkManager objects can exist per client for session or 
 * temporary objects. Multiple requests for a manager for the same client
 * will return the same manager. Once all references dissappear this 
 * manager will go away.
 */

G_BEGIN_DECLS

#define GKR_TYPE_PK_MANAGER             (gkr_pk_manager_get_type ())
#define GKR_PK_MANAGER(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_PK_MANAGER, GkrPkManager))
#define GKR_PK_MANAGER_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_PK_MANAGER, GkrPkManager))
#define GKR_IS_PK_MANAGER(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_PK_MANAGER))
#define GKR_IS_PK_MANAGER_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_PK_MANAGER))
#define GKR_PK_MANAGER_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_PK_MANAGER, GkrPkManagerClass))

typedef struct _GkrPkManagerClass GkrPkManagerClass;

struct _GkrPkManager {
	 GObject parent;
	 GList *objects;
};

struct _GkrPkManagerClass {
	GObjectClass parent_class;
};

GType                   gkr_pk_manager_get_type            (void) G_GNUC_CONST;

GType                   gkr_pk_manager_type_from_string    (const gchar *type);

GkrPkManager*           gkr_pk_manager_new                 (void);

GkrPkManager*           gkr_pk_manager_for_token           (void);

GkrPkManager*           gkr_pk_manager_for_client          (pid_t pid);

GkrPkManager*           gkr_pk_manager_instance_for_client (pid_t pid);

void                    gkr_pk_manager_register           (GkrPkManager *objmgr, 
                                                           GkrPkObject *object);

void                    gkr_pk_manager_unregister         (GkrPkManager *objmgr, 
                                                           GkrPkObject *object);

GkrPkObject*            gkr_pk_manager_lookup             (GkrPkManager *objmgr,
                                                           CK_OBJECT_HANDLE obj);

GList*                  gkr_pk_manager_find               (GkrPkManager *objmgr,
                                                           GType type, GArray *attrs);
                                                                  
GList*                  gkr_pk_manager_findv              (GkrPkManager *objmgr,
                                                           GType gtype, ...) G_GNUC_NULL_TERMINATED;

GkrPkObject*            gkr_pk_manager_find_by_id         (GkrPkManager *objmgr,
                                                           GType gtype, gkrconstid id);

GkrPkObject*            gkr_pk_manager_find_by_digest     (GkrPkManager *objmgr,
                                                           gkrconstid digest);

G_END_DECLS

#endif /* __GKR_PK_MANAGER_H__ */

