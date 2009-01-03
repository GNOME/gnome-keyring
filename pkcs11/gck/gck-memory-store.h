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

#ifndef __GCK_MEMORY_STORE_H__
#define __GCK_MEMORY_STORE_H__

#include <glib-object.h>

#include "gck-store.h"
#include "gck-types.h"

#define GCK_TYPE_MEMORY_STORE               (gck_memory_store_get_type ())
#define GCK_MEMORY_STORE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_MEMORY_STORE, GckMemoryStore))
#define GCK_MEMORY_STORE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_MEMORY_STORE, GckMemoryStoreClass))
#define GCK_IS_MEMORY_STORE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_MEMORY_STORE))
#define GCK_IS_MEMORY_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_MEMORY_STORE))
#define GCK_MEMORY_STORE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_MEMORY_STORE, GckMemoryStoreClass))

typedef struct _GckMemoryStore GckMemoryStore;
typedef struct _GckMemoryStoreClass GckMemoryStoreClass;
    
struct _GckMemoryStoreClass {
	GckStoreClass parent_class;
};

GType                 gck_memory_store_get_type               (void);

GckMemoryStore*       gck_memory_store_new                    (void);

#endif /* __GCK_MEMORY_STORE_H__ */
