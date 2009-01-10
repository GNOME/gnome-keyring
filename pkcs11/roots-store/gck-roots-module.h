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

#ifndef __GCK_ROOTS_MODULE_H__
#define __GCK_ROOTS_MODULE_H__

#include <glib-object.h>

#include "gck/gck-module.h"

#define GCK_TYPE_ROOTS_MODULE               (gck_roots_module_get_type ())
#define GCK_ROOTS_MODULE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_ROOTS_MODULE, GckRootsModule))
#define GCK_ROOTS_MODULE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_ROOTS_MODULE, GckRootsModuleClass))
#define GCK_IS_ROOTS_MODULE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_ROOTS_MODULE))
#define GCK_IS_ROOTS_MODULE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_ROOTS_MODULE))
#define GCK_ROOTS_MODULE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_ROOTS_MODULE, GckRootsModuleClass))

typedef struct _GckRootsModule GckRootsModule;
typedef struct _GckRootsModuleClass GckRootsModuleClass;
    
struct _GckRootsModuleClass {
	GckModuleClass parent_class;
};

GType               gck_roots_module_get_type               (void);

#endif /* __GCK_ROOTS_MODULE_H__ */
