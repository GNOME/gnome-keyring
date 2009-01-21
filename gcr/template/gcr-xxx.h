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

#ifndef __GCR_XXX_H__
#define __GCR_XXX_H__

#include "gcr.h"

#include <glib-object.h>

#define GCR_TYPE_XXX               (gcr_xxx_get_type ())
#define GCR_XXX(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_XXX, GcrXxx))
#define GCR_XXX_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_XXX, GcrXxxClass))
#define GCR_IS_XXX(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_XXX))
#define GCR_IS_XXX_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_XXX))
#define GCR_XXX_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_XXX, GcrXxxClass))

typedef struct _GcrXxx GcrXxx;
typedef struct _GcrXxxClass GcrXxxClass;
typedef struct _GcrXxxPrivate GcrXxxPrivate;

struct _GcrXxx {
	GObject parent;
	GcrXxxPrivate *pv;
};

struct _GcrXxxClass {
	GObjectClass parent_class;
    
	/* signals --------------------------------------------------------- */
    
	void (*signal) (GcrXxx *self);
};

GType               gcr_xxx_get_type               (void);

GcrXxx*             gcr_xxx_new                    (void);

#endif /* __GCR_XXX_H__ */
