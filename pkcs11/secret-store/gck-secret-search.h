/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
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

#ifndef __GCK_SECRET_SEARCH_H__
#define __GCK_SECRET_SEARCH_H__

#include "gck-secret-types.h"

#include "gck/gck-object.h"

#include <glib-object.h>

#define GCK_TYPE_SECRET_SEARCH               (gck_secret_search_get_type ())
#define GCK_SECRET_SEARCH(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SECRET_SEARCH, GckSecretSearch))
#define GCK_SECRET_SEARCH_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_SECRET_SEARCH, GckSecretSearchClass))
#define GCK_IS_SECRET_SEARCH(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SECRET_SEARCH))
#define GCK_IS_SECRET_SEARCH_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_SECRET_SEARCH))
#define GCK_SECRET_SEARCH_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_SECRET_SEARCH, GckSecretSearchClass))

typedef struct _GckSecretSearchClass GckSecretSearchClass;

struct _GckSecretSearchClass {
	GckObjectClass parent_class;
};

GType                gck_secret_search_get_type        (void);

GHashTable*          gck_secret_search_get_fields      (GckSecretSearch *self);

#endif /* __GCK_SECRET_SEARCH_H__ */
