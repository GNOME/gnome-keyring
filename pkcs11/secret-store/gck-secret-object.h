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

#ifndef __GCK_SECRET_OBJECT_H__
#define __GCK_SECRET_OBJECT_H__

#include <glib-object.h>

#include "gck/gck-object.h"

#define GCK_TYPE_SECRET_OBJECT               (gck_secret_object_get_type ())
#define GCK_SECRET_OBJECT(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SECRET_OBJECT, GckSecretObject))
#define GCK_SECRET_OBJECT_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_SECRET_OBJECT, GckSecretObjectClass))
#define GCK_IS_SECRET_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SECRET_OBJECT))
#define GCK_IS_SECRET_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_SECRET_OBJECT))
#define GCK_SECRET_OBJECT_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_SECRET_OBJECT, GckSecretObjectClass))

typedef struct _GckSecretObject GckSecretObject;
typedef struct _GckSecretObjectClass GckSecretObjectClass;
typedef struct _GckSecretObjectPrivate GckSecretObjectPrivate;

struct _GckSecretObject {
	GckObject parent;
	GckSecretObjectPrivate *pv;
};
struct _GckSecretObjectClass {
	GckObjectClass parent_class;
	
	CK_RV (*lock) (GckSecretObject *self, GckSession *session);

	gboolean (*is_locked) (GckSecretObject *self, GckSession *session);
};

GType                gck_secret_object_get_type        (void);

const gchar*         gck_secret_object_get_identifier  (GckSecretObject *self);

const gchar*         gck_secret_object_get_label       (GckSecretObject *self);

void                 gck_secret_object_set_label       (GckSecretObject *self,
                                                        const gchar *label);

glong                gck_secret_object_get_created     (GckSecretObject *self);

glong                gck_secret_object_get_modified    (GckSecretObject *self);

void                 gck_secret_object_was_modified    (GckSecretObject *self);

gboolean             gck_secret_object_is_locked       (GckSecretObject *self,
                                                        GckSession *session);

void                 gck_secret_object_lock            (GckSecretObject *self,
                                                        GckSession *session);

#endif /* __GCK_SECRET_OBJECT_H__ */
