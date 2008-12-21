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

#ifndef __GCK_OBJECT_H__
#define __GCK_OBJECT_H__

#include <glib-object.h>

#include "pkcs11/pkcs11.h"

#define GCK_OBJECT_HANDLE_MASK  0x0FFFFFFF
#define GCK_OBJECT_IS_PERMANENT	0x10000000
#define GCK_OBJECT_IS_TEMPORARY	0x00000000

#define GCK_TYPE_OBJECT               (gck_object_get_type ())
#define GCK_OBJECT(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_OBJECT, GckObject))
#define GCK_OBJECT_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_OBJECT, GckObjectClass))
#define GCK_IS_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_OBJECT))
#define GCK_IS_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_OBJECT))
#define GCK_OBJECT_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_OBJECT, GckObjectClass))

typedef struct _GckObject GckObject;
typedef struct _GckObjectClass GckObjectClass;
typedef struct _GckObjectPrivate GckObjectPrivate;

typedef struct _GckManager GckManager;

struct _GckObject {
	GObject parent;
	GckObjectPrivate *pv;
};

struct _GckObjectClass {
	GObjectClass parent_class;
	
	/* virtual methods  --------------------------------------------------------- */
    
	CK_RV (*get_attribute) (GckObject *object, CK_ATTRIBUTE* attr);
	
	CK_RV (*unlock) (GckObject *self, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin);
};

GType                  gck_object_get_type               (void);

CK_OBJECT_HANDLE       gck_object_get_handle             (GckObject *self);

void                   gck_object_set_handle             (GckObject *self,
                                                          CK_OBJECT_HANDLE handle);

GckManager*            gck_object_get_manager            (GckObject *self);

void                   gck_object_set_manager            (GckObject *self,
                                                          GckManager *manager);

CK_RV                  gck_object_unlock                 (GckObject *self, 
                                                          CK_UTF8CHAR_PTR pin, 
                                                          CK_ULONG n_pin);

gboolean               gck_object_match                  (GckObject *self,
                                                          CK_ATTRIBUTE_PTR attr);

gboolean               gck_object_match_all              (GckObject *self,
                                                          CK_ATTRIBUTE_PTR attrs,
                                                          CK_ULONG n_attrs);

CK_RV                  gck_object_get_attribute          (GckObject *self,
                                                          CK_ATTRIBUTE_PTR attr);

void                   gck_object_cache_attribute        (GckObject *self,
                                                          CK_ATTRIBUTE_PTR attr);

gboolean               gck_object_get_attribute_boolean  (GckObject *self,
                                                          CK_ATTRIBUTE_TYPE type,
                                                          gboolean *value);

gboolean               gck_object_get_attribute_ulong    (GckObject *self,
                                                          CK_ATTRIBUTE_TYPE type,
                                                          gulong *value);

void*                  gck_object_get_attribute_data     (GckObject *self,
                                                          CK_ATTRIBUTE_TYPE type,
                                                          gsize *n_data);

#endif /* __GCK_OBJECT_H__ */
