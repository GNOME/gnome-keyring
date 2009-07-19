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

#include "gck-types.h"

#define GCK_TYPE_OBJECT               (gck_object_get_type ())
#define GCK_OBJECT(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_OBJECT, GckObject))
#define GCK_OBJECT_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_OBJECT, GckObjectClass))
#define GCK_IS_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_OBJECT))
#define GCK_IS_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_OBJECT))
#define GCK_OBJECT_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_OBJECT, GckObjectClass))

typedef struct _GckObjectClass GckObjectClass;
typedef struct _GckObjectPrivate GckObjectPrivate;

struct _GckObject {
	GObject parent;
	GckObjectPrivate *pv;
};

struct _GckObjectClass {
	GObjectClass parent_class;
	
	/* signals ------------------------------------------------------------------ */
	
	void (*notify_attribute) (GckObject *object, CK_ATTRIBUTE_TYPE attr_type);
	
	/* virtual methods  --------------------------------------------------------- */
    
	CK_RV (*get_attribute) (GckObject *object, GckSession *session,
	                        CK_ATTRIBUTE *attr);
	
	void (*set_attribute) (GckObject *object, GckSession *session,
	                       GckTransaction *transaction, CK_ATTRIBUTE *attr);
	
	void (*create_attributes) (GckObject *object, GckSession *session,
	                           GckTransaction *transaction, CK_ATTRIBUTE *attrs, CK_ULONG n_attrs);

	CK_RV (*unlock) (GckObject *self, GckAuthenticator *auth);
};

GType                  gck_object_get_type               (void);

CK_OBJECT_HANDLE       gck_object_get_handle             (GckObject *self);

void                   gck_object_set_handle             (GckObject *self,
                                                          CK_OBJECT_HANDLE handle);

GckModule*             gck_object_get_module             (GckObject *self);

GckManager*            gck_object_get_manager            (GckObject *self);

const gchar*           gck_object_get_unique             (GckObject *self);

gboolean               gck_object_get_transient          (GckObject *self);

CK_RV                  gck_object_unlock                 (GckObject *self, 
                                                          GckAuthenticator *auth);

void                   gck_object_destroy                (GckObject *self,
                                                          GckTransaction *transaction);

gboolean               gck_object_match                  (GckObject *self,
                                                          GckSession *session,
                                                          CK_ATTRIBUTE_PTR attr);

gboolean               gck_object_match_all              (GckObject *self,
                                                          GckSession *session,
                                                          CK_ATTRIBUTE_PTR attrs,
                                                          CK_ULONG n_attrs);

CK_RV                  gck_object_get_attribute          (GckObject *self,
                                                          GckSession *session,
                                                          CK_ATTRIBUTE_PTR attr);

void                   gck_object_set_attribute          (GckObject *self,
                                                          GckSession *session,
                                                          GckTransaction *transaction,
                                                          CK_ATTRIBUTE_PTR attr);

void                   gck_object_create_attributes      (GckObject *self,
                                                          GckSession *session,
                                                          GckTransaction *transaction,
                                                          CK_ATTRIBUTE_PTR attrs,
                                                          CK_ULONG n_attrs);

void                   gck_object_notify_attribute       (GckObject *self,
                                                          CK_ATTRIBUTE_TYPE attr_type);

gboolean               gck_object_get_attribute_boolean  (GckObject *self,
                                                          GckSession *session,
                                                          CK_ATTRIBUTE_TYPE type,
                                                          gboolean *value);

gboolean               gck_object_get_attribute_ulong    (GckObject *self,
                                                          GckSession *session,
                                                          CK_ATTRIBUTE_TYPE type,
                                                          gulong *value);

void*                  gck_object_get_attribute_data     (GckObject *self,
                                                          GckSession *session,
                                                          CK_ATTRIBUTE_TYPE type,
                                                          gsize *n_data);

#endif /* __GCK_OBJECT_H__ */
