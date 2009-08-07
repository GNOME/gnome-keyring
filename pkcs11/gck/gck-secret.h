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

#ifndef __GCK_SECRET_H__
#define __GCK_SECRET_H__

#include <glib-object.h>

#include "gck-types.h"

#include "pkcs11/pkcs11.h"

#define GCK_TYPE_SECRET               (gck_secret_get_type ())
#define GCK_SECRET(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SECRET, GckSecret))
#define GCK_SECRET_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_SECRET, GckSecretClass))
#define GCK_IS_SECRET(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SECRET))
#define GCK_IS_SECRET_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_SECRET))
#define GCK_SECRET_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_SECRET, GckSecretClass))

typedef struct _GckSecretClass GckSecretClass;
    
struct _GckSecretClass {
	GObjectClass parent_class;
};

GType               gck_secret_get_type               (void);

GckSecret*          gck_secret_new                    (const guchar *data, 
                                                       gssize n_data);

GckSecret*          gck_secret_new_from_login         (CK_UTF8CHAR_PTR pin, 
                                                       CK_ULONG n_pin);

GckSecret*          gck_secret_new_from_password      (const gchar *password);

const guchar*       gck_secret_get                    (GckSecret *self,
                                                       gsize *n_data);

const gchar*        gck_secret_get_password           (GckSecret *self,
                                                       gsize *n_pin);

gboolean            gck_secret_equals                 (GckSecret *self,
                                                       const guchar *data,
                                                       gssize n_data);

#endif /* __GCK_SECRET_H__ */
