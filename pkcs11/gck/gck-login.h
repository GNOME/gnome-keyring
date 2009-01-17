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

#ifndef __GCK_LOGIN_H__
#define __GCK_LOGIN_H__

#include <glib-object.h>

#include "gck-types.h"

#include "pkcs11/pkcs11.h"

#define GCK_TYPE_LOGIN               (gck_login_get_type ())
#define GCK_LOGIN(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_LOGIN, GckLogin))
#define GCK_LOGIN_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_LOGIN, GckLoginClass))
#define GCK_IS_LOGIN(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_LOGIN))
#define GCK_IS_LOGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_LOGIN))
#define GCK_LOGIN_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_LOGIN, GckLoginClass))

typedef struct _GckLoginClass GckLoginClass;
    
struct _GckLoginClass {
	GObjectClass parent_class;
};

GType               gck_login_get_type               (void);

GckLogin*           gck_login_new                    (CK_UTF8CHAR_PTR pin, 
                                                      CK_ULONG n_pin);

const gchar*        gck_login_get_password           (GckLogin *self, 
                                                      gsize *n_pin);

gboolean            gck_login_equals                 (GckLogin *self,
                                                      CK_UTF8CHAR_PTR pin,
                                                      CK_ULONG n_pin);

#endif /* __GCK_LOGIN_H__ */
