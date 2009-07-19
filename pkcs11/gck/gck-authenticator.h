/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *  
 * You should have received a copy of the GNU Lesser General 
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef __GCK_AUTHENTICATOR_H__
#define __GCK_AUTHENTICATOR_H__

#include <glib-object.h>

#include "gck-object.h"
#include "gck-types.h"

#define GCK_FACTORY_AUTHENTICATOR            (gck_authenticator_get_factory ())

#define GCK_TYPE_AUTHENTICATOR               (gck_authenticator_get_type ())
#define GCK_AUTHENTICATOR(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_AUTHENTICATOR, GckAuthenticator))
#define GCK_AUTHENTICATOR_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_AUTHENTICATOR, GckAuthenticatorClass))
#define GCK_IS_AUTHENTICATOR(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_AUTHENTICATOR))
#define GCK_IS_AUTHENTICATOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_AUTHENTICATOR))
#define GCK_AUTHENTICATOR_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_AUTHENTICATOR, GckAuthenticatorClass))

typedef struct _GckAuthenticatorClass GckAuthenticatorClass;
typedef struct _GckAuthenticatorPrivate GckAuthenticatorPrivate;
    
struct _GckAuthenticator {
	GckObject parent;
	GckAuthenticatorPrivate *pv;
};

struct _GckAuthenticatorClass {
	GckObjectClass parent_class;
};

GType                      gck_authenticator_get_type               (void);

GckFactoryInfo*            gck_authenticator_get_factory            (void);

CK_RV                      gck_authenticator_create                 (GckObject *object,
                                                                     CK_UTF8CHAR_PTR pin,
                                                                     CK_ULONG n_pin,
                                                                     GckAuthenticator **result);

GckLogin*                  gck_authenticator_get_login              (GckAuthenticator *self);

void                       gck_authenticator_set_login              (GckAuthenticator *self,
                                                                     GckLogin *login);

const gchar*               gck_authenticator_get_password           (GckAuthenticator *self,
                                                                     gsize *n_password);

GckObject*                 gck_authenticator_get_object             (GckAuthenticator *self);

gint                       gck_authenticator_get_uses_remaining     (GckAuthenticator *self);

void                       gck_authenticator_set_uses_remaining     (GckAuthenticator *self,
                                                                     gint use_count);

void                       gck_authenticator_throw_away_one_use     (GckAuthenticator *self);

#endif /* __GCK_AUTHENTICATOR_H__ */
