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
 * You should have received a copy of the GNU Lesser General Private
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef __GCK_PRIVATE_XSA_KEY_H__
#define __GCK_PRIVATE_XSA_KEY_H__

#include <glib-object.h>

#include "gck-key.h"
#include "gck-types.h"

#define GCK_FACTORY_PRIVATE_XSA_KEY            (gck_private_xsa_key_get_factory ())

#define GCK_TYPE_PRIVATE_XSA_KEY               (gck_private_xsa_key_get_type ())
#define GCK_PRIVATE_XSA_KEY(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_PRIVATE_XSA_KEY, GckPrivateXsaKey))
#define GCK_PRIVATE_XSA_KEY_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_PRIVATE_XSA_KEY, GckPrivateXsaKeyClass))
#define GCK_IS_PRIVATE_XSA_KEY(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_PRIVATE_XSA_KEY))
#define GCK_IS_PRIVATE_XSA_KEY_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_PRIVATE_XSA_KEY))
#define GCK_PRIVATE_XSA_KEY_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_PRIVATE_XSA_KEY, GckPrivateXsaKeyClass))

typedef struct _GckPrivateXsaKeyClass GckPrivateXsaKeyClass;
typedef struct _GckPrivateXsaKeyPrivate GckPrivateXsaKeyPrivate;

struct _GckPrivateXsaKey {
	GckKey parent;
	GckPrivateXsaKeyPrivate *pv;
};

struct _GckPrivateXsaKeyClass {
	GckKeyClass parent_class;
};

GType                  gck_private_xsa_key_get_type               (void);

void                   gck_private_xsa_key_set_unlocked_private   (GckPrivateXsaKey *self,
                                                                   GckSexp *sexp);

void                   gck_private_xsa_key_set_locked_private     (GckPrivateXsaKey *self,
                                                                   GckCredential *cred,
                                                                   GckSexp *sexp);

GckFactory*            gck_private_xsa_key_get_factory            (void);

GckSexp*               gck_private_xsa_key_create_sexp            (GckSession *session,
                                                                   GckTransaction *transaction,
                                                                   CK_ATTRIBUTE_PTR attrs,
                                                                   CK_ULONG n_attrs);

#endif /* __GCK_PRIVATE_XSA_KEY_H__ */
