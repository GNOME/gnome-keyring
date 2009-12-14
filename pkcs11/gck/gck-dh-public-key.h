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

#ifndef __GCK_DH_PUBLIC_KEY_H__
#define __GCK_DH_PUBLIC_KEY_H__

#include <glib-object.h>

#include "gck-dh-key.h"
#include "gck-types.h"

#define GCK_FACTORY_DH_PUBLIC_KEY            (gck_dh_public_key_get_factory ())

#define GCK_TYPE_DH_PUBLIC_KEY               (gck_dh_public_key_get_type ())
#define GCK_DH_PUBLIC_KEY(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_DH_PUBLIC_KEY, GckDhPublicKey))
#define GCK_DH_PUBLIC_KEY_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_DH_PUBLIC_KEY, GckDhPublicKeyClass))
#define GCK_IS_DH_PUBLIC_KEY(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_DH_PUBLIC_KEY))
#define GCK_IS_DH_PUBLIC_KEY_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_DH_PUBLIC_KEY))
#define GCK_DH_PUBLIC_KEY_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_DH_PUBLIC_KEY, GckDhPublicKeyClass))

typedef struct _GckDhPublicKeyClass GckDhPublicKeyClass;

struct _GckDhPublicKeyClass {
	GckDhKeyClass parent_class;
};

GType                     gck_dh_public_key_get_type           (void);

GckFactory*               gck_dh_public_key_get_factory        (void);

GckDhPublicKey*           gck_dh_public_key_new                (GckModule *module,
                                                                GckManager *manager,
                                                                gcry_mpi_t prime,
                                                                gcry_mpi_t base,
                                                                gcry_mpi_t value,
                                                                gpointer id,
                                                                gsize n_id);

#endif /* __GCK_DH_PUBLIC_KEY_H__ */
