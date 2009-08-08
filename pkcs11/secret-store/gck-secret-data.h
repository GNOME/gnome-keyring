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

#ifndef __GCK_SECRET_DATA_H__
#define __GCK_SECRET_DATA_H__

#include <glib-object.h>

#include "gck-secret-types.h"

#define GCK_TYPE_SECRET_DATA               (gck_secret_data_get_type ())
#define GCK_SECRET_DATA(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SECRET_DATA, GckSecretData))
#define GCK_SECRET_DATA_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_SECRET_DATA, GckSecretDataClass))
#define GCK_IS_SECRET_DATA(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SECRET_DATA))
#define GCK_IS_SECRET_DATA_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_SECRET_DATA))
#define GCK_SECRET_DATA_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_SECRET_DATA, GckSecretDataClass))

typedef struct _GckSecretDataClass GckSecretDataClass;

struct _GckSecretDataClass {
	GObjectClass parent_class;
};

GType                gck_secret_data_get_type        (void);

const guchar*        gck_secret_data_get_secret      (GckSecretData *self,
                                                      const gchar *identifer,
                                                      gsize *n_secret);

void                 gck_secret_data_add_secret      (GckSecretData *self,
                                                      const gchar *identifer,
                                                      const guchar *secret,
                                                      gsize n_secret);

void                 gck_secret_data_remove_secret   (GckSecretData *self,
                                                      const gchar *identifer);

void                 gck_secret_data_get_key         (GckSecretData *self,
                                                      const guchar **key,
                                                      gsize *n_key,
                                                      const guchar **salt,
                                                      gsize *n_salt,
                                                      guint *iterations);

void                 gck_secret_data_set_key         (GckSecretData *self,
                                                      const guchar *key,
                                                      gsize n_key,
                                                      const guchar *salt,
                                                      gsize n_salt,
                                                      guint iterations);

void                 gck_secret_data_clear_key       (GckSecretData *self);

gboolean             gck_secret_data_has_key         (GckSecretData *self);

#endif /* __GCK_SECRET_DATA_H__ */
