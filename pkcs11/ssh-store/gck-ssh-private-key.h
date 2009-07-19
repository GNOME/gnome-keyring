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

#ifndef __GCK_SSH_PRIVATE_KEY_H__
#define __GCK_SSH_PRIVATE_KEY_H__

#include <glib-object.h>

#include "gck-ssh-public-key.h"

#include "gck/gck-private-key.h"

#define GCK_TYPE_SSH_PRIVATE_KEY               (gck_ssh_private_key_get_type ())
#define GCK_SSH_PRIVATE_KEY(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SSH_PRIVATE_KEY, GckSshPrivateKey))
#define GCK_SSH_PRIVATE_KEY_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_SSH_PRIVATE_KEY, GckSshPrivateKeyClass))
#define GCK_IS_SSH_PRIVATE_KEY(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SSH_PRIVATE_KEY))
#define GCK_IS_SSH_PRIVATE_KEY_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_SSH_PRIVATE_KEY))
#define GCK_SSH_PRIVATE_KEY_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_SSH_PRIVATE_KEY, GckSshPrivateKeyClass))

typedef struct _GckSshPrivateKey GckSshPrivateKey;
typedef struct _GckSshPrivateKeyClass GckSshPrivateKeyClass;
    
struct _GckSshPrivateKeyClass {
	GckPrivateKeyClass parent_class;
};

GType               gck_ssh_private_key_get_type               (void);

GckSshPrivateKey*   gck_ssh_private_key_new                    (GckModule *module, 
                                                                const gchar *unique);

gboolean            gck_ssh_private_key_parse                  (GckSshPrivateKey *self,
                                                                const gchar *public_path,
                                                                const gchar *private_path,
                                                                GError **error);

const gchar*        gck_ssh_private_key_get_label              (GckSshPrivateKey *key);

void                gck_ssh_private_key_set_label              (GckSshPrivateKey *key,
                                                                const gchar *label);

GckSshPublicKey*    gck_ssh_private_key_get_public_key         (GckSshPrivateKey *self);

#endif /* __GCK_SSH_PRIVATE_KEY_H__ */
