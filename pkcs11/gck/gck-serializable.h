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

#ifndef __GCK_SERIALIZABLE_H__
#define __GCK_SERIALIZABLE_H__

#include <glib-object.h>

#include "gck-types.h"

G_BEGIN_DECLS

#define GCK_TYPE_SERIALIZABLE                 (gck_serializable_get_type())
#define GCK_SERIALIZABLE(obj)                 (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SERIALIZABLE, GckSerializable))
#define GCK_IS_SERIALIZABLE(obj)              (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SERIALIZABLE))
#define GCK_SERIALIZABLE_GET_INTERFACE(inst)  (G_TYPE_INSTANCE_GET_INTERFACE ((inst), GCK_TYPE_SERIALIZABLE, GckSerializableIface))

typedef struct _GckSerializable      GckSerializable;
typedef struct _GckSerializableIface GckSerializableIface;

struct _GckSerializableIface {
	GTypeInterface parent;
	
	const gchar *extension;

	gboolean (*load) (GckSerializable *self, GckLogin *login, const guchar *data, gsize n_data);
	
	gboolean (*save) (GckSerializable *self, GckLogin *login, guchar **data, gsize *n_data);
};

GType                  gck_serializable_get_type                          (void) G_GNUC_CONST;

gboolean               gck_serializable_load                              (GckSerializable *self,
                                                                           GckLogin *login,
                                                                           const guchar *data,
                                                                           gsize n_data);

gboolean                gck_serializable_save                             (GckSerializable *self,
                                                                           GckLogin *login,
                                                                           guchar** data,
                                                                           gsize *n_data);

G_END_DECLS

#endif /* __GCK_SERIALIZABLE_H__ */

