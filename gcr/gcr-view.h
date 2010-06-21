/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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

#ifndef __GCR_VIEW_H__
#define __GCR_VIEW_H__

#include <glib-object.h>

#include "gcr-types.h"

G_BEGIN_DECLS

#define GCR_TYPE_VIEW                 (gcr_view_get_type())
#define GCR_VIEW(obj)                 (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_VIEW, GcrView))
#define GCR_IS_VIEW(obj)              (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_VIEW))
#define GCR_VIEW_GET_INTERFACE(inst)  (G_TYPE_INSTANCE_GET_INTERFACE ((inst), GCR_TYPE_VIEW, GcrViewIface))

typedef struct _GcrView      GcrView;
typedef struct _GcrViewIface GcrViewIface;

struct _GcrViewIface {
	GTypeInterface parent;
};

GType                  gcr_view_get_type                          (void) G_GNUC_CONST;

GcrView*               gcr_view_create                            (const gchar *label,
                                                                   struct _GP11Attributes *attrs);

void                   gcr_view_register                          (GType view_type,
                                                                   struct _GP11Attributes *attrs);

G_END_DECLS

#endif /* __GCR_VIEW_H__ */
