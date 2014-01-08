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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __GKR_ZZZ_H__
#define __GKR_ZZZ_H__

#include <glib-object.h>

G_BEGIN_DECLS

#define GKR_TYPE_ZZZ                 (gkr_zzz_get_type())
#define GKR_ZZZ(obj)                 (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_ZZZ, GkrZzz))
#define GKR_IS_ZZZ(obj)              (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_ZZZ))
#define GKR_ZZZ_GET_INTERFACE(inst)  (G_TYPE_INSTANCE_GET_INTERFACE ((inst), GKR_TYPE_ZZZ, GkrZzzIface))

typedef struct _GkrZzz      GkrZzz;
typedef struct _GkrZzzIface GkrZzzIface;

struct _GkrZzzIface {
	GTypeInterface parent;
};

GType                  gkr_zzz_get_type                          (void) G_GNUC_CONST;

G_END_DECLS

#endif /* __GKR_ZZZ_H__ */
