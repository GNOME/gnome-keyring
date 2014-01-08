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

#ifndef __GKM_XXX_H__
#define __GKM_XXX_H__

#include <glib-object.h>

#define GKM_TYPE_XXX               (gkm_xxx_get_type ())
#define GKM_XXX(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKM_TYPE_XXX, GkmXxx))
#define GKM_XXX_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKM_TYPE_XXX, GkmXxxClass))
#define GKM_IS_XXX(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKM_TYPE_XXX))
#define GKM_IS_XXX_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKM_TYPE_XXX))
#define GKM_XXX_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKM_TYPE_XXX, GkmXxxClass))

typedef struct _GkmXxx GkmXxx;
typedef struct _GkmXxxClass GkmXxxClass;

struct _GkmXxxClass {
	GObjectClass parent_class;

	/* signals --------------------------------------------------------- */

	void (*signal) (GkmXxx *xxx);
};

GType               gkm_xxx_get_type               (void);

GkmXxx*             gkm_xxx_new                    (void);

#endif /* __GKM_XXX_H__ */
