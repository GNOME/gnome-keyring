/*
 * gnome-keyring
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#ifndef __GKD_SECRET_PORTAL_H__
#define __GKD_SECRET_PORTAL_H__

#include <glib-object.h>

#define GKD_SECRET_TYPE_PORTAL (gkd_secret_portal_get_type ())
G_DECLARE_FINAL_TYPE (GkdSecretPortal, gkd_secret_portal, GKD_SECRET, PORTAL, GObject);

struct _GkdSecretPortalClass {
	GObjectClass parent_class;
};

#endif /* __GKD_SECRET_PORTAL_H__ */
