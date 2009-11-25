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

#ifndef __GKD_SECRET_UTIL_H__
#define __GKD_SECRET_UTIL_H__

#include "gkd-secret-types.h"

#include "gp11/gp11.h"

GP11Object*       gkd_secret_util_path_to_collection                    (GP11Session *session,
                                                                         const gchar *path);

GP11Object*       gkd_secret_util_path_to_item                          (GP11Session *session,
                                                                         const gchar *path);

GP11Object*       gkd_secret_util_path_to_object                        (GP11Session *session,
                                                                         const gchar *path,
                                                                         gboolean *is_item);

gchar*            gkd_secret_util_path_for_collection                   (GP11Object *object);

gchar*            gkd_secret_util_path_for_item                         (GP11Object *object);

gchar*            gkd_secret_util_identifier_for_collection             (GP11Object *collection);

GP11Attributes*   gkd_secret_util_attributes_for_item                   (GP11Object *item);

#endif /* __GKD_SECRET_UTIL_H__ */
