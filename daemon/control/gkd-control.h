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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __GKD_CONTROL_H__
#define __GKD_CONTROL_H__

#include <glib.h>

typedef enum {
	GKD_CONTROL_QUIET_IF_NO_PEER = 1 << 0,
	GKD_CONTROL_WAIT_FOR_CLOSE = 1 << 1,
} GkdControlFlags;

gboolean          gkd_control_listen        (void);

void              gkd_control_stop          (void);

gchar**           gkd_control_initialize    (const gchar *directory,
                                             const gchar *components,
                                             const gchar **env);

gboolean          gkd_control_unlock        (const gchar *directory,
                                             const gchar *password);

gboolean          gkd_control_change_lock   (const gchar *directory,
                                             const gchar *original,
                                             const gchar *password);

gboolean          gkd_control_quit          (const gchar *directory,
                                             GkdControlFlags flags);

#endif /* __GKD_CONTROL_H__ */
