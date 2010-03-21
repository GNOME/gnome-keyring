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

#ifndef __GKD_LOGIN_H__
#define __GKD_LOGIN_H__

#include <glib.h>

#include "gp11/gp11.h"

gboolean          gkd_login_unlock                   (const gchar *master);

gboolean          gkd_login_change_lock              (const gchar *original,
                                                      const gchar *master);

gboolean          gkd_login_did_unlock_fail          (void);

gboolean          gkd_login_is_usable                (void);

void              gkd_login_attach_secret            (const gchar *label,
                                                      const gchar *secret,
                                                      const gchar *first,
                                                      ...);

GP11Attributes*   gkd_login_attach_make_attributes   (const gchar *label,
                                                      const gchar *first,
                                                      ...);

gchar*            gkd_login_lookup_secret            (const gchar *first,
                                                      ...);

void              gkd_login_remove_secret            (const gchar *first,
                                                      ...);

#endif /* __GKD_LOGIN_H__ */
