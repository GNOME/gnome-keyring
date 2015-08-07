/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus.h - header for dbus component

   Copyright (C) 2009, Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef GKD_DBUS_H
#define GKD_DBUS_H

#include <gio/gio.h>
#include <glib.h>

gboolean      gkd_dbus_setup                    (void);

gboolean  gkd_dbus_secrets_startup  (void);

gboolean      gkd_dbus_singleton_acquire        (gboolean *acquired);

gchar*        gkd_dbus_singleton_control        (void);

/* DBus utils */
gboolean      gkd_dbus_invocation_matches_caller (GDBusMethodInvocation *invocation,
						  const char            *caller);

#endif /* GKD_DBUS_H */
