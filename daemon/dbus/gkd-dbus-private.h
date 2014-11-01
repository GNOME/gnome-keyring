/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus-private.h - header bits for dbus components

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

#ifndef GKD_DBUS_PRIVATE_H
#define GKD_DBUS_PRIVATE_H

#include <glib.h>
#include <gio/gio.h>

/* DBus environment variables sent to session */
void   gkd_dbus_environment_init        (GDBusConnection *conn);
void   gkd_dbus_environment_cleanup     (GDBusConnection *conn);

/* The gnome-keyring Dbus service, very simple */
void   gkd_dbus_service_init            (GDBusConnection *conn);
void   gkd_dbus_service_cleanup         (GDBusConnection *conn);

/* DBus desktop session interaction */
void   gkd_dbus_session_init            (GDBusConnection *conn);
void   gkd_dbus_session_cleanup         (GDBusConnection *conn);

/* DBus secrets API */
void   gkd_dbus_secrets_init            (GDBusConnection *conn);
void   gkd_dbus_secrets_cleanup         (GDBusConnection *conn);

#endif /* GKD_DBUS_PRIVATE_H */
