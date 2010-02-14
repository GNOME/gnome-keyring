/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus.c - hook into dbus, call other bits

   Copyright (C) 2007, 2009, Stefan Walter

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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkd-dbus.h"
#include "gkd-dbus-private.h"

#include "egg/egg-cleanup.h"
#include "egg/egg-dbus.h"

#include <glib.h>

#include <dbus/dbus.h>

static DBusConnection *dbus_conn = NULL;
static gboolean dbus_do_session = TRUE;

static void
daemon_dbus_cleanup (gpointer unused)
{
	if (!dbus_conn)
		return;

	gkd_dbus_secrets_cleanup (dbus_conn);

	if (dbus_do_session) {
		gkd_dbus_session_cleanup (dbus_conn);
		gkd_dbus_environment_cleanup (dbus_conn);
	}

	gkd_dbus_service_cleanup (dbus_conn);

	egg_dbus_disconnect_from_mainloop (dbus_conn, NULL);
	dbus_connection_unref (dbus_conn);
	dbus_conn = NULL;
}

void
gkd_dbus_setup (void)
{
	DBusError derr = { 0 };

	if (dbus_conn)
		return;

	dbus_error_init (&derr);

	/* Get the dbus bus and hook up */
	dbus_conn = dbus_bus_get (DBUS_BUS_SESSION, &derr);
	if (!dbus_conn) {
		g_message ("couldn't connect to dbus session bus: %s", derr.message);
		dbus_error_free (&derr);
		return;
	}

	egg_cleanup_register (daemon_dbus_cleanup, NULL);

	egg_dbus_connect_with_mainloop (dbus_conn, NULL);

	/* Make sure dbus doesn't kill our app */
	dbus_connection_set_exit_on_disconnect (dbus_conn, FALSE);

	/* Gnome Keyring service */
	gkd_dbus_service_init (dbus_conn);

	/* Session stuff */
	if (dbus_do_session) {
		gkd_dbus_environment_init (dbus_conn);
		gkd_dbus_session_init (dbus_conn);
	}

	/* Secrets API */
	gkd_dbus_secrets_init (dbus_conn);
}
