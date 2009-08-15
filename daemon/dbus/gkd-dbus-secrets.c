/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus-secrets.c - dbus secrets service

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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkd-dbus-private.h"
#include "gkd-secrets-service.h"

static GkdSecretsService *secrets_service = NULL;

void
gkd_dbus_secrets_init (DBusConnection *conn)
{
	DBusError error = DBUS_ERROR_INIT;
	dbus_uint32_t result = 0;

	/* Try and grab our name */
	result = dbus_bus_request_name (conn, SECRETS_SERVICE, 0, &error);
	if (dbus_error_is_set (&error)) {
		g_message ("couldn't request name '%s' on session bus: %s",
		           SECRETS_SERVICE, error.message);
		dbus_error_free (&error);

	} else {
		switch (result) {

		/* We acquired the service name */
		case DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER:
			break;

		/* We already acquired the service name. Odd */
		case DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER:
			g_return_if_reached ();
			break;

		/* Another daemon is running */
		case DBUS_REQUEST_NAME_REPLY_IN_QUEUE:
		case DBUS_REQUEST_NAME_REPLY_EXISTS:
			g_message ("another secrets service is running");
			break;

		default:
			g_return_if_reached ();
			break;
		};
	}

	g_return_if_fail (!secrets_service);
	secrets_service = g_object_new (GKD_SECRETS_TYPE_SERVICE, "connection", conn, NULL);
}

void
gkd_dbus_secrets_cleanup (DBusConnection *conn)
{
	if (secrets_service) {
		g_object_run_dispose (G_OBJECT (secrets_service));
		g_object_unref (secrets_service);
		secrets_service = NULL;
	}
}
