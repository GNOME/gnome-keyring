/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus-secrets.c - dbus secret service

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

#include "config.h"

#include "gkd-dbus.h"
#include "gkd-dbus-private.h"
#include "gkd-secret-service.h"

#include "daemon/gkd-pkcs11.h"

#include "egg/egg-cleanup.h"
#include "egg/egg-error.h"

#include <gck/gck.h>

static GDBusConnection *dbus_conn = NULL;
static GkdSecretService *secrets_service = NULL;

static GckSlot*
calculate_secrets_slot (void)
{
	GckSlot *slot = NULL;
	GckModule *module;
	GList *modules;
	GError *err = NULL;
	CK_FUNCTION_LIST_PTR funcs;

	/* TODO: Should we be handling just one module here? */
	funcs = gkd_pkcs11_get_functions ();
	g_return_val_if_fail (funcs != NULL, NULL);

	module = gck_module_new (funcs);
	g_return_val_if_fail (module, NULL);

	modules = g_list_prepend (NULL, module);
	slot = gck_modules_token_for_uri (modules, "pkcs11:token=Secret%20Store", &err);
	if (!slot && err) {
		g_warning ("couldn't find secret store: %s", egg_error_message (err));
		g_clear_error (&err);
	}

	gck_list_unref_free (modules);
	return slot;
}

gboolean
gkd_dbus_secrets_startup (void)
{
	const gchar *service = NULL;
	unsigned int flags = 0;
	GckSlot *slot;
	GError *error = NULL;
	GVariant *request_variant;
	guint res;

	g_return_val_if_fail (dbus_conn, FALSE);

#ifdef WITH_DEBUG
	service = g_getenv ("GNOME_KEYRING_TEST_SERVICE");
	if (service && service[0])
		flags = G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT | G_BUS_NAME_OWNER_FLAGS_REPLACE;
	else
#endif
		service = SECRET_SERVICE;

	/* Figure out which slot to use */
	slot = calculate_secrets_slot ();
	g_return_val_if_fail (slot, FALSE);

	/* Try and grab our name */
	request_variant = g_dbus_connection_call_sync (dbus_conn,
						       "org.freedesktop.DBus",  /* bus name */
						       "/org/freedesktop/DBus", /* object path */
						       "org.freedesktop.DBus",  /* interface name */
						       "RequestName",           /* method name */
						       g_variant_new ("(su)",
								      service,
								      flags),
						       G_VARIANT_TYPE ("(u)"),
						       G_DBUS_CALL_FLAGS_NONE,
						       -1, NULL, &error);

	if (error != NULL) {
		g_message ("couldn't request name '%s' on session bus: %s",
		           service, error->message);
		g_error_free (error);
	} else {
		g_variant_get (request_variant, "(u)", &res);
		g_variant_unref (request_variant);

		switch (res) {
		/* We acquired the service name */
		case 1: /* DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER */
		/* We already acquired the service name. */
		case 4: /* DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER */
			break;
		/* Another daemon is running */
		case 2: /* DBUS_REQUEST_NAME_REPLY_IN_QUEUE */
		case 3: /* DBUS_REQUEST_NAME_REPLY_EXISTS */
			g_message ("another secret service is running");
			break;
		default:
			g_return_val_if_reached (FALSE);
			break;
		};
	}

	g_return_val_if_fail (!secrets_service, FALSE);
	secrets_service = g_object_new (GKD_SECRET_TYPE_SERVICE,
	                                "connection", dbus_conn, "pkcs11-slot", slot, NULL);

	g_object_unref (slot);
	return TRUE;
}

static void
cleanup_dbus_conn (gpointer unused)
{
	g_assert (dbus_conn);
	g_clear_object (&dbus_conn);
}

void
gkd_dbus_secrets_init (GDBusConnection *conn)
{
	dbus_conn = g_object_ref (conn);
	egg_cleanup_register (cleanup_dbus_conn, NULL);
}

void
gkd_dbus_secrets_cleanup (GDBusConnection *conn)
{
	if (secrets_service) {
		g_object_run_dispose (G_OBJECT (secrets_service));
		g_object_unref (secrets_service);
		secrets_service = NULL;
	}
}
