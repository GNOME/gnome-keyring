/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "egg/egg-cleanup.h"
#include "egg/egg-error.h"

#include "gkd-dbus.h"
#include "gkd-secret-service.h"

#include "pkcs11/wrap-layer/gkm-wrap-layer.h"
#include "pkcs11/secret-store/gkm-secret-store.h"

#include <string.h>
#include <gck/gck.h>

static void
pkcs11_cleanup (gpointer data)
{
	CK_FUNCTION_LIST_PTR pkcs11_roof = data;
	CK_RV rv;

	g_assert (pkcs11_roof);

	rv = (pkcs11_roof->C_Finalize) (NULL);

	if (rv != CKR_OK)
		g_warning ("couldn't finalize internal PKCS#11 stack (code: %d)", (gint)rv);
}

static gboolean
pkcs11_initialize (const gchar *app_id)
{
	CK_FUNCTION_LIST_PTR secret_store;
	CK_FUNCTION_LIST_PTR pkcs11_roof;
	CK_C_INITIALIZE_ARGS init_args;
	CK_RV rv;
	GckSlot *slot = NULL;
	GckModule *module;
	GList *modules;
	GkdSecretService *service;
	GError *error = NULL;
	GDBusConnection *connection;
	gchar *path;

	/* Secrets */
	secret_store = gkm_secret_store_get_functions ();

	/* Add all of those into the wrapper layer */
	gkm_wrap_layer_add_module (secret_store);

	pkcs11_roof = gkm_wrap_layer_get_functions ();

	memset (&init_args, 0, sizeof (init_args));
	init_args.flags = CKF_OS_LOCKING_OK;
	path = g_build_filename (g_get_user_data_dir (), "keyrings", app_id, NULL);
	init_args.pReserved = g_strdup_printf ("directory=\"%s\"", path);
	g_free (path);

	/* Initialize the whole caboodle */
	rv = (pkcs11_roof->C_Initialize) (&init_args);
	g_free (init_args.pReserved);

	if (rv != CKR_OK) {
		g_warning ("couldn't initialize internal PKCS#11 stack (code: %d)", (gint)rv);
		return FALSE;
	}

	egg_cleanup_register (pkcs11_cleanup, NULL);

	module = gck_module_new (pkcs11_roof);
	g_return_val_if_fail (module, FALSE);

	modules = g_list_prepend (NULL, module);
	slot = gck_modules_token_for_uri (modules,
					  "pkcs11:token=Secret%20Store", &error);
	gck_list_unref_free (modules);
	if (!slot) {
		g_warning ("couldn't find secret store: %s",
			   egg_error_message (error));
		g_clear_error (&error);
		return FALSE;
	}

	connection = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
	if (!connection) {
		g_warning ("couldn't connect to session bus: %s",
			   egg_error_message (error));
		g_clear_error (&error);
		return FALSE;
	}
	g_print ("%s\n", g_dbus_connection_get_unique_name (connection));

	service = g_object_new (GKD_SECRET_TYPE_SERVICE,
				"connection", connection,
				"pkcs11-slot", slot,
				NULL);

	egg_cleanup_register (g_object_unref, service);
	egg_cleanup_register (g_object_unref, connection);

	return TRUE;
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;

	if (argc != 2) {
		g_printerr ("gkd-secrets-helper APP-ID\n");
		return 1;
	}

	if (!pkcs11_initialize (argv[1]))
		return 1;

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	return 0;
}
