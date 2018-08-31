/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2018 Red Hat, Inc.
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

static CK_FUNCTION_LIST_PTR pkcs11_roof;
static GkdSecretService *service;
static GDBusConnection *connection = NULL;

static void
pkcs11_cleanup (gpointer unused)
{
	CK_RV rv;

	if (pkcs11_roof) {
		rv = (pkcs11_roof->C_Finalize) (NULL);

		if (rv != CKR_OK)
			g_warning ("couldn't finalize internal PKCS#11 stack (code: %d)", (gint)rv);
	}
	g_clear_object (&service);
	g_clear_object (&connection);
}

static gboolean
pkcs11_initialize (const gchar *path)
{
	CK_FUNCTION_LIST_PTR secret_store;
	CK_C_INITIALIZE_ARGS init_args;
	CK_RV rv;
	GckSlot *slot = NULL;
	GckModule *module = NULL;
	GList *modules = NULL;
	GError *error = NULL;

	/* Secrets */
	secret_store = gkm_secret_store_get_functions ();

	/* Add all of those into the wrapper layer */
	gkm_wrap_layer_add_module (secret_store);

	pkcs11_roof = gkm_wrap_layer_get_functions ();

	memset (&init_args, 0, sizeof (init_args));
	init_args.flags = CKF_OS_LOCKING_OK;
	init_args.pReserved = g_strdup_printf ("directory=\"%s\"", path);

	/* Initialize the whole caboodle */
	rv = (pkcs11_roof->C_Initialize) (&init_args);
	g_free (init_args.pReserved);

	if (rv != CKR_OK) {
		g_warning ("couldn't initialize internal PKCS#11 stack (code: %d)", (gint)rv);
		goto cleanup;
	}

	module = gck_module_new (pkcs11_roof);
	if (!module)
		goto cleanup;

	modules = g_list_prepend (NULL, module);
	module = NULL;
	slot = gck_modules_token_for_uri (modules,
					  "pkcs11:token=Secret%20Store", &error);
	if (!slot) {
		g_warning ("couldn't find secret store: %s",
			   egg_error_message (error));
		g_clear_error (&error);
		goto cleanup;
	}
	gck_list_unref_free (modules);

	connection = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
	if (!connection) {
		g_warning ("couldn't connect to session bus: %s",
			   egg_error_message (error));
		g_clear_error (&error);
		goto cleanup;
	}
	g_print ("%s\n", g_dbus_connection_get_unique_name (connection));

	service = g_object_new (GKD_SECRET_TYPE_SERVICE,
				"connection", connection,
				"pkcs11-slot", slot,
				NULL);
	g_object_unref (connection);
	g_object_unref (slot);

	egg_cleanup_register (pkcs11_cleanup, NULL);

	return TRUE;

 cleanup:

	gck_list_unref_free (modules);
	g_clear_object (&module);
	g_clear_object (&slot);
	g_clear_object (&service);
	g_clear_object (&connection);

	return FALSE;
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;

	if (argc != 2) {
		g_printerr ("gkd-secrets-helper PATH\n");
		return 1;
	}

	if (!pkcs11_initialize (argv[1]))
		return 1;

	loop = g_main_loop_new (NULL, FALSE);
	g_unix_fd_add (STDIN_FILENO, G_IO_IN | G_IO_HUP | G_IO_ERR, g_main_loop_quit, loop);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	return 0;
}
