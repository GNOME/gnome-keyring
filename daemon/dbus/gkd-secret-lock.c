/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
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

#include "config.h"

#include "gkd-secret-lock.h"
#include "gkd-secret-service.h"

#include "egg/egg-error.h"

#include "pkcs11/pkcs11i.h"

#include <gck/gck.h>

gboolean
gkd_secret_lock (GckObject *collection,
                 GError **error_out)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GError *error = NULL;
	GList *objects, *l;
	GckSession *session;

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_CREDENTIAL);
	gck_builder_add_ulong (&builder, CKA_G_OBJECT, gck_object_get_handle (collection));

	session = gck_object_get_session (collection);
	g_return_val_if_fail (session, FALSE);

	objects = gck_session_find_objects (session, gck_builder_end (&builder), NULL, &error);

	g_object_unref (session);

	if (error != NULL) {
		g_warning ("couldn't search for credential objects: %s", egg_error_message (error));
                g_set_error_literal (error_out, G_DBUS_ERROR,
                                     G_DBUS_ERROR_FAILED,
                                     "Couldn't lock collection");
		g_clear_error (&error);
		return FALSE;
	}

	for (l = objects; l; l = g_list_next (l)) {
		if (!gck_object_destroy (l->data, NULL, &error)) {
			g_warning ("couldn't destroy credential object: %s", egg_error_message (error));
			g_clear_error (&error);
		}
	}

	gck_list_unref_free (objects);
	return TRUE;
}

gboolean
gkd_secret_lock_all (GckSession *session,
                     GError **error_out)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GError *error = NULL;
	GList *objects, *l;

	/* Lock all the main collections */
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_CREDENTIAL);
	gck_builder_add_boolean (&builder, CKA_GNOME_TRANSIENT, TRUE);

	objects = gck_session_find_objects (session, gck_builder_end (&builder), NULL, &error);
	if (error != NULL) {
		g_warning ("couldn't search for credential objects: %s", egg_error_message (error));
                g_set_error (error_out, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Couldn't lock service");
		g_clear_error (&error);
		return FALSE;
	}

	for (l = objects; l; l = g_list_next (l)) {
		if (!gck_object_destroy (l->data, NULL, &error)) {
			g_warning ("couldn't destroy credential object: %s", egg_error_message (error));
			g_clear_error (&error);
		}
	}

	/* Now delete all session objects */
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
	gck_builder_add_string (&builder, CKA_G_COLLECTION, "session");

	objects = gck_session_find_objects (session, gck_builder_end (&builder), NULL, &error);
	if (error != NULL) {
		g_warning ("couldn't search for session items: %s", egg_error_message (error));
                g_set_error (error_out, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Couldn't lock service");
		g_clear_error (&error);
		return FALSE;
	}

	for (l = objects; l; l = g_list_next (l)) {
		if (!gck_object_destroy (l->data, NULL, &error)) {
			g_warning ("couldn't destroy session item: %s", egg_error_message (error));
			g_clear_error (&error);
		}
	}

	gck_list_unref_free (objects);
	return TRUE;
}
