/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-modules.c - the GObject PKCS#11 wrapper library

   Copyright (C) 2008, Stefan Walter

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

   Author: Stef Walter <nielsen@memberwebs.com>
*/

#include "config.h"

#include "gck.h"
#include "gck-private.h"
#include "gck-marshal.h"

#include <string.h>

/**
 * SECTION:gck-modules
 * @title: GckModule lists
 * @short_description: Dealing with lists of PKCS#11 modules.
 *
 * Xxxxx
 */

gchar**
gck_modules_list_registered_paths (GError **err)
{
	const gchar *name;
	gchar *path;
	GDir *dir;
	GArray *paths;

	g_return_val_if_fail (!err || !*err, NULL);

	dir = g_dir_open (PKCS11_REGISTRY_DIR, 0, err);
	if (dir == NULL)
		return NULL;

	paths = g_array_new (TRUE, TRUE, sizeof (gchar*));

	for (;;) {
		name = g_dir_read_name (dir);
		if (!name)
			break;

		path = g_build_filename (PKCS11_REGISTRY_DIR, name, NULL);
		if (g_file_test (path, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))
			g_array_append_val (paths, path);
		else
			g_free (path);
	}

	g_dir_close (dir);

	return (gchar**)g_array_free (paths, FALSE);
}

GList*
gck_modules_initialize_registered (guint options)
{
	GError *err = NULL;
	gchar **paths, **p;
	GckModule *module;
	GList *results = NULL;

	paths = gck_modules_list_registered_paths (&err);
	if (!paths && err) {
		g_warning ("couldn't list registered PKCS#11 module paths: %s",
		           err && err->message ? err->message : "");
		g_clear_error (&err);
		return NULL;
	}

	for (p = paths; *p; ++p) {
		module = gck_module_initialize (*p, NULL, 0, &err);
		if (module) {
			results = g_list_prepend (results, module);

		} else {
			g_warning ("couldn't load PKCS#11 module: %s: %s",
			           *p, err && err->message ? err->message : "");
			g_clear_error (&err);
		}
	}

	g_strfreev (paths);
	return results;
}

GList*
gck_modules_get_slots (GList *modules, gboolean token_present)
{
	GList *result = NULL;
	GList *m;

	for (m = modules; m; m = g_list_next (m)) {
		result = g_list_concat (result, gck_module_get_slots (m->data, token_present));
	}

	return result;
}

/**
 * gck_module_enumerate_objects_full:
 * @self: The module to enumerate objects.
 * @attrs: Attributes that the objects must have, or empty for all objects.
 * @session_flags: PKCS#11 flags for opening a session.
 * @cancellable: Optional cancellation object, or NULL.
 * @func: Function to call for each object.
 * @user_data: Data to pass to the function.
 * @error: Location to return error information.
 *
 * Call a function for every matching object on the module. This call may
 * block for an indefinite period.
 *
 * This function will open a session per slot. It's recommended that you
 * set the 'reuse-sessions' property on each slot if you'll be calling
 * it a lot.
 *
 * You can access the session in which the object was found, by using the
 * gck_object_get_session() function on the resulting objects.
 *
 * The function can return FALSE to stop the enumeration.
 *
 * Return value: If FALSE then an error prevented all matching objects from being enumerated.
 **/
gboolean
gck_modules_enumerate_objects (GList *modules, GckAttributes *attrs, guint session_flags,
                               GCancellable *cancellable, GckObjectForeachFunc func,
                               gpointer user_data, GError **err)
{
	gboolean stop = FALSE;
	gboolean ret = TRUE;
	GList *objects, *o;
	GList *slots, *l, *m;
	GError *error = NULL;
	GckSession *session;

	g_return_val_if_fail (attrs, FALSE);
	g_return_val_if_fail (func, FALSE);

	gck_attributes_ref (attrs);

	for (m = modules; ret && !stop && m; m = g_list_next (m)) {
		slots = gck_module_get_slots (m->data, TRUE);

		for (l = slots; ret && !stop && l; l = g_list_next (l)) {

			session = gck_slot_open_session (l->data, session_flags, &error);
			if (!session) {
				g_return_val_if_fail (error != NULL, FALSE);

				/* Ignore these errors when enumerating */
				if (g_error_matches (error, GCK_ERROR, CKR_USER_PIN_NOT_INITIALIZED)) {
					g_clear_error (&error);

				} else {
					ret = FALSE;
					g_propagate_error (err, error);
					error = NULL;
				}
				continue;
			}

			objects = gck_session_find_objects (session, attrs, cancellable, &error);
			if (error) {
				ret = FALSE;
				g_object_unref (session);
				g_propagate_error (err, error);
				error = NULL;
				continue;
			}

			for (o = objects; !stop && o; o = g_list_next (o)) {
				if (!(func)(o->data, user_data)) {
					stop = TRUE;
					break;
				}
			}

			g_object_unref (session);
			gck_list_unref_free (objects);
		}

		gck_list_unref_free (slots);
	}

	gck_attributes_unref (attrs);

	return ret;
}

/**
 * GckObjectForeachFunc:
 * @object: The enumerated object.
 * @user_data: Data passed to enumerate function.
 *
 * This function is passed to gck_module_enumerate_objects() or a similar function.
 * It is called once for each object matched.
 *
 * The GckSession through which the object is accessible can be retrieved by calling
 * gck_object_get_session() on object.
 *
 * Returns: TRUE to continue enumerating, FALSE to stop.
 */
