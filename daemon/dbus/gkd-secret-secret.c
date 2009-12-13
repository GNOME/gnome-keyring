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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "gkd-secret-secret.h"

#include "egg/egg-secure-memory.h"

#include <string.h>

static void
destroy_with_owned_memory (gpointer data)
{
	GkdSecretSecret *secret = data;
	g_free (secret->path);
	g_free (secret->caller);
	g_free (secret->parameter);
	g_free (secret->value);
}

GkdSecretSecret*
gkd_secret_secret_new_take_memory (const gchar *path, const gchar *caller,
                                   gpointer parameter, gsize n_parameter,
                                   gpointer value, gsize n_value)
{
	GkdSecretSecret *secret;

	g_return_val_if_fail (path, NULL);
	g_return_val_if_fail (caller, NULL);

	secret = g_slice_new0 (GkdSecretSecret);
	secret->path = g_strdup (path);
	secret->caller = g_strdup (caller);
	secret->parameter = parameter;
	secret->n_parameter = n_parameter;
	secret->value = value;
	secret->n_value = n_value;

	secret->destroy_func = destroy_with_owned_memory;
	secret->destroy_data = secret;

	return secret;
}

GkdSecretSecret*
gkd_secret_secret_parse (DBusMessage *message, DBusMessageIter *iter)
{
	GkdSecretSecret *secret;
	DBusMessageIter struc, array;
	void *parameter, *value;
	int n_value, n_parameter;
	char *path;

	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRUCT, NULL);
	dbus_message_iter_recurse (iter, &struc);

	/* Get the path */
	if (dbus_message_iter_get_arg_type (&struc) != DBUS_TYPE_OBJECT_PATH)
		return NULL;
	dbus_message_iter_get_basic (&struc, &path);

	/* Get the parameter */
	if (!dbus_message_iter_next (&struc) ||
	    dbus_message_iter_get_arg_type (&struc) != DBUS_TYPE_ARRAY ||
	    dbus_message_iter_get_element_type(&struc) != DBUS_TYPE_BYTE)
		return NULL;
	dbus_message_iter_recurse (&struc, &array);
	dbus_message_iter_get_fixed_array (&array, &parameter, &n_parameter);

	/* Get the value */
	if (!dbus_message_iter_next (&struc) ||
	    dbus_message_iter_get_arg_type (&struc) != DBUS_TYPE_ARRAY ||
	    dbus_message_iter_get_element_type(&struc) != DBUS_TYPE_BYTE)
		return NULL;
	dbus_message_iter_recurse (&struc, &array);
	dbus_message_iter_get_fixed_array (&array, &value, &n_value);

	secret = g_slice_new0 (GkdSecretSecret);
	secret->path = path;
	secret->caller = (char*)dbus_message_get_sender (message);
	secret->parameter = parameter;
	secret->n_parameter = n_parameter;
	secret->value = value;
	secret->n_value = n_value;

	/* All the memory is owned by the message */
	secret->destroy_data = dbus_message_ref (message);
	secret->destroy_func = (GDestroyNotify)dbus_message_unref;
	return secret;
}

void
gkd_secret_secret_append (GkdSecretSecret *secret, DBusMessageIter *iter)
{
	DBusMessageIter struc, array;
	int length;

	dbus_message_iter_open_container (iter, DBUS_TYPE_STRUCT, NULL, &struc);
	dbus_message_iter_append_basic (&struc, DBUS_TYPE_OBJECT_PATH, &(secret->path));
	dbus_message_iter_open_container (&struc, DBUS_TYPE_ARRAY, "y", &array);
	length = secret->n_parameter;
	dbus_message_iter_append_fixed_array (&array, DBUS_TYPE_BYTE, &(secret->parameter), length);
	dbus_message_iter_close_container (&struc, &array);
	dbus_message_iter_open_container (&struc, DBUS_TYPE_ARRAY, "y", &array);
	length = secret->n_value;
	dbus_message_iter_append_fixed_array (&array, DBUS_TYPE_BYTE, &(secret->value), length);
	dbus_message_iter_close_container (&struc, &array);
	dbus_message_iter_close_container (iter, &struc);
}

void
gkd_secret_secret_free (gpointer data)
{
	GkdSecretSecret *secret;

	if (!data)
		return;

	secret = data;

	/*
	 * These are not usually actual plain text secrets. However in
	 * the case that they are, we want to clear them from memory.
	 *
	 * This is not foolproof in any way. If they're plaintext, they would
	 * have been sent over DBus, and through all sorts of processes.
	 */

	egg_secure_clear (secret->parameter, secret->n_parameter);
	egg_secure_clear (secret->value, secret->n_value);

	/* Call the destructor of memory */
	if (secret->destroy_func)
		(secret->destroy_func) (secret->destroy_data);

	g_slice_free (GkdSecretSecret, secret);
}
