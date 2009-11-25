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

GkdSecretSecret*
gkd_secret_secret_create_and_take_memory (const gchar *path, gpointer parameter,
                                          gsize n_parameter, gpointer value,
                                          gsize n_value)
{
	GkdSecretSecret *secret;

	secret = g_slice_new0 (GkdSecretSecret);
	secret->path = g_strdup (path);
	secret->parameter = parameter;
	secret->n_parameter = n_parameter;
	secret->value = value;
	secret->n_value = n_value;
	return secret;
}

GkdSecretSecret*
gkd_secret_secret_parse (DBusMessageIter *iter)
{
	DBusMessageIter struc;
	const void *parameter, *value;
	int n_value, n_parameter;
	const char *path;

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
	dbus_message_iter_get_fixed_array (&struc, &parameter, &n_parameter);

	/* Get the value */
	if (!dbus_message_iter_next (&struc) ||
	    dbus_message_iter_get_arg_type (&struc) != DBUS_TYPE_ARRAY ||
	    dbus_message_iter_get_element_type(&struc) != DBUS_TYPE_BYTE)
		return NULL;
	dbus_message_iter_get_fixed_array (&struc, &value, &n_value);

	return gkd_secret_secret_create_and_take_memory (path,
	                                                 n_parameter ? g_memdup (parameter, n_parameter) : NULL,
	                                                 n_parameter,
	                                                 n_value ? g_memdup (value, n_value) : NULL,
	                                                 n_value);
}

void
gkd_secret_secret_append (GkdSecretSecret *secret, DBusMessageIter *iter)
{
	DBusMessageIter struc;
	int length;

	dbus_message_iter_open_container (iter, DBUS_TYPE_STRUCT, "oayay", &struc);
	dbus_message_iter_append_basic (iter, DBUS_TYPE_OBJECT_PATH, &(secret->path));
	length = secret->n_parameter;
	dbus_message_iter_append_fixed_array (iter, DBUS_TYPE_BYTE, &(secret->parameter), length);
	length = secret->n_value;
	dbus_message_iter_append_fixed_array (iter, DBUS_TYPE_BYTE, &(secret->value), length);
	dbus_message_iter_close_container (iter, &struc);
}

void
gkd_secret_secret_free (gpointer data)
{
	GkdSecretSecret *secret;

	if (!data)
		return;

	/*
	 * These are not usually actual plain text secrets. However in
	 * the case that they are, we want to clear them from memory.
	 *
	 * This is not foolproof in any way. If they're plaintext, they would
	 * have been sent over DBus, and through all sorts of processes.
	 */

	secret = data;
	g_free (secret->path);
	egg_secure_clear (secret->parameter, secret->n_parameter);
	g_free (secret->parameter);
	egg_secure_clear (secret->value, secret->n_value);
	g_free (secret->value);
	g_slice_free (GkdSecretSecret, secret);

}
