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

#include "gkd-secret-error.h"

#include "egg/egg-error.h"

#include <gck/gck.h>

#include <glib.h>

DBusMessage*
gkd_secret_error_no_such_object (DBusMessage *message)
{
	g_return_val_if_fail (message, NULL);
	return dbus_message_new_error_printf (message, SECRET_ERROR_NO_SUCH_OBJECT,
	                                      "The '%s' object does not exist", dbus_message_get_path (message));
}

DBusMessage*
gkd_secret_error_to_reply (DBusMessage *message, DBusError *derr)
{
	DBusMessage *reply;

	g_return_val_if_fail (message, NULL);
	g_return_val_if_fail (derr, NULL);
	g_return_val_if_fail (dbus_error_is_set (derr), NULL);

	reply = dbus_message_new_error (message, derr->name, derr->message);
	dbus_error_free (derr);
	return reply;
}

DBusMessage *
gkd_secret_propagate_error (DBusMessage *message,
                            const gchar *description,
                            GError *error)
{
	DBusError derr = DBUS_ERROR_INIT;

	g_return_val_if_fail (error != NULL, NULL);

	if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN) ||
	    g_error_matches (error, GCK_ERROR, CKR_PIN_INCORRECT)) {
		dbus_set_error (&derr, INTERNAL_ERROR_DENIED, "The password was invalid");

	} else if (g_error_matches (error, GCK_ERROR, CKR_WRAPPED_KEY_INVALID) ||
	           g_error_matches (error, GCK_ERROR, CKR_WRAPPED_KEY_LEN_RANGE) ||
	           g_error_matches (error, GCK_ERROR, CKR_MECHANISM_PARAM_INVALID)) {
		dbus_set_error_const (&derr, DBUS_ERROR_INVALID_ARGS,
		                      "The secret was transferred or encrypted in an invalid way.");

	} else {
		g_warning ("%s: %s", description, egg_error_message (error));
		dbus_set_error (&derr, DBUS_ERROR_FAILED, "Couldn't create new collection");
	}

	g_error_free (error);
	return gkd_secret_error_to_reply (message, &derr);
}
