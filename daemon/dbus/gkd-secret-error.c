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

static const GDBusErrorEntry gkd_secret_error_entries[] = {
        { GKD_SECRET_ERROR_ALREADY_EXISTS, SECRET_INTERFACE_PREFIX "Error.AlreadyExists" },
        { GKD_SECRET_ERROR_IS_LOCKED, SECRET_INTERFACE_PREFIX "Error.IsLocked" },
        { GKD_SECRET_ERROR_NO_SESSION, SECRET_INTERFACE_PREFIX "Error.NoSession" },
        { GKD_SECRET_ERROR_NO_SUCH_OBJECT, SECRET_INTERFACE_PREFIX "Error.NoSuchObject" }
};

GQuark
gkd_secret_error_quark (void)
{
        static volatile gsize quark_volatile = 0;

        g_dbus_error_register_error_domain ("gkd_secret_error",
                                            &quark_volatile,
                                            gkd_secret_error_entries,
                                            G_N_ELEMENTS (gkd_secret_error_entries));
        return quark_volatile;
}

static const GDBusErrorEntry gkd_secret_daemon_error_entries[] = {
	{ GKD_SECRET_DAEMON_ERROR_DENIED, "org.gnome.keyring.Error.Denied" }
};

GQuark
gkd_secret_daemon_error_quark (void)
{
        static volatile gsize quark_volatile = 0;

        g_dbus_error_register_error_domain ("gkd_secret_daemon_error",
                                            &quark_volatile,
                                            gkd_secret_daemon_error_entries,
                                            G_N_ELEMENTS (gkd_secret_daemon_error_entries));
        return quark_volatile;
}

void
gkd_secret_propagate_error (GDBusMethodInvocation *invocation,
                            const gchar *description,
                            GError *error)
{
	g_return_if_fail (error != NULL);

	if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN) ||
	    g_error_matches (error, GCK_ERROR, CKR_PIN_INCORRECT)) {
		g_dbus_method_invocation_return_error_literal (invocation,
                                                               GKD_SECRET_DAEMON_ERROR,
							       GKD_SECRET_DAEMON_ERROR_DENIED,
							       "The password was invalid");
	} else if (g_error_matches (error, GCK_ERROR, CKR_WRAPPED_KEY_INVALID) ||
	           g_error_matches (error, GCK_ERROR, CKR_WRAPPED_KEY_LEN_RANGE) ||
	           g_error_matches (error, GCK_ERROR, CKR_MECHANISM_PARAM_INVALID)) {
		g_dbus_method_invocation_return_error_literal (invocation,
                                                               G_DBUS_ERROR,
                                                               G_DBUS_ERROR_INVALID_ARGS,
                                                               "The secret was transferred or encrypted in an invalid way.");
	} else {
		g_warning ("%s: %s", description, egg_error_message (error));
		g_dbus_method_invocation_return_error_literal (invocation,
                                                               G_DBUS_ERROR,
                                                               G_DBUS_ERROR_FAILED,
							       description);
	}

	g_error_free (error);
}
