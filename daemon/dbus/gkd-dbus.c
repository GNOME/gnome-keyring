/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus.c - hook into dbus, call other bits

   Copyright (C) 2007, 2009, Stefan Walter

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

#include "gkd-daemon-generated.h"
#include "gkd-dbus.h"
#include "gkd-dbus-private.h"

#include "daemon/gkd-main.h"
#include "daemon/gkd-util.h"

#include "egg/egg-cleanup.h"

#include <glib.h>
#include <glib-unix.h>
#include <gio/gio.h>
#include <errno.h>

static GDBusConnection *dbus_conn = NULL;
static gboolean object_registered = FALSE;
static gboolean acquired_asked = FALSE;
static gboolean acquired_service = FALSE;

#define GNOME_KEYRING_DAEMON_SERVICE    "org.gnome.keyring"
#define GNOME_KEYRING_DAEMON_PATH       "/org/gnome/keyring/daemon"
#define GNOME_KEYRING_DAEMON_INTERFACE  "org.gnome.keyring.Daemon"

static void
cleanup_session_bus (gpointer unused)
{
	if (!dbus_conn)
		return;

	g_clear_object (&dbus_conn);
}

static void
on_connection_close (gpointer user_data)
{
	g_debug ("dbus connection closed, exiting");
	gkd_main_quit ();
}

static gboolean
connect_to_session_bus (void)
{
	GError *error = NULL;

	if (dbus_conn)
		return TRUE;

	dbus_conn = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
	if (!dbus_conn) {
		g_message ("couldn't connect to dbus session bus: %s", error->message);
		g_error_free (error);
		return FALSE;
	}

	g_signal_connect (dbus_conn, "closed",
			  G_CALLBACK (on_connection_close), NULL);
	egg_cleanup_register (cleanup_session_bus, NULL);
	return TRUE;
}

static gboolean
handle_get_environment (GkdExportedDaemon *skeleton,
			GDBusMethodInvocation *invocation,
			gpointer user_data)
{
	const gchar **env;
	gchar **parts;
	GVariantBuilder builder;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));

	for (env = gkd_util_get_environment (); *env != NULL; env++) {
		parts = g_strsplit (*env, "=", 2);
		g_variant_builder_add (&builder, "{ss}", parts[0], parts[1]);
		g_strfreev (parts);
	}

	gkd_exported_daemon_complete_get_environment (skeleton, invocation,
						      g_variant_builder_end (&builder));
	return TRUE;
}

static gboolean
handle_get_control_directory (GkdExportedDaemon *skeleton,
			      GDBusMethodInvocation *invocation,
			      gpointer user_data)
{
	gkd_exported_daemon_complete_get_control_directory (skeleton, invocation,
							    gkd_util_get_master_directory ());
	return TRUE;
}

typedef struct _GkdSecretsHelper {
	gboolean ready;
	gchar name[1024];
	GPid pid;
	gint input;
	gint output;
	guint output_id;
	guint child_id;
	guint timeout_id;
	guint name_watch_id;
} GkdSecretsHelper;

static GList *helpers = NULL;
static GMutex helpers_lock;

static void
cleanup_secrets_helper (GkdSecretsHelper *helper)
{
	int status;

	if (helper->timeout_id > 0) {
		g_source_remove (helper->timeout_id);
		helper->timeout_id = 0;
	}

	if (helper->child_id > 0) {
		g_source_remove (helper->child_id);
		helper->child_id = 0;
	}

	if (helper->output_id > 0) {
		g_source_remove (helper->output_id);
		helper->output_id = 0;
	}

	if (helper->input > 0) {
		close (helper->input);
		helper->input = 0;
	}

	if (helper->output > 0) {
		close (helper->output);
		helper->output = 0;
	}

	if (helper->pid > 0) {
		waitpid (helper->pid, &status, 0);
		g_spawn_close_pid (helper->pid);
		helper->pid = 0;
	}
}

static void
free_secrets_helper (GkdSecretsHelper *helper)
{
	cleanup_secrets_helper (helper);
	g_free (helper);
}

static void
on_child_watch (GPid pid,
                gint status,
                gpointer user_data)
{
	GkdSecretsHelper *helper = user_data;
	GError *error = NULL;

	if (pid != helper->pid)
		return;

	helper->pid = 0;
	helper->output_id = 0;
	helper->child_id = 0;

	if (!g_spawn_check_exit_status (status, &error)) {
		g_message ("gkd-secrets-helper: %s", error->message);
		g_error_free (error);
	}

	g_spawn_close_pid (pid);
}

static gboolean
on_output_watch (gint fd,
		 GIOCondition condition,
		 gpointer user_data)
{
	GkdSecretsHelper *helper = user_data;
	guint8 buf[1024];
	gssize len;

	if (condition & G_IO_IN) {
		guint8 *p;

		len = read (fd, buf, sizeof (buf));
		if (len < 0) {
			if (errno != EAGAIN && errno != EINTR)
				g_message ("couldn't read from gkd-secrets-helper: %m");
			condition |= G_IO_ERR;
		}
		p = memchr (buf, '\n', len);
		if (p) {
			helper->ready = TRUE;
			memcpy (helper->name, buf, p - buf);
			helper->name[p - buf] = '\0';
		}
	}

	if (condition & G_IO_HUP || condition & G_IO_ERR)
		return FALSE;

	return TRUE;
}

static gboolean
on_timeout (gpointer user_data)
{
	GkdSecretsHelper *helper = user_data;

	cleanup_secrets_helper (helper);

	return TRUE;
}

static void
on_sender_vanished (GDBusConnection *connection,
		    const gchar *name,
		    gpointer user_data)
{
	GkdSecretsHelper *helper = user_data;

	cleanup_secrets_helper (helper);
}

static void
child_setup (gpointer user_data)
{
	close (STDERR_FILENO);
}

static gboolean
handle_create_secret_service (GkdExportedDaemon *skeleton,
			      GDBusMethodInvocation *invocation,
			      const gchar *arg_KeyringDirectory,
			      gpointer user_data)
{
	const gchar *argv[] = { GKD_SECRETS_HELPER, arg_KeyringDirectory, NULL };
	GkdSecretsHelper *helper;
	GError *error = NULL;

	helper = g_new0 (GkdSecretsHelper, 1);

	if (!g_spawn_async_with_pipes ("/", (gchar **)argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                               child_setup, NULL, &helper->pid, NULL, &helper->output, NULL, &error)) {
		g_dbus_method_invocation_return_gerror (invocation, error);
		g_clear_error (&error);
		g_free (helper);
		return FALSE;
	}

	helper->output_id = g_unix_fd_add (helper->output,
					  G_IO_IN | G_IO_HUP | G_IO_ERR,
					  on_output_watch, helper);
	helper->child_id = g_child_watch_add (helper->pid, on_child_watch, helper);
	helper->timeout_id = g_timeout_add_seconds (5, on_timeout, helper);

	while (!helper->ready && helper->timeout_id > 0)
		g_main_context_iteration (NULL, FALSE);
	g_source_remove (helper->timeout_id);

	if (!helper->ready) {
		g_set_error (&error, G_IO_ERROR, G_IO_ERROR_FAILED,
			     "gkd-secrets-helper process is not ready");
		g_dbus_method_invocation_return_gerror (invocation, error);
		g_clear_error (&error);
		cleanup_secrets_helper (helper);
		g_free (helper);
		return FALSE;
	}

	helper->name_watch_id = g_bus_watch_name_on_connection (g_dbus_method_invocation_get_connection (invocation),
								g_dbus_method_invocation_get_sender (invocation),
								G_BUS_NAME_WATCHER_FLAGS_NONE,
								NULL,
								on_sender_vanished,
								helper,
								(GDestroyNotify)cleanup_secrets_helper);

	gkd_exported_daemon_complete_create_secret_service (skeleton, invocation,
							    helper->name);

	g_mutex_lock (&helpers_lock);
	helpers = g_list_append (helpers, helper);
	g_mutex_unlock (&helpers_lock);

	return TRUE;
}

static void
cleanup_singleton (gpointer user_data)
{
	GkdExportedDaemon *skeleton = user_data;

	g_return_if_fail (dbus_conn);
	if (object_registered) {
		g_dbus_interface_skeleton_unexport_from_connection (G_DBUS_INTERFACE_SKELETON (skeleton), dbus_conn);
		g_object_unref (skeleton);
	}
	object_registered = FALSE;

	g_mutex_lock (&helpers_lock);
	g_list_free_full (helpers, (GDestroyNotify)free_secrets_helper);
	g_mutex_unlock (&helpers_lock);
}

gboolean
gkd_dbus_singleton_acquire (gboolean *acquired)
{
	const gchar *service = NULL;
	GBusNameOwnerFlags flags = G_BUS_NAME_OWNER_FLAGS_NONE;
	GVariant *acquire_variant;
	guint res;
	GError *error = NULL;
	GkdExportedDaemon *skeleton;

	g_assert (acquired);

	if (!connect_to_session_bus ())
		return FALSE;

	/* First register the object */
	if (!object_registered) {
		skeleton = gkd_exported_daemon_skeleton_new ();

		g_signal_connect (skeleton, "handle-get-control-directory",
				  G_CALLBACK (handle_get_control_directory), NULL);
		g_signal_connect (skeleton, "handle-get-environment",
				  G_CALLBACK (handle_get_environment), NULL);
		g_signal_connect (skeleton, "handle-create-secret-service",
				  G_CALLBACK (handle_create_secret_service), NULL);

		g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (skeleton), dbus_conn,
						  GNOME_KEYRING_DAEMON_PATH, &error);

		if (error == NULL) {
			object_registered = TRUE;
			egg_cleanup_register (cleanup_singleton, skeleton);
		} else {
			g_message ("couldn't register dbus object path: %s", error->message);
			g_clear_error (&error);
		}
	}

	/* Try and grab our name */
	if (!acquired_asked) {
#ifdef WITH_DEBUG
		service = g_getenv ("GNOME_KEYRING_TEST_SERVICE");
		if (service && service[0])
			flags = G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT | G_BUS_NAME_OWNER_FLAGS_REPLACE;
		else
#endif
			service = GNOME_KEYRING_DAEMON_SERVICE;

		/* attempt to acquire the name */
		acquire_variant = g_dbus_connection_call_sync (dbus_conn,
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
			g_message ("couldn't request name '%s' on session bus: %s", service, error->message);
			g_error_free (error);
			return FALSE;
		}

		acquired_asked = TRUE;
		g_variant_get (acquire_variant, "(u)", &res);
		g_variant_unref (acquire_variant);

		switch (res) {
		/* We acquired the service name */
		case 1: /* DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER */
		case 4: /* DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER */
		       acquired_service = TRUE;
		       break;
		/* Another daemon is running */
		case 2: /* DBUS_REQUEST_NAME_REPLY_IN_QUEUE */
		case 3: /* DBUS_REQUEST_NAME_REPLY_EXISTS */
		       acquired_service = FALSE;
		       break;
		default:
		       acquired_service = FALSE;
		       g_return_val_if_reached (FALSE);
		       break;
	       };
	}

	*acquired = acquired_service;

	return TRUE;
}

gchar*
gkd_dbus_singleton_control (void)
{
	gchar *control = NULL;
	GError *error = NULL;
	GVariant *control_variant;

	/* If tried to aquire the service must have failed */
	g_return_val_if_fail (!acquired_service, NULL);

	if (!connect_to_session_bus ())
		return NULL;

	control_variant = g_dbus_connection_call_sync (dbus_conn,
						       GNOME_KEYRING_DAEMON_SERVICE,
						       GNOME_KEYRING_DAEMON_PATH,
						       GNOME_KEYRING_DAEMON_INTERFACE,
						       "GetControlDirectory",
						       NULL, NULL,
						       G_DBUS_CALL_FLAGS_NO_AUTO_START,
						       1000, NULL, &error);

	if (error != NULL) {
		if (!g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_NAME_HAS_NO_OWNER))
			g_message ("couldn't communicate with already running daemon: %s", error->message);
		g_error_free (error);
		return NULL;
	}

	g_variant_get (control_variant, "(s)", &control);
	g_variant_unref (control_variant);

	return control;
}

static void
dbus_cleanup (gpointer unused)
{
	g_return_if_fail (dbus_conn);
	gkd_dbus_secrets_cleanup (dbus_conn);
	gkd_dbus_session_cleanup (dbus_conn);
	gkd_dbus_environment_cleanup (dbus_conn);
	g_mutex_clear (&helpers_lock);
}

gboolean
gkd_dbus_setup (void)
{
	gboolean unused;

	if (!connect_to_session_bus ())
		return FALSE;

	/* Our singleton, and internal service API */
	gkd_dbus_singleton_acquire (&unused);

	/* Session stuff */
	gkd_dbus_environment_init (dbus_conn);
	gkd_dbus_session_init (dbus_conn);

	/* Secrets API */
	gkd_dbus_secrets_init (dbus_conn);
	g_mutex_init (&helpers_lock);

	egg_cleanup_register (dbus_cleanup, NULL);
	return TRUE;
}
