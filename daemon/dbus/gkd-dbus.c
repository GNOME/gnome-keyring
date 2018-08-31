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

struct SecretHelperData
{
	GPid pid;
	GMainLoop *loop;
	GIOChannel *channel;
	gchar *name;
	guint output_id;
	guint child_id;
	guint timeout_id;
};

static gboolean
on_secrets_helper_output (GIOChannel *source,
			  GIOCondition condition,
			  gpointer user_data)
{
	struct SecretHelperData *data = user_data;
	gchar *line;
	gsize terminator_pos;
	GError *error = NULL;

	if (g_io_channel_read_line (source, &line, NULL,
				    &terminator_pos, &error) ==
	    G_IO_STATUS_NORMAL) {
		line[terminator_pos] = '\0';
		data->name = line;
	}

	data->output_id = 0;
	g_main_loop_quit (data->loop);
	return FALSE;
}

static void
on_secrets_helper_child (GPid pid,
			 gint status,
			 gpointer user_data)
{
	struct SecretHelperData *data = user_data;

	g_spawn_close_pid (pid);
	if (data->output_id > 0)
		g_source_remove (data->output_id);
	if (data->timeout_id > 0)
		g_source_remove (data->timeout_id);

	data->child_id = 0;
	g_main_loop_quit (data->loop);
}

static gboolean
on_secrets_helper_timeout (gpointer user_data)
{
	struct SecretHelperData *data = user_data;

	kill (data->pid, SIGTERM);
	data->timeout_id = 0;
	g_main_loop_quit (data->loop);
	return FALSE;
}

static void
on_secrets_helper_peer_vanished (GDBusConnection *connection,
				 const gchar *name,
				 gpointer user_data)
{
	GPid pid = GPOINTER_TO_INT (user_data);
	kill (pid, SIGTERM);
}

static gboolean
handle_get_secret_service (GkdExportedDaemon *object,
			   GDBusMethodInvocation *invocation,
			   const gchar *arg_AppID)
{
	gchar *args[] = {
		GKD_SECRETS_HELPER,
		(gchar *) arg_AppID,
		NULL
	};
	gint standard_output;
	GError *error = NULL;
	struct SecretHelperData data;
	const gchar *sender;

	memset (&data, 0, sizeof (data));

	if (!g_spawn_async_with_pipes (NULL, args, NULL, G_SPAWN_DEFAULT, NULL,
				       NULL, &data.pid, NULL, &standard_output, NULL, &error)) {
		g_dbus_method_invocation_return_gerror (invocation, error);
		return FALSE;
	}

	data.loop = g_main_loop_new (NULL, FALSE);
	data.channel = g_io_channel_unix_new (standard_output);
	data.name = NULL;
	data.output_id = g_io_add_watch (data.channel, G_IO_IN, on_secrets_helper_output, &data);
	data.child_id = g_child_watch_add (data.pid, on_secrets_helper_child, &data);
	data.timeout_id = g_timeout_add (10000, on_secrets_helper_timeout, &data);

	g_main_loop_run (data.loop);

	if (data.output_id > 0)
		g_source_remove (data.output_id);
	if (data.child_id > 0)
		g_source_remove (data.child_id);
	if (data.timeout_id > 0)
		g_source_remove (data.timeout_id);

	g_main_loop_unref (data.loop);
	g_io_channel_unref (data.channel);

	if (data.name == NULL) {
		g_dbus_method_invocation_return_error (invocation,
						       G_IO_ERROR,
						       G_IO_ERROR_FAILED,
						       "couldn't launch gkd-secrets-service");
		return FALSE;
	}

	sender = g_dbus_method_invocation_get_sender (invocation);
	g_bus_watch_name_on_connection (g_dbus_method_invocation_get_connection (invocation),
					sender,
					G_BUS_NAME_WATCHER_FLAGS_NONE,
					NULL,
					on_secrets_helper_peer_vanished,
					GINT_TO_POINTER (data.pid),
					NULL);

	gkd_exported_daemon_complete_get_secret_service (object,
							 invocation,
							 data.name);
	g_free (data.name);
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

		g_signal_connect (skeleton, "handle-get-secret-service",
				  G_CALLBACK (handle_get_secret_service), NULL);

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

	egg_cleanup_register (dbus_cleanup, NULL);
	return TRUE;
}
