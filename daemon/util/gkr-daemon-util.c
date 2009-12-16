/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-daemon-util.c - Helper utilities for the daemon

   Copyright (C) 2007, Stefan Walter

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-daemon-async.h"
#include "gkr-daemon-util.h"

#include "egg/egg-cleanup.h"
#include "egg/egg-mkdtemp.h"
#include "egg/egg-unix-credentials.h"

#include <glib.h>

#include <sys/stat.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
	PROP_0,
	PROP_PID,
	PROP_APP_PATH,
	PROP_APP_DISPLAY
};

enum {
	DISCONNECTED,
	LAST_SIGNAL
};

G_DEFINE_TYPE (GkrDaemonClient, gkr_daemon_client, G_TYPE_OBJECT);

static guint signals[LAST_SIGNAL] = { 0 };

static GkrDaemonAsyncPrivate *current_client = NULL;

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void
unregister_client (gpointer data)
{
	g_assert (GKR_IS_DAEMON_CLIENT (data));
	g_signal_emit (data, signals[DISCONNECTED], 0);
	g_object_unref (data);
}

static void
register_client (GkrDaemonClient *client)
{
	g_assert (GKR_IS_DAEMON_CLIENT (client));
	g_assert (current_client);
	gkr_daemon_async_private_set (current_client, client);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_daemon_client_init (GkrDaemonClient *obj)
{

}

static void
gkr_daemon_client_get_property (GObject *obj, guint prop_id, GValue *value, 
                                GParamSpec *pspec)
{
	GkrDaemonClient *client = GKR_DAEMON_CLIENT (obj);

	switch (prop_id) {
	case PROP_PID:
		g_value_set_uint (value, client->pid);
		break;
	case PROP_APP_PATH:
		g_value_set_string (value, client->app_path);
		break;
	case PROP_APP_DISPLAY:
		g_value_set_string (value, client->app_display);
		break;
	}
}

static void
gkr_daemon_client_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                GParamSpec *pspec)
{
	GkrDaemonClient *client = GKR_DAEMON_CLIENT (obj);

	switch (prop_id) {
	case PROP_PID:
		g_return_if_fail (!client->pid);
		client->pid = g_value_get_uint (value);
		break;
	case PROP_APP_PATH:
		g_return_if_fail (!client->app_path);
		client->app_path = g_value_dup_string (value);
		break;
	case PROP_APP_DISPLAY:
		g_free (client->app_display);
		client->app_display = g_value_dup_string (value);
		break;
	}
}

static void
gkr_daemon_client_finalize (GObject *obj)
{
	GkrDaemonClient *client = GKR_DAEMON_CLIENT (obj);
	 
	if (client->app_path)
		g_free (client->app_path);
	if (client->app_display)
		g_free (client->app_display);
	
	G_OBJECT_CLASS (gkr_daemon_client_parent_class)->finalize (obj);
}

static void
gkr_daemon_client_class_init (GkrDaemonClientClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*) klass;
	gkr_daemon_client_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->get_property = gkr_daemon_client_get_property;
	gobject_class->set_property = gkr_daemon_client_set_property;
	gobject_class->finalize = gkr_daemon_client_finalize;

	g_object_class_install_property (gobject_class, PROP_PID,
		g_param_spec_uint ("pid", "Process ID", "Process ID of client",
		                   0, G_MAXUINT, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
		                   
	g_object_class_install_property (gobject_class, PROP_APP_PATH,
		g_param_spec_string ("app-path", "Application Path", "Client application path",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
		                     
	g_object_class_install_property (gobject_class, PROP_APP_DISPLAY,
		g_param_spec_string ("app-display", "Application Display Name", "Client application display name",
		                     NULL, G_PARAM_READWRITE));
		                     
	signals[DISCONNECTED] = g_signal_new ("disconnected", GKR_TYPE_DAEMON_CLIENT, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrDaemonClientClass, disconnected),
			NULL, NULL, g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);
	
	current_client = gkr_daemon_async_private_new (unregister_client);
}

/* -------------------------------------------------------------------------------------
 * PUBLIC STUFF
 */

GkrDaemonClient*
gkr_daemon_client_set_current (pid_t pid, const gchar *app_path, const gchar *app_display)
{
	GkrDaemonClient *client;
	char *path = NULL;
	
	/* Try and figure out the path from the pid */
	if (pid > 0 && !app_path)
		app_path = path = egg_unix_credentials_executable (pid);
	
	client = g_object_new (GKR_TYPE_DAEMON_CLIENT, "pid", pid, "app-path", app_path, 
	                       "app-display", app_display, NULL);
	
	register_client (client);
	free (path);
	
	return client;
}

GkrDaemonClient*
gkr_daemon_client_get_current (void)
{
	if (!current_client)
		return NULL;
	return gkr_daemon_async_private_get (current_client);
}

pid_t
gkr_daemon_client_get_app_pid (GkrDaemonClient* client)
{
	if (!client)
		client = gkr_daemon_client_get_current ();
	g_return_val_if_fail (GKR_IS_DAEMON_CLIENT (client), 0);
	return client->pid;
}

const gchar*
gkr_daemon_client_get_app_display (GkrDaemonClient* client)
{
	if (!client)
		client = gkr_daemon_client_get_current ();
	g_return_val_if_fail (GKR_IS_DAEMON_CLIENT (client), 0);
	return client->app_display;
}

const gchar*
gkr_daemon_client_get_app_path (GkrDaemonClient* client)
{
	if (!client)
		client = gkr_daemon_client_get_current ();
	g_return_val_if_fail (GKR_IS_DAEMON_CLIENT (client), 0);
	return client->app_path;
}

