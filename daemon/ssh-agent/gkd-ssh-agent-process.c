/*
 * Copyright (C) 2013 Red Hat Inc.
 *
 * Gnome keyring is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * Gnome keyring is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

gint
agent_start (const char *socket)
{
	gchar *argv[] = { SSH_AGENT, "-a", socket, NULL };
	gchar *standard_error = NULL;
	gchar *standard_output = NULL;
	GError *error = NULL;
	gint exit_status = 0;
	gint ret = 0;
	gchar *cmd;

	if (!g_spawn_sync ("/", argv, NULL, NULL, NULL, &standard_output,
	                   &standard_error, &exit_status, &error) ||
	    !g_spawn_check_exit_status (exit_status, NULL)) {
		cmd = g_strjoinv (" ", argv);
		if (error != NULL) {
			g_warning ("couldn't run: %s: %s", cmd, error->message);
			g_error_free (error);
		} else {
			g_warning ("failed to run: %s", cmd);
		}
		g_free (cmd);

	/* Sucessfully running, pull out the PID */
	} else {
		lines = g_strsplit (standard_output, "\n", -1);
		for (i = 0; lines[i] != NULL; i++) {
			g_strstrip (lines[i]);
			if (g_str_has_prefix (lines[i], "SSH_AGENT_PID=")) {
				pid = lines[i] + 16;
				pos = strchr (pid, ';');
				if (pos != NULL)
					pos[0] = '\0';
				ret = (int)strtol (pid, 10, &endptr);
				if (!endptr || endptr != '\0') {
					g_warning ("invalid pid received from ssh-agent: %s", pid);
					ret = 0;
				}
				break;
			}
		}
		g_strfreev (lines);
	}

	if (standard_error) {
		lines = g_strsplit (standard_error, "\n", -1);
		for (i = 0; lines[i] != NULL; i++)
			g_warning ("%s", g_strchomp (lines[0]));
		g_strfreev (lines);
	}

	g_free (standard_error);
	g_free (standard_output);
	return ret;
}

gboolean
agent_check (gint pid)
{
	return pid && (kill (pid, 0) == 0);
}

void
agent_terminate (gint pid)
{
	kill (pid, SIGTERM);
}

static gchar *
agent_make_path (void)
{
	const char *directory;

	directory = gkd_util_master_directory ();
}

G_LOCK (ssh_agent_process);
static gchar *ssh_agent_path = NULL;
static gint ssh_agent_pid;

GIOStream *
gkd_ssh_agent_process_connect (void)
{
	GSocketConnection *connection;
	GSocketAddress *address;
	const gchar *directory;
	GError *error = NULL;
	GSocket *sock;
	gboolean ready;

	G_LOCK (ssh_agent_process);

	if (ssh_agent_path) {
		directory = gkd_util_master_directory ();
		ssh_agent_path = g_build_filename (directory, "ssh-actual", NULL);
	}

	ready = agent_check (ssh_agent_pid);
	if (!ready) {
		ssh_agent_pid = agent_start (ssh_agent_path);
		ready = (ssh_agent_pid != 0);
	}

	G_UNLOCK (ssh_agent_pid);

	if (!ready)
		return NULL;

	sock = g_socket_new (G_SOCKET_FAMILY_UNIX, G_SOCKET_TYPE_STREAM,
	                     G_SOCKET_PROTOCOL_DEFAULT);
	g_return_val_if_fail (sock != NULL, NULL);

	connection = g_socket_connection_factory_create_connection (sock);
	g_return_val_if_fail (connection != NULL, NULL);
	g_object_unref (sock);

	address = g_unix_socket_address_new (ssh_agent_path);
	g_return_val_if_fail (address != NULL, NULL);

	if (!g_socket_connection_connect (connection, address, NULL, &error)) {
		g_warning ("couldn't connect to ssh-agent: %s", error->message);
		g_object_unref (connection);
		connection = NULL;
	}

	g_object_unref (address);
	return connection;
}

void
gkd_ssh_agent_process_cleanup (void)
{
	G_LOCK (ssh_agent_process);

	if (ssh_agent_pid)
		agent_terminate (ssh_agent_pid);
	ssh_agent_pid = 0;

	g_free (ssh_agent_path);
	ssh_agent_path = NULL;

	G_UNLOCK (ssh_agent_process);
}
