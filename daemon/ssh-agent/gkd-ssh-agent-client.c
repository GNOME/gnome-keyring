/*
 * Copyright (C) 2014 Stef Walter
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
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"

#include "gkd-ssh-agent-client.h"

#include "daemon/gkd-util.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <unistd.h>

static gchar *ssh_agent_path = NULL;
static GPid ssh_agent_pid;
static GMutex ssh_agent_mutex;

static void
on_child_watch (GPid pid,
                gint status,
                gpointer user_data)
{
	GError *error = NULL;

	if (pid != ssh_agent_pid)
		return;

	g_mutex_lock (&ssh_agent_mutex);

	ssh_agent_pid = 0;

	if (!g_spawn_check_exit_status (status, &error)) {
		g_message ("ssh-agent: %s", error->message);
		g_error_free (error);
	}

	g_mutex_unlock (&ssh_agent_mutex);
}

static gboolean
agent_start_inlock (const char *socket)
{
	const gchar *argv[] = { SSH_AGENT, "-d", "-a", socket, NULL };
	GError *error = NULL;
	GPid pid;

	if (!g_spawn_async ("/", (gchar **)argv, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDOUT_TO_DEV_NULL,
	                    NULL, NULL, &pid, &error)) {
		g_warning ("couldn't run %s: %s", SSH_AGENT, error->message);
		g_error_free (error);
		return FALSE;
	}

	ssh_agent_pid = pid;
	g_child_watch_add (ssh_agent_pid, on_child_watch, NULL);
	return TRUE;
}

static gboolean
agent_check (GPid pid)
{
	return pid && (kill (pid, 0) == 0);
}

static void
agent_terminate (gint pid)
{
	kill (pid, SIGTERM);
}

gint
gkd_ssh_agent_client_connect (void)
{
	struct sockaddr_un addr;
	const gchar *directory;
	gboolean ready;
	gint sock;

	g_mutex_lock (&ssh_agent_mutex);

	if (!ssh_agent_path) {
		directory = gkd_util_get_master_directory ();
		ssh_agent_path = g_build_filename (directory, "ssh-agent-real", NULL);
	}

	ready = agent_check (ssh_agent_pid);
	if (!ready)
		ready = agent_start_inlock (ssh_agent_path);

	addr.sun_family = AF_UNIX;
	g_strlcpy (addr.sun_path, ssh_agent_path, sizeof (addr.sun_path));

	g_mutex_unlock (&ssh_agent_mutex);

	if (!ready)
		return -1;

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	g_return_val_if_fail (sock >= 0, -1);

	if (connect (sock, (struct sockaddr*) &addr, sizeof (addr)) < 0) {
		g_message ("couldn't connect to ssh-agent socket at: %s: %s",
		           addr.sun_path, g_strerror (errno));
		close (sock);
		sock = -1;
	}

	return sock;
}

void
gkd_ssh_agent_client_cleanup (void)
{
	g_mutex_lock (&ssh_agent_mutex);

	if (ssh_agent_pid)
		agent_terminate (ssh_agent_pid);
	ssh_agent_pid = 0;

	g_free (ssh_agent_path);
	ssh_agent_path = NULL;

	g_mutex_unlock (&ssh_agent_mutex);
}
