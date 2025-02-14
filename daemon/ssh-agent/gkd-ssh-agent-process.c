/*
 * gnome-keyring
 *
 * Copyright (C) 2014 Stef Walter
 * Copyright (C) 2018 Red Hat, Inc.
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
 *
 * Author: Stef Walter <stef@thewalter.net>, Daiki Ueno
 */

#include "config.h"

#include "gkd-ssh-agent-process.h"
#include "gkd-ssh-agent-private.h"
#include "gkd-ssh-agent-util.h"

#include <gio/gunixsocketaddress.h>
#include <glib-unix.h>
#include <glib/gstdio.h>

enum {
	PROP_0,
	PROP_PATH
};

enum {
	CLOSED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _GkdSshAgentProcess
{
	GObject object;
	gchar *path;
	gint output;
	GMutex lock;
	GPid pid;
	guint output_id;
	guint child_id;
	gboolean ready;
};

G_DEFINE_TYPE (GkdSshAgentProcess, gkd_ssh_agent_process, G_TYPE_OBJECT);

static void
gkd_ssh_agent_process_init (GkdSshAgentProcess *self)
{
	self->output = -1;
	g_mutex_init (&self->lock);
}

static void
gkd_ssh_agent_process_finalize (GObject *object)
{
	GkdSshAgentProcess *self = GKD_SSH_AGENT_PROCESS (object);

	if (self->output != -1)
		close (self->output);
	if (self->output_id)
		g_source_remove (self->output_id);
	if (self->child_id)
		g_source_remove (self->child_id);
	if (self->pid)
		kill (self->pid, SIGTERM);
	g_unlink (self->path);
	g_free (self->path);
	g_mutex_clear (&self->lock);

	G_OBJECT_CLASS (gkd_ssh_agent_process_parent_class)->finalize (object);
}

static void
gkd_ssh_agent_process_set_property (GObject *object,
                                    guint prop_id,
                                    const GValue *value,
                                    GParamSpec *pspec)
{
	GkdSshAgentProcess *self = GKD_SSH_AGENT_PROCESS (object);

	switch (prop_id) {
	case PROP_PATH:
		self->path = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gkd_ssh_agent_process_class_init (GkdSshAgentProcessClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->finalize = gkd_ssh_agent_process_finalize;
	gobject_class->set_property = gkd_ssh_agent_process_set_property;
	g_object_class_install_property (gobject_class, PROP_PATH,
		 g_param_spec_string ("path", "Path", "Path",
				      "",
				      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
	signals[CLOSED] = g_signal_new_class_handler ("closed",
						      G_TYPE_FROM_CLASS (klass),
						      G_SIGNAL_RUN_LAST,
						      NULL, NULL, NULL, NULL,
						      G_TYPE_NONE, 0);
}

static void
on_child_watch (GPid pid,
                gint status,
                gpointer user_data)
{
	GkdSshAgentProcess *self = GKD_SSH_AGENT_PROCESS (user_data);
	GError *error = NULL;

	if (pid != self->pid)
		return;

	g_mutex_lock (&self->lock);

	self->pid = 0;
	self->output_id = 0;
	self->child_id = 0;

	if (!g_spawn_check_wait_status (status, &error)) {
		g_message ("ssh-agent: %s", error->message);
		g_error_free (error);
	}

	g_spawn_close_pid (pid);

	g_mutex_unlock (&self->lock);

	g_signal_emit (self, signals[CLOSED], 0);
}

static gboolean
on_output_watch (gint fd,
		 GIOCondition condition,
		 gpointer user_data)
{
	GkdSshAgentProcess *self = GKD_SSH_AGENT_PROCESS (user_data);
	guint8 buf[1024];
	gssize len;

	if (condition & G_IO_IN) {
		self->ready = TRUE;

		len = read (fd, buf, sizeof (buf));
		if (len < 0) {
			if (errno != EAGAIN && errno != EINTR)
				g_message ("couldn't read from ssh-agent stdout: %m");
			condition |= G_IO_ERR;
		}
	}

	if (condition & G_IO_HUP || condition & G_IO_ERR)
		return FALSE;

	return TRUE;
}

static gboolean
agent_start_inlock (GkdSshAgentProcess *self,
		    GError **error)
{
	const gchar *argv[] = { SSH_AGENT, "-D", "-a", self->path, NULL };
	GPid pid;

	if (!g_spawn_async_with_pipes ("/", (gchar **)argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                               NULL, NULL, &pid, NULL, &self->output, NULL, error))
		return FALSE;

	self->ready = FALSE;
	self->output_id = g_unix_fd_add (self->output,
					 G_IO_IN | G_IO_HUP | G_IO_ERR,
					 on_output_watch, self);

	self->pid = pid;
	self->child_id = g_child_watch_add (self->pid, on_child_watch, self);

	return TRUE;
}

static gboolean
on_timeout (gpointer user_data)
{
	gboolean *timedout = user_data;
	*timedout = TRUE;
	return TRUE;
}

GSocketConnection *
gkd_ssh_agent_process_connect (GkdSshAgentProcess *self,
			       GCancellable *cancellable,
			       GError **error)
{
	gboolean started = FALSE;
	gboolean timedout = FALSE;
	guint source;
	GSocketClient *client;
	GSocketAddress *address;
	GSocketConnection *connection;

	g_mutex_lock (&self->lock);

	if (self->pid == 0) {
		if (!agent_start_inlock (self, error)) {
			g_mutex_unlock (&self->lock);
			return NULL;
		}
		started = TRUE;
	}

	if (started && self->pid && !self->ready) {
		source = g_timeout_add_seconds (5, on_timeout, &timedout);
		while (self->pid && !self->ready && !timedout) {
			g_mutex_unlock (&self->lock);
			g_main_context_iteration (NULL, FALSE);
			g_mutex_lock (&self->lock);
		}
		g_source_remove (source);
	}

	if (!self->ready) {
		g_mutex_unlock (&self->lock);
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			     "ssh-agent process is not ready");
		return NULL;
	}

	address = g_unix_socket_address_new (self->path);
	client = g_socket_client_new ();

	connection = g_socket_client_connect (client,
					      G_SOCKET_CONNECTABLE (address),
					      cancellable,
					      error);
	g_object_unref (address);
	g_object_unref (client);

	g_mutex_unlock (&self->lock);

	return connection;
}

GkdSshAgentProcess *
gkd_ssh_agent_process_new (const gchar *path)
{
	g_return_val_if_fail (path, NULL);

	return g_object_new (GKD_TYPE_SSH_AGENT_PROCESS, "path", path, NULL);
}

GPid
gkd_ssh_agent_process_get_pid (GkdSshAgentProcess *self)
{
	return self->pid;
}
