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

#include "gkd-ssh-agent-process.h"
#include "gkd-ssh-agent-private.h"

#include "daemon/gkd-util.h"

#include <glib-unix.h>
#include <glib/gstdio.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <unistd.h>

enum {
	PROP_0,
	PROP_PATH
};

struct _GkdSshAgentProcess
{
	GObject object;
	gchar *path;
	gint socket_fd;	  /* socket opened by the ssh-agent process */
	gint output_fd;	  /* stdout of the ssh-agent process */
	GHashTable *keys; /* keys actually known to the ssh-agent process */
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
	self->socket_fd = -1;
	self->output_fd = -1;
	self->keys = g_hash_table_new_full (g_bytes_hash, g_bytes_equal,
					    (GDestroyNotify)g_bytes_unref, NULL);
	g_mutex_init (&self->lock);
}

static void
gkd_ssh_agent_process_finalize (GObject *object)
{
	GkdSshAgentProcess *self = GKD_SSH_AGENT_PROCESS (object);

	if (self->socket_fd != -1)
		close (self->socket_fd);
	if (self->output_fd != -1)
		close (self->output_fd);
	if (self->output_id)
		g_source_remove (self->output_id);
	if (self->child_id)
		g_source_remove (self->child_id);
	if (self->pid)
		kill (self->pid, SIGTERM);
	if (self->keys)
		g_hash_table_unref (self->keys);
	g_unlink (self->path);
	g_free (self->path);
	g_mutex_clear (&self->lock);

	G_OBJECT_CLASS (gkd_ssh_agent_process_parent_class)->finalize (object);
}

static void
gkd_ssh_agent_process_set_property (GObject      *object,
                                    guint         prop_id,
                                    const GValue *value,
                                    GParamSpec   *pspec)
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

	if (!g_spawn_check_exit_status (status, &error)) {
		g_message ("ssh-agent: %s", error->message);
		g_error_free (error);
	}

	g_mutex_unlock (&self->lock);
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
		} else if (len > 0) {
			gkd_ssh_agent_write_all (1, buf, len, "stdout");
		}
	}

	if (condition & G_IO_HUP || condition & G_IO_ERR)
		return FALSE;

	return TRUE;
}

static gboolean
agent_start_inlock (GkdSshAgentProcess *self)
{
	const gchar *argv[] = { SSH_AGENT, "-D", "-a", self->path, NULL };
	GError *error = NULL;
	GPid pid;

	if (!g_spawn_async_with_pipes ("/", (gchar **)argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                               NULL, NULL, &pid, NULL, &self->output_fd, NULL, &error)) {
		g_warning ("couldn't run %s: %s", SSH_AGENT, error->message);
		g_error_free (error);
		return FALSE;
	}

	self->ready = FALSE;
	self->output_id = g_unix_fd_add (self->output_fd,
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

gboolean
gkd_ssh_agent_process_connect (GkdSshAgentProcess *self)
{
	gboolean started = FALSE;
	struct sockaddr_un addr;
	gboolean timedout = FALSE;
	guint source;
	gint sock;

	g_mutex_lock (&self->lock);

	if (self->pid == 0 || kill (self->pid, 0) != 0)
		started = agent_start_inlock (self);

	addr.sun_family = AF_UNIX;
	g_strlcpy (addr.sun_path, self->path, sizeof (addr.sun_path));

	if (started && !self->ready) {
		source = g_timeout_add_seconds (5, on_timeout, &timedout);
		while (!self->ready && !timedout)
			g_main_context_iteration (NULL, FALSE);
		g_source_remove (source);
	}

	if (!self->ready)
		return FALSE;

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	g_return_val_if_fail (sock >= 0, -1);

	if (connect (sock, (struct sockaddr*) &addr, sizeof (addr)) < 0) {
		g_message ("couldn't connect to ssh-agent socket at: %s: %s",
		           addr.sun_path, g_strerror (errno));
		close (sock);
		sock = -1;
	}

	self->socket_fd = sock;

	g_mutex_unlock (&self->lock);

	return sock != -1;
}

gboolean
gkd_ssh_agent_process_call (GkdSshAgentProcess *self,
                            EggBuffer          *req,
                            EggBuffer          *resp)
{
	return gkd_ssh_agent_write_packet (self->socket_fd, req) &&
	       gkd_ssh_agent_read_packet (self->socket_fd, resp);
}

gboolean
gkd_ssh_agent_process_lookup_key (GkdSshAgentProcess *self,
                                  GBytes             *key)
{
	gboolean ret;
	g_mutex_lock (&self->lock);
	ret = g_hash_table_contains (self->keys, key);
	g_mutex_unlock (&self->lock);
	return ret;
}

void
gkd_ssh_agent_process_add_key (GkdSshAgentProcess *self,
                               GBytes             *key)
{
	g_mutex_lock (&self->lock);
	g_hash_table_add (self->keys, g_bytes_ref (key));
	g_mutex_unlock (&self->lock);
}

void
gkd_ssh_agent_process_remove_key (GkdSshAgentProcess *self,
                                  GBytes             *key)
{
	g_mutex_lock (&self->lock);
	g_hash_table_remove (self->keys, key);
	g_mutex_lock (&self->lock);
}

void
gkd_ssh_agent_process_clear_keys (GkdSshAgentProcess *self)
{
	g_mutex_lock (&self->lock);
	g_hash_table_remove_all (self->keys);
	g_mutex_unlock (&self->lock);
}

GkdSshAgentProcess *
gkd_ssh_agent_process_new (const gchar *path)
{
	return g_object_new (GKD_TYPE_SSH_AGENT_PROCESS, "path", path, NULL);
}
