/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-ssh-agent.c - handles SSH i/o from the clients

   Copyright (C) 2007 Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gkd-ssh-agent.h"
#include "gkd-ssh-agent-private.h"

#include "egg/egg-buffer.h"
#include "egg/egg-error.h"
#include "egg/egg-secure-memory.h"

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

/* The loaded PKCS#11 modules */
static GList *pkcs11_modules = NULL;

EGG_SECURE_DECLARE (ssh_agent);

static gboolean
read_all (int fd, guchar *buf, int len)
{
	int all = len;
	int res;

	while (len > 0) {

		res = read (fd, buf, len);

		if (res < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			g_warning ("couldn't read %u bytes from client: %s", all,
			           g_strerror (errno));
			return FALSE;
		} else if (res == 0) {
			return FALSE;
		} else  {
			len -= res;
			buf += res;
		}
	}

	return TRUE;
}

static gboolean
write_all (int fd, const guchar *buf, int len)
{
	int all = len;
	int res;

	while (len > 0) {

		res = write (fd, buf, len);
		if (res < 0) {
			if (errno == EAGAIN && errno == EINTR)
				continue;
			if (errno != EPIPE)
				g_warning ("couldn't write %u bytes to client: %s", all,
				           g_strerror (errno));
			return FALSE;
		} else if (res == 0) {
			g_warning ("couldn't write %u bytes to client", all);
			return FALSE;
		} else  {
			len -= res;
			buf += res;
		}
	}

	return TRUE;
}

gboolean
gkd_ssh_agent_read_packet (gint fd,
                           EggBuffer *buffer)
{
	guint32 packet_size;

	egg_buffer_reset (buffer);
	egg_buffer_resize (buffer, 4);
	if (!read_all (fd, buffer->buf, 4))
		return FALSE;

	if (!egg_buffer_get_uint32 (buffer, 0, NULL, &packet_size) ||
	    packet_size < 1) {
		g_warning ("invalid packet size from client");
		return FALSE;
	}

	egg_buffer_resize (buffer, packet_size + 4);
	if (!read_all (fd, buffer->buf + 4, packet_size))
		return FALSE;

	return TRUE;
}

gboolean
gkd_ssh_agent_write_packet (gint fd,
                            EggBuffer *buffer)
{
	if (!egg_buffer_set_uint32 (buffer, 0, buffer->len - 4))
		g_return_val_if_reached (FALSE);
	return write_all (fd, buffer->buf, buffer->len);
}

static gpointer
run_client_thread (gpointer data)
{
	gint *socket = xxxx;
	gint *agent = xxxx;
	GkdSshAgentCall call;
	GkdSshAgentOperation func;
	EggBuffer req;
	EggBuffer resp;
	guchar op;

	memset (&call, 0, sizeof (call));
	call.sock = g_atomic_int_get (socket);
	g_assert (call.sock != -1);

	egg_buffer_init_full (&req, 128, egg_secure_realloc);
	egg_buffer_init_full (&resp, 128, (EggBufferAllocator)g_realloc);
	call.req = &req;
	call.resp = &resp;

	call.agent = gkd_ssh_agent_client_connect ();
	if (!call.agent)
		goto out;

	for (;;) {

		/* 1. Read in the request */
		if (!gkd_ssh_agent_read_packet (call.sock, &call.req))
			break;

		/* 2. Now decode the operation */
		if (!egg_buffer_get_byte (call.req, 4, NULL, &op))
			break;

		/* 3. Execute the right operation */
		egg_buffer_reset (call.resp);
		egg_buffer_add_uint32 (call.resp, 0);
		if (op >= GKD_SSH_OP_MAX || gkd_ssh_agent_operations[op])
			func = gkd_ssh_agent_operations[op];
		else
			func = gkd_ssh_agent_relay;
		if (!func (&call))
			break;

		/* 4. Write the reply back out */
		if (!gkd_ssh_agent_write_packet (call.sock, call.resp))
			break;
	}

out:
	egg_buffer_uninit (&req);
	egg_buffer_uninit (&resp);

	close (call.sock);
	g_atomic_int_set (socket, -1);

	return NULL;
}

/* --------------------------------------------------------------------------------------
 * MAIN THREAD
 */

typedef struct _Client {
	GThread *thread;
	gint sock;
	gint agent;
} Client;

/* Each client thread in this list */
static GList *socket_clients = NULL;

/* The main socket we listen on */
static int socket_fd = -1;

/* The path of the socket listening on */
static char socket_path[1024] = { 0, };

void
gkd_ssh_agent_accept (void)
{
	Client *client;
	struct sockaddr_un addr;
	socklen_t addrlen;
	GError *error = NULL;
	GList *l;
	int new_fd;

	g_return_if_fail (socket_fd != -1);

	/* Cleanup any completed dispatch threads */
	for (l = socket_clients; l; l = g_list_next (l)) {
		client = l->data;
		if (g_atomic_int_get (&client->sock) == -1) {
			g_thread_join (client->thread);
			g_slice_free (Client, client);
			l->data = NULL;
		}
	}
	socket_clients = g_list_remove_all (socket_clients, NULL);

	addrlen = sizeof (addr);
	new_fd = accept (socket_fd, (struct sockaddr*) &addr, &addrlen);
	if (socket_fd < 0) {
		g_warning ("cannot accept SSH agent connection: %s", strerror (errno));
		return;
	}

	real_agent = gkd_ssh_agent_process_connect ();
	if (real_agent < 0) {
		/* Warning already printed */
		close (new_fd);
		return;
	}

	client = g_slice_new0 (Client);
	client->sock = new_fd;
	client->agent = real_agent;

	/* And create a new thread/process */
	client->thread = g_thread_new ("ssh-agent", run_client_thread, &client->sock);
	socket_clients = g_list_append (socket_clients, client);
}

void
gkd_ssh_agent_shutdown (void)
{
	Client *client;
	GList *l;

	if (socket_fd != -1)
		close (socket_fd);

	if (*socket_path)
		unlink (socket_path);

	/* Stop all of the dispatch threads */
	for (l = socket_clients; l; l = g_list_next (l)) {
		client = l->data;

		/* Forcibly shutdown the connection */
		if (client->sock != -1) {
			shutdown (client->sock, SHUT_RDWR);
			shutdown (client->agent, SHUT_RDWR);
		}
		g_thread_join (client->thread);

		/* This is always closed by client thread */
		g_assert (client->sock == -1);
		g_slice_free (Client, client);
	}

	g_list_free (socket_clients);
	socket_clients = NULL;

	gkd_ssh_agent_process_cleanup ();
}

int
gkd_ssh_agent_startup (const gchar *prefix)
{
	struct sockaddr_un addr;
	int sock;

	g_return_val_if_fail (prefix, -1);

	snprintf (socket_path, sizeof (socket_path), "%s/ssh", prefix);
	unlink (socket_path);

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		g_warning ("couldn't create socket: %s", g_strerror (errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, socket_path, sizeof (addr.sun_path));
	if (bind (sock, (struct sockaddr *) & addr, sizeof (addr)) < 0) {
		g_warning ("couldn't bind to socket: %s: %s", socket_path, g_strerror (errno));
		close (sock);
		return -1;
	}

	if (listen (sock, 128) < 0) {
		g_warning ("couldn't listen on socket: %s", g_strerror (errno));
		close (sock);
		return -1;
	}

	g_setenv ("SSH_AUTH_SOCK", socket_path, TRUE);

	socket_fd = sock;
	return sock;
}
