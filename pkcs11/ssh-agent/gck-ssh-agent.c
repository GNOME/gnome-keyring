/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-ssh-agent.c - handles SSH i/o from the clients

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

#include "gck-ssh-agent.h"
#include "gck-ssh-agent-private.h"

#include "common/gkr-buffer.h"
#include "common/gkr-secure-memory.h"

#ifndef HAVE_SOCKLEN_T
#define socklen_t int
#endif

/* The PKCS#11 slot we call into */
static GP11Slot *pkcs11_slot = NULL;

static gboolean
read_all (int fd, guchar *buf, int len)
{
	int all = len;
	int res;
	
	while (len > 0) {
		
		res = read (fd, buf, len);
			
		if (res <= 0) {
			if (errno == EAGAIN && errno == EINTR)
				continue;
			if (res < 0)
				g_warning ("couldn't read %u bytes from client: %s", all, 
				           g_strerror (errno));
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

		if (res <= 0) {
			if (errno == EAGAIN && errno == EINTR)
				continue;
			g_warning ("couldn't write %u bytes to client: %s", all, 
			           res < 0 ? g_strerror (errno) : "");
			return FALSE;
		} else  {
			len -= res;
			buf += res;
		}
	}
	
	return TRUE;
}

static gboolean
read_packet_with_size (GckSshAgentCall *call)
{
	int fd;
	guint32 packet_size;

	fd = call->sock;
	
	gkr_buffer_resize (call->req, 4);
	if (!read_all (fd, call->req->buf, 4))
		return FALSE;

	if (!gkr_buffer_get_uint32 (call->req, 0, NULL, &packet_size) || 
	    packet_size < 1) {
	    	g_warning ("invalid packet size from client");
		return FALSE;
	}

	gkr_buffer_resize (call->req, packet_size + 4);
	if (!read_all (fd, call->req->buf + 4, packet_size))
		return FALSE;

	return TRUE;
}

static gpointer
run_client_thread (gpointer data)
{
	gboolean running = TRUE;
	GError *error = NULL;
	gint *socket = data;
	GckSshAgentCall call;
	GkrBuffer req;
	GkrBuffer resp;
	guchar op;
	
	g_assert (pkcs11_slot);
	
	memset (&call, 0, sizeof (call));
	call.sock = g_atomic_int_get (socket);
	g_assert (call.sock != -1);
	
	gkr_buffer_init_full (&req, 128, gkr_secure_realloc);
	gkr_buffer_init_full (&resp, 128, (GkrBufferAllocator)g_realloc);
	call.req = &req;
	call.resp = &resp;
	
	/* Try to open a session for this thread */
	call.session = gp11_slot_open_session (pkcs11_slot, CKF_SERIAL_SESSION, &error);
	if (!call.session) {
		g_warning ("couldn't open pkcs#11 session for agent thread: %s", error->message);
		g_clear_error (&error);
		running = FALSE;
	}

	while (running) {
		
		gkr_buffer_reset (call.req);
		
		/* 1. Read in the request */
		if (!read_packet_with_size (&call))
			break;

		/* 2. Now decode the operation */
		if (!gkr_buffer_get_byte (call.req, 4, NULL, &op))
			break; 
		if (op >= GCK_SSH_OP_MAX)
			break;
		g_assert (gck_ssh_agent_operations[op]);
		
		/* 3. Execute the right operation */
		gkr_buffer_reset (call.resp);
		gkr_buffer_add_uint32 (call.resp, 0);
		if (!(gck_ssh_agent_operations[op]) (&call))
			break;
		if (!gkr_buffer_set_uint32 (call.resp, 0, call.resp->len - 4))
			break;

		/* 4. Write the reply back out */
		if (!write_all (call.sock, call.resp->buf, call.resp->len))
			break;
	}
	
	gkr_buffer_uninit (&req);
	gkr_buffer_uninit (&resp);

	close (call.sock);
	g_atomic_int_set (socket, -1);
	
	return NULL;
}

/* --------------------------------------------------------------------------------------
 * MAIN SESSION
 */

/* The main PKCS#11 session that owns objects, and the mutex/cond for waiting on it */
static GP11Session *pkcs11_session = NULL;
static gboolean pkcs11_session_checked = FALSE;
static GMutex *pkcs11_session_mutex = NULL;
static GCond *pkcs11_session_cond = NULL;

static gboolean
init_main_session (GP11Slot *slot)
{
	GP11Session *session;
	GError *error = NULL;
	
	g_assert (GP11_IS_SLOT (slot));

	/* Load our main session */
	session = gp11_slot_open_session (slot, CKF_SERIAL_SESSION, &error);
	if (!session) {
		g_warning ("couldn't create pkcs#11 session: %s", error->message);
		g_clear_error (&error);
		return FALSE;
	}

	pkcs11_session_mutex = g_mutex_new ();
	pkcs11_session_cond = g_cond_new ();
	pkcs11_session_checked = FALSE;
	pkcs11_session = session;
	
	return TRUE;
}

GP11Session*
gck_ssh_agent_checkout_main_session (void)
{
	GP11Session *result;
	
	g_mutex_lock (pkcs11_session_mutex);
	
		g_assert (GP11_IS_SESSION (pkcs11_session));
		while (pkcs11_session_checked)
			g_cond_wait (pkcs11_session_cond, pkcs11_session_mutex);
		pkcs11_session_checked = TRUE;
		result = g_object_ref (pkcs11_session);
	
	g_mutex_unlock (pkcs11_session_mutex);
	
	return result;
}

void
gck_ssh_agent_checkin_main_session (GP11Session *session)
{
	g_assert (GP11_IS_SESSION (session));
	
	g_mutex_lock (pkcs11_session_mutex);
	
		g_assert (session == pkcs11_session);
		g_assert (pkcs11_session_checked);
		
		g_object_unref (session);
		pkcs11_session_checked = FALSE;
		g_cond_signal (pkcs11_session_cond);
		
	g_mutex_unlock (pkcs11_session_mutex);
}

static void
uninit_main_session (void)
{
	gboolean ret;
	
	g_assert (pkcs11_session_mutex);
	ret = g_mutex_trylock (pkcs11_session_mutex);
	g_assert (ret);

		g_assert (GP11_IS_SESSION (pkcs11_session));
		g_assert (!pkcs11_session_checked);
		g_object_unref (pkcs11_session);
		pkcs11_session = NULL;
		
	g_mutex_unlock (pkcs11_session_mutex);
	g_mutex_free (pkcs11_session_mutex);
	g_cond_free (pkcs11_session_cond);		
}

/* --------------------------------------------------------------------------------------
 * MAIN THREAD
 */

typedef struct _Client {
	GThread *thread;
	gint sock;
} Client;

/* Each client thread in this list */
static GList *socket_clients = NULL; 

/* The main socket we listen on */
static int socket_fd = -1;

/* The path of the socket listening on */
static char socket_path[1024] = { 0, };

int
gck_ssh_agent_get_socket_fd (void)
{
	return socket_fd;
}

const gchar*
gck_ssh_agent_get_socket_path (void)
{
	return socket_path;
}

void
gck_ssh_agent_accept (void)
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
	
	client = g_slice_new0 (Client);
	client->sock = new_fd;
	
	/* And create a new thread/process */
	client->thread = g_thread_create (run_client_thread, &client->sock, TRUE, &error);
	if (!client->thread) {
		g_warning ("couldn't create thread SSH agent connection: %s", 
		           error && error->message ? error->message : "");
		g_slice_free (Client, client);
		return;
	}
	
	socket_clients = g_list_append (socket_clients, client);
}

void 
gck_ssh_agent_uninitialize (void)
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
		if (client->sock != -1)
			shutdown (client->sock, SHUT_RDWR);
		g_thread_join (client->thread);
		
		/* This is always closed by client thread */
		g_assert (client->sock == -1);
		g_slice_free (Client, client);
	}
	
	g_list_free (socket_clients);
	socket_clients = NULL;
	
	uninit_main_session ();
	
	g_object_unref (pkcs11_slot);
	pkcs11_slot = NULL;
}

gboolean
gck_ssh_agent_initialize (const gchar *prefix, GP11Slot *slot)
{
	struct sockaddr_un addr;
	int sock;
	
	g_return_val_if_fail (GP11_IS_SLOT (slot), FALSE);
	g_return_val_if_fail (prefix, FALSE);
	
	snprintf (socket_path, sizeof (socket_path), "%s.ssh", prefix);
	unlink (socket_path);

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		g_warning ("couldn't create socket: %s", g_strerror (errno));
		return FALSE;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, socket_path, sizeof (addr.sun_path));
	if (bind (sock, (struct sockaddr *) & addr, sizeof (addr)) < 0) {
		g_warning ("couldn't bind to socket: %s: %s", socket_path, g_strerror (errno));
		close (sock);
		return FALSE;
	}
	
	if (listen (sock, 128) < 0) {
		g_warning ("couldn't listen on socket: %s", g_strerror (errno));
		close (sock);
		return FALSE;
	}
	
	/* Load our main session */
	if (!init_main_session (slot)) {
		close (sock);
		return FALSE;
	}
	
	pkcs11_slot = g_object_ref (slot);
	socket_fd = sock;
	return TRUE;
}
