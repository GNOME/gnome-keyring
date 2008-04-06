/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ssh-daemon-io.c - handles SSH i/o from the clients

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

#include "gkr-ssh-daemon.h"
#include "gkr-ssh-private.h"

#include "common/gkr-async.h"
#include "common/gkr-buffer.h"
#include "common/gkr-cleanup.h"
#include "common/gkr-daemon-util.h"
#include "common/gkr-secure-memory.h"

#include "pk/gkr-pk-object-storage.h"

#ifndef HAVE_SOCKLEN_T
#define socklen_t int
#endif

typedef struct {
	GkrAsyncWorker *worker;
	int sock;

	GkrBuffer input_buffer;
	GkrBuffer output_buffer;
} SshClient;

static char socket_path[1024] = { 0, };

static gboolean
yield_and_read_all (int fd, guchar *buf, int len)
{
	int all = len;
	int res;
	
	while (len > 0) {
		
		/* Is this worker stopping? */
		if (gkr_async_is_stopping ())
			return FALSE;
			
		/* Don't block other threads during the read */
		gkr_async_begin_concurrent ();
		
			res = read (fd, buf, len);
			
		gkr_async_end_concurrent ();
		
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
yield_and_write_all (int fd, const guchar *buf, int len)
{
	int all = len;
	int res;
	
	while (len > 0) {
		
		/* Is this worker stopping? */
		if (gkr_async_is_stopping ())
			return FALSE;
			
		/* Don't block other threads during the read */
		gkr_async_begin_concurrent ();

			res = write (fd, buf, len);
			
		gkr_async_end_concurrent ();
		
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
read_packet_with_size (SshClient *client)
{
	int fd;
	guint32 packet_size;

	fd = client->sock;
	
	gkr_buffer_resize (&client->input_buffer, 4);
	if (!yield_and_read_all (fd, client->input_buffer.buf, 4))
		return FALSE;

	if (!gkr_buffer_get_uint32 (&client->input_buffer, 0, NULL, &packet_size) || 
	    packet_size < 1) {
	    	g_warning ("invalid packet size from client");
		return FALSE;
	}

	gkr_buffer_resize (&client->input_buffer, packet_size + 4);
	if (!yield_and_read_all (fd, client->input_buffer.buf + 4, packet_size))
		return FALSE;

	return TRUE;
}

static void
close_fd (gpointer data)
{
	int *fd = (int*)data;
	g_assert (fd);

	/* If we're waiting anywhere this makes the thread stop */
	shutdown (*fd, SHUT_RDWR);
}

static gpointer
client_worker_main (gpointer user_data)
{
	SshClient *client = (SshClient*)user_data;
	guchar op;
	
	/* This array needs to be laid out properly */
	g_assert ((sizeof (gkr_ssh_operations) / sizeof (gkr_ssh_operations[0])) == GKR_SSH_OP_MAX);

	/* This helps any reads wakeup when this worker is stopping */
	gkr_async_register_cancel (close_fd, &client->sock);
	
	/* Make sure everything is in sync for this connection */
	gkr_pk_object_storage_refresh (NULL);
	
	while (!gkr_async_is_stopping ()) {
		
		/* 1. Read in the request */
		if (!read_packet_with_size (client))
			break;

		/* 2. Now decode the operation */
		if (!gkr_buffer_get_byte (&client->input_buffer, 4, NULL, &op))
			break; 
		if (op >= GKR_SSH_OP_MAX)
			break;
		g_assert (gkr_ssh_operations[op]);
		
		/* 3. Execute the right operation */
		gkr_buffer_reset (&client->output_buffer);
		gkr_buffer_add_uint32 (&client->output_buffer, 0);
		if (!(gkr_ssh_operations[op]) (&client->input_buffer, &client->output_buffer))
			break;
		if (!gkr_buffer_set_uint32 (&client->output_buffer, 0,
		                            client->output_buffer.len - 4))
			break;

		/* 4. Write the reply back out */
		if (!yield_and_write_all (client->sock, client->output_buffer.buf,
		                          client->output_buffer.len))
			break;
	} 

	/* All done */
	shutdown (client->sock, SHUT_RDWR);
	return NULL;
}

static void
client_worker_done (GkrAsyncWorker *worker, gpointer result, gpointer user_data)
{
	SshClient *client = (SshClient*)user_data;

	gkr_buffer_uninit (&client->input_buffer);
	gkr_buffer_uninit (&client->output_buffer);

	if (client->sock != -1)
		close (client->sock);
	g_free (client);
}

static void
client_new (int fd)
{
	SshClient *client;

	client = g_new0 (SshClient, 1);
	client->sock = fd;
	
	/* 
	 * We really have no idea what operation the client will send, 
	 * so we err on the side of caution and use secure memory in case
	 * keys are involved.
	 */
	/* TODO: Switch to gkr_secure_memory */
	gkr_buffer_init_full (&client->input_buffer, 128, gkr_secure_realloc);
	gkr_buffer_init_full (&client->output_buffer, 128, (GkrBufferAllocator)g_realloc);

	client->worker = gkr_async_worker_start (client_worker_main, 
	                                         client_worker_done, client);
	g_assert (client->worker);
	
	/* 
	 * The worker thread is tracked in a global list, and is guaranteed to 
	 * be cleaned up, either when it exits, or when the application closes.
	 */
}

static gboolean
accept_client (GIOChannel *channel, GIOCondition cond,
               gpointer callback_data)
{
	int fd;
	int new_fd;
	struct sockaddr_un addr;
	socklen_t addrlen;
  
	fd = g_io_channel_unix_get_fd (channel);
	
	addrlen = sizeof (addr);
	new_fd = accept (fd, (struct sockaddr *) &addr, &addrlen);
	
	if (new_fd >= 0) 
		client_new (new_fd);
	return TRUE;
}

static void
cleanup_socket_dir (gpointer data)
{
	if(*socket_path)
		unlink (socket_path);
}

gboolean
gkr_daemon_ssh_io_initialize (void)
{
	const gchar *tmp_dir;
	int sock;
	struct sockaddr_un addr;
	GIOChannel *channel;

	tmp_dir = gkr_daemon_util_get_master_directory ();
	g_return_val_if_fail (tmp_dir, FALSE);
		
	snprintf (socket_path, sizeof (socket_path), "%s/ssh", tmp_dir);
	
#ifdef WITH_TESTS
	if (g_getenv ("GNOME_KEYRING_TEST_PATH"))
		unlink (socket_path);
#endif

	gkr_cleanup_register (cleanup_socket_dir, NULL);
	
	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		g_warning ("couldn't create socket: %s", g_strerror (errno));
		return FALSE;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, socket_path, sizeof (addr.sun_path));
	if (bind (sock, (struct sockaddr *) & addr, sizeof (addr)) < 0) {
		g_warning ("couldn't bind to socket: %s", g_strerror (errno));
		return FALSE;
	}
	
	if (listen (sock, 128) < 0) {
		g_warning ("couldn't listen on socket: %s", g_strerror (errno));
		return FALSE;
	}

	channel = g_io_channel_unix_new (sock);
	g_io_add_watch (channel, G_IO_IN | G_IO_HUP, accept_client, NULL);
	g_io_channel_unref (channel);
	
	if (g_getenv ("SSH_AUTH_SOCK"))
		g_message ("another SSH agent is running at: %s", g_getenv ("SSH_AUTH_SOCK")); 
		
	/* TODO: Do we need to push SSH_AGENT_PID? */
	gkr_daemon_util_push_environment ("SSH_AUTH_SOCK", socket_path);
	
	return TRUE;
}
