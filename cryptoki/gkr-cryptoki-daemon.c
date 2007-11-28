/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-cryptoki-daemon.c - main connection/thread handling

   Copyright (C) 2007, Nate Nielsen

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

   Author: Nate Nielsen <nielsen@memberwebs.com>
*/

#include <glib.h>

#include "gkr-cryptoki-calls.h"
#include "gkr-cryptoki-message.h"
#include "gkr-cryptoki-daemon.h"

#include "common/gkr-async.h"
#include "common/gkr-secure-memory.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>

#ifdef _DEBUG
#include <assert.h>
#endif 

/* -----------------------------------------------------------------------------
 * LOGGING 
 * 
 * Common code used in both the module and the daemon, requires this 
 * is implemented so that it can log any warnings appropriately.
 */
 
void 
gkr_cryptoki_warn (const char* msg, ...)
{
	va_list va;
	va_start (va, msg);
	g_logv (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, msg, va);
	va_end (va);
}

/* -----------------------------------------------------------------------------
 * CRYPTOKI DAEMON 
 */

/* The socket path on which we're listening */
static gchar *cryptoki_socket_path = NULL;
static int cryptoki_socket_fd = -1;
static GIOChannel *cryptoki_socket_channel = NULL;
static GHashTable *session_workers = NULL;

static void 
stop_connection (gpointer key, gpointer value, gpointer data)
{
	GkrAsyncWorker *worker = (GkrAsyncWorker*)key;
	int socket = GPOINTER_TO_INT (value);
	
	g_assert (socket >= 0);
	g_assert (worker);
	
	/* This makes sure the thread isn't blocked listening on the socket */
	shutdown (socket, SHUT_RDWR);

	/* completed_connection will be called to actually close the socket */	
	gkr_async_worker_stop (worker);
}

static void
completed_connection (GkrAsyncWorker* worker, gpointer result, gpointer user_data)
{
	int socket = GPOINTER_TO_INT (user_data);
	g_assert (socket >= 0);
	close (socket);
	
	/* This will be NULL when we're shutting down */
	if (session_workers)
		g_hash_table_remove (session_workers, worker);
}

static gboolean
handle_new_connection (GIOChannel *channel, GIOCondition cond, gpointer callback_data)
{
	GkrAsyncWorker *worker;
	int fd;
	int new_fd;
	struct sockaddr_un addr;
	socklen_t addrlen;

	g_assert (session_workers);
	
	fd = g_io_channel_unix_get_fd (channel);
	
	addrlen = sizeof (addr);
	new_fd = accept (fd, (struct sockaddr *) &addr, &addrlen);
	if (new_fd < 0) {
		g_warning ("cannot accept cryptoki connection: %s", strerror (errno));
		return TRUE;
	}
	
	/* And create a new thread */
	worker = gkr_async_worker_start (gkr_cryptoki_daemon_session_thread, 
	                                 completed_connection, GINT_TO_POINTER (new_fd));
	if (!worker) {
		g_warning ("couldn't create new connection session thread");
		close (new_fd);
		return TRUE;
	}
	
	g_hash_table_insert (session_workers, worker, GINT_TO_POINTER (new_fd)); 

	return TRUE;
}

gboolean
gkr_cryptoki_daemon_setup (const gchar* socket_path)
{
	struct sockaddr_un addr;
	int sock;
	
#ifdef _DEBUG
	GKR_CRYPTOKI_CHECK_CALLS ();
#endif
	
	g_assert (socket_path);
	
	/* cannot be called more than once */
	g_assert (!cryptoki_socket_path);
	g_assert (cryptoki_socket_fd == -1);
	g_assert (!cryptoki_socket_channel);
	
	cryptoki_socket_path = g_strjoin (NULL, socket_path, 
	                                  GKR_CRYPTOKI_SOCKET_EXT, NULL);
	
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		g_warning ("couldn't create cryptoki socket: %s", strerror (errno));
		return FALSE;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, cryptoki_socket_path, sizeof (addr.sun_path));
	if (bind (sock, (struct sockaddr*)&addr, sizeof (addr)) < 0) {
		g_warning ("couldn't bind to cryptoki socket: %s: %s", 
		           cryptoki_socket_path, strerror (errno));
		return FALSE;
	}
	
	if (listen (sock, 128) < 0) {
		g_warning ("couldn't listen on cryptoki socket: %s: %s", 
		           cryptoki_socket_path, strerror (errno));
		return FALSE;
	}
	
	/* TODO: Socket credentials */

	cryptoki_socket_channel = g_io_channel_unix_new (sock);
	g_io_add_watch (cryptoki_socket_channel, G_IO_IN | G_IO_HUP, 
	                handle_new_connection, NULL);
	
	/* Prep for sessions (ie: connections) */
	session_workers = g_hash_table_new (g_direct_hash, g_direct_equal);

	return TRUE;
}

void 
gkr_cryptoki_daemon_cleanup (void)
{	
	if (cryptoki_socket_channel)
		g_io_channel_unref (cryptoki_socket_channel);
	cryptoki_socket_channel = NULL;
	
	if (cryptoki_socket_fd != -1)
		close (cryptoki_socket_fd);
	cryptoki_socket_fd = -1;
	
	g_free (cryptoki_socket_path);
	cryptoki_socket_path = NULL;
	
	if (session_workers) {
		
		/* Swap out the hash table, so that completed_connection doesn't remove from it */
		GHashTable *workers = session_workers;
		session_workers = NULL;
		
		g_hash_table_foreach (workers, (GHFunc)stop_connection, NULL);
		g_hash_table_destroy (workers);
	}
}

