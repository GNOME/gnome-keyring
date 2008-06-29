/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkcs11-daemon.c - main connection/thread handling

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

#include "gkr-pkcs11-calls.h"
#include "gkr-pkcs11-message.h"
#include "gkr-pkcs11-daemon.h"

#include "common/gkr-async.h"
#include "common/gkr-cleanup.h"
#include "common/gkr-daemon-util.h"
#include "common/gkr-secure-memory.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

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
gkr_pkcs11_warn (const char* msg, ...)
{
	va_list va;
	va_start (va, msg);
	g_logv (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, msg, va);
	va_end (va);
}

/* -----------------------------------------------------------------------------
 * PKCS#11 DAEMON 
 */

/* The socket path on which we're listening */
static gchar *pkcs11_socket_path = NULL;
static int pkcs11_socket_fd = -1;
static GIOChannel *pkcs11_socket_channel = NULL;
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
		g_warning ("cannot accept pkcs11 connection: %s", strerror (errno));
		return TRUE;
	}
	
	/* And create a new thread */
	worker = gkr_async_worker_start (gkr_pkcs11_daemon_session_thread, 
	                                 completed_connection, GINT_TO_POINTER (new_fd));
	if (!worker) {
		g_warning ("couldn't create new connection session thread");
		close (new_fd);
		return TRUE;
	}
	
	g_hash_table_insert (session_workers, worker, GINT_TO_POINTER (new_fd)); 

	return TRUE;
}

static void 
pkcs11_daemon_cleanup (gpointer unused)
{
	if (pkcs11_socket_channel)
		g_io_channel_unref (pkcs11_socket_channel);
	pkcs11_socket_channel = NULL;
	
	if (pkcs11_socket_fd != -1)
		close (pkcs11_socket_fd);
	pkcs11_socket_fd = -1;
	
	if(pkcs11_socket_path) {
		unlink (pkcs11_socket_path);
		g_free (pkcs11_socket_path);
		pkcs11_socket_path = NULL;
	}
	
	if (session_workers) {
		
		/* Swap out the hash table, so that completed_connection doesn't remove from it */
		GHashTable *workers = session_workers;
		session_workers = NULL;
		
		g_hash_table_foreach (workers, (GHFunc)stop_connection, NULL);
		g_hash_table_destroy (workers);
	}
}

gboolean
gkr_pkcs11_daemon_setup (void)
{
	struct sockaddr_un addr;
	const gchar *tmp_dir;
	int sock;
	
#ifdef _DEBUG
	GKR_PKCS11_CHECK_CALLS ();
#endif
	
	/* cannot be called more than once */
	g_assert (!pkcs11_socket_path);
	g_assert (pkcs11_socket_fd == -1);
	g_assert (!pkcs11_socket_channel);
	
	gkr_cleanup_register (pkcs11_daemon_cleanup, NULL);
	
	tmp_dir = gkr_daemon_util_get_master_directory ();
	g_return_val_if_fail (tmp_dir, FALSE);
		
	pkcs11_socket_path = g_strjoin (NULL, tmp_dir, G_DIR_SEPARATOR_S, "socket", 
	                                GKR_PKCS11_SOCKET_EXT, NULL);

#ifdef WITH_TESTS
	if (g_getenv ("GNOME_KEYRING_TEST_PATH"))
		unlink (pkcs11_socket_path);
#endif

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		g_warning ("couldn't create pkcs11 socket: %s", strerror (errno));
		return FALSE;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, pkcs11_socket_path, sizeof (addr.sun_path));
	if (bind (sock, (struct sockaddr*)&addr, sizeof (addr)) < 0) {
		g_warning ("couldn't bind to pkcs11 socket: %s: %s", 
		           pkcs11_socket_path, strerror (errno));
		return FALSE;
	}
	
	if (listen (sock, 128) < 0) {
		g_warning ("couldn't listen on pkcs11 socket: %s: %s", 
		           pkcs11_socket_path, strerror (errno));
		return FALSE;
	}
	
	pkcs11_socket_channel = g_io_channel_unix_new (sock);
	g_io_add_watch (pkcs11_socket_channel, G_IO_IN | G_IO_HUP, 
	                handle_new_connection, NULL);
	
	/* Prep for sessions (ie: connections) */
	session_workers = g_hash_table_new (g_direct_hash, g_direct_equal);

	return TRUE;
}
