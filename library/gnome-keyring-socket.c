/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring.c - library for talking to the keyring daemon.

   Copyright (C) 2003 Red Hat, Inc
   Copyright (C) 2008 Stefan Walter

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

   Author: Alexander Larsson <alexl@redhat.com>
   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gnome-keyring-private.h"

#include <glib.h>

#include <dbus/dbus.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static gchar* 
find_daemon_via_dbus ()
{
	DBusConnection *dconn;
	DBusMessage *reply;
	DBusMessage *msg;
	DBusMessageIter args;
	DBusError derr;
	char* socket = NULL;

	if (!g_getenv ("DBUS_SESSION_BUS_ADDRESS"))
		return NULL;

	dbus_error_init (&derr);
	dconn = dbus_bus_get (DBUS_BUS_SESSION, &derr);
	if (!dconn) {
		g_warning ("couldn't connect to dbus session bus: %s", derr.message);
		return NULL;
	}	

	msg = dbus_message_new_method_call (GNOME_KEYRING_DAEMON_SERVICE,
	                                    GNOME_KEYRING_DAEMON_PATH,
	                                    GNOME_KEYRING_DAEMON_INTERFACE,
	                                    "GetSocketPath");
	if (!msg) {
		g_warning ("couldn't create dbus message");
		dbus_connection_unref (dconn);
		return NULL;
	}

	/* Send message and get a handle for a reply */
	reply = dbus_connection_send_with_reply_and_block (dconn, msg, -1, &derr);
	dbus_message_unref (msg);
	if (!reply) {
		g_warning ("couldn't communicate with gnome keyring daemon via dbus: %s", derr.message);
		dbus_connection_unref (dconn);
		return NULL;
	}

	/* Read the return value */
	if (!dbus_message_iter_init(reply, &args) || 
	    dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		g_warning ("gnome-keyring-daemon sent back an invalid reply");
	} else {
		dbus_message_iter_get_basic(&args, &socket);
		socket = g_strdup (socket);
	}

	dbus_message_unref (reply);
	dbus_connection_unref (dconn);

	return socket;
}

static int 
connect_to_daemon_at (const gchar *path)
{
	struct sockaddr_un addr;
	int sock;

	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, path, sizeof (addr.sun_path));
	
	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		return -1;
	}

	/* close on exec */
	if (fcntl (sock, F_SETFD, 1) == -1) {
		close (sock);
		return -1;
	}

	if (connect (sock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		close (sock);
		return -1;
	}

	return sock;
}

int
gnome_keyring_socket_connect_daemon (gboolean non_blocking, gboolean only_running)
{
	const gchar *epath = NULL;
	int sock = -1;
	int val;

	/* Try using the environment variable */
	epath = g_getenv ("GNOME_KEYRING_SOCKET");
	if (epath && epath[0]) {
		sock = connect_to_daemon_at (epath);
		if (sock < 0) {
			g_warning ("couldn't connect to daemon at $GNOME_KEYRING_SOCKET: %s: %s", 
				   epath, g_strerror (errno));
		}
	}

	/* Try using DBus to find daemon */
	if (sock < 0 && !only_running) {
		gchar *dpath = find_daemon_via_dbus ();
		if (dpath) {
			sock = connect_to_daemon_at (dpath);
			g_free (dpath);
			if (sock < 0) {
				g_warning ("couldn't connect to daemon at DBus discovered socket: %s: %s", 
					     dpath, g_strerror (errno));
			}
		}
	}

	if (sock < 0)
		return -1;

	/* Setup non blocking */
	if (non_blocking) {
		val = fcntl (sock, F_GETFL, 0);
		if (val < 0) {
			close (sock);
			return -1;
		}

		if (fcntl (sock, F_SETFL, val | O_NONBLOCK) < 0) {
			close (sock);
			return -1;
		}
	}
	
	return sock;
}

int
gnome_keyring_socket_read_all (int fd, guchar *buf, size_t len)
{
	size_t bytes;
	ssize_t res;
	
	bytes = 0;
	while (bytes < len) {
		res = read (fd, buf + bytes, len - bytes);
		if (res <= 0) {
			if (res == 0)
				res = -1;
			else if (errno == EAGAIN)
				continue;
			else 
				g_warning ("couldn't read %u bytes from gnome-keyring socket: %s", 
					   (unsigned int)len, g_strerror (errno));
			return res;
		}
		bytes += res;
	}
	return 0;
}


int
gnome_keyring_socket_write_all (int fd, const guchar *buf, size_t len)
{
	size_t bytes;
	ssize_t res;

	bytes = 0;
	while (bytes < len) {
		res = write (fd, buf + bytes, len - bytes);
		if (res < 0) {
			if (errno != EINTR &&
			    errno != EAGAIN) {
				g_warning ("write_all write failure: %s", g_strerror (errno));
				return -1;
			}
		} else {
			bytes += res;
		}
	}
	return 0;
}

gboolean 
gnome_keyring_socket_read_buffer (int fd, EggBuffer *buffer)
{
	guint32 packet_size;
	
	egg_buffer_resize (buffer, 4);
	if (gnome_keyring_socket_read_all (fd, buffer->buf, 4) < 0)
		return FALSE;

	if (!gkr_proto_decode_packet_size (buffer, &packet_size) ||
	    packet_size < 4)
		return FALSE;

	egg_buffer_resize (buffer, packet_size);
	if (gnome_keyring_socket_read_all (fd, buffer->buf + 4, packet_size - 4) < 0)
		return FALSE;

	return TRUE;
}

gboolean 
gnome_keyring_socket_write_buffer (int fd, EggBuffer *buffer)
{
	return gnome_keyring_socket_write_all (fd, buffer->buf, buffer->len) >= 0;
}

