/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "gkd-control.h"
#include "gkd-main.h"
#include "gkd-util.h"

#include "egg/egg-buffer.h"
#include "egg/egg-cleanup.h"
#include "egg/egg-secure-memory.h"
#include "egg/egg-unix-credentials.h"

#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

typedef struct _ControlData {
	EggBuffer buffer;
	gsize position;
} ControlData;

/* All the old op codes, most are no longer used */
enum {
	GNOME_KEYRING_OP_LOCK_ALL,
	GNOME_KEYRING_OP_SET_DEFAULT_KEYRING,
	GNOME_KEYRING_OP_GET_DEFAULT_KEYRING,
	GNOME_KEYRING_OP_LIST_KEYRINGS,
	GNOME_KEYRING_OP_CREATE_KEYRING,
	GNOME_KEYRING_OP_LOCK_KEYRING,
	GNOME_KEYRING_OP_UNLOCK_KEYRING,
	GNOME_KEYRING_OP_DELETE_KEYRING,
	GNOME_KEYRING_OP_GET_KEYRING_INFO,
	GNOME_KEYRING_OP_SET_KEYRING_INFO,
	GNOME_KEYRING_OP_LIST_ITEMS,
	GNOME_KEYRING_OP_FIND,
	GNOME_KEYRING_OP_CREATE_ITEM,
	GNOME_KEYRING_OP_DELETE_ITEM,
	GNOME_KEYRING_OP_GET_ITEM_INFO,
	GNOME_KEYRING_OP_SET_ITEM_INFO,
	GNOME_KEYRING_OP_GET_ITEM_ATTRIBUTES,
	GNOME_KEYRING_OP_SET_ITEM_ATTRIBUTES,
	GNOME_KEYRING_OP_GET_ITEM_ACL,
	GNOME_KEYRING_OP_SET_ITEM_ACL,
	GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD,
	GNOME_KEYRING_OP_SET_DAEMON_DISPLAY,
	GNOME_KEYRING_OP_GET_ITEM_INFO_FULL,
	GNOME_KEYRING_OP_PREPARE_ENVIRONMENT,

	/* Add new ops here */

	GNOME_KEYRING_NUM_OPS
};

/* All the old result codes */
enum {
	GNOME_KEYRING_RESULT_OK,
	GNOME_KEYRING_RESULT_DENIED,
	GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON,
	GNOME_KEYRING_RESULT_ALREADY_UNLOCKED,
	GNOME_KEYRING_RESULT_NO_SUCH_KEYRING,
	GNOME_KEYRING_RESULT_BAD_ARGUMENTS,
	GNOME_KEYRING_RESULT_IO_ERROR,
	GNOME_KEYRING_RESULT_CANCELLED,
	GNOME_KEYRING_RESULT_KEYRING_ALREADY_EXISTS,
	GNOME_KEYRING_RESULT_NO_MATCH
};

/* -----------------------------------------------------------------------------------
 * CONTROL SERVER
 */

static ControlData*
control_data_new (void)
{
	ControlData *cdata = g_slice_new0 (ControlData);
	egg_buffer_init_full (&cdata->buffer, 128, egg_secure_realloc);
	cdata->position = 0;
	return cdata;
}

static void
control_data_free (gpointer data)
{
	ControlData *cdata = data;
	egg_buffer_uninit (&cdata->buffer);
	g_slice_free (ControlData, cdata);
}

static guint32
control_unlock_keyring (EggBuffer *buffer)
{
	gchar *name;
	gchar *master;
	gsize offset = 8;
	guint32 res;

	if (!egg_buffer_get_string (buffer, offset, &offset, &name, g_realloc))
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;

	if (!egg_buffer_get_string (buffer, offset, &offset, &master, egg_secure_realloc)) {
		g_free (name);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	if (!name || g_str_equal (name, "login")) {
		// TODO: Perform unlocking */
		res = GNOME_KEYRING_RESULT_DENIED;
	} else {
		g_message ("keyring request not supported");
		res = GNOME_KEYRING_RESULT_NO_SUCH_KEYRING;
	}

	egg_secure_strfree (master);
	g_free (name);
	return res;
}

static guint32
control_change_keyring_password (EggBuffer *buffer)
{
	gsize offset = 8;
	guint32 res;
	gchar *name;
	gchar *master;
	gchar *original;

	if (!egg_buffer_get_string (buffer, offset, &offset, &name, g_realloc))
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;

	if (!egg_buffer_get_string (buffer, offset, &offset, &original, egg_secure_realloc)) {
		g_free (name);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	if (!egg_buffer_get_string (buffer, offset, &offset, &master, egg_secure_realloc)) {
		egg_secure_strfree (original);
		g_free (name);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	if (!name || g_str_equal (name, "login")) {
		// TODO: Perform unlocking */
		res = GNOME_KEYRING_RESULT_DENIED;
	} else {
		g_message ("keyring request not supported");
		res = GNOME_KEYRING_RESULT_NO_SUCH_KEYRING;
	}

	egg_secure_strfree (master);
	egg_secure_strfree (original);
	g_free (name);
	return res;
}

static guint32
control_prepare_environment (EggBuffer *buffer)
{
	gchar **environment, **e;
	gsize offset = 8;
	gchar *x;
	int i;

	if (!egg_buffer_get_stringv (buffer, offset, &offset, &environment, g_realloc))
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;

	/* Accept environment from outside */
	for (e = environment; *e; ++e) {
		x = strchr (*e, '=');
		if (x) {
			*(x++) = 0;
			/* We're only interested in these environment variables */
			for (i = 0; GKD_UTIL_IN_ENVIRONMENT[i] != NULL; ++i) {
				if (g_str_equal (*e, GKD_UTIL_IN_ENVIRONMENT[i])) {
					g_setenv (*e, x, FALSE);
					break;
				}
			}
		}
	}

	g_strfreev (environment);

	/*
	 * We've now definitely received everything we need to run. Ask
	 * the daemon to complete the initialization.
	 */
	gkd_main_complete_initialization ();
	return GNOME_KEYRING_RESULT_OK;
}

static gboolean
control_output (GIOChannel *channel, GIOCondition cond, gpointer user_data)
{
	ControlData *cdata = user_data;
	EggBuffer *buffer = &cdata->buffer;
	int fd, res;

	fd = g_io_channel_unix_get_fd (channel);
	g_assert (cdata->position < buffer->len);

	if (cond & G_IO_OUT) {
		res = write (fd, buffer->buf + cdata->position, buffer->len - cdata->position);
		if (res <= 0) {
			if (errno != EAGAIN && errno != EINTR)
				cdata->position = buffer->len;
		} else {
			cdata->position += res;
			g_assert (cdata->position <= buffer->len);
		}
	}

	if (cdata->position == buffer->len)
		cond |= G_IO_HUP;

	return (cond & G_IO_HUP) == 0;
}

static void
control_process (EggBuffer *req, GIOChannel *channel)
{
	ControlData *cdata = NULL;
	guint32 res;
	guint32 op;

	if (!egg_buffer_get_uint32 (req, 4, NULL, &op)) {
		g_message ("invalid operation sent to control socket");
		return;
	}

	switch (op) {
	case GNOME_KEYRING_OP_CREATE_KEYRING:
	case GNOME_KEYRING_OP_UNLOCK_KEYRING:
		res = control_unlock_keyring (req);
		cdata = control_data_new ();
		egg_buffer_add_uint32 (&cdata->buffer, 0);
		egg_buffer_add_uint32 (&cdata->buffer, res);
		break;
	case GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD:
		res = control_change_keyring_password (req);
		cdata = control_data_new ();
		egg_buffer_add_uint32 (&cdata->buffer, 0);
		egg_buffer_add_uint32 (&cdata->buffer, res);
		break;
	case GNOME_KEYRING_OP_PREPARE_ENVIRONMENT:
		res = control_prepare_environment (req);
		cdata = control_data_new ();
		egg_buffer_add_uint32 (&cdata->buffer, 0);
		egg_buffer_add_uint32 (&cdata->buffer, res);
		egg_buffer_add_stringv (&cdata->buffer, gkd_util_get_environment ());
		break;
	default:
		g_message ("received unsupported request operation on control socket: %d", (int)op);
		break;
	}

	if (cdata) {
		g_return_if_fail (!egg_buffer_has_error (&cdata->buffer));
		egg_buffer_set_uint32 (&cdata->buffer, 0, cdata->buffer.len);
		g_io_add_watch_full (channel, G_PRIORITY_DEFAULT, G_IO_OUT | G_IO_HUP,
		                     control_output, cdata, control_data_free);
	}
}

static gboolean
control_input (GIOChannel *channel, GIOCondition cond, gpointer user_data)
{
	ControlData *cdata = user_data;
	EggBuffer *buffer = &cdata->buffer;
	guint32 packet_size = 0;
	gboolean finished = FALSE;
	int fd, res;
	pid_t pid;
	uid_t uid;

	fd = g_io_channel_unix_get_fd (channel);

	if (cond & G_IO_IN) {

		/* Time for reading credentials */
		if (cdata->position == 0) {
			if (egg_unix_credentials_read (fd, &pid, &uid) < 0) {
				if (errno != EAGAIN || errno != EINTR)
					finished = TRUE;
			} else if (getuid () != uid) {
				g_message ("control request from bad uid: %u, should be %u\n", uid, getuid ());
				finished = TRUE;
			} else {
				cdata->position = 1;
			}

		/* Time for reading a packet size */
		} else if (egg_buffer_length (buffer) < 4) {
			egg_buffer_reserve (buffer, 4);
			res = read (fd, buffer->buf + buffer->len, 4 - buffer->len);
			if (res <= 0) {
				if (errno != EAGAIN || errno != EINTR)
					finished = TRUE;
			} else {
				buffer->len += res;
			}

		/* Time for reading the packet */
		} else {
			if (!egg_buffer_get_uint32 (buffer, 0, NULL, &packet_size) || packet_size < 4) {
				g_message ("invalid packet size in control request");
				finished = TRUE;
			} else {
				g_assert (buffer->len < packet_size);
				egg_buffer_reserve (buffer, packet_size);
				res = read (fd, buffer->buf + buffer->len, packet_size - buffer->len);
				if (res <= 0) {
					if (errno != EAGAIN && errno != EINTR)
						finished = TRUE;
				} else {
					buffer->len += res;
					g_assert (buffer->len <= packet_size);
				}
			}
		}

		/* Received a full packet, process */
		if (packet_size && buffer->len == packet_size) {
			control_process (buffer, channel);
			finished = TRUE;
		}
	}

	if (finished)
		cond |= G_IO_HUP;

	return (cond & G_IO_HUP) == 0;
}

static gboolean
control_accept (GIOChannel *channel, GIOCondition cond, gpointer callback_data)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	ControlData *cdata;
	GIOChannel *new_channel;
	int fd, new_fd;
	int val;

	fd = g_io_channel_unix_get_fd (channel);

	addrlen = sizeof (addr);
	new_fd = accept (fd, (struct sockaddr *) &addr, &addrlen);
	if (new_fd < 0) {
		g_warning ("couldn't accept new control request: %s", g_strerror (errno));
		return TRUE;
	}

	val = fcntl (new_fd, F_GETFL, 0);
	if (val < 0) {
		g_warning ("can't get control request fd flags: %s", g_strerror (errno));
		close (new_fd);
		return TRUE;
	}

	if (fcntl (new_fd, F_SETFL, val | O_NONBLOCK) < 0) {
		g_warning ("can't set control request to non-blocking io: %s", g_strerror (errno));
		close (new_fd);
		return TRUE;
	}

	cdata = control_data_new ();
	new_channel = g_io_channel_unix_new (new_fd);
	g_io_channel_set_close_on_unref (new_channel, TRUE);
	g_io_add_watch_full (new_channel, G_PRIORITY_DEFAULT, G_IO_IN | G_IO_HUP,
	                     control_input, cdata, control_data_free);
	g_io_channel_unref (new_channel);

	return TRUE;
}

static void
control_cleanup_channel (gpointer user_data)
{
	gchar *path = user_data;
	unlink (path);
	g_free (path);
}

gboolean
gkd_control_listen (void)
{
	struct sockaddr_un addr;
	GIOChannel *channel;
	gchar *path;
	int sock;

	path = g_strdup_printf ("%s/control", gkd_util_get_master_directory ());
	egg_cleanup_register (control_cleanup_channel, path);

	unlink (path);

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		g_warning ("couldn't open socket: %s", g_strerror (errno));
		return FALSE;
	}

	memset (&addr, 0, sizeof (addr));
	addr.sun_family = AF_UNIX;
	g_strlcpy (addr.sun_path, path, sizeof (addr.sun_path));
	if (bind (sock, (struct sockaddr*) &addr, sizeof (addr)) < 0) {
		g_warning ("couldn't bind to control socket: %s: %s", path, g_strerror (errno));
		close (sock);
		return FALSE;
	}

	if (listen (sock, 128) < 0) {
		g_warning ("couldn't listen on control socket: %s: %s", path, g_strerror (errno));
		close (sock);
		return FALSE;
	}

	if (!egg_unix_credentials_setup (sock) < 0) {
		close (sock);
		return FALSE;
	}

	channel = g_io_channel_unix_new (sock);
	g_io_add_watch (channel, G_IO_IN | G_IO_HUP, control_accept, NULL);
	g_io_channel_set_close_on_unref (channel, TRUE);
	egg_cleanup_register ((GDestroyNotify)g_io_channel_unref, channel);

	return TRUE;
}

/* -----------------------------------------------------------------------------------
 * CONTROL CLIENT
 */

static int
control_connect (const gchar *path)
{
	struct sockaddr_un addr;
	struct stat st;
	int sock;

	/* First a bunch of checks to make sure nothing funny is going on */
	if (lstat (path, &st) < 0) {
		g_message ("couldn't access conrol socket: %s: %s", path, g_strerror (errno));
		return -1;

	} else if (st.st_uid != geteuid ()) {
		g_message("The control socket is not owned with the same "
		          "credentials as the user login: %s", path);
		return -1;

	} else if (S_ISLNK (st.st_mode) || !S_ISSOCK (st.st_mode)) {
		g_message ("The control socket is not a valid simple non-linked socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	g_strlcpy (addr.sun_path, path, sizeof (addr.sun_path));

	/* Now we connect */
	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		g_warning ("couldn't create control socket: %s", g_strerror (errno));
		return -1;
	}

	/* Close on exec */
	fcntl (sock, F_SETFD, 1);

	if (connect (sock, (struct sockaddr*) &addr, sizeof (addr)) < 0) {
		g_message ("couldn't connect to control socket at: %s: %s",
		           addr.sun_path, g_strerror (errno));
		close (sock);
		return -1;
	}

	/* This lets the server verify us */
	for (;;) {
		if (egg_unix_credentials_write (sock) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			g_message ("couldn't send credentials to control socket: %s",
			           g_strerror (errno));
			close (sock);
			return -1;
		}

		return sock;
	}
}

static gboolean
control_write (int fd, EggBuffer *buf)
{
	gsize bytes = 0;
	gssize res;

	while (bytes < buf->len) {
		res = write (fd, buf->buf + bytes, buf->len - bytes);
		if (res < 0) {
			if (errno != EINTR && errno != EAGAIN) {
				g_warning ("couldn't write all bytes to control socket: %s",
				           g_strerror (errno));
				return FALSE;
			}
		} else {
			bytes += res;
		}
	}

	return TRUE;
}

static gsize
control_read_raw (int fd, guchar *buf, size_t len)
{
	gsize bytes;
	gssize res;

	bytes = 0;
	while (bytes < len) {
		res = read (fd, buf + bytes, len - bytes);
		if (res <= 0) {
			if (res == 0)
				res = -1;
			else if (errno == EAGAIN)
				continue;
			else
				g_warning ("couldn't read %u bytes from control socket: %s",
					   (unsigned int)len, g_strerror (errno));
			return res;
		}
		bytes += res;
	}
	return bytes;
}


static gboolean
control_read (int fd, EggBuffer *buffer)
{
	guint32 packet_size;

	egg_buffer_resize (buffer, 4);
	if (control_read_raw (fd, buffer->buf, 4) != 4)
		return FALSE;

	if (!egg_buffer_get_uint32 (buffer, 0, NULL, &packet_size) ||
	    packet_size < 4)
		return FALSE;

	egg_buffer_resize (buffer, packet_size);
	if (control_read_raw (fd, buffer->buf + 4, packet_size - 4) != packet_size - 4)
		return FALSE;

	return TRUE;
}

static gboolean
control_chat (int sock)
{
	gchar **envp, **e;
	EggBuffer buffer;
	gsize offset;
	gboolean ret;
	guint32 res;

	envp = gkd_util_build_environment (GKD_UTIL_IN_ENVIRONMENT);

	egg_buffer_init_full (&buffer, 128, g_realloc);
	egg_buffer_add_uint32 (&buffer, 0);
	egg_buffer_add_uint32 (&buffer, GNOME_KEYRING_OP_PREPARE_ENVIRONMENT);
	egg_buffer_add_stringv (&buffer, (const char**)envp);
	egg_buffer_set_uint32 (&buffer, 0, buffer.len);

	g_strfreev (envp);

	g_return_val_if_fail (!egg_buffer_has_error (&buffer), FALSE);

	envp = NULL;

	ret = control_write (sock, &buffer) &&
	      control_read (sock, &buffer);

	offset = 4;
	if (ret)
		ret = egg_buffer_get_uint32 (&buffer, offset, &offset, &res);
	if (ret && res == GNOME_KEYRING_RESULT_OK)
	      egg_buffer_get_stringv (&buffer, offset, &offset, &envp, g_realloc);

	egg_buffer_uninit (&buffer);

	if (!ret || res != GNOME_KEYRING_RESULT_OK) {
		g_message ("couldn't initialize running daemon");
		return FALSE;
	}

	g_return_val_if_fail (envp, FALSE);
	for (e = envp; *e; ++e)
		gkd_util_push_environment_full (*e);
	g_strfreev (envp);

	return TRUE;
}

gboolean
gkd_control_initialize (const gchar *directory)
{
	gboolean ret;
	gchar *path;
	int sock;

	g_return_val_if_fail (directory, FALSE);

	path = g_strdup_printf ("%s/control", directory);
	sock = control_connect (path);
	g_free (path);

	if (sock < 0)
		return FALSE;

	ret = control_chat (sock);

	close (sock);
	return ret;
}
