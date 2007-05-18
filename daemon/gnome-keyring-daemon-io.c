/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-daemon-io.c - handles i/o from the clients

   Copyright (C) 2003 Red Hat, Inc

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

   Author: Alexander Larsson <alexl@redhat.com>
*/

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#if defined(HAVE_GETPEERUCRED)
#include <ucred.h>
#endif

#include "gnome-keyring-daemon.h"
#include "mkdtemp.h"

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-private.h"
#include "library/gnome-keyring-proto.h"
#include "keyrings/gkr-keyrings.h"
#include "ui/gkr-ask-daemon.h"

#ifndef HAVE_SOCKLEN_T
#define socklen_t int
#endif

typedef enum {
	GNOME_CLIENT_STATE_CREDENTIALS,
	GNOME_CLIENT_STATE_READ_DISPLAYNAME,
	GNOME_CLIENT_STATE_READ_PACKET,
	GNOME_CLIENT_STATE_COLLECT_INFO,
	GNOME_CLIENT_STATE_REQUEST_ACCESS,
	GNOME_CLIENT_STATE_EXECUTE_OP,
	GNOME_CLIENT_STATE_WRITE_REPLY
} GnomeKeyringClientStates;

typedef struct {
	GnomeKeyringClientStates state;
	int sock;

	GnomeKeyringApplicationRef *app_ref;

	guint hup_watch;
	
	guint input_watch;
	GIOChannel *input_channel;
	GString *input_buffer;
	gint input_pos;

	GkrAskRequest* ask;

	GList *ask_requests;
	GList *granted_requests;

	guint output_watch;
	GString *output_buffer;
	gint output_pos;
} GnomeKeyringClient;

char tmp_dir[1024];
char socket_path[1024];
GList *clients = NULL;

#if 0
#define debug_print(x) g_print x
#else
#define debug_print(x)
#endif


static void gnome_keyring_client_state_machine (GnomeKeyringClient *client);
static void ask_result (GkrAskRequest *ask, gpointer data);

static gboolean
set_local_creds (int fd, gboolean on)
{
  gboolean retval = TRUE;

#if defined(LOCAL_CREDS) && !defined(HAVE_CMSGCRED)
  int val = on ? 1 : 0;
  if (setsockopt (fd, 0, LOCAL_CREDS, &val, sizeof (val)) < 0)
    {
      g_warning ("Unable to set LOCAL_CREDS socket option on fd %d\n", fd);
      retval = FALSE;
    }
#endif

  return retval;
}


static gboolean
read_unix_socket_credentials (int fd,
			      pid_t *pid,
			      uid_t *uid)
{
	struct msghdr msg;
	struct iovec iov;
	char buf;
	
#if defined(HAVE_CMSGCRED) || defined(LOCAL_CREDS)
	/* Prefer CMSGCRED over LOCAL_CREDS because the former provides the
	 * remote PID. */
#if defined(HAVE_CMSGCRED)
	struct cmsgcred *cred;
	const size_t cmsglen = CMSG_LEN (sizeof (struct cmsgcred));
	const size_t cmsgspace = CMSG_SPACE (sizeof (struct cmsgcred));
#else /* defined(LOCAL_CREDS) */
	struct sockcred *cred;
	const size_t cmsglen = CMSG_LEN (sizeof (struct sockcred));
	const size_t cmsgspace = CMSG_SPACE (sizeof (struct sockcred));
#endif
	union {
		struct cmsghdr hdr;
		char cred[cmsgspace];
	} cmsg;
#endif
	
	*pid = 0;
	*uid = 0;
	
	/* If LOCAL_CREDS are used in this platform, they have already been
	 * initialized by init_connection prior to sending of the credentials
	 * byte we receive below. */
	
	iov.iov_base = &buf;
	iov.iov_len = 1;
	
	memset (&msg, 0, sizeof (msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
#if defined(HAVE_CMSGCRED) || defined(LOCAL_CREDS)
	memset (&cmsg, 0, sizeof (cmsg));
	msg.msg_control = (caddr_t) &cmsg;
	msg.msg_controllen = cmsgspace;
#endif

 again:
	if (recvmsg (fd, &msg, 0) < 0) {
		if (errno == EINTR) {
			goto again;
		}
		
		g_warning ("Failed to read credentials byte");
		return FALSE;
	}
	
	if (buf != '\0') {
		g_warning ("Credentials byte was not nul");
		return FALSE;
	}

#if defined(HAVE_CMSGCRED) || defined(LOCAL_CREDS)
	if (cmsg.hdr.cmsg_len < cmsglen || cmsg.hdr.cmsg_type != SCM_CREDS) {
		g_warning ("Message from recvmsg() was not SCM_CREDS\n");
		return FALSE;
	}
#endif

	{
#ifdef SO_PEERCRED
		struct ucred cr;   
		socklen_t cr_len = sizeof (cr);
		
		if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) == 0 &&
		    cr_len == sizeof (cr)) {
			*pid = cr.pid;
			*uid = cr.uid;
		} else {
			g_warning ("Failed to getsockopt() credentials, returned len %d/%d\n",
				   cr_len, (int) sizeof (cr));
			return FALSE;
		}
#elif defined(HAVE_CMSGCRED)
		cred = (struct cmsgcred *) CMSG_DATA (&cmsg.hdr);
		*pid = cred->cmcred_pid;
		*uid = cred->cmcred_euid;
#elif defined(LOCAL_CREDS)
		cred = (struct sockcred *) CMSG_DATA (&cmsg.hdr);
		*pid = 0;
		*uid = cred->sc_euid;
		set_local_creds(fd, FALSE);
#elif defined(HAVE_GETPEERUCRED)
		ucred_t *uc = NULL;

		if (getpeerucred (fd, &uc) == 0) {
			*pid = ucred_getpid (uc);
			*uid = ucred_geteuid (uc);
			ucred_free (uc);
		} else {
			g_warning ("getpeerucred() failed: %s", strerror (errno));
			return FALSE;
		}
#else /* !SO_PEERCRED && !HAVE_CMSGCRED */
		g_warning ("Socket credentials not supported on this OS\n");
		return FALSE;
#endif
	}

	return TRUE;
}


static void
gnome_keyring_client_free (GnomeKeyringClient *client)
{
	clients = g_list_remove (clients, client);


	if (client->input_buffer != NULL) {
		g_string_free (client->input_buffer, TRUE);
	}
	if (client->output_buffer != NULL) {
		g_string_free (client->output_buffer, TRUE);
	}

	if (client->app_ref != NULL) {
		gnome_keyring_application_ref_free (client->app_ref);
	}

	if (client->input_watch != 0) {
		g_source_remove (client->input_watch);
	}

	if (client->output_watch != 0) {
		g_source_remove (client->output_watch);
	}

	if (client->hup_watch != 0) {
		g_source_remove (client->hup_watch);
	}

	if (client->ask != NULL) {
		g_signal_handlers_disconnect_by_func (client->ask, ask_result, client);
		gkr_ask_daemon_cancel (client->ask);
	}
	
	close (client->sock);
	g_free (client);
}

static gboolean
read_packet_with_size (GnomeKeyringClient *client)
{
	int fd;
	guint32 packet_size;
	int res;

	fd = client->sock;
	
	if (client->input_pos < 4) {
		g_string_set_size (client->input_buffer, 4);
		res = read (fd, client->input_buffer->str + client->input_pos,
			    4 - client->input_pos);
		if (res <= 0) {
			if (errno != EAGAIN &&
			    errno != EINTR) {
				gnome_keyring_client_free (client);
			}
			return FALSE;
		}
		
		client->input_pos += res;
	}

	if (client->input_pos >= 4) {
		if (!gnome_keyring_proto_decode_packet_size (client->input_buffer, &packet_size)) {
			gnome_keyring_client_free (client);
			return FALSE;
		}
		if (packet_size < 4) {
			gnome_keyring_client_free (client);
			return FALSE;
		}
		
		g_assert (client->input_pos < packet_size);
		g_string_set_size (client->input_buffer, packet_size);

		res = read (fd, client->input_buffer->str + client->input_pos,
			    packet_size - client->input_pos);
		if (res <= 0) {
			if (errno != EAGAIN &&
			    errno != EINTR) {
				gnome_keyring_client_free (client);
			}
			return FALSE;
		}
				
		client->input_pos += res;
		
		if (client->input_pos == packet_size) {
			return TRUE;
		}
	}

	return FALSE;
}

static void 
ask_list_free (GList *asks)
{
	GList *l;
	
	for (l = asks; l; l = g_list_next (l))
		g_object_unref (l->data);
	g_list_free (asks);
}

static void
ask_result (GkrAskRequest *ask, gpointer data)
{
	GnomeKeyringClient *client;

	client = data;
	
	/* Should match up with the first one in the ask list */
	g_assert (client->ask == ask);
	
	/* Move it to the granted list? */
	if (ask->response >= GKR_ASK_RESPONSE_ALLOW) {
		client->granted_requests = g_list_append (client->granted_requests, ask);
		g_object_ref (ask);
	}
	
	/* And discard it */
	g_object_unref (client->ask);
	client->ask = NULL;

	gnome_keyring_client_state_machine (client);
}

static gboolean
gnome_keyring_client_io (GIOChannel  *channel,
			 GIOCondition cond,
			 gpointer     callback_data)
{
	GnomeKeyringClient *client;

	client = callback_data;
	gnome_keyring_client_state_machine (client);
	
	return TRUE;
}

static void
gnome_keyring_client_state_machine (GnomeKeyringClient *client)
{
	GnomeKeyringOpCode op;
	GIOChannel *channel;
	GList *access_requests;
	pid_t pid;
	uid_t uid;
	int res;
	char *str;
	
 new_state:
	switch (client->state) {
	case GNOME_CLIENT_STATE_CREDENTIALS:
		debug_print (("GNOME_CLIENT_STATE_CREDENTIALS %p\n", client));
		if (!read_unix_socket_credentials (client->sock, &pid, &uid)) {
			gnome_keyring_client_free (client);
			return;
		}
		if (getuid() != uid) {
			g_warning ("uid mismatch: %u, should be %u\n",
				   (guint)uid, (guint)getuid());
			gnome_keyring_client_free (client);
			return;
		}
		client->app_ref = gnome_keyring_application_ref_new_from_pid (pid);

		client->input_pos = 0;
		client->state = GNOME_CLIENT_STATE_READ_DISPLAYNAME;
		break;
		
	case GNOME_CLIENT_STATE_READ_DISPLAYNAME:
		debug_print (("GNOME_CLIENT_STATE_READ_DISPLAYNAME %p\n", client));
		if (read_packet_with_size (client)) {
			debug_print (("read packet\n"));
			if (!gnome_keyring_proto_get_utf8_string (client->input_buffer,
								  4, NULL, &str)) {
				gnome_keyring_client_free (client);
				return;
			}
			if (!str) {
				gnome_keyring_client_free (client);
				return;
			}
			debug_print (("got name: %s\n", str));
			client->app_ref->display_name = str;
			client->input_pos = 0;
			client->state = GNOME_CLIENT_STATE_READ_PACKET;
		}
		break;
		
	case GNOME_CLIENT_STATE_READ_PACKET:
		debug_print (("GNOME_CLIENT_STATE_READ_PACKET %p\n", client));
		if (read_packet_with_size (client)) {
			debug_print (("read packet, size: %d\n", client->input_buffer->len));
			g_source_remove (client->input_watch);
			client->input_watch = 0;
			client->state = GNOME_CLIENT_STATE_COLLECT_INFO;
			
			goto new_state;
		}
		break;
		
	case GNOME_CLIENT_STATE_COLLECT_INFO:
		debug_print (("GNOME_CLIENT_STATE_COLLECT_INFO %p\n", client));
		if (!gnome_keyring_proto_decode_packet_operation (client->input_buffer, &op)) {
			gnome_keyring_client_free (client);
			return;
		}
		if (op < 0 || op >= GNOME_KEYRING_NUM_OPS) {
			gnome_keyring_client_free (client);
			return;
		}

		if (keyring_ops[op].collect_info == NULL) {
			client->state = GNOME_CLIENT_STATE_EXECUTE_OP;
			goto new_state;
		}
		
		/* Make sure keyrings in memory are up to date before asking for access */
		gkr_keyrings_update ();
		
		access_requests = NULL;
		if (!keyring_ops[op].collect_info (client->input_buffer, client->app_ref, 
						   &access_requests)) {
			gnome_keyring_client_free (client);
			return;
		}
		
		/* All the things we have to ask about */
		client->ask_requests = access_requests;

		/* request_access can reenter here if there is no need to
		 * wait for access rights */
		client->state = GNOME_CLIENT_STATE_REQUEST_ACCESS;
		goto new_state;
		
	case GNOME_CLIENT_STATE_REQUEST_ACCESS:
		debug_print (("GNOME_CLIENT_STATE_REQUEST_ACCESS %p\n", client));
		
		/* Nothing should currently be asking */
		g_assert (!client->ask);
		
		/* Some access requests are processed right away, so loop */
		if (!client->ask && client->ask_requests) {
			
			/* Go for first item in the list */
			client->ask = GKR_ASK_REQUEST (client->ask_requests->data);
			client->ask_requests = g_list_remove (client->ask_requests, client->ask);
			g_signal_connect (client->ask, "completed", G_CALLBACK (ask_result), client);
			gkr_ask_daemon_queue (client->ask);
			
			/* 
			 * If it was processed immediately, then ask_result will have 
			 * already been called and client->ask will be NULL.
			 */
			return;
		}
		
		/* Got all data now? */
		if (!client->ask) {
			g_assert (!client->ask_requests);
			client->state = GNOME_CLIENT_STATE_EXECUTE_OP;
			goto new_state;
		}
		break;
		
	case GNOME_CLIENT_STATE_EXECUTE_OP:
		debug_print (("GNOME_CLIENT_STATE_EXECUTE_OP %p\n", client));
		if (!gnome_keyring_proto_decode_packet_operation (client->input_buffer, &op)) {
			gnome_keyring_client_free (client);
			return;
		}

		client->output_buffer = g_string_new (NULL);

		/* Make sure keyrings in memory are up to date */
		/* This call may remove items or keyrings, which change
		   the client->access_requests list */
		gkr_keyrings_update ();

		/* Must have already processed all requests */
		g_assert (!client->ask);
		g_assert (!client->ask_requests);
		
		/* Add empty size */
		gnome_keyring_proto_add_uint32 (client->output_buffer, 0);
		
		if (!keyring_ops[op].execute_op (client->input_buffer,
						 client->output_buffer,
						 client->app_ref,
						 client->granted_requests)) {
			gnome_keyring_client_free (client);
			return;
		}
		
		ask_list_free (client->granted_requests);
		client->granted_requests = NULL;

		if (!gnome_keyring_proto_set_uint32 (client->output_buffer, 0,
						     client->output_buffer->len)) {
			gnome_keyring_client_free (client);
			return;
		}

		client->output_pos = 0;
		channel = g_io_channel_unix_new (client->sock);
		client->output_watch = g_io_add_watch (channel, G_IO_OUT,
						      gnome_keyring_client_io, client);
		g_io_channel_unref (channel);
		
		client->state = GNOME_CLIENT_STATE_WRITE_REPLY;
		goto new_state;
		break;
		
	case GNOME_CLIENT_STATE_WRITE_REPLY:
		debug_print (("GNOME_CLIENT_STATE_WRITE_REPLY %p\n", client));
		debug_print (("writing %d bytes\n", client->output_buffer->len));
		res = write (client->sock,
			     client->output_buffer->str + client->output_pos,
			     client->output_buffer->len - client->output_pos);
		if (res <= 0) {
			if (errno != EAGAIN &&
			    errno != EINTR) {
				gnome_keyring_client_free (client);
			}
			return;
		}
		client->output_pos += res;

		if (client->output_pos == client->output_buffer->len) {
			/* Finished operation */
			gnome_keyring_client_free (client);
		}
		break;
		
	default:
		break;
	}
}

static gboolean
gnome_keyring_client_hup (GIOChannel  *channel,
			  GIOCondition cond,
			  gpointer     callback_data)
{
	GnomeKeyringClient *client;

	client = callback_data;
	
	gnome_keyring_client_free (client);
	
	return TRUE;
}

static void
gnome_keyring_client_new (int fd)
{
	GnomeKeyringClient *client;
	GIOChannel *channel;

	client = g_new0 (GnomeKeyringClient, 1);

	debug_print (("gnome_keyring_client_new(fd:%d) -> %p\n", fd, client));
	
	channel = g_io_channel_unix_new (fd);
	client->input_watch = g_io_add_watch (channel, G_IO_IN,
					      gnome_keyring_client_io, client);
	g_io_channel_unref (channel);
	
	channel = g_io_channel_unix_new (fd);
	client->hup_watch = g_io_add_watch (channel, G_IO_HUP,
					      gnome_keyring_client_hup, client);
	g_io_channel_unref (channel);

	client->state = GNOME_CLIENT_STATE_CREDENTIALS;
	client->sock = fd;
	client->input_channel = channel;
	client->input_buffer = g_string_new (NULL);
	client->input_pos = 0;

	clients = g_list_prepend (clients, client);
}


static gboolean
new_client (GIOChannel  *channel,
	    GIOCondition cond,
	    gpointer     callback_data)
{
	int fd;
	int new_fd;
	struct sockaddr_un addr;
	socklen_t addrlen;
	int val;
  
	fd = g_io_channel_unix_get_fd (channel);
	
	addrlen = sizeof (addr);
	new_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);

	val = fcntl (new_fd, F_GETFL, 0);
	if (val < 0) {
		g_warning ("Cant get client fd flags");
		close (new_fd);
		return TRUE;
	}
	if (fcntl (new_fd, F_SETFL, val | O_NONBLOCK) < 0) {
		g_warning ("Cant set client fd nonblocking");
		close (new_fd);
		return TRUE;
	}
	
	if (new_fd >= 0) {
		gnome_keyring_client_new (new_fd);
	}
	return TRUE;
}

void
cleanup_socket_dir (void)
{
	unlink (socket_path);
	rmdir (tmp_dir);
}

gboolean
create_master_socket (const char **path)
{
	int sock;
	struct sockaddr_un addr;
	GIOChannel *channel;
	gchar *tmp_tmp_dir;
	
	/* Create private directory for agent socket */
	tmp_tmp_dir = g_build_filename (g_get_tmp_dir (), "keyring-XXXXXX", NULL);
	strncpy (tmp_dir, tmp_tmp_dir, sizeof (tmp_dir));
	if (mkdtemp (tmp_dir) == NULL) {
		perror ("mkdtemp: socket dir");
		return FALSE;
	}
	snprintf (socket_path, sizeof (socket_path), "%s/socket", tmp_dir);
	
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		cleanup_socket_dir ();
		return FALSE;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, socket_path, sizeof (addr.sun_path));
	if (bind (sock, (struct sockaddr *) & addr, sizeof (addr)) < 0) {
		perror ("bind");
		cleanup_socket_dir ();
		return FALSE;
	}
	
	if (listen (sock, 128) < 0) {
		perror ("listen");
		cleanup_socket_dir ();
		return FALSE;
	}

        if (!set_local_creds (sock, TRUE)) {
		close (sock);
		cleanup_socket_dir ();
		return FALSE;
	}

	g_free (tmp_tmp_dir);
	channel = g_io_channel_unix_new (sock);
	g_io_add_watch (channel, G_IO_IN | G_IO_HUP, new_client, NULL);
	g_io_channel_unref (channel);
	
	*path = socket_path;
	return TRUE;
}

