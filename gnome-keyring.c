/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring.c - library for talking to the keyring daemon.

   Copyright (C) 2003 Red Hat, Inc

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
*/

#include "config.h"

#include "gnome-keyring.h"
#include "gnome-keyring-private.h"
#include "gnome-keyring-proto.h"

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <stdarg.h>

typedef enum {
	CALLBACK_DONE,
	CALLBACK_GET_STRING,
	CALLBACK_GET_INT,
	CALLBACK_GET_LIST,
	CALLBACK_GET_KEYRING_INFO,
	CALLBACK_GET_ITEM_INFO,
	CALLBACK_GET_ATTRIBUTES,
	CALLBACK_GET_ACL
} KeyringCallbackType;

typedef enum {
	STATE_FAILED,
	STATE_WRITING_CREDS,
	STATE_WRITING_PACKET,
	STATE_READING_REPLY
} KeyringState;

typedef struct GnomeKeyringOperation GnomeKeyringOperation;

typedef void (*KeyringHandleReply) (GnomeKeyringOperation *op);

struct GnomeKeyringOperation {
	int socket;

	KeyringState state;
	GnomeKeyringResult result;

	guint io_watch;
	
	GString *send_buffer;
	gsize send_pos;

	GString *receive_buffer;
	gsize receive_pos;
	
	KeyringCallbackType user_callback_type;
	gpointer user_callback;
	gpointer user_data;
	GDestroyNotify destroy_user_data;

	KeyringHandleReply reply_handler;
};

/**
 * GnomeKeyringAttributeList:
 *
 * A list of keyring item attributes. It's used to search for keyring items
 * with eg. gnome_keyring_find_items_sync().
 */

/**
 * gnome_keyring_attribute_list_new():
 *
 * Create a new #GnomeKeyringAttributeList.
 *
 * Returns an empty #GnomeKeyringAttributeList.
 */

static int
connect_to_daemon (gboolean non_blocking)
{
	const char *socket_file;
	struct sockaddr_un addr;
	int sock;
	int val;

	socket_file = g_getenv ("GNOME_KEYRING_SOCKET");
	
	if (socket_file == NULL) {
		return -1;
	}

	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, socket_file, sizeof (addr.sun_path));
	
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

	val = fcntl (sock, F_GETFL, 0);
	if (val < 0) {
		close (sock);
		return -1;
	}

	if (non_blocking) {
		if (fcntl (sock, F_SETFL, val | O_NONBLOCK) < 0) {
			close (sock);
			return -1;
		}
	}
	
	return sock;
}


static void
gnome_keyring_operation_free (GnomeKeyringOperation *op)
{
	if (op->io_watch != 0) {
		g_source_remove (op->io_watch);
		op->io_watch = 0;
	}
	if (op->destroy_user_data != NULL) {
		(*op->destroy_user_data) (op->user_data);
	}
	if (op->send_buffer != NULL) {
		g_string_free (op->send_buffer, TRUE);
	}
	if (op->receive_buffer != NULL) {
		g_string_free (op->receive_buffer, TRUE);
	}
	close (op->socket);
	g_free (op);
}

static gboolean
op_failed (gpointer data)
{
	GnomeKeyringOperation *op;

	op = data;

	switch (op->user_callback_type) {
	case CALLBACK_DONE:
		((GnomeKeyringOperationDoneCallback)op->user_callback) (op->result, op->user_data);
		break;
	case CALLBACK_GET_STRING:
		((GnomeKeyringOperationGetStringCallback)op->user_callback) (op->result, NULL, op->user_data);
		break;
	case CALLBACK_GET_INT:
		((GnomeKeyringOperationGetIntCallback)op->user_callback) (op->result, 0, op->user_data);
		break;
	case CALLBACK_GET_LIST:
		((GnomeKeyringOperationGetListCallback)op->user_callback) (op->result, NULL, op->user_data);
		break;
	case CALLBACK_GET_KEYRING_INFO:
		((GnomeKeyringOperationGetKeyringInfoCallback)op->user_callback) (op->result, NULL, op->user_data);
		break;
	case CALLBACK_GET_ITEM_INFO:
		((GnomeKeyringOperationGetItemInfoCallback)op->user_callback) (op->result, NULL, op->user_data);
		break;
	case CALLBACK_GET_ATTRIBUTES:
		((GnomeKeyringOperationGetAttributesCallback)op->user_callback) (op->result, NULL, op->user_data);
		break;
	case CALLBACK_GET_ACL:
		((GnomeKeyringOperationGetListCallback)op->user_callback) (op->result, NULL, op->user_data);
		break;
	}

	gnome_keyring_operation_free (op);
	
	return FALSE;
}


static void
schedule_op_failed (GnomeKeyringOperation *op,
		    GnomeKeyringResult result)
{
	if (op->io_watch != 0) {
		g_source_remove (op->io_watch);
		op->io_watch = 0;
	}
	op->state = STATE_FAILED;
	op->result = result;
	g_idle_add (op_failed, op);
}

static int
read_all (int fd, char *buf, size_t len)
{
	size_t bytes;
	ssize_t res;
	
	bytes = 0;
	while (bytes < len) {
		res = read (fd, buf + bytes, len - bytes);
		if (res <= 0) {
			if (res == 0)
				res = -1;
			return res;
		}
		bytes += res;
	}
	return 0;
}


static int
write_all (int fd, const char *buf, size_t len)
{
	size_t bytes;
	ssize_t res;

	bytes = 0;
	while (bytes < len) {
		res = write (fd, buf + bytes, len - bytes);
		if (res < 0) {
			if (errno != EINTR &&
			    errno != EAGAIN) {
				perror ("write_all write failure:");
				return -1;
			}
		} else {
			bytes += res;
		}
	}
	return 0;
}

static GnomeKeyringResult
write_credentials_byte_sync (int socket)
{
  char buf;
  int bytes_written;
#if defined(HAVE_CMSGCRED) && (!defined(LOCAL_CREDS) || defined(__FreeBSD__))
  union {
	  struct cmsghdr hdr;
	  char cred[CMSG_SPACE (sizeof (struct cmsgcred))];
  } cmsg;
  struct iovec iov;
  struct msghdr msg;
#endif

  buf = 0;
#if defined(HAVE_CMSGCRED) && (!defined(LOCAL_CREDS) || defined(__FreeBSD__))
  iov.iov_base = &buf;
  iov.iov_len = 1;

  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  msg.msg_control = (caddr_t) &cmsg;
  msg.msg_controllen = CMSG_SPACE (sizeof (struct cmsgcred));
  memset (&cmsg, 0, sizeof (cmsg));
  cmsg->cmsg_len = CMSG_LEN (sizeof (struct cmsgcred));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_CREDS;
#endif

 again:

#if defined(HAVE_CMSGCRED) && (!defined(LOCAL_CREDS) || defined(__FreeBSD__))
  bytes_written = sendmsg (socket, &msg, 0);
#else
  bytes_written = write (socket, &buf, 1);
#endif

  if (bytes_written < 0 && errno == EINTR)
    goto again;

  if (bytes_written <= 0) {
	  return GNOME_KEYRING_RESULT_IO_ERROR;
  } else {
	  return GNOME_KEYRING_RESULT_OK;
  }
}
  

static void
write_credentials_byte (GnomeKeyringOperation *op)
{
  char buf;
  int bytes_written;
#if defined(HAVE_CMSGCRED) && (!defined(LOCAL_CREDS) || defined(__FreeBSD__))
  union {
	  struct cmsghdr hdr;
	  char cred[CMSG_SPACE (sizeof (struct cmsgcred))];
  } cmsg;
  struct iovec iov;
  struct msghdr msg;
#endif

  buf = 0;
#if defined(HAVE_CMSGCRED) && (!defined(LOCAL_CREDS) || defined(__FreeBSD__))
  iov.iov_base = &buf;
  iov.iov_len = 1;

  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  msg.msg_control = (caddr_t) &cmsg;
  msg.msg_controllen = CMSG_SPACE (sizeof (struct cmsgcred));
  memset (cmsg, 0, sizeof (cmsg));
  cmsg->cmsg_len = CMSG_LEN (sizeof (struct cmsgcred));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_CREDS;
#endif

 again:

#if defined(HAVE_CMSGCRED) && (!defined(LOCAL_CREDS) || defined(__FreeBSD__))
  bytes_written = sendmsg (op->socket, &msg, 0);
#else
  bytes_written = write (op->socket, &buf, 1);
#endif

  if (bytes_written < 0 && errno == EINTR)
    goto again;

  if (bytes_written <= 0) {
	  if (errno == EAGAIN) {
		  return;
	  }
	  schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
	  return;
  } else {
	  op->state = STATE_WRITING_PACKET;
	  return;
  }
}



static gboolean
operation_io (GIOChannel  *io_channel,
	      GIOCondition cond,
	      gpointer     callback_data)
{
	GIOChannel *channel;
	GnomeKeyringOperation *op;
	int res;
	guint32 packet_size;

	op = callback_data;

	if (cond & G_IO_HUP && !(cond & G_IO_IN)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
	}

	if (op->state == STATE_WRITING_CREDS && (cond & G_IO_OUT)) {
		write_credentials_byte (op);
	}
	if (op->state == STATE_WRITING_PACKET && (cond & G_IO_OUT)) {
		res = write (op->socket,
			     op->send_buffer->str + op->send_pos,
			     op->send_buffer->len - op->send_pos);
		if (res <= 0) {
			if (errno != EAGAIN &&
			    errno != EINTR) {
				schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
			} 
		} else {
			op->send_pos += res;

			if (op->send_pos == op->send_buffer->len) {
				op->state = STATE_READING_REPLY;
				op->receive_buffer = g_string_new (NULL);
				op->receive_pos = 0;
				
				g_source_remove (op->io_watch);
				channel = g_io_channel_unix_new (op->socket);
				op->io_watch = g_io_add_watch (channel,
							       G_IO_IN | G_IO_HUP,
							       operation_io, op);
				g_io_channel_unref (channel);
			}
		}
	}

	if (op->state == STATE_READING_REPLY && (cond & G_IO_IN)) {
		if (op->receive_pos < 4) {
			g_string_set_size (op->receive_buffer, 4);
			res = read (op->socket,
				    op->receive_buffer->str + op->receive_pos,
				    4 - op->receive_pos);
			if (res <= 0) {
				if (errno != EAGAIN &&
				    errno != EINTR) {
					schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
				}
			} else {
				op->receive_pos += res;
			}
		}
		
		if (op->receive_pos >= 4) {
			if (!gnome_keyring_proto_decode_packet_size (op->receive_buffer,
								     &packet_size) ||
			    packet_size < 4) {
				schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
			}
		
			g_assert (op->receive_pos <= packet_size);
			g_string_set_size (op->receive_buffer, packet_size);

			res = read (op->socket, op->receive_buffer->str + op->receive_pos,
				    packet_size - op->receive_pos);
			if (res <= 0) {
				if (errno != EAGAIN &&
				    errno != EINTR) {
					schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
				}
			} else {
				op->receive_pos += res;
				
				if (op->receive_pos == packet_size) {
					g_source_remove (op->io_watch);
					op->io_watch = 0;
					op->result = GNOME_KEYRING_RESULT_OK;
					
					(*op->reply_handler) (op);
					gnome_keyring_operation_free (op);
				}
			}
		}
	}
	

	return TRUE;
}


static GnomeKeyringOperation *
start_operation (gpointer callback, KeyringCallbackType callback_type,
		 gpointer user_data, GDestroyNotify destroy_user_data)
{
	GnomeKeyringOperation *op;
	GIOChannel *channel;

	op = g_new0 (GnomeKeyringOperation, 1);

	/* Start in failed mode */
	op->state = STATE_FAILED;
	op->result = GNOME_KEYRING_RESULT_OK;

	op->user_callback_type = callback_type;
	op->user_callback = callback;
	op->user_data = user_data;
	op->destroy_user_data = destroy_user_data;
	
	op->socket = connect_to_daemon (TRUE);

	if (op->socket < 0) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON);
	} else  {
		op->state = STATE_WRITING_CREDS;
		op->send_buffer = g_string_new (NULL);
		op->send_pos = 0;
		
		channel = g_io_channel_unix_new (op->socket);
		op->io_watch = g_io_add_watch (channel,
					       G_IO_OUT | G_IO_HUP,
					       operation_io, op);
		g_io_channel_unref (channel);
	} 
	
	return op;
}

static GnomeKeyringResult
run_sync_operation (GString *buffer,
		    GString *receive_buffer)
{
	GnomeKeyringResult res;
	int socket;
	guint32 packet_size;

	g_assert (buffer != NULL);
	g_assert (receive_buffer != NULL);

	socket = connect_to_daemon (FALSE);
	if (socket < 0) {
		return GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON;
	}
	res = write_credentials_byte_sync (socket);
	if (res != GNOME_KEYRING_RESULT_OK) {
		close (socket);
		return res;
	}

	if (write_all (socket,
		       buffer->str, buffer->len) < 0) {
		close (socket);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}

	g_string_set_size (receive_buffer, 4);
	if (read_all (socket, receive_buffer->str, 4) < 0) {
		close (socket);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}

	if (!gnome_keyring_proto_decode_packet_size (receive_buffer,
						     &packet_size) ||
	    packet_size < 4) {
		close (socket);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	
	g_string_set_size (receive_buffer, packet_size);
	if (read_all (socket, receive_buffer->str + 4, packet_size - 4) < 0) {
		close (socket);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	close (socket);
	
	return GNOME_KEYRING_RESULT_OK;
}

/**
 * gnome_keyring_is_available():
 *
 * Check whether you can communicate with a Gnome Keyring Daemon.
 *
 * Returns %FALSE if you can't communicate with the daemon (so you can't load
 * and save passwords).
 */
gboolean
gnome_keyring_is_available (void)
{
	int socket;
	
	socket = connect_to_daemon (FALSE);
	if (socket < 0) {
		return FALSE;
	}
	close (socket);
	return TRUE;
}


void
gnome_keyring_cancel_request (gpointer request)
{
	GnomeKeyringOperation *op;

	op = request;

	schedule_op_failed (op, GNOME_KEYRING_RESULT_CANCELLED);
}

static void
gnome_keyring_standard_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationDoneCallback callback;

	g_assert (op->user_callback_type == CALLBACK_DONE);
	
	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_result_reply (op->receive_buffer, &result)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, op->user_data);
	} else {
		(*callback) (result, op->user_data);
	}
}

static void
gnome_keyring_string_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetStringCallback callback;
	char *string;

	g_assert (op->user_callback_type == CALLBACK_GET_STRING);

	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_result_string_reply (op->receive_buffer, &result, &string)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, string, op->user_data);
		g_free (string);
	}
}

static void
gnome_keyring_int_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetIntCallback callback;
	guint32 integer;

	g_assert (op->user_callback_type == CALLBACK_GET_INT);

	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_result_integer_reply (op->receive_buffer, &result, &integer)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, 0, op->user_data);
	} else {
		(*callback) (result, integer, op->user_data);
	}
}

gpointer
gnome_keyring_set_default_keyring (const char                             *keyring,
				   GnomeKeyringOperationDoneCallback       callback,
				   gpointer                                data,
				   GDestroyNotify                          destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}

	if (!gnome_keyring_proto_encode_op_string (op->send_buffer,
						   GNOME_KEYRING_OP_SET_DEFAULT_KEYRING,
						   keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_standard_reply;
	return op;
}

GnomeKeyringResult 
gnome_keyring_set_default_keyring_sync (const char *keyring)
{
	GString *send, *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_op_string (send,
						   GNOME_KEYRING_OP_SET_DEFAULT_KEYRING,
						   keyring)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

	if (!gnome_keyring_proto_decode_result_reply (receive, &res)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
 	g_string_free (receive, TRUE);

	return res;
}

gpointer
gnome_keyring_get_default_keyring (GnomeKeyringOperationGetStringCallback  callback,
				   gpointer                                data,
				   GDestroyNotify                          destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_STRING, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}

	if (!gnome_keyring_proto_encode_op_only (op->send_buffer,
						 GNOME_KEYRING_OP_GET_DEFAULT_KEYRING)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_string_reply;
	return op;
}

GnomeKeyringResult 
gnome_keyring_get_default_keyring_sync (char **keyring)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);
	
	*keyring = NULL;

	if (!gnome_keyring_proto_encode_op_only (send,
						 GNOME_KEYRING_OP_GET_DEFAULT_KEYRING)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

	if (!gnome_keyring_proto_decode_result_string_reply (receive, &res, keyring)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}

static void
gnome_keyring_list_keyring_names_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetListCallback callback;
	GList *names;

	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_result_string_list_reply (op->receive_buffer, &result, &names)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, names, op->user_data);
		g_list_foreach (names, (GFunc) g_free, NULL);
		g_list_free (names);
	}
}

gpointer
gnome_keyring_list_keyring_names  (GnomeKeyringOperationGetListCallback    callback,
				   gpointer                                data,
				   GDestroyNotify                          destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_LIST, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}

	if (!gnome_keyring_proto_encode_op_only (op->send_buffer,
						 GNOME_KEYRING_OP_LIST_KEYRINGS)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_list_keyring_names_reply;
	return op;
}

GnomeKeyringResult 
gnome_keyring_list_keyring_names_sync (GList **keyrings)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);
	
	*keyrings = NULL;

	if (!gnome_keyring_proto_encode_op_only (send,
						 GNOME_KEYRING_OP_LIST_KEYRINGS)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

	if (!gnome_keyring_proto_decode_result_string_list_reply (receive, &res, keyrings)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}
 
gpointer
gnome_keyring_lock_all (GnomeKeyringOperationDoneCallback       callback,
			gpointer                                data,
			GDestroyNotify                          destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}

	if (!gnome_keyring_proto_encode_op_only (op->send_buffer,
						 GNOME_KEYRING_OP_LOCK_ALL)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_standard_reply;
	return op;
}

GnomeKeyringResult 
gnome_keyring_lock_all_sync (void)
{
	GString *send, *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);

	if (!gnome_keyring_proto_encode_op_only (send,
						 GNOME_KEYRING_OP_LOCK_ALL)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

        if (!gnome_keyring_proto_decode_result_reply (receive, &res)) {
                g_string_free (receive, TRUE);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        g_string_free (receive, TRUE);

        return res;
}



/* NULL password means ask user */
gpointer
gnome_keyring_create (const char                                  *keyring_name,
		      const char                                  *password,
		      GnomeKeyringOperationDoneCallback            callback,
		      gpointer                                     data,
		      GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string_string (op->send_buffer,
							  GNOME_KEYRING_OP_CREATE_KEYRING,
							  keyring_name, password)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_create_sync (const char *keyring_name,
			   const char *password)
{
	GString *send, *receive;
	GnomeKeyringResult res;
	
	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_op_string_string (send,
							  GNOME_KEYRING_OP_CREATE_KEYRING,
							  keyring_name, password)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

        if (!gnome_keyring_proto_decode_result_reply (receive, &res)) {
                g_string_free (receive, TRUE);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        g_string_free (receive, TRUE);

        return res;
}

gpointer
gnome_keyring_unlock (const char                                  *keyring,
		      const char                                  *password,
		      GnomeKeyringOperationDoneCallback            callback,
		      gpointer                                     data,
		      GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string_string (op->send_buffer,
							  GNOME_KEYRING_OP_UNLOCK_KEYRING,
							  keyring, password)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_unlock_sync (const char *keyring,
			   const char *password)
{
	GString *send, *receive;
	GnomeKeyringResult res;
	
	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_op_string_string (send,
							  GNOME_KEYRING_OP_UNLOCK_KEYRING,
							  keyring, password)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

        if (!gnome_keyring_proto_decode_result_reply (receive, &res)) {
                g_string_free (receive, TRUE);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        g_string_free (receive, TRUE);

	return res;
}

gpointer
gnome_keyring_lock (const char                                  *keyring,
		    GnomeKeyringOperationDoneCallback            callback,
		    gpointer                                     data,
		    GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string (op->send_buffer,
						   GNOME_KEYRING_OP_LOCK_KEYRING,
						   keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_lock_sync (const char *keyring)
{
	GString *send, *receive;
	GnomeKeyringResult res;
	
	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_op_string (send,
						   GNOME_KEYRING_OP_LOCK_KEYRING,
						   keyring)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

        if (!gnome_keyring_proto_decode_result_reply (receive, &res)) {
                g_string_free (receive, TRUE);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        g_string_free (receive, TRUE);

        return res;
}

gpointer
gnome_keyring_delete (const char                                  *keyring,
		      GnomeKeyringOperationDoneCallback            callback,
		      gpointer                                     data,
		      GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string (op->send_buffer,
						   GNOME_KEYRING_OP_DELETE_KEYRING,
						   keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_delete_sync (const char *keyring)
{
	GString *send, *receive;
	GnomeKeyringResult res;
	
	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_op_string (send,
						   GNOME_KEYRING_OP_DELETE_KEYRING,
						   keyring)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

        if (!gnome_keyring_proto_decode_result_reply (receive, &res)) {
                g_string_free (receive, TRUE);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        g_string_free (receive, TRUE);

        return res;
}

gpointer
gnome_keyring_change_password (const char                                  *keyring,
		      const char                                  *original,
		      const char                                  *password,
		      GnomeKeyringOperationDoneCallback            callback,
		      gpointer                                     data,
		      GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string_string_string (op->send_buffer,
							  GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD,
							  keyring, original, password)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_change_password_sync (const char *keyring_name,
			   const char *original, const char *password)
{
	GString *send, *receive;
	GnomeKeyringResult res;
	
	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_op_string_string_string (send,
							  GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD,
							  keyring_name, original, password)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

	if (!gnome_keyring_proto_decode_result_reply (receive, &res)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);

	return res;
}

static void
gnome_keyring_get_keyring_info_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetKeyringInfoCallback callback;
	GnomeKeyringInfo *info;

	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_get_keyring_info_reply (op->receive_buffer, &result, &info)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, info, op->user_data);
		gnome_keyring_info_free (info);
	}
}

gpointer
gnome_keyring_get_info (const char                                  *keyring,
			GnomeKeyringOperationGetKeyringInfoCallback  callback,
			gpointer                                     data,
			GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_KEYRING_INFO, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string (op->send_buffer,
						   GNOME_KEYRING_OP_GET_KEYRING_INFO,
						   keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_get_keyring_info_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_get_info_sync (const char        *keyring,
			     GnomeKeyringInfo **info)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);
	
	*info = NULL;

	if (!gnome_keyring_proto_encode_op_string (send,
						   GNOME_KEYRING_OP_GET_KEYRING_INFO,
						   keyring)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

	if (!gnome_keyring_proto_decode_get_keyring_info_reply (receive, &res, info)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}

gpointer
gnome_keyring_set_info (const char                                  *keyring,
			GnomeKeyringInfo                            *info,
			GnomeKeyringOperationDoneCallback            callback,
			gpointer                                     data,
			GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_set_keyring_info (op->send_buffer,
							  keyring, info)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_set_info_sync (const char       *keyring,
			     GnomeKeyringInfo *info)
{
	GString *send, *receive;
	GnomeKeyringResult res;
	
	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_set_keyring_info (send,
							  keyring, info)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	g_string_free (receive, TRUE);
	
	return res;
}

static void
gnome_keyring_list_item_ids_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetListCallback callback;
	GList *items;

	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_result_int_list_reply (op->receive_buffer, &result, &items)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, items, op->user_data);
		g_list_free (items);
	}
}

gpointer
gnome_keyring_list_item_ids (const char                                  *keyring,
			     GnomeKeyringOperationGetListCallback         callback,
			     gpointer                                     data,
			     GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_LIST, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}

	if (!gnome_keyring_proto_encode_op_string (op->send_buffer,
						   GNOME_KEYRING_OP_LIST_ITEMS,
						   keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_list_item_ids_reply;
	return op;
}

GnomeKeyringResult
gnome_keyring_list_item_ids_sync (const char  *keyring,
				  GList      **ids)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);
	
	*ids = NULL;

	if (!gnome_keyring_proto_encode_op_string (send,
						   GNOME_KEYRING_OP_LIST_ITEMS,
						   keyring)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

	if (!gnome_keyring_proto_decode_result_int_list_reply (receive, &res, ids)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}

GnomeKeyringResult
gnome_keyring_daemon_set_display_sync (const char *display)
{
	GString *send, *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);

	if (!gnome_keyring_proto_encode_op_string (send,
						   GNOME_KEYRING_OP_SET_DAEMON_DISPLAY,
						   display)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

	if (!gnome_keyring_proto_decode_result_reply (receive, &res)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);

	return res;
}

void
gnome_keyring_info_set_lock_on_idle (GnomeKeyringInfo *keyring_info,
				     gboolean          value)
{
	keyring_info->lock_on_idle = value;
}

gboolean
gnome_keyring_info_get_lock_on_idle (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->lock_on_idle;
}

void
gnome_keyring_info_set_lock_timeout (GnomeKeyringInfo *keyring_info,
				     guint32           value)
{
	keyring_info->lock_timeout = value;
}

guint32
gnome_keyring_info_get_lock_timeout (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->lock_timeout;
}

time_t
gnome_keyring_info_get_mtime (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->mtime;
}

time_t
gnome_keyring_info_get_ctime (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->ctime;
}

gboolean
gnome_keyring_info_get_is_locked (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->is_locked;
}

static void
gnome_keyring_find_items_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetListCallback callback;
	GList *found_items;

	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_find_reply (op->receive_buffer, &result, &found_items)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, found_items, op->user_data);
		gnome_keyring_found_list_free (found_items);
	}
}
     
gpointer
gnome_keyring_find_items  (GnomeKeyringItemType                  type,
			   GnomeKeyringAttributeList            *attributes,
			   GnomeKeyringOperationGetListCallback  callback,
			   gpointer                              data,
			   GDestroyNotify                        destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_LIST, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}

	if (!gnome_keyring_proto_encode_find (op->send_buffer,
					      type,
					      attributes)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_find_items_reply;
	return op;
}


static GnomeKeyringAttributeList *
make_attribute_list_va (va_list args)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;
	char *str;
	guint32 val;
	
	attributes = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));
	
	while ((attribute.name = va_arg (args, char *)) != NULL) {
		attribute.type = va_arg (args, GnomeKeyringAttributeType);
		
		switch (attribute.type) {
		case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
			str = va_arg (args, char *);
			attribute.value.string = str;
			g_array_append_val (attributes, attribute);
			break;
		case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
			val = va_arg (args, guint32);
			attribute.value.integer = val;
			g_array_append_val (attributes, attribute);
			break;
		default:
			g_array_free (attributes, TRUE);
			return NULL;
		}
	}
	return attributes;
}


gpointer
gnome_keyring_find_itemsv (GnomeKeyringItemType                  type,
			   GnomeKeyringOperationGetListCallback  callback,
			   gpointer                              data,
			   GDestroyNotify                        destroy_data,
			   ...)
{
	GnomeKeyringOperation *op;
	GnomeKeyringAttributeList *attributes;
	va_list args;
	
	op = start_operation (callback, CALLBACK_GET_LIST, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}

	va_start (args, destroy_data);
	attributes = make_attribute_list_va (args);
	va_end (args);
	if (attributes == NULL) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		return op;
	}
	
	if (!gnome_keyring_proto_encode_find (op->send_buffer,
					      type,
					      attributes))  {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	g_array_free (attributes, TRUE);

	op->reply_handler = gnome_keyring_find_items_reply;
	return op;
}

/**
 * gnome_keyring_find_items_sync:
 * @type: a #GnomeKeyringItemType
 * @attributes: a #GnomeKeyringAttributeList
 * @found: a return location for the found items, must not be %NULL
 *
 * Find elements of type #GnomeKeyring by matching attributes and @type.
 *
 * Returns: %GNOME_KEYRING_RESULT_OK if everythink went fine. A #GList of
 * #GnomeKeyringFound will be returned into @found, free all results with
 * gnome_keyring_found_list_free() or every single item with
 * gnome_keyring_found_free()
 */
GnomeKeyringResult
gnome_keyring_find_items_sync (GnomeKeyringItemType        type,
			       GnomeKeyringAttributeList  *attributes,
			       GList                     **found)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);

	*found = NULL;
	
	if (!gnome_keyring_proto_encode_find (send, type,
					      attributes)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}
	
	if (!gnome_keyring_proto_decode_find_reply (receive, &res, found)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}

GnomeKeyringResult
gnome_keyring_find_itemsv_sync  (GnomeKeyringItemType        type,
				 GList                     **found,
				 ...)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult res;
	va_list args;

	va_start (args, found);
	attributes = make_attribute_list_va (args);
	va_end (args);
	if (attributes == NULL) {
		return  GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	res = gnome_keyring_find_items_sync (type, attributes, found);
	g_array_free (attributes, TRUE);
	return res;
}


gpointer
gnome_keyring_item_create (const char                          *keyring,
			   GnomeKeyringItemType                 type,
			   const char                          *display_name,
			   GnomeKeyringAttributeList           *attributes,
			   const char                          *secret,
			   gboolean                             update_if_exists,
			   GnomeKeyringOperationGetIntCallback  callback,
			   gpointer                             data,
			   GDestroyNotify                       destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_INT, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_create_item (op->send_buffer,
						     keyring,
						     display_name,
						     attributes,
						     secret,
						     type,
						     update_if_exists)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_int_reply;
	
	return op;
}

/**
 * gnome_keyring_item_create_sync():
 * @keyring: the keyring name (%NULL for default)
 * @type: the #GnomeKeyringItemType of the item to save
 * @display_name: the name for this item to be used in the password manager
 * @attributes: the attributes specifying the keyring item
 * @secret: the secret information (password, passphrase, pin, etc) to be saved
 * @update_if_exists: set to %TRUE to update an existing item, if found. Create
 * a new one otherwise. Only item @attributes are matched.
 * @item_id: return location for the id of the created/updated keyring item.
 *
 * Create (or update of @update_if_exists is set) a keyring item with the
 * specified type, attributes and secret.
 *
 * Returns %GNOME_KEYRING_RESULT_OK if everything went fine.
 */
GnomeKeyringResult
gnome_keyring_item_create_sync    (const char                                 *keyring,
				   GnomeKeyringItemType                        type,
				   const char                                 *display_name,
				   GnomeKeyringAttributeList                  *attributes,
				   const char                                 *secret,
				   gboolean                                    update_if_exists,
				   guint32                                    *item_id)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);

	*item_id = 0;
	
	if (!gnome_keyring_proto_encode_create_item (send,
						     keyring,
						     display_name,
						     attributes,
						     secret,
						     type,
						     update_if_exists)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}

	if (!gnome_keyring_proto_decode_result_integer_reply (receive, &res, item_id)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}

gpointer
gnome_keyring_item_delete (const char                                 *keyring,
			   guint32                                     id,
			   GnomeKeyringOperationDoneCallback           callback,
			   gpointer                                    data,
			   GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string_int (op->send_buffer,
						       GNOME_KEYRING_OP_DELETE_ITEM,
						       keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

/**
 * gnome_keyring_item_delete_sync():
 * @keyring: the keyring to work with (%NULL for the default keyring)
 * @id: the keyring item id to delete
 *
 * Deletes an item from your keyring. Obtain @id by calling a function like
 * gnome_keyring_find_items_sync() or gnome_keyring_item_create_sync().
 *
 * Returns %GNOME_KEYRING_RESULT_OK on success, the error code otherwise.
 */
GnomeKeyringResult
gnome_keyring_item_delete_sync (const char *keyring,
				guint32     id)
{
	GString *send, *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_op_string_int (send,
						       GNOME_KEYRING_OP_DELETE_ITEM,
						       keyring,
						       id)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	g_string_free (receive, TRUE);

	return res;
}

static void
gnome_keyring_get_item_info_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetItemInfoCallback callback;
	GnomeKeyringItemInfo *info;

	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_get_item_info_reply (op->receive_buffer, &result, &info)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, info, op->user_data);
		gnome_keyring_item_info_free (info);
	}
}

gpointer
gnome_keyring_item_get_info (const char                                 *keyring,
			     guint32                                     id,
			     GnomeKeyringOperationGetItemInfoCallback    callback,
			     gpointer                                    data,
			     GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_ITEM_INFO, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string_int (op->send_buffer,
						       GNOME_KEYRING_OP_GET_ITEM_INFO,
						       keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_get_item_info_reply;
	
	return op;
}

GnomeKeyringResult 
gnome_keyring_item_get_info_sync (const char            *keyring,
				  guint32                id,
				  GnomeKeyringItemInfo **info)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);

	*info = NULL;
	
	if (!gnome_keyring_proto_encode_op_string_int (send, 
						       GNOME_KEYRING_OP_GET_ITEM_INFO,
						       keyring, id)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}
	
	if (!gnome_keyring_proto_decode_get_item_info_reply (receive, &res, info)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}

gpointer
gnome_keyring_item_get_info_full (const char                                 *keyring,
				  guint32                                     id,
				  guint32                                     flags,
				  GnomeKeyringOperationGetItemInfoCallback    callback,
				  gpointer                                    data,
				  GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_ITEM_INFO, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string_int_int (op->send_buffer,
							   GNOME_KEYRING_OP_GET_ITEM_INFO_FULL,
							   keyring, id, flags)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_get_item_info_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_item_get_info_full_sync (const char              *keyring,
				       guint32                  id,
				       guint32                  flags,
 				       GnomeKeyringItemInfo   **info)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);

	*info = NULL;
	
	if (!gnome_keyring_proto_encode_op_string_int_int (send, 
							   GNOME_KEYRING_OP_GET_ITEM_INFO_FULL,
							   keyring, id, flags)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}
	
	if (!gnome_keyring_proto_decode_get_item_info_reply (receive, &res, info)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}

gpointer
gnome_keyring_item_set_info (const char                                 *keyring,
			     guint32                                     id,
			     GnomeKeyringItemInfo                       *info,
			     GnomeKeyringOperationDoneCallback           callback,
			     gpointer                                    data,
			     GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_set_item_info (op->send_buffer,
						       keyring, id, info)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

GnomeKeyringResult 
gnome_keyring_item_set_info_sync (const char           *keyring,
				  guint32               id,
				  GnomeKeyringItemInfo *info)
{
	GString *send, *receive;
	GnomeKeyringResult res;
	
	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_set_item_info (send,
						       keyring, id, info)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	g_string_free (receive, TRUE);
	
	return res;
}

static void
gnome_keyring_get_attributes_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetAttributesCallback callback;
	GnomeKeyringAttributeList *attributes;

	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_get_attributes_reply (op->receive_buffer, &result, &attributes)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, attributes, op->user_data);
		gnome_keyring_attribute_list_free (attributes);
	}
}

static void
gnome_keyring_get_acl_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetListCallback callback;
	GList *acl;

	callback = op->user_callback;
	
	if (!gnome_keyring_proto_decode_get_acl_reply (op->receive_buffer, &result, &acl)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, acl, op->user_data);
		g_list_free (acl);
	}
}


gpointer
gnome_keyring_item_get_attributes (const char                                 *keyring,
				   guint32                                     id,
				   GnomeKeyringOperationGetAttributesCallback  callback,
				   gpointer                                    data,
				   GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_ATTRIBUTES, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string_int (op->send_buffer,
						       GNOME_KEYRING_OP_GET_ITEM_ATTRIBUTES,
						       keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_get_attributes_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_item_get_attributes_sync (const char                 *keyring,
					guint32                     id,
					GnomeKeyringAttributeList **attributes)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);

	*attributes = NULL;
	
	if (!gnome_keyring_proto_encode_op_string_int (send, 
						       GNOME_KEYRING_OP_GET_ITEM_ATTRIBUTES,
						       keyring, id)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}
	
	if (!gnome_keyring_proto_decode_get_attributes_reply (receive, &res, attributes)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}

gpointer
gnome_keyring_item_set_attributes (const char                                 *keyring,
				   guint32                                     id,
				   GnomeKeyringAttributeList                  *attributes,
				   GnomeKeyringOperationDoneCallback           callback,
				   gpointer                                    data,
				   GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_set_attributes (op->send_buffer,
							keyring, id,
							attributes)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_item_set_attributes_sync (const char                *keyring,
					guint32                    id,
					GnomeKeyringAttributeList *attributes)
{
	GString *send, *receive;
	GnomeKeyringResult res;
	
	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_set_attributes (send,
							keyring, id, 
							attributes)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	g_string_free (receive, TRUE);
	
	return res;

}

gpointer
gnome_keyring_item_get_acl (const char                                 *keyring,
			    guint32                                     id,
			    GnomeKeyringOperationGetListCallback        callback,
			    gpointer                                    data,
			    GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_GET_ACL, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_op_string_int (op->send_buffer,
						       GNOME_KEYRING_OP_GET_ITEM_ACL,
						       keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_get_acl_reply;
	
	return op;
}

GnomeKeyringResult
gnome_keyring_item_get_acl_sync (const char  *keyring,
				 guint32      id,
				 GList      **acl)
{
	GString *send;
	GString *receive;
	GnomeKeyringResult res;

	send = g_string_new (NULL);

	*acl = NULL;
	
	if (!gnome_keyring_proto_encode_op_string_int (send, 
						       GNOME_KEYRING_OP_GET_ITEM_ACL,
						       keyring, id)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
	receive = g_string_new (NULL);

	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK) {
		g_string_free (receive, TRUE);
		return res;
	}
	
	if (!gnome_keyring_proto_decode_get_acl_reply (receive, &res, acl)) {
		g_string_free (receive, TRUE);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	g_string_free (receive, TRUE);
	
	return res;
}

gpointer
gnome_keyring_item_set_acl (const char                                 *keyring,
			    guint32                                     id,
			    GList                                      *acl,
			    GnomeKeyringOperationDoneCallback           callback,
			    gpointer                                    data,
			    GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = start_operation (callback, CALLBACK_DONE, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}
	
	if (!gnome_keyring_proto_encode_set_acl (op->send_buffer,
						 keyring, id,
						 acl)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
}

GnomeKeyringResult 
gnome_keyring_item_set_acl_sync (const char *keyring,
				 guint32     id,
				 GList      *acl)
{
	GString *send, *receive;
	GnomeKeyringResult res;
	
	send = g_string_new (NULL);
	
	if (!gnome_keyring_proto_encode_set_acl (send,
						 keyring, id, 
						 acl)) {
		g_string_free (send, TRUE);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	receive = g_string_new (NULL);
	res = run_sync_operation (send, receive);
	g_string_free (send, TRUE);
	g_string_free (receive, TRUE);
	
	return res;
}

GnomeKeyringResult 
gnome_keyring_item_grant_access_rights_sync (const char                   *keyring, 
					     const char                   *display_name, 
					     const char                   *full_path, 
					     const guint32                id, 
					     const GnomeKeyringAccessType rights) 
{
 	GList *acl_list = NULL;
 	GnomeKeyringApplicationRef new_app_ref;
 	GnomeKeyringAccessControl acl;
	GnomeKeyringResult res;

	/* setup application structure */
	new_app_ref.display_name = (char *) display_name;
	new_app_ref.pathname = (char *) full_path;
	acl.application = &new_app_ref; 
	acl.types_allowed = rights; 

	/* get the original acl list */
	res = gnome_keyring_item_get_acl_sync (keyring,
					       id,
					       &acl_list);
	if (GNOME_KEYRING_RESULT_OK != res)
		goto out;

	/* append access rights */
	acl_list = g_list_append (acl_list, (gpointer) &acl);
	res = gnome_keyring_item_set_acl_sync (keyring, 
					       id,
					       acl_list);
out:
	if (acl_list)
		g_list_free (acl_list);

	return res;
}

GnomeKeyringItemType
gnome_keyring_item_info_get_type (GnomeKeyringItemInfo *item_info)
{
	return item_info->type;
}

void
gnome_keyring_item_info_set_type (GnomeKeyringItemInfo *item_info,
				  GnomeKeyringItemType  type)
{
	item_info->type = type;
}

char *
gnome_keyring_item_info_get_secret (GnomeKeyringItemInfo *item_info)
{
	return g_strdup (item_info->secret);
}

void
gnome_keyring_item_info_set_secret (GnomeKeyringItemInfo *item_info,
				    const char           *value)
{
	g_free (item_info->secret);
	item_info->secret = g_strdup (value);
}

char *
gnome_keyring_item_info_get_display_name (GnomeKeyringItemInfo *item_info)
{
	return g_strdup (item_info->display_name);
}

void
gnome_keyring_item_info_set_display_name (GnomeKeyringItemInfo *item_info,
					  const char           *value)
{
	g_free (item_info->display_name);
	item_info->display_name = g_strdup (value);
}

time_t
gnome_keyring_item_info_get_mtime (GnomeKeyringItemInfo *item_info)
{
	return item_info->mtime;
}

time_t
gnome_keyring_item_info_get_ctime (GnomeKeyringItemInfo *item_info)
{
	return item_info->ctime;
}

char *
gnome_keyring_item_ac_get_display_name (GnomeKeyringAccessControl *ac)
{
	return g_strdup (ac->application->display_name);
}

void
gnome_keyring_item_ac_set_display_name (GnomeKeyringAccessControl *ac,
					const char                *value)
{
	g_free (ac->application->display_name);
	ac->application->display_name = g_strdup (value);
}

char *
gnome_keyring_item_ac_get_path_name (GnomeKeyringAccessControl *ac)
{
	return g_strdup (ac->application->pathname);
}

void
gnome_keyring_item_ac_set_path_name (GnomeKeyringAccessControl *ac,
				     const char                *value)
{
	g_free (ac->application->pathname);
	ac->application->pathname = g_strdup (value);
}

GnomeKeyringAccessType
gnome_keyring_item_ac_get_access_type (GnomeKeyringAccessControl *ac)
{
	return ac->types_allowed;
}

void
gnome_keyring_item_ac_set_access_type (GnomeKeyringAccessControl *ac,
				       const GnomeKeyringAccessType value)
{
	ac->types_allowed = value;
}


struct FindNetworkPasswordInfo {
	GnomeKeyringOperationGetListCallback callback;
	gpointer                             data;
	GDestroyNotify                       destroy_data;
};

static void
free_find_network_password_info (struct FindNetworkPasswordInfo *info)
{
	if (info->destroy_data != NULL) {
		info->destroy_data (info->data);
	}
	g_free (info);
}

static GList *
found_list_to_nework_password_list (GList *found_list)
{
	GnomeKeyringNetworkPasswordData *data;
	GnomeKeyringFound *found;
	GnomeKeyringAttribute *attributes;
	GList *result, *l;
	int i;
	
	result = NULL;
	for (l = found_list; l != NULL; l = l->next) {
		found = l->data;
		
		data = g_new0 (GnomeKeyringNetworkPasswordData, 1);

		result = g_list_prepend (result, data);

		data->keyring = g_strdup (found->keyring);
		data->item_id = found->item_id;
		data->password = g_strdup (found->secret);

		attributes = (GnomeKeyringAttribute *) found->attributes->data;
		for (i = 0; i < found->attributes->len; i++) {
			if (strcmp (attributes[i].name, "user") == 0 &&
			    attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->user = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "domain") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->domain = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "server") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->server = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "object") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->object = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "protocol") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->protocol = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "authtype") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->authtype = g_strdup (attributes[i].value.string);
			} else if (strcmp (attributes[i].name, "port") == 0 &&
				   attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32) {
				data->port = attributes[i].value.integer;
			} 
		}
	}
	
	return g_list_reverse (result);
}

void
gnome_keyring_network_password_free (GnomeKeyringNetworkPasswordData *data)
{
	g_free (data->keyring);
	g_free (data->protocol);
	g_free (data->server);
	g_free (data->object);
	g_free (data->authtype);
	g_free (data->user);
	g_free (data->domain);
	g_free (data->password);
	
	g_free (data);
}

void
gnome_keyring_network_password_list_free (GList *list)
{
	g_list_foreach (list, (GFunc)gnome_keyring_network_password_free, NULL);
	g_list_free (list);
}

static void
find_network_password_callback (GnomeKeyringResult result,
				GList             *list,
				gpointer           data)
{
	struct FindNetworkPasswordInfo *info;
	GList *data_list;

	info = data;
	
	data_list = NULL;
	if (result == GNOME_KEYRING_RESULT_OK) {
		data_list = found_list_to_nework_password_list (list);
	}
	info->callback (result, data_list, info->data);
	gnome_keyring_network_password_list_free (data_list);
	return;
}

/**
 * gnome_keyring_attribute_list_append_string():
 * @attributes: a #GnomeKeyringAttributeList
 * @attributename: the name of the new attribute
 * @value: the value to store in @attributes
 *
 * Store a key-value-pair with a string value in @attributes.
 */
void
gnome_keyring_attribute_list_append_string (GnomeKeyringAttributeList *attributes,
					    const char *attributename, const char *value)
{
	GnomeKeyringAttribute attribute;

	attribute.name = g_strdup (attributename);
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = g_strdup (value);
	
	g_array_append_val (attributes, attribute);
}

/**
 * gnome_keyring_attribute_append_uint32:
 * @attributes: a #GnomeKeyringAttributeList
 * @attributename: the name of the new attribute
 * @value: the value to store in @attributes
 *
 * Store a key-value-pair with an unsigned 32bit number value in @attributes.
 */
void
gnome_keyring_attribute_list_append_uint32 (GnomeKeyringAttributeList *attributes,
					    const char *attributename, guint32 value)
{
	GnomeKeyringAttribute attribute;
	
	attribute.name = g_strdup (attributename);
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32;
	attribute.value.integer = value;
	g_array_append_val (attributes, attribute);
}

static GnomeKeyringAttributeList *
make_attribute_list_for_network_password (const char                            *user,
					  const char                            *domain,
					  const char                            *server,
					  const char                            *object,
					  const char                            *protocol,
					  const char                            *authtype,
					  guint32                                port)
{
	GnomeKeyringAttributeList *attributes;
	
	attributes = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));

	if (user != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "user", user);
	}
	if (domain != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "domain", domain);
	}
	if (server != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "server", server);
	}
	if (object != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "object", object);
	}
	if (protocol != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "protocol", protocol);
	}
	if (authtype != NULL) {
		gnome_keyring_attribute_list_append_string (attributes, "authtype", authtype);
	}
	if (port != 0) {
		gnome_keyring_attribute_list_append_uint32 (attributes, "port", port);
	}
	return attributes;
}


gpointer
gnome_keyring_find_network_password      (const char                            *user,
					  const char                            *domain,
					  const char                            *server,
					  const char                            *object,
					  const char                            *protocol,
					  const char                            *authtype,
					  guint32                                port,
					  GnomeKeyringOperationGetListCallback   callback,
					  gpointer                               user_data,
					  GDestroyNotify                         destroy_data)
{
	GnomeKeyringAttributeList *attributes;
	gpointer request;
	struct FindNetworkPasswordInfo *info;

	info = g_new0 (struct FindNetworkPasswordInfo, 1);
	info->callback = callback;
	info->data = user_data;
	info->destroy_data = destroy_data;

	attributes = make_attribute_list_for_network_password (user,
							       domain,
							       server,
							       object,
							       protocol,
							       authtype,
							       port);
	
	request = gnome_keyring_find_items (GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
					    attributes,
					    find_network_password_callback,
					    info,
					    (GDestroyNotify)free_find_network_password_info);

	gnome_keyring_attribute_list_free (attributes);
	return request;
}



GnomeKeyringResult
gnome_keyring_find_network_password_sync (const char                            *user,
					  const char                            *domain,
					  const char                            *server,
					  const char                            *object,
					  const char                            *protocol,
					  const char                            *authtype,
					  guint32                                port,
					  GList                                **out_list)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult result;
	GList *found;
	
	*out_list = NULL;
	attributes = make_attribute_list_for_network_password (user,
							       domain,
							       server,
							       object,
							       protocol,
							       authtype,
							       port);
	
	result = gnome_keyring_find_items_sync (GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
						 attributes,
						 &found);

	gnome_keyring_attribute_list_free (attributes);

	if (result == GNOME_KEYRING_RESULT_OK) {
		*out_list = found_list_to_nework_password_list (found);
		gnome_keyring_found_list_free (found);
	}

	return result;
}

static char *
get_network_password_display_name (const char *user,
				   const char *server,
				   const char *object,
				   guint32  port)
{
	GString *s;
	char *name;

	if (server != NULL) {
		s = g_string_new (NULL);
		if (user != NULL) {
			g_string_append_printf (s, "%s@", user);
		}
		g_string_append (s, server);
		if (port != 0) {
			g_string_append_printf (s, ":%d", port);
		}
		if (object != NULL) {
			g_string_append_printf (s, "/%s", object);
		}
		name = g_string_free (s, FALSE);
	} else {
		name = g_strdup ("network password");
	}
	return name;
}
				   


gpointer
gnome_keyring_set_network_password      (const char                            *keyring,
					 const char                            *user,
					 const char                            *domain,
					 const char                            *server,
					 const char                            *object,
					 const char                            *protocol,
					 const char                            *authtype,
					 guint32                                port,
					 const char                            *password,
					 GnomeKeyringOperationGetIntCallback    callback,
					 gpointer                               data,
					 GDestroyNotify                         destroy_data)
{
	GnomeKeyringAttributeList *attributes;
	gpointer req;
	char *name;

	name = get_network_password_display_name (user, server, object, port);

	attributes = make_attribute_list_for_network_password (user,
							       domain,
							       server,
							       object,
							       protocol,
							       authtype,
							       port);
	
	req = gnome_keyring_item_create (keyring,
					 GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
					 name,
					 attributes,
					 password,
					 TRUE,
					 callback, data, destroy_data);
	
	gnome_keyring_attribute_list_free (attributes);
	g_free (name);
	
	return req;
}

GnomeKeyringResult
gnome_keyring_set_network_password_sync (const char                            *keyring,
					 const char                            *user,
					 const char                            *domain,
					 const char                            *server,
					 const char                            *object,
					 const char                            *protocol,
					 const char                            *authtype,
					 guint32                                port,
					 const char                            *password,
					 guint32                               *item_id)
{
	GnomeKeyringAttributeList *attributes;
	char *name;
	GnomeKeyringResult res;

	name = get_network_password_display_name (user, server, object, port);
	attributes = make_attribute_list_for_network_password (user,
							       domain,
							       server,
							       object,
							       protocol,
							       authtype,
							       port);
	
	res = gnome_keyring_item_create_sync (keyring,
					      GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
					      name,
					      attributes,
					      password,
					      TRUE,
					      item_id);
	
	gnome_keyring_attribute_list_free (attributes);
	g_free (name);
	
	return res;
}
