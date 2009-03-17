/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring.c - library for talking to the keyring daemon.

   Copyright (C) 2003 Red Hat, Inc
   Copyright (C) 2007 Stefan Walter

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

#include "gnome-keyring.h"
#include "gnome-keyring-memory.h"
#include "gnome-keyring-private.h"
#include "gnome-keyring-proto.h"

#include "egg/egg-buffer.h"
#include "egg/egg-unix-credentials.h"

#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdarg.h>

/**
 * SECTION:gnome-keyring-generic-callbacks
 * @title: Callbacks
 * @short_description: Different callbacks for retrieving async results
 */

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

#define NORMAL_ALLOCATOR  ((EggBufferAllocator)g_realloc)
#define SECURE_ALLOCATOR  ((EggBufferAllocator)gnome_keyring_memory_realloc)

typedef gboolean (*KeyringHandleReply) (GnomeKeyringOperation *op);

struct GnomeKeyringOperation {
	int socket;

	KeyringState state;
	GnomeKeyringResult result;

	guint io_watch;
	guint idle_watch;
	
	EggBuffer send_buffer;
	gsize send_pos;

	EggBuffer receive_buffer;
	gsize receive_pos;
	
	KeyringCallbackType user_callback_type;
	gpointer user_callback;
	gpointer user_data;
	GDestroyNotify destroy_user_data;

	KeyringHandleReply reply_handler;
	gpointer reply_data;
	GDestroyNotify destroy_reply_data;
};

static void
operation_free (GnomeKeyringOperation *op)
{
	if (op->idle_watch != 0) {
		g_source_remove (op->idle_watch);
		op->idle_watch = 0;
	}
	if (op->io_watch != 0) {
		g_source_remove (op->io_watch);
		op->io_watch = 0;
	}
	if (op->destroy_user_data != NULL && op->user_data != NULL)
		(*op->destroy_user_data) (op->user_data);
	if (op->destroy_reply_data != NULL && op->reply_data != NULL)
		(*op->destroy_reply_data) (op->reply_data);	
	egg_buffer_uninit (&op->send_buffer);
	egg_buffer_uninit (&op->receive_buffer);
	
	shutdown (op->socket, SHUT_RDWR);
	close (op->socket);
	g_free (op);
}

static gboolean
op_failed (gpointer data)
{
	GnomeKeyringOperation *op;

	op = data;
	op->idle_watch = 0;

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

	operation_free (op);
	
	/* Don't run idle handler again */
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
	
	if (op->idle_watch == 0)
		op->idle_watch = g_idle_add (op_failed, op);
}

static GnomeKeyringResult
write_credentials_byte_sync (int socket)
{
	if (egg_unix_credentials_write (socket) < 0)
		return GNOME_KEYRING_RESULT_IO_ERROR;
	return GNOME_KEYRING_RESULT_OK;
}

static void
write_credentials_byte (GnomeKeyringOperation *op)
{
	if (egg_unix_credentials_write (op->socket) < 0) {
		if (errno == EAGAIN)
			return;
		schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
		return;
	}
	
	op->state = STATE_WRITING_PACKET;
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
			     op->send_buffer.buf + op->send_pos,
			     op->send_buffer.len - op->send_pos);
		if (res <= 0) {
			if (errno != EAGAIN &&
			    errno != EINTR) {
				schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
			} 
		} else {
			op->send_pos += res;

			if (op->send_pos == op->send_buffer.len) {
				op->state = STATE_READING_REPLY;
				egg_buffer_reset (&op->receive_buffer);
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
			egg_buffer_resize (&op->receive_buffer, 4);
			res = read (op->socket,
				    op->receive_buffer.buf + op->receive_pos,
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
			if (!gkr_proto_decode_packet_size (&op->receive_buffer, &packet_size) ||
			    packet_size < 4) {
				schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
			}
		
			g_assert (op->receive_pos <= packet_size);
			egg_buffer_resize (&op->receive_buffer, packet_size);

			res = read (op->socket, op->receive_buffer.buf + op->receive_pos,
				    packet_size - op->receive_pos);
			if (res <= 0) {
				if (errno != EAGAIN &&
				    errno != EINTR) {
					schedule_op_failed (op, GNOME_KEYRING_RESULT_IO_ERROR);
				}
			} else {
				op->receive_pos += res;
				
				if (op->receive_pos == packet_size) {
					op->result = GNOME_KEYRING_RESULT_OK;
					
					/* Only cleanup if the handler says we're done */
					if ((*op->reply_handler) (op)) {
						g_source_remove (op->io_watch);
						op->io_watch = 0;
						operation_free (op);
					}
				}
			}
		}
	}
	

	return TRUE;
}


static GnomeKeyringOperation*
create_operation (gboolean receive_secure, gpointer callback, 
                  KeyringCallbackType callback_type, gpointer user_data, 
                  GDestroyNotify destroy_user_data)
{
	GnomeKeyringOperation *op;

	op = g_new0 (GnomeKeyringOperation, 1);

	/* Start in failed mode */
	op->state = STATE_FAILED;
	op->result = GNOME_KEYRING_RESULT_OK;

	op->user_callback_type = callback_type;
	op->user_callback = callback;
	op->user_data = user_data;
	op->destroy_user_data = destroy_user_data;
	op->socket = -1;
	
	egg_buffer_init_full (&op->send_buffer, 128, NORMAL_ALLOCATOR);
	egg_buffer_init_full (&op->receive_buffer, 128, 
		receive_secure ? SECURE_ALLOCATOR : NORMAL_ALLOCATOR);
		
	return op;
}

static void
start_operation (GnomeKeyringOperation *op)
{
	GIOChannel *channel;

	/* Start in failed mode */
	op->state = STATE_FAILED;
	op->result = GNOME_KEYRING_RESULT_OK;
	
	if (op->io_watch != 0) {
		g_source_remove (op->io_watch);
		op->io_watch = 0;
	}
	if (op->socket >= 0) {
		shutdown (op->socket, SHUT_RDWR);
		close (op->socket);
	}

	op->socket = gnome_keyring_socket_connect_daemon (TRUE, FALSE);
	if (op->socket < 0) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON);
	} else  {
		op->state = STATE_WRITING_CREDS;
		
		egg_buffer_reset (&op->receive_buffer);
		op->send_pos = 0;
		
		channel = g_io_channel_unix_new (op->socket);
		op->io_watch = g_io_add_watch (channel,
					       G_IO_OUT | G_IO_HUP,
					       operation_io, op);
		g_io_channel_unref (channel);
	} 
}

static GnomeKeyringResult
run_sync_operation (EggBuffer *buffer,
		    EggBuffer *receive_buffer)
{
	GnomeKeyringResult res;
	int socket;

	g_assert (buffer != NULL);
	g_assert (receive_buffer != NULL);

	socket = gnome_keyring_socket_connect_daemon (FALSE, FALSE);
	if (socket < 0)
		return GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON;

	res = write_credentials_byte_sync (socket);
	if (res != GNOME_KEYRING_RESULT_OK) {
		close (socket);
		return res;
	}

	if (!gnome_keyring_socket_write_buffer (socket, buffer) || 
	    !gnome_keyring_socket_read_buffer (socket, receive_buffer)) {
		close (socket);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}

	close (socket);
	return GNOME_KEYRING_RESULT_OK;
}

/**
 * SECTION:gnome-keyring-misc
 * @title: Miscellaneous Functions
 * @short_description: Miscellaneous functions.
 */

/**
 * gnome_keyring_is_available:
 *
 * Check whether you can communicate with a gnome-keyring-daemon.
 *
 * Return value: %FALSE if you can't communicate with the daemon (so you 
 * can't load and save passwords).
 **/
gboolean
gnome_keyring_is_available (void)
{
	int socket;
	
	socket = gnome_keyring_socket_connect_daemon (FALSE, FALSE);
	if (socket < 0) {
		return FALSE;
	}
	close (socket);
	return TRUE;
}

/**
 * gnome_keyring_cancel_request:
 * @request: The request returned from the asynchronous call function. 
 * 
 * Cancel an asynchronous request. 
 * 
 * If a callback was registered when making the asynchronous request, that callback
 * function will be called with a result of %GNOME_KEYRING_RESULT_CANCELLED
 **/
void
gnome_keyring_cancel_request (gpointer request)
{
	GnomeKeyringOperation *op;

	op = request;

	schedule_op_failed (op, GNOME_KEYRING_RESULT_CANCELLED);
}

static gboolean
standard_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationDoneCallback callback;

	g_assert (op->user_callback_type == CALLBACK_DONE);
	
	callback = op->user_callback;
	
	if (!gkr_proto_decode_result_reply (&op->receive_buffer, &result)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, op->user_data);
	} else {
		(*callback) (result, op->user_data);
	}
	
	/* Operation is done */
	return TRUE;
}

static gboolean
string_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetStringCallback callback;
	char *string;

	g_assert (op->user_callback_type == CALLBACK_GET_STRING);

	callback = op->user_callback;
	
	if (!gkr_proto_decode_result_string_reply (&op->receive_buffer, &result, &string)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, string, op->user_data);
		g_free (string);
	}
	
	/* Operation is done */
	return TRUE;
}

static gboolean
int_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetIntCallback callback;
	guint32 integer;

	g_assert (op->user_callback_type == CALLBACK_GET_INT);

	callback = op->user_callback;
	
	if (!gkr_proto_decode_result_integer_reply (&op->receive_buffer, &result, &integer)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, 0, op->user_data);
	} else {
		(*callback) (result, integer, op->user_data);
	}
	
	/* Operation is done */
	return TRUE;
}

/**
 * SECTION:gnome-keyring-keyrings
 * @title: Keyrings
 * @short_description: Listing and managing keyrings
 * 
 * %gnome-keyring-daemon manages multiple keyrings. Each keyring can store one or more items containing secrets.
 * 
 * One of the keyrings is the default keyring, which can in many cases be used by specifying %NULL for a keyring name.
 * 
 * Each keyring can be in a locked or unlocked state. A password must be specified, either by the user or the calling application, to unlock the keyring.
 */

/**
 * gnome_keyring_set_default_keyring:
 * @keyring: The keyring to make default
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * 
 * Change the default keyring. 
 * 
 * For a synchronous version of this function see gnome_keyring_set_default_keyring_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_set_default_keyring (const gchar                             *keyring,
				   GnomeKeyringOperationDoneCallback       callback,
				   gpointer                                data,
				   GDestroyNotify                          destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	if (!gkr_proto_encode_op_string (&op->send_buffer, GNOME_KEYRING_OP_SET_DEFAULT_KEYRING,
	                                 keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_set_default_keyring_sync:
 * @keyring: The keyring to make default
 * 
 * Change the default keyring. 
 * 
 * For an asynchronous version of this function see gnome_keyring_set_default_keyring(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise.
 **/
GnomeKeyringResult 
gnome_keyring_set_default_keyring_sync (const char *keyring)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	if (!gkr_proto_encode_op_string (&send, GNOME_KEYRING_OP_SET_DEFAULT_KEYRING,
	                                 keyring)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_reply (&receive, &res)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
 	egg_buffer_uninit (&receive);

	return res;
}

/**
 * gnome_keyring_get_default_keyring:
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * 
 * Get the default keyring name, which will be passed to the @callback. If no 
 * default keyring exists, then %NULL will be passed to the @callback. The 
 * string will be freed after @callback returns.
 * 
 * For a synchronous version of this function see gnome_keyring_get_default_keyring_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_get_default_keyring (GnomeKeyringOperationGetStringCallback  callback,
				   gpointer                                data,
				   GDestroyNotify                          destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_GET_STRING, data, destroy_data);
	if (!gkr_proto_encode_op_only (&op->send_buffer, GNOME_KEYRING_OP_GET_DEFAULT_KEYRING)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = string_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_get_default_keyring_sync:
 * @keyring: Location for the default keyring name to be returned.
 * 
 * Get the default keyring name. 
 * 
 * The string returned in @keyring must be freed with g_free(). 
 * 
 * For an asynchronous version of this function see gnome_keyring_get_default_keyring(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise.
 **/
GnomeKeyringResult 
gnome_keyring_get_default_keyring_sync (char **keyring)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	*keyring = NULL;

	if (!gkr_proto_encode_op_only (&send, GNOME_KEYRING_OP_GET_DEFAULT_KEYRING)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_string_reply (&receive, &res, keyring)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

static gboolean
list_keyring_names_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetListCallback callback;
	GList *names;

	callback = op->user_callback;
	
	if (!gkr_proto_decode_result_string_list_reply (&op->receive_buffer, &result, &names)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, names, op->user_data);
		gnome_keyring_string_list_free (names);
	}
	
	/* Operation is done */
	return TRUE;
}

/**
 * gnome_keyring_list_keyring_names:
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * 
 * Get a list of keyring names. 
 * 
 * A %GList of null terminated strings will be passed to 
 * the @callback. If no keyrings exist then an empty list will be passed to the 
 * @callback. The list is freed after @callback returns.
 * 
 * For a synchronous version of this function see gnome_keyring_list_keyrings_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_list_keyring_names  (GnomeKeyringOperationGetListCallback    callback,
				   gpointer                                data,
				   GDestroyNotify                          destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_GET_LIST, data, destroy_data);
	if (!gkr_proto_encode_op_only (&op->send_buffer,
						 GNOME_KEYRING_OP_LIST_KEYRINGS)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = list_keyring_names_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_list_keyring_names_sync:
 * @keyrings: Location for a %GList of keyring names to be returned.
 * 
 * Get a list of keyring names.
 * 
 * The list returned in in @keyrings must be freed using 
 * gnome_keyring_string_list_free().
 * 
 * For an asynchronous version of this function see gnome_keyring_list_keyring_names(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise.
 **/
GnomeKeyringResult 
gnome_keyring_list_keyring_names_sync (GList **keyrings)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	*keyrings = NULL;

	if (!gkr_proto_encode_op_only (&send, GNOME_KEYRING_OP_LIST_KEYRINGS)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_string_list_reply (&receive, &res, keyrings)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

/**
 * gnome_keyring_lock_all:
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * 
 * Lock all the keyrings, so that their contents may not be accessed without 
 * first unlocking them with a password.
 * 
 * For a synchronous version of this function see gnome_keyring_lock_all_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/ 
gpointer
gnome_keyring_lock_all (GnomeKeyringOperationDoneCallback       callback,
			gpointer                                data,
			GDestroyNotify                          destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	if (!gkr_proto_encode_op_only (&op->send_buffer, GNOME_KEYRING_OP_LOCK_ALL)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_lock_all_sync:
 * 
 * Lock all the keyrings, so that their contents may not eb accessed without
 * first unlocking them with a password.
 * 
 * For an asynchronous version of this function see gnome_keyring_lock_all(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise.
 **/
GnomeKeyringResult 
gnome_keyring_lock_all_sync (void)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	if (!gkr_proto_encode_op_only (&send, GNOME_KEYRING_OP_LOCK_ALL)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

        if (!gkr_proto_decode_result_reply (&receive, &res)) {
                egg_buffer_uninit (&receive);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        egg_buffer_uninit (&receive);

        return res;
}

/**
 * gnome_keyring_create:
 * @keyring_name: The new keyring name. Must not be %NULL.
 * @password: The password for the new keyring. If %NULL user will be prompted.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Create a new keyring with the specified name. In most cases %NULL will be 
 * passed as the @password, which will prompt the user to enter a password
 * of their choice. 
 * 
 * For a synchronous version of this function see gnome_keyring_create_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_create (const char                                  *keyring_name,
		      const char                                  *password,
		      GnomeKeyringOperationDoneCallback            callback,
		      gpointer                                     data,
		      GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	/* Automatically secures buffer */
	if (!gkr_proto_encode_op_string_secret (&op->send_buffer, GNOME_KEYRING_OP_CREATE_KEYRING,
	                                        keyring_name, password)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_create_sync:
 * @keyring_name: The new keyring name. Must not be %NULL
 * @password: The password for the new keyring. If %NULL user will be prompted.
 * 
 * Create a new keyring with the specified name. In most cases %NULL will be 
 * passed in as the @password, which will prompt the user to enter a password 
 * of their choice.

 * For an asynchronous version of this function see gnome_keyring_create(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise.
 **/
GnomeKeyringResult
gnome_keyring_create_sync (const char *keyring_name,
			   const char *password)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;
	
	egg_buffer_init_full (&send, 128, SECURE_ALLOCATOR);

	if (!gkr_proto_encode_op_string_secret (&send, GNOME_KEYRING_OP_CREATE_KEYRING,
	                                        keyring_name, password)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

        if (!gkr_proto_decode_result_reply (&receive, &res)) {
                egg_buffer_uninit (&receive);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        egg_buffer_uninit (&receive);

        return res;
}

/**
 * gnome_keyring_unlock:
 * @keyring: The name of the keyring to unlock, or %NULL for the default keyring.
 * @password: The password to unlock the keyring with, or %NULL to prompt the user.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Unlock a @keyring, so that its contents may be accessed. In most cases %NULL
 * will be passed as the @password, which will prompt the user to enter the 
 * correct password.
 * 
 * Most keyring operations involving items require that you first unlock the 
 * keyring. One exception is gnome_keyring_find_items() and related functions.
 * 
 * For a synchronous version of this function see gnome_keyring_unlock_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_unlock (const char                                  *keyring,
		      const char                                  *password,
		      GnomeKeyringOperationDoneCallback            callback,
		      gpointer                                     data,
		      GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	/* Automatically secures buffer */
	if (!gkr_proto_encode_op_string_secret (&op->send_buffer, GNOME_KEYRING_OP_UNLOCK_KEYRING,
	                                        keyring, password)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_operation (op);	
	return op;
}

/**
 * gnome_keyring_unlock_sync:
 * @keyring_name: The name of the keyring to unlock, or %NULL for the default keyring.
 * @password: The password to unlock the keyring with, or %NULL to prompt the user.
 * 
 * Unlock a @keyring, so that its contents may be accessed. In most cases %NULL
 * will be passed in as the @password, which will prompt the user to enter the 
 * correct password.
 * 
 * Most keyring opretaions involving items require that yo ufirst unlock the 
 * keyring. One exception is gnome_keyring_find_items_sync() and related functions.
 *
 * For an asynchronous version of this function see gnome_keyring_unlock(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
GnomeKeyringResult
gnome_keyring_unlock_sync (const char *keyring,
			   const char *password)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	/* Use secure non-pageable buffer */	
	egg_buffer_init_full (&send, 128, SECURE_ALLOCATOR);
	
	if (!gkr_proto_encode_op_string_secret (&send, GNOME_KEYRING_OP_UNLOCK_KEYRING,
	                                        keyring, password)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

        if (!gkr_proto_decode_result_reply (&receive, &res)) {
                egg_buffer_uninit (&receive);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        egg_buffer_uninit (&receive);

	return res;
}

/**
 * gnome_keyring_lock:
 * @keyring: The name of the keyring to lock, or %NULL for the default keyring.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Lock a @keyring, so that its contents may not be accessed without first 
 * supplying a password. 
 * 
 * Most keyring operations involving items require that you first unlock the 
 * keyring. One exception is gnome_keyring_find_items() and related functions.
 * 
 * For a synchronous version of this function see gnome_keyring_lock_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_lock (const char                                  *keyring,
		    GnomeKeyringOperationDoneCallback            callback,
		    gpointer                                     data,
		    GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	if (!gkr_proto_encode_op_string (&op->send_buffer, GNOME_KEYRING_OP_LOCK_KEYRING,
	                                 keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = standard_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_unlock_sync:
 * @keyring: The name of the keyring to lock, or %NULL for the default keyring.
 * 
 * Lock a @keyring, so that its contents may not be accessed without first
 * supplying a password. 
 * 
 * Most keyring opretaions involving items require that you first unlock the 
 * keyring. One exception is gnome_keyring_find_items_sync() and related functions.
 *
 * For an asynchronous version of this function see gnome_keyring_lock(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
GnomeKeyringResult
gnome_keyring_lock_sync (const char *keyring)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;
	
	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	if (!gkr_proto_encode_op_string (&send, GNOME_KEYRING_OP_LOCK_KEYRING,
	                                 keyring)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

        if (!gkr_proto_decode_result_reply (&receive, &res)) {
                egg_buffer_uninit (&receive);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        egg_buffer_uninit (&receive);

        return res;
}

/**
 * gnome_keyring_delete:
 * @keyring: The name of the keyring to delete. Cannot be %NULL.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Delete @keyring. Once a keyring is deleted there is no mechanism for 
 * recovery of its contents. 
 * 
 * For a synchronous version of this function see gnome_keyring_delete_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_delete (const char                                  *keyring,
		      GnomeKeyringOperationDoneCallback            callback,
		      gpointer                                     data,
		      GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	if (!gkr_proto_encode_op_string (&op->send_buffer, GNOME_KEYRING_OP_DELETE_KEYRING,
	                                 keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = standard_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_delete_sync:
 * @keyring: The name of the keyring to delete. Cannot be %NULL
 * 
 * Delete @keyring. Once a keyring is deleted there is no mechanism for 
 * recovery of its contents. 
 * 
 * For an asynchronous version of this function see gnome_keyring_delete(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
GnomeKeyringResult
gnome_keyring_delete_sync (const char *keyring)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;
	
	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	if (!gkr_proto_encode_op_string (&send, GNOME_KEYRING_OP_DELETE_KEYRING,
	                                 keyring)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

        if (!gkr_proto_decode_result_reply (&receive, &res)) {
                egg_buffer_uninit (&receive);
                return GNOME_KEYRING_RESULT_IO_ERROR;
        }
        egg_buffer_uninit (&receive);

        return res;
}

/**
 * gnome_keyring_change_password:
 * @keyring: The name of the keyring to change the password for. Cannot be %NULL.
 * @original: The old keyring password, or %NULL to prompt the user for it.
 * @password: The new keyring password, or %NULL to prompt the user for it. 
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Change the password for a @keyring. In most cases you would specify %NULL for
 * both the @original and @password arguments and allow the user to type the 
 * correct passwords. 
 * 
 * For a synchronous version of this function see gnome_keyring_change_password_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_change_password (const char                                  *keyring,
		      const char                                  *original,
		      const char                                  *password,
		      GnomeKeyringOperationDoneCallback            callback,
		      gpointer                                     data,
		      GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);

	/* Automatically secures buffer */	
	if (!gkr_proto_encode_op_string_secret_secret (&op->send_buffer,
	                                               GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD,
	                                               keyring, original, password)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = standard_reply;
	start_operation (op);
	
	return op;
}


/**
 * gnome_keyring_change_password_sync:
 * @keyring: The name of the keyring to change the password for. Cannot be %NULL
 * @original: The old keyring password, or %NULL to prompt the user for it.
 * @password: The new keyring password, or %NULL to prompt the user for it.
 *
 * Change the password for @keyring. In most cases you would specify %NULL for
 * both the @original and @password arguments and allow the user to type the 
 * correct passwords.  
 * 
 * For an asynchronous version of this function see gnome_keyring_change_password(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
GnomeKeyringResult
gnome_keyring_change_password_sync (const char *keyring_name,
			   const char *original, const char *password)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;
	
	egg_buffer_init_full (&send, 128, SECURE_ALLOCATOR);
	
	if (!gkr_proto_encode_op_string_secret_secret (&send,
	                                               GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD,
	                                               keyring_name, original, password)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_reply (&receive, &res)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
}

static gboolean
get_keyring_info_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetKeyringInfoCallback callback;
	GnomeKeyringInfo *info;

	callback = op->user_callback;
	
	if (!gkr_proto_decode_get_keyring_info_reply (&op->receive_buffer, &result, &info)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, info, op->user_data);
		gnome_keyring_info_free (info);
	}
	
	/* Operation is done */
	return TRUE;
}

/**
 * gnome_keyring_get_info:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get information about the @keyring. The resulting #GnomeKeyringInfo structure 
 * will be passed to @callback. The structure is freed after @callback returns.
 * 
 * For a synchronous version of this function see gnome_keyring_get_info_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_get_info (const char                                  *keyring,
			GnomeKeyringOperationGetKeyringInfoCallback  callback,
			gpointer                                     data,
			GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_GET_KEYRING_INFO, data, destroy_data);
	
	if (!gkr_proto_encode_op_string (&op->send_buffer, GNOME_KEYRING_OP_GET_KEYRING_INFO,
	                                 keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = get_keyring_info_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_get_info_sync:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @info: Location for the information about the keyring to be returned.
 *
 * Get information about @keyring. 
 * 
 * The #GnomeKeyringInfo structure returned in @info must be freed with 
 * gnome_keyring_info_free().
 * 
 * For an asynchronous version of this function see gnome_keyring_get_info(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
GnomeKeyringResult
gnome_keyring_get_info_sync (const char        *keyring,
			     GnomeKeyringInfo **info)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	*info = NULL;

	if (!gkr_proto_encode_op_string (&send, GNOME_KEYRING_OP_GET_KEYRING_INFO,
	                                 keyring)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_get_keyring_info_reply (&receive, &res, info)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

/**
 * gnome_keyring_set_info:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @info: A structure containing flags and info for the keyring.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Set flags and info for the @keyring. The only fields in @info that are used 
 * are %lock_on_idle and %lock_timeout. 
 * 
 * For a synchronous version of this function see gnome_keyring_set_info_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_set_info (const char                                  *keyring,
			GnomeKeyringInfo                            *info,
			GnomeKeyringOperationDoneCallback            callback,
			gpointer                                     data,
			GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	if (!gkr_proto_encode_set_keyring_info (&op->send_buffer, keyring, info)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = standard_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_set_info_sync:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @info: A structure containing flags and info for the keyring.
 *
 * Set flags and info for @keyring. The only fields in @info that are used
 * are %lock_on_idle and %lock_timeout.
 * 
 * For an asynchronous version of this function see gnome_keyring_set_info(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
GnomeKeyringResult
gnome_keyring_set_info_sync (const char       *keyring,
			     GnomeKeyringInfo *info)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;
	
	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	if (!gkr_proto_encode_set_keyring_info (&send, keyring, info)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	egg_buffer_uninit (&receive);
	
	return res;
}

static gboolean
list_item_ids_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetListCallback callback;
	GList *items;

	callback = op->user_callback;
	
	if (!gkr_proto_decode_result_int_list_reply (&op->receive_buffer, &result, &items)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, items, op->user_data);
		g_list_free (items);
	}
	
	/* Operation is done */
	return TRUE;
}

/**
 * gnome_keyring_list_item_ids:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get a list of all the ids for items in @keyring. These are passed in a %GList
 * to the @callback. Use GPOINTER_TO_UINT() on the list to access the integer ids.
 * The list is freed after @callback returns.
 * 
 * All items that are not flagged as %GNOME_KEYRING_ITEM_APPLICATION_SECRET are 
 * included in the list. This includes items that the calling application may not 
 * (yet) have access to.
 * 
 * For a synchronous version of this function see gnome_keyring_list_item_ids_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_list_item_ids (const char                                  *keyring,
			     GnomeKeyringOperationGetListCallback         callback,
			     gpointer                                     data,
			     GDestroyNotify                               destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_GET_LIST, data, destroy_data);

	if (!gkr_proto_encode_op_string (&op->send_buffer, GNOME_KEYRING_OP_LIST_ITEMS,
	                                 keyring)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = list_item_ids_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_list_item_ids_sync:
 * @keyring: The name of the keyring, or %NULL for the default keyring.
 * @ids: The location to store a %GList of item ids (ie: unsigned integers).
 *
 * Get a list of all the ids for items in @keyring. 
 * 
 * Use GPOINTER_TO_UINT() on the list to access the integer ids. The list 
 * should be freed with g_list_free(). 
 * 
 * For an asynchronous version of this function see gnome_keyring_list_item_ids(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
GnomeKeyringResult
gnome_keyring_list_item_ids_sync (const char  *keyring,
				  GList      **ids)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	*ids = NULL;

	if (!gkr_proto_encode_op_string (&send, GNOME_KEYRING_OP_LIST_ITEMS,
	                                 keyring)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_int_list_reply (&receive, &res, ids)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

/**
 * SECTION:gnome-keyring-daemon
 * @title: Daemon Management Functions
 * @short_description: Functions used by session to run the Gnome Keyring Daemon.
 * 
 * These functions are not used by most applications using Gnome Keyring.
 */

/**
 * gnome_keyring_daemon_set_display_sync:
 * @display: Deprecated 
 * 
 * Deprecated. Use gnome_keyring_daemon_prepare_environment_sync()
 **/ 
GnomeKeyringResult
gnome_keyring_daemon_set_display_sync (const char *display)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	if (!gkr_proto_encode_op_string (&send, GNOME_KEYRING_OP_SET_DAEMON_DISPLAY,
	                                 display)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_reply (&receive, &res)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);

	return res;
}

/**
 * gnome_keyring_daemon_prepare_environment_sync:
 * 
 * Used by session managers or applications that manage the gnome-keyring-daemon
 * process. Prepares the environment of both the daemon and the application
 * for successful communication. 
 * 
 * This includes telling the daemon the DBUS addresses, X display and related 
 * information to use for communication and display. This information is only 
 * used by the daemon if it does not already have it. For example the X display
 * of the daemon cannot be changed using this call.  
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/ 
GnomeKeyringResult
gnome_keyring_daemon_prepare_environment_sync (void)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;
	gchar **envp;
	gboolean ret;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	/* Get all the environment names */
	envp = gnome_keyring_build_environment (GNOME_KEYRING_IN_ENVIRONMENT);
	ret = gkr_proto_encode_prepare_environment (&send, (const gchar**)envp);
	g_strfreev (envp);
	
	if (!ret) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_prepare_environment_reply (&receive, &res, &envp)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	if (res == GNOME_KEYRING_RESULT_OK) {
		g_return_val_if_fail (envp, GNOME_KEYRING_RESULT_IO_ERROR);
		gnome_keyring_apply_environment (envp);
	}
	
	g_strfreev (envp);

	return res;
}

/**
 * gnome_keyring_info_set_lock_on_idle:
 * @keyring_info: The keyring info.
 * @value: Whether to lock or not.
 *
 * Set whether or not to lock a keyring after a certain amount of idle time.
 * 
 * See also gnome_keyring_info_set_lock_timeout().
 */
void
gnome_keyring_info_set_lock_on_idle (GnomeKeyringInfo *keyring_info,
				     gboolean          value)
{
	keyring_info->lock_on_idle = value;
}

/**
 * gnome_keyring_info_get_lock_on_idle:
 * @keyring_info: The keyring info.
 *
 * Get whether or not to lock a keyring after a certain amount of idle time.
 * 
 * See also gnome_keyring_info_get_lock_timeout().
 * 
 * Return value: Whether to lock or not.
 */
gboolean
gnome_keyring_info_get_lock_on_idle (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->lock_on_idle;
}

/**
 * gnome_keyring_info_set_lock_timeout:
 * @keyring_info: The keyring info.
 * @value: The lock timeout in seconds.
 *
 * Set the idle timeout, in seconds, after which to lock the keyring. 
 * 
 * See also gnome_keyring_info_set_lock_on_idle().
 */
void
gnome_keyring_info_set_lock_timeout (GnomeKeyringInfo *keyring_info,
				     guint32           value)
{
	keyring_info->lock_timeout = value;
}

/**
 * gnome_keyring_info_get_lock_timeout:
 * @keyring_info: The keyring info.
 *
 * Get the idle timeout, in seconds, after which to lock the keyring. 
 * 
 * See also gnome_keyring_info_get_lock_on_idle().
 * 
 * Return value: The idle timeout, in seconds.
 */
guint32
gnome_keyring_info_get_lock_timeout (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->lock_timeout;
}

/**
 * gnome_keyring_info_get_mtime:
 * @keyring_info: The keyring info.
 *
 * Get the time at which the keyring was last modified.
 * 
 * Return value: The last modified time.
 */
time_t
gnome_keyring_info_get_mtime (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->mtime;
}

/**
 * gnome_keyring_info_get_ctime:
 * @keyring_info: The keyring info.
 *
 * Get the time at which the keyring was created.
 * 
 * Return value: The created time.
 */
time_t
gnome_keyring_info_get_ctime (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->ctime;
}

/**
 * gnome_keyring_info_get_is_locked:
 * @keyring_info: The keyring info.
 *
 * Get whether the keyring is locked or not.
 * 
 * Return value: Whether the keyring is locked or not.
 */
gboolean
gnome_keyring_info_get_is_locked (GnomeKeyringInfo *keyring_info)
{
	return keyring_info->is_locked;
}

static gboolean
find_items_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetListCallback callback;
	GList *found_items;

	callback = op->user_callback;
	
	if (!gkr_proto_decode_find_reply (&op->receive_buffer, &result, &found_items)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, found_items, op->user_data);
		gnome_keyring_found_list_free (found_items);
	}
	
	/* Operation is done */
	return TRUE;
}

/**
 * SECTION:gnome-keyring-find
 * @title: Search Functionality
 * @short_description: Find Keyring Items
 * 
 * A find operation searches through all keyrings for items that match the 
 * attributes. The user may have been prompted to unlock necessary keyrings, and 
 * user will have been prompted for access to the items if needed.
 * 
 * A find operation may return multiple or zero results.
 */

/**
 * gnome_keyring_find_items:
 * @type: The type of items to find. 
 * @attributes: A list of attributes to search for. This cannot be an empty list.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Searches through all keyrings for items that match the @attributes. The matches
 * are for exact equality. 
 * 
 * A %GList of GnomeKeyringFound structures are passed to the @callback. The 
 * list and structures are freed after the callback returns.
 * 
 * The user may have been prompted to unlock necessary keyrings, and user will 
 * have been prompted for access to the items if needed. 
 * 
 * For a synchronous version of this function see gnome_keyring_find_items_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_find_items  (GnomeKeyringItemType                  type,
			   GnomeKeyringAttributeList            *attributes,
			   GnomeKeyringOperationGetListCallback  callback,
			   gpointer                              data,
			   GDestroyNotify                        destroy_data)
{
	GnomeKeyringOperation *op;
	
	/* Use a secure receive buffer */
	op = create_operation (TRUE, callback, CALLBACK_GET_LIST, data, destroy_data);

	if (!gkr_proto_encode_find (&op->send_buffer, type, attributes)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = find_items_reply;
	start_operation (op);
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

/**
 * gnome_keyring_find_itemsv:
 * @type: The type of items to find. 
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Searches through all keyrings for items that match the specified attributes. 
 * The matches are for exact equality.
 * 
 * The variable argument list should contain a) The attribute name as a null 
 * terminated string, followed by b) The attribute type, either 
 * %GNOME_KEYRING_ATTRIBUTE_TYPE_STRING or %GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32
 * and then the c) attribute value, either a character string, or 32-bit 
 * unsigned int. The list should be terminated with a NULL. 
 * 
 * A %GList of GnomeKeyringFound structures are passed to the @callback. The 
 * list and structures are freed after the callback returns.
 * 
 * The user may have been prompted to unlock necessary keyrings, and user will 
 * have been prompted for access to the items if needed. 
 * 
 * For a synchronous version of this function see gnome_keyring_find_itemsv_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
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
	
	/* Use a secure receive buffer */
	op = create_operation (TRUE, callback, CALLBACK_GET_LIST, data, destroy_data);

	va_start (args, destroy_data);
	attributes = make_attribute_list_va (args);
	va_end (args);
	if (attributes == NULL) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		return op;
	}
	
	if (!gkr_proto_encode_find (&op->send_buffer, type, attributes))  {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	g_array_free (attributes, TRUE);

	op->reply_handler = find_items_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_find_items_sync:
 * @type: The type of items to find. 
 * @attributes: A list of attributes to search for. This cannot be an empty list.
 * @found: The location to return a list of #GnomeKeyringFound pointers.
 * 
 * Searches through all keyrings for items that match the @attributes and @type. 
 * The matches are for exact equality. 
 * 
 * A %GList of GnomeKeyringFound structures is returned in @found. The list may 
 * have zero items if nothing matched the criteria. The list should be freed 
 * using gnome_keyring_found_list_free().
 * 
 * The user may have been prompted to unlock necessary keyrings, and user will 
 * have been prompted for access to the items if needed. 
 * 
 * For an asynchronous version of this function see gnome_keyring_find_items(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
GnomeKeyringResult
gnome_keyring_find_items_sync (GnomeKeyringItemType        type,
			       GnomeKeyringAttributeList  *attributes,
			       GList                     **found)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	*found = NULL;
	
	if (!gkr_proto_encode_find (&send, type, attributes)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
	/* Use a secure receive buffer */
	egg_buffer_init_full (&receive, 128, SECURE_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}
	
	if (!gkr_proto_decode_find_reply (&receive, &res, found)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

/**
 * gnome_keyring_find_itemsv_sync:
 * @type: The type of items to find. 
 * @found: The location to return a list of #GnomeKeyringFound pointers.
 * 
 * Searches through all keyrings for items that match the @attributes and @type. 
 * The matches are for exact equality. 
 * 
 * The variable argument list should contain a) The attribute name as a null 
 * terminated string, followed by b) The attribute type, either 
 * %GNOME_KEYRING_ATTRIBUTE_TYPE_STRING or %GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32
 * and then the c) attribute value, either a character string, or 32-bit 
 * unsigned int. The list should be terminated with a NULL. 
 * 
 * A %GList of GnomeKeyringFound structures is returned in @found. The list may 
 * have zero items if nothing matched the criteria. The list should be freed 
 * using gnome_keyring_found_list_free().
 * 
 * The user may have been prompted to unlock necessary keyrings, and user will 
 * have been prompted for access to the items if needed. 
 * 
 * For an asynchronous version of this function see gnome_keyring_find_items(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
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

/** 
 * SECTION:gnome-keyring-items
 * @title: Keyring Items
 * @short_description: Keyring items each hold a secret and a number of attributes.
 * 
 * A keyring contains multiple items. Each item has a secret, attributes and access 
 * information associated with it.
 * 
 * An item is identified by an unsigned integer unique to the keyring in which it 
 * exists. An item's name is for displaying to the user. Each item has a single secret, 
 * which is a null-terminated string. This secret is stored in non-pageable memory, and 
 * encrypted on disk. All of this information is exposed via #GnomeKeyringItemInfo
 * pointers.
 * 
 * Attributes allow various other pieces of information to be associated with an item. 
 * These can also be used to search for relevant items. Attributes are accessed with 
 * #GnomeKeyringAttribute structures and built into lists using #GnomeKeyringAttributeList.
 * 
 * Each item has an access control list, which specifies the applications that 
 * can read, write or delete an item. The read access applies only to reading the secret.
 * All applications can read other parts of the item. ACLs are accessed and changed
 * through #GnomeKeyringAccessControl pointers.
 */

/**
 * gnome_keyring_item_create:
 * @keyring: The name of the keyring in which to create the item, or NULL for the default keyring.
 * @type: The item type.
 * @display_name: The name of the item. This will be displayed to the user where necessary.
 * @attributes: A (possibly empty) list of attributes to store with the item. 
 * @secret: The password or secret of the item.
 * @update_if_exists: If true, then another item matching the type, and attributes
 *  will be updated instead of creating a new item.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Create a new item in a keyring. 
 * 
 * The @secret must be a null terminated string. It should be allocated using secure 
 * memory whenever possible. See gnome_keyring_memory_strdup() 
 *
 * The user may have been prompted to unlock necessary keyrings. If %NULL is 
 * specified as the @keyring and no default keyring exists, the user will be 
 * prompted to create a new keyring.
 * 
 * When @update_if_exists is set to %TRUE, the user may be prompted for access
 * to the previously existing item.
 *
 * Whether a new item is created or not, id of the item will be passed to 
 * the @callback. 
 * 
 * For a synchronous version of this function see gnome_keyring_item_create_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
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
	
	op = create_operation (FALSE, callback, CALLBACK_GET_INT, data, destroy_data);
	
	/* Automatically secures buffer */
	if (!gkr_proto_encode_create_item (&op->send_buffer, keyring, display_name,
	                                   attributes, secret, type, update_if_exists)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = int_reply;
	start_operation (op);	
	return op;
}

/**
 * gnome_keyring_item_create_sync():
 * @keyring: The name of the keyring in which to create the item, or NULL for the default keyring.
 * @type: The item type.
 * @display_name: The name of the item. This will be displayed to the user where necessary.
 * @attributes: A (possibly empty) list of attributes to store with the item. 
 * @secret: The password or secret of the item.
 * @update_if_exists: If true, then another item matching the type, and attributes
 *  will be updated instead of creating a new item.
 * @item_id: return location for the id of the created/updated keyring item.
 *
 * Create a new item in a keyring. 
 * 
 * The @secret must be a null terminated string. It should be allocated using secure 
 * memory whenever possible. See gnome_keyring_memory_strdup() 
 *
 * The user may have been prompted to unlock necessary keyrings. If %NULL is 
 * specified as the @keyring and no default keyring exists, the user will be 
 * prompted to create a new keyring.
 * 
 * When @update_if_exists is set to %TRUE, the user may be prompted for access
 * to the previously existing item.
 *
 * For an asynchronous version of this function see gnome_keyring_create(). 
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
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
	EggBuffer send, receive;
	GnomeKeyringResult res;

	/* Use a secure buffer */
	egg_buffer_init_full (&send, 128, SECURE_ALLOCATOR);

	*item_id = 0;
	
	if (!gkr_proto_encode_create_item (&send, keyring, display_name, attributes,
	                                   secret, type, update_if_exists)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}

	if (!gkr_proto_decode_result_integer_reply (&receive, &res, item_id)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

/**
 * gnome_keyring_item_delete:
 * @keyring: The name of the keyring from which to delete the item, or NULL for the default keyring.
 * @id: The id of the item
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Delete an item in a keyring. 
 * 
 * The user may be prompted if the calling application doesn't have necessary
 * access to delete the item.
 *
 * For an asynchronous version of this function see gnome_keyring_delete(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_delete (const char                                 *keyring,
			   guint32                                     id,
			   GnomeKeyringOperationDoneCallback           callback,
			   gpointer                                    data,
			   GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	if (!gkr_proto_encode_op_string_int (&op->send_buffer, GNOME_KEYRING_OP_DELETE_ITEM,
	                                     keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = standard_reply;
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_item_delete_sync:
 * @keyring: The name of the keyring from which to delete the item, or NULL for the default keyring.
 * @id: The id of the item
 *
 * Delete an item in a keyring. 
 * 
 * The user may be prompted if the calling application doesn't have necessary
 * access to delete the item.
 *
 * For an asynchronous version of this function see gnome_keyring_item_delete(). 
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
GnomeKeyringResult
gnome_keyring_item_delete_sync (const char *keyring,
				guint32     id)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	if (!gkr_proto_encode_op_string_int (&send, GNOME_KEYRING_OP_DELETE_ITEM,
	                                     keyring, id)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	egg_buffer_uninit (&receive);

	return res;
}

static gboolean
get_item_info_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetItemInfoCallback callback;
	GnomeKeyringItemInfo *info;

	callback = op->user_callback;
	
	if (!gkr_proto_decode_get_item_info_reply (&op->receive_buffer, &result, &info)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, info, op->user_data);
		gnome_keyring_item_info_free (info);
	}

	/* Operation is done */
	return TRUE;
}

/**
 * gnome_keyring_item_get_info:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get information about an item and its secret.
 * 
 * The user may be prompted if the calling application doesn't have necessary
 * access to read the item with its secret.
 * 
 * A #GnomeKeyringItemInfo structure will be passed to the @callback. This structure
 * will be freed after @callback returns.
 *
 * For a synchronous version of this function see gnome_keyring_item_get_info_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_get_info (const char                                 *keyring,
			     guint32                                     id,
			     GnomeKeyringOperationGetItemInfoCallback    callback,
			     gpointer                                    data,
			     GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	/* Use a secure receive buffer */
	op = create_operation (TRUE, callback, CALLBACK_GET_ITEM_INFO, data, destroy_data);
	
	if (!gkr_proto_encode_op_string_int (&op->send_buffer, GNOME_KEYRING_OP_GET_ITEM_INFO,
	                                     keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = get_item_info_reply;
	start_operation (op);	
	return op;
}

/**
 * gnome_keyring_item_get_info_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @info: The location to return a #GnomeKeyringItemInfo pointer.
 *
 * Get information about an item and its secret.
 *
 * The user may be prompted if the calling application doesn't have necessary
 * access to read the item with its secret. 
 *
 * A #GnomeKeyringItemInfo structure will be returned in @info. This must be
 * freed using gnome_keyring_item_info_free().
 *
 * For an asynchronous version of this function see gnome_keyring_item_get_info(). 
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
GnomeKeyringResult 
gnome_keyring_item_get_info_sync (const char            *keyring,
				  guint32                id,
				  GnomeKeyringItemInfo **info)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	*info = NULL;
	
	if (!gkr_proto_encode_op_string_int (&send, GNOME_KEYRING_OP_GET_ITEM_INFO,
	                                     keyring, id)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}

	/* Use a secure buffer */ 	
	egg_buffer_init_full (&receive, 128, SECURE_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}
	
	if (!gkr_proto_decode_get_item_info_reply (&receive, &res, info)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

/**
 * gnome_keyring_item_get_info_full:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @flags: The parts of the item to retrieve.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get information about an item, optionally retrieving its secret.
 * 
 * If @flags includes %GNOME_KEYRING_ITEM_INFO_SECRET then the user may be 
 * prompted if the calling application doesn't have necessary access to read 
 * the item with its secret.
 * 
 * A #GnomeKeyringItemInfo pointer will be passed to the @callback. Certain fields
 * of this structure may be NULL or zero if they were not specified in @flags. This 
 * structure will be freed after @callback returns.
 *
 * For a synchronous version of this function see gnome_keyring_item_get_info_full_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_get_info_full (const char                                 *keyring,
				  guint32                                     id,
				  guint32                                     flags,
				  GnomeKeyringOperationGetItemInfoCallback    callback,
				  gpointer                                    data,
				  GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	/* Use a secure receive buffer */ 
	op = create_operation (TRUE, callback, CALLBACK_GET_ITEM_INFO, data, destroy_data);
	
	if (!gkr_proto_encode_op_string_int_int (&op->send_buffer,
	                                         GNOME_KEYRING_OP_GET_ITEM_INFO_FULL,
	                                         keyring, id, flags)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = get_item_info_reply;
	start_operation (op);	
	return op;
}

/**
 * gnome_keyring_item_get_info_full_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @flags: The parts of the item to retrieve.
 * @info: The location to return a #GnomeKeyringItemInfo pointer.
 *
 * Get information about an item, optionally retrieving its secret.
 * 
 * If @flags includes %GNOME_KEYRING_ITEM_INFO_SECRET then the user may be 
 * prompted if the calling application doesn't have necessary access to read 
 * the item with its secret.
 * 
 * A #GnomeKeyringItemInfo structure will be returned in @info. Certain fields
 * of this structure may be NULL or zero if they were not specified in @flags. 
 * This must be freed using gnome_keyring_item_info_free().
 *
 * For an asynchronous version of this function see gnome_keyring_item_get_info_full(). 
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
GnomeKeyringResult
gnome_keyring_item_get_info_full_sync (const char              *keyring,
				       guint32                  id,
				       guint32                  flags,
 				       GnomeKeyringItemInfo   **info)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	*info = NULL;
	
	if (!gkr_proto_encode_op_string_int_int (&send, GNOME_KEYRING_OP_GET_ITEM_INFO_FULL,
	                                         keyring, id, flags)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
	/* Use a secure buffer */
	egg_buffer_init_full (&receive, 128, SECURE_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}
	
	if (!gkr_proto_decode_get_item_info_reply (&receive, &res, info)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

/**
 * gnome_keyring_item_set_info:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @info: The item info to save into the item. 
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Set information on an item, like its display name, secret etc...
 * 
 * Only the fields in the @info pointer that are non-null or non-zero will be 
 * set on the item. 
 * 
 * For a synchronous version of this function see gnome_keyring_item_set_info_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_set_info (const char                                 *keyring,
			     guint32                                     id,
			     GnomeKeyringItemInfo                       *info,
			     GnomeKeyringOperationDoneCallback           callback,
			     gpointer                                    data,
			     GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	/* Automatically secures buffer */
	if (!gkr_proto_encode_set_item_info (&op->send_buffer, keyring, id, info)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = standard_reply;
	start_operation (op);	
	return op;
}

/**
 * gnome_keyring_item_set_info_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @info: The item info to save into the item.
 *
 * Set information on an item, like its display name, secret etc...
 *
 * Only the fields in the @info pointer that are non-null or non-zero will be 
 * set on the item.
 *  
 * For an asynchronous version of this function see gnome_keyring_item_set_info(). 
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
GnomeKeyringResult 
gnome_keyring_item_set_info_sync (const char           *keyring,
				  guint32               id,
				  GnomeKeyringItemInfo *info)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;
	
	/* Use a secure memory buffer */
	egg_buffer_init_full (&send, 128, SECURE_ALLOCATOR);
	
	if (!gkr_proto_encode_set_item_info (&send, keyring, id, info)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	egg_buffer_uninit (&receive);
	
	return res;
}

static gboolean
get_attributes_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetAttributesCallback callback;
	GnomeKeyringAttributeList *attributes;

	callback = op->user_callback;
	
	if (!gkr_proto_decode_get_attributes_reply (&op->receive_buffer, &result, &attributes)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, attributes, op->user_data);
		gnome_keyring_attribute_list_free (attributes);
	}
	
	/* Operation is done */
	return TRUE;
}

static gboolean
get_acl_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetListCallback callback;
	GList *acl;

	callback = op->user_callback;
	
	if (!gkr_proto_decode_get_acl_reply (&op->receive_buffer, &result, &acl)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		(*callback) (result, acl, op->user_data);
		g_list_free (acl);
	}
	
	/* Operation is done */
	return TRUE;
}

/**
 * gnome_keyring_item_get_attributes:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get all the attributes for an item.
 * 
 * A #GnomeKeyringAttributeList will be passed to the @callback. This list will 
 * be freed after @callback returns.
 * 
 * For a synchronous version of this function see gnome_keyring_item_get_attributes_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_get_attributes (const char                                 *keyring,
				   guint32                                     id,
				   GnomeKeyringOperationGetAttributesCallback  callback,
				   gpointer                                    data,
				   GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_GET_ATTRIBUTES, data, destroy_data);
	
	if (!gkr_proto_encode_op_string_int (&op->send_buffer, GNOME_KEYRING_OP_GET_ITEM_ATTRIBUTES,
	                                     keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = get_attributes_reply;
	start_operation (op);	
	return op;
}

/**
 * gnome_keyring_item_get_attributes_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @attributes: The location to return a pointer to the attribute list.
 *
 * Get all attributes for an item.
 *
 * A #GnomeKeyringAttributeList will be returned in @attributes. This should be 
 * freed using gnome_keyring_attribute_list_free(). 
 *  
 * For an asynchronous version of this function see gnome_keyring_item_get_attributes(). 
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
GnomeKeyringResult
gnome_keyring_item_get_attributes_sync (const char                 *keyring,
					guint32                     id,
					GnomeKeyringAttributeList **attributes)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	*attributes = NULL;
	
	if (!gkr_proto_encode_op_string_int (&send, GNOME_KEYRING_OP_GET_ITEM_ATTRIBUTES,
	                                     keyring, id)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}
	
	if (!gkr_proto_decode_get_attributes_reply (&receive, &res, attributes)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

/**
 * gnome_keyring_item_set_attributes:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @attributes: The full list of attributes to set on the item.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Set all the attributes for an item. This will replace any previous attributes
 * set on the item. 
 * 
 * For a synchronous version of this function see gnome_keyring_item_set_attributes_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_set_attributes (const char                                 *keyring,
				   guint32                                     id,
				   GnomeKeyringAttributeList                  *attributes,
				   GnomeKeyringOperationDoneCallback           callback,
				   gpointer                                    data,
				   GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	if (!gkr_proto_encode_set_attributes (&op->send_buffer, keyring, id,
	                                      attributes)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = standard_reply;
	start_operation (op);	
	return op;
}

/**
 * gnome_keyring_item_set_attributes_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @attributes: The full list of attributes to set on the item.
 *
 * Set all the attributes for an item. This will replace any previous attributes
 * set on the item.
 *
 * For an asynchronous version of this function see gnome_keyring_item_set_attributes(). 
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
GnomeKeyringResult
gnome_keyring_item_set_attributes_sync (const char                *keyring,
					guint32                    id,
					GnomeKeyringAttributeList *attributes)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;
	
	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	if (!gkr_proto_encode_set_attributes (&send, keyring, id, attributes)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	egg_buffer_uninit (&receive);
	
	return res;

}

/**
 * gnome_keyring_item_get_acl:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Get the access control list for an item.
 * 
 * A %GList of #GnomeKeyringAccessControl pointers will be passed to the @callback. 
 * This list and its contents will be freed after @callback returns.
 * 
 * For a synchronous version of this function see gnome_keyring_item_get_acl_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_get_acl (const char                                 *keyring,
			    guint32                                     id,
			    GnomeKeyringOperationGetListCallback        callback,
			    gpointer                                    data,
			    GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_GET_ACL, data, destroy_data);
	
	if (!gkr_proto_encode_op_string_int (&op->send_buffer,
	                                     GNOME_KEYRING_OP_GET_ITEM_ACL,
	                                     keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = get_acl_reply;
	start_operation (op);	
	return op;
}

/**
 * gnome_keyring_item_get_acl_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @acl: The location to return a pointer to the access control list.
 *
 * Get the access control list for an item.
 *
 * A %GList of #GnomeKeyringAccessControl pointers will be passed to the @callback. 
 * This list should be freed using gnome_keyring_access_control_list_free(). 
 *  
 * For an asynchronous version of this function see gnome_keyring_item_get_acl(). 
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
GnomeKeyringResult
gnome_keyring_item_get_acl_sync (const char  *keyring,
				 guint32      id,
				 GList      **acl)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;

	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);

	*acl = NULL;
	
	if (!gkr_proto_encode_op_string_int (&send, GNOME_KEYRING_OP_GET_ITEM_ACL,
	                                     keyring, id)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);

	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	if (res != GNOME_KEYRING_RESULT_OK) {
		egg_buffer_uninit (&receive);
		return res;
	}
	
	if (!gkr_proto_decode_get_acl_reply (&receive, &res, acl)) {
		egg_buffer_uninit (&receive);
		return GNOME_KEYRING_RESULT_IO_ERROR;
	}
	egg_buffer_uninit (&receive);
	
	return res;
}

/**
 * gnome_keyring_item_set_acl:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @acl: The access control list to set on the item.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 *
 * Set the full access control list on an item. This replaces any previous ACL 
 * setup on the item. 
 * 
 * For a synchronous version of this function see gnome_keyring_item_set_acl_sync(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 **/
gpointer
gnome_keyring_item_set_acl (const char                                 *keyring,
			    guint32                                     id,
			    GList                                      *acl,
			    GnomeKeyringOperationDoneCallback           callback,
			    gpointer                                    data,
			    GDestroyNotify                              destroy_data)
{
	GnomeKeyringOperation *op;
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	if (!gkr_proto_encode_set_acl (&op->send_buffer, keyring, id, acl)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = standard_reply;
	start_operation (op);	
	return op;
}

/**
 * gnome_keyring_item_set_acl_sync:
 * @keyring: The name of the keyring in which the item exists, or NULL for the default keyring.
 * @id: The id of the item
 * @acl: The access control list to set on the item.
 *
 * Set the full access control list on an item. This  replaces any previous
 * ACL setup on the item.
 *
 * For an asynchronous version of this function see gnome_keyring_item_set_acl(). 
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
GnomeKeyringResult 
gnome_keyring_item_set_acl_sync (const char *keyring,
				 guint32     id,
				 GList      *acl)
{
	EggBuffer send, receive;
	GnomeKeyringResult res;
	
	egg_buffer_init_full (&send, 128, NORMAL_ALLOCATOR);
	
	if (!gkr_proto_encode_set_acl (&send, keyring, id, acl)) {
		egg_buffer_uninit (&send);
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	}
	
 	egg_buffer_init_full (&receive, 128, NORMAL_ALLOCATOR);
	res = run_sync_operation (&send, &receive);
	egg_buffer_uninit (&send);
	egg_buffer_uninit (&receive);
	
	return res;
}

typedef struct _GrantAccessRights {
	GnomeKeyringApplicationRef app_ref;
	GnomeKeyringAccessControl acl;
	gchar *keyring_name;
	guint32 id;
} GrantAccessRights;

static void
destroy_grant_access_rights (gpointer data)
{
	GrantAccessRights *gar = (GrantAccessRights*)data;
	g_free (gar->app_ref.display_name);
	g_free (gar->app_ref.pathname);
	g_free (gar->keyring_name);
	g_free (gar);
}

static gboolean
item_grant_access_rights_reply (GnomeKeyringOperation *op)
{
	GrantAccessRights *gar;
	GnomeKeyringResult result;
	GnomeKeyringOperationDoneCallback callback;
	gboolean ret;
	GList *acl;

	callback = op->user_callback;
	
	/* Parse the old access rights */
	if (!gkr_proto_decode_get_acl_reply (&op->receive_buffer, &result, &acl)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, op->user_data);
		return TRUE;
	} 
	
	gar = (GrantAccessRights*)op->reply_data;
	g_assert (gar);
	
	/* Send off the new access rights */
	start_operation (op);
	
	/* Append our ACL to the list */
	egg_buffer_reset (&op->send_buffer);
	acl = g_list_append (acl, &gar->acl);
	ret = gkr_proto_encode_set_acl (&op->send_buffer, gar->keyring_name, 
	                                          gar->id, acl);
	                  
	/* A bit of cleanup */                        
	acl = g_list_remove (acl, &gar->acl);
	g_list_free (acl); 
	                                          
	if (!ret) {
		(*callback) (GNOME_KEYRING_RESULT_BAD_ARGUMENTS, op->user_data);
		return TRUE;
	}
	
	op->reply_handler = standard_reply;
	
	/* Not done yet */
	return FALSE;
}

/**
 * gnome_keyring_item_grant_access_rights:
 * @keyring: The keyring name, or NULL for the default keyring.
 * @display_name: The display name for the application, as returned by g_get_application_name().
 * @full_path: The full filepath to the application.
 * @id: The id of the item to grant access to.
 * @rights: The type of rights to grant.
 * @callback: Callback which is called when the operation completes
 * @data: Data to be passed to callback
 * @destroy_data: Function to be called when data is no longer needed.
 * 
 * Will grant the application access rights to the item, provided 
 * callee has write access to said item.
 * 
 * This is similar to calling gnome_keyring_item_get_acl() and 
 * gnome_keyring_item_set_acl() with appropriate parameters.
 * 
 * For a synchronous version of this function see gnome_keyring_item_grant_access_rights(). 
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 * Since: 2.20
 **/
gpointer 
gnome_keyring_item_grant_access_rights (const gchar *keyring, 
                                        const gchar *display_name, 
                                        const gchar *full_path, 
                                        const guint32 id, 
                                        const GnomeKeyringAccessType rights,
                                        GnomeKeyringOperationDoneCallback callback,
                                        gpointer data,
                                        GDestroyNotify destroy_data)
{    
	GnomeKeyringOperation *op;
	GrantAccessRights *gar;
	
	/* First get current ACL */
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	if (!gkr_proto_encode_op_string_int (&op->send_buffer,
	                                     GNOME_KEYRING_OP_GET_ITEM_ACL,
	                                     keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = item_grant_access_rights_reply;

	/* Copy information that the reply callback needs */
	gar = g_new0 (GrantAccessRights, 1); 
	gar->app_ref.display_name = g_strdup (display_name);
	gar->app_ref.pathname = g_strdup (full_path);
	gar->acl.application = &gar->app_ref;
	gar->acl.types_allowed = rights;
	gar->keyring_name = g_strdup (keyring);
	gar->id = id;
	
	op->reply_data = gar;
	op->destroy_reply_data = destroy_grant_access_rights;
	start_operation (op);
	
	return op;
}

/**
 * gnome_keyring_item_grant_access_rights_sync:
 * @keyring: The keyring name, or NULL for the default keyring.
 * @display_name: The display name for the application, as returned by g_get_application_name().
 * @full_path: The full filepath to the application.
 * @id: The id of the item to grant access to.
 * @rights: The type of rights to grant.
 * 
 * Will grant the application access rights to the item, provided 
 * callee has write access to said item.
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 **/
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

/**
 * gnome_keyring_item_info_get_type:
 * @item_info: A keyring item info pointer.
 * 
 * Get the item type.
 * 
 * Return value: The item type
 **/
GnomeKeyringItemType
gnome_keyring_item_info_get_type (GnomeKeyringItemInfo *item_info)
{
	return item_info->type;
}

/**
 * gnome_keyring_item_info_set_type:
 * @item_info: A keyring item info pointer.
 * @type: The new item type
 *
 * Set the type on an item info.
 **/
void
gnome_keyring_item_info_set_type (GnomeKeyringItemInfo *item_info,
				  GnomeKeyringItemType  type)
{
	item_info->type = type;
}

/**
 * gnome_keyring_item_info_get_secret:
 * @item_info: A keyring item info pointer.
 *
 * Get the item secret. 
 * 
 * Return value: The newly allocated string containing the item secret.
 **/
char *
gnome_keyring_item_info_get_secret (GnomeKeyringItemInfo *item_info)
{
	/* XXXX For compatibility reasons we can't use secure memory here */
	return g_strdup (item_info->secret);
}

/**
 * gnome_keyring_item_info_set_secret:
 * @item_info: A keyring item info pointer.
 * @value: The new item secret
 *
 * Set the secret on an item info.
 **/
void
gnome_keyring_item_info_set_secret (GnomeKeyringItemInfo *item_info,
				    const char           *value)
{
	gnome_keyring_free_password (item_info->secret);
	item_info->secret = gnome_keyring_memory_strdup (value);
}

/**
 * gnome_keyring_item_info_get_display_name:
 * @item_info: A keyring item info pointer.
 *
 * Get the item display name.
 * 
 * Return value: The newly allocated string containing the item display name.
 **/
char *
gnome_keyring_item_info_get_display_name (GnomeKeyringItemInfo *item_info)
{
	return g_strdup (item_info->display_name);
}

/**
 * gnome_keyring_item_info_set_display_name:
 * @item_info: A keyring item info pointer.
 * @value: The new display name.
 *
 * Set the display name on an item info.
 **/
void
gnome_keyring_item_info_set_display_name (GnomeKeyringItemInfo *item_info,
					  const char           *value)
{
	g_free (item_info->display_name);
	item_info->display_name = g_strdup (value);
}

/**
 * gnome_keyring_item_info_get_mtime:
 * @item_info: A keyring item info pointer.
 *
 * Get the item last modified time.
 * 
 * Return value: The item last modified time.
 **/
time_t
gnome_keyring_item_info_get_mtime (GnomeKeyringItemInfo *item_info)
{
	return item_info->mtime;
}

/**
 * gnome_keyring_item_info_get_ctime:
 * @item_info: A keyring item info pointer.
 *
 * Get the item created time.
 * 
 * Return value: The item created time.
 **/
time_t
gnome_keyring_item_info_get_ctime (GnomeKeyringItemInfo *item_info)
{
	return item_info->ctime;
}

/**
 * SECTION:gnome-keyring-acl
 * @title: Item ACLs
 * @short_description: Access control lists for keyring items.
 * 
 * Each item has an access control list, which specifies the applications that 
 * can read, write or delete an item. The read access applies only to reading the secret.
 * All applications can read other parts of the item. ACLs are accessed and changed
 * gnome_keyring_item_get_acl() and gnome_keyring_item_set_acl().
 */

/**
 * gnome_keyring_item_ac_get_display_name:
 * @ac: A #GnomeKeyringAccessControl pointer.
 * 
 * Get the access control application's display name.  
 * 
 * Return value: A newly allocated string containing the display name.
 */
char *
gnome_keyring_item_ac_get_display_name (GnomeKeyringAccessControl *ac)
{
	return g_strdup (ac->application->display_name);
}

/**
 * gnome_keyring_item_ac_set_display_name:
 * @ac: A #GnomeKeyringAcccessControl pointer.
 * @value: The new application display name.
 * 
 * Set the access control application's display name.
 **/
void
gnome_keyring_item_ac_set_display_name (GnomeKeyringAccessControl *ac,
					const char                *value)
{
	g_free (ac->application->display_name);
	ac->application->display_name = g_strdup (value);
}

/**
 * gnome_keyring_item_ac_get_path_name:
 * @ac: A #GnomeKeyringAccessControl pointer.
 * 
 * Get the access control application's full path name.
 * 
 * Return value: A newly allocated string containing the display name.
 **/
char *
gnome_keyring_item_ac_get_path_name (GnomeKeyringAccessControl *ac)
{
	return g_strdup (ac->application->pathname);
}

/**
 * gnome_keyring_item_ac_set_path_name:
 * @ac: A #GnomeKeyringAccessControl pointer
 * @value: The new application full path.
 * 
 * Set the access control application's full path name.
 **/
void
gnome_keyring_item_ac_set_path_name (GnomeKeyringAccessControl *ac,
				     const char                *value)
{
	g_free (ac->application->pathname);
	ac->application->pathname = g_strdup (value);
}

/**
 * gnome_keyring_item_ac_get_access_type:
 * @ac: A #GnomeKeyringAccessControl pointer.
 * 
 * Get the application access rights for the access control.
 * 
 * Return value: The access rights.
 */ 
GnomeKeyringAccessType
gnome_keyring_item_ac_get_access_type (GnomeKeyringAccessControl *ac)
{
	return ac->types_allowed;
}

/**
 * gnome_keyring_item_ac_set_access_type:
 * @ac: A #GnomeKeyringAccessControl pointer.
 * @value: The new access rights.
 * 
 * Set the application access rights for the access control.
 **/
void
gnome_keyring_item_ac_set_access_type (GnomeKeyringAccessControl *ac,
				       const GnomeKeyringAccessType value)
{
	ac->types_allowed = value;
}

/* ------------------------------------------------------------------------------
 * NETWORK PASSWORD APIS
 */

/**
 * SECTION:gnome-keyring-network
 * @title: Network Passwords
 * @short_description: Saving of network passwords.
 * 
 * Networks passwords are a simple way of saving passwords associated with a 
 * certain user/server/protocol and other fields.
 */

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
		data->password = gnome_keyring_memory_strdup (found->secret);

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

/**
 * gnome_keyring_network_password_free:
 * @data: A #GnomeKeyringNetworkPasswordData pointer.
 * 
 * Free a network password data pointer. If %NULL is passed in,
 * nothing happens.
 */
void
gnome_keyring_network_password_free (GnomeKeyringNetworkPasswordData *data)
{
	if (!data)
		return;
		
	g_free (data->keyring);
	g_free (data->protocol);
	g_free (data->server);
	g_free (data->object);
	g_free (data->authtype);
	g_free (data->user);
	g_free (data->domain);
	gnome_keyring_free_password (data->password);
	
	g_free (data);
}

/**
 * gnome_keyring_network_password_list_free:
 * @list: A list of #GnomeKeyringNetworkPasswordData pointers.
 * 
 * Free a list of network password data.
 */
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

/**
 * gnome_keyring_find_network_password:
 * @user: The user name or %NULL for any user.
 * @domain: The domain name %NULL for any domain.
 * @server: The server or %NULL for any server.
 * @object: The remote object or %NULL for any object.
 * @protocol: The network protorol or %NULL for any protocol.
 * @authtype: The authentication type or %NULL for any type.
 * @port: The network port or zero for any port.
 * @callback: Callback which is called when the operation completes
 * @data: Data to be passed to callback
 * @destroy_data: Function to be called when data is no longer needed.
 * 
 * Find a previously stored network password. Searches all keyrings.
 * 
 * A %GList of #GnomeKeyringNetworkPasswordData structures are passed to the 
 * @callback. The list and structures are freed after the callback returns.
 * 
 * The user may have been prompted to unlock necessary keyrings, and user will 
 * have been prompted for access to the items if needed. 
 * 
 * Network passwords are items with the item type %GNOME_KEYRING_ITEM_NETWORK_PASSWORD
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 */
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

/**
 * gnome_keyring_find_network_password_sync:
 * @user: The user name or %NULL.
 * @domain: The domain name %NULL.
 * @server: The server or %NULL.
 * @object: The remote object or %NULL.
 * @protocol: The network protorol or %NULL.
 * @authtype: The authentication type or %NULL.
 * @port: The network port or zero.
 * @results: A location to return a %GList of #GnomeKeyringNetworkPasswordData pointers.
 * 
 * Find a previously stored network password. Searches all keyrings.
 * 
 * A %GList of #GnomeKeyringNetworkPasswordData structures are returned in the 
 * @out_list argument. The list should be freed with gnome_keyring_network_password_list_free()
 * 
 * The user may have been prompted to unlock necessary keyrings, and user will 
 * have been prompted for access to the items if needed. 
 * 
 * Network passwords are items with the item type %GNOME_KEYRING_ITEM_NETWORK_PASSWORD
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
GnomeKeyringResult
gnome_keyring_find_network_password_sync (const char                            *user,
					  const char                            *domain,
					  const char                            *server,
					  const char                            *object,
					  const char                            *protocol,
					  const char                            *authtype,
					  guint32                                port,
					  GList                                **results)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult result;
	GList *found;
	
	*results = NULL;
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
		*results = found_list_to_nework_password_list (found);
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
				   

/**
 * gnome_keyring_set_network_password:
 * @keyring: The keyring to store the password in, or %NULL for the default keyring.
 * @user: The user name or %NULL.
 * @domain: The domain name %NULL.
 * @server: The server or %NULL.
 * @object: The remote object or %NULL.
 * @protocol: The network protorol or %NULL.
 * @authtype: The authentication type or %NULL.
 * @port: The network port or zero.
 * @password: The password to store, must not be %NULL.
 * @callback: Callback which is called when the operation completes
 * @data: Data to be passed to callback
 * @destroy_data: Function to be called when data is no longer needed.
 * 
 * Store a network password.
 * 
 * If an item already exists for with this network info (ie: user, server etc...)
 * then it will be updated. 
 * 
 * Whether a new item is created or not, id of the item will be passed to 
 * the @callback. 
 * 
 * Network passwords are items with the item type %GNOME_KEYRING_ITEM_NETWORK_PASSWORD
 * 
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 */
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

/**
 * gnome_keyring_set_network_password_sync:
 * @keyring: The keyring to store the password in, or %NULL for the default keyring.
 * @user: The user name or %NULL.
 * @domain: The domain name %NULL.
 * @server: The server or %NULL.
 * @object: The remote object or %NULL.
 * @protocol: The network protorol or %NULL.
 * @authtype: The authentication type or %NULL.
 * @port: The network port or zero.
 * @password: The password to store, must not be %NULL.
 * @item_id: A location to store the resulting item's id.
 * 
 * Store a network password.
 * 
 * If an item already exists for with this network info (ie: user, server etc...)
 * then it will be updated. 
 * 
 * The created or updated item id will be returned in @item_id.
 * 
 * Network passwords are items with the item type %GNOME_KEYRING_ITEM_NETWORK_PASSWORD
 * 
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 */
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

/* ------------------------------------------------------------------------------
 * SIMPLE PASSWORD APIS
 */

/**
 * SECTION:gnome-keyring-password
 * @title: Simple Password Storage
 * @short_description: Store and lookup passwords with a set of attributes.
 * 
 * This is a simple API for storing passwords and retrieving passwords in the keyring.
 * 
 * Each password is associated with a set of attributes. Attribute values can be either 
 * strings or unsigned integers.
 *  
 * The names and types of allowed attributes for a given password are defined with a 
 * schema. Certain schemas are predefined such as %GNOME_KEYRING_NETWORK_PASSWORD. 
 * Additional schemas can be defined via the %GnomeKeyringPasswordSchema structure.
 * 
 * Each function accepts a variable list of attributes names and their values. 
 * Include a %NULL to terminate the list of attributes.
 * 
 * <example>
 * <title>Passing attributes to the functions</title>
 * <programlisting>
 *   res = gnome_keyring_delete_password_sync (GNOME_KEYRING_NETWORK_PASSWORD,
 *                                             "user", "me",        // A string attribute
 *                                             "server, "example.gnome.org", 
 *                                             "port", "8080",      // An integer attribute
 *                                             NULL);
 * </programlisting></example>
 */

/**
 * GnomeKeyringPasswordSchema:
 * 
 * Describes a password schema. Often you'll want to use a predefined schema such 
 * as %GNOME_KEYRING_NETWORK_PASSWORD.
 * 
 * <para>
 * The last attribute name in a schema must be %NULL.
 * 
 * <programlisting>
 *   GnomeKeyringPasswordSchema my_schema = {
 *       GNOME_KEYRING_ITEM_GENERIC_SECRET,
 *       { 
 *            { "string-attr", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
 *            { "uint-attr", GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32 },
 *            { NULL, 0 }
 *       }
 *   };
 * </programlisting>
 * </para>
 */

static const GnomeKeyringPasswordSchema network_password_schema = {
	GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
	{
		{  "user", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "domain", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "object", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "protocol", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "port", GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32 },
		{  "server", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
		{  "NULL", 0 },
	}
};

/**
 * GNOME_KEYRING_NETWORK_PASSWORD:
 * 
 * <para>
 * A predefined schema for network paswsords. It contains the following attributes:
 * </para>
 * <itemizedlist>
 * <listitem>user: A string for the user login.</listitem>
 * <listitem>server: The server being connected to.</listitem>
 * <listitem>protocol: The protocol used to access the server, such as 'http' or 'smb'</listitem>
 * <listitem>domain: A realm or domain, such as a Windows login domain.</listitem>
 * <listitem>port: The network port to used to connect to the server.</listitem>
 * </itemizedlist>
 */

/* Declared in gnome-keyring.h */
const GnomeKeyringPasswordSchema *GNOME_KEYRING_NETWORK_PASSWORD = &network_password_schema;

/**
 * GNOME_KEYRING_DEFAULT:
 * 
 * <para>
 * The default keyring.
 * </para>
 */

/**
 * GNOME_KEYRING_SESSION:
 * 
 * <para>
 * A keyring only stored in memory.
 * </para>
 */

static GnomeKeyringAttributeList*
schema_attribute_list_va (const GnomeKeyringPasswordSchema *schema, va_list args)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttributeType type;
	GnomeKeyringAttribute attribute;
	gboolean type_found;
	char *str;
	guint32 i, val;
	
	attributes = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));
	
	while ((attribute.name = va_arg (args, char *)) != NULL) {
		
		type_found = FALSE;
		for (i = 0; i < G_N_ELEMENTS (schema->attributes); ++i) {
			if (!schema->attributes[i].name)
				break;
			if (strcmp (schema->attributes[i].name, attribute.name) == 0) {
				type_found = TRUE;
				type = schema->attributes[i].type;
				break;
			}
		}
		
		if (!type_found) {
			g_warning ("The password attribute '%s' was not found in the password schema.", attribute.name);
			g_array_free (attributes, TRUE);
			return NULL;
		}
		
		attribute.type = type;
		switch (type) {
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
			g_warning ("The password attribute '%s' has an invalid type in the password schema.", attribute.name);
			g_array_free (attributes, TRUE);
			return NULL;
		}
	}
	
	return attributes;
}

/**
 * gnome_keyring_store_password:
 * @schema: The password schema.
 * @keyring: The keyring to store the password in. Specify %NULL for the default keyring. 
 *           Use %GNOME_KEYRING_SESSION to store the password in memory only.
 * @display_name: A human readable description of what the password is for.
 * @password: The password to store.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null 
 *       terminated string, followed by b) attribute value, either a character string, 
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL. 
 * 
 * Store a password associated with a given set of attributes.
 * 
 * Attributes which identify this password must be passed as additional 
 * arguments. Attributes passed must be defined in the schema.
 *
 * If a password exists in the keyring that already has all the same arguments,
 * then the password will be updated. 
 * 
 * Another more complex way to create a keyring item is using gnome_keyring_item_create().
 *   
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 * Since: 2.22
 */
gpointer
gnome_keyring_store_password (const GnomeKeyringPasswordSchema* schema, const gchar *keyring,  
                              const gchar *display_name, const gchar *password, 
                              GnomeKeyringOperationDoneCallback callback,
                              gpointer data, GDestroyNotify destroy_data, ...)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringOperation *op;
	va_list args;
	
	va_start (args, destroy_data);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);
	
	op = create_operation (FALSE, callback, CALLBACK_DONE, data, destroy_data);
	
	/* Automatically secures buffer */
	if (!attributes || !attributes->len ||
	    !gkr_proto_encode_create_item (&op->send_buffer, keyring, display_name,
	                                   attributes, password, schema->item_type, TRUE))
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	op->reply_handler = standard_reply;
	g_array_free (attributes, TRUE);
	start_operation (op);
	return op;
}

/**
 * gnome_keyring_store_password_sync:
 * @schema: The password schema.
 * @keyring: The keyring to store the password in. Specify %NULL for the default keyring. 
 *           Use %GNOME_KEYRING_SESSION to store the password in memory only.
 * @display_name: A human readable description of what the password is for.
 * @password: The password to store.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null 
 *       terminated string, followed by b) attribute value, either a character string, 
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL. 
 * 
 * Store a password associated with a given set of attributes.
 * 
 * Attributes which identify this password must be passed as additional 
 * arguments. Attributes passed must be defined in the schema.
 * 
 * This function may block for an unspecified period. If your application must
 * remain responsive to the user, then use gnome_keyring_store_password(). 
 *
 * If a password exists in the keyring that already has all the same arguments,
 * then the password will be updated. 
 * 
 * Another more complex way to create a keyring item is using 
 * gnome_keyring_item_create_sync().
 *   
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 * Since: 2.22
 */
GnomeKeyringResult
gnome_keyring_store_password_sync (const GnomeKeyringPasswordSchema* schema, const gchar *keyring,  
                                   const gchar *display_name, const gchar *password, ...)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult res;
	guint32 item_id;
	va_list args;
	
	va_start (args, password);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);
	
	if (!attributes || !attributes->len)
		return GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	
	res = gnome_keyring_item_create_sync (keyring, schema->item_type, display_name, 
	                                      attributes, password, TRUE, &item_id);
	
	g_array_free (attributes, TRUE);
	return res;
}

static gboolean
find_password_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationGetStringCallback callback;
	GList *found_items;
	const gchar *password;

	g_assert (op->user_callback_type == CALLBACK_GET_STRING);
	callback = op->user_callback;
	
	if (!gkr_proto_decode_find_reply (&op->receive_buffer, &result, &found_items)) {
		(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, NULL, op->user_data);
	} else {
		password = NULL;
		if (found_items)
			password = ((GnomeKeyringFound*)(found_items->data))->secret;
		(*callback) (result, password, op->user_data);
		gnome_keyring_found_list_free (found_items);
	}
	
	/* Operation is done */
	return TRUE;
}

/**
 * gnome_keyring_find_password:
 * @schema: The password schema.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null 
 *       terminated string, followed by b) attribute value, either a character string, 
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL. 
 * 
 * Find a password that matches a given set of attributes.
 * 
 * Attributes which identify this password must be passed as additional 
 * arguments. Attributes passed must be defined in the schema.
 * 
 * The string that is passed to @callback is automatically freed when the 
 * function returns.
 * 
 * Another more complex way to find items in the keyrings is using 
 * gnome_keyring_find_items().
 *   
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 * Since: 2.22
 */
gpointer
gnome_keyring_find_password (const GnomeKeyringPasswordSchema* schema,
                             GnomeKeyringOperationGetStringCallback callback,
                             gpointer data, GDestroyNotify destroy_data, ...)
{
	GnomeKeyringOperation *op;
	GnomeKeyringAttributeList *attributes;
	va_list args;
	
	op = create_operation (TRUE, callback, CALLBACK_GET_STRING, data, destroy_data);

	va_start (args, destroy_data);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);
	
	if (!attributes || !attributes->len || 
	    !gkr_proto_encode_find (&op->send_buffer, schema->item_type, attributes)) 
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	g_array_free (attributes, TRUE);

	op->reply_handler = find_password_reply;
	start_operation (op);
	return op;
	
}

/**
 * gnome_keyring_find_password_sync:
 * @schema: The password schema.
 * @password: An address to store password that was found. The password must 
 *            be freed with gnome_keyring_free_password().
 * @...: The variable argument list should contain pairs of a) The attribute name as a null 
 *       terminated string, followed by b) attribute value, either a character string, 
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL. 
 * 
 * Find a password that matches a given set of attributes.
 * 
 * Attributes which identify this password must be passed as additional 
 * arguments. Attributes passed must be defined in the schema.
 * 
 * This function may block for an unspecified period. If your application must
 * remain responsive to the user, then use gnome_keyring_find_password(). 
 *
 * Another more complex way to find items in the keyrings is using 
 * gnome_keyring_find_items_sync().
 *   
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 * Since: 2.22
 */
GnomeKeyringResult
gnome_keyring_find_password_sync(const GnomeKeyringPasswordSchema* schema, gchar **password, ...)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult res;
	GnomeKeyringFound *f;
	GList* found = NULL;
	va_list args;

	va_start (args, password);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);
	
	if (!attributes || !attributes->len)
		res = GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	else
		res = gnome_keyring_find_items_sync (schema->item_type, attributes, &found);
		
	g_array_free (attributes, TRUE);

	if (password && res == GNOME_KEYRING_RESULT_OK) {
		*password = NULL;
		if (g_list_length (found) > 0) {
			f = (GnomeKeyringFound*)(found->data);
			*password = f->secret;
			f->secret = NULL;
		}
	}

	gnome_keyring_found_list_free (found);
	return res;
}

typedef struct _DeletePassword {
	GList *found;
	GList *at;
	guint non_session;
	guint deleted;
} DeletePassword;

static void
delete_password_destroy (gpointer data)
{
	DeletePassword *dp = (DeletePassword*)data;
	gnome_keyring_found_list_free (dp->found);
	g_free (dp);
}

static gboolean
delete_password_reply (GnomeKeyringOperation *op)
{
	GnomeKeyringResult result;
	GnomeKeyringOperationDoneCallback callback;
	GnomeKeyringFound *f;
	DeletePassword *dp;

	g_assert (op->user_callback_type == CALLBACK_DONE);
	callback = op->user_callback;
	
	dp = op->reply_data;
	g_assert (dp);
	
	/* The result of the find */
	if (!dp->found) {
		if (!gkr_proto_decode_find_reply (&op->receive_buffer, &result, &dp->found))
			result = GNOME_KEYRING_RESULT_IO_ERROR;
		
		/* On the first item */
		dp->at = dp->found;
		
	/* The result of a delete */
	} else {
		if (!gkr_proto_decode_find_reply (&op->receive_buffer, &result, &dp->found)) 
			result = GNOME_KEYRING_RESULT_IO_ERROR;

		++dp->deleted;
	}

	/* Stop on any failure */
	if (result != GNOME_KEYRING_RESULT_OK) {
		(*callback) (result, op->user_data);
		return TRUE; /* Operation is done */
	}
			
	/* Iterate over list and find next item to delete */
	while (dp->at) {
		f = (GnomeKeyringFound*)(dp->at->data);
		dp->at = g_list_next (dp->at);
		
		/* If not an item in the session keyring ... */
		if (!f->keyring || strcmp (f->keyring, GNOME_KEYRING_SESSION) != 0) {

			++dp->non_session;
			
			/* ... then we only delete one of those */
			if (dp->non_session > 1)
				continue;
		}

		/* Reset the operation into a delete */
		start_operation (op);
	
		egg_buffer_reset (&op->send_buffer);
		if (!gkr_proto_encode_op_string_int (&op->send_buffer, GNOME_KEYRING_OP_DELETE_ITEM,
                                                     f->keyring, f->item_id)) {
			/*
			 * This would happen if the server somehow sent us an invalid
			 * keyring and item_id. Very unlikely, and it seems this is 
			 * the best error code in this case.
			 */
			(*callback) (GNOME_KEYRING_RESULT_IO_ERROR, op->user_data);
			return TRUE;
		}

		/* 
		 * The delete operation is ready for processing, by returning 
		 * FALSE we indicate that the operation is not complete.
		 */
		return FALSE;
	} 
		
	/* Nothing more to find */
	g_assert (!dp->at);
	
	/* Operation is done */
	(*callback) (dp->deleted > 0 ? GNOME_KEYRING_RESULT_OK : GNOME_KEYRING_RESULT_NO_MATCH, op->user_data);
	return TRUE;
}

/**
 * gnome_keyring_delete_password:
 * @schema: The password schema.
 * @callback: A callback which will be called when the request completes or fails.
 * @data: A pointer to arbitrary data that will be passed to the @callback.
 * @destroy_data: A function to free @data when it's no longer needed.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null 
 *       terminated string, followed by b) attribute value, either a character string, 
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL. 
 * 
 * Delete a password that matches a given set of attributes.
 * 
 * Attributes which identify this password must be passed as additional 
 * arguments. Attributes passed must be defined in the schema.
 * 
 * Another more complex way to find items in the keyrings is using 
 * gnome_keyring_item_delete().
 *   
 * Return value: The asychronous request, which can be passed to gnome_keyring_cancel_request().
 * Since: 2.22
 */
gpointer
gnome_keyring_delete_password (const GnomeKeyringPasswordSchema* schema,
                               GnomeKeyringOperationDoneCallback callback,
                               gpointer data, GDestroyNotify destroy_data, ...)
{
	GnomeKeyringOperation *op;
	GnomeKeyringAttributeList *attributes;
	va_list args;
	
	op = create_operation (TRUE, callback, CALLBACK_DONE, data, destroy_data);

	va_start (args, destroy_data);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);
	if (!attributes || !attributes->len ||
	    !gkr_proto_encode_find (&op->send_buffer, schema->item_type, attributes)) 
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);

	g_array_free (attributes, TRUE);

	op->reply_handler = delete_password_reply;
	op->reply_data = g_new0 (DeletePassword, 1);
	op->destroy_reply_data = delete_password_destroy;

	start_operation (op);
	return op;
}

/**
 * gnome_keyring_delete_password_sync:
 * @schema: The password schema.
 * @...: The variable argument list should contain pairs of a) The attribute name as a null 
 *       terminated string, followed by b) attribute value, either a character string, 
 *       or 32-bit unsigned int, as defined in the password @schema. The list of attribtues
 *       should be terminated with a %NULL. 
 * 
 * Delete a password that matches a given set of attributes.
 * 
 * Attributes which identify this password must be passed as additional 
 * arguments. Attributes passed must be defined in the schema.
 * 
 * This function may block for an unspecified period. If your application must
 * remain responsive to the user, then use gnome_keyring_delete_password(). 
 *
 * Another more complex way to find items in the keyrings is using 
 * gnome_keyring_item_delete_sync().
 *
 * Return value: %GNOME_KEYRING_RESULT_OK if the operation was succcessful or 
 * an error result otherwise. 
 * Since: 2.22
 */
GnomeKeyringResult
gnome_keyring_delete_password_sync (const GnomeKeyringPasswordSchema* schema, ...)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringResult res;
	GnomeKeyringFound *f;
	GList *found, *l;
	va_list args;
	guint non_session;

	va_start (args, schema);
	attributes = schema_attribute_list_va (schema, args);
	va_end (args);
	
	if (!attributes || !attributes->len)
		res = GNOME_KEYRING_RESULT_BAD_ARGUMENTS;

	/* Find the item(s) in question */
	else
		res = gnome_keyring_find_items_sync (schema->item_type, attributes, &found);
		
	g_array_free (attributes, TRUE);
	if (res != GNOME_KEYRING_RESULT_OK)
		return res;

	non_session = 0;
	for (l = found; l; l = g_list_next (l)) {
		f = (GnomeKeyringFound*)(l->data);
		
		/* If not an item in the session keyring ... */
		if (!f->keyring || strcmp (f->keyring, GNOME_KEYRING_SESSION) != 0) {

			++non_session;
			
			/* ... then we only delete one of those */
			if (non_session > 1)
				continue;
		}

		res = gnome_keyring_item_delete_sync (f->keyring, f->item_id);
		if (res != GNOME_KEYRING_RESULT_OK)
			break;
	}
	
	gnome_keyring_found_list_free (found);
	return res;
}
