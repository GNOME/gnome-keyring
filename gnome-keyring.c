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
#include <sys/types.h>
#include <sys/socket.h>
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

static int
connect_to_daemon (void)
{
	const char *socket_file;
	struct sockaddr_un addr;
	int sock;
	int val;

	socket_file = g_getenv ("GNOME_KEYCHAIN_SOCKET");
	
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
	
	if (fcntl (sock, F_SETFL, val | O_NONBLOCK) < 0) {
		close (sock);
		return -1;
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

static void
write_credentials_byte (GnomeKeyringOperation *op)
{
  char buf;
  int bytes_written;

 again:

  buf = 0;
  bytes_written = write (op->socket, &buf, 1);

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
	gsize packet_size;

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
		
			g_assert (op->receive_pos < packet_size);
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
	
	op->socket = connect_to_daemon ();

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
		g_list_foreach (found_items, (GFunc) gnome_keyring_found_free, NULL);
		g_list_free (found_items);
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
	char *str;
	guint32 val;
	GnomeKeyringAttribute attribute;
	
	op = start_operation (callback, CALLBACK_GET_LIST, data, destroy_data);
	if (op->state == STATE_FAILED) {
		return op;
	}

	attributes = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));
	
	va_start (args, destroy_data);
	while ((attribute.name = va_arg (args, char *)) != NULL) {
		attribute.type = va_arg (args, GnomeKeyringAttributeType);
		
		switch (attribute.type) {
		case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
			str = va_arg (args, char *);
			if (str != NULL) {
				attribute.value.string = str;
				g_array_append_val (attributes, attribute);
			}
			break;
		case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
			val = va_arg (args, guint32);
			if (val != 0) {
				attribute.value.integer = val;
				g_array_append_val (attributes, attribute);
			}
			break;
		default:
			schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
			g_array_free (attributes, TRUE);
			return op;
		}
	}

	va_end (args);
	
	if (!gnome_keyring_proto_encode_find (op->send_buffer,
					      type,
					      attributes))  {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	g_array_free (attributes, TRUE);

	op->reply_handler = gnome_keyring_find_items_reply;
	return op;
}

gpointer
gnome_keyring_item_create (const char                          *keyring,
			   GnomeKeyringItemType                 type,
			   const char                          *display_name,
			   GnomeKeyringAttributeList           *attributes,
			   const char                          *secret,
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
						     type)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}

	op->reply_handler = gnome_keyring_int_reply;
	
	return op;
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
						       GNOME_KEYRING_OP_GET_KEYRING_INFO,
						       keyring, id)) {
		schedule_op_failed (op, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
	}
	
	op->reply_handler = gnome_keyring_standard_reply;
	
	return op;
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






































#if 0

GnomeKeyringResult
gnome_keyring_find_internet_password (char *user,
				      char *domain,
				      char *server,
				      char *path,
				      char *protocol,
				      char *authtype,
				      guint32 port,
				      GList **result_list_out)
{
	GnomeKeyringInternetPasswordData *data;
	GnomeKeyringResult result;
	GnomeKeyringFin *find;
	GList *find_list;
	GList *result_list;
	GList *l;
	int i;

	result = gnome_keyring_find (&find_list,
				     GNOME_KEYRING_ITEM_INTERNET_PASSWORD,
				     "user", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, user,
				     "domain", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, domain,
				     "server", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, server,
				     "path", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, path,
				     "protocol", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, protocol,
				     "auth", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, authtype,
				     "port", GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32, port,
				     NULL);
	if (result != GNOME_KEYRING_RESULT_OK) {
		return result;
	}

	result_list = NULL;
	for (l = find_list; l != NULL; l = l->next) {
		find = l->data;
		
		data = g_new0 (GnomeKeyringInternetPasswordData, 1);

		result_list = g_list_prepend (result_list, data);
		data->secret = g_strdup (find->secret);
		for (i = 0; i < find->num_attributes; i++) {
			if (strcmp (find->attributes[i].name, "user") == 0 &&
			    find->attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->user = g_strdup (find->attributes[i].value.string);
			} else if (strcmp (find->attributes[i].name, "domain") == 0 &&
			    find->attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->domain = g_strdup (find->attributes[i].value.string);
			} else if (strcmp (find->attributes[i].name, "server") == 0 &&
			    find->attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->server = g_strdup (find->attributes[i].value.string);
			} else if (strcmp (find->attributes[i].name, "path") == 0 &&
			    find->attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->path = g_strdup (find->attributes[i].value.string);
			} else if (strcmp (find->attributes[i].name, "protocol") == 0 &&
			    find->attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->protocol = g_strdup (find->attributes[i].value.string);
			} else if (strcmp (find->attributes[i].name, "auth") == 0 &&
			    find->attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				data->authtype = g_strdup (find->attributes[i].value.string);
			} else if (strcmp (find->attributes[i].name, "port") == 0 &&
			    find->attributes[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32) {
				data->port = find->attributes[i].value.integer;
			} 
		}
	}
	*result_list_out = g_list_reverse (result_list);
	return GNOME_KEYRING_RESULT_OK;
}



GnomeKeyringResult
gnome_keyring_find_internet_password_async (char *user,
					    char *domain,
					    char *server,
					    char *path,
					    char *protocol,
					    char *authtype,
					    guint32 port,
					    GnomeKeyringFindInternetPasswordCallback callback);


GnomeKeyringResult
gnome_keyring_set_internet_password (char *user,
				     char *domain,
				     char *server,
				     char *path,
				     char *protocol,
				     char *authtype,
				     guint32 port,
				     char *password);


#endif
