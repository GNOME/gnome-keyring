/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-proto.h - helper code for the keyring daemon protocol

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
#ifndef GNOME_KEYRING_PROTO_H
#define GNOME_KEYRING_PROTO_H

#include <stdarg.h>
#include "gnome-keyring.h"

typedef enum {
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

	/* Add new ops here */
	
	GNOME_KEYRING_NUM_OPS
} GnomeKeyringOpCode;

/* request:
   uint32 package size
   uint32 operation
   ... op data

   reply:
   uint32 reply size
   uint32 result
*/

/* Core buffer ops */
void     gnome_keyring_proto_add_uint32         (GString                    *buffer,
						 guint32                     val);
gboolean gnome_keyring_proto_set_uint32         (GString                    *buffer,
						 gsize                       offset,
						 guint32                     val);
gboolean gnome_keyring_proto_get_uint32         (GString                    *buffer,
						 gsize                       offset,
						 gsize                      *next_offset,
						 guint32                    *val);
void     gnome_keyring_proto_add_time           (GString                    *buffer,
						 time_t                      val);
gboolean gnome_keyring_proto_get_time           (GString                    *buffer,
						 gsize                       offset,
						 gsize                      *next_offset,
						 time_t                     *time);
gboolean gnome_keyring_proto_add_utf8_string    (GString                    *buffer,
						 const char                 *str);
gboolean gnome_keyring_proto_get_utf8_string    (GString                    *buffer,
						 gsize                       offset,
						 gsize                      *next_offset,
						 char                      **str_ret);
gboolean gnome_keyring_proto_add_attribute_list (GString                    *buffer,
						 GnomeKeyringAttributeList  *attributes);


/* marshallers */
gboolean gnome_keyring_proto_encode_op_only          (GString                   *buffer,
						      GnomeKeyringOpCode         op);
gboolean gnome_keyring_proto_encode_op_string        (GString                   *buffer,
						      GnomeKeyringOpCode         op,
						      const char                *str);
gboolean gnome_keyring_proto_encode_op_string_int    (GString                   *buffer,
						      GnomeKeyringOpCode         op,
						      const char                *str,
						      guint32                    integer);
gboolean gnome_keyring_proto_encode_op_string_string (GString                   *buffer,
						      GnomeKeyringOpCode         op,
						      const char                *str1,
						      const char                *str2);
gboolean gnome_keyring_proto_encode_find             (GString                   *buffer,
						      GnomeKeyringItemType       type,
						      GnomeKeyringAttributeList *attributes);
gboolean gnome_keyring_proto_encode_create_item      (GString                   *buffer,
						      const char                *keyring,
						      const char                *display_name,
						      GnomeKeyringAttributeList *attributes,
						      const char                *secret,
						      GnomeKeyringItemType       type);
gboolean gnome_keyring_proto_encode_set_attributes   (GString                   *buffer,
						      const char                *keyring,
						      guint32                    id,
						      GnomeKeyringAttributeList *attributes);
gboolean gnome_keyring_proto_encode_set_item_info    (GString                   *buffer,
						      const char                *keyring,
						      guint32                    id,
						      GnomeKeyringItemInfo      *info);
gboolean gnome_keyring_proto_encode_set_keyring_info (GString                   *buffer,
						      const char                *keyring,
						      GnomeKeyringInfo          *info);


/* demarshallers */
gboolean gnome_keyring_proto_decode_packet_operation         (GString                    *buffer,
							      GnomeKeyringOpCode         *op);
gboolean gnome_keyring_proto_decode_packet_size              (GString                    *buffer,
							      guint32                    *size);
gboolean gnome_keyring_proto_decode_attribute_list (GString *buffer,
						    gsize offset,
						    gsize *next_offset,
						    GnomeKeyringAttributeList **attributes_out);
gboolean gnome_keyring_proto_decode_result_reply             (GString                    *buffer,
							      GnomeKeyringResult         *result);
gboolean gnome_keyring_proto_decode_result_string_reply      (GString                    *buffer,
							      GnomeKeyringResult         *result,
							      char                      **str);
gboolean gnome_keyring_proto_decode_result_string_list_reply (GString                    *buffer,
							      GnomeKeyringResult         *result,
							      GList                     **list);
gboolean gnome_keyring_proto_decode_op_string (GString *buffer,
					       GnomeKeyringOpCode *op_out,
					       char **str_out);
gboolean gnome_keyring_proto_decode_op_string_string (GString *buffer,
						      GnomeKeyringOpCode *op_out,
						      char **str1_out,
						      char **str2_out);
gboolean gnome_keyring_proto_decode_op_string_int (GString *buffer,
						   GnomeKeyringOpCode *op_out,
						   char **str1,
						   guint32 *val);
gboolean gnome_keyring_proto_decode_find                     (GString                    *buffer,
							      GnomeKeyringItemType       *type,
							      GnomeKeyringAttributeList **attributes);
gboolean gnome_keyring_proto_decode_find_reply               (GString                    *buffer,
							      GnomeKeyringResult         *result,
							      GList                     **list_out);
gboolean gnome_keyring_proto_decode_get_attributes_reply     (GString                    *buffer,
							      GnomeKeyringResult         *result,
							      GnomeKeyringAttributeList **attributes);
gboolean gnome_keyring_proto_decode_get_item_info_reply      (GString                    *buffer,
							      GnomeKeyringResult         *result,
							      GnomeKeyringItemInfo      **info);
gboolean gnome_keyring_proto_decode_get_keyring_info_reply   (GString                    *buffer,
							      GnomeKeyringResult         *result,
							      GnomeKeyringInfo          **info);
gboolean gnome_keyring_proto_decode_result_int_list_reply    (GString                    *buffer,
							      GnomeKeyringResult         *result,
							      GList                     **list);
gboolean gnome_keyring_proto_decode_result_integer_reply     (GString                    *buffer,
							      GnomeKeyringResult         *result,
							      guint32                    *integer);
gboolean gnome_keyring_proto_decode_create_item (GString *packet,
						 char **keyring,
						 char **display_name,
						 GnomeKeyringAttributeList **attributes,
						 char **secret,
						 GnomeKeyringItemType *type_out);



   
#endif /* GNOME_KEYRING_PROTO_H */
