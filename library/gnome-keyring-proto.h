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
#include "gnome-keyring-opcodes.h"

#include "egg/egg-buffer.h"

/* request:
   uint32 package size
   uint32 operation
   ... op data

   reply:
   uint32 reply size
   uint32 result
*/

void     gkr_proto_go_secure                         (EggBuffer *buffer);

/* Core buffer ops */
gboolean gkr_proto_get_bytes                         (EggBuffer                  *buffer,
                                                      gsize                       offset,
                                                      gsize                      *next_offset,
                                                      guchar                     *out,
                                                      gsize                       n_bytes);
void     gkr_proto_add_time                          (EggBuffer                  *buffer,
                                                      time_t                      val);
gboolean gkr_proto_get_time                          (EggBuffer                  *buffer,
                                                      gsize                       offset,
                                                      gsize                      *next_offset,
                                                      time_t                     *time);
gboolean gkr_proto_add_utf8_string                   (EggBuffer                  *buffer,
                                                      const char                 *str);
gboolean gkr_proto_add_utf8_secret                   (EggBuffer                  *buffer,
                                                      const char                 *str);
gboolean gkr_proto_get_utf8_full                     (EggBuffer                  *buffer,
                                                      gsize                       offset,
                                                      gsize                      *next_offset,
                                                      char                      **str_ret, 
                                                      EggBufferAllocator          allocator);
gboolean gkr_proto_get_utf8_string                   (EggBuffer                  *buffer,
                                                      gsize                       offset,
                                                      gsize                      *next_offset,
                                                      char                      **str_ret);
gboolean gkr_proto_get_utf8_secret                   (EggBuffer                  *buffer,
                                                      gsize                       offset,
                                                      gsize                      *next_offset,
                                                      char                      **str_ret);
gboolean gkr_proto_get_raw_secret                    (EggBuffer                  *buffer, 
                                                      gsize                       offset, 
                                                      gsize                      *next_offset,
                                                      guchar                    **secret, 
                                                      gsize                      *n_secret);
gboolean gkr_proto_add_attribute_list                (EggBuffer                  *buffer,
                                                      GnomeKeyringAttributeList  *attributes);
gboolean gkr_proto_add_acl                           (EggBuffer                  *buffer,
                                                      GList                      *acl);


/* marshallers */
gboolean gkr_proto_encode_op_only                    (EggBuffer                 *buffer,
                                                      GnomeKeyringOpCode         op);
gboolean gkr_proto_encode_op_string                  (EggBuffer                 *buffer,
                                                      GnomeKeyringOpCode         op,
                                                      const char                *str);
gboolean gkr_proto_encode_op_string_int              (EggBuffer                 *buffer,
                                                      GnomeKeyringOpCode         op,
                                                      const char                *str,
                                                      guint32                    integer);
gboolean gkr_proto_encode_op_string_int_int          (EggBuffer                 *buffer,
                                                      GnomeKeyringOpCode         op,
                                                      const char                *str,
                                                      guint32                    integer1,
                                                      guint32                    integer2);
gboolean gkr_proto_encode_op_string_secret           (EggBuffer                 *buffer,
                                                      GnomeKeyringOpCode         op,
                                                      const char                *str1,
                                                      const char                *str2);
gboolean gkr_proto_encode_op_string_secret_secret    (EggBuffer                 *buffer,
                                                      GnomeKeyringOpCode         op,
                                                      const char                *str1,
                                                      const char                *str2,
                                                      const char                *str3);
gboolean gkr_proto_encode_find                       (EggBuffer                 *buffer,
                                                      GnomeKeyringItemType       type,
                                                      GnomeKeyringAttributeList *attributes);
gboolean gkr_proto_encode_create_item                (EggBuffer                 *buffer,
                                                      const char                *keyring,
                                                      const char                *display_name,
                                                      GnomeKeyringAttributeList *attributes,
                                                      const char                *secret,
                                                      GnomeKeyringItemType       type,
                                                      gboolean                   update_if_exists);
gboolean gkr_proto_encode_set_attributes             (EggBuffer                 *buffer,
                                                      const char                *keyring,
                                                      guint32                    id,
                                                      GnomeKeyringAttributeList *attributes);
gboolean gkr_proto_encode_set_acl                    (EggBuffer                 *buffer,
                                                      const char                *keyring,
                                                      guint32                    id,
                                                      GList 			*acl);
gboolean gkr_proto_encode_set_item_info              (EggBuffer                 *buffer,
                                                      const char                *keyring,
                                                      guint32                    id,
                                                      GnomeKeyringItemInfo      *info);
gboolean gkr_proto_encode_set_keyring_info           (EggBuffer                 *buffer,
                                                      const char                *keyring,
                                                      GnomeKeyringInfo          *info);
gboolean gkr_proto_encode_prepare_environment        (EggBuffer                 *buffer, 
                                                      const gchar              **environment);


/* demarshallers */
gboolean gkr_proto_decode_packet_operation           (EggBuffer                  *buffer,
                                                      GnomeKeyringOpCode         *op);
gboolean gkr_proto_decode_packet_size                (EggBuffer                  *buffer,
                                                      guint32                    *size);
gboolean gkr_proto_decode_attribute_list             (EggBuffer                  *buffer,
                                                      gsize                       offset,
                                                      gsize                      *next_offset,
                                                      GnomeKeyringAttributeList **attributes_out);
gboolean gkr_proto_decode_acl                        (EggBuffer                  *buffer,
                                                      gsize                       offset,
                                                      gsize                      *next_offset,
                                                      GList                     **attributes_out);
gboolean gkr_proto_decode_result_reply               (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result);
gboolean gkr_proto_decode_result_string_reply        (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result,
                                                      char                      **str);
gboolean gkr_proto_decode_result_string_list_reply   (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result,
                                                      GList                     **list);
gboolean gkr_proto_decode_op_string                  (EggBuffer                  *buffer,
                                                      GnomeKeyringOpCode         *op_out,
                                                      char                      **str_out);
gboolean gkr_proto_decode_op_string_secret           (EggBuffer                  *buffer,
                                                      GnomeKeyringOpCode         *op_out,
                                                      char                      **str1_out,
                                                      char                      **str2_out);
gboolean gkr_proto_decode_op_string_secret_secret    (EggBuffer                  *buffer,
                                                      GnomeKeyringOpCode         *op_out,
                                                      char                      **str1_out,
                                                      char                      **str2_out,
                                                      char                      **str3_out);
gboolean gkr_proto_decode_op_string_int              (EggBuffer                  *buffer,
                                                      GnomeKeyringOpCode         *op_out,
                                                      char                      **str1,
                                                      guint32                    *val);
gboolean gkr_proto_decode_get_item_info	             (EggBuffer                  *buffer,
                                                      GnomeKeyringOpCode         *op_out,
                                                      char                      **keyring,
                                                      guint32                    *item_id,
                                                      guint32                    *flags);
gboolean gkr_proto_decode_find                       (EggBuffer                  *buffer,
                                                      GnomeKeyringItemType       *type,
                                                      GnomeKeyringAttributeList **attributes);
gboolean gkr_proto_decode_find_reply                 (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result,
                                                      GList                     **list_out);
gboolean gkr_proto_decode_get_attributes_reply       (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result,
                                                      GnomeKeyringAttributeList **attributes);
gboolean gkr_proto_decode_get_acl_reply              (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result,
                                                      GList                     **acl);
gboolean gkr_proto_decode_get_item_info_reply        (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result,
                                                      GnomeKeyringItemInfo      **info);
gboolean gkr_proto_decode_get_keyring_info_reply     (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result,
                                                      GnomeKeyringInfo          **info);
gboolean gkr_proto_decode_result_int_list_reply      (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result,
                                                      GList                     **list);
gboolean gkr_proto_decode_result_integer_reply       (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *result,
                                                      guint32                    *integer);
gboolean gkr_proto_decode_create_item                (EggBuffer                  *packet,
                                                      char                      **keyring,
                                                      char                      **display_name,
                                                      GnomeKeyringAttributeList **attributes,
                                                      char                      **secret,
                                                      GnomeKeyringItemType       *type_out,
                                                      gboolean                   *update_if_exists);
gboolean gkr_proto_decode_set_item_info              (EggBuffer                  *buffer,
                                                      char                      **keyring,
                                                      guint32                    *item_id,
                                                      GnomeKeyringItemType       *type,
                                                      char                      **display_name,
                                                      char                      **secret);
gboolean gkr_proto_decode_set_keyring_info           (EggBuffer                  *buffer,
                                                      char                      **keyring,
                                                      gboolean                   *lock_on_idle,
                                                      guint32                    *lock_timeout);
gboolean gkr_proto_decode_set_attributes             (EggBuffer                  *buffer,
                                                      char                      **keyring,
                                                      guint32                    *item_id,
                                                      GnomeKeyringAttributeList **attributes);
gboolean gkr_proto_decode_set_acl                    (EggBuffer                  *buffer,
                                                      char                      **keyring,
                                                      guint32                    *item_id,
                                                      GList                     **acl);
gboolean gkr_proto_decode_prepare_environment        (EggBuffer                  *buffer, 
                                                      char                     ***environment);
gboolean gkr_proto_decode_prepare_environment_reply  (EggBuffer                  *buffer,
                                                      GnomeKeyringResult         *res,
                                                      char                     ***environment);
   
#endif /* GNOME_KEYRING_PROTO_H */
