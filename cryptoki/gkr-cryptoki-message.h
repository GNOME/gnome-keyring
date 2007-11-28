/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-cryptoki-message.h - our marshalled cryptoki protocol.

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

#include "common/gkr-buffer.h"

#include "pkcs11/pkcs11.h"

#ifndef GKR_CRYPTOKI_MESSAGE_H
#define GKR_CRYPTOKI_MESSAGE_H

/* This needs to be defined elsewhere in the module/daemon */
void gkr_cryptoki_warn (const char* format, ...);

typedef enum _GkrCryptokiMessageType {
	GKR_CRYPTOKI_REQUEST = 1,
	GKR_CRYPTOKI_RESPONSE
} GkrCryptokiMessageType;

typedef struct _GkrCryptokiMessage {
	int call_id;
	GkrCryptokiMessageType call_type;
	const char *signature;
	GkrBuffer buffer;

	size_t parsed;
	const char *sigverify;
} GkrCryptokiMessage;

#define gkr_cryptoki_message_is_verified(msg) \
	((msg)->sigverify[0] == 0)

#define gkr_cryptoki_message_buffer_error(msg) \
	(gkr_buffer_has_error(&(msg)->buffer))

GkrCryptokiMessage*      gkr_cryptoki_message_new                   (GkrBufferAllocator allocator);

void                     gkr_cryptoki_message_free                  (GkrCryptokiMessage *msg);

void                     gkr_cryptoki_message_reset                 (GkrCryptokiMessage *msg);

int                      gkr_cryptoki_message_equals                (GkrCryptokiMessage *m1, 
                                                                          GkrCryptokiMessage *m2);

CK_RV                    gkr_cryptoki_message_prep                  (GkrCryptokiMessage *msg, 
                                                                          int call_id, 
                                                                          GkrCryptokiMessageType type);

CK_RV                    gkr_cryptoki_message_parse                 (GkrCryptokiMessage *msg, 
                                                                          GkrCryptokiMessageType type);

int                      gkr_cryptoki_message_verify_part           (GkrCryptokiMessage *msg, 
                                                                          const char* part);

CK_RV                    gkr_cryptoki_message_write_attribute_array (GkrCryptokiMessage *msg, 
                                                                          CK_ATTRIBUTE_PTR arr, 
                                                                          CK_ULONG num);

CK_RV                    gkr_cryptoki_message_read_boolean          (GkrCryptokiMessage *msg,
                                                                          CK_BBOOL *val);

CK_RV                    gkr_cryptoki_message_write_boolean         (GkrCryptokiMessage *msg,
                                                                          CK_BBOOL val);

CK_RV                    gkr_cryptoki_message_write_byte_array      (GkrCryptokiMessage *msg, 
                                                                          CK_BYTE_PTR arr, 
                                                                          CK_ULONG num);

CK_RV                    gkr_cryptoki_message_read_uint32           (GkrCryptokiMessage *msg, 
                                                                          CK_ULONG *val);

CK_RV                    gkr_cryptoki_message_write_uint32          (GkrCryptokiMessage *msg, 
                                                                          CK_ULONG val);

#endif /* GKR_CRYPTOKI_PROTO_H */

