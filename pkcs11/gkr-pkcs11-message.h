/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkcs11-message.h - our marshalled PKCS#11 protocol.

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

#include "pkcs11.h"

#ifndef GKR_PKCS11_MESSAGE_H
#define GKR_PKCS11_MESSAGE_H

/* This needs to be defined elsewhere in the module/daemon */
void gkr_pkcs11_warn (const char* format, ...);

typedef enum _GkrPkcs11MessageType {
	GKR_PKCS11_REQUEST = 1,
	GKR_PKCS11_RESPONSE
} GkrPkcs11MessageType;

typedef struct _GkrPkcs11Message {
	int call_id;
	GkrPkcs11MessageType call_type;
	const char *signature;
	GkrBuffer buffer;

	size_t parsed;
	const char *sigverify;
} GkrPkcs11Message;

#define gkr_pkcs11_message_is_verified(msg) \
	((msg)->sigverify[0] == 0)

#define gkr_pkcs11_message_buffer_error(msg) \
	(gkr_buffer_has_error(&(msg)->buffer))

GkrPkcs11Message*        gkr_pkcs11_message_new                   (GkrBufferAllocator allocator);

void                     gkr_pkcs11_message_free                  (GkrPkcs11Message *msg);

void                     gkr_pkcs11_message_reset                 (GkrPkcs11Message *msg);

int                      gkr_pkcs11_message_equals                (GkrPkcs11Message *m1, 
                                                                   GkrPkcs11Message *m2);

CK_RV                    gkr_pkcs11_message_prep                  (GkrPkcs11Message *msg, 
                                                                   int call_id, 
                                                                   GkrPkcs11MessageType type);

CK_RV                    gkr_pkcs11_message_parse                 (GkrPkcs11Message *msg, 
                                                                   GkrPkcs11MessageType type);

int                      gkr_pkcs11_message_verify_part           (GkrPkcs11Message *msg, 
                                                                   const char* part);

CK_RV                    gkr_pkcs11_message_write_attribute_array (GkrPkcs11Message *msg, 
                                                                   CK_ATTRIBUTE_PTR arr, 
                                                                   CK_ULONG num);

CK_RV                    gkr_pkcs11_message_read_boolean          (GkrPkcs11Message *msg,
                                                                   CK_BBOOL *val);

CK_RV                    gkr_pkcs11_message_write_boolean         (GkrPkcs11Message *msg,
                                                                   CK_BBOOL val);

CK_RV                    gkr_pkcs11_message_write_byte_array      (GkrPkcs11Message *msg, 
                                                                   CK_BYTE_PTR arr, 
                                                                   CK_ULONG num);

CK_RV                    gkr_pkcs11_message_read_uint32           (GkrPkcs11Message *msg, 
                                                                   CK_ULONG *val);

CK_RV                    gkr_pkcs11_message_write_uint32          (GkrPkcs11Message *msg, 
                                                                   CK_ULONG val);

#endif /* GKR_PKCS11_MESSAGE_H */
