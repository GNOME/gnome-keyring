/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-cryptoki-message.c - our marshalled cryptoki protocol.

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

#include "config.h"

#include "gkr-cryptoki-message.h"
#include "gkr-cryptoki-calls.h"

#include <string.h>

#ifndef ASSERT
#  ifdef _DEBUG
#    include <assert.h>
#    define ASSERT(x) assert(x)
#  else
#    define ASSERT(x)
#  endif 
#endif

GkrCryptokiMessage*
gkr_cryptoki_message_new (GkrBufferAllocator allocator)
{
	GkrCryptokiMessage *msg;
	
	ASSERT (allocator);
	
	msg = (GkrCryptokiMessage*) (allocator)(NULL, sizeof (GkrCryptokiMessage));
	if (!msg)
		return NULL;
	memset (msg, 0, sizeof (*msg));
	
	if (!gkr_buffer_init_full (&msg->buffer, 64, allocator)) {
		(allocator) (msg, 0); /* Frees allocation */
		return NULL;
	}
	
	gkr_cryptoki_message_reset (msg);
	
	return msg;
}

void 
gkr_cryptoki_message_free (GkrCryptokiMessage *msg)
{
	GkrBufferAllocator allocator;
	
	if (msg) {
		ASSERT (msg->buffer.allocator);
		allocator = msg->buffer.allocator; 
		gkr_buffer_uninit (&msg->buffer);
		
		/* frees data buffer */
		(allocator) (msg, 0);
	}
}

void 
gkr_cryptoki_message_reset (GkrCryptokiMessage *msg)
{
	ASSERT (msg);
	
	msg->call_id = 0;
	msg->call_type = 0;
	msg->signature = NULL;
	msg->sigverify = NULL;
	msg->parsed = 0;
	
	gkr_buffer_reset (&msg->buffer);
}

CK_RV
gkr_cryptoki_message_prep (GkrCryptokiMessage *msg, int call_id, 
                                GkrCryptokiMessageType type)
{
	int len;

	ASSERT (type);
	ASSERT (call_id >= CRYPTOKI_CALL_ERROR);
	ASSERT (call_id < CRYPTOKI_CALL_MAX);
	
	gkr_cryptoki_message_reset (msg);

	if (call_id != CRYPTOKI_CALL_ERROR) {

		/* The call id and signature */
		if (type == GKR_CRYPTOKI_REQUEST) 
			msg->signature = gkr_cryptoki_calls[call_id].request;
		else if (type == GKR_CRYPTOKI_RESPONSE)
			msg->signature = gkr_cryptoki_calls[call_id].response;
		else
			ASSERT (0 && "invalid message type");
		msg->sigverify = msg->signature;
	}
	
	msg->call_id = call_id;
	msg->call_type = type;

	/* Encode the two of them */
	gkr_buffer_add_uint32 (&msg->buffer, call_id);
	if (msg->signature) {
		len = strlen (msg->signature);
		gkr_buffer_add_byte_array (&msg->buffer, (unsigned char*)msg->signature, len);
	}

	msg->parsed = 0;
	return gkr_buffer_has_error (&msg->buffer) ? CKR_HOST_MEMORY : CKR_OK;
}

CK_RV 
gkr_cryptoki_message_parse (GkrCryptokiMessage *msg, 
                                 GkrCryptokiMessageType type)
{
	const unsigned char *val;
	size_t len;
	uint32_t call_id;

	msg->parsed = 0;

	/* Pull out the call identifier */
	if (!gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, &(msg->parsed), &call_id)) {
		gkr_cryptoki_warn ("invalid message: couldn't read call identifier");
		return CKR_DEVICE_ERROR;
	}

	msg->signature = msg->sigverify = NULL;

	/* If it's an error code then no more processing */
	if (call_id == CRYPTOKI_CALL_ERROR) {
		if (type == GKR_CRYPTOKI_REQUEST) {
			gkr_cryptoki_warn ("invalid message: error code in request");
			return CKR_DEVICE_ERROR;
		}
		return CKR_OK;
	}

	/* The call id and signature */
	if (call_id <= 0 || call_id >= CRYPTOKI_CALL_MAX) {
		gkr_cryptoki_warn ("invalid message: bad call id: %d", call_id);
		return CKR_DEVICE_ERROR;
	}
	if (type == GKR_CRYPTOKI_REQUEST) 
		msg->signature = gkr_cryptoki_calls[call_id].request;
	else if (type == GKR_CRYPTOKI_RESPONSE)
		msg->signature = gkr_cryptoki_calls[call_id].response;
	else
		ASSERT (0 && "invalid message type");
	msg->call_id = call_id;
	msg->call_type = type;
	msg->sigverify = msg->signature;

	/* Verify the incoming signature */
	if (!gkr_buffer_get_byte_array (&msg->buffer, msg->parsed, &(msg->parsed), &val, &len)) {
		gkr_cryptoki_warn ("invalid message: couldn't read signature");
		return CKR_DEVICE_ERROR;
	}
	
	if ((strlen (msg->signature) != len) || (memcmp (val, msg->signature, len) != 0)) {
		gkr_cryptoki_warn ("invalid message: signature doesn't match");
		return CKR_DEVICE_ERROR;
	}
	
	return CKR_OK;
}

int
gkr_cryptoki_message_equals (GkrCryptokiMessage *m1, GkrCryptokiMessage *m2)
{
	ASSERT (m1 && m2);
	
	/* Any errors and messages are never equal */
	if (gkr_buffer_has_error (&m1->buffer) || 
	    gkr_buffer_has_error (&m2->buffer))
		return 0;

	/* Calls and signatures must be identical */	
	if (m1->call_id != m2->call_id)
		return 0;
	if (m1->call_type != m2->call_type)
		return 0;
	if (m1->signature && m2->signature) {
		if (strcmp (m1->signature, m2->signature) != 0)
			return 0;
	} else if (m1->signature != m2->signature) {
		return 0;
	}
		
	/* Data in buffer must be identical */
	return gkr_buffer_equal (&m1->buffer, &m2->buffer);
}

int 
gkr_cryptoki_message_verify_part (GkrCryptokiMessage *msg, const char* part)
{
	int len, ok;
	
	if (!msg->sigverify)
		return 1;

	len = strlen (part);
	ok = (strncmp (msg->sigverify, part, len) == 0);
	if (ok)
		msg->sigverify += len;
	return ok;
}

CK_RV
gkr_cryptoki_message_write_attribute_array (GkrCryptokiMessage *msg, 
                                                 CK_ATTRIBUTE_PTR arr, CK_ULONG num)
{
	CK_ULONG i;
	CK_ATTRIBUTE_PTR attr;
	unsigned char validity;

	ASSERT (arr);
	ASSERT (msg);

	/* Make sure this is in the rigth order */
	ASSERT (!msg->signature || gkr_cryptoki_message_verify_part (msg, "aA"));
	
	/* Write the number of items */
	gkr_buffer_add_uint32 (&msg->buffer, num);
	
	for (i = 0; i < num; ++i) {
		attr = &(arr[i]);

		/* The attribute type */
		gkr_buffer_add_uint32 (&msg->buffer, attr->type);

		/* Write out the attribute validity */
		validity = (((CK_LONG)attr->ulValueLen) == -1) ? 0 : 1;
		gkr_buffer_add_byte (&msg->buffer, validity);

		/* The attribute value */
		if (validity)
			gkr_buffer_add_byte_array (&msg->buffer, attr->pValue, attr->ulValueLen);
	}

	return gkr_buffer_has_error (&msg->buffer) ? CKR_HOST_MEMORY : CKR_OK;
}

CK_RV
gkr_cryptoki_message_read_boolean (GkrCryptokiMessage *msg, CK_BBOOL *val)
{
	unsigned char v;
	
	ASSERT (msg);

	/* Make sure this is in the right order */
	ASSERT (!msg->signature || gkr_cryptoki_message_verify_part (msg, "b"));
	
	if (!gkr_buffer_get_byte (&msg->buffer, msg->parsed, &msg->parsed, &v))
		return CKR_GENERAL_ERROR;
	if (val) 
		*val = v ? CK_TRUE : CK_FALSE;
	return CKR_OK;
}

CK_RV
gkr_cryptoki_message_write_boolean (GkrCryptokiMessage *msg, CK_BBOOL val)
{
	unsigned char v;
	ASSERT (msg);

	/* Make sure this is in the right order */
	ASSERT (!msg->signature || gkr_cryptoki_message_verify_part (msg, "b"));
	
	v = CK_TRUE ? 1 : 0;
	if (!gkr_buffer_add_byte (&msg->buffer, v))
		return CKR_HOST_MEMORY;
	
	return CKR_OK;
}

CK_RV
gkr_cryptoki_message_write_byte_array (GkrCryptokiMessage *msg, 
                                            CK_BYTE_PTR arr, CK_ULONG num)
{
	ASSERT (arr);
	ASSERT (msg);

	/* Make sure this is in the right order */
	ASSERT (!msg->signature || gkr_cryptoki_message_verify_part (msg, "ay"));
	
	if (!gkr_buffer_add_byte_array (&msg->buffer, arr, num))
		return CKR_HOST_MEMORY;

	return CKR_OK;
}

CK_RV 
gkr_cryptoki_message_read_uint32 (GkrCryptokiMessage *msg, CK_ULONG *val)
{
	uint32_t v;
	ASSERT (msg);
	
	/* Make sure this is in the right order */
	ASSERT (!msg->signature || gkr_cryptoki_message_verify_part (msg, "u"));

	if (!gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &v))
		return CKR_GENERAL_ERROR;
	if (val)
		*val = v;
	return CKR_OK;
}

CK_RV
gkr_cryptoki_message_write_uint32 (GkrCryptokiMessage *msg, CK_ULONG val)
{
	ASSERT (msg);

	/* Make sure this is in the rigth order */
	ASSERT (!msg->signature || gkr_cryptoki_message_verify_part (msg, "u"));
	
	if (!gkr_buffer_add_uint32 (&msg->buffer, val))
		return CKR_HOST_MEMORY;

	return CKR_OK;
}
