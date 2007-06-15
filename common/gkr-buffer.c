/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-buffer.c - helper code for the keyring daemon protocol

   Copyright (C) 2007 Nate Nielsen

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

#include <string.h>
#include <stdarg.h>

#include "gkr-buffer.h"

#define DEFAULT_ALLOCATOR  ((GkrBufferAllocator)realloc)

GkrBuffer*
gkr_buffer_new (size_t reserve)
{
	return gkr_buffer_new_full (reserve, NULL);
}

GkrBuffer*
gkr_buffer_new_full (size_t reserve, GkrBufferAllocator allocator)
{
	GkrBuffer *buffer = calloc (1, sizeof (GkrBuffer));
	if (!buffer)
		return NULL;
		
	if (!allocator) 
		allocator = DEFAULT_ALLOCATOR;

	if (reserve == 0)
		reserve = 64;

	buffer->buf = (allocator) (NULL, reserve);
	if (!buffer->buf) {
		free (buffer);
		return NULL;
	}

	buffer->len = 0;
	buffer->allocated_len = reserve;
	buffer->failures = 0;
	buffer->allocator = allocator;

	return buffer;
}

GkrBuffer*
gkr_buffer_new_static (unsigned char *buf, size_t len)
{
	GkrBuffer *buffer = calloc (1, sizeof (GkrBuffer));
	if (!buffer)
		return NULL;
		
	buffer->buf = buf;
	buffer->len = len;
	buffer->allocated_len = len;
	buffer->failures = 0;
	
	/* A null allocator, and the buffer can't change in size */
	buffer->allocator = NULL;
	
	return buffer;	
}


void 
gkr_buffer_reset (GkrBuffer *buffer)
{
	memset (buffer->buf, 0, buffer->allocated_len);
	buffer->len = 0;
	buffer->failures = 0;
}

void
gkr_buffer_free (GkrBuffer *buffer)
{
	if (!buffer)
		return;

	/* 
	 * Free the memory block using allocator. If no allocator, 
	 * then this memory is ownerd elsewhere and not to be freed. 
	 */
	if (buffer->buf && buffer->allocator)
		(buffer->allocator) (buffer->buf, 0);
	free (buffer);
}

int
gkr_buffer_change_allocator (GkrBuffer *buffer, GkrBufferAllocator allocator)
{
	unsigned char *buf;
	
	if (!allocator)
		allocator = DEFAULT_ALLOCATOR;
	if (buffer->allocator == allocator)
		return 1;
	
	/* Reallocate memory block using new allocator */
	buf = (allocator) (NULL, buffer->allocated_len);
	if (!buf)
		return 0;
		
	/* Copy stuff and free old memory */
	memcpy (buf, buffer->buf, buffer->allocated_len);
	
	/* If old wasn't static, then free it */
	if (buffer->allocator)
		(buffer->allocator) (buffer->buf, 0);
		
	buffer->buf = buf;
	buffer->allocator = allocator;
	
	return 1;
}

int
gkr_buffer_equal (GkrBuffer *b1, GkrBuffer *b2)
{
	if (b1->len != b2->len)
		return 0;
	return memcmp (b1->buf, b2->buf, b1->len) == 0;
}

int
gkr_buffer_reserve (GkrBuffer *buffer, size_t len)
{
	unsigned char *newbuf;
	size_t newlen;

	if (len < buffer->allocated_len)
		return 1;

	/* Calculate a new length, minimize number of buffer allocations */
	newlen = buffer->allocated_len * 2;
	if (len < newlen)
		newlen += len;
	
	/* Memory owned elsewhere can't be reallocated */	
	if (!buffer->allocator) {
		buffer->failures++;
		return 0;
	}

	/* Allocate built in buffer using allocator */
	newbuf = (buffer->allocator) (buffer->buf, newlen);
	if (!newbuf) {
		buffer->failures++;
		return 0;
	}

	memcpy (newbuf, buffer->buf, buffer->len);
	buffer->buf = newbuf;
	buffer->allocated_len = newlen;

	return 1;
}

int
gkr_buffer_resize (GkrBuffer *buffer, size_t len)
{
	if (!gkr_buffer_reserve (buffer, len))
		return 0;
		
	buffer->len = len;
	return 1;
}

int
gkr_buffer_bump (GkrBuffer *buffer, size_t len)
{
	if (!gkr_buffer_reserve (buffer, buffer->len + len))
		return 0;
	
	buffer->len += len;
	return 1;
}

int 
gkr_buffer_append (GkrBuffer *buffer, const unsigned char *val,
                             size_t len)
{
	if (!gkr_buffer_reserve (buffer, buffer->len + len))
		return 0; /* failures already incremented */
	memcpy (buffer->buf + buffer->len, val, len);
	buffer->len += len;
	return 1;
}

int
gkr_buffer_add_byte (GkrBuffer *buffer, unsigned char val)
{
	if (!gkr_buffer_reserve (buffer, buffer->len + 1))
		return 0; /* failures already incremented */
	buffer->buf[buffer->len] = val;
	buffer->len++;
	return 1;
}

int
gkr_buffer_get_byte (GkrBuffer *buffer, size_t offset,
                               size_t *next_offset, unsigned char *val)
{
	unsigned char *ptr;
	if (buffer->len < 1 || offset > buffer->len - 1) {
		buffer->failures++;
		return 0;
	}
	ptr = (unsigned char*)buffer->buf + offset;
	if (val != NULL)
		*val = *ptr;
	if (next_offset != NULL)
		*next_offset = offset + 1;
	return 1;
}

void 
gkr_buffer_encode_uint32 (unsigned char* buf, uint32_t val)
{
	buf[0] = (val >> 24) & 0xff;
	buf[1] = (val >> 16) & 0xff;
	buf[2] = (val >> 8) & 0xff;
	buf[3] = (val >> 0) & 0xff;
}

uint32_t
gkr_buffer_decode_uint32 (unsigned char* ptr)
{
	uint32_t val = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
	return val;
}

int 
gkr_buffer_add_uint32 (GkrBuffer *buffer, uint32_t val)
{
	if (!gkr_buffer_reserve (buffer, buffer->len + 4))
		return 0; /* failures already incremented */
	buffer->len += 4;
	gkr_buffer_set_uint32 (buffer, buffer->len - 4, val);
	return 1;
}

int
gkr_buffer_set_uint32 (GkrBuffer *buffer, size_t offset, uint32_t val)
{
	unsigned char *ptr;
	if (buffer->len < 4 || offset > buffer->len - 4) {
		buffer->failures++;
		return 0;
	}
	ptr = (unsigned char*)buffer->buf + offset;
	gkr_buffer_encode_uint32 (ptr, val);
	return 1;
}

int
gkr_buffer_get_uint32 (GkrBuffer *buffer, size_t offset, size_t *next_offset,
                                 uint32_t *val)
{
	unsigned char *ptr;
	if (buffer->len < 4 || offset > buffer->len - 4) {
		buffer->failures++;
		return 0;
	}
	ptr = (unsigned char*)buffer->buf + offset;
	if (val != NULL)
		*val = gkr_buffer_decode_uint32 (ptr);
	if (next_offset != NULL)
		*next_offset = offset + 4;
	return 1;
}

int
gkr_buffer_add_uint64 (GkrBuffer *buffer, uint64_t val)
{
	if (!gkr_buffer_add_uint32 (buffer, ((val >> 32) & 0xffffffff)))
		return 0;
	return gkr_buffer_add_uint32 (buffer, (val & 0xffffffff));
}

int
gkr_buffer_get_uint64 (GkrBuffer *buffer, size_t offset, 
					   size_t *next_offset, uint64_t *val)
{
	uint32_t a, b;
	if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &a))
		return 0;
	if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &b))
		return 0;
	if (val != NULL)
		*val = ((uint64_t)a) << 32 | b;
	if (next_offset != NULL)
		*next_offset = offset;
	return 1;
}

int
gkr_buffer_add_byte_array (GkrBuffer *buffer, const unsigned char *val,
                                     size_t len)
{
	if (val == NULL) 
		return gkr_buffer_add_uint32 (buffer, 0xffffffff);
	if (len >= 0x7fffffff) {
		buffer->failures++;
		return 0; 
	}
	if (!gkr_buffer_add_uint32 (buffer, len))
		return 0;
	return gkr_buffer_append (buffer, val, len);
}

int
gkr_buffer_get_byte_array (GkrBuffer *buffer, size_t offset,
                                      size_t *next_offset, const unsigned char **val,
                                      size_t *vlen)
{
	uint32_t len;
	if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &len))
		return 0;
	if (len == 0xffffffff) {
		if (next_offset) 
			*next_offset = offset;
		if (val)
			*val = NULL;
		if (vlen)
			*vlen = 0;
		return 1;
	} else if (len >= 0x7fffffff) {
		buffer->failures++;
		return 0;
	}

	if (buffer->len < len || offset > buffer->len - len) {
		buffer->failures++;
		return 0;
	}
	
	if (val) 
		*val = buffer->buf + offset;
	if (vlen)
		*vlen = len;
	if (next_offset) 
		*next_offset = offset + len;

	return 1;
}


