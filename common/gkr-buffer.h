/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-buffer.h - helper code for the keyring daemon protocol

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

#ifndef GKR_BUFFER_H
#define GKR_BUFFER_H

#include <stdlib.h>
#include <stdint.h>

/* -------------------------------------------------------------------
 * GkrBuffer 
 * 
 * IMPORTANT: This is pure vanila standard C, no glib. We need this 
 * because certain consumers of this protocol need to be built 
 * without linking in any special libraries. ie: the PKCS#11 module.
 */
 
/* The allocator for the GkrBuffer. This follows the realloc() syntax and logic */
typedef void* (*GkrBufferAllocator) (void* p, unsigned long len);

typedef struct _GkrBuffer {
	unsigned char *buf;
	size_t len;
	size_t allocated_len;
	int failures; 
	GkrBufferAllocator allocator;
} GkrBuffer;

GkrBuffer*      gkr_buffer_new                  (size_t reserve);

GkrBuffer*      gkr_buffer_new_full             (size_t reserve, 
                                                 GkrBufferAllocator allocator);
                                                 
GkrBuffer*      gkr_buffer_new_static           (unsigned char *buf, 
                                                 size_t len);

void            gkr_buffer_free 		(GkrBuffer *buffer);

int             gkr_buffer_change_allocator     (GkrBuffer *buffer, 
                                                 GkrBufferAllocator allocator);

void 		gkr_buffer_reset		(GkrBuffer *buffer);

int		gkr_buffer_equal		(GkrBuffer *b1,
						 GkrBuffer *b2);

int             gkr_buffer_reserve              (GkrBuffer *buffer,
                                                 size_t len);
						 
int             gkr_buffer_resize               (GkrBuffer *buffer,
                                                 size_t len);

int		gkr_buffer_bump			(GkrBuffer *buffer,
						 size_t len);

int		gkr_buffer_append 		(GkrBuffer *buffer,
						 const unsigned char *val,
						 size_t len);

int 		gkr_buffer_add_byte		(GkrBuffer *buffer,
						 unsigned char val);

int 		gkr_buffer_get_byte		(GkrBuffer *buffer,
						 size_t offset,
						 size_t *next_offset,
						 unsigned char *val);
									 
void 		gkr_buffer_encode_uint32	(unsigned char* buf, 
						 uint32_t val);

uint32_t	gkr_buffer_decode_uint32	(unsigned char* buf);

int 		gkr_buffer_add_uint32		(GkrBuffer *buffer,
						 uint32_t val);

int		gkr_buffer_set_uint32		(GkrBuffer *buffer,
						 size_t offset, 
						 uint32_t val);

int		gkr_buffer_get_uint32		(GkrBuffer *buffer,
						 size_t offset,
						 size_t *next_offset,
						 uint32_t *val);

int		gkr_buffer_add_byte_array	(GkrBuffer *buffer,
						 const unsigned char *val,
						 size_t len);

int		gkr_buffer_get_byte_array	(GkrBuffer *buffer,
						 size_t offset,
						 size_t *next_offset,
						 const unsigned char **val,
						 size_t *vlen);

int		gkr_buffer_add_uint64		(GkrBuffer *buffer,
						 uint64_t val);

int		gkr_buffer_get_uint64		(GkrBuffer *buffer,
						 size_t offset,
						 size_t *next_offset,
						 uint64_t *val);

#define		gkr_buffer_length(b)		((b)->len)

#define 	gkr_buffer_has_error(b)		((b)->failures > 0)

#endif /* GKR_BUFFER_H */

