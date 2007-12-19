/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-buffer.h - helper code for the keyring daemon protocol

   Copyright (C) 2007, Stefan Walter

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

   Author: Stef Walter <stef@memberwebs.com>
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
 * 
 * Memory Allocation
 * 
 * Callers can set their own allocator. If NULL is used then standard 
 * C library heap memory is used and failures will not be fatal. Memory 
 * failures will instead result in a zero return value or 
 * gkr_buffer_has_error() returning one.
 * 
 * If you use something like g_realloc as the allocator, then memory 
 * failures become fatal just like in a standard GTK program.
 * 
 * Don't change the allocator manually in the GkrBuffer structure. The 
 * gkr_buffer_set_allocator() func will reallocate and handle things 
 * properly.
 * 
 * Pointers into the Buffer
 * 
 * Any write operation has the posibility of reallocating memory
 * and invalidating any direct pointers into the buffer.
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

#define 	GKR_BUFFER_EMPTY		{ NULL, 0, 0, 0, NULL }

int             gkr_buffer_init                 (GkrBuffer *buffer, size_t reserve);

int             gkr_buffer_init_full            (GkrBuffer *buffer, 
                                                 size_t reserve, 
                                                 GkrBufferAllocator allocator);
                                                 
void            gkr_buffer_init_static          (GkrBuffer *buffer, 
                                                 unsigned char *buf, 
                                                 size_t len);

void            gkr_buffer_init_allocated       (GkrBuffer *buffer, 
                                                 unsigned char *buf, 
                                                 size_t len,
                                                 GkrBufferAllocator allocator);
                                                 
void            gkr_buffer_uninit               (GkrBuffer *buffer);

int             gkr_buffer_set_allocator        (GkrBuffer *buffer, 
                                                 GkrBufferAllocator allocator);

void 		gkr_buffer_reset		(GkrBuffer *buffer);

int		gkr_buffer_equal		(GkrBuffer *b1,
						 GkrBuffer *b2);

int             gkr_buffer_reserve              (GkrBuffer *buffer,
                                                 size_t len);
						 
int             gkr_buffer_resize               (GkrBuffer *buffer,
                                                 size_t len);

int		gkr_buffer_append 		(GkrBuffer *buffer,
						 const unsigned char *val,
						 size_t len);

int		gkr_buffer_add_empty	        (GkrBuffer *buffer,
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

unsigned char*  gkr_buffer_add_byte_array_empty (GkrBuffer *buffer,
                                                 size_t vlen);						 

int             gkr_buffer_add_string           (GkrBuffer *buffer, 
                                                 const char *str);
                                                 
int             gkr_buffer_get_string           (GkrBuffer *buffer, 
                                                 size_t offset, 
                                                 size_t *next_offset, 
                                                 char **str_ret, 
                                                 GkrBufferAllocator allocator);
                                                 
int		gkr_buffer_add_uint64		(GkrBuffer *buffer,
						 uint64_t val);

int		gkr_buffer_get_uint64		(GkrBuffer *buffer,
						 size_t offset,
						 size_t *next_offset,
						 uint64_t *val);

#define		gkr_buffer_length(b)		((b)->len)

#define 	gkr_buffer_has_error(b)		((b)->failures > 0)

#endif /* GKR_BUFFER_H */

