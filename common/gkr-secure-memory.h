/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-secure-memory.h - library for allocating memory that is non-pageable

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef GKR_SECURE_MEMORY_H
#define GKR_SECURE_MEMORY_H

/* -------------------------------------------------------------------
 * Low Level Secure Memory 
 * 
 * IMPORTANT: This is pure vanila standard C, no glib. We need this 
 * because certain consumers of this protocol need to be built 
 * without linking in any special libraries. ie: the PKCS#11 module.
 * 
 * Thread locking
 * 
 * In order to use these functions in a module the following functions
 * must be defined somewhere, and provide appropriate locking for 
 * secure memory between threads:
 */
 
extern void   gkr_memory_lock (void);

extern void   gkr_memory_unlock (void);

/*
 * Allocation Fallbacks
 * 
 * If we cannot allocate secure memory, then this function
 * (defined elsewhere) will be called which has a chance to 
 * allocate other memory abort or do whatever.
 * 
 * Same call semantics as realloc with regard to NULL and zeros 
 */
extern void*  gkr_memory_fallback (void *p, unsigned long sz);


/* 
 * Main functionality
 *  
 * Allocations return NULL on failure.
 */ 
 
#define GKR_SECURE_USE_FALLBACK     0x0001

void*  gkr_secure_alloc        (unsigned long sz);

void*  gkr_secure_alloc_full   (unsigned long, int flags);

void*  gkr_secure_realloc      (void *p, unsigned long sz);

void*  gkr_secure_realloc_full (void *p, unsigned long sz, int fallback);

void   gkr_secure_free         (void* p); 

void   gkr_secure_free_full    (void* p, int fallback); 

int    gkr_secure_check        (const void* p); 

void   gkr_secure_dump_blocks  (void);

char*  gkr_secure_strdup       (const char *str);

void   gkr_secure_strfree      (char *str);

#endif /* GKR_SECURE_MEMORY_H */
