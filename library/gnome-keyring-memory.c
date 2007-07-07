/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-memory.c - library for allocating memory that is non-pageable

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

#include "config.h"

#include "gnome-keyring-memory.h"

#include "common/gkr-secure-memory.h"

#include <glib.h>

#include <string.h>

static GStaticMutex memory_mutex = G_STATIC_MUTEX_INIT;

/* 
 * These are called from gkr-secure-memory.c to provide appropriate
 * locking for memory between threads
 */ 

void
gkr_memory_lock (void)
{
	g_static_mutex_lock (&memory_mutex);
}

void 
gkr_memory_unlock (void)
{
	g_static_mutex_unlock (&memory_mutex);
}

/* -----------------------------------------------------------------------------
 * PUBLIC FUNCTIONS
 */

static gboolean do_warning = TRUE;
#define WARNING  "couldn't allocate secure memory to keep passwords " \
		 "and or keys from being written to the disk"
		 
#define ABORTMSG "The GNOME_KEYRING_PARANOID environment variable was set. " \
                 "Exiting..."

/**
 * gnome_keyring_memory_alloc:
 * @sz: The new desired size of the memory block.
 * 
 * Allocate a block of gnome-keyring non-pageable memory. 
 * 
 * If non-pageable memory cannot be allocated then normal memory will be 
 * returned.
 * 
 * Return value:  The new memory block which should be freed with 
 * gnome_keyring_memory_free()
 **/ 
gpointer
gnome_keyring_memory_alloc (gulong sz)
{
	const gchar *env;
	gpointer p;
	
	/* Try to allocate secure memory */
	p = gkr_secure_memory_alloc (sz);
	
	if (p) {
		do_warning = TRUE;
		return p;
	}
	
	if (do_warning) {
		g_message (WARNING);
		do_warning = FALSE;
	}
	
	env = g_getenv ("GNOME_KEYRING_PARANOID");
	if (env && *env) 
		 g_error (ABORTMSG);
			 
	return g_malloc0 (sz);
}

/**
 * gnome_keyring_memory_try_alloc:
 * @sz: The new desired size of the memory block.
 * 
 * Allocate a block of gnome-keyring non-pageable memory.
 * 
 * If non-pageable memory cannot be allocated, then NULL is returned.
 * 
 * Return value: The new block, or NULL if memory cannot be allocated.
 * The memory block should be freed with gnome_keyring_memory_free()
 */ 
gpointer
gnome_keyring_memory_try_alloc (gulong sz)
{
	return gkr_secure_memory_alloc (sz);
}

/**
 * gnome_keyring_memory_realloc:
 * @p: The pointer to reallocate or NULL to allocate a new block.
 * @sz: The new desired size of the memory block, or 0 to free the memory. 
 * 
 * Reallocate a block of gnome-keyring non-pageable memory.
 * 
 * Glib memory is also reallocated correctly. If called with a null pointer, 
 * then a new block of memory is allocated. If called with a zero size, 
 * then the block of memory is freed.
 *
 * If non-pageable memory cannot be allocated then normal memory will be 
 * returned. 
 * 
 * Return value: The new block, or NULL if the block was freed.
 * The memory block should be freed with gnome_keyring_memory_free()
 */ 
gpointer
gnome_keyring_memory_realloc (gpointer p, gulong sz)
{
	gsize oldsz;
	gpointer n;
	const gchar *env;

	if (!p) { 
		return gnome_keyring_memory_alloc (sz);
	} else if (!sz) {
		 gnome_keyring_memory_free (p);
		 return NULL;
	} else if (!gkr_secure_memory_check (p)) {
		return g_realloc (p, sz);
	}
		
	/* First try and ask secure memory to reallocate */
	n = gkr_secure_memory_realloc (p, sz);
	if (n) {
		do_warning = TRUE;
		return n;
	}
	
	if (do_warning) {
		g_message (WARNING);
		do_warning = FALSE;
	}
	
	env = g_getenv ("GNOME_KEYRING_PARANOID");
	if (env && *env) 
		g_error (ABORTMSG);
		
	oldsz = gkr_secure_memory_size (p);
	g_assert (oldsz);
	
	n = g_malloc0 (sz);
	memcpy (n, p, oldsz);
	gkr_secure_memory_free (p);
	
	return n;
}

/**
 * gnome_keyring_memory_try_realloc:
 * @p: The pointer to reallocate or NULL to allocate a new block.
 * @sz: The new desired size of the memory block.
 * 
 * Reallocate a block of gnome-keyring non-pageable memory.
 * 
 * Glib memory is also reallocated correctly when passed to this function.
 * If called with a null pointer, then a new block of memory is allocated. 
 * If called with a zero size, then the block of memory is freed.
 * 
 * If memory cannot be allocated, NULL is returned and the original block
 * of memory remains intact.
 * 
 * Return value: The new block, or NULL if memory cannot be allocated.
 * The memory block should be freed with gnome_keyring_memory_free()
 */ 
gpointer
gnome_keyring_memory_try_realloc (gpointer p, gulong sz)
{
	if (gkr_secure_memory_check (p))
		return gkr_secure_memory_realloc (p, sz);
	else
		return g_try_realloc (p, sz);
}

/**
 * gnome_keyring_memory_free:
 * @p: The pointer to the beginning of the block of memory to free.  
 * 
 * Free a block of gnome-keyring non-pageable memory. 
 * 
 * Glib memory is also freed correctly when passed to this function. If called
 * with a null pointer then no action is taken. 
 */
void
gnome_keyring_memory_free (gpointer p)
{
	if (!p)
		return;
	else if (!gkr_secure_memory_check (p))
		g_free (p);
	else 
		gkr_secure_memory_free (p);
}


/**
 * gnome_keyring_memory_is_secure:
 * @p: The pointer to check 
 * 
 * Check if a pointer is in non-pageable memory allocated by gnome-keyring.
 * 
 * Return value: Whether the memory is non-pageable or not
 */
gboolean  
gnome_keyring_memory_is_secure (gpointer p)
{
	return gkr_secure_memory_check (p) ? TRUE : FALSE;
}

/**
 * gnome_keyring_memory_strdup:
 * @str: The null terminated string to copy 
 * 
 * Copy a string into non-pageable memory. If the input string is %NULL, then 
 * %NULL will be returned.
 * 
 * Return value: The copied string, should be freed with gnome_keyring_memory_free()
 */
gchar*
gnome_keyring_memory_strdup (const gchar* str)
{
	unsigned long len;
	
	if (!str)
		return NULL;
	
	len = strlen (str) + 1;	
	gchar *res = (gchar*)gnome_keyring_memory_alloc (len);
	strcpy (res, str);
	return res;
}
