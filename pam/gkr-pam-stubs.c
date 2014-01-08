/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pam-stubs.c - Stubs to allow linking memory code

   Copyright (C) 2007 Stef Walter

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "egg/egg-secure-memory.h"

#include <stdlib.h>

/* 
 * These are called from gkr-secure-memory.c to provide appropriate
 * locking for memory between threads
 */ 

static void
egg_memory_lock (void)
{
	/* No threads in PAM, no locking */
}

static void
egg_memory_unlock (void)
{
	/* No threads in PAM, no locking */
}

static void *
egg_memory_fallback (void *p, size_t sz)
{
	/* Handles allocation, reallocation and freeing */
	return realloc (p, sz);
}

EGG_SECURE_DEFINE_GLOBALS (egg_memory_lock, egg_memory_unlock, egg_memory_fallback);
