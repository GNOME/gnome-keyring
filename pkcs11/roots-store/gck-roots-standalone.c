/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-roots-standalone.h - The Roots PKCS#11 code as a standalone module

   Copyright (C) 2008, Stef Walter

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

#include "gck-roots-store.h"

#include "gck/gck-crypto.h"

#include "egg/egg-secure-memory.h"

#include <glib-object.h>

#include "pkcs11/pkcs11.h"

/* Module callbacks for secure memory */
static GStaticMutex memory_mutex = G_STATIC_MUTEX_INIT;
void egg_memory_lock (void) 
	{ g_static_mutex_lock (&memory_mutex); }
void egg_memory_unlock (void) 
	{ g_static_mutex_unlock (&memory_mutex); }
void* egg_memory_fallback (void *p, size_t sz) 
	{ return g_realloc (p, sz); }

CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	if (!list)
		return CKR_ARGUMENTS_BAD;
	
	g_type_init ();
	
	if (!g_thread_supported ())
		g_thread_init (NULL);
	
	gck_crypto_initialize ();
	
	*list = gck_roots_store_get_functions ();
	return CKR_OK;
}
