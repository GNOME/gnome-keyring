/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-secmem.c: Test low level secure memory allocation functionality

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "run-base-test.h"

#include "common/gkr-secure-memory.h"

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void);
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void);
 * 
 * Tests be run in the order specified here.
 */
 
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

#define IS_ZERO ~0

static gsize
find_non_zero (gpointer mem, gsize len)
{
	guchar *b, *e;
	gsize sz = 0;
	for (b = (guchar*)mem, e = ((guchar*)mem) + len; b != e; ++b, ++sz) {
		if (*b != 0x00)
			return sz;
	}
	
	return IS_ZERO;
}

void unit_test_secmem_alloc_free (CuTest* cu)
{
	gpointer p;
	gboolean ret;
	
	p = gkr_secure_memory_alloc (512);
	CuAssertPtrNotNull (cu, p);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p, 512));
	CuAssert (cu, "bad block size", gkr_secure_memory_size (p) >= 512);
	
	memset (p, 0x67, 512);
	
	ret = gkr_secure_memory_check (p);
	CuAssertIntEquals (cu, ret, TRUE);
	
	gkr_secure_memory_free (p);
}

void unit_test_secmem_realloc_across (CuTest *cu)
{
	gpointer p, p2;
	
	/* Tiny allocation */
	p = gkr_secure_memory_realloc (NULL, 88);
	CuAssertPtrNotNull (cu, p);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p, 88));
	CuAssert (cu, "bad block size", gkr_secure_memory_size (p) >= 88);

	/* Reallocate to a large one, will have to have changed blocks */	
	p2 = gkr_secure_memory_realloc (p, 64000);
	CuAssertPtrNotNull (cu, p2);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p2, 64000));
	CuAssert (cu, "bad block size", gkr_secure_memory_size (p2) >= 64000);
}

void unit_test_secmem_alloc_two (CuTest* cu)
{
	gpointer p, p2;
	gboolean ret;
	
	p2 = gkr_secure_memory_alloc (4);
	CuAssertPtrNotNull (cu, p2);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p2, 4));
	CuAssert (cu, "bad block size", gkr_secure_memory_size (p2) >= 4);

	memset (p2, 0x67, 4);
	
	p = gkr_secure_memory_alloc (64536);
	CuAssertPtrNotNull (cu, p);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p, 64536));
	CuAssert (cu, "bad block size", gkr_secure_memory_size (p) >= 64536);

	memset (p, 0x67, 64536);
	
	ret = gkr_secure_memory_check (p);
	CuAssertIntEquals (cu, ret, TRUE);
	
	gkr_secure_memory_free (p2);
	gkr_secure_memory_free (p);
}

void unit_test_secmem_alloc_insane (CuTest* cu)
{
	gpointer p2;
	
	p2 = gkr_secure_memory_alloc (G_MAXSIZE);
	CuAssert (cu, "shouldn't have worked", p2 == NULL);
}

void unit_test_secmem_realloc (CuTest* cu)
{
	gchar *str = "a test string to see if realloc works properly";
	gpointer p, p2;
	int r;
	gsize len;
	
	len = strlen (str) + 1;
	
	p = gkr_secure_memory_realloc (NULL, len);
	CuAssertPtrNotNull (cu, p);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p, len));
	CuAssert (cu, "bad block size", gkr_secure_memory_size (p) >= len);
	
	strcpy ((gchar*)p, str);
	
	p2 = gkr_secure_memory_realloc (p, 512);
	CuAssertPtrNotNull (cu, p2);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (((gchar*)p2) + len, 512 - len));
	CuAssert (cu, "bad block size", gkr_secure_memory_size (p2) >= 512);
	
	r = strcmp (p2, str);
	CuAssert (cu, "strings not equal after realloc", r == 0);
	
	p = gkr_secure_memory_realloc (p2, 0);
	CuAssert (cu, "should have freed memory", p == NULL);
}

