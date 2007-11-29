/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-memory.c: Test memory allocation functionality

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

#include "run-auto-test.h"

#include "library/gnome-keyring-memory.h"

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
 
void unit_test_alloc_free (CuTest* cu)
{
	gpointer p;
	gboolean ret;
	
	p = gnome_keyring_memory_alloc (512);
	CuAssertPtrNotNull (cu, p);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p, 512));
	
	memset (p, 0x67, 512);
	
	ret = gnome_keyring_memory_is_secure (p);
	CuAssertIntEquals (cu, ret, TRUE);
	
	gnome_keyring_memory_free (p);
}

void unit_test_alloc_two (CuTest* cu)
{
	gpointer p, p2;
	gboolean ret;
	
	p2 = gnome_keyring_memory_alloc (4);
	CuAssertPtrNotNull (cu, p2);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p2, 4));
	
	memset (p2, 0x67, 4);
	
	p = gnome_keyring_memory_alloc (64536);
	CuAssertPtrNotNull (cu, p);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p, 64536));

	memset (p, 0x67, 64536);
	
	ret = gnome_keyring_memory_is_secure (p);
	CuAssertIntEquals (cu, ret, TRUE);
	
	gnome_keyring_memory_free (p2);
	gnome_keyring_memory_free (p);
}

void unit_test_realloc (CuTest* cu)
{
	gchar *str = "a test string to see if realloc works properly";
	gpointer p, p2;
	int r;
	gsize len;
	
	len = strlen (str) + 1;
	
	p = gnome_keyring_memory_realloc (NULL, len);
	CuAssertPtrNotNull (cu, p);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p, len));
	
	strcpy ((gchar*)p, str);
	
	p2 = gnome_keyring_memory_realloc (p, 512);
	CuAssertPtrNotNull (cu, p2);
	
	r = strcmp (p2, str);
	CuAssert (cu, "strings not equal after realloc", r == 0);
	
	p = gnome_keyring_memory_realloc (p2, 0);
	CuAssert (cu, "should have freed memory", p == NULL);
}

void unit_test_realloc_across (CuTest *cu)
{
	gpointer p, p2;
	
	/* Tiny allocation */
	p = gnome_keyring_memory_realloc (NULL, 88);
	CuAssertPtrNotNull (cu, p);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p, 88));

	/* Reallocate to a large one, will have to have changed blocks */	
	p2 = gnome_keyring_memory_realloc (p, 64000);
	CuAssertPtrNotNull (cu, p2);
	CuAssertIntEquals (cu, IS_ZERO, find_non_zero (p2, 64000));
	
	gnome_keyring_memory_free (p2);
}
