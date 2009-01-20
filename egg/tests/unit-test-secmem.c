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

#include "run-auto-test.h"

#include "egg/egg-secure-memory.h"

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

#define IS_ZERO ((gsize)~0)

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

DEFINE_TEST(secmem_alloc_free)
{
	gpointer p;
	gboolean ret;
	
	p = egg_secure_alloc_full (512, 0);
	g_assert (p != NULL);
	g_assert_cmpint (IS_ZERO, ==, find_non_zero (p, 512));
	
	memset (p, 0x67, 512);
	
	ret = egg_secure_check (p);
	g_assert (ret == TRUE);
	
	egg_secure_free_full (p, 0);
}

DEFINE_TEST(secmem_realloc_across)
{
	gpointer p, p2;
	
	/* Tiny allocation */
	p = egg_secure_realloc_full (NULL, 1088, 0);
	g_assert (p != NULL);
	g_assert_cmpint (IS_ZERO, ==, find_non_zero (p, 1088));

	/* Reallocate to a large one, will have to have changed blocks */	
	p2 = egg_secure_realloc_full (p, 16200, 0);
	g_assert (p2 != NULL);
	g_assert_cmpint (IS_ZERO, ==, find_non_zero (p2, 16200));
}

DEFINE_TEST(secmem_alloc_two)
{
	gpointer p, p2;
	gboolean ret;
	
	p2 = egg_secure_alloc_full (4, 0);
	g_assert (p2 != NULL);
	g_assert_cmpint (IS_ZERO, ==, find_non_zero (p2, 4));

	memset (p2, 0x67, 4);
	
	p = egg_secure_alloc_full (16200, 0);
	g_assert (p != NULL);
	g_assert_cmpint (IS_ZERO, ==, find_non_zero (p, 16200));

	memset (p, 0x67, 16200);
	
	ret = egg_secure_check (p);
	g_assert (ret == TRUE);
	
	egg_secure_free_full (p2, 0);
	egg_secure_free_full (p, 0);
}

DEFINE_TEST(secmem_realloc)
{
	gchar *str = "a test string to see if realloc works properly";
	gpointer p, p2;
	gsize len;
	
	len = strlen (str) + 1;
	
	p = egg_secure_realloc_full (NULL, len, 0);
	g_assert (p != NULL);
	g_assert_cmpint (IS_ZERO, ==, find_non_zero (p, len));
	
	strcpy ((gchar*)p, str);
	
	p2 = egg_secure_realloc_full (p, 512, 0);
	g_assert (p2 != NULL);
	g_assert_cmpint (IS_ZERO, ==, find_non_zero (((gchar*)p2) + len, 512 - len));
	
	g_assert (strcmp (p2, str) == 0);
	
	p = egg_secure_realloc_full (p2, 0, 0);
	g_assert (p == NULL);
}

