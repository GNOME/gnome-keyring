/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-signal.c: Test unix signal handling

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <glib.h>

#include "run-auto-test.h"

#include "common/gkr-unique.h"

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
void unit_test_unique_basics (CuTest* cu)
{
	gchar test[] = "my big test";
	gkrunique uni, uni2;
	const guchar *data;
	gsize n_data;
	
	uni = gkr_unique_new ((guchar*)test, strlen (test));
	CuAssert (cu, "didn't create unique", uni != NULL);
	
	data = gkr_unique_get_raw (uni, &n_data);
	CuAssert (cu, "raw returned null", data != NULL);
	CuAssert (cu, "length has changed", n_data == strlen (test));
	CuAssert (cu, "unique data is wrong", memcmp (data, test, n_data) == 0);
	
	uni2 = gkr_unique_new ((guchar*)test, strlen(test));
	CuAssert (cu, "didn't create unique", uni != NULL);
	CuAssert (cu, "two identically created uniques are different", 
	          gkr_unique_equals (uni, uni2));

	uni2 = gkr_unique_dup (uni);
	CuAssert (cu, "didn't dup unique", uni != NULL);
	CuAssert (cu, "two duped created uniques are different", 
	          gkr_unique_equals (uni, uni2));
	          
	gkr_unique_free (uni);
}		

void unit_test_unique_digest (CuTest* cu)
{
	guchar test[40];
	gkrunique uni, uni2;
	
	memset (test, 'h', 40);
	
	uni = gkr_unique_new_digest (test, 40);
	CuAssert (cu, "didn't create unique", uni != NULL);

	uni2 = gkr_unique_new_digest (test, 40);
	CuAssert (cu, "didn't create unique", uni != NULL);
	CuAssert (cu, "two identically digested uniques are different", 
	          gkr_unique_equals (uni, uni2));
	
	uni2 = gkr_unique_new_digestv (test, 20, test + 20, 20, NULL);
	CuAssert (cu, "didn't create unique", uni != NULL);
	CuAssert (cu, "block digested unique is different", 
	          gkr_unique_equals (uni, uni2));
}
