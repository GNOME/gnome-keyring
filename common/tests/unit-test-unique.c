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

#include "common/gkr-id.h"

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
	gkrid id, id2;
	const guchar *data;
	gsize n_data;
	
	id = gkr_id_new ((guchar*)test, strlen (test));
	CuAssert (cu, "didn't create id", id != NULL);
	
	data = gkr_id_get_raw (id, &n_data);
	CuAssert (cu, "raw returned null", data != NULL);
	CuAssert (cu, "length has changed", n_data == strlen (test));
	CuAssert (cu, "unique data is wrong", memcmp (data, test, n_data) == 0);
	
	id2 = gkr_id_new ((guchar*)test, strlen(test));
	CuAssert (cu, "didn't create id", id != NULL);
	CuAssert (cu, "two identically created ids are different", 
	          gkr_id_equals (id, id2));

	id2 = gkr_id_dup (id);
	CuAssert (cu, "didn't dup id", id != NULL);
	CuAssert (cu, "two duped created ids are different", 
	          gkr_id_equals (id, id2));
	          
	gkr_id_free (id);
}		

void unit_test_id_digest (CuTest* cu)
{
	guchar test[40];
	gkrid id, id2;
	
	memset (test, 'h', 40);
	
	id = gkr_id_new_digest (test, 40);
	CuAssert (cu, "didn't create id", id != NULL);

	id2 = gkr_id_new_digest (test, 40);
	CuAssert (cu, "didn't create id", id != NULL);
	CuAssert (cu, "two identically digested ids are different", 
	          gkr_id_equals (id, id2));
	
	id2 = gkr_id_new_digestv (test, 20, test + 20, 20, NULL);
	CuAssert (cu, "didn't create id", id != NULL);
	CuAssert (cu, "block digested id is different", 
	          gkr_id_equals (id, id2));
}
