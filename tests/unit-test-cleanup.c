/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-cleanup.c: Test low level cleanup functionality

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

#include "common/gkr-cleanup.h"

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
 
#define DATA "some string"

typedef struct _CleanupParam {
	CuTest *cu;
	gpointer value;
} CleanupParam;

static void 
cleanup_callback (gpointer user_data)
{	
	CleanupParam *param = (CleanupParam*)user_data;
	CuAssert (param->cu, "invalid user_data passed to callback", param->value == DATA);
	param->value = NULL;
}

void unit_test_cleanup (CuTest* cu)
{
	CleanupParam param;
	
	param.cu = cu;
	param.value = DATA;
	
	gkr_cleanup_register (cleanup_callback, &param);
	
	gkr_cleanup_perform ();
	
	CuAssert (cu, "cleanup handler not called", param.value == NULL);
}

/* -----------------------------------------------------------------------------
 * Cleanup handlers are called in the opposite order as installed 
 */

static gint order_value = 0;

typedef struct _OrderParam {
	CuTest *cu;
	gint reference;
} OrderParam;

static void 
order_callback (gpointer user_data)
{	
	OrderParam *param = (OrderParam*)user_data;
	CuAssert (param->cu, "cleanup handler called out of order", order_value == param->reference);
	param->reference = -1;
	--order_value;
}
 
void unit_test_order (CuTest* cu)
{
	OrderParam param[8];
	int i;
	
	for (i = 0; i < 8; ++i) {
		param[i].cu = cu;
		param[i].reference = i;	
		gkr_cleanup_register (order_callback, &param[i]);
	}

	order_value = i - 1;
	
	gkr_cleanup_perform ();

	for (i = 0; i < 8; ++i)
		CuAssert (cu, "cleanup handler not called", param[i].reference == -1); 
	
	CuAssert (cu, "not all cleanup handlers called", order_value == -1);
}

/* -----------------------------------------------------------------------------
 * A cleanup handler might cause another to be registered.
 */
 
static gboolean cleaned_up = FALSE;

static void
second_callback (gpointer user_data)
{
	cleaned_up = TRUE;
}
 
static void
reregister_callback (gpointer user_data)
{
	gkr_cleanup_register (second_callback, NULL);	
} 

void unit_test_reregister (CuTest* cu)
{
	cleaned_up = FALSE;
	
	gkr_cleanup_register (reregister_callback, NULL);
	
	gkr_cleanup_perform ();
	
	CuAssert (cu, "second cleanup handler not called", cleaned_up == TRUE);
}

/* -----------------------------------------------------------------------------
 * Cleanup handlers can be removed 
 */
 
static gboolean test_cleaned_up = FALSE;

static void 
remove_callback (gpointer user_data)
{
	test_cleaned_up = TRUE;	
}

void unit_test_remove (CuTest* cu)
{
	gkr_cleanup_register (remove_callback, NULL);
	gkr_cleanup_register (remove_callback, DATA);
	gkr_cleanup_unregister (remove_callback, DATA);
	gkr_cleanup_unregister (remove_callback, NULL);
	gkr_cleanup_perform ();
	
	CuAssert (cu, "removed callback was called", test_cleaned_up == FALSE);		
}
