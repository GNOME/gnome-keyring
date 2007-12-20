/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pk-index.c: Test PK Indexes

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

#include "run-auto-test.h"

#include "pk/gkr-pk-index.h"
#include "pk/gkr-pk-object.h"

#include "common/gkr-location.h"
#include "common/gkr-unique.h"

#include <glib.h>
#include <memory.h>

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void)
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void)
 * 
 * Tests be run in the order specified here.
 */

#define DATA ((guchar*)"aosentuhsao")
#define DATA_L (strlen ((gchar*)DATA))

#define STR "a test string"

static GkrPkObject *object = NULL;

void unit_setup_index (void)
{
	/* This is just any arbitrary data */
	gkrunique unique = gkr_unique_new (DATA, DATA_L);
	GQuark location = gkr_location_from_child (GKR_LOCATION_VOLUME_LOCAL, "woof");
	
	object = g_object_new (GKR_TYPE_PK_OBJECT, "location", location, "unique", unique, NULL);
}

void unit_test_index_binary (CuTest* cu)
{
	gboolean ret;
	guchar *data;
	gsize n_data;
	
	/* Test binary */
	ret = gkr_pk_index_set_binary (object, "field", DATA, DATA_L);
	CuAssert (cu, "set_binary returned false", ret);

	data = gkr_pk_index_get_binary (object, "field", &n_data);
	CuAssert (cu, "get_binary returned no data", data != NULL);
	CuAssert (cu, "get_binary returned bad length data", n_data == DATA_L);
	CuAssert (cu, "get_binary returned wrong data", memcmp (data, DATA, DATA_L) == 0);
}

void unit_test_index_string (CuTest *cu)
{
	gchar *str;
	gboolean ret;
	
	/* Test strings */
	ret = gkr_pk_index_set_string (object, "string", STR);
	CuAssert (cu, "set_string returned false", ret);

	str = gkr_pk_index_get_string (object, "string");
	CuAssert (cu, "get_string returned no string", str != NULL);
	CuAssert (cu, "get_string returned wrong string", strcmp (str, STR) == 0);
}

void unit_test_index_int (CuTest *cu)
{
	gint val;
	gboolean ret;
	
	ret = gkr_pk_index_set_int (object, "intval", 23423523);
	CuAssert (cu, "set_int returned false", ret);

	val = gkr_pk_index_get_int (object, "intval", 0);
	CuAssert (cu, "get_int returned wrong value", val == 23423523);

	val = gkr_pk_index_get_int (object, "nonexistant", 35);
	CuAssert (cu, "get_int didn't return default", val == 35);
}

void unit_test_index_boolean (CuTest *cu)
{
	gboolean val;
	gboolean ret;
	
	ret = gkr_pk_index_set_boolean (object, "boolval", TRUE);
	CuAssert (cu, "set_boolean returned false", ret);

	val = gkr_pk_index_get_boolean (object, "boolval", 0);
	CuAssert (cu, "get_boolean returned wrong value", val == TRUE);

	val = gkr_pk_index_get_boolean (object, "nonexistant", TRUE);
	CuAssert (cu, "get_boolean didn't return default", val == TRUE);
}

void unit_test_index_quarks (CuTest *cu)
{
	GQuark *quarks;
	GQuark *output;
	gboolean ret;
	gint i;
	
	quarks = g_new0 (GQuark, 5);
	for (i = 0; i < 4; ++i)
		quarks[i] = g_quark_from_static_string ("blah");
	
	ret = gkr_pk_index_set_quarks (object, "quarks", quarks);
	CuAssert (cu, "set_quarks returned false", ret);
	
	/* A second time which exercises internals to not write same value twice */
	ret = gkr_pk_index_set_quarks (object, "quarks", quarks);
	CuAssert (cu, "set_quarks returned false", ret);
	
	output = gkr_pk_index_get_quarks (object, "quarks"); 
	CuAssert (cu, "get_quarks returned null", output != NULL);
	
	for (i = 0; i < 4; ++i)
		CuAssert (cu, "returned quark is different", quarks[i] == output[i]);
	
	output = gkr_pk_index_get_quarks (object, "nonexistant");
	CuAssert (cu, "get_quarks didn't return null", output == NULL);
}

void unit_test_index_delete (CuTest *cu)
{
	gboolean ret;
	gboolean val;
	
	ret = gkr_pk_index_delete (object, "boolval");
	CuAssert (cu, "delete returned false", ret);
	
	val = gkr_pk_index_get_boolean (object, "boolval", FALSE);
	CuAssert (cu, "delete didn't work", val == FALSE);
	
	ret = gkr_pk_index_delete (object, "nonexistant");
	CuAssert (cu, "delete returned false", ret);
}
