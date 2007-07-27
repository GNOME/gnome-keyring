/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-location.c: Test location functionality

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
#include "common/gkr-location.h"

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
 
#define MEDIA_DEVICE "/media/DummyMount"
#define MEDIA_DEVICE2 "/media/DummyMount2"
#define MEDIA_SERIAL "MEDIA-0239482093"


void unit_test_location_simple (CuTest* cu)
{
	gchar *path = g_build_filename (g_get_home_dir (), "blah", NULL);
	gchar *path2;
	GQuark loc, child;
	
	loc = gkr_location_from_path (path);
	CuAssert (cu, "should return a non-zero loc quark", loc != 0);

	g_print ("quark: %s\n", g_quark_to_string (loc));
	
	path2 = gkr_location_to_path (loc);
	CuAssert (cu, "should return non-null path", path2 != NULL);
	CuAssert (cu, "should return the same path", strcmp (path2, path) == 0);

	child = gkr_location_from_child (loc, "3");
	CuAssert (cu, "should return a non-zero loc quark", loc != 0);

	child = gkr_location_from_child (child, "2");
	CuAssert (cu, "should return a non-zero loc quark", loc != 0);

	g_print ("child quark: %s\n", g_quark_to_string (child));

	path2 = gkr_location_to_path (child);
	CuAssert (cu, "should return non-null path", path2 != NULL);
	CuAssert (cu, "should return the same path even with a child present", strcmp (path2, path) == 0);
}

void unit_test_location_media (CuTest* cu)
{
	gchar *path = g_build_filename (MEDIA_DEVICE, "testo", NULL);
	gchar *path2;
	GQuark loc;
	
	/* Device is inserted */
	gkr_location_manager_register (gkr_location_manager_get (), 
	                               MEDIA_SERIAL, MEDIA_DEVICE, "Test Media");
	
	loc = gkr_location_from_path (path);
	CuAssert (cu, "should return a non-zero loc quark", loc != 0);
	
	path2 = gkr_location_to_path (loc);
	CuAssert (cu, "should return non-null path", path2 != NULL);
	CuAssert (cu, "should return the same path", strcmp (path2, path) == 0);

	/* Device is removed */
	gkr_location_manager_unregister (gkr_location_manager_get (), MEDIA_SERIAL);
	
	path2 = gkr_location_to_path (loc);
	CuAssert (cu, "should return a null path", path2 == NULL);
		
	/* Device is inserted at another path */
	gkr_location_manager_register (gkr_location_manager_get (), 
	                               MEDIA_SERIAL, MEDIA_DEVICE2, "Test Media");
	
	path2 = gkr_location_to_path (loc);
	CuAssert (cu, "should return non-null path", path2 != NULL);
	CuAssert (cu, "should return a path at new prefix", strncmp (path2, MEDIA_DEVICE2, strlen (MEDIA_DEVICE2)) == 0);
	
}

