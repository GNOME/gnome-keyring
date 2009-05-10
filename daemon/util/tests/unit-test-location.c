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

#include "run-auto-test.h"

#include "util/gkr-location.h"

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

DEFINE_TEST(location_simple)
{
	gchar *path = g_build_filename (g_get_home_dir (), "blah", NULL);
	gchar *path2;
	GQuark loc, child;
	
	loc = gkr_location_from_path (path);
	/* "should return a non-zero loc quark" */
	g_assert_cmpint (loc, !=, 0);

	g_print ("quark: %s\n", g_quark_to_string (loc));
	
	path2 = gkr_location_to_path (loc);
	/* "should return non-null path" */
	g_assert (path2 != NULL);
	/* "should return the same path" */
	g_assert_cmpstr (path2, ==, path);

	child = gkr_location_from_child (loc, "3");
	/* "should return a non-zero loc quark" */
	g_assert_cmpint (loc, !=, 0);

	child = gkr_location_from_child (child, "2");
	/* "should return a non-zero loc quark" */
	g_assert_cmpint (loc, !=, 0);

	g_print ("child quark: %s\n", g_quark_to_string (child));

	path2 = gkr_location_to_path (child);
	/* "should return non-null path" */
	g_assert (path2 != NULL);

	/* "should be volume" */
	g_assert (gkr_location_is_volume (GKR_LOCATION_VOLUME_HOME));
	/* "should not be volume" */
	g_assert (!gkr_location_is_volume (loc));
	/* "should not be volume" */
	g_assert (!gkr_location_is_volume (child));
}

DEFINE_TEST (location_trailing)
{
	GQuark one, two, ref;
	
	one = gkr_location_from_child (GKR_LOCATION_VOLUME_LOCAL, "/blah/");
	/* "should return a non-zero quark" */
	g_assert_cmpint (one, !=, 0);

	two = gkr_location_from_child (GKR_LOCATION_VOLUME_LOCAL, "blah//");
	/* "should return a non-zero quark" */
	g_assert_cmpint (two, !=, 0);

	ref = gkr_location_from_child (GKR_LOCATION_VOLUME_LOCAL, "blah");
	/* "should return a non-zero quark" */
	g_assert_cmpint (ref, !=, 0);

	/* Should all be identical */
	/* "stripping of leading and trailing slashes did not work" */
	g_assert (ref == one);
	/* "stripping of leading and trailing slashes did not work" */
	g_assert (ref == two);
}

DEFINE_TEST(location_parent)
{
	GQuark child, ref, parent;

	ref = gkr_location_from_child (GKR_LOCATION_VOLUME_LOCAL, "first");
	/* "should return a non-zero quark" */
	g_assert_cmpint (ref, !=, 0);
	
	child = gkr_location_from_child (ref, "second");
	/* "should return a non-zero quark" */
	g_assert_cmpint (child, !=, 0);
	
	parent = gkr_location_to_parent (child);
	/* "should return a non-zero quark" */
	g_assert_cmpint (parent, !=, 0);
	/* "parent location does not equal original" */
	g_assert (parent == ref);
	
	/* Should return the volume */
	parent = gkr_location_to_parent (parent);
	/* "should return a non-zero quark" */
	g_assert_cmpint (parent, !=, 0);
	/* "parent of parent location does not equal volume" */
	g_assert (parent == GKR_LOCATION_VOLUME_LOCAL);
}

DEFINE_TEST(location_media)
{
	gchar *path = g_build_filename (MEDIA_DEVICE, "testo", NULL);
	gchar *path2;
	GQuark loc;
	
	/* Device is inserted */
	gkr_location_manager_register (gkr_location_manager_get (), 
	                               MEDIA_SERIAL, MEDIA_DEVICE, "Test Media");
	
	loc = gkr_location_from_path (path);
	/* "should return a non-zero loc quark" */
	g_assert_cmpint (loc, !=, 0);
	
	path2 = gkr_location_to_path (loc);
	/* "should return non-null path" */
	g_assert (path2 != NULL);
	/* "should return the same path" */
	g_assert_cmpstr (path2, ==, path);

	/* Device is removed */
	gkr_location_manager_unregister (gkr_location_manager_get (), MEDIA_SERIAL);
	
	/* Device is inserted at another path */
	gkr_location_manager_register (gkr_location_manager_get (), 
	                               MEDIA_SERIAL, MEDIA_DEVICE2, "Test Media");
	
	path2 = gkr_location_to_path (loc);
	/* "should return non-null path" */
	g_assert (path2 != NULL);
	/* "should return a path at new prefix" */
	g_assert (strncmp (path2, MEDIA_DEVICE2, strlen (MEDIA_DEVICE2)) == 0);
	
}

DEFINE_TEST(location_fileops)
{
	const guchar *data = (guchar*)"TEST DATA FOR FILE";
	guchar *result;
	gsize n_result, len;
	gboolean ret;
	GQuark loc;
	
	loc = gkr_location_from_child (GKR_LOCATION_VOLUME_FILE, "/tmp/gkr-test-location-fileops");
	/* "should return a non-zero quark" */
	g_assert_cmpint (loc, !=, 0);
	
	len = strlen ((gchar*)data);
	ret = gkr_location_write_file (loc, data, len, NULL);
	/* "should be successful writing to temp file" */
	g_assert (ret == TRUE);

	ret = gkr_location_read_file (loc, &result, &n_result, NULL);
	/* "should be successful reading from temp file" */
	g_assert (ret == TRUE);
	/* "should have read same length as written" */
	g_assert (n_result == len);
	/* "should have read same data as written" */
	g_assert (memcmp (data, result, len) == 0);
	
	ret = gkr_location_delete_file (loc, NULL);
	/* "should have successfully deleted file" */
	g_assert (ret == TRUE);

	ret = gkr_location_read_file (loc, &result, &n_result, NULL);
	/* "shouldn't be able to read from deleted file" */
	g_assert (ret == FALSE);

	ret = gkr_location_delete_file (loc, NULL);
	/* "should be able to successfully delete non-existant file" */
	g_assert (ret == TRUE);
}
