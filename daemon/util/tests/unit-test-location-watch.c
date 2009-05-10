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
#include <unistd.h>

#include "run-auto-test.h"

#include "util/gkr-location-watch.h"

#include <glib/gstdio.h>

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
 
#define DATA "test-data"
#define SUBDIR "test-subdir"
#define WILDCARD "*.woo?"

static GkrLocationWatch *the_watch = NULL;
static gchar *test_dir = NULL;
static gchar *test_file = NULL;

static guint n_locations_added = 0;
static GQuark last_location_added = 0;

static guint n_locations_changed = 0;
static GQuark last_location_changed = 0;

static guint n_locations_removed = 0;
static GQuark last_location_removed = 0;

static void
location_added (GkrLocationWatch *watch, GQuark loc, gpointer unused)
{
	/* "should be a non-null quark" */
	g_assert_cmpint (loc, !=, 0);
	/* "should be a valid quark" */
	g_assert (g_quark_to_string (loc) != NULL);
	
	++n_locations_added;
	last_location_added = loc;
}

static void
location_changed (GkrLocationWatch *watch, GQuark loc, gpointer unused)
{
	/* "should be a non-null quark" */
	g_assert_cmpint (loc, !=, 0);
	/* "should be a valid quark" */
	g_assert (g_quark_to_string (loc) != NULL);
	
	++n_locations_changed;
	last_location_changed = loc;
}

static void
location_removed (GkrLocationWatch *watch, GQuark loc, gpointer unused)
{
	/* "should be a non-null quark" */
	g_assert_cmpint (loc, !=, 0);
	/* "should be a valid quark" */
	g_assert (g_quark_to_string (loc) != NULL);
	
	++n_locations_removed;
	last_location_removed = loc;
}

DEFINE_TEST(location_watch)
{
	GQuark loc;
	
	/* Mtime must change so wait between tests */
	sleep (1);

	the_watch = gkr_location_watch_new (NULL, 0, SUBDIR, WILDCARD, NULL);
	g_signal_connect (the_watch, "location-added", G_CALLBACK (location_added), NULL); 
	g_signal_connect (the_watch, "location-removed", G_CALLBACK (location_removed), NULL); 
	g_signal_connect (the_watch, "location-changed", G_CALLBACK (location_changed), NULL);
	
	/* Make a test directory */
	loc = gkr_location_from_child (GKR_LOCATION_VOLUME_LOCAL, SUBDIR);
	test_dir = gkr_location_to_path (loc); 
	
	test_file = g_build_filename (test_dir, "my-file.woof", NULL);
	g_unlink (test_file);

	/* A watch for an empty directory, should have no responses */
	gkr_location_watch_refresh (the_watch, FALSE);
	
	g_assert_cmpint (0, ==, n_locations_added);
	g_assert_cmpint (0, ==, n_locations_changed);
	g_assert_cmpint (0, ==, n_locations_removed);
	
	g_mkdir_with_parents (test_dir, 0700);
	
	/* Should still have no responses even though it exists */
	gkr_location_watch_refresh (the_watch, FALSE);
	
	g_assert_cmpint (0, ==, n_locations_added);
	g_assert_cmpint (0, ==, n_locations_changed);
	g_assert_cmpint (0, ==, n_locations_removed);
}

DEFINE_TEST(location_file)
{
	gboolean ret;
	GQuark loc;
	
	/* Mtime must change so wait between tests */
	sleep (1);

	/* Make sure things are clean */
	g_unlink (test_file);
	gkr_location_watch_refresh (the_watch, FALSE);
	
	n_locations_added = n_locations_changed = n_locations_removed = 0;
	last_location_added = last_location_changed = last_location_removed = 0;

	ret = g_file_set_contents (test_file, DATA, strlen (DATA), NULL);
	g_assert (ret == TRUE);
	
	/* Now make sure that file is located */
	gkr_location_watch_refresh (the_watch, FALSE);
	
	g_assert_cmpint (1, ==, n_locations_added);
	g_assert_cmpint (0, ==, n_locations_changed);
	g_assert_cmpint (0, ==, n_locations_removed);
	
	/* The added one should match our file */
	loc = gkr_location_from_path (test_file);
	/* "returned zero location" */
	g_assert_cmpint (loc, !=, 0);
	/* "wrong location was signalled" */
	g_assert (loc == last_location_added);
	
	
	
	n_locations_added = n_locations_changed = n_locations_removed = 0;
	last_location_added = last_location_changed = last_location_removed = 0;
	
	sleep (1);
	
	/* Shouldn't find the file again */
	gkr_location_watch_refresh (the_watch, FALSE);
	g_assert_cmpint (0, ==, n_locations_added);
	g_assert_cmpint (0, ==, n_locations_changed);
	g_assert_cmpint (0, ==, n_locations_removed);
	
	/* But we should find the file if forced to */	
	gkr_location_watch_refresh (the_watch, TRUE);
	g_assert_cmpint (0, ==, n_locations_added);
	g_assert_cmpint (1, ==, n_locations_changed);
	g_assert_cmpint (0, ==, n_locations_removed);
	/* "wrong location was signalled" */
	g_assert (loc == last_location_changed);



	n_locations_added = n_locations_changed = n_locations_removed = 0;
	last_location_added = last_location_changed = last_location_removed = 0;

	ret = g_file_set_contents (test_file, DATA, strlen (DATA), NULL);
	g_assert (ret == TRUE);

	/* File was updated */
	gkr_location_watch_refresh (the_watch, FALSE);
	g_assert_cmpint (0, ==, n_locations_added);
	g_assert_cmpint (1, ==, n_locations_changed);
	g_assert_cmpint (0, ==, n_locations_removed);
	/* "wrong location was signalled" */
	g_assert (loc == last_location_changed);
	
	
	
	n_locations_added = n_locations_changed = n_locations_removed = 0;
	last_location_added = last_location_changed = last_location_removed = 0;
	
	g_unlink (test_file);
	
	/* Now file should be removed */
	gkr_location_watch_refresh (the_watch, FALSE);

	g_assert_cmpint (0, ==, n_locations_added);
	g_assert_cmpint (0, ==, n_locations_changed);
	g_assert_cmpint (1, ==, n_locations_removed);
	/* "wrong location was signalled" */
	g_assert (loc == last_location_removed);
}

DEFINE_TEST(location_nomatch)
{
	gchar *file = g_build_filename (test_dir, "my-file.toot", NULL);
	gboolean ret;

	/* Mtime must change so wait between tests */
	sleep (1);
	
	ret = g_file_set_contents (file, DATA, strlen (DATA), NULL);
	g_assert (ret == TRUE);

	n_locations_added = n_locations_changed = n_locations_removed = 0;
	last_location_added = last_location_changed = last_location_removed = 0;
	
	/* Now make sure that file is not located */
	gkr_location_watch_refresh (the_watch, FALSE);
	
	g_assert_cmpint (0, ==, n_locations_added);
	g_assert_cmpint (0, ==, n_locations_changed);
	g_assert_cmpint (0, ==, n_locations_removed);
	
	g_unlink (file);
}
