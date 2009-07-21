/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-helpers.c: Common functions called from gtest unit tests

   Copyright (C) 2008 Stefan Walter

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

/* This file is included into the main .c file for each gtest unit-test program */

#include <glib.h>
#include <gtk/gtk.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "gtest-helpers.h"

#include "egg/egg-secure-memory.h"

static GStaticMutex memory_mutex = G_STATIC_MUTEX_INIT;
static const gchar *test_path = NULL;

void egg_memory_lock (void) 
{ 
	g_static_mutex_lock (&memory_mutex); 
}

void egg_memory_unlock (void) 
{ 
	g_static_mutex_unlock (&memory_mutex); 
}

void* egg_memory_fallback (void *p, size_t sz) 
{ 
	return g_realloc (p, sz); 
}

static GMainLoop *mainloop = NULL;

static gboolean
quit_loop (gpointer unused)
{
	g_main_loop_quit (mainloop);
	return TRUE;	
}

void
test_mainloop_quit (void)
{
	g_main_loop_quit (mainloop);
}

void
test_mainloop_run (int timeout)
{
	guint id = 0;
	
	if (timeout)
		id = g_timeout_add (timeout, quit_loop, NULL);
	g_main_loop_run (mainloop);
	if (timeout)
		g_source_remove (id); 
} 

GMainLoop* 
test_mainloop_get (void)
{
	if (!mainloop)
		mainloop = g_main_loop_new (NULL, FALSE);
	return mainloop;
}

gchar*
test_build_filename (const gchar *basename)
{
	return g_build_filename (test_path, basename, NULL);
}

const gchar*
test_dir_testdata (void)
{
	const gchar *dir;
	gchar *cur, *env;

	dir = g_getenv ("TEST_DATA");
	if (dir == NULL)
		dir = "./test-data";
	if (!g_path_is_absolute (dir)) {
		cur = g_get_current_dir ();
		if (strncmp (dir, "./", 2) == 0)
			dir += 2;
		env = g_build_filename (cur, dir, NULL);
		g_free (cur);
		g_setenv ("TEST_DATA", env, TRUE);
		g_free (env);
		dir = g_getenv ("TEST_DATA");
	}

	return dir;
}

guchar* 
test_read_testdata (const gchar *basename, gsize *n_result)
{
	GError *error = NULL;
	gchar *result;
	gchar *file;

	file = g_build_filename (test_dir_testdata (), basename, NULL);
	if (!g_file_get_contents (file, &result, n_result, &error)) {
		g_warning ("could not read test data file: %s: %s", file,
		           error && error->message ? error->message : "");
		g_assert_not_reached ();
	}

	g_free (file);
	return (guchar*)result;
}

static void 
chdir_base_dir (char* argv0)
{
	gchar *dir, *base;

	dir = g_path_get_dirname (argv0);
	if (chdir (dir) < 0)
		g_warning ("couldn't change directory to: %s: %s", 
		           dir, g_strerror (errno));
	
	base = g_path_get_basename (dir);
	if (strcmp (base, ".libs") == 0) {
		if (chdir ("..") < 0)
			g_warning ("couldn't change directory to ..: %s",
			           g_strerror (errno));
	}

	g_free (dir);
}

int
main (int argc, char* argv[])
{
	GLogLevelFlags fatal_mask;
	int ret;

	g_thread_init (NULL);

	test_path = getenv ("GNOME_KEYRING_TEST_PATH");
	if (test_path) {
		setenv ("GNOME_KEYRING_OUTSIDE_TEST", "TRUE", 1);
	} else {
		test_path = "/tmp/test-gnome-keyring";
		setenv ("GNOME_KEYRING_TEST_PATH", test_path, 1);
		g_mkdir_with_parents (test_path, 0777);
	}

	chdir_base_dir (argv[0]);
	g_test_init (&argc, &argv, NULL);
	gtk_init (&argc, &argv);
	mainloop = g_main_loop_new (NULL, FALSE);

	fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
	fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
	g_log_set_always_fatal (fatal_mask);

	initialize_tests ();

	start_tests ();
	ret = g_test_run ();
	stop_tests();

	return ret;
}
