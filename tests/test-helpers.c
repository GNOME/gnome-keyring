
/* This file is included into the main .c file for each unit-test program */

#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "test-helpers.h"

#include "common/gkr-secure-memory.h"

static GStaticMutex memory_mutex = G_STATIC_MUTEX_INIT;
void gkr_memory_lock (void) 
{ 
	g_static_mutex_lock (&memory_mutex); 
}

void gkr_memory_unlock (void) 
{ 
	g_static_mutex_unlock (&memory_mutex); 
}

void* gkr_memory_fallback (void *p, unsigned long sz) 
{ 
	return g_realloc (p, sz); 
}

#ifndef EXTERNAL_TEST
#include "common/gkr-async.h"
#endif

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

	g_free (base);
	g_free (dir);
}

int
main (int argc, char* argv[])
{
	GLogLevelFlags fatal_mask;
	const gchar* envi;

	g_thread_init (NULL);

	envi = getenv ("GNOME_KEYRING_TEST_PATH");
	if (envi) {
		setenv ("GNOME_KEYRING_OUTSIDE_TEST", "TRUE", 1);
	} else {
		setenv ("GNOME_KEYRING_TEST_PATH", "/tmp/test-gnome-keyring", 1);
		g_mkdir_with_parents ("/tmp/test-gnome-keyring", 0777);
	}

	chdir_base_dir (argv[0]);
	gtk_init(&argc, &argv);
	mainloop = g_main_loop_new (NULL, FALSE);

#ifndef EXTERNAL_TEST

	gkr_async_workers_init (mainloop);
	
#endif

	fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
	fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
	g_log_set_always_fatal (fatal_mask);
	
	return RunAllTests();
} 
