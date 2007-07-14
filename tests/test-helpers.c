
/* This file is included into the main .c file for each unit-test program */

#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static void 
chdir_base_dir (char* argv0)
{
	gchar *dir, *base;

	dir = g_path_get_dirname (argv0);
	chdir (dir);
	
	base = g_path_get_basename (dir);
	if (strcmp (base, ".libs") == 0)
		chdir ("..");

	g_free (base);
	g_free (dir);
}

int
main (int argc, char* argv[])
{
    GLogLevelFlags fatal_mask;
    chdir_base_dir (argv[0]);
    g_thread_init (NULL);
    gtk_init(&argc, &argv);
    fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
    fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
    g_log_set_always_fatal (fatal_mask);
    RunAllTests();
    return 0;
} 
