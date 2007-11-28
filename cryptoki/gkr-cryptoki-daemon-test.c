/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-cryptoki-daemon-test.c - a test daemon for running cryptoki code

   Copyright (C) 2007, Nate Nielsen

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

   Author: Nate Nielsen <nielsen@memberwebs.com>
*/

#include <glib.h>
#include <glib/gstdio.h>

#include "gkr-cryptoki-daemon.h"

#include "common/gkr-async.h"
#include "common/gkr-secure-memory.h"

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

/* -----------------------------------------------------------------------------
 * MEMORY
 */

static gboolean do_warning = TRUE;
#define WARNING  "couldn't allocate secure memory to keep passwords " \
		 "and or keys from being written to the disk"
		 
#define ABORTMSG "The GNOME_KEYRING_PARANOID environment variable was set. " \
                 "Exiting..."


/* 
 * These are called from gkr-secure-memory.c to provide appropriate
 * locking for memory between threads
 */ 

void
gkr_memory_lock (void)
{
	/* The daemon uses cooperative threading, and doesn't need locking */
}

void 
gkr_memory_unlock (void)
{
	/* The daemon uses cooperative threading, and doesn't need locking */
}

void*
gkr_memory_fallback (void *p, unsigned long sz)
{
	const gchar *env;
	
	/* We were asked to free memory */
	if (!sz) {
		g_free (p);
		return NULL;
	}
	
	/* We were asked to allocate */
	if (do_warning) {
		g_message (WARNING);
		do_warning = FALSE;
	}
	
	env = g_getenv ("GNOME_KEYRING_PARANOID");
	if (env && *env) 
		 g_error (ABORTMSG);
			 
	return g_malloc0 (sz);
}

/* -------------------------------------------------------------------------- */

static GMainLoop *loop = NULL;
static gboolean do_quit = FALSE;

static void
cleanup_handler (int sig)
{
	do_quit = TRUE;
}

static gboolean
check_quit (gpointer dummy)
{
	if (do_quit) {
		g_main_quit (loop);
		return FALSE;
	}
	
	return TRUE;
}

int
main (int argc, char *argv[])
{
	gchar *path;
	gchar *tmp_dir;
	
	g_thread_init (NULL);

	/* Create private directory for agent socket */
	tmp_dir = g_build_filename (g_get_tmp_dir (), "keyring-test", NULL);
	if (g_mkdir (tmp_dir, 0700) && errno != EEXIST)
		g_error ("mkdtemp: socket dir");
	path = g_strdup_printf ("%s/socket", tmp_dir);
	unlink (path);
	g_free (tmp_dir);


	srand (time (NULL));
	signal (SIGPIPE, SIG_IGN);
	signal (SIGINT, cleanup_handler);
	signal (SIGHUP, cleanup_handler);
	signal (SIGTERM, cleanup_handler);
	
	g_print ("# This is for gnome-keyring testing purposes only\n");
	g_print ("GNOME_KEYRING_SOCKET=%s\n", path);
	g_print ("GNOME_KEYRING_PID=%d\n", getpid ());

	loop = g_main_loop_new (NULL, FALSE);
	
	/* Don't do this for real daemons, boys and girls */
	g_timeout_add (200, check_quit, NULL);
	
	gkr_cryptoki_daemon_setup (path);
	
	g_main_loop_run (loop);
	
	gkr_async_workers_stop_all ();
	gkr_cryptoki_daemon_cleanup ();
	
	g_main_loop_unref (loop);
	loop = NULL;

	g_free (path);
	return 0;
}

