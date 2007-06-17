/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-daemon.c - main keyring daemon code.

   Copyright (C) 2003 Red Hat, Inc

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Alexander Larsson <alexl@redhat.com>
*/

#include "config.h"

#include "gnome-keyring.h"
#include "gnome-keyring-daemon.h"

#include "keyrings/gkr-keyrings.h"

#include "ui/gkr-ask-daemon.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <glib.h>
#include <glib/gi18n.h>

#include <gcrypt.h>

static GMainLoop *loop = NULL;

#ifndef HAVE_SOCKLEN_T
#define socklen_t int
#endif

static RETSIGTYPE
cleanup_handler (int sig)
{
        cleanup_socket_dir ();
        _exit (2);
}

static int
sane_dup2 (int fd1, int fd2)
{
	int ret;

 retry:
	ret = dup2 (fd1, fd2);
	if (ret < 0 && errno == EINTR)
		goto retry;
	
	return ret;
}

static void
close_stdinout (void)
{
	int fd;
	
	fd = open ("/dev/null", O_RDONLY);
	sane_dup2 (fd, 0);
	close (fd);
	
	fd = open ("/dev/null", O_WRONLY);
	sane_dup2 (fd, 1);
	close (fd);
}

static gboolean
lifetime_slave_pipe_io (GIOChannel  *channel,
			GIOCondition cond,
			gpointer     callback_data)
{
        cleanup_socket_dir ();
        _exit (2);
}

int
main (int argc, char *argv[])
{
	const char *path;
	char *fd_str;
	int fd;
	pid_t pid;
	gboolean foreground;
	gboolean daemon;
	GIOChannel *channel;
	int i;
	
	g_type_init ();

	/* We do not use gcrypt in a multi-threaded manner */
	gcry_check_version (LIBGCRYPT_VERSION);
	
	if (!create_master_socket (&path)) {
		exit (1);
	}
	
#ifdef HAVE_LOCALE_H
	/* internationalisation */
	setlocale (LC_ALL, "");
#endif

#ifdef HAVE_GETTEXT
	bindtextdomain (GETTEXT_PACKAGE, GNOMELOCALEDIR);
	textdomain (GETTEXT_PACKAGE);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
#endif


	srand (time (NULL));

	foreground = FALSE;
	daemon = FALSE;

	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			if (strcmp (argv[i], "-f") == 0) {
				foreground = TRUE;
			}
			if (strcmp (argv[i], "-d") == 0) {
				daemon = TRUE;
			}
		}
	}

	if (!foreground) {
		pid = fork ();
		if (pid == 0) {
			/* intermediated child */
			if (daemon) {
				pid = fork ();
				
				if (pid != 0) {
					/* still intermediated child */
					
					/* This process exits, so that the
					 * final child will inherit init as parent
					 * to avoid zombies
					 */
					if (pid == -1) {
						exit (1);
					} else {
						/* This is where we know the pid of the daemon.
						 * The initial process will waitpid until we exit,
						 * so there is no race */
						g_print ("GNOME_KEYRING_SOCKET=%s\n", path);
						g_print ("GNOME_KEYRING_PID=%d\n", (gint)pid);
						exit (0);
					}
				}
			}
			
			close_stdinout ();
			
			/* final child continues here */
		} else {
			if (daemon) {
				int status;
				/* Initial process, waits for intermediate child */
				if (pid == -1) {
					exit (1);
				}
				waitpid (pid, &status, 0);
				if (status != 0) {
					exit (status);
				}
			} else {
				g_print ("GNOME_KEYRING_SOCKET=%s\n", path);
				g_print ("GNOME_KEYRING_PID=%d\n", (gint)pid);
			}
			
			exit (0);
		}
	} else {
		g_print ("GNOME_KEYRING_SOCKET=%s\n", path);
		g_print ("GNOME_KEYRING_PID=%d\n", (gint)getpid ());
	}

	/* Daemon process continues here */

	signal (SIGPIPE, SIG_IGN);
	signal (SIGINT, cleanup_handler);
        signal (SIGHUP, cleanup_handler);
        signal (SIGTERM, cleanup_handler);

	loop = g_main_loop_new (NULL, FALSE);

	fd_str = getenv ("GNOME_KEYRING_LIFETIME_FD");
	if (fd_str != NULL && fd_str[0] != 0) {
		fd = atoi (fd_str);
		if (fd != 0) {
			channel = g_io_channel_unix_new (fd);
			g_io_add_watch (channel,
					G_IO_IN | G_IO_HUP,
					lifetime_slave_pipe_io, NULL);
			g_io_channel_unref (channel);
		}
		
	}
	
	gkr_ask_daemon_init ();
	gkr_keyrings_init ();
	
#ifdef WITH_DBUS
	gnome_keyring_daemon_dbus_setup (loop, path);
#endif
	
	g_main_loop_run (loop);

#ifdef WITH_DBUS
	gnome_keyring_daemon_dbus_cleanup ();
#endif
	
	gkr_keyrings_cleanup ();
	gkr_ask_daemon_cleanup ();

	cleanup_socket_dir ();
	return 0;
}

