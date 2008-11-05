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

#include "gkr-daemon.h"

#include "common/gkr-async.h"
#include "common/gkr-cleanup.h"
#include "common/gkr-crypto.h"
#include "common/gkr-daemon-util.h"
#include "common/gkr-secure-memory.h"
#include "common/gkr-unix-signal.h"

#include "keyrings/gkr-keyring-login.h"

#include "library/gnome-keyring.h"

#include "pk/gkr-pk-object-storage.h"
#ifdef ROOT_CERTIFICATES
#include "pk/gkr-pk-root-storage.h"
#endif

#include "pkcs11/gkr-pkcs11-daemon.h"

#ifdef WITH_SSH
#include "ssh/gkr-ssh-daemon.h"
#include "ssh/gkr-ssh-storage.h"
#endif

#include "ui/gkr-ask-daemon.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <glib.h>
#include <glib/gi18n.h>

#include <gconf/gconf.h>
#include <gconf/gconf-client.h>

#include <gcrypt.h>

/* preset file descriptors */
#define  STDIN   0
#define  STDOUT  1
#define  STDERR  2

static GMainLoop *loop = NULL;

#ifndef HAVE_SOCKLEN_T
#define socklen_t int
#endif

/* -----------------------------------------------------------------------------
 * COMMAND LINE
 */

/* All the components to run on startup if not set in gconf */
#ifdef WITH_SSH
#define DEFAULT_COMPONENTS  "ssh,keyring,pkcs11"
#else
#define DEFAULT_COMPONENTS  "keyring,pkcs11"
#endif

static gboolean run_foreground = FALSE;
static gboolean run_daemonized = FALSE;
static gboolean unlock_with_login = FALSE;
static gchar* run_components = NULL;

static GOptionEntry option_entries[] = {
	{ "foreground", 'f', 0, G_OPTION_ARG_NONE, &run_foreground, 
	  "Run in the foreground", NULL }, 
	{ "daemonize", 'd', 0, G_OPTION_ARG_NONE, &run_daemonized, 
	  "Run as a daemon", NULL }, 
	{ "login", 'l', 0, G_OPTION_ARG_NONE, &unlock_with_login, 
	  "Use login password from stdin", NULL },
	{ "components", 'c', 0, G_OPTION_ARG_STRING, &run_components,
	  "The components to run", DEFAULT_COMPONENTS },
	{ NULL }
};

static void
parse_arguments (int *argc, char** argv[])
{
	GError *err = NULL;
	GOptionContext *context;
	
	context = g_option_context_new ("- The Gnome Keyring Daemon");
	g_option_context_add_main_entries (context, option_entries, GETTEXT_PACKAGE);
	
	if (!g_option_context_parse (context, argc, argv, &err)) {
		g_printerr ("gnome-keyring-daemon: %s", err && err->message ? err->message : "");
		g_clear_error (&err);
	}
	
	/* Take ownership of the string */
	if (run_components) {
		run_components = g_strdup (run_components);
		gkr_cleanup_register (g_free, run_components);
	}
	
	g_option_context_free (context);
}

static gboolean
check_conf_component (const gchar* component, gboolean *enabled)
{
	GConfClient *client;
	GConfValue *value;
	GError *err = NULL;
	gchar *key; 

	*enabled = FALSE;

	client = gconf_client_get_default ();
	g_return_val_if_fail (client, FALSE);
	
	key = g_strdup_printf ("/apps/gnome-keyring/daemon-components/%s", component);
	value = gconf_client_get (client, key, &err);
	g_free (key);
	g_object_unref (client);
	
	if (err) {
		g_printerr ("gnome-keyring-daemon: couldn't lookup %s component setting: %s", 
		            component, err->message ? err->message : "");
		g_clear_error (&err);
		return FALSE;
	}
	
	/* Value is unset */
	if (!value)
		return FALSE;		
	
	/* Should be a list of type string */
	if (value->type != GCONF_VALUE_BOOL) {
	    	g_printerr ("gnome-keyring-daemon: bad gconf value type for daemon-components");
	    	g_clear_error (&err);
	    	gconf_value_free (value);
	    	return FALSE;
	}
	
	*enabled = gconf_value_get_bool (value);
	gconf_value_free (value);
	return TRUE;
}

static gboolean
check_run_component (const char* component)
{
	const gchar *run = run_components;
	gboolean enabled;

	if (run == NULL) {

		/* Use gconf to determine whether the component should be enabled */	
		if (check_conf_component (component, &enabled))
			return enabled;
			
		/* No gconf, error or unset, use built in defaults */
		run = DEFAULT_COMPONENTS;
	}
	
	/* 
	 * Note that this assumes that no components are substrings of 
	 * one another. Which makes things quick, and simple.
	 */
	return strstr (run, component) ? TRUE : FALSE;
}

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
	if (!p) {
		if (do_warning) {
			g_message (WARNING);
			do_warning = FALSE;
		}
		
		env = g_getenv ("GNOME_KEYRING_PARANOID");
		if (env && *env) 
			g_error (ABORTMSG);
			
		return g_malloc0 (sz);
	}
	
	/* 
	 * Reallocation is a bit of a gray area, as we can be asked 
	 * by external libraries (like libgcrypt) to reallocate a 
	 * non-secure block into secure memory. We cannot satisfy 
	 * this request (as we don't know the size of the original 
	 * block) so we just try our best here.
	 */
			 
	return g_realloc (p, sz);
}

/* -----------------------------------------------------------------------------
 * LOGS
 */

static void
log_handler (const gchar *log_domain, GLogLevelFlags log_level, 
             const gchar *message, gpointer user_data)
{
    int level;

    /* Note that crit and err are the other way around in syslog */
        
    switch (G_LOG_LEVEL_MASK & log_level) {
    case G_LOG_LEVEL_ERROR:
        level = LOG_CRIT;
        break;
    case G_LOG_LEVEL_CRITICAL:
        level = LOG_ERR;
        break;
    case G_LOG_LEVEL_WARNING:
        level = LOG_WARNING;
        break;
    case G_LOG_LEVEL_MESSAGE:
        level = LOG_NOTICE;
        break;
    case G_LOG_LEVEL_INFO:
        level = LOG_INFO;
        break;
    case G_LOG_LEVEL_DEBUG:
        level = LOG_DEBUG;
        break;
    default:
        level = LOG_ERR;
        break;
    }
    
    /* Log to syslog first */
    if (log_domain)
        syslog (level, "%s: %s", log_domain, message);
    else
        syslog (level, "%s", message);
 
    /* And then to default handler for aborting and stuff like that */
    g_log_default_handler (log_domain, log_level, message, user_data); 
}

static void
prepare_logging ()
{
    GLogLevelFlags flags = G_LOG_FLAG_FATAL | G_LOG_LEVEL_ERROR | 
                G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING | 
                G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO;
                
    openlog ("gnome-keyring-daemon", LOG_PID, LOG_AUTH);
    
    g_log_set_handler (NULL, flags, log_handler, NULL);
    g_log_set_handler ("Glib", flags, log_handler, NULL);
    g_log_set_handler ("Gtk", flags, log_handler, NULL);
    g_log_set_handler ("Gnome", flags, log_handler, NULL);
    g_log_set_default_handler (log_handler, NULL);
}

static gboolean
signal_handler (guint sig, gpointer unused)
{
	g_main_loop_quit (loop);
	return TRUE;
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

static gchar*
read_login_password (int fd)
{
	/* We only accept a max of 8K as the login password */
	#define MAX_LENGTH 8192
	#define MAX_BLOCK 256
	
	gchar *buf = gkr_secure_alloc (MAX_BLOCK);
	gchar *ret = NULL;
	int r, len = 0;
	
	for (;;) {
		r = read (fd, buf, sizeof (buf));
		if (r < 0) {
			if (errno == EAGAIN)
				continue;
			gkr_secure_free (ret);
			gkr_secure_free (buf);
			return NULL;
			
		} else  { 
			char *n = gkr_secure_realloc (ret, len + r + 1);
			memset(n + len, 0, r + 1); 
			ret = n;
			len = len + r;
			
			strncat (ret, buf, r);
		}
		
		if (r == 0 || len > MAX_LENGTH)
			break;
	}
	
	gkr_secure_free (buf);
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

	fd = open ("/dev/null", O_WRONLY);
	sane_dup2 (fd, 2);
	close (fd);
}

static void
cleanup_and_exit (int code)
{
	gkr_cleanup_perform ();
	_exit (code);
}

static gboolean
lifetime_slave_pipe_io (GIOChannel  *channel,
			GIOCondition cond,
			gpointer     callback_data)
{
	cleanup_and_exit (2);
	return FALSE;
}

static void
print_environment (pid_t pid)
{
	const gchar **env;
	for (env = gkr_daemon_util_get_environment (); *env; ++env)
		printf ("%s\n", *env);
	printf ("GNOME_KEYRING_PID=%d\n", (gint)pid);
}

int
main (int argc, char *argv[])
{
	const char *env;
	int fd;
	pid_t pid;
	GIOChannel *channel;
	GMainContext *ctx;
	gchar *login_password;
	unsigned seed;
	
	g_type_init ();
	g_thread_init (NULL);
	
	parse_arguments (&argc, &argv);

#ifdef HAVE_LOCALE_H
	/* internationalisation */
	setlocale (LC_ALL, "");
#endif

#ifdef HAVE_GETTEXT
	bindtextdomain (GETTEXT_PACKAGE, GNOMELOCALEDIR);
	textdomain (GETTEXT_PACKAGE);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
#endif

	gkr_crypto_setup ();

	gcry_create_nonce (&seed, sizeof (seed));
	srand (seed);
	
	/* Initialize object storage */
	if (!gkr_pk_object_storage_initialize ())
		cleanup_and_exit (1);
	
#ifdef ROOT_CERTIFICATES
	if (!gkr_pk_root_storage_initialize ())
		cleanup_and_exit (1);
#endif

	/* Initialize the appropriate components */
	if (check_run_component ("keyring")) {
		if (!gkr_daemon_io_create_master_socket ())
			cleanup_and_exit (1);
	}

#ifdef WITH_SSH	
	if (check_run_component ("ssh")) {
		if (!gkr_daemon_ssh_io_initialize () ||
		    !gkr_ssh_storage_initialize ())
			cleanup_and_exit (1);
	}
#endif
	
	if (check_run_component ("pkcs11")) {
		if (!gkr_pkcs11_daemon_setup ())
			cleanup_and_exit (1);
	}	
	 
	/* 
	 * When --login is specified then the login password is passed 
	 * in on stdin. All data (including newlines) are part of the 
	 * password.
	 */
	login_password = unlock_with_login ? read_login_password (STDIN) : NULL;
	
	/* 
	 * The whole forking and daemonizing dance starts here.
	 */
	if (!run_foreground) {
		pid = fork ();
		
		/* An intermediate child */
		if (pid == 0) {
			if (run_daemonized) {
				pid = fork ();
				
				/* Still in the intermedate child */
				if (pid != 0) {
					gkr_secure_free (login_password);
					
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
						print_environment (pid);
						exit (0);
					}
				}
			}
			
			/* final child continues here */
			
		/* The initial process */
		} else {
			gkr_secure_free (login_password);
			
			if (run_daemonized) {
				int status;
				
				/* Initial process, waits for intermediate child */
				if (pid == -1)
					exit (1);

				waitpid (pid, &status, 0);
				if (WEXITSTATUS (status) != 0)
					exit (WEXITSTATUS (status));
				
			} else {
				print_environment (pid);
			}
			
			exit (0);
		}
		
		/* The final child ... */
		close_stdinout ();

	} else {
		print_environment (getpid ());
	}

	/* Daemon process continues here */

        /* Send all warning or error messages to syslog */
	prepare_logging();

	loop = g_main_loop_new (NULL, FALSE);
	ctx = g_main_loop_get_context (loop);
	
	signal (SIGPIPE, SIG_IGN);
	gkr_unix_signal_connect (ctx, SIGINT, signal_handler, NULL);
	gkr_unix_signal_connect (ctx, SIGHUP, signal_handler, NULL);
	gkr_unix_signal_connect (ctx, SIGTERM, signal_handler, NULL);
             
	env = getenv ("GNOME_KEYRING_LIFETIME_FD");
	if (env && env[0]) {
		fd = atoi (env);
		if (fd != 0) {
			channel = g_io_channel_unix_new (fd);
			g_io_add_watch (channel,
					G_IO_IN | G_IO_HUP,
					lifetime_slave_pipe_io, NULL);
			g_io_channel_unref (channel);
		}
		
	}
	
	gkr_async_workers_init (loop);
	
	/* 
	 * We may be launched before the DBUS session, (ie: via PAM) 
	 * and DBus tries to launch itself somehow, so double check 
	 * that it has really started.
	 */ 
	env = getenv ("DBUS_SESSION_BUS_ADDRESS");
	if (env && env[0])
		gkr_daemon_dbus_setup (loop);

	/*
	 * Unlock the login keyring if we were given a password on STDIN.
	 * If it does not exist. We create it. 
	 */
	if (unlock_with_login && login_password) {
		if (!gkr_keyring_login_unlock (login_password))
			g_warning ("Failed to unlock login on startup");
		gkr_secure_free (login_password);
	}
	
	g_main_loop_run (loop);

	/* Make sure no other threads are running */
	gkr_async_workers_stop_all ();
	
	/* This wraps everything up in order */
	gkr_cleanup_perform ();
	
	/* Final shutdown of anything workers running about */
	gkr_async_workers_uninit ();

	return 0;
}
