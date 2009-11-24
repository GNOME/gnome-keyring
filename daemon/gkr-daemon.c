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

#include "egg/egg-cleanup.h"
#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"
#include "egg/egg-unix-credentials.h"

#include "keyrings/gkr-keyring-login.h"

#include "library/gnome-keyring.h"

#include "pkcs11/gkr-pkcs11-daemon.h"

#include "ui/gkr-ask-daemon.h"

#include "util/gkr-daemon-async.h"
#include "util/gkr-daemon-util.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
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

#ifndef HAVE_SOCKLEN_T
#define socklen_t int
#endif

/* -----------------------------------------------------------------------------
 * COMMAND LINE
 */

/* All the components to run on startup if not set in gconf */
#ifdef WITH_SSH
#define DEFAULT_COMPONENTS  "ssh,pkcs11"
#else
#define DEFAULT_COMPONENTS  "pkcs11"
#endif

static gboolean run_foreground = FALSE;
static gboolean run_daemonized = FALSE;
static gboolean run_for_login = FALSE;
static gboolean run_for_start = FALSE;
static gchar* run_components = NULL;
static gchar* login_password = NULL;
static gboolean initialization_completed = FALSE;
static gboolean sig_thread_valid = FALSE;
static pthread_t sig_thread;

static GOptionEntry option_entries[] = {
	{ "foreground", 'f', 0, G_OPTION_ARG_NONE, &run_foreground, 
	  "Run in the foreground", NULL }, 
	{ "daemonize", 'd', 0, G_OPTION_ARG_NONE, &run_daemonized, 
	  "Run as a daemon", NULL }, 
	{ "login", 'l', 0, G_OPTION_ARG_NONE, &run_for_login, 
	  "Run for a user login. Read login password from stdin", NULL },
	{ "start", 's', 0, G_OPTION_ARG_NONE, &run_for_start,
	  "Start a dameon or initialize an already running daemon." },
	{ "components", 'c', 0, G_OPTION_ARG_STRING, &run_components,
	  "The optional components to run", DEFAULT_COMPONENTS },
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
		egg_cleanup_register (g_free, run_components);
	}
	
	/* Check the arguments */
	if (run_for_login && run_for_start) {
		g_printerr ("gnome-keyring-daemon: The --start option is incompatible with --login");
		run_for_login = FALSE;
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
egg_memory_lock (void)
{
	/* The daemon uses cooperative threading, and doesn't need locking */
}

void 
egg_memory_unlock (void)
{
	/* The daemon uses cooperative threading, and doesn't need locking */
}

void*
egg_memory_fallback (void *p, size_t sz)
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
printerr_handler (const gchar *string)
{
	/* Print to syslog and stderr */
	syslog (LOG_WARNING, "%s", string);
	fprintf (stderr, "%s", string);
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
    g_set_printerr_handler (printerr_handler);
}

/* -----------------------------------------------------------------------------
 * SIGNALS
 */

static sigset_t signal_set;
static gint signal_quitting = 0;

static gpointer
signal_thread (gpointer user_data)
{
	GMainLoop *loop = user_data;
	int sig, err;

	for (;;) {
		err = sigwait (&signal_set, &sig);
		if (err != EINTR && err != 0) {
			g_warning ("couldn't wait for signals: %s", g_strerror (err));
			return NULL;
		}

		switch (sig) {
		case SIGPIPE:
			/* Ignore */
			break;
		case SIGINT:
		case SIGHUP:
		case SIGTERM:
			g_atomic_int_set (&signal_quitting, 1);
			g_main_loop_quit (loop);
			return NULL;
		default:
			g_warning ("received unexpected signal when waiting for signals: %d", sig);
			break;
		}
	}

	g_assert_not_reached ();
	return NULL;
}

static void
setup_signal_handling (GMainLoop *loop)
{
	int res;

	/*
	 * Block these signals for this thread, and any threads
	 * started up after this point (so essentially all threads).
	 *
	 * We also start a signal handling thread which uses signal_set
	 * to catch the various signals we're interested in.
	 */

	sigemptyset (&signal_set);
	sigaddset (&signal_set, SIGPIPE);
	sigaddset (&signal_set, SIGINT);
	sigaddset (&signal_set, SIGHUP);
	sigaddset (&signal_set, SIGTERM);
	pthread_sigmask (SIG_BLOCK, &signal_set, NULL);

	res = pthread_create (&sig_thread, NULL, signal_thread, loop);
	if (res == 0) {
		sig_thread_valid = TRUE;
	} else {
		g_warning ("couldn't startup thread for signal handling: %s",
		           g_strerror (res));
	}
}

void
gkr_daemon_quit (void)
{
	/*
	 * Send a signal to terminate our signal thread,
	 * which in turn runs stops the main loop and that
	 * starts the shutdown process.
	 */

	if (sig_thread_valid)
		pthread_kill (sig_thread, SIGTERM);
	else
		raise (SIGTERM);
}

static void
cleanup_signal_handling (void)
{
	/* The thread is not joinable, so cleans itself up */
	if (!g_atomic_int_get (&signal_quitting))
		g_warning ("gkr_daemon_quit() was not used to shutdown the daemon");
}

/* -----------------------------------------------------------------------------
 * STARTUP
 */

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

	/* 
	 * When --login is specified then the login password is passed 
	 * in on stdin. All data (including newlines) are part of the 
	 * password.
	 */
	
	gchar *buf = egg_secure_alloc (MAX_BLOCK);
	gchar *ret = NULL;
	int r, len = 0;
	
	for (;;) {
		r = read (fd, buf, sizeof (buf));
		if (r < 0) {
			if (errno == EAGAIN)
				continue;
			egg_secure_free (ret);
			egg_secure_free (buf);
			return NULL;
			
		} else  { 
			char *n = egg_secure_realloc (ret, len + r + 1);
			memset(n + len, 0, r + 1); 
			ret = n;
			len = len + r;
			
			strncat (ret, buf, r);
		}
		
		if (r == 0 || len > MAX_LENGTH)
			break;
	}
	
	egg_secure_free (buf);
	return ret;
}

static void
cleanup_and_exit (int code)
{
	egg_cleanup_perform ();
	exit (code);
}

static void
clear_login_password (void)
{
	if(login_password)
		egg_secure_strfree (login_password);
	login_password = NULL;
}

static gboolean
lifetime_slave_pipe_io (GIOChannel  *channel,
			GIOCondition cond,
			gpointer     callback_data)
{
	egg_cleanup_perform ();
	_exit (2);
	return FALSE;
}

static void
slave_lifetime_to_fd (void)
{
	const char *env;
	GIOChannel *channel;
	int fd;
	
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
}

static void
print_environment (pid_t pid)
{
	const gchar **env;
	for (env = gkr_daemon_util_get_environment (); *env; ++env)
		printf ("%s\n", *env);
	if (pid)
		printf ("GNOME_KEYRING_PID=%d\n", (gint)pid);
}

static gboolean
initialize_other_running_daemon (int sock)
{
	GnomeKeyringResult res;
	gchar **envp, **e;
	EggBuffer buf;
	gboolean ret;
	
	if (egg_unix_credentials_write (sock) < 0)
		return FALSE;

	egg_buffer_init_full (&buf, 128, g_realloc);
	
	envp = gnome_keyring_build_environment (GNOME_KEYRING_IN_ENVIRONMENT);
	ret = gkr_proto_encode_prepare_environment (&buf, (const gchar**)envp);
	g_strfreev (envp);
	
	if (!ret) {
		egg_buffer_uninit (&buf);
		g_return_val_if_reached (FALSE);
	}

	envp = NULL;

	ret = gnome_keyring_socket_write_buffer (sock, &buf) && 
	      gnome_keyring_socket_read_buffer (sock, &buf) && 
	      gkr_proto_decode_prepare_environment_reply (&buf, &res, &envp);
	
	
	egg_buffer_uninit (&buf);
	
	if(!ret) {
		g_warning ("couldn't initialize running daemon");
		return FALSE;
	}

	if (res == GNOME_KEYRING_RESULT_OK) {
		g_return_val_if_fail (envp, FALSE);
		for (e = envp; *e; ++e)
			gkr_daemon_util_push_environment_full (*e);
		ret = TRUE;
	} else {
		g_warning ("couldn't initialize running daemon: %s", gnome_keyring_result_to_message (res));
		ret = FALSE;
	}
	
	g_strfreev (envp);

	return ret;
}

static gboolean
start_or_initialize_daemon (void)
{
	gboolean ret;
	int sock;
	
	/* 
	 * Is a daemon already running? If not we need to run
	 * a daemon process, just return and let things go 
	 * their normal way. 
	 */
	sock = gnome_keyring_socket_connect_daemon (FALSE, TRUE);
	if (sock == -1)
		return FALSE;
	
	ret = initialize_other_running_daemon (sock);
	close (sock);
	
	/* Initialization failed, start this process up as a daemon */
	if (!ret)
		return FALSE;
	
	/* 
	 * Now we've initialized the daemon, we need to print out 
	 * the daemon's environment for any callers, and possibly
	 * block if we've been asked to remain in the foreground.
	 */
	print_environment (0);
	
	/* TODO: Better way to sleep forever? */
	if (run_foreground) {
		while (sleep(0x08000000) == 0);
	}
	
	return TRUE;
}

static void
fork_and_print_environment (void)
{
	int status;
	pid_t pid;
	int fd, i;

	if (run_foreground) {
		print_environment (getpid ());
		return;
	}
	
	pid = fork ();
		
	if (pid != 0) {

		/* Here we are in the initial process */

		if (run_daemonized) {
			
			/* Initial process, waits for intermediate child */
			if (pid == -1)
				exit (1);

			waitpid (pid, &status, 0);
			if (WEXITSTATUS (status) != 0)
				exit (WEXITSTATUS (status));
			
		} else {
			/* Not double forking, we know the PID */
			print_environment (pid);
		}

		/* The initial process exits successfully */
		exit (0);
	}
	
	if (run_daemonized) { 
		
		/* Double fork if need to daemonize properly */
		pid = fork ();
	
		if (pid != 0) {

			/* Here we are in the intermediate child process */
				
			/* 
			 * This process exits, so that the final child will inherit 
			 * init as parent to avoid zombies
			 */
			if (pid == -1)
				exit (1);
	
			/* We've done two forks. Now we know the PID */
			print_environment (pid);
				
			/* The intermediate child exits */
			exit (0);
		}
		
	}

	/* Here we are in the resulting daemon or background process. */

	for (i = 0; i < 3; ++i) {
		fd = open ("/dev/null", O_RDONLY);
		sane_dup2 (fd, i);
		close (fd);
	}
}

static gboolean
gkr_daemon_startup_steps (void)
{
	/* Startup the appropriate components, creates sockets etc.. */
#ifdef WITH_SSH	
	if (check_run_component ("ssh")) {
		if (!gkr_pkcs11_daemon_startup_ssh ())
			return FALSE;
	}
#endif

	if (check_run_component ("pkcs11")) {
		if (!gkr_pkcs11_daemon_startup_pkcs11 ())
			return FALSE;
	}

	return TRUE;
}

static gboolean
gkr_daemon_initialize_steps (void)
{
	/* Initialize new style PKCS#11 components */
	if (!gkr_pkcs11_daemon_initialize ())
		return FALSE;

	gkr_daemon_dbus_initialize ();
	return TRUE;
}

void
gkr_daemon_complete_initialization (void)
{
	/*
	 * Sometimes we don't initialize the full daemon right on 
	 * startup. When run with --login is one such case.
	 */

	if (initialization_completed) {
		g_message ("The daemon was already initialized.");
		return;
	}

	/* Set this early so that two initializations don't overlap */
	initialization_completed = TRUE;
	gkr_daemon_startup_steps ();
	gkr_daemon_initialize_steps ();
}

int
main (int argc, char *argv[])
{
	GMainContext *ctx;
	GMainLoop *loop;

	/* 
	 * The gnome-keyring startup is not as simple as I wish it could be. 
	 * 
	 * It's often started in the primidoral stages of a session, where 
	 * there's no DBus, no GConf, and no proper X display. This is the 
	 * strange world of PAM.
	 * 
	 * When started with the --login option, we do as little initialization
	 * as possible. We expect a login password on the stdin, and unlock
	 * or create the login keyring.
	 * 
	 * Then later we expect gnome-keyring-dameon to be run again with the 
	 * --start option. This second gnome-keyring-daemon will hook the
	 * original daemon up with environment variables necessary to initialize
	 * itself and bring it into the session. This second daemon usually exits.
	 * 
	 * Without either of these options, we follow a more boring and 
	 * predictable startup.  
	 */
	
	g_type_init ();
	g_thread_init (NULL);
	
#ifdef HAVE_LOCALE_H
	/* internationalisation */
	setlocale (LC_ALL, "");
#endif

#ifdef HAVE_GETTEXT
	bindtextdomain (GETTEXT_PACKAGE, GNOMELOCALEDIR);
	textdomain (GETTEXT_PACKAGE);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
#endif

	egg_libgcrypt_initialize ();
	
	/* Send all warning or error messages to syslog */
	prepare_logging ();
	
	parse_arguments (&argc, &argv);
	
	/* The --start option */
	if (run_for_start) {
		if (start_or_initialize_daemon ())
			cleanup_and_exit (0);
	} 

	/* Initialize our daemon main loop and threading */
	loop = g_main_loop_new (NULL, FALSE);
	ctx = g_main_loop_get_context (loop);
	gkr_daemon_async_workers_init (loop);
	
	/* 
	 * Always initialize the keyring subsystem. This is a necessary
	 * component that everything else depends on in one way or 
	 * another. 
	 */
	if (!gkr_daemon_io_create_master_socket ())
		cleanup_and_exit (1);

	/* The --login option. Delayed initialization */
	if (run_for_login) {
		login_password = read_login_password (STDIN);
		atexit (clear_login_password);

	/* Not a login daemon. Startup stuff now.*/
	} else {
		/* These are things that can run before forking */
		if (!gkr_daemon_startup_steps ())
			cleanup_and_exit (1);
	}

	/* The whole forking and daemonizing dance starts here. */
	fork_and_print_environment();

	setup_signal_handling (loop);

	/* Prepare logging a second time, since we may be in a different process */
	prepare_logging();

	/* Remainder initialization after forking, if initialization not delayed */
	if (!run_for_login) {
		initialization_completed = TRUE;
		gkr_daemon_initialize_steps ();
	}

	/* TODO: Do we still need this? XFCE still seems to use it. */
	slave_lifetime_to_fd ();

	/*
	 * Unlock the login keyring if we were given a password on STDIN.
	 * If it does not exist. We create it. 
	 */
	if (login_password) {
		if (!gkr_keyring_login_unlock (login_password))
			g_message ("Failed to unlock login on startup");
		egg_secure_strclear (login_password);
	}
	
	g_main_loop_run (loop);

	/* Make sure no other threads are running */
	gkr_daemon_async_workers_stop_all ();
	
	/* This wraps everything up in order */
	egg_cleanup_perform ();
	
	/* Final shutdown of anything workers running about */
	gkr_daemon_async_workers_uninit ();

	/* Wrap up signal handling here */
	cleanup_signal_handling ();

	return 0;
}
