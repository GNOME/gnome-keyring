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
   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkd-glue.h"
#include "gkd-main.h"
#include "gkd-capability.h"
#include "gkd-pkcs11.h"
#include "gkd-util.h"

#include "control/gkd-control.h"

#include "dbus/gkd-dbus.h"

#include "egg/egg-cleanup.h"
#include "egg/egg-error.h"
#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"
#include "egg/egg-unix-credentials.h"

#include "login/gkd-login.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <gio/gunixinputstream.h>
#include <gio/gunixoutputstream.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <glib-unix.h>

#include <gcrypt.h>

/* preset file descriptors */
#define  STDIN   0
#define  STDOUT  1
#define  STDERR  2

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#define GKD_COMP_KEYRING    "keyring"
#define GKD_COMP_PKCS11     "pkcs11"
#define GKD_COMP_SECRETS    "secrets"
#define GKD_COMP_SSH        "ssh"

EGG_SECURE_DECLARE (daemon_main);

/* -----------------------------------------------------------------------------
 * COMMAND LINE
 */

/* All the components to run on startup if not specified on command line */
#ifdef WITH_SSH
#	ifdef WITH_GPG
#		define DEFAULT_COMPONENTS  GKD_COMP_PKCS11 "," GKD_COMP_SECRETS "," GKD_COMP_SSH "," GKD_COMP_GPG
#	else
#		define DEFAULT_COMPONENTS  GKD_COMP_PKCS11 "," GKD_COMP_SECRETS "," GKD_COMP_SSH
#	endif
#else
#	ifdef WITH_GPG
#		define DEFAULT_COMPONENTS  GKD_COMP_PKCS11 "," GKD_COMP_SECRETS  "," GKD_COMP_GPG
#	else
#		define DEFAULT_COMPONENTS  GKD_COMP_PKCS11 "," GKD_COMP_SECRETS
#	endif
#endif

/*
 * If --login is used and then daemon is not initialized within LOGIN_TIMEOUT
 * seconds, then we exit. See on_login_timeout() below.
 */

#define LOGIN_TIMEOUT 120

static char *run_components = NULL;
static gboolean pkcs11_started = FALSE;
static gboolean secrets_started = FALSE;
static gboolean dbus_started = FALSE;

static gboolean run_foreground = FALSE;
static gboolean run_daemonized = FALSE;
static gboolean run_version = FALSE;
static gboolean run_for_login = FALSE;
static gboolean perform_unlock = FALSE;
static gboolean run_for_start = FALSE;
static gboolean run_for_replace = FALSE;
static gchar* login_password = NULL;
static gchar* control_directory = NULL;
static guint timeout_id = 0;
static gboolean initialization_completed = FALSE;
static GMainLoop *loop = NULL;
static int parent_wakeup_fd = -1;
static GDBusConnection *system_bus_connection = NULL;

static GOptionEntry option_entries[] = {
	{ "start", 's', 0, G_OPTION_ARG_NONE, &run_for_start,
	  "Start a dameon or initialize an already running daemon." },
	{ "replace", 'r', 0, G_OPTION_ARG_NONE, &run_for_replace,
	  "Replace the daemon for this desktop login environment." },
	{ "foreground", 'f', 0, G_OPTION_ARG_NONE, &run_foreground,
	  "Run in the foreground", NULL },
	{ "daemonize", 'd', 0, G_OPTION_ARG_NONE, &run_daemonized,
	  "Run as a daemon", NULL },
	{ "login", 'l', 0, G_OPTION_ARG_NONE, &run_for_login,
	  "Run by PAM for a user login. Read login password from stdin", NULL },
	{ "unlock", 0, 0, G_OPTION_ARG_NONE, &perform_unlock,
	  "Prompt for login keyring password, or read from stdin", NULL },
	{ "components", 'c', 0, G_OPTION_ARG_STRING, &run_components,
	  "The optional components to run", DEFAULT_COMPONENTS },
	{ "control-directory", 'C', 0, G_OPTION_ARG_FILENAME, &control_directory,
	  "The directory for sockets and control data", NULL },
	{ "version", 'V', 0, G_OPTION_ARG_NONE, &run_version,
	  "Show the version number and exit.", NULL },
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
		g_printerr ("gnome-keyring-daemon: %s\n", egg_error_message (err));
		g_clear_error (&err);
	}

	if (!run_components || !run_components[0]) {
		g_free (run_components); /* Don't leak "" */
		run_components = g_strdup (DEFAULT_COMPONENTS);
	}
	egg_cleanup_register (g_free, run_components);

	/* Check the arguments */
	if (run_for_login && run_for_start) {
		g_printerr ("gnome-keyring-daemon: The --start option is incompatible with --login\n");
		run_for_login = FALSE;
	}

	if (run_for_login && run_for_replace) {
		g_printerr ("gnome-keyring-daemon: The --replace option is incompatible with --login\n");
		run_for_login = FALSE;
	}

	if (run_for_start && run_for_replace) {
		g_printerr ("gnome-keyring-daemon: The --replace option is incompatible with --start\n");
		run_for_start = FALSE;
	}

	if (run_for_start && perform_unlock) {
		g_printerr ("gnome-keyring-daemon: The --start option is incompatible with --unlock");
		perform_unlock = FALSE;
	}

	if (run_for_login)
		perform_unlock = TRUE;

	g_option_context_free (context);
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

G_LOCK_DEFINE_STATIC (memory_mutex);

static void
egg_memory_lock (void)
{
	G_LOCK (memory_mutex);
}

static void
egg_memory_unlock (void)
{
	G_UNLOCK (memory_mutex);
}

static void *
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

EGG_SECURE_DEFINE_GLOBALS (egg_memory_lock, egg_memory_unlock, egg_memory_fallback);

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
		level = -1;
		break;
	default:
		level = LOG_ERR;
		break;
	}

	/* Log to syslog first */
	if (level != -1) {
		if (log_domain)
			syslog (level, "%s: %s", log_domain, message);
		else
			syslog (level, "%s", message);
	}

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

#ifdef WITH_DEBUG

static void
dump_diagnostics (void)
{
	egg_secure_rec *records;
	egg_secure_rec *rec;
	unsigned int count, i;
	GHashTable *table;
	GHashTableIter iter;
	gsize request = 0;
	gsize block = 0;

	g_printerr ("------------------- Secure Memory --------------------\n");
	g_printerr (" Tag                          Used            Space\n");
	g_printerr ("------------------------------------------------------\n");

	records = egg_secure_records (&count);
	table = g_hash_table_new (g_str_hash, g_str_equal);
	for (i = 0; i < count; i++) {
		if (!records[i].tag)
			records[i].tag = "<unused>";
		rec = g_hash_table_lookup (table, records[i].tag);
		if (rec == NULL)
			g_hash_table_insert (table, (gchar *)records[i].tag, &records[i]);
		else {
			rec->block_length += records[i].block_length;
			rec->request_length += records[i].request_length;
		}
		block += records[i].block_length;
		request += records[i].request_length;
	}

	g_hash_table_iter_init (&iter, table);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *)&rec))
		g_printerr (" %-20s %12lu %16lu\n", rec->tag,
		            (unsigned long)rec->request_length,
		            (unsigned long)rec->block_length);

	if (count > 0)
		g_printerr ("------------------------------------------------------\n");

	g_printerr (" %-20s %12lu %16lu\n", "Total",
	            (unsigned long)request, (unsigned long)block);
	g_printerr ("------------------------------------------------------\n");

	g_hash_table_destroy (table);
	free (records);
}

#endif /* WITH_DEBUG */

/* -----------------------------------------------------------------------------
 * SIGNALS
 */

void
gkd_main_quit (void)
{
	/* Always stop accepting control connections immediately */
	gkd_control_stop ();
	g_main_loop_quit (loop);
}

static gboolean
on_signal_term (gpointer user_data)
{
	gkd_main_quit ();
	g_debug ("received signal, terminating");
	return FALSE;
}

static gboolean
on_signal_usr1 (gpointer user_data)
{
#ifdef WITH_DEBUG
	dump_diagnostics ();
#endif
	return TRUE;
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
	 * password. A zero length password is no password.
	 */

	gchar *buf = egg_secure_alloc (MAX_BLOCK);
	gchar *ret = NULL;
	int r, len = 0;

	for (;;) {
		r = read (fd, buf, MAX_BLOCK);
		if (r < 0) {
			if (errno == EAGAIN)
				continue;
			egg_secure_free (ret);
			egg_secure_free (buf);
			return NULL;

		} else if (r == 0 || len > MAX_LENGTH) {
			break;

		} else {
			ret = egg_secure_realloc (ret, len + r + 1);
			memset (ret + len, 0, r + 1);
			len = len + r;
			strncat (ret, buf, r);
		}
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

static void
print_environment (void)
{
	const gchar **env;
	for (env = gkd_util_get_environment (); *env; ++env)
		printf ("%s\n", *env);
	fflush (stdout);
}

static gboolean
initialize_daemon_at (const gchar *directory)
{
	gchar **ourenv, **daemonenv, **e;

	/* Exchange environment variables, and try to initialize daemon */
	ourenv = gkd_util_build_environment (GKD_UTIL_IN_ENVIRONMENT);
	daemonenv = gkd_control_initialize (directory, run_components,
	                                    (const gchar**)ourenv);
	g_strfreev (ourenv);

	/* Initialization failed, start this process up as a daemon */
	if (!daemonenv)
		return FALSE;

	/* Setup all the environment variables we were passed */
	for (e = daemonenv; *e; ++e)
		gkd_util_push_environment_full (*e);
	g_strfreev (daemonenv);

	return TRUE;
}

static gboolean
replace_daemon_at (const gchar *directory)
{
	gboolean ret;

	/*
	 * The first control_directory is the environment one, always
	 * prefer that since it's the one that ssh will connect to
	 */
	if (control_directory == NULL)
		control_directory = g_strdup (directory);

	ret = gkd_control_quit (directory, GKD_CONTROL_QUIET_IF_NO_PEER);

	/*
	 * If we quit, wait a short time before initializing so the other
	 * daemon can quit completely
	 */
	if (ret == TRUE)
		g_usleep (200 * 1000); /* 200 ms in us */

	/*
	 * Note that we don't return TRUE, since we want to quit all the
	 * running daemons (for this session) that may have been started
	 * by dbus or elsewhere.
	 */

	return FALSE;
}

typedef gboolean (*DiscoverFunc) (const gchar *control_directory);

static gboolean
discover_other_daemon (DiscoverFunc callback, gboolean acquire)
{
	const gchar *control_env;
	gchar *control = NULL;
	gboolean acquired = FALSE;
	gboolean ret;

	/* A pre-specified directory to control at, don't try anything else */
	if (control_directory)
		return (callback) (control_directory);

	/* An environment variable from an already running daemon */
	control_env = g_getenv (GKD_UTIL_ENV_CONTROL);
	if (control_env && control_env[0]) {
		if ((callback)(control_env))
			return TRUE;
	}

	/* Or the default location when no evironment variable */
	control_env = g_getenv ("XDG_RUNTIME_DIR");
	if (control_env) {
		control = g_build_filename (control_env, "keyring", NULL);
		ret = (callback) (control);
		g_free (control);
		g_printerr ("discover_other_daemon: %d", ret);
		if (ret == TRUE)
			return TRUE;
	}

	/* See if we can contact a daemon running, that didn't set an env variable */
	if (acquire && !gkd_dbus_singleton_acquire (&acquired))
		return FALSE;

	/* We're the main daemon */
	if (acquired)
		return FALSE;

	control = gkd_dbus_singleton_control ();
	if (control) {
		ret = (callback) (control);
		g_free (control);
		if (ret == TRUE)
			return TRUE;
	}

	return FALSE;
}

static void
redirect_fds_after_fork (void)
{
	int fd, i;

	for (i = 0; i < 3; ++i) {
		fd = open ("/dev/null", O_RDONLY);
		sane_dup2 (fd, i);
		close (fd);
	}
}

static void
block_on_fd (int fd)
{
	unsigned char dummy;
	read (fd, &dummy, 1);
}

static int
fork_and_print_environment (void)
{
	int status;
	pid_t pid;
	int wakeup_fds[2] = { -1, -1 };

	if (run_foreground) {
		return -1;
	}

	if (!g_unix_open_pipe (wakeup_fds, FD_CLOEXEC, NULL))
		exit (1);

	pid = fork ();

	if (pid != 0) {
		/* Here we are in the initial process */
		close (wakeup_fds[1]);

		if (run_daemonized) {

			/* Initial process, waits for intermediate child */
			if (pid == -1)
				exit (1);

			waitpid (pid, &status, 0);
			if (WEXITSTATUS (status) != 0)
				exit (WEXITSTATUS (status));

		} else {
			/* Not double forking, wait for child */
			block_on_fd (wakeup_fds[0]);
		}

		/* The initial process exits successfully */
		exit (0);
	}

	if (run_daemonized) {

		/*
		 * Become session leader of a new session, process group leader of a new
		 * process group, and detach from the controlling TTY, so that SIGHUP is
		 * not sent to this process when the previous session leader dies
		 */
		setsid ();

		/* Double fork if need to daemonize properly */
		pid = fork ();

		if (pid != 0) {
			close (wakeup_fds[1]);

			/* Here we are in the intermediate child process */

			/*
			 * This process exits, so that the final child will inherit
			 * init as parent to avoid zombies
			 */
			if (pid == -1)
				exit (1);

			/* We've done two forks. */
			block_on_fd (wakeup_fds[0]);

			/* The intermediate child exits */
			exit (0);
		}

	}

	/* Here we are in the resulting daemon or background process. */
	return wakeup_fds[1];
}

static gboolean
gkr_daemon_startup_steps (const gchar *components)
{
	g_assert (components);

	/*
	 * Startup that must run before forking.
	 * Note that we set initialized flags early so that two
	 * initializations don't overlap
	 */

#ifdef WITH_SSH
        static gboolean ssh_started = FALSE;

	if (strstr (components, GKD_COMP_SSH)) {
		if (ssh_started) {
			g_message ("The SSH agent was already initialized");
		} else {
			ssh_started = TRUE;
			if (!gkd_daemon_startup_ssh ()) {
				ssh_started = FALSE;
				return FALSE;
			}
		}
	}
#endif

	return TRUE;
}

static gboolean
gkr_daemon_initialize_steps (const gchar *components)
{
	g_assert (components);

	/*
	 * Startup that can run after forking.
	 * Note that we set initialized flags early so that two
	 * initializations don't overlap
	 */

	if (!initialization_completed) {

		/* The LANG environment variable may have changed */
		setlocale (LC_ALL, "");

		initialization_completed = TRUE;
		if (timeout_id)
			g_source_remove (timeout_id);

		/* Initialize new style PKCS#11 components */
		if (!gkd_pkcs11_initialize ())
			return FALSE;

		/*
		 * Unlock the login keyring if we were given a password on STDIN.
		 * If it does not exist. We create it.
		 */
		if (login_password) {
			if (!gkd_login_unlock (login_password))
				g_message ("failed to unlock login keyring on startup");
			egg_secure_strclear (login_password);
		}

		dbus_started = TRUE;
		if (!gkd_dbus_setup ())
			dbus_started = FALSE;
	}

	/* The Secret Service API */
	if (strstr (components, GKD_COMP_SECRETS) || strstr (components, GKD_COMP_KEYRING)) {
		if (secrets_started) {
			g_message ("The Secret Service was already initialized");
		} else {
			if (!dbus_started) {
				dbus_started = TRUE;
				if (!gkd_dbus_setup ())
					dbus_started = FALSE;
			}
			if (dbus_started) {
				secrets_started = TRUE;
				if (!gkd_dbus_secrets_startup ()) {
					secrets_started = FALSE;
					return FALSE;
				}
			}
		}
	}

	/* The PKCS#11 remoting */
	if (strstr (components, GKD_COMP_PKCS11)) {
		if (pkcs11_started) {
			g_message ("The PKCS#11 component was already initialized");
		} else {
			pkcs11_started = TRUE;
			if (!gkd_pkcs11_startup_pkcs11 ()) {
				pkcs11_started = FALSE;
				return FALSE;
			}
		}
	}

	return TRUE;
}

void
gkd_main_complete_initialization (const gchar *components)
{
	g_assert (components);

	/*
	 * Sometimes we don't initialize the full daemon right on
	 * startup. When run with --login is one such case.
	 */

	gkr_daemon_startup_steps (components);
	gkr_daemon_initialize_steps (components);
}

static gboolean
on_login_timeout (gpointer data)
{
	if (!initialization_completed)
		cleanup_and_exit (0);
	return FALSE;
}

static void
on_vanished_quit_loop (GDBusConnection *connection,
                       const gchar *name,
                       gpointer user_data)
{
	g_main_loop_quit (user_data);
}

static void on_logind_session_property_get (GObject *connection,
					    GAsyncResult *res,
					    gpointer user_data G_GNUC_UNUSED)
{
	GError *error = NULL;
	GVariant *result, *resultv;
	const gchar *state;
	gboolean should_quit;

	result = g_dbus_connection_call_finish (G_DBUS_CONNECTION (connection), res, &error);

	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_critical ("%s Couldn't get session state: %s", G_STRLOC, error->message);
		g_error_free (error);
		return;
	}

	g_variant_get (result, "(v)", &resultv, NULL);
	state = g_variant_get_string (resultv, NULL);

	should_quit = g_strcmp0 (state, "closing") == 0;

	g_clear_pointer (&result, g_variant_unref);
	g_clear_pointer (&resultv, g_variant_unref);

	/* yes, the session is closing, so we'll quit now */
	if (should_quit)
		cleanup_and_exit (0);
}

static void on_logind_session_properties_changed (GDBusConnection *connection,
						  const gchar *sender_name G_GNUC_UNUSED,
						  const gchar *object_path,
						  const gchar *interface_name G_GNUC_UNUSED,
						  const gchar *signal_name G_GNUC_UNUSED,
						  GVariant *parameters,
						  gpointer user_data G_GNUC_UNUSED)
{
	const gchar *prop_iface;
	gboolean active;
	GVariant* changed_properties;

	g_variant_get (parameters, "(&s@a{sv}^as)", &prop_iface, &changed_properties, NULL);

	if (g_variant_lookup (changed_properties, "Active", "b", &active, NULL)) {
		if (!active) {
			/* ok, the session went inactive, let's see if that is because
			 * it is closing */
			g_dbus_connection_call (
				connection,
				"org.freedesktop.login1",
				object_path,
				"org.freedesktop.DBus.Properties",
				"Get",
				g_variant_new ("(ss)", prop_iface, "State"),
				G_VARIANT_TYPE ("(v)"),
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				NULL,
				on_logind_session_property_get,
				NULL
			);
		}
	}

	g_variant_unref (changed_properties);
}

static void
on_logind_object_path_get (GObject *connection,
			   GAsyncResult *res,
			   gpointer user_data G_GNUC_UNUSED)
{
	GError *error = NULL;
	GVariant *result;
	const gchar *object_path;
	gchar *remote_error;
	gboolean is_cancelled, is_name_has_no_owner;

	result = g_dbus_connection_call_finish (G_DBUS_CONNECTION (connection), res, &error);

	/* If there's an error we always want to quit - but we only tell the
	 * user about it if something went wrong. Cancelling the operation or
	 * not having logind available are okay. */
	if (error) {
		is_cancelled = g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);

		remote_error = g_dbus_error_get_remote_error (error);
		is_name_has_no_owner = g_strcmp0 (remote_error, "org.freedesktop.DBus.Error.NameHasNoOwner") == 0;

		if (!is_cancelled && !is_name_has_no_owner)
			g_critical ("%s Couldn't get object path: %s", G_STRLOC, error->message);

		g_free (remote_error);
		g_error_free (error);
		return;
	}

	/* now we know which object path to look on, watch for
	 * PropertiesChanged. Note that, per logind's documentation, we only
	 * get notified for 'Active' changing */
	g_variant_get (result, "(&o)", &object_path, NULL);

	g_dbus_connection_signal_subscribe (
		G_DBUS_CONNECTION (connection),
		"org.freedesktop.login1",
		"org.freedesktop.DBus.Properties",
		"PropertiesChanged",
		object_path,
		NULL,
		G_DBUS_SIGNAL_FLAGS_NONE,
		on_logind_session_properties_changed,
		NULL,
		NULL
	);

	g_clear_pointer (&result, g_variant_unref);
}

static void
start_watching_logind_for_session_closure ()
{
	g_return_if_fail (system_bus_connection != NULL);

	const gchar *xdg_session_id;

	xdg_session_id = g_getenv ("XDG_SESSION_ID");

	if (!xdg_session_id)
		return;

	/* get the right object path */
	g_dbus_connection_call (
		system_bus_connection,
		"org.freedesktop.login1",
		"/org/freedesktop/login1",
		"org.freedesktop.login1.Manager",
		"GetSession",
		g_variant_new ("(s)", xdg_session_id, NULL),
		G_VARIANT_TYPE ("(o)"),
		G_DBUS_CALL_FLAGS_NO_AUTO_START,
		-1,
		NULL,
		on_logind_object_path_get,
		NULL
	);
}

int
main (int argc, char *argv[])
{
	/*
	 * The gnome-keyring startup is not as simple as I wish it could be.
	 *
	 * It's often started in the primordial stages of a session, where
	 * there's no DBus, and no proper X display. This is the strange world
	 * of PAM.
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

	GDBusConnection *connection = NULL;
	GError *error = NULL;

	/*
	 * Before we do ANYTHING, we drop privileges so we don't become
	 * a security issue ourselves.
	 */
	gkd_capability_obtain_capability_and_drop_privileges ();

#ifdef WITH_STRICT
	g_setenv ("DBUS_FATAL_WARNINGS", "1", FALSE);
	if (!g_getenv ("G_DEBUG"))
		g_log_set_always_fatal (G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING);
#endif

#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif

	/* internationalisation */
	setlocale (LC_ALL, "");

#ifdef HAVE_GETTEXT
	bindtextdomain (GETTEXT_PACKAGE, GNOMELOCALEDIR);
	textdomain (GETTEXT_PACKAGE);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
#endif

	egg_libgcrypt_initialize ();

	/* Send all warning or error messages to syslog */
	prepare_logging ();

	parse_arguments (&argc, &argv);

	/* The --version option. This is machine parseable output */
	if (run_version) {
		g_print ("gnome-keyring-daemon: %s\n", VERSION);
		g_print ("testing: %s\n",
#ifdef WITH_DEBUG
		         "enabled");
#else
		         "disabled");
#endif
		exit (0);
	}

	if (perform_unlock) {
		login_password = read_login_password (STDIN);
		atexit (clear_login_password);
	}

	/* The whole forking and daemonizing dance starts here. */
	parent_wakeup_fd = fork_and_print_environment();

	/* The --start option */
	if (run_for_start) {
		if (discover_other_daemon (initialize_daemon_at, TRUE)) {
			/*
			 * Another daemon was initialized, print out environment,
			 * tell parent we're done, and quit or go comatose.
			 */
			print_environment ();
			close (parent_wakeup_fd);
			if (run_foreground) {
				connection = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
				if (error) {
					g_warning ("Couldn't connect to session bus: %s", error->message);
					g_clear_error (&error);
				}
				loop = g_main_loop_new (NULL, FALSE);
				g_bus_watch_name (G_BUS_TYPE_SESSION, "org.gnome.keyring",
				                  G_BUS_NAME_WATCHER_FLAGS_NONE,
				                  NULL, on_vanished_quit_loop, loop, NULL);
				g_main_loop_run (loop);
				g_clear_pointer (&loop, g_main_loop_unref);
				g_clear_object (&connection);
			}
			cleanup_and_exit (0);
		}

	/* The --replace option */
	} else if (run_for_replace) {
		discover_other_daemon (replace_daemon_at, FALSE);
		if (control_directory)
			g_message ("Replacing daemon, using directory: %s", control_directory);
		else
			g_message ("Could not find daemon to replace, staring normally");
	}

	/* Initialize the main directory */
	gkd_util_init_master_directory (control_directory);

	/* Initialize our daemon main loop and threading */
	loop = g_main_loop_new (NULL, FALSE);

	/* Initialize our control socket */
	if (!gkd_control_listen ())
		return FALSE;

	/* The --login option. Delayed initialization */
	if (run_for_login) {
		timeout_id = g_timeout_add_seconds (LOGIN_TIMEOUT, (GSourceFunc) on_login_timeout, NULL);

	/* Not a login daemon. Startup stuff now.*/
	} else {
		/* These are things that can run before forking */
		if (!gkr_daemon_startup_steps (run_components))
			cleanup_and_exit (1);
	}

	/* if we can get a connection to the system bus, watch it and then kill
	 * ourselves when our session closes */

	system_bus_connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, NULL);

	if (system_bus_connection)
		start_watching_logind_for_session_closure ();

	signal (SIGPIPE, SIG_IGN);

	/* Print the environment and tell the parent we're done */
	print_environment ();

	if (!run_foreground) {
		close (parent_wakeup_fd);
		redirect_fds_after_fork ();
	}

	g_unix_signal_add (SIGTERM, on_signal_term, loop);
	g_unix_signal_add (SIGHUP, on_signal_term, loop);
	g_unix_signal_add (SIGUSR1, on_signal_usr1, loop);

	/* Prepare logging a second time, since we may be in a different process */
	prepare_logging();

	/* Remainder initialization after forking, if initialization not delayed */
	if (!run_for_login) {
		gkr_daemon_initialize_steps (run_components);

		/*
		 * Close stdout and so that the caller knows that we're
		 * all initialized, (when run in foreground mode).
		 *
		 * However since some logging goes to stdout, redirect that
		 * to stderr. We don't want the caller confusing that with
		 * valid output anyway.
		 */
		if (dup2 (2, 1) < 1)
			g_warning ("couldn't redirect stdout to stderr");

		g_debug ("initialization complete");
	}

	g_main_loop_run (loop);

	/* This wraps everything up in order */
	egg_cleanup_perform ();

	g_free (control_directory);

	g_debug ("exiting cleanly");
	return 0;
}
