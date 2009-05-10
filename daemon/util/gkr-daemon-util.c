/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-daemon-util.c - Helper utilities for the daemon

   Copyright (C) 2007, Stefan Walter

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

#include "config.h"

#include "gkr-daemon-async.h"
#include "gkr-daemon-util.h"

#include "egg/egg-cleanup.h"

#include <glib.h>

#include <sys/stat.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

enum {
	PROP_0,
	PROP_PID,
	PROP_APP_PATH,
	PROP_APP_DISPLAY
};

enum {
	DISCONNECTED,
	LAST_SIGNAL
};

G_DEFINE_TYPE (GkrDaemonClient, gkr_daemon_client, G_TYPE_OBJECT);

static guint signals[LAST_SIGNAL] = { 0 };

static GkrDaemonAsyncPrivate *current_client = NULL;

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void
unregister_client (gpointer data)
{
	g_assert (GKR_IS_DAEMON_CLIENT (data));
	g_signal_emit (data, signals[DISCONNECTED], 0);
	g_object_unref (data);
}

static void
register_client (GkrDaemonClient *client)
{
	g_assert (GKR_IS_DAEMON_CLIENT (client));
	g_assert (current_client);
	gkr_daemon_async_private_set (current_client, client);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_daemon_client_init (GkrDaemonClient *obj)
{

}

static void
gkr_daemon_client_get_property (GObject *obj, guint prop_id, GValue *value, 
                                GParamSpec *pspec)
{
	GkrDaemonClient *client = GKR_DAEMON_CLIENT (obj);

	switch (prop_id) {
	case PROP_PID:
		g_value_set_uint (value, client->pid);
		break;
	case PROP_APP_PATH:
		g_value_set_string (value, client->app_path);
		break;
	case PROP_APP_DISPLAY:
		g_value_set_string (value, client->app_display);
		break;
	}
}

static void
gkr_daemon_client_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                GParamSpec *pspec)
{
	GkrDaemonClient *client = GKR_DAEMON_CLIENT (obj);

	switch (prop_id) {
	case PROP_PID:
		g_return_if_fail (!client->pid);
		client->pid = g_value_get_uint (value);
		break;
	case PROP_APP_PATH:
		g_return_if_fail (!client->app_path);
		client->app_path = g_value_dup_string (value);
		break;
	case PROP_APP_DISPLAY:
		g_free (client->app_display);
		client->app_display = g_value_dup_string (value);
		break;
	}
}

static void
gkr_daemon_client_finalize (GObject *obj)
{
	GkrDaemonClient *client = GKR_DAEMON_CLIENT (obj);
	 
	if (client->app_path)
		g_free (client->app_path);
	if (client->app_display)
		g_free (client->app_display);
	
	G_OBJECT_CLASS (gkr_daemon_client_parent_class)->finalize (obj);
}

static void
gkr_daemon_client_class_init (GkrDaemonClientClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*) klass;
	gkr_daemon_client_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->get_property = gkr_daemon_client_get_property;
	gobject_class->set_property = gkr_daemon_client_set_property;
	gobject_class->finalize = gkr_daemon_client_finalize;

	g_object_class_install_property (gobject_class, PROP_PID,
		g_param_spec_uint ("pid", "Process ID", "Process ID of client",
		                   0, G_MAXUINT, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
		                   
	g_object_class_install_property (gobject_class, PROP_APP_PATH,
		g_param_spec_string ("app-path", "Application Path", "Client application path",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
		                     
	g_object_class_install_property (gobject_class, PROP_APP_DISPLAY,
		g_param_spec_string ("app-display", "Application Display Name", "Client application display name",
		                     NULL, G_PARAM_READWRITE));
		                     
	signals[DISCONNECTED] = g_signal_new ("disconnected", GKR_TYPE_DAEMON_CLIENT, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrDaemonClientClass, disconnected),
			NULL, NULL, g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);
	
	current_client = gkr_daemon_async_private_new (unregister_client);
}

/* -------------------------------------------------------------------------------------
 * PUBLIC STUFF
 */

GkrDaemonClient*
gkr_daemon_client_set_current (pid_t pid, const gchar *app_path, const gchar *app_display)
{
	GkrDaemonClient *client;
	gchar *path = NULL;
	
	/* Try and figure out the path from the pid */
#if defined(__linux__) || defined(__FreeBSD__)
	if (pid > 0 && !app_path) {
		char *buffer;
		int len;
		char *path = NULL;
			
#if defined(__linux__)
		path = g_strdup_printf ("/proc/%d/exe", (gint)pid);
#elif defined(__FreeBSD__)
		path = g_strdup_printf ("/proc/%d/file", (gint)pid);
#endif
		buffer = g_file_read_link (path, NULL);
		g_free (path);

		len = (buffer != NULL) ? strlen (buffer) : 0;
		if (len > 0) {
			path = g_strndup (buffer, len);
			app_path = path;
		}
		
		g_free (buffer);
	}
#endif
	
	client = g_object_new (GKR_TYPE_DAEMON_CLIENT, "pid", pid, "app-path", app_path, 
	                       "app-display", app_display, NULL);
	
	register_client (client);
	g_free (path);
	
	return client;
}

GkrDaemonClient*
gkr_daemon_client_get_current (void)
{
	if (!current_client)
		return NULL;
	return gkr_daemon_async_private_get (current_client);
}

pid_t
gkr_daemon_client_get_app_pid (GkrDaemonClient* client)
{
	if (!client)
		client = gkr_daemon_client_get_current ();
	g_return_val_if_fail (GKR_IS_DAEMON_CLIENT (client), 0);
	return client->pid;
}

const gchar*
gkr_daemon_client_get_app_display (GkrDaemonClient* client)
{
	if (!client)
		client = gkr_daemon_client_get_current ();
	g_return_val_if_fail (GKR_IS_DAEMON_CLIENT (client), 0);
	return client->app_display;
}

const gchar*
gkr_daemon_client_get_app_path (GkrDaemonClient* client)
{
	if (!client)
		client = gkr_daemon_client_get_current ();
	g_return_val_if_fail (GKR_IS_DAEMON_CLIENT (client), 0);
	return client->app_path;
}

/* -------------------------------------------------------------------------------------- */

static gchar* master_directory = NULL;
static GArray* published_environ = NULL;

/* Forward declaration, see gnu libc code lower down in this file */
static char* do_mkdtemp (char *template);

static void
uninit_master_directory (gpointer data)
{
	g_assert (master_directory);
	rmdir (master_directory);
	g_free (master_directory);
	master_directory = NULL;
}

static void
init_master_directory (void)
{
	gboolean have_path = FALSE;

	/* 
	 * When run under control of unit tests, we let the parent process
	 * pass in the socket path that we're going to create our main socket on.
 	 */
	
#ifdef WITH_TESTS
	const gchar* env = g_getenv ("GNOME_KEYRING_TEST_PATH");
	if (env && *env) {
		master_directory = g_strdup (env);
		if (g_mkdir_with_parents (master_directory, S_IRUSR | S_IWUSR | S_IXUSR) < 0)
			g_warning ("couldn't create socket directory: %s", g_strerror (errno));
		have_path = TRUE;
	} 
#endif /* WITH_TESTS */	
	
	/* Create private directory for agent socket */
	if (!have_path) {
		master_directory = g_build_filename (g_get_tmp_dir (), "keyring-XXXXXX", NULL);
		if (do_mkdtemp (master_directory) == NULL)
			g_warning ("couldn't create socket directory: %s", g_strerror (errno));
	}
	
	egg_cleanup_register (uninit_master_directory, NULL);
}
		
const gchar*
gkr_daemon_util_get_master_directory (void)
{
	if (!master_directory) 
		init_master_directory ();
	
	return master_directory;
}

static void
uninit_environment (gpointer data)
{
	guint i;
	
	if (published_environ) {
		for (i = 0; i < published_environ->len; ++i)
			g_free (g_array_index (published_environ, gchar*, i));
		g_array_free (published_environ, TRUE);
	}
	
	published_environ = NULL;
}

static void 
init_environment ()
{
	if (published_environ)
		return;
	published_environ = g_array_new (TRUE, TRUE, sizeof (gchar*)); 
	egg_cleanup_register (uninit_environment, NULL);
}

void
gkr_daemon_util_push_environment (const gchar *name, const gchar *value)
{
	gchar *env;

	init_environment ();
		
	env = g_strdup_printf ("%s=%s", name, value);
	g_array_append_val (published_environ, env);
}

void 
gkr_daemon_util_push_environment_full (const gchar *var)
{
	gchar *env;
	
	g_return_if_fail (strchr (var, '=') != NULL);
	init_environment ();
	
	env = g_strdup (var);
	g_array_append_val (published_environ, env);
}

const gchar**
gkr_daemon_util_get_environment (void)
{
	init_environment ();
	return (const gchar**)published_environ->data;
}

/* Copyright (C) 1999, 2001-2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* Extracted from misc/mkdtemp.c and sysdeps/posix/tempname.c.  */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <errno.h>
#ifndef __set_errno
# define __set_errno(Val) errno = (Val)
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#ifndef TMP_MAX
# define TMP_MAX 238328
#endif

#if HAVE_STDINT_H_WITH_UINTMAX || _LIBC
# include <stdint.h>
#endif

#if HAVE_INTTYPES_H_WITH_UINTMAX || _LIBC
# include <inttypes.h>
#endif

#if HAVE_UNISTD_H || _LIBC
# include <unistd.h>
#endif

#if HAVE_GETTIMEOFDAY || _LIBC
# if HAVE_SYS_TIME_H || _LIBC
#  include <sys/time.h>
# endif
#else
# if HAVE_TIME_H || _LIBC
#  include <time.h>
# endif
#endif

#include <sys/stat.h>
#if STAT_MACROS_BROKEN
# undef S_ISDIR
#endif
#if !defined S_ISDIR && defined S_IFDIR
# define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif
#if !S_IRUSR && S_IREAD
# define S_IRUSR S_IREAD
#endif
#if !S_IRUSR
# define S_IRUSR 00400
#endif
#if !S_IWUSR && S_IWRITE
# define S_IWUSR S_IWRITE
#endif
#if !S_IWUSR
# define S_IWUSR 00200
#endif
#if !S_IXUSR && S_IEXEC
# define S_IXUSR S_IEXEC
#endif
#if !S_IXUSR
# define S_IXUSR 00100
#endif

#if !_LIBC
# define __getpid getpid
# define __gettimeofday gettimeofday
# define __mkdir mkdir
#endif

/* Use the widest available unsigned type if uint64_t is not
   available.  The algorithm below extracts a number less than 62**6
   (approximately 2**35.725) from uint64_t, so ancient hosts where
   uintmax_t is only 32 bits lose about 3.725 bits of randomness,
   which is better than not having mkstemp at all.  */
#if !defined UINT64_MAX && !defined uint64_t
# define uint64_t uintmax_t
#endif

/* These are the characters used in temporary filenames.  */
static const char letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* Generate a temporary file name based on TMPL.  TMPL must match the
   rules for mk[s]temp (i.e. end in "XXXXXX").  The name constructed
   does not exist at the time of the call to __gen_tempname.  TMPL is
   overwritten with the result.

   KIND is:
   __GT_DIR:		create a directory, which will be mode 0700.

   We use a clever algorithm to get hard-to-predict names. */
static int
gen_tempname (tmpl)
     char *tmpl;
{
  int len;
  char *XXXXXX;
  static uint64_t value;
  uint64_t random_time_bits;
  int count, fd = -1;
  int save_errno = errno;

  len = strlen (tmpl);
  if (len < 6 || strcmp (&tmpl[len - 6], "XXXXXX"))
    {
      __set_errno (EINVAL);
      return -1;
    }

  /* This is where the Xs start.  */
  XXXXXX = &tmpl[len - 6];

  /* Get some more or less random data.  */
#ifdef RANDOM_BITS
  RANDOM_BITS (random_time_bits);
#else
# if HAVE_GETTIMEOFDAY || _LIBC
  {
    struct timeval tv;
    __gettimeofday (&tv, NULL);
    random_time_bits = ((uint64_t) tv.tv_usec << 16) ^ tv.tv_sec;
  }
# else
  random_time_bits = time (NULL);
# endif
#endif
  value += random_time_bits ^ __getpid ();

  for (count = 0; count < TMP_MAX; value += 7777, ++count)
    {
      uint64_t v = value;

      /* Fill in the random bits.  */
      XXXXXX[0] = letters[v % 62];
      v /= 62;
      XXXXXX[1] = letters[v % 62];
      v /= 62;
      XXXXXX[2] = letters[v % 62];
      v /= 62;
      XXXXXX[3] = letters[v % 62];
      v /= 62;
      XXXXXX[4] = letters[v % 62];
      v /= 62;
      XXXXXX[5] = letters[v % 62];

      fd = __mkdir (tmpl, S_IRUSR | S_IWUSR | S_IXUSR);

      if (fd >= 0)
	{
	  __set_errno (save_errno);
	  return fd;
	}
      else if (errno != EEXIST)
	return -1;
    }

  /* We got out of the loop because we ran out of combinations to try.  */
  __set_errno (EEXIST);
  return -1;
}

/* Generate a unique temporary directory from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the filename unique.
   The directory is created, mode 700, and its name is returned.
   (This function comes from OpenBSD.) */
static char *
do_mkdtemp (template)
     char *template;
{
  if (gen_tempname (template))
    return NULL;
  else
    return template;
}

