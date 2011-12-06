/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "egg-testing.h"

#include <errno.h>
#include <unistd.h>

#if GLIB_CHECK_VERSION(2,31,3)
static GCond wait_condition;
static GCond wait_start;
static GMutex wait_mutex;
#else
static GCond *wait_condition = NULL;
static GCond *wait_start = NULL;
static GMutex *wait_mutex = NULL;
#endif

static gboolean wait_waiting = FALSE;

static const char HEXC[] = "0123456789ABCDEF";

static gchar*
hex_dump (const guchar *data, gsize n_data)
{
	GString *result;
	gsize i;
	guchar j;

	g_assert (data);

	result = g_string_sized_new (n_data * 2 + 1);
	for (i = 0; i < n_data; ++i) {
		g_string_append (result, "\\x");

		j = data[i] >> 4 & 0xf;
		g_string_append_c (result, HEXC[j]);
		j = data[i] & 0xf;
		g_string_append_c (result, HEXC[j]);
	}

	return g_string_free (result, FALSE);
}

void
egg_assertion_message_cmpmem (const char     *domain,
                              const char     *file,
                              int             line,
                              const char     *func,
                              const char     *expr,
                              gconstpointer   arg1,
                              gsize           n_arg1,
                              const char     *cmp,
                              gconstpointer   arg2,
                              gsize           n_arg2)
{
  char *a1, *a2, *s;
  a1 = arg1 ? hex_dump (arg1, n_arg1) : g_strdup ("NULL");
  a2 = arg2 ? hex_dump (arg2, n_arg2) : g_strdup ("NULL");
  s = g_strdup_printf ("assertion failed (%s): (%s %s %s)", expr, a1, cmp, a2);
  g_free (a1);
  g_free (a2);
  g_assertion_message (domain, file, line, func, s);
  g_free (s);
}

void
egg_test_wait_stop (void)
{
#if GLIB_CHECK_VERSION(2,31,3)
	g_mutex_lock (&wait_mutex);
#else
	g_assert (wait_mutex);
	g_assert (wait_condition);
	g_mutex_lock (wait_mutex);
#endif

	if (!wait_waiting) {
#if GLIB_CHECK_VERSION(2,31,3)
		gint64 time = g_get_monotonic_time () + 1 * G_TIME_SPAN_SECOND;
		g_cond_wait_until (&wait_start, &wait_mutex, time);
#else
		GTimeVal tv;
		g_get_current_time (&tv);
		g_time_val_add (&tv, 1000);
		g_cond_timed_wait (wait_start, wait_mutex, &tv);
#endif
	}
	g_assert (wait_waiting);

#if GLIB_CHECK_VERSION(2,31,3)
	g_cond_broadcast (&wait_condition);
	g_mutex_unlock (&wait_mutex);
#else
	g_cond_broadcast (wait_condition);
	g_mutex_unlock (wait_mutex);
#endif
}

gboolean
egg_test_wait_until (int timeout)
{
	gboolean ret;

#if GLIB_CHECK_VERSION(2,31,3)
	g_mutex_lock (&wait_mutex);
#else
	g_assert (wait_mutex);
	g_assert (wait_condition);
	g_mutex_lock (wait_mutex);
#endif

	g_assert (!wait_waiting);
	wait_waiting = TRUE;

	{
#if GLIB_CHECK_VERSION(2,31,3)
		gint64 time = g_get_monotonic_time () + ((timeout + 1000) * G_TIME_SPAN_MILLISECOND);
		g_cond_broadcast (&wait_start);
		ret = g_cond_wait_until (&wait_start, &wait_mutex, time);
#else
		GTimeVal tv;
		g_get_current_time (&tv);
		g_time_val_add (&tv, timeout * 1000);
		g_cond_broadcast (wait_start);
		ret = g_cond_timed_wait (wait_condition, wait_mutex, &tv);
#endif
	}

	g_assert (wait_waiting);
	wait_waiting = FALSE;
#if GLIB_CHECK_VERSION(2,31,3)
	g_mutex_unlock (&wait_mutex);
#else
	g_mutex_unlock (wait_mutex);
#endif

	return ret;
}

static gpointer
testing_thread (gpointer loop)
{
	/* Must have been defined by the test including this file */
	gint ret = g_test_run ();
	g_main_loop_quit (loop);
	return GINT_TO_POINTER (ret);
}

gint
egg_tests_run_in_thread_with_loop (void)
{
	GThread *thread;
	GMainLoop *loop;
	gpointer ret;

#if !GLIB_CHECK_VERSION(2,31,3)
	g_thread_init (NULL);
#endif

	loop = g_main_loop_new (NULL, FALSE);
#if GLIB_CHECK_VERSION(2,31,3)
	g_cond_init (&wait_condition);
	g_cond_init (&wait_start);
	g_mutex_init (&wait_mutex);
	thread = g_thread_new ("testing", testing_thread, loop);
#else
	wait_condition = g_cond_new ();
	wait_start = g_cond_new ();
	wait_mutex = g_mutex_new ();
	thread = g_thread_create (testing_thread, loop, TRUE, NULL);
#endif

	g_assert (thread);

	g_main_loop_run (loop);
	ret = g_thread_join (thread);
	g_main_loop_unref (loop);

#if GLIB_CHECK_VERSION(2,31,2)
	g_cond_clear (&wait_condition);
	g_mutex_clear (&wait_mutex);
#else
	g_cond_free (wait_condition);
	g_mutex_free (wait_mutex);
#endif

	return GPOINTER_TO_INT (ret);
}
