/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "egg-mkdtemp.h"
#include "egg-testing.h"

#include <glib/gstdio.h>

#include <errno.h>
#include <unistd.h>

static GCond wait_condition;
static GCond wait_start;
static GMutex wait_mutex;

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
	g_mutex_lock (&wait_mutex);

	if (!wait_waiting) {
		gint64 time = g_get_monotonic_time () + 1 * G_TIME_SPAN_SECOND;
		g_cond_wait_until (&wait_start, &wait_mutex, time);
	}
	g_assert (wait_waiting);

	g_cond_broadcast (&wait_condition);
	g_mutex_unlock (&wait_mutex);
}

gboolean
egg_test_wait_until (int timeout)
{
	gboolean ret;

	g_mutex_lock (&wait_mutex);

	g_assert (!wait_waiting);
	wait_waiting = TRUE;

	{
		gint64 time = g_get_monotonic_time () + ((timeout + 1000) * G_TIME_SPAN_MILLISECOND);
		g_cond_broadcast (&wait_start);
		ret = g_cond_wait_until (&wait_start, &wait_mutex, time);
	}

	g_assert (wait_waiting);
	wait_waiting = FALSE;
	g_mutex_unlock (&wait_mutex);

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

	loop = g_main_loop_new (NULL, FALSE);
	g_cond_init (&wait_condition);
	g_cond_init (&wait_start);
	g_mutex_init (&wait_mutex);
	thread = g_thread_new ("testing", testing_thread, loop);

	g_assert (thread);

	g_main_loop_run (loop);
	ret = g_thread_join (thread);
	g_main_loop_unref (loop);

	g_cond_clear (&wait_condition);
	g_mutex_clear (&wait_mutex);

	return GPOINTER_TO_INT (ret);
}

static void
copy_scratch_file (const gchar *filename,
                   const gchar *directory)
{
	GError *error = NULL;
	gchar *basename;
	gchar *contents;
	gchar *destination;
	gsize length;

	g_assert (directory);

	g_file_get_contents (filename, &contents, &length, &error);
	g_assert_no_error (error);

	basename = g_path_get_basename (filename);
	destination = g_build_filename (directory, basename, NULL);
	g_free (basename);

	g_file_set_contents (destination, contents, length, &error);
	g_assert_no_error (error);
	g_free (destination);
	g_free (contents);
}

gchar *
egg_tests_create_scratch_directory (const gchar *file_to_copy,
                                    ...)
{
	gchar *basename;
	gchar *directory;
	va_list va;

	basename = g_path_get_basename (g_get_prgname ());
	directory = g_strdup_printf ("/tmp/scratch-%s.XXXXXX", basename);
	g_free (basename);

	if (!egg_mkdtemp (directory))
		g_assert_not_reached ();

	va_start (va, file_to_copy);

	while (file_to_copy != NULL) {
		copy_scratch_file (file_to_copy, directory);
		file_to_copy = va_arg (va, const gchar *);
	}

	va_end (va);

	return directory;
}

void
egg_tests_remove_scratch_directory (const gchar *directory)
{
	GDir *dir;
	GError *error = NULL;
	const gchar *name;
	gchar *filename;

	dir = g_dir_open (directory, 0, &error);
	g_assert_no_error (error);

	while ((name = g_dir_read_name (dir)) != NULL) {
		filename = g_build_filename (directory, name, NULL);
		if (g_unlink (filename) < 0)
			g_assert_not_reached ();
		g_free (filename);
	}

	g_dir_close (dir);

	if (g_rmdir (directory) < 0)
		g_assert_not_reached ();
}
