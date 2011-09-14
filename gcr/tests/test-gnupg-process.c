/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2011 Collabora Ltd

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

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#include "config.h"

#include "gcr/gcr-base.h"
#include "gcr/gcr-callback-output-stream.h"
#include "gcr/gcr-gnupg-process.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>
#include <string.h>

#define WAIT 50000

typedef struct {
	GcrGnupgProcess *process;
	GAsyncResult *result;
	GString *output_buf;
	GString *error_buf;
	GString *attribute_buf;
	GcrRecord *record;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	test->output_buf = g_string_new ("");
	test->error_buf = g_string_new ("");
	test->attribute_buf = g_string_new ("");
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_assert (!test->result);
	g_assert (!test->process);
	if (test->output_buf)
		g_string_free (test->output_buf, TRUE);
	if (test->error_buf)
		g_string_free (test->error_buf, TRUE);
	if (test->attribute_buf)
		g_string_free (test->attribute_buf, TRUE);
	_gcr_record_free (test->record);
}

static void
test_create (Test *test, gconstpointer unused)
{
	gchar *value;

	test->process = _gcr_gnupg_process_new ("/the/directory", "/path/to/executable");

	g_object_get (test->process, "directory", &value, NULL);
	g_assert_cmpstr (value, ==, "/the/directory");
	g_free (value);

	g_object_get (test->process, "executable", &value, NULL);
	g_assert_cmpstr (value, ==, "/path/to/executable");
	g_free (value);

	g_clear_object (&test->process);
}

static void
on_async_ready (GObject *source, GAsyncResult *result, gpointer user_data)
{
	Test *test = user_data;

	g_assert (G_OBJECT (test->process) == source);
	g_assert (test->result == NULL);
	g_assert (g_async_result_get_source_object (result) == source);

	test->result = g_object_ref (result);
	egg_test_wait_stop ();
}

static gchar*
build_script_path (const gchar *name)
{
	gchar *path;

	path = g_build_filename (SRCDIR, "files", "gnupg-mock", name, NULL);

	return path;
}

static gssize
on_process_output_data (gconstpointer buffer,
                        gsize count,
                        GCancellable *cancellable,
                        gpointer user_data,
                        GError **error)
{
	Test *test = user_data;
	g_string_append_len (test->output_buf, buffer, count);
	return count;
}

static gssize
on_process_attribute_data (gconstpointer buffer,
                           gsize count,
                           GCancellable *cancellable,
                           gpointer user_data,
                           GError **error)
{
	Test *test = user_data;
	g_string_append_len (test->attribute_buf, buffer, count);
	return count;
}

static void
on_process_error_line (GcrGnupgProcess *process, const gchar *line, gpointer user_data)
{
	Test *test = user_data;

	g_assert (process == test->process);
	g_assert (line);
	g_assert (!strchr (line, '\n'));

	g_string_append_printf (test->error_buf, "%s\n", line);
}

static void
on_process_status_record (GcrGnupgProcess *process, GcrRecord *record, gpointer user_data)
{
	Test *test = user_data;

	g_assert (process == test->process);
	g_assert (record);

	g_assert (!test->record);
	test->record = _gcr_record_copy (record);
}

static void
test_run_simple_output (Test *test, gconstpointer unused)
{
	const gchar *argv[] = { NULL };
	GOutputStream *output;
	GError *error = NULL;
	gboolean ret;
	gchar *script;

	script = build_script_path ("mock-simple-output");
	test->process = _gcr_gnupg_process_new (NULL, script);
	g_free (script);

	output = _gcr_callback_output_stream_new (on_process_output_data, test, NULL);
	_gcr_gnupg_process_set_output_stream (test->process, output);
	g_object_unref (output);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, 0, NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert_cmpstr ("simple-output\n", ==, test->output_buf->str);

	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

static void
test_run_simple_error (Test *test, gconstpointer unused)
{
	const gchar *argv[] = { NULL };
	GError *error = NULL;
	gchar *script;
	gboolean ret;

	script = build_script_path ("mock-simple-error");
	test->process = _gcr_gnupg_process_new (NULL, script);
	g_free (script);

	g_signal_connect (test->process, "error-line", G_CALLBACK (on_process_error_line), test);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, 0, NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert_cmpstr ("line 1: more line 1\nline 2\nline 3\n", ==, test->error_buf->str);

	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

static void
test_run_status_and_output (Test *test, gconstpointer unused)
{
	const gchar *argv[] = { NULL };
	GOutputStream *output;
	GError *error = NULL;
	gchar *script;
	gboolean ret;

	script = build_script_path ("mock-status-and-output");
	test->process = _gcr_gnupg_process_new (NULL, script);
	g_free (script);

	output = _gcr_callback_output_stream_new (on_process_output_data, test, NULL);
	_gcr_gnupg_process_set_output_stream (test->process, output);
	g_object_unref (output);

	g_signal_connect (test->process, "status-record", G_CALLBACK (on_process_status_record), test);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, GCR_GNUPG_PROCESS_WITH_STATUS,
	                              NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (test->record);
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 0), ==, "SCHEMA");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 1), ==, "one");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 2), ==, "two");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 3), ==, "three");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 4), ==, "four");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 5), ==, NULL);
	g_assert_cmpstr ("Here's some output\nMore output\n", ==, test->output_buf->str);

	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

static void
test_run_status_and_attribute (Test *test, gconstpointer unused)
{
	const gchar *argv[] = { NULL };
	GOutputStream *output;
	GError *error = NULL;
	gchar *script;
	gboolean ret;

	script = build_script_path ("mock-status-and-attribute");
	test->process = _gcr_gnupg_process_new (NULL, script);
	g_free (script);

	output = _gcr_callback_output_stream_new (on_process_attribute_data, test, NULL);
	_gcr_gnupg_process_set_attribute_stream (test->process, output);
	g_object_unref (output);

	g_signal_connect (test->process, "status-record", G_CALLBACK (on_process_status_record), test);

	_gcr_gnupg_process_run_async (test->process, argv, NULL,
	                              GCR_GNUPG_PROCESS_WITH_STATUS | GCR_GNUPG_PROCESS_WITH_ATTRIBUTES,
	                              NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (test->record);
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 0), ==, "SCHEMA");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 1), ==, "one");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 2), ==, "two");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 3), ==, "three");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 4), ==, "four");
	g_assert_cmpstr (_gcr_record_get_raw (test->record, 5), ==, NULL);
	g_assert_cmpstr ("1lc923g4laoeurc23rc241lcg2r23c4gr3", ==, test->attribute_buf->str);

	g_clear_object (&test->result);
	g_clear_object (&test->process);
}


static void
test_run_arguments_and_environment (Test *test, gconstpointer unused)
{
	GError *error = NULL;
	GOutputStream *output;
	gchar *script;
	gboolean ret;

	const gchar *argv[] = {
		"-1", "value1",
		"-2", "value2",
		NULL
	};

	const gchar *envp[] = {
		"ENVIRON1=VALUE1",
		"ENVIRON2=VALUE2",
		NULL
	};

	script = build_script_path ("mock-arguments-environ");
	test->process = _gcr_gnupg_process_new (NULL, script);
	g_free (script);

	output = _gcr_callback_output_stream_new (on_process_output_data, test, NULL);
	_gcr_gnupg_process_set_output_stream (test->process, output);
	g_object_unref (output);

	g_signal_connect (test->process, "error-line", G_CALLBACK (on_process_error_line), test);

	_gcr_gnupg_process_run_async (test->process, argv, envp, 0, NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	if (error) {
		g_printerr ("%s\n", test->error_buf->str);
		g_assert_no_error (error);
	}
	g_assert (ret == TRUE);

	g_assert_cmpstr ("value1\nvalue2\n", ==, test->output_buf->str);
	g_assert_cmpstr ("VALUE1VALUE2\n", ==, test->error_buf->str);

	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

static void
test_run_with_homedir (Test *test, gconstpointer unused)
{
	const gchar *argv[] = { NULL };
	GOutputStream *output;
	GError *error = NULL;
	gchar *script;
	gchar *check;
	gboolean ret;

	script = build_script_path ("mock-with-homedir");
	test->process = _gcr_gnupg_process_new (SRCDIR, script);
	g_free (script);

	output = _gcr_callback_output_stream_new (on_process_output_data, test, NULL);
	_gcr_gnupg_process_set_output_stream (test->process, output);
	g_object_unref (output);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, 0, NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	check = g_strdup_printf ("DIR: %s\n", SRCDIR);
	g_assert_cmpstr (check, ==, test->output_buf->str);
	g_free (check);

	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

static void
test_run_with_input_and_output (Test *test,
                                gconstpointer unused)
{
	const gchar *argv[] = { NULL };
	const gchar *data = "one\ntwenty two\nthree\nfourty four\n";
	GInputStream *input;
	GOutputStream *output;
	GError *error = NULL;
	GString *string;
	gchar *script;
	gboolean ret;

	script = build_script_path ("mock-echo");
	test->process = _gcr_gnupg_process_new (SRCDIR, script);
	g_free (script);

	input = g_memory_input_stream_new_from_data ((gpointer)data, -1, NULL);
	output = g_memory_output_stream_new (NULL, 0, g_realloc, g_free);

	_gcr_gnupg_process_set_input_stream (test->process, input);
	_gcr_gnupg_process_set_output_stream (test->process, output);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, 0, NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	string = g_string_new_len (g_memory_output_stream_get_data (G_MEMORY_OUTPUT_STREAM (output)),
	                           g_memory_output_stream_get_data_size (G_MEMORY_OUTPUT_STREAM (output)));
	g_assert_cmpstr (data, ==, string->str);
	g_string_free (string, TRUE);

	g_clear_object (&input);
	g_clear_object (&output);
	g_clear_object (&test->result);
	g_clear_object (&test->process);

}

static void
test_run_bad_executable (Test *test, gconstpointer unused)
{
	GError *error = NULL;
	gchar *script;
	const gchar *argv[] = { NULL };
	gboolean ret;

	script = build_script_path ("mock-invalid");
	test->process = _gcr_gnupg_process_new (NULL, script);
	g_free (script);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, 0, NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_error (error, G_SPAWN_ERROR, G_SPAWN_ERROR_NOENT);
	g_clear_error (&error);
	g_assert (ret == FALSE);

	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

static void
test_run_fail_exit (Test *test, gconstpointer unused)
{
	GError *error = NULL;
	gchar *script;
	const gchar *argv[] = { "55" };
	gboolean ret;

	script = build_script_path ("mock-fail-exit");
	test->process = _gcr_gnupg_process_new (NULL, script);
	g_free (script);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, 0, NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_error (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED);
	g_assert_cmpstr (error->message, ==, "Gnupg process exited with code: 55");
	g_clear_error (&error);
	g_assert (ret == FALSE);

	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

static void
test_run_fail_signal (Test *test, gconstpointer unused)
{
	GError *error = NULL;
	gchar *script;
	const gchar *argv[] = { "15" };
	gboolean ret;

	script = build_script_path ("mock-fail-signal");
	test->process = _gcr_gnupg_process_new (NULL, script);
	g_free (script);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, 0, NULL, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_error (error, G_SPAWN_ERROR, G_SPAWN_ERROR_FAILED);
	g_assert_cmpstr (error->message, ==, "Gnupg process was terminated with signal: 15");
	g_clear_error (&error);
	g_assert (ret == FALSE);

	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

static void
test_run_and_cancel (Test *test, gconstpointer unused)
{
	GError *error = NULL;
	gchar *script;
	const gchar *argv[] = { "15" };
	GCancellable *cancellable;
	gboolean ret;

	cancellable = g_cancellable_new ();

	script = build_script_path ("mock-simple-output");
	test->process = _gcr_gnupg_process_new (NULL, script);
	g_free (script);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, 0, cancellable, on_async_ready, test);
	g_cancellable_cancel (cancellable);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);
	g_assert (ret == FALSE);

	g_object_unref (cancellable);
	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

static gssize
on_process_output_cancel (gconstpointer buffer,
                          gsize count,
                          GCancellable *cancellable,
                          gpointer user_data,
                          GError **error)
{
	g_cancellable_cancel (cancellable);
	g_cancellable_set_error_if_cancelled (cancellable, error);
	return -1;
}

static void
test_run_and_cancel_later (Test *test, gconstpointer unused)
{
	GError *error = NULL;
	GOutputStream *output;
	gchar *script;
	const gchar *argv[] = { "15" };
	GCancellable *cancellable;
	gboolean ret;

	cancellable = g_cancellable_new ();

	script = build_script_path ("mock-simple-output");
	test->process = _gcr_gnupg_process_new (NULL, script);
	output = _gcr_callback_output_stream_new (on_process_output_cancel, NULL, NULL);
	_gcr_gnupg_process_set_output_stream (test->process, output);
	g_object_unref (output);
	g_free (script);

	_gcr_gnupg_process_run_async (test->process, argv, NULL, 0, cancellable, on_async_ready, test);
	egg_test_wait_until (WAIT);

	g_assert (test->result);
	ret = _gcr_gnupg_process_run_finish (test->process, test->result, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);
	g_assert (ret == FALSE);

	g_object_unref (cancellable);
	g_clear_object (&test->result);
	g_clear_object (&test->process);
}

int
main (int argc, char **argv)
{
	g_type_init ();
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-gnupg-process");

	g_test_add ("/gcr/gnupg-process/create", Test, NULL, setup, test_create, teardown);
	g_test_add ("/gcr/gnupg-process/run_simple_output", Test, NULL, setup, test_run_simple_output, teardown);
	g_test_add ("/gcr/gnupg-process/run_simple_error", Test, NULL, setup, test_run_simple_error, teardown);
	g_test_add ("/gcr/gnupg-process/run_status_and_output", Test, NULL, setup, test_run_status_and_output, teardown);
	g_test_add ("/gcr/gnupg-process/run_status_and_attribute", Test, NULL, setup, test_run_status_and_attribute, teardown);
	g_test_add ("/gcr/gnupg-process/run_arguments_and_environment", Test, NULL, setup, test_run_arguments_and_environment, teardown);
	g_test_add ("/gcr/gnupg-process/run_with_homedir", Test, NULL, setup, test_run_with_homedir, teardown);
	g_test_add ("/gcr/gnupg-process/run_with_input_and_output", Test, NULL, setup, test_run_with_input_and_output, teardown);
	g_test_add ("/gcr/gnupg-process/run_bad_executable", Test, NULL, setup, test_run_bad_executable, teardown);
	g_test_add ("/gcr/gnupg-process/run_fail_exit", Test, NULL, setup, test_run_fail_exit, teardown);
	g_test_add ("/gcr/gnupg-process/run_fail_signal", Test, NULL, setup, test_run_fail_signal, teardown);
	g_test_add ("/gcr/gnupg-process/run_and_cancel", Test, NULL, setup, test_run_and_cancel, teardown);
	g_test_add ("/gcr/gnupg-process/run_and_cancel_later", Test, NULL, setup, test_run_and_cancel_later, teardown);

	return egg_tests_run_in_thread_with_loop ();
}
