/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pkix-parser.c: Test PKIX parser

   Copyright (C) 2007 Stefan Walter

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

#include "egg/egg-error.h"
#include "egg/egg-secure-memory.h"

#include "gcr/gcr-base.h"
#include "gcr/gcr-internal.h"

#include "gck/gck.h"

#include <glib.h>
#include <gcrypt.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 *
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void);
 *
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void);
 *
 * Tests be run in the order specified here.
 */

typedef struct {
	GcrParser *parser;
	const gchar* filedesc;
} Test;

static void
ensure_block_can_be_parsed (gconstpointer block,
                            gsize n_block)
{
	GcrParser *parser;
	gboolean result;
	GError *error = NULL;

	g_assert (block);
	g_assert (n_block);

	parser = gcr_parser_new ();
	result = gcr_parser_parse_data (parser, block, n_block, &error);

	if (!result) {
		g_critical ("The data returned from gcr_parser_get_parsed_block() "
		            "cannot be parsed: %s", error->message);
		g_assert_not_reached ();
	}

	g_object_unref (parser);
}

static void
parsed_item (GcrParser *par, gpointer user_data)
{
	GckAttributes *attrs;
	const gchar *description;
	const gchar *label;
	Test *test = user_data;
	gconstpointer block;
	gsize n_block;

	g_assert (GCR_IS_PARSER (par));
	g_assert (par == test->parser);

	attrs = gcr_parser_get_parsed_attributes (test->parser);
	g_assert (attrs);

	description = gcr_parser_get_parsed_description (test->parser);
	label = gcr_parser_get_parsed_label (test->parser);
	block = gcr_parser_get_parsed_block (test->parser, &n_block);
	ensure_block_can_be_parsed (block, n_block);

	if (g_test_verbose ())
		g_print ("%s: '%s'\n", description, label);
}

static gboolean
authenticate (GcrParser *par, gint state, gpointer user_data)
{
	Test *test = user_data;

	g_assert (GCR_IS_PARSER (par));
	g_assert (par == test->parser);

	switch (state) {
	case 0:
		gcr_parser_add_password (test->parser, "booo");
		return TRUE;
	default:
		g_printerr ("decryption didn't work for: %s", test->filedesc);
		g_assert_not_reached ();
		return FALSE;
	};
}

static void
setup (Test *test, gconstpointer unused)
{
	test->parser = gcr_parser_new ();
	g_signal_connect (test->parser, "parsed", G_CALLBACK (parsed_item), test);
	g_signal_connect (test->parser, "authenticate", G_CALLBACK (authenticate), test);
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_object_unref (test->parser);
}

static void
test_parse_one (Test *test,
                gconstpointer user_data)
{
	const gchar *path = user_data;
	gchar *contents;
	GError *error = NULL;
	gboolean result;
	gsize len;

	if (!g_file_get_contents (path, &contents, &len, NULL))
		g_assert_not_reached ();

	test->filedesc = path;
	result = gcr_parser_parse_data (test->parser, contents, len, &error);
	g_assert_no_error (error);
	g_assert (result);

	g_free (contents);
}

static void
test_parse_null (void)
{
	GcrParser *parser = gcr_parser_new ();
	GError *error = NULL;
	gboolean result;

	result = gcr_parser_parse_data (parser, NULL, 0, &error);
	g_assert_error (error, GCR_DATA_ERROR, GCR_ERROR_UNRECOGNIZED);
	g_assert (!result);
	g_error_free (error);

	g_object_unref (parser);
}

static void
test_parse_empty (void)
{
	GcrParser *parser = gcr_parser_new ();
	GError *error = NULL;
	gboolean result;

	result = gcr_parser_parse_data (parser, "", 0, &error);
	g_assert_error (error, GCR_DATA_ERROR, GCR_ERROR_UNRECOGNIZED);
	g_assert (!result);
	g_error_free (error);

	g_object_unref (parser);
}

int
main (int argc, char **argv)
{
	const gchar *filename;
	GError *error = NULL;
	GPtrArray *strings;
	GDir *dir;
	gchar *path;
	gchar *lower;
	gchar *test;
	int ret;

	g_type_init ();
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-parser");

	strings = g_ptr_array_new_with_free_func (g_free);
	dir = g_dir_open (SRCDIR "/files", 0, &error);
	g_assert_no_error (error);

	for (;;) {
		filename = g_dir_read_name (dir);
		if (!filename)
			break;
		if (filename[0] == '.')
			continue;

		path = g_build_filename (SRCDIR "/files", filename, NULL);

		if (g_file_test (path, G_FILE_TEST_IS_DIR)) {
			g_free (path);
			continue;
		}

		lower = g_ascii_strdown (filename, -1);
		test = g_strdup_printf ("/gcr/parser/%s",
		                        g_strcanon (lower, "abcdefghijklmnopqrstuvwxyz012345789", '_'));
		g_free (lower);

		g_test_add (test, Test, path, setup, test_parse_one, teardown);
		g_ptr_array_add (strings, path);
		g_ptr_array_add (strings, test);
	}

	g_dir_close (dir);

	g_test_add_func ("/gcr/parser/parse_null", test_parse_null);
	g_test_add_func ("/gcr/parser/parse_empty", test_parse_empty);

	ret = g_test_run ();
	g_ptr_array_free (strings, TRUE);
	return ret;
}
