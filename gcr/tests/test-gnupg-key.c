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

#include "gcr/gcr-colons.h"
#include "gcr/gcr-gnupg-key.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>
#include <string.h>

typedef struct {
	GPtrArray *dataset;
	GcrGnupgKey *key;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	GPtrArray *dataset;

	dataset = g_ptr_array_new_with_free_func (_gcr_colons_free);
	g_ptr_array_add (dataset, _gcr_colons_parse ("pub:f:1024:17:6C7EE1B8621CC013:899817715:1055898235::m:::scESC:", -1));
	g_ptr_array_add (dataset, _gcr_colons_parse ("fpr:::::::::ECAF7590EB3443B5C7CF3ACB6C7EE1B8621CC013:", -1));
	g_ptr_array_add (dataset, _gcr_colons_parse ("uid:f::::::::Werner Koch <wk@g10code.com>:\n", -1));
	g_ptr_array_add (dataset, _gcr_colons_parse ("uid:f::::::::Werner Koch <wk@gnupg.org>:\n", -1));
	g_ptr_array_add (dataset, _gcr_colons_parse ("sub:f:1536:16:06AD222CADF6A6E1:919537416:1036177416:::::e:\n", -1));
	g_ptr_array_add (dataset, _gcr_colons_parse ("fpr:::::::::CF8BCC4B18DE08FCD8A1615906AD222CADF6A6E1:\n", -1));
	g_ptr_array_add (dataset, _gcr_colons_parse ("sub:r:1536:20:5CE086B5B5A18FF4:899817788:1025961788:::::esc:\n", -1));
	g_ptr_array_add (dataset, _gcr_colons_parse ("fpr:::::::::AB059359A3B81F410FCFF97F5CE086B5B5A18FF4:", -1));

	test->key = _gcr_gnupg_key_new (dataset);
	test->dataset = dataset;
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_object_unref (test->key);
	g_ptr_array_unref (test->dataset);
}

static void
test_label (Test *test, gconstpointer unused)
{
	gchar *label;

	g_object_get (test->key, "label", &label, NULL);
	g_assert_cmpstr (label, ==, "Werner Koch <wk@g10code.com>");

	g_free (label);
}

static void
test_markup (Test *test, gconstpointer unused)
{
	gchar *markup;

	g_object_get (test->key, "markup", &markup, NULL);
	g_assert_cmpstr (markup, ==, "Werner Koch &lt;wk@g10code.com&gt;");

	g_free (markup);
}

static void
test_description (Test *test, gconstpointer unused)
{
	gchar *description;

	g_object_get (test->key, "description", &description, NULL);
	g_assert_cmpstr (description, ==, "PGP Key");

	g_free (description);
}

static void
test_dataset (Test *test, gconstpointer unused)
{
	GPtrArray *dataset;

	g_object_get (test->key, "dataset", &dataset, NULL);
	g_assert (dataset == test->dataset);

	g_ptr_array_unref (dataset);
}

static void
test_keyid_for_colons (Test *test, gconstpointer unused)
{
	const gchar *keyid;

	keyid = _gcr_gnupg_key_get_keyid_for_colons (test->dataset);
	g_assert_cmpstr (keyid, ==, "6C7EE1B8621CC013");
}

int
main (int argc, char **argv)
{
	g_type_init ();
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/gcr/gnupg-key/label", Test, NULL, setup, test_label, teardown);
	g_test_add ("/gcr/gnupg-key/description", Test, NULL, setup, test_description, teardown);
	g_test_add ("/gcr/gnupg-key/markup", Test, NULL, setup, test_markup, teardown);
	g_test_add ("/gcr/gnupg-key/dataset", Test, NULL, setup, test_dataset, teardown);
	g_test_add ("/gcr/gnupg-key/keyid_for_colons", Test, NULL, setup, test_keyid_for_colons, teardown);

	return g_test_run ();
}
