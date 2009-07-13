/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-file-store.c: Test file store functionality

   Copyright (C) 2008 Stefan Walter

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

#include "run-auto-test.h"

#include "gck/gck-data-file.h"
#include "gck/gck-object.h"

#include <glib/gstdio.h>

#include <fcntl.h>

/* Both point to the same thing */
static GckDataFile *data_file = NULL;
static gchar *public_filename = NULL;
static gchar *private_filename = NULL;
static gchar *write_filename = NULL;
static int write_fd = -1;
static int public_fd = -1;
static int private_fd = -1;
static GckLogin *login = NULL;

DEFINE_SETUP(file_store)
{
	public_filename = g_build_filename (test_dir_testdata (), "data-file-public.store", NULL);
	private_filename = g_build_filename (test_dir_testdata (), "data-file-private.store", NULL);
	write_filename = test_build_filename ("unit-test-file.store");

	data_file = gck_data_file_new ();

	public_fd = g_open (public_filename, O_RDONLY, 0);
	g_assert (public_fd != -1);
	
	private_fd = g_open (private_filename, O_RDONLY, 0);
	g_assert (private_fd != -1);
	
	write_fd = g_open (write_filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	g_assert (write_fd != -1);
	
	login = gck_login_new ((CK_UTF8CHAR_PTR)"booo", 4);
}

DEFINE_TEARDOWN(file_store)
{
	g_free (public_filename);
	g_free (private_filename);
	g_free (write_filename);
	
	g_object_unref (data_file);
	data_file = NULL;
	
	if (public_fd != -1)
		close (public_fd);
	if (private_fd != -1)
		close (private_fd);
	if (write_fd != -1)
		close (write_fd);
	public_fd = private_fd = write_fd = -1;
	
	g_object_unref (login);
}

DEFINE_TEST(test_file_create)
{
	GckDataResult res;
	
	res = gck_data_file_create_entry (data_file, "identifier-public", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Should be able to create private in a new file */
	res = gck_data_file_create_entry (data_file, "identifier-public", GCK_DATA_FILE_SECTION_PRIVATE);
	g_assert (res == GCK_DATA_SUCCESS);
}

DEFINE_TEST(test_file_write_value)
{
	GckDataResult res;
	
	/* Can't write when no identifier present */
	res = gck_data_file_write_value (data_file, "identifier-public", CKA_LABEL, "public-label", 12);
	g_assert (res == GCK_DATA_UNRECOGNIZED);
	
	res = gck_data_file_create_entry (data_file, "identifier-public", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Should be able to write now */
	res = gck_data_file_write_value (data_file, "identifier-public", CKA_LABEL, "public-label", 12);
	g_assert (res == GCK_DATA_SUCCESS);
}

DEFINE_TEST(test_file_read_value)
{
	gconstpointer value = NULL;
	GckDataResult res;
	gsize n_value;
	guint number = 7778;
	
	/* Write some stuff in */
	res = gck_data_file_create_entry (data_file, "ident", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);
	res = gck_data_file_write_value (data_file, "ident", CKA_LABEL, "TWO-label", 10);
	g_assert (res == GCK_DATA_SUCCESS);
	res = gck_data_file_write_value (data_file, "ident", CKA_VALUE, &number, sizeof (number));
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* Read for an invalid item */
	res = gck_data_file_read_value (data_file, "non-existant", CKA_LABEL, &value, &n_value);
	g_assert (res == GCK_DATA_UNRECOGNIZED);
	
	/* Read for an invalid attribute */
	res = gck_data_file_read_value (data_file, "ident", CKA_ID, &value, &n_value);
	g_assert (res == GCK_DATA_UNRECOGNIZED);
	
	/* Read out a valid number */
	res = gck_data_file_read_value (data_file, "ident", CKA_VALUE, &value, &n_value);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (value);
	g_assert (n_value == sizeof (number));
	g_assert_cmpuint (*((guint*)value), ==, number);
	
	/* Read out the valid string */
	res = gck_data_file_read_value (data_file, "ident", CKA_LABEL, &value, &n_value);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (value);
	g_assert (n_value == 10);
	g_assert_cmpstr ((const gchar*)value, ==, "TWO-label");
}

DEFINE_TEST(test_file_read)
{
	GckDataResult res;
	
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
}

DEFINE_TEST(test_file_lookup)
{
	GckDataResult res;
	guint section;
	gboolean ret;
	
	/* Invalid shouldn't succeed */
	ret = gck_data_file_lookup_entry (data_file, "non-existant", &section);
	g_assert (ret == FALSE);

	/* Create a test item */
	res = gck_data_file_create_entry (data_file, "test-ident", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);
	
	ret = gck_data_file_lookup_entry (data_file, "test-ident", &section);
	g_assert (ret == TRUE);
	g_assert (section == GCK_DATA_FILE_SECTION_PUBLIC);
	
	/* Should be able to call without asking for section */
	ret = gck_data_file_lookup_entry (data_file, "test-ident", NULL);
	g_assert (ret == TRUE);
}

DEFINE_TEST(file_read_private_without_login)
{
	GckDataResult res;
	guint section;
	gconstpointer value;
	gsize n_value;
	gboolean ret;
	
	res = gck_data_file_read_fd (data_file, private_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* Items from the private section should exist */
	ret = gck_data_file_lookup_entry (data_file, "identifier-private", &section);
	g_assert (ret);
	g_assert (section == GCK_DATA_FILE_SECTION_PRIVATE);
	
	/* But we shouldn't be able to read values from those private items */
	ret = gck_data_file_read_value (data_file, "identifier-private", CKA_LABEL, &value, &n_value);
	g_assert (ret == GCK_DATA_LOCKED);
	
	/* Shouldn't be able to create private items */
	res = gck_data_file_create_entry (data_file, "dummy-private", GCK_DATA_FILE_SECTION_PRIVATE);
	g_assert (res == GCK_DATA_LOCKED);
	
	/* Shouldn't be able to write with another login */
	res = gck_data_file_write_fd (data_file, write_fd, login);
	g_assert (res == GCK_DATA_LOCKED);
	
	/* Now load a public file without private bits*/
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* Now we should be able to load private stuff */
	res = gck_data_file_create_entry (data_file, "dummy-private", GCK_DATA_FILE_SECTION_PRIVATE);
	g_assert (res == GCK_DATA_SUCCESS);
}

DEFINE_TEST(test_file_write)
{
	GckDataResult res;

	res = gck_data_file_create_entry (data_file, "identifier-public", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);
	
	res = gck_data_file_write_value (data_file, "identifier-public", CKA_LABEL, "public-label", 12);
	g_assert (res == GCK_DATA_SUCCESS);

	res = gck_data_file_create_entry (data_file, "identifier-two", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);

	res = gck_data_file_write_fd (data_file, write_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
}

DEFINE_TEST(cant_write_private_without_login)
{
	GckDataResult res;
	
	res = gck_data_file_create_entry (data_file, "identifier_private", GCK_DATA_FILE_SECTION_PRIVATE);
	g_assert (res == GCK_DATA_SUCCESS);
	
	res = gck_data_file_write_fd (data_file, write_fd, NULL);
	g_assert (res == GCK_DATA_LOCKED);
}

DEFINE_TEST(write_private_with_login)
{
	GckDataResult res;
	gulong value;
	
	res = gck_data_file_create_entry (data_file, "identifier-public", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);
	res = gck_data_file_write_value (data_file, "identifier-public", CKA_LABEL, "public-label", 12);
	g_assert (res == GCK_DATA_SUCCESS);

	res = gck_data_file_create_entry (data_file, "identifier-two", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);
	res = gck_data_file_write_value (data_file, "identifier-two", CKA_LABEL, "TWO-label", 9);
	g_assert (res == GCK_DATA_SUCCESS);
	value = 555;
	res = gck_data_file_write_value (data_file, "identifier-two", CKA_VALUE, &value, sizeof (value));
	g_assert (res == GCK_DATA_SUCCESS);
	
	res = gck_data_file_create_entry (data_file, "identifier-private", GCK_DATA_FILE_SECTION_PRIVATE);
	g_assert (res == GCK_DATA_SUCCESS);
	res = gck_data_file_write_value (data_file, "identifier-private", CKA_LABEL, "private-label", 13);
	g_assert (res == GCK_DATA_SUCCESS);

	res = gck_data_file_write_fd (data_file, write_fd, login);
	g_assert (res == GCK_DATA_SUCCESS);
}

DEFINE_TEST(read_private_with_login)
{
	GckDataResult res;
	gconstpointer value;
	gsize n_value;
	
	res = gck_data_file_read_fd (data_file, private_fd, login);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* Should be able to read private items */
	res = gck_data_file_read_value (data_file, "identifier-private", CKA_LABEL, &value, &n_value);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert_cmpuint (n_value, ==, 13);
	g_assert (memcmp (value, "private-label", 13) == 0);
}

DEFINE_TEST(destroy_entry)
{
	GckDataResult res;
	
	res = gck_data_file_destroy_entry (data_file, "non-existant");
	g_assert (res == GCK_DATA_UNRECOGNIZED);
	
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* Make sure it's here */
	g_assert (gck_data_file_lookup_entry (data_file, "identifier-public", NULL));
	
	res = gck_data_file_destroy_entry (data_file, "identifier-public");
	g_assert (res == GCK_DATA_SUCCESS);

	/* Make sure it's gone */
	g_assert (!gck_data_file_lookup_entry (data_file, "identifier-public", NULL));
}

DEFINE_TEST(destroy_entry_by_loading)
{
	GckDataResult res;
	
	/* Create some extra idenifiers */
	res = gck_data_file_create_entry (data_file, "my-public", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);
	res = gck_data_file_create_entry (data_file, "my-private", GCK_DATA_FILE_SECTION_PRIVATE);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* Now read from the file */
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* Both should be gone */
	g_assert (!gck_data_file_lookup_entry (data_file, "my-public", NULL));
	g_assert (!gck_data_file_lookup_entry (data_file, "my-private", NULL));
}


DEFINE_TEST(destroy_private_without_login)
{
	GckDataResult res;
	
	res = gck_data_file_read_fd (data_file, private_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* Make sure it's here */
	g_assert (gck_data_file_lookup_entry (data_file, "identifier-private", NULL));
	
	/* Shouldn't be able to destroy */
	res = gck_data_file_destroy_entry (data_file, "identifier-private");
	g_assert (res == GCK_DATA_LOCKED);
	
	/* Make sure it's still here */
	g_assert (gck_data_file_lookup_entry (data_file, "identifier-private", NULL));
}

static void
entry_added_one (GckDataFile *df, const gchar *identifier, gboolean *added)
{
	g_assert (GCK_IS_DATA_FILE (df));
	g_assert (df == data_file);
	g_assert (identifier);
	g_assert (added);
	
	/* Should only be called once */
	g_assert (!*added);
	*added = TRUE;
}

DEFINE_TEST(entry_added_signal)
{
	GckDataResult res;
	gboolean added;
	
	g_signal_connect (data_file, "entry-added", G_CALLBACK (entry_added_one), &added);
	
	/* Should fire the signal */
	added = FALSE;
	res = gck_data_file_create_entry (data_file, "identifier-public", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (added == TRUE);
	
	/* Another one should be added when we load */
	added = FALSE;
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (added == TRUE);
}

static void
entry_changed_one (GckDataFile *df, const gchar *identifier, gulong type, gboolean *changed)
{
	g_assert (GCK_IS_DATA_FILE (df));
	g_assert (df == data_file);
	g_assert (identifier);
	g_assert (changed);
	g_assert (type == CKA_LABEL);
	
	/* Should only be called once */
	g_assert (!*changed);
	*changed = TRUE;
}

DEFINE_TEST(entry_changed_signal)
{
	GckDataResult res;
	gboolean changed;
	
	g_signal_connect (data_file, "entry-changed", G_CALLBACK (entry_changed_one), &changed);
	
	/* Loading shouldn't fire the signal */
	changed = FALSE;
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (changed == FALSE);
	
	/* Shouldn't fire the signal on nonexistant */
	changed = FALSE;
	res = gck_data_file_write_value (data_file, "non-existant", CKA_LABEL, "new-value", 10);
	g_assert (res == GCK_DATA_UNRECOGNIZED);
	g_assert (changed == FALSE);
	
	/* Should fire the signal */
	changed = FALSE;
	res = gck_data_file_write_value (data_file, "identifier-public", CKA_LABEL, "new-value", 10);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (changed == TRUE);

	/* Shouldn't fire the signal, same value again */
	changed = FALSE;
	res = gck_data_file_write_value (data_file, "identifier-public", CKA_LABEL, "new-value", 10);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (changed == FALSE);
	
	/* Reload file, should revert, fire signal */
	changed = FALSE;
	g_assert (lseek (public_fd, 0, SEEK_SET) != -1);
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (changed == TRUE);
}

static void
entry_removed_one (GckDataFile *df, const gchar *identifier, gboolean *removed)
{
	g_assert (GCK_IS_DATA_FILE (df));
	g_assert (df == data_file);
	g_assert (identifier);
	g_assert (removed);
	
	/* Should only be called once */
	g_assert (!*removed);
	*removed = TRUE;
}

DEFINE_TEST(entry_removed_signal)
{
	GckDataResult res;
	gboolean removed;
	
	g_signal_connect (data_file, "entry-removed", G_CALLBACK (entry_removed_one), &removed);
	
	/* Loading shouldn't fire the signal */
	removed = FALSE;
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (removed == FALSE);
	
	/* Shouldn't fire the signal on removing nonexistant */
	removed = FALSE;
	res = gck_data_file_destroy_entry (data_file, "non-existant");
	g_assert (res == GCK_DATA_UNRECOGNIZED);
	g_assert (removed == FALSE);
	
	/* Remove a real entry */
	removed = FALSE;
	res = gck_data_file_destroy_entry (data_file, "identifier-public");
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (removed == TRUE);
	
	/* Add a dummy entry */
	res = gck_data_file_create_entry (data_file, "extra-dummy", GCK_DATA_FILE_SECTION_PUBLIC);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* That one should go away when we reload, fire signal */
	removed = FALSE;
	g_assert (lseek (public_fd, 0, SEEK_SET) != -1);
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (removed == TRUE);
}

static void
foreach_entry (GckDataFile *df, const gchar *identifier, gpointer data)
{
	GPtrArray *array = data;
	const gchar *ident;
	int i;
	
	g_assert (data);
	g_assert (identifier);
	g_assert (GCK_IS_DATA_FILE (df));
	
	/* Check that this is unique */
	for (i = 0; i < array->len; ++i) {
		ident = g_ptr_array_index (array, i);
		g_assert (ident);
		g_assert_cmpstr (ident, !=, identifier);
	}
	
	/* Add it */
	g_ptr_array_add (array, g_strdup (identifier));
}

DEFINE_TEST(data_file_foreach)
{
	GckDataResult res;
	GPtrArray *array;
	
	res = gck_data_file_read_fd (data_file, private_fd, login);
	g_assert (res == GCK_DATA_SUCCESS);
	
	array = g_ptr_array_new ();
	gck_data_file_foreach_entry (data_file, foreach_entry, array);
	g_assert (array->len == 4);
	
	g_ptr_array_add (array, NULL);
	g_strfreev ((gchar**)g_ptr_array_free (array, FALSE));
}

DEFINE_TEST(unique_entry)
{
	GckDataResult res;
	gchar *identifier;
	
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* Should change an identifier that conflicts */
	identifier = g_strdup ("identifier-public"); 
	res = gck_data_file_unique_entry (data_file, &identifier);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert_cmpstr (identifier, !=, "identifier-public");
	g_free (identifier);

	/* Shouldn't change a unique identifier */
	identifier = g_strdup ("identifier-unique"); 
	res = gck_data_file_unique_entry (data_file, &identifier);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert_cmpstr (identifier, ==, "identifier-unique");
	g_free (identifier);
	
	/* Should be able to get from NULL */
	identifier = NULL;
	res = gck_data_file_unique_entry (data_file, &identifier);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (identifier != NULL);
	g_assert (identifier[0] != 0);
	g_free (identifier);
}

DEFINE_TEST(have_sections)
{
	GckDataResult res;
	
	res = gck_data_file_read_fd (data_file, public_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);
	
	/* No private section */
	g_assert (gck_data_file_have_section (data_file, GCK_DATA_FILE_SECTION_PUBLIC));
	g_assert (!gck_data_file_have_section (data_file, GCK_DATA_FILE_SECTION_PRIVATE));

	/* Read private stuff into file, without login */
	res = gck_data_file_read_fd (data_file, private_fd, NULL);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Should have a private section even without login */
	g_assert (gck_data_file_have_section (data_file, GCK_DATA_FILE_SECTION_PUBLIC));
	g_assert (gck_data_file_have_section (data_file, GCK_DATA_FILE_SECTION_PRIVATE));

	/* Read private stuff into file, with login */
	g_assert (lseek (private_fd, 0, SEEK_SET) == 0);
	res = gck_data_file_read_fd (data_file, private_fd, login);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Should have a private section now with login */
	g_assert (gck_data_file_have_section (data_file, GCK_DATA_FILE_SECTION_PUBLIC));
	g_assert (gck_data_file_have_section (data_file, GCK_DATA_FILE_SECTION_PRIVATE));

	/* Read public stuff back into file*/
	g_assert (lseek (public_fd, 0, SEEK_SET) == 0);
	res = gck_data_file_read_fd (data_file, public_fd, login);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Shouldn't have a private section now  */
	g_assert (gck_data_file_have_section (data_file, GCK_DATA_FILE_SECTION_PUBLIC));
	g_assert (!gck_data_file_have_section (data_file, GCK_DATA_FILE_SECTION_PRIVATE));
}
