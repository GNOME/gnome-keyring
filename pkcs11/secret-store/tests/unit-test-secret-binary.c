/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-secret-binary.c: Test binary keyring read and write

   Copyright (C) 2009 Stefan Walter

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

#include "run-auto-test.h"
#include "test-secret-module.h"

#include "gck-secret-binary.h"
#include "gck-secret-collection.h"
#include "gck-secret-data.h"
#include "gck-secret-fields.h"
#include "gck-secret-item.h"

#include "gck/gck-secret.h"

#include "pkcs11/pkcs11i.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static GckModule *module = NULL;
static GckSession *session = NULL;
static GckSecretCollection *collection = NULL;
static GckSecretData *sdata = NULL;

DEFINE_SETUP(binary)
{
	GckSecret *master;

	module = test_secret_module_initialize_and_enter ();
	session = test_secret_module_open_session (TRUE);

	collection = g_object_new (GCK_TYPE_SECRET_COLLECTION,
	                           "module", module,
	                           "identifier", "test",
	                           "label", "brigadooooooooooooon",
	                           NULL);
	
	sdata = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	master = gck_secret_new_from_password ("my-keyring-password");
	gck_secret_data_set_master (sdata, master);
	g_object_unref (master);

	g_assert (GCK_IS_SECRET_COLLECTION (collection));
	
}

DEFINE_TEARDOWN(binary)
{
	if (collection)
		g_object_unref (collection);
	collection = NULL;

	if (sdata)
		g_object_unref (sdata);
	sdata = NULL;

	test_secret_module_leave_and_finalize ();
	module = NULL;
	session = NULL;
}

DEFINE_TEST(binary_read)
{
	GckDataResult res;
	guchar *data;
	gsize n_data;

	data = test_data_read ("encrypted.keyring", &n_data);
	res = gck_secret_binary_read (collection, sdata, data, n_data);
	g_free (data);

	test_secret_collection_validate (collection, sdata);

	g_assert (res == GCK_DATA_SUCCESS);
}

DEFINE_TEST(binary_read_wrong_format)
{
	GckDataResult res;
	guchar *data;
	gsize n_data;

	data = test_data_read ("plain.keyring", &n_data);
	res = gck_secret_binary_read (collection, sdata, data, n_data);
	g_free (data);

	g_assert (res == GCK_DATA_UNRECOGNIZED);
}

DEFINE_TEST(binary_read_wrong_master)
{
	GckDataResult res;
	GckSecret *master;
	guchar *data;
	gsize n_data;

	master = gck_secret_new_from_password ("wrong");
	gck_secret_data_set_master (sdata, master);
	g_object_unref (master);

	data = test_data_read ("encrypted.keyring", &n_data);
	res = gck_secret_binary_read (collection, sdata, data, n_data);
	g_free (data);

	g_assert (res == GCK_DATA_LOCKED);
}

DEFINE_TEST(binary_read_sdata_but_no_master)
{
	GckDataResult res;
	guchar *data;
	gsize n_data;

	gck_secret_data_set_master (sdata, NULL);

	data = test_data_read ("encrypted.keyring", &n_data);
	res = gck_secret_binary_read (collection, sdata, data, n_data);
	g_free (data);

	g_assert (res == GCK_DATA_LOCKED);
}

DEFINE_TEST(binary_write)
{
	GckDataResult res;
	guchar *data;
	gsize n_data;

	test_secret_collection_populate (collection, sdata);

	res = gck_secret_binary_write (collection, sdata, &data, &n_data);
	g_assert (res == GCK_DATA_SUCCESS);
	g_assert (data);
	g_assert (n_data);

	/* Try parsing it again */
	res = gck_secret_binary_read (collection, sdata, data, n_data);
	g_assert (res == GCK_DATA_SUCCESS);
}

DEFINE_TEST(binary_remove_unavailable)
{
	GckDataResult res;
	GList *items;
	guchar *data;
	gsize n_data;

	data = test_data_read ("encrypted.keyring", &n_data);
	res = gck_secret_binary_read (collection, sdata, data, n_data);
	g_assert (res == GCK_DATA_SUCCESS);

	/* Two items from the file */
	items = gck_secret_collection_get_items (collection);
	g_assert_cmpint (g_list_length (items), ==, 2);
	g_list_free (items);

	/* Fill in some more data */
	test_secret_collection_populate (collection, sdata);

	/* Should have added three more */
	items = gck_secret_collection_get_items (collection);
	g_assert_cmpint (g_list_length (items), ==, 5);
	g_list_free (items);

	/* Re-read the keyring */
	res = gck_secret_binary_read (collection, sdata, data, n_data);
	g_assert (res == GCK_DATA_SUCCESS);

	/* And we're back to two */
	items = gck_secret_collection_get_items (collection);
	g_assert_cmpint (g_list_length (items), ==, 2);
	g_list_free (items);

	g_free (data);
}
