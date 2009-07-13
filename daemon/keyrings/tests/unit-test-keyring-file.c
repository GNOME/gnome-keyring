/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-keyrings-file.c: Test Keyring file formats

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

#include "run-auto-test.h"

#include "egg/egg-secure-memory.h"

#include "keyrings/gkr-keyring.h"

#include "library/gnome-keyring-private.h"

#include "util/gkr-location.h"

#include <glib.h>
#include <string.h>

static GQuark
location_for_test_data (const gchar *filename)
{
	GQuark quark;
	gchar *path;
	
	path = g_build_filename (test_dir_testdata (), filename, NULL);
	quark = gkr_location_from_path (path);
	g_free (path);
	
	return quark;
}
 
static void
validate_keyring_contents (GkrKeyring *keyring)
{
	GnomeKeyringAccessControl *ac;
	GkrKeyringItem* item; 
	GArray *attrs;
	
	/* The keyring itself */
	/* "Missing keyring name" */
	g_assert (keyring->keyring_name != NULL);
	/* "Invalid keyring name" */
	g_assert_cmpstr (keyring->keyring_name, ==, "unit-test-keyring");
	/* "Bad lock settings" */
	g_assert (!keyring->lock_on_idle && keyring->lock_timeout == 0);
	/* "Bad Creation Time" */
	g_assert_cmpint (keyring->ctime, ==, 1198027852);
	/* "Bad Modification Time" */
	g_assert_cmpint (keyring->mtime, ==, 1198027852);
	/* "Wrong number of items" */
	g_assert_cmpint (g_list_length (keyring->items), ==, 2);
	
	/* Item #2 */
	item = gkr_keyring_get_item (keyring, 2);
	/* "Couldn't find item" */
	g_assert (item != NULL);
	/* "Invalid item type" */
	g_assert_cmpint (item->type, ==, GNOME_KEYRING_ITEM_GENERIC_SECRET);
	/* "Missing secret" */
	g_assert (item->secret != NULL);
	/* "Wrong secret" */
	g_assert_cmpstr (item->secret, ==, "item-secret");
	/* "Bad Creation Time" */
	g_assert_cmpint (item->ctime, ==, 1198027852);
	
	/* Item #2 ACL */
	/* "Bad ACLs" */
	g_assert_cmpint (g_list_length (item->acl), ==, 1);
	ac = (GnomeKeyringAccessControl*)item->acl->data;
	/* "Invalid ACL" */
	g_assert (ac && ac->application);
	/* "Invalid ACL Path" */
	g_assert (ac->application->pathname && strstr (ac->application->pathname, "run-auto-test"));
	/* "Invalid ACL Display Name" */
	g_assert (ac->application->display_name);
	g_assert_cmpstr (ac->application->display_name, ==, "run-auto-test");
	/* "Invalid ACL Access Type" */
	g_assert_cmpint (ac->types_allowed, ==, (GNOME_KEYRING_ACCESS_READ | GNOME_KEYRING_ACCESS_WRITE | GNOME_KEYRING_ACCESS_REMOVE)); 
		
	/* Item #3 */
	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs, "dog", "woof");
	gnome_keyring_attribute_list_append_string (attrs, "bird", "cheep");
	gnome_keyring_attribute_list_append_string (attrs, "iguana", "");
	gnome_keyring_attribute_list_append_uint32 (attrs, "num", 3); 
	item = gkr_keyring_find_item (keyring, GNOME_KEYRING_ITEM_GENERIC_SECRET, attrs, TRUE);
	gnome_keyring_attribute_list_free (attrs);
	/* "Couldn't find item #3" */
	g_assert (item != NULL);
	/* "Invalid item found" */
	g_assert_cmpint (item->id, ==, 3);
	/* "Invalid item type" */
	g_assert_cmpint (item->type, ==, GNOME_KEYRING_ITEM_GENERIC_SECRET);
	/* "Missing secret" */
	g_assert (item->secret != NULL);
	/* "Wrong secret" */
	g_assert_cmpstr (item->secret, ==, "item-secret");
}

DEFINE_TEST(keyring_parse_encrypted)
{
	GkrKeyring *encrypted, *plain;
	EggBuffer buffer, output;
	guchar *data;
	gsize n_data;
	gint ret;
	gboolean success;
	
	encrypted = gkr_keyring_new ("encrypted", 0);
	encrypted->password = "my-keyring-password";
	plain = gkr_keyring_new ("plain", 0);
	
	data = test_read_testdata ("encrypted.keyring", &n_data);

	/* Parse it */
	egg_buffer_init_allocated (&buffer, data, n_data, NULL);
	data = g_memdup (data, n_data); /* Make a copy for double parse */
	ret = gkr_keyring_binary_parse (encrypted, &buffer);
	egg_buffer_uninit (&buffer);
	/* "couldn't parse encrypted keyring" */
	g_assert (ret == 1);
	/* "didn't unlock encrypted keyring" */
	g_assert (!encrypted->locked);
	
	validate_keyring_contents (encrypted);

	/* Double parse shouldn't change it */
	egg_buffer_init_allocated (&buffer, (guchar*)data, n_data, NULL);
	ret = gkr_keyring_binary_parse (encrypted, &buffer);
	egg_buffer_uninit (&buffer);
	/* "couldn't parse encrypted keyring" */
	g_assert (ret == 1);
	/* "didn't unlock encrypted keyring" */
	g_assert (!encrypted->locked);
	
	validate_keyring_contents (encrypted);
	
	/* Output same data in the cleartext format */
	egg_buffer_init (&output, 128);
	success = gkr_keyring_textual_generate (encrypted, &output);
	/* "couldn't generate textual data" */
	g_assert (success);
	
	/* Make sure it parses */
	ret = gkr_keyring_textual_parse (plain, &output);
	/* "couldn't parse generated textual data" */
	g_assert (ret == 1);
	/* "keyring should not be locked" */
	g_assert (!plain->locked);
	
	validate_keyring_contents (plain);
}

DEFINE_TEST(keyring_parse_plain)
{
	GkrKeyring *keyring;
	EggBuffer buffer;
	guchar *data;
	gsize n_data;
	gint ret;
	
	keyring = gkr_keyring_new ("plain", 0);
	
	data = test_read_testdata ("plain.keyring", &n_data);
		
	/* Parse it */
	egg_buffer_init_static (&buffer, (guchar*)data, n_data);
	ret = gkr_keyring_textual_parse (keyring, &buffer);
	/* "couldn't parse generated textual data" */
	g_assert (ret == 1);
	/* "keyring should not be locked" */
	g_assert (!keyring->locked);
	
	validate_keyring_contents (keyring);
	
	/* Double parse shouldn't change it */
	egg_buffer_init_static (&buffer, (guchar*)data, n_data);
	ret = gkr_keyring_textual_parse (keyring, &buffer);
	/* "couldn't parse generated textual data" */
	g_assert (ret == 1);
	/* "keyring should not be locked" */
	g_assert (!keyring->locked);
	
	validate_keyring_contents (keyring);
}

DEFINE_TEST(keyring_double_lock_encrypted)
{
	GkrKeyring *encrypted;
	gboolean ret;
	
	encrypted = gkr_keyring_new ("encrypted", location_for_test_data ("encrypted.keyring"));
	encrypted->password = egg_secure_strdup ("my-keyring-password");
	ret = gkr_keyring_update_from_disk (encrypted);
	/* "couldn't parse generated textual data" */
	g_assert (ret == TRUE);
	
	/* Lock it */
	gkr_keyring_lock (encrypted);
	g_assert (encrypted->locked);
	
	/* Should succeed */
	gkr_keyring_lock (encrypted);
	g_assert (encrypted->locked);
	
	g_object_unref (encrypted);
}

DEFINE_TEST(keyring_double_lock_plain)
{
	GkrKeyring *keyring;
	gboolean ret;
	
	keyring = gkr_keyring_new ("plain", location_for_test_data ("plain.keyring"));
	ret = gkr_keyring_update_from_disk (keyring);
	/* "couldn't parse generated textual data" */
	g_assert (ret == TRUE);

	/* Lock it, shouldn't actually work, no way to lock */
	gkr_keyring_lock (keyring);
	g_assert (!keyring->locked);
	
	/* Shouldn't crash */
	gkr_keyring_lock (keyring);
	g_assert (!keyring->locked);
	
	g_object_unref (keyring);
}
