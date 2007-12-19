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

#include "common/gkr-secure-memory.h"

#include "keyrings/gkr-keyring.h"

#include "library/gnome-keyring-private.h"

#include <glib.h>
#include <string.h>

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void)
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void)
 * 
 * Tests be run in the order specified here.
 */
 
static void
validate_keyring_contents (GkrKeyring *keyring, CuTest *cu)
{
	GnomeKeyringAccessControl *ac;
	GkrKeyringItem* item; 
	GArray *attrs;
	
	/* The keyring itself */
	CuAssert (cu, "Missing keyring name", keyring->keyring_name != NULL);
	CuAssert (cu, "Invalid keyring name", g_str_equal (keyring->keyring_name, "unit-test-keyring"));
	CuAssert (cu, "Bad lock settings", !keyring->lock_on_idle && keyring->lock_timeout == 0);
	CuAssert (cu, "Bad Creation Time", keyring->ctime == 1198027852);
	CuAssert (cu, "Bad Modification Time", keyring->mtime == 1198027852);
	CuAssert (cu, "Wrong number of items", g_list_length (keyring->items) == 2);
	
	/* Item #2 */
	item = gkr_keyring_get_item (keyring, 2);
	CuAssert (cu, "Couldn't find item", item != NULL);
	CuAssert (cu, "Invalid item type", item->type == GNOME_KEYRING_ITEM_GENERIC_SECRET);
	CuAssert (cu, "Missing secret", item->secret != NULL);
	CuAssert (cu, "Wrong secret", g_str_equal (item->secret, "item-secret"));
	CuAssert (cu, "Bad Creation Time", item->ctime == 1198027852);
	
	/* Item #2 ACL */
	CuAssert (cu, "Bad ACLs", g_list_length (item->acl) == 1);
	ac = (GnomeKeyringAccessControl*)item->acl->data;
	CuAssert (cu, "Invalid ACL", ac && ac->application);
	CuAssert (cu, "Invalid ACL Path", ac->application->pathname && 
			g_str_equal (ac->application->pathname, "/data/projects/gnome-keyring/library/tests/.libs/run-auto-test"));
	CuAssert (cu, "Invalid ACL Display Name", ac->application->display_name && 
			g_str_equal (ac->application->display_name, "run-auto-test"));
	CuAssert (cu, "Invalid ACL Access Type", 
			ac->types_allowed == (GNOME_KEYRING_ACCESS_READ | GNOME_KEYRING_ACCESS_WRITE | GNOME_KEYRING_ACCESS_REMOVE)); 
		
	/* Item #3 */
	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs, "dog", "woof");
	gnome_keyring_attribute_list_append_string (attrs, "bird", "cheep");
	gnome_keyring_attribute_list_append_string (attrs, "iguana", "");
	gnome_keyring_attribute_list_append_uint32 (attrs, "num", 3); 
	item = gkr_keyring_find_item (keyring, GNOME_KEYRING_ITEM_GENERIC_SECRET, attrs);
	gnome_keyring_attribute_list_free (attrs);
	CuAssert (cu, "Couldn't find item #3", item != NULL);
	CuAssert (cu, "Invalid item found", item->id == 3);
	CuAssert (cu, "Invalid item type", item->type == GNOME_KEYRING_ITEM_GENERIC_SECRET);
	CuAssert (cu, "Missing secret", item->secret != NULL);
	CuAssert (cu, "Wrong secret", g_str_equal (item->secret, "item-secret"));
}

void unit_test_keyring_parse_encrypted (CuTest *cu)
{
	GkrKeyring *encrypted, *plain;
	GkrBuffer buffer, output;
	gchar *data;
	gsize n_data;
	gint ret;
	gboolean success;
	
	encrypted = gkr_keyring_new ("encrypted", 0);
	encrypted->password = "my-keyring-password";
	plain = gkr_keyring_new ("plain", 0);
	
	if (!g_file_get_contents ("test-data/encrypted.keyring", &data, &n_data, NULL))
		g_assert (FALSE && "couldn't read in encrypted.keyring");
		
	/* Parse it */
	gkr_buffer_init_allocated (&buffer, (guchar*)data, n_data, NULL);
	data = g_memdup (data, n_data); /* Make a copy for double parse */
	ret = gkr_keyring_binary_parse (encrypted, &buffer);
	gkr_buffer_uninit (&buffer);
	CuAssert (cu, "couldn't parse encrypted keyring", ret == 1);
	CuAssert (cu, "didn't unlock encrypted keyring", !encrypted->locked);
	
	validate_keyring_contents (encrypted, cu);

	/* Double parse shouldn't change it */
	gkr_buffer_init_allocated (&buffer, (guchar*)data, n_data, NULL);
	ret = gkr_keyring_binary_parse (encrypted, &buffer);
	gkr_buffer_uninit (&buffer);
	CuAssert (cu, "couldn't parse encrypted keyring", ret == 1);
	CuAssert (cu, "didn't unlock encrypted keyring", !encrypted->locked);
	
	validate_keyring_contents (encrypted, cu);
	
	/* Output same data in the cleartext format */
	gkr_buffer_init (&output, 128);
	success = gkr_keyring_textual_generate (encrypted, &output);
	CuAssert (cu, "couldn't generate textual data", success);
	
	/* Make sure it parses */
	ret = gkr_keyring_textual_parse (plain, &output);
	CuAssert (cu, "couldn't parse generated textual data", ret == 1);
	CuAssert (cu, "keyring should not be locked", !plain->locked);
	
	validate_keyring_contents (plain, cu);
}

void unit_test_keyring_parse_plain (CuTest *cu)
{
	GkrKeyring *keyring;
	GkrBuffer buffer;
	gchar *data;
	gsize n_data;
	gint ret;
	
	keyring = gkr_keyring_new ("plain", 0);
	
	if (!g_file_get_contents ("test-data/plain.keyring", &data, &n_data, NULL))
		g_assert (FALSE && "couldn't read in plain.keyring");
		
	/* Parse it */
	gkr_buffer_init_static (&buffer, (guchar*)data, n_data);
	ret = gkr_keyring_textual_parse (keyring, &buffer);
	CuAssert (cu, "couldn't parse generated textual data", ret == 1);
	CuAssert (cu, "keyring should not be locked", !keyring->locked);
	
	validate_keyring_contents (keyring, cu);
	
	/* Double parse shouldn't change it */
	gkr_buffer_init_static (&buffer, (guchar*)data, n_data);
	ret = gkr_keyring_textual_parse (keyring, &buffer);
	CuAssert (cu, "couldn't parse generated textual data", ret == 1);
	CuAssert (cu, "keyring should not be locked", !keyring->locked);
	
	validate_keyring_contents (keyring, cu);
}
