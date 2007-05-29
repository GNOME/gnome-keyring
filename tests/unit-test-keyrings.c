/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-keyrings.c: Test basic keyring functionality

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "unit-test-auto.h"
#include "library/gnome-keyring.h"

static GList* keyrings = NULL;
gchar* default_keyring = NULL;

#define PASSWORD "my-keyring-password"
#define KEYRING_NAME "unit-test-keyring"
#define INVALID_KEYRING_NAME "invalid-keyring-name"
#define DISPLAY_NAME "Item Display Name"
#define SECRET "item-secret"

/* 
 * Each test function must begin with (on the same line):
 *   void unit_test_
 * 
 * Tests will be run in the order specified here.
 */
 
void unit_test_stash_default (CuTest* cu)
{
	GnomeKeyringResult res;
	res = gnome_keyring_get_default_keyring_sync (&default_keyring);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	
}

void unit_test_list_keyrings (CuTest* cu)
{
	GnomeKeyringResult res;
	GList *l;
	
	res = gnome_keyring_list_keyring_names_sync (&keyrings);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	printf("\t\tkeyrings:\n");
	for (l = keyrings; l; l = g_list_next (l))
		printf("\t\t  %s\n", (gchar*)l->data);
}

void unit_test_create_keyring (CuTest* cu)
{
	GnomeKeyringResult res;
	
	res = gnome_keyring_create_sync (KEYRING_NAME, PASSWORD);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	res = gnome_keyring_create_sync (KEYRING_NAME, PASSWORD);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_ALREADY_EXISTS, res);
}

void unit_test_set_default_keyring (CuTest* cu)
{
	GnomeKeyringResult res;
	gchar* name;
	
	res = gnome_keyring_set_default_keyring_sync (KEYRING_NAME);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	

	res = gnome_keyring_set_default_keyring_sync (INVALID_KEYRING_NAME);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING, res);
		
	res = gnome_keyring_get_default_keyring_sync (&name);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	
	CuAssertPtrNotNull(cu, name);
	CuAssertStrEquals(cu, name, KEYRING_NAME);	
}

void unit_test_delete_keyring (CuTest* cu)
{
	GnomeKeyringResult res;
	gchar* name;
	
	res = gnome_keyring_delete_sync (KEYRING_NAME);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	
	
	res = gnome_keyring_delete_sync (KEYRING_NAME);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING, res);	

	res = gnome_keyring_get_default_keyring_sync (&name);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	CuAssert(cu, "returning deleted keyring as default", name == NULL || strcmp (name, KEYRING_NAME) != 0);
}

void unit_test_recreate_keyring (CuTest* cu)
{
	GnomeKeyringResult res;

	/* Create the test keyring again and set as default */
	res = gnome_keyring_create_sync (KEYRING_NAME, PASSWORD);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	
	res = gnome_keyring_set_default_keyring_sync (KEYRING_NAME);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);		
}

void unit_test_create_list_items (CuTest* cu)
{
	GnomeKeyringResult res;
	guint id, id2, id3;
	GList *ids;
	GnomeKeyringItemInfo *info;
	GnomeKeyringAttributeList* attrs;

	/* Try in an invalid keyring */
	res = gnome_keyring_item_create_sync (INVALID_KEYRING_NAME, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      DISPLAY_NAME, NULL, SECRET, FALSE, &id);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING, res);

	/* Create for real in valid keyring */
	res = gnome_keyring_item_create_sync (KEYRING_NAME, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      DISPLAY_NAME, NULL, SECRET, FALSE, &id);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	/* Update the item, shouldn't create new */
	res = gnome_keyring_item_create_sync (KEYRING_NAME, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      DISPLAY_NAME, NULL, SECRET, TRUE, &id3);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	CuAssert(cu, "Updated item doesn't have the same id", id == id3);

	/* Update in NULL keyring, should use default */
	res = gnome_keyring_item_create_sync (NULL, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      DISPLAY_NAME, NULL, SECRET, TRUE, &id3);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	CuAssert(cu, "Updated item in NULL keyring doesn't have the same id", id == id3);
			
	/* Create new,  shouldn't update */
	res = gnome_keyring_item_create_sync (KEYRING_NAME, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      "Another display name", NULL, SECRET, FALSE, &id2);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	CuAssert(cu, "Two items created with the same id", id2 != id);
	
	/* Set some attributes, NULL keyring = default */
	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs, "bender", "rocks");
	res = gnome_keyring_item_set_attributes_sync (NULL, id, attrs);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	/* List ids that were created */
	res = gnome_keyring_list_item_ids_sync (KEYRING_NAME, &ids); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	/* Check that they're the same ids */
	CuAssert(cu, "Wrong number of ids created", g_list_length (ids) == 2);
	if (g_list_length (ids) == 2) {
		CuAssertIntEquals(cu, id, GPOINTER_TO_UINT (ids->data));
		CuAssertIntEquals(cu, id2, GPOINTER_TO_UINT (ids->next->data));
	}
	
	/* Now make sure both have that same secret */
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	if (res == GNOME_KEYRING_RESULT_OK)
		CuAssert(cu, "Secret has changed", strcmp (gnome_keyring_item_info_get_secret (info), SECRET) == 0);	

	/* And try it with a NULL (ie: default) keyring */
	res = gnome_keyring_item_get_info_sync (NULL, id2, &info); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	if (res == GNOME_KEYRING_RESULT_OK)
		CuAssert(cu, "Secret has changed", strcmp (gnome_keyring_item_info_get_secret (info), SECRET) == 0);
		
	/* Set the info back, should work */
	res = gnome_keyring_item_set_info_sync (NULL, id2, info);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	/* Make sure it's still the same */
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	if (res == GNOME_KEYRING_RESULT_OK)
		CuAssert(cu, "Secret has changed", strcmp (gnome_keyring_item_info_get_secret (info), SECRET) == 0);	
		
	/* Now delete the item */
	res = gnome_keyring_item_delete_sync (NULL, id);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	
}

void unit_test_find_keyrings (CuTest* cu)
{
	GnomeKeyringResult res;
	GnomeKeyringAttributeList* attrs;
	GnomeKeyringAttribute *attr;
	GnomeKeyringFound* f;
	guint id, i;
	GList *found;
	
	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs, "dog", "woof");
	gnome_keyring_attribute_list_append_string (attrs, "bird", "cheep");
	gnome_keyring_attribute_list_append_string (attrs, "iguana", "");
	gnome_keyring_attribute_list_append_uint32 (attrs, "num", 3);
	
	/* Create teh item */
	res = gnome_keyring_item_create_sync (NULL, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      "Barnyard", attrs, SECRET, FALSE, &id);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	/* Now try to find it */
	res = gnome_keyring_find_items_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET, attrs, &found);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	CuAssert(cu, "Too many items found", g_list_length (found) == 1);

	f = (GnomeKeyringFound*)found->data;	
	CuAssert(cu, "Wrong item found", f->item_id == id);
	CuAssert(cu, "Found in wrong keyring", strcmp (f->keyring, KEYRING_NAME) == 0);
	CuAssert(cu, "Wrong secret came back", strcmp (f->secret, SECRET) == 0);
	
	res = gnome_keyring_item_get_attributes_sync (NULL, id, &attrs);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	/* Make sure that dog does in fact woof */
	attr = NULL;
	for(i = 0; i < attrs->len; ++i)
	{
		attr = &gnome_keyring_attribute_list_index (attrs, i);
		if (strcmp (attr->name, "dog") == 0)
			break;
	}
	
	CuAssertPtrNotNull (cu, attr);
	if (attr) {
		CuAssert (cu, "invalid attribute found", strcmp (attr->name, "dog") == 0);
		CuAssert (cu, "invalid attribute type", attr->type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING);
		CuAssert (cu, "invalid attribute value", strcmp (attr->value.string, "woof") == 0);
	}
}

void unit_test_lock_keyrings (CuTest* cu)
{
	GnomeKeyringResult res;

	res = gnome_keyring_lock_all_sync ();
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	res = gnome_keyring_unlock_sync (KEYRING_NAME, PASSWORD);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
}

void unit_test_change_password (CuTest* cu)
{
	GnomeKeyringResult res;
	
	res = gnome_keyring_change_password_sync (KEYRING_NAME, PASSWORD, "new password"); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	
}

void unit_test_keyring_info (CuTest* cu)
{
	GnomeKeyringResult res;
	GnomeKeyringInfo *info;
	
	res = gnome_keyring_get_info_sync (NULL, &info);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	

	res = gnome_keyring_set_info_sync (NULL, info);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	
}

void unit_test_cleaup (CuTest* cu)
{
	GnomeKeyringResult res;
	
	res = gnome_keyring_delete_sync (KEYRING_NAME);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	

	if (default_keyring) {
		res = gnome_keyring_set_default_keyring_sync (default_keyring);
		CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	}	
}
