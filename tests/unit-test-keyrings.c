/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-keyrings.c: Test basic keyring functionality

   Copyright (C) 2007 Nate Nielsen

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

   Author: Nate Nielsen <nielsen@memberwebs.com>
*/

#include <stdlib.h>
#include <stdio.h>

#include <glib.h>
#include <gnome-keyring.h>
#include "CuTest.h"

static GList* keyrings = NULL;
#define PASSWORD "my-keyring-password"
#define KEYRING_NAME "unit-test-keyring"
#define INVALID_KEYRING_NAME "invalid-keyring-name"
#define DISPLAY_NAME "Item Display Name"
#define SECRET "item-secret"

void unit_test_list_keyrings (CuTest* cu)
{
	GnomeKeyringResult res;
	GList *l;
	
	res = gnome_keyring_list_keyring_names_sync (&keyrings);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	printf("\t\tkeyrings:\n");
	for (l = keyrings; l; l = g_list_next (l))
		printf("\t\t  %s\n", l->data);
}

void unit_test_create_keyring (CuTest* cu)
{
	GnomeKeyringResult res;
	
	res = gnome_keyring_create_sync (KEYRING_NAME, PASSWORD);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	res = gnome_keyring_create_sync (KEYRING_NAME, PASSWORD);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_ALREADY_EXISTS, res);
}

void unit_test_create_items (CuTest* cu)
{
	GnomeKeyringResult res;
	guint id, id2, id3;

	res = gnome_keyring_item_create_sync (INVALID_KEYRING_NAME, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      DISPLAY_NAME, NULL, SECRET, FALSE, &id);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING, res);

	res = gnome_keyring_item_create_sync (KEYRING_NAME, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      DISPLAY_NAME, NULL, SECRET, FALSE, &id);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	res = gnome_keyring_item_create_sync (KEYRING_NAME, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      DISPLAY_NAME, NULL, SECRET, TRUE, &id3);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	CuAssert(cu, "Updated item doesn't have the same id", id == id3);
				
	res = gnome_keyring_item_create_sync (KEYRING_NAME, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      "Another display name", NULL, SECRET, FALSE, &id2);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	CuAssert(cu, "Two items created with the same id", id2 != id);
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

void unit_test_lock_keyrings (CuTest* cu)
{
	GnomeKeyringResult res;

	res = gnome_keyring_lock_all_sync ();
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	res = gnome_keyring_unlock_sync (KEYRING_NAME, PASSWORD);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
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

