/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-keyrings-prompt.c: Test basic prompt functionality

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
#include <unistd.h>

#include "run-prompt-test.h"

#include "library/gnome-keyring.h"

static void 
TELL(const char* what)
{
	printf("INTERACTION: %s\n", what);
}


gchar* default_keyring = NULL;

#define KEYRING_NAME "unit-test-keyring"
#define DISPLAY_NAME "Item Display Name"
#define SECRET "item-secret"

DEFINE_TEST(stash_default)
{
	GnomeKeyringResult res;
	res = gnome_keyring_get_default_keyring_sync (&default_keyring);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
}

DEFINE_TEST(create_prompt_keyring)
{
	GnomeKeyringResult res;

	TELL("press 'DENY'");
	res = gnome_keyring_create_sync (KEYRING_NAME, NULL);
	g_assert_cmpint (GNOME_KEYRING_RESULT_DENIED, ==, res);
	
	TELL("type in a new keyring password and click 'OK'");
	
	res = gnome_keyring_create_sync (KEYRING_NAME, NULL);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	res = gnome_keyring_create_sync (KEYRING_NAME, NULL);
	g_assert_cmpint (GNOME_KEYRING_RESULT_ALREADY_EXISTS, ==, res);
	
	res = gnome_keyring_set_default_keyring_sync (KEYRING_NAME);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
}

DEFINE_TEST(change_prompt_keyring)
{
	GnomeKeyringResult res;

	TELL("press 'DENY' here");	

	res = gnome_keyring_change_password_sync (KEYRING_NAME, NULL, NULL); 
	g_assert_cmpint (GNOME_KEYRING_RESULT_DENIED, ==, res);
	
	TELL("type in original password then new keyring password and click 'OK'");

	res = gnome_keyring_change_password_sync (KEYRING_NAME, NULL, NULL); 
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
}

DEFINE_TEST(acls)
{
	GnomeKeyringResult res;
	GnomeKeyringAccessControl *ac, *acl;
	GnomeKeyringItemInfo *info;
	GList *acls, *l;
	guint id;
	gchar *prog;
	
	/* Create teh item */
	res = gnome_keyring_item_create_sync (KEYRING_NAME, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      "Fry", NULL, "secret", FALSE, &id);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	/* Get the ACLs */
	gnome_keyring_item_get_acl_sync (KEYRING_NAME, id, &acls);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	/* Make sure we're in the list, since we created */
	prog = g_get_prgname ();
	acl = NULL;
	for (l = acls; l; l = g_list_next (l)) {
		ac = (GnomeKeyringAccessControl*)l->data;
		if (strstr (gnome_keyring_item_ac_get_path_name (ac), prog)) {
			acl = ac;
			break;
		}
	}
	
	/* "couldn't find ACL for this process on new item" */
	g_assert (acl != NULL);
	
	/* Now remove all ACLs from the item */
	l = NULL;
	gnome_keyring_item_set_acl_sync (KEYRING_NAME, id, l);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	/* Shouldn't be prompted here, not accessing secrets */
	TELL("No prompt should show up at this point");
	res = gnome_keyring_item_get_info_full_sync (KEYRING_NAME, id, GNOME_KEYRING_ITEM_INFO_BASICS, &info);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	/* "returned a secret when it shouldn't have" */
	g_assert (gnome_keyring_item_info_get_secret (info) == NULL);
	sleep(2);

	/* Now try to read the item, should be prompted */
#ifdef ENABLE_ACL_PROMPTS
	TELL("Press 'Allow Once' to give program access to the data");
#endif
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	/* "didn't return a secret when it should have" */
	g_assert (gnome_keyring_item_info_get_secret (info) != NULL);
	
#ifdef ENABLE_ACL_PROMPTS
	/* Now try to read the item again, give forever access */
	TELL("Press 'Always Allow' to give program access to the data");
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	/* Now try to read the item, should be prompted */
	TELL("No prompt should show up at this point");
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	sleep(2);	
#endif
}

DEFINE_TEST(application_secret)
{
	GnomeKeyringResult res;
	GnomeKeyringItemInfo *info;
	GList *acls;
	guint id;
	
	/* Create teh item */
	res = gnome_keyring_item_create_sync (KEYRING_NAME, 
			GNOME_KEYRING_ITEM_GENERIC_SECRET | GNOME_KEYRING_ITEM_APPLICATION_SECRET, 
	                "Fry", NULL, "secret", FALSE, &id);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	/* Remove all ACLs from the item */
	acls = NULL;
	gnome_keyring_item_set_acl_sync (KEYRING_NAME, id, acls);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	/* Shouldn't be prompted here, not accessing secrets */
	TELL("No prompt should show up at this point");
	res = gnome_keyring_item_get_info_full_sync (KEYRING_NAME, id, GNOME_KEYRING_ITEM_INFO_BASICS, &info);
	g_assert_cmpint (GNOME_KEYRING_RESULT_DENIED, ==, res);
	sleep(2);

	/* Now try to read the item, should be prompted */
	TELL("No prompt should show up at this point");
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	g_assert_cmpint (GNOME_KEYRING_RESULT_DENIED, ==, res);
	sleep(2);
}

DEFINE_TEST(unlock_prompt)
{
	GnomeKeyringResult res;
	
	res = gnome_keyring_lock_all_sync ();
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	TELL("press 'DENY' here");
	res = gnome_keyring_unlock_sync (KEYRING_NAME, NULL);
	g_assert_cmpint (GNOME_KEYRING_RESULT_DENIED, ==, res);

	TELL("type in keyring password and click 'OK'");
	res = gnome_keyring_unlock_sync (KEYRING_NAME, NULL);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
}

DEFINE_TEST(find_locked)
{
	GnomeKeyringResult res;
	GnomeKeyringAttributeList* attrs;
	guint id;
	GList *found;
	
	GTimeVal tv;
	guint32 unique;
	
	/* Make a unique value */
	g_get_current_time (&tv);
	unique = ((guint32)tv.tv_sec) ^ ((guint32)tv.tv_usec);
	
	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs, "dog", "barks");
	gnome_keyring_attribute_list_append_string (attrs, "bird", "tweets");
	gnome_keyring_attribute_list_append_string (attrs, "iguana", "silence");
	gnome_keyring_attribute_list_append_uint32 (attrs, "num", unique);

	/* Create teh item */
	res = gnome_keyring_item_create_sync (NULL, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      "Yay!", attrs, SECRET, FALSE, &id);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	/* Lock the keyring ... */
	res = gnome_keyring_lock_all_sync ();
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	/* Now, try to access the item */	
	TELL("type in keyring password and click 'OK'");
	res = gnome_keyring_find_items_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET, attrs, &found);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	/* "Wrong number of items found" */
	g_assert_cmpint (g_list_length (found), ==, 1);
}

DEFINE_TEST(get_info_locked)
{
	GnomeKeyringResult res;
	GnomeKeyringItemInfo *info;
	guint id;
	
	/* Create teh item */
	res = gnome_keyring_item_create_sync (NULL, GNOME_KEYRING_ITEM_GENERIC_SECRET, 
	                                      "My test locked", NULL, SECRET, FALSE, &id);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	/* Lock the keyring ... */
	res = gnome_keyring_lock_all_sync ();
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	/* Now, try to access the item */	
	TELL("type in keyring password and click 'OK'");
	res = gnome_keyring_item_get_info_sync (NULL, id, &info);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
}

DEFINE_TEST(cleanup)
{
	GnomeKeyringResult res;
	
	res = gnome_keyring_delete_sync (KEYRING_NAME);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	if (default_keyring) {
		res = gnome_keyring_set_default_keyring_sync (default_keyring);
		g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	}	
}
