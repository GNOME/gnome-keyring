
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "run-prompt-test.h"
#include "library/gnome-keyring.h"

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
 
static void 
TELL(const char* what)
{
	printf("INTERACTION: %s\n", what);
}


gchar* default_keyring = NULL;

#define KEYRING_NAME "unit-test-keyring"
#define DISPLAY_NAME "Item Display Name"
#define SECRET "item-secret"

void unit_test_stash_default (CuTest* cu)
{
	GnomeKeyringResult res;
	res = gnome_keyring_get_default_keyring_sync (&default_keyring);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);	
}

void unit_test_create_prompt_keyring (CuTest* cu)
{
	GnomeKeyringResult res;

	TELL("press 'DENY'");
	res = gnome_keyring_create_sync (KEYRING_NAME, NULL);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_DENIED, res);
	
	TELL("type in a new keyring password and click 'OK'");
	
	res = gnome_keyring_create_sync (KEYRING_NAME, NULL);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	res = gnome_keyring_create_sync (KEYRING_NAME, NULL);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_ALREADY_EXISTS, res);
	
	res = gnome_keyring_set_default_keyring_sync (KEYRING_NAME);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
}


void unit_test_change_prompt_keyring (CuTest* cu)
{
	GnomeKeyringResult res;

	TELL("press 'DENY' here");	

	res = gnome_keyring_change_password_sync (KEYRING_NAME, NULL, NULL); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_DENIED, res);
	
	TELL("type in original password then new keyring password and click 'OK'");

	res = gnome_keyring_change_password_sync (KEYRING_NAME, NULL, NULL); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res); 
}

void unit_test_acls (CuTest* cu)
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
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	/* Get the ACLs */
	gnome_keyring_item_get_acl_sync (KEYRING_NAME, id, &acls);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

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
	
	CuAssert(cu, "couldn't find ACL for this process on new item", acl != NULL);
	
	/* Now remove all ACLs from the item */
	l = NULL;
	gnome_keyring_item_set_acl_sync (KEYRING_NAME, id, l);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	/* Shouldn't be prompted here, not accessing secrets */
	TELL("No prompt should show up at this point");
	res = gnome_keyring_item_get_info_full_sync (KEYRING_NAME, id, GNOME_KEYRING_ITEM_INFO_BASICS, &info);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	CuAssert(cu, "returned a secret when it shouldn't have", gnome_keyring_item_info_get_secret (info) == NULL);
	sleep(2);

	/* Now try to read the item, should be prompted */
	TELL("Press 'Allow Once' to give program access to the data");
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	CuAssert(cu, "didn't return a secret when it should have", gnome_keyring_item_info_get_secret (info) != NULL);
	
	/* Now try to read the item again, give forever access */
	TELL("Press 'Always Allow' to give program access to the data");
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	/* Now try to read the item, should be prompted */
	TELL("No prompt should show up at this point");
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	sleep(2);	
}

void unit_test_application_secret (CuTest* cu)
{
	GnomeKeyringResult res;
	GnomeKeyringItemInfo *info;
	GList *acls;
	guint id;
	
	/* Create teh item */
	res = gnome_keyring_item_create_sync (KEYRING_NAME, 
			GNOME_KEYRING_ITEM_GENERIC_SECRET | GNOME_KEYRING_ITEM_APPLICATION_SECRET, 
	                "Fry", NULL, "secret", FALSE, &id);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	/* Remove all ACLs from the item */
	acls = NULL;
	gnome_keyring_item_set_acl_sync (KEYRING_NAME, id, acls);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	/* Shouldn't be prompted here, not accessing secrets */
	TELL("No prompt should show up at this point");
	res = gnome_keyring_item_get_info_full_sync (KEYRING_NAME, id, GNOME_KEYRING_ITEM_INFO_BASICS, &info);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_DENIED, res);
	sleep(2);

	/* Now try to read the item, should be prompted */
	TELL("No prompt should show up at this point");
	res = gnome_keyring_item_get_info_sync (KEYRING_NAME, id, &info); 
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_DENIED, res);
	sleep(2);
}

void unit_test_unlock_prompt (CuTest *cu)
{
	GnomeKeyringResult res;
	
	res = gnome_keyring_lock_all_sync ();
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	TELL("press 'DENY' here");
	res = gnome_keyring_unlock_sync (KEYRING_NAME, NULL);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_DENIED, res);

	TELL("type in keyring password and click 'OK'");
	res = gnome_keyring_unlock_sync (KEYRING_NAME, NULL);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
}

void unit_test_find_locked (CuTest *cu)
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
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);
	
	/* Lock the keyring ... */
	res = gnome_keyring_lock_all_sync ();
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	/* Now, try to access the item */	
	TELL("type in keyring password and click 'OK'");
	res = gnome_keyring_find_items_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET, attrs, &found);
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_OK, res);

	CuAssert(cu, "Wrong number of items found", g_list_length (found) == 1);
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
