#include <stdlib.h>

#include "gnome-keyring.h"

static GMainLoop *loop = NULL;

static void
ok_cb  (GnomeKeyringResult result,
	gpointer           data)
{
	g_print ("%s: %d\n", (char *)data, result);
	g_main_loop_quit (loop);
}

static void
lock_all (void)
{
	gnome_keyring_lock_all (ok_cb, "lock all", NULL);
	g_main_loop_run (loop);
}

static void
lock (char *keyring)
{
	gnome_keyring_lock (keyring,
 			    ok_cb, "lock", NULL);
	g_main_loop_run (loop);
}

static void
unlock (char *keyring, char *password)
{
	gnome_keyring_unlock (keyring, password,
			      ok_cb, "unlock", NULL);
	g_main_loop_run (loop);
}

#if 0
static void
found_items (GnomeKeyringResult result,
	    GList *found_items,
	    gpointer data)
{
	g_print ("found items: res: %d nr items: %d\n", result, g_list_length (found_items));

	if (found_items != NULL) {
		GnomeKeyringFound *found = found_items->data;
		
		g_print ("Found item: keyring=%s, id=%d, secret='%s'\n", found->keyring, found->item_id, found->secret); 
		
	}
	
	g_main_loop_quit (loop); 
}
#endif

static void
creat_item_cb  (GnomeKeyringResult result,
		guint32            id,
		gpointer           data)
{
	g_print ("created item: res: %d id: %d\n", result, id);
	g_main_loop_quit (loop);
}

static void
create_item (char *name)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;

	attribute.name = g_strdup ("testattribute");
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = g_strdup ("test item");
	
	attributes = gnome_keyring_attribute_list_new ();
	g_array_append_val (attributes, attribute);
	
	gnome_keyring_item_create (NULL,
				   GNOME_KEYRING_ITEM_NOTE,
				   name,
				   attributes,
				   "secret text",
				   creat_item_cb, NULL, NULL);
	gnome_keyring_attribute_list_free (attributes);
	g_main_loop_run (loop);
}

static void
show_item_cb (GnomeKeyringResult result,
	      GnomeKeyringItemInfo  *info,
	      gpointer           data)
{
	char *secret;
	char *name;
	if (result != GNOME_KEYRING_RESULT_OK) {
		g_print ("error getting item info: %d\n", result);
	} else {
		name = gnome_keyring_item_info_get_display_name (info);
		secret = gnome_keyring_item_info_get_secret (info);
		g_print (" type: %u\n", gnome_keyring_item_info_get_type (info));
		g_print (" name: %s\n", name);
		g_print (" secret: %s\n", secret);
		g_print (" mtime: %lu\n", (unsigned long)gnome_keyring_item_info_get_mtime (info));
		g_print (" ctime: %lu\n", (unsigned long)gnome_keyring_item_info_get_ctime (info));
		gnome_keyring_free_password (secret);
		g_free (name);
	}
	
	g_main_loop_quit (loop);
}

static void
print_attributes (GnomeKeyringResult result,
		  GnomeKeyringAttributeList *attributes,
		  gpointer           data)
{
	GnomeKeyringAttribute *array;
	int i;
	
	if (result != GNOME_KEYRING_RESULT_OK) {
		g_print ("error getting item attributes: %d\n", result);
	} else {
		array = (GnomeKeyringAttribute *)attributes->data;
		g_print (" Attributes:\n");
		for (i = 0; i < attributes->len; i++) {
			if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				g_print ("  %s = '%s'\n", array[i].name, array[i].value.string);
			} else if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32) {
				g_print ("  %s = %u\n", array[i].name, array[i].value.integer);
			} else {
				g_print ("  %s = ** unsupported attribute type **\n", array[i].name);
			}
		}
	}
	
	g_main_loop_quit (loop);
}


static void
show_item (char *keyring, guint32 item_id)
{
	gnome_keyring_item_get_info (keyring, item_id,
				     show_item_cb, NULL, NULL);
	g_main_loop_run (loop);
	gnome_keyring_item_get_attributes (keyring, item_id,
					   print_attributes, NULL, NULL);
	g_main_loop_run (loop);
}

static void
delete_item (char *keyring, guint32 item_id)
{
	gnome_keyring_item_delete (keyring, item_id,
				   ok_cb, "delete item", NULL);
	g_main_loop_run (loop);
}

static void
set_item_secret (char *keyring, guint32 item_id, char *secret)
{
	GnomeKeyringItemInfo *info;

	info = gnome_keyring_item_info_new ();
	gnome_keyring_item_info_set_secret (info, secret);
	gnome_keyring_item_set_info (keyring, item_id, info, 
				     ok_cb, "set item", NULL);
	gnome_keyring_item_info_free (info);
	g_main_loop_run (loop);
}

static void
set_item_attribute (char *keyring, guint32 item_id, char *value)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;

	attribute.name = g_strdup ("testattribute");
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = g_strdup (value);
	
	attributes = gnome_keyring_attribute_list_new ();
	g_array_append_val (attributes, attribute);
	
	gnome_keyring_item_set_attributes (keyring, item_id, attributes, 
					   ok_cb, "set attributes", NULL);
	gnome_keyring_attribute_list_free (attributes);
	g_main_loop_run (loop);
}

static void
create_keyring (char *name, char *password)
{
	gnome_keyring_create (name,  password, 
			      ok_cb, "create keyring", NULL);
	g_main_loop_run (loop);
}

static void
set_default (char *name)
{
	gnome_keyring_set_default_keyring (name,
					   ok_cb, "set default", NULL);
	g_main_loop_run (loop);
}

int
main (int argc, char *argv[])
{
	char arg;

	loop = g_main_loop_new (NULL, FALSE);
	
	arg = 0;
	if (argc >= 2) {
		arg = argv[1][0];
	}

	if (arg == 'L') {
		lock_all ();
	} else if (arg == 'l') {
		if (argc >= 3) {
			lock (argv[2]);
		} else {
			lock (NULL);
		}
	} else if (arg == 'u') {
		if (argc >= 4) {
			unlock (argv[2], argv[3]);
		} else {
			g_print ("unlock requires keyring and password\n");
		}
	} else if (arg == 'c') {
		if (argc >= 3) {
			create_item (argv[2]);
		} else {
			g_print ("create item requires item name\n");
		}
	} else if (arg == 'i') {
		if (argc >= 4) {
			show_item (argv[2], atoi(argv[3]));
		} else {
			g_print ("must give keyring & item id to show\n");
		}
	} else if (arg == 'd') {
		if (argc >= 4) {
			delete_item (argv[2] ,atoi (argv[3]));
		} else {
			g_print ("must give keyring & item id to delete\n");
		}
	} else if (arg == 's') {
		if (argc >= 5) {
			set_item_secret (argv[2] ,atoi (argv[3]), argv[4]);
		} else {
			g_print ("must give keyring & item id & secret\n");
		}
	} else if (arg == 'a') {
		if (argc >= 5) {
			set_item_attribute (argv[2] ,atoi (argv[3]), argv[4]);
		} else {
			g_print ("must give keyring & item id & attribute value\n");
		}
	} else if (arg == 'k') {
		if (argc >= 4) {
			create_keyring (argv[2], argv[3]);
		} else if (argc >= 3) {
			create_keyring (argv[2], NULL);
		} else {
			g_print ("create keyring requires keyring name\n");
		}
	} else if (arg == 'd') {
		if (argc >= 3) {
			set_default (argv[2]);
		} else {
			set_default (NULL);
		}
	} else {
		g_print ("unsupported test\n");
	}
	
	
	return 0;
}
