/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-keyrings.c - test app 

   Copyright (C) 2003 Red Hat, Inc

   The Gnome Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Alexander Larsson <alexl@redhat.com>
*/
#include <stdlib.h>

#include "library/gnome-keyring.h"

static GMainLoop *loop = NULL;

static void
print_attributes (GnomeKeyringAttributeList *attributes)
{
	GnomeKeyringAttribute *array;
	int i;
	
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

static const gchar* result_msg[] = {
	"GNOME_KEYRING_RESULT_OK",
	"GNOME_KEYRING_RESULT_DENIED",
	"GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON",
	"GNOME_KEYRING_RESULT_ALREADY_UNLOCKED",
	"GNOME_KEYRING_RESULT_NO_SUCH_KEYRING",
	"GNOME_KEYRING_RESULT_BAD_ARGUMENTS",
	"GNOME_KEYRING_RESULT_IO_ERROR",
	"GNOME_KEYRING_RESULT_CANCELLED",
	"GNOME_KEYRING_RESULT_ALREADY_EXISTS"
};

static const gchar*
get_msg_for_keyring_result (GnomeKeyringResult result)
{
	if (result<=GNOME_KEYRING_RESULT_ALREADY_EXISTS) {
		return result_msg[result];
	} else {
		return "Unknown GnomeKeyringResult";
	}
}

static void
ok_cb  (GnomeKeyringResult result,
	gpointer           data)
{
	g_print ("%s: %d (%s)\n", (char *)data, result, get_msg_for_keyring_result (result));
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

static void
find_items_cb (GnomeKeyringResult result,
	       GList *found_items,
	       gpointer data)
{
	g_print ("found items: res: %d (%s) nr items: %d\n", result, get_msg_for_keyring_result (result), g_list_length (found_items));

	if (found_items != NULL) {
		GnomeKeyringFound *found = found_items->data;
		
		g_print ("Found item: keyring=%s, id=%d, secret='%s'\n", found->keyring, found->item_id, found->secret); 
		print_attributes (found->attributes);
	}
	
	g_main_loop_quit (loop); 
}

static void
find_items (char *attr_val)
{
	gnome_keyring_find_itemsv (GNOME_KEYRING_ITEM_NOTE,
				   find_items_cb, NULL, NULL,
				   "testattribute", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, attr_val,
				   NULL);
	g_main_loop_run (loop);
}

static void
creat_item_cb  (GnomeKeyringResult result,
		guint32            id,
		gpointer           data)
{
	g_print ("created item: res: %d (%s) id: %d\n", result, get_msg_for_keyring_result (result), id);
	g_main_loop_quit (loop);
}

static void
create_item (char *name, char *attr_name, gboolean update_if_exists)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;

	attribute.name = g_strdup ("testattribute");
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = g_strdup (attr_name);
	
	attributes = gnome_keyring_attribute_list_new ();
	g_array_append_val (attributes, attribute);
	
	gnome_keyring_item_create (NULL,
				   GNOME_KEYRING_ITEM_NOTE,
				   name,
				   attributes,
				   "secret text",
				   update_if_exists,
				   creat_item_cb, NULL, NULL);
	gnome_keyring_attribute_list_free (attributes);
	g_main_loop_run (loop);
}

static void
creat_application_item_cb  (GnomeKeyringResult result,
			    guint32            id,
			    gpointer           data)
{
	g_print ("created application item: res: %d (%s) id: %d\n", result, get_msg_for_keyring_result (result), id);
	g_main_loop_quit (loop);
}

static void
create_application_item (char *name, char *attr_name, gboolean update_if_exists)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;

	attribute.name = g_strdup ("testattribute");
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = g_strdup (attr_name);
	
	attributes = gnome_keyring_attribute_list_new ();
	g_array_append_val (attributes, attribute);
	
	gnome_keyring_item_create (NULL,
				   GNOME_KEYRING_ITEM_NOTE | GNOME_KEYRING_ITEM_APPLICATION_SECRET,
				   name,
				   attributes,
				   "application secret text",
				   update_if_exists,
				   creat_application_item_cb, NULL, NULL);
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
		g_print ("error getting item info: %d (%s)\n", result, get_msg_for_keyring_result (result));
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
print_attributes_cb (GnomeKeyringResult result,
		  GnomeKeyringAttributeList *attributes,
		  gpointer           data)
{
	if (result != GNOME_KEYRING_RESULT_OK) {
		g_print ("error getting item attributes: %d (%s)\n", result, get_msg_for_keyring_result (result));
	} else {
		print_attributes (attributes);
	}

	g_main_loop_quit (loop);
}

static void
show_item (char *keyring, guint32 item_id, guint32 parts)
{
	gnome_keyring_item_get_info_full (keyring, item_id, parts,
				     	  show_item_cb, NULL, NULL);
	g_main_loop_run (loop);
	gnome_keyring_item_get_attributes (keyring, item_id,
					   print_attributes_cb, NULL, NULL);
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

static void
set_network_cb  (GnomeKeyringResult result,
		 guint32            id,
		 gpointer           data)
{
	g_print ("set network password: res: %d id: %d\n", result, id);
	g_main_loop_quit (loop);
}


static void
set_network (char *server, char *password)
{
	gnome_keyring_set_network_password (NULL /* default keyring */,
					    NULL,
					    NULL,
					    server,
					    NULL,
					    "smb",
					    NULL,
					    0,
					    password,
					    set_network_cb, NULL, NULL);
	g_main_loop_run (loop);
}

static void
set_network_sync (char *server, char *password)
{
	guint32 id;
	GnomeKeyringResult res;
	res = gnome_keyring_set_network_password_sync (NULL /* default keyring */,
						       NULL,
						       NULL,
						       server,
						       NULL,
						       "smb",
						       NULL,
						       0,
						       password,
						       &id);
	g_print ("set network password: res: %d id: %d\n", res, id);
}

static void
find_network (char *server)
{
	GnomeKeyringResult res;
	GList *list, *l;

	list = NULL;
	res = gnome_keyring_find_network_password_sync (NULL, NULL,
							server, NULL,
							"smb",
							NULL, 
							0,
							&list);
	g_print ("find network password, res: %d, len: %d\n", res, g_list_length (list));
	for (l = list; l != NULL; l = l->next) {
		GnomeKeyringNetworkPasswordData *data;
		data = l->data;

		g_print ("%s:%d - proto: %s, server: %s, object: %s, authtype: %s, port: %d, user: %s, domain: %s, password: %s\n",
			 data->keyring,
			 data->item_id,
			 data->protocol,
			 data->server,
			 data->object,
			 data->authtype,
			 data->port,
			 data->user,
			 data->domain,
			 data->password);
	}
}

static void 
list_items_cb (GnomeKeyringResult result, GList *list, gpointer data)
{
	g_print ("list items: res: %d (%s)\n", result, get_msg_for_keyring_result (result));
	for ( ; list; list = list->next)
		g_print ("   id: %d\n", GPOINTER_TO_UINT (list->data));
	g_main_loop_quit (loop);
}

static void
list_items (const char *keyring)
{
	gnome_keyring_list_item_ids (keyring, list_items_cb, NULL, NULL);
	g_main_loop_run (loop);
}

int
main (int argc, char *argv[])
{
	char arg;

	g_set_application_name("test-keyring");
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
		if (argc >= 4) {
			create_item (argv[2], argv[3], FALSE);
		} else {
			g_print ("create item requires item name and attr value\n");
		}
	} else if (arg == 'C') {
		if (argc >= 4) {
			create_item (argv[2], argv[3], TRUE);
		} else {
			g_print ("create item requires item name and attr value\n");
		}

 	} else if (arg == 'A') {
 		if (argc >= 4) {
 			create_application_item (argv[2], argv[3], FALSE);
 		} else {
 			g_print ("create application item requires item name and attr value\n");
 		}

	/* Show complete item information */
	} else if (arg == 'i') {
		if (argc >= 4) {
			show_item (argv[2], atoi(argv[3]), GNOME_KEYRING_ITEM_INFO_SECRET);
		} else {
			g_print ("must give keyring & item id to show\n");
		}

	/* Show basic item information */
	} else if (arg == 'b') {
		if (argc >= 4) {
			show_item (argv[2], atoi(argv[3]), GNOME_KEYRING_ITEM_INFO_BASICS);
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
	} else if (arg == 'f') {
		if (argc >= 3) {
			find_items (argv[2]);
		} else {
			g_print ("must give testattribute value\n");
		}
	} else if (arg == 'k') {
		if (argc >= 4) {
			create_keyring (argv[2], argv[3]);
		} else if (argc >= 3) {
			create_keyring (argv[2], NULL);
		} else {
			g_print ("create keyring requires keyring name\n");
		}
	} else if (arg == 'D') {
		if (argc >= 3) {
			set_default (argv[2]);
		} else {
			set_default (NULL);
		}
	} else if (arg == 'n') {
		if (argc >= 4) {
			set_network (argv[2], argv[3]);
		} else {
			g_print ("need server & password\n");
		}
	} else if (arg == 'N') {
		if (argc >= 4) {
			set_network_sync (argv[2], argv[3]);
		} else {
			g_print ("need server & password\n");
		}
	} else if (arg == 'p') {
		if (argc >= 3) {
			find_network (argv[2]);
		} else {
			g_print ("need server\n");
		}
	} else if (arg == 't') {
		g_print ("gnome keyring is: %s\n",
			 gnome_keyring_is_available ()?"available":"not available");
	} else if (arg == 'I') {
		if (argc >= 3) {
			list_items(argv[2]);
		} else {
			g_print ("need keyring\n");
		}
	} else {
		g_print ("unsupported test\n");
	}
	
	
	return 0;
}
