/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* list-keyrings.c - test app to list keyrings

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
#include "library/gnome-keyring.h"

static GMainLoop *loop = NULL;


static void
string_callback  (GnomeKeyringResult result,
		  const char *str,
		  gpointer data)
{
	char **out;

	out = data;

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_print ("string op failed: %d\n", result);
		*out = NULL;
	} else {
		*out = g_strdup (str);
	}
	g_main_loop_quit (loop);
}


static void
print_keyring_info (GnomeKeyringResult result,
		    GnomeKeyringInfo  *info,
		    gpointer           data)
{
	gboolean *locked;
	locked = data;
	
	*locked = TRUE;
	if (result != GNOME_KEYRING_RESULT_OK) {
		g_print ("error getting keyring info: %d\n", result);
	} else {
		g_print ("lock_on_idle: %d\n", gnome_keyring_info_get_lock_on_idle (info));
		g_print ("lock timeout: %d\n", gnome_keyring_info_get_lock_timeout (info));
		g_print ("mtime: %lu\n", (unsigned long)gnome_keyring_info_get_mtime (info));
		g_print ("ctime: %lu\n", (unsigned long)gnome_keyring_info_get_ctime (info));
		g_print ("locked: %d\n", gnome_keyring_info_get_is_locked (info));
		*locked = gnome_keyring_info_get_is_locked (info);
	}
	
	g_main_loop_quit (loop);
}

static void
print_item_info (GnomeKeyringResult result,
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
get_items_callback (GnomeKeyringResult result,
		    GList *list,
		    gpointer data)
{
	GList **out;

	out = data;
	*out = NULL;
	
	if (result != GNOME_KEYRING_RESULT_OK) {
		g_print ("error getting item list: %d\n", result);
	} else {
		*out = g_list_copy (list);
	}
	
	g_main_loop_quit (loop);
}

static void
string_list_callback (GnomeKeyringResult result,
		      GList *list,
		      gpointer data)
{
	GList *l;
	char *name;
	GList **out;

	out = data;

	*out = NULL;
	
	if (result != GNOME_KEYRING_RESULT_OK) {
		g_print ("error getting keyring list: %d\n", result);
	} else {
		for (l = list; l != NULL; l = l->next) {
			name = l->data;
			*out = g_list_append (*out, g_strdup (name));
		}
	}
	
	g_main_loop_quit (loop);
}


int
main (int argc, char *argv[])
{
	GList *keyrings, *l, *items, *ll;
	char *keyring;
	gboolean locked;
	guint32 item_id;
	
	g_set_application_name("list-keyrings");
	loop = g_main_loop_new (NULL, FALSE);
	
	g_print ("Keyrings:\n");
	gnome_keyring_list_keyring_names (string_list_callback, &keyrings, NULL);
	g_main_loop_run (loop);
	for (l = keyrings; l != NULL; l = l->next) {
		keyring = l->data;
		g_print ("\nkeyring: %s\n", keyring);
		
		gnome_keyring_get_info (keyring, print_keyring_info, &locked, NULL);
		g_main_loop_run (loop);
		
		if (1 || !locked) {
			gnome_keyring_list_item_ids (keyring, get_items_callback, &items, NULL);
			g_main_loop_run (loop);
			
			if (items != NULL) {
				g_print ("Items: \n");
			}
			for (ll = items; ll != NULL; ll = ll->next) {
				item_id = GPOINTER_TO_UINT(ll->data);
				
				g_print ("\n");
				g_print (" id: %u\n", item_id);
				gnome_keyring_item_get_info (keyring,
							     item_id,
							     print_item_info, NULL, NULL);
				g_main_loop_run (loop);
				gnome_keyring_item_get_attributes (keyring,
								   item_id,
								   print_attributes, NULL, NULL);
				g_main_loop_run (loop);
			}
			g_list_free (items);
		}
		
		g_free (keyring);
	}
	g_list_free (keyrings);
	
	gnome_keyring_get_default_keyring (string_callback, &keyring, NULL);
	g_main_loop_run (loop);
	g_print ("\n");
	if (keyring != NULL) {
		g_print ("The default keyring for storage is '%s'\n", keyring);
	} else {
		g_print ("No default keyring defined\n");
	}

	return 0;
}
