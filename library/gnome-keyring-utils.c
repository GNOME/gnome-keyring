/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-proto.c - shared utility functions

   Copyright (C) 2003 Red Hat, Inc

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

   Author: Alexander Larsson <alexl@redhat.com>
*/
#include "config.h"

#include <string.h>
#include <glib.h>

#include "gnome-keyring-private.h"
#include "gnome-keyring-memory.h"

/* Functions used by both the library and the daemon */

/**
 * gnome_keyring_free_password:
 * @str: the password to be freed
 *
 * Clears the memory used by password by filling with '\0' and frees the memory
 * after doing this. You should use this function instead of g_free() for
 * secret information.
 */
void
gnome_keyring_free_password (gchar *str)
{
	volatile char *vp;
	size_t len;
	
	if (!str)
		return;
		
	/*
	 * If we're using unpageable 'secure' memory, then the free call
	 * should zero out the memory, but because on certain platforms 
	 * we may be using normal memory, zero it out here just in case.
	 */
		
        vp = (volatile char*)str;
       	len = strlen (str);
        while (len) { 
        	*vp = 0xAA;
        	vp++;
        	len--; 
        } 
	
	gnome_keyring_memory_free (str);
}

/**
 * gnome_keyring_found_free():
 * @found: a #GnomeKeyringFound
 * 
 * Free the memory used by a #GnomeKeyringFound item.
 *
 * You usually want to use gnome_keyring_found_list_free() on the list of
 * results.
 */
void
gnome_keyring_found_free (GnomeKeyringFound *found)
{
	g_free (found->keyring);
	gnome_keyring_free_password (found->secret);
	gnome_keyring_attribute_list_free (found->attributes);
	g_free (found);
}

/**
 * gnome_keyring_found_list_free():
 * @found_list: a #GList of #GnomeKeyringFound
 *
 * Free the memory used by the #GnomeKeyringFound items in @found_list.
 */
void
gnome_keyring_found_list_free (GList *found_list)
{
	g_list_foreach (found_list, (GFunc) gnome_keyring_found_free, NULL);
	g_list_free (found_list);
}

/**
 * gnome_keyring_attribute_list_free():
 * @attributes: a #GnomeKeyringAttributeList
 *
 * Free the memory used by @attributes.
 */
void
gnome_keyring_attribute_list_free (GnomeKeyringAttributeList *attributes)
{
	GnomeKeyringAttribute *array;
	int i;

	if (attributes == NULL) {
		return;
	}

	array = (GnomeKeyringAttribute *)attributes->data;
	for (i = 0; i < attributes->len; i++) {
		g_free (array[i].name);
		if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
			g_free (array[i].value.string);
		}
	}
	
	g_array_free (attributes, TRUE);
}

GnomeKeyringAttributeList *
gnome_keyring_attribute_list_copy (GnomeKeyringAttributeList *attributes)
{
	GnomeKeyringAttribute *array;
	GnomeKeyringAttributeList *copy;
	int i;

	if (attributes == NULL) {
		return NULL;
	}

	copy = g_array_sized_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute), attributes->len);
	
	copy->len = attributes->len;
	memcpy (copy->data, attributes->data, sizeof (GnomeKeyringAttribute) * attributes->len);
	
	array = (GnomeKeyringAttribute *)copy->data;
	for (i = 0; i < copy->len; i++) {
		array[i].name = g_strdup (array[i].name);
		if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
			array[i].value.string = g_strdup (array[i].value.string);
		}
	}
	return copy;
}

void
gnome_keyring_info_free (GnomeKeyringInfo *keyring_info)
{
	g_free (keyring_info);
}

GnomeKeyringInfo *
gnome_keyring_info_copy (GnomeKeyringInfo *keyring_info)
{
	GnomeKeyringInfo *copy;

	copy = g_new (GnomeKeyringInfo, 1);
	memcpy (copy, keyring_info, sizeof (GnomeKeyringInfo));
	
	return copy;
}


void
gnome_keyring_item_info_free (GnomeKeyringItemInfo *item_info)
{
	if (item_info != NULL) {
		g_free (item_info->display_name);
		gnome_keyring_free_password (item_info->secret);
		g_free (item_info);
	}
}

GnomeKeyringItemInfo *
gnome_keyring_item_info_new (void)
{
	GnomeKeyringItemInfo *info;

	info = g_new0 (GnomeKeyringItemInfo, 1);

	info->type = GNOME_KEYRING_ITEM_NO_TYPE;
	
	return info;
}

GnomeKeyringItemInfo *
gnome_keyring_item_info_copy (GnomeKeyringItemInfo *item_info)
{
	GnomeKeyringItemInfo *copy;

	copy = g_new (GnomeKeyringItemInfo, 1);
	memcpy (copy, item_info, sizeof (GnomeKeyringItemInfo));

	copy->display_name = g_strdup (copy->display_name);
	copy->secret = gnome_keyring_memory_strdup (copy->secret);
	
	return copy;
}

GnomeKeyringApplicationRef *
gnome_keyring_application_ref_new (void)
{
	GnomeKeyringApplicationRef *app_ref;

	app_ref = g_new0 (GnomeKeyringApplicationRef, 1);

	return app_ref;
}

void
gnome_keyring_application_ref_free (GnomeKeyringApplicationRef *app_ref)
{
	g_free (app_ref->display_name);
	g_free (app_ref->pathname);
	g_free (app_ref);
}

GnomeKeyringApplicationRef *
gnome_keyring_application_ref_copy (const GnomeKeyringApplicationRef *app)
{
	GnomeKeyringApplicationRef *copy;

	copy = g_new (GnomeKeyringApplicationRef, 1);
	copy->display_name = g_strdup (app->display_name);
	copy->pathname = g_strdup (app->pathname);

	return copy;
}

GnomeKeyringAccessControl *
gnome_keyring_access_control_new (const GnomeKeyringApplicationRef *application,
                                  GnomeKeyringAccessType types_allowed)
{
	GnomeKeyringAccessControl *ac;
	ac = g_new (GnomeKeyringAccessControl, 1);

	ac->application = gnome_keyring_application_ref_copy (application);
	ac->types_allowed = types_allowed;

	return ac;
}

void
gnome_keyring_access_control_free (GnomeKeyringAccessControl *ac)
{
	gnome_keyring_application_ref_free (ac->application);
	g_free (ac);
}

GnomeKeyringAccessControl *
gnome_keyring_access_control_copy (GnomeKeyringAccessControl *ac)
{
	GnomeKeyringAccessControl *ret;

	ret = gnome_keyring_access_control_new (gnome_keyring_application_ref_copy (ac->application), ac->types_allowed);

	return ret;
}

GList *
gnome_keyring_acl_copy (GList *list)
{
	GList *ret, *l;

	ret = g_list_copy (list);
	for (l = ret; l != NULL; l = l->next) {
		l->data = gnome_keyring_access_control_copy (l->data);
	}

	return ret;
}

void
gnome_keyring_acl_free (GList *acl)
{
	g_list_foreach (acl, (GFunc)gnome_keyring_access_control_free, NULL);
	g_list_free (acl);
}

