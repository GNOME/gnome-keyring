/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyrings-auto-unlock.c - get secrets to automatically unlock keyrings or keys

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

#include "gkr-keyrings-auto-unlock.h"

#include "gkr-keyring.h"
#include "gkr-keyring-item.h"
#include "gkr-keyrings.h"

#include "common/gkr-secure-memory.h"

#include "library/gnome-keyring.h"

#include <glib.h>

#include <stdarg.h>
#include <unistd.h>

gboolean
gkr_keyrings_auto_unlock_check (void)
{
	return gkr_keyrings_get_login () != NULL;
}

static GnomeKeyringAttributeList*
string_attribute_list_va (va_list args)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;
	
	attributes = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));
	
	while ((attribute.name = va_arg (args, char *)) != NULL) {
		attribute.name = g_strdup (attribute.name);
		attribute.value.string = g_strdup (va_arg (args, char *));
		attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
		g_array_append_val (attributes, attribute);
	}
	
	return attributes;
}

void
gkr_keyrings_auto_unlock_save (GnomeKeyringItemType type, const gchar *display_name, 
                               const gchar *secret, ...)
{
	GkrKeyring *login;
	GnomeKeyringAttributeList *attrs;
	GkrKeyringItem *item;
	va_list args;
	
	login = gkr_keyrings_get_login ();
	if (!login || login->locked)
		return;
		
	va_start (args, secret);
	attrs = string_attribute_list_va (args);
	va_end (args);
	
	item = gkr_keyring_find_item (login, type, attrs);
	
	if (!item) {
		item = gkr_keyring_item_create (login, type);
		gkr_keyring_add_item (login, item);
	}
	
	g_free (item->display_name);
	item->display_name = g_strdup (display_name); 
	
	gkr_secure_strfree (item->secret);
	item->secret = gkr_secure_strdup (secret);
	
	gnome_keyring_attribute_list_free (item->attributes);
	item->attributes = attrs;
	
	gkr_keyring_save_to_disk (login);
}

const gchar*
gkr_keyrings_auto_unlock_lookup (GnomeKeyringItemType type, ...)
{
	GkrKeyring *login;
	GkrKeyringItem *item;
	GnomeKeyringAttributeList *attrs;
	va_list args;
	
	login = gkr_keyrings_get_login ();
	if (!login || login->locked)
		return NULL;

	if (!login->location)
		return NULL;

	va_start (args, type);
	attrs = string_attribute_list_va (args);
	va_end (args);
				
	item = gkr_keyring_find_item (login, type, attrs);
	gnome_keyring_attribute_list_free (attrs);
	
	if (item)
		return item->secret;
		
	return NULL;
}
                                                 
void
gkr_keyrings_auto_unlock_remove (GnomeKeyringItemType type, ...)
{
	GkrKeyring *login;
	GkrKeyringItem *item;
	GnomeKeyringAttributeList *attrs;
	va_list args;
	
	login = gkr_keyrings_get_login ();
	if (!login || login->locked)
		return;
		
	if (!login->location)
		return;

	va_start (args, type);
	attrs = string_attribute_list_va (args);
	va_end (args);
		
	item = gkr_keyring_find_item (login, type, attrs);
	gnome_keyring_attribute_list_free (attrs);
	
	if (item) {
		gkr_keyring_remove_item (login, item);
		gkr_keyring_save_to_disk (login);
	}
}
