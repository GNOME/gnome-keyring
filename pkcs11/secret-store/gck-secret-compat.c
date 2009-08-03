/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *  
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "gck-secret-compat.h"

#include <string.h>

void
gck_secret_compat_access_free (gpointer data)
{
	GckSecretAccess *ac = data;
	if (ac) {
		g_free (ac->display_name);
		g_free (ac->pathname);
		g_free (ac);
	}
}

void
gck_secret_compat_acl_free (gpointer acl)
{
	GList *l;
	for (l = acl; l; l = g_list_next (l)) 
		gck_secret_compat_access_free (l->data);
	g_list_free (acl);
}

guint
gck_secret_compat_parse_item_type (const gchar *value)
{
	if (value == NULL)
		return 0; /* The default */
	if (strcmp (value, "generic-secret") == 0)
		return 0; /* GNOME_KEYRING_ITEM_GENERIC_SECRET */
	if (strcmp (value, "network-password") == 0)
		return 1; /* GNOME_KEYRING_ITEM_NETWORK_PASSWORD */
	if (strcmp (value, "note") == 0)
		return 2; /* GNOME_KEYRING_ITEM_NOTE */
	if (strcmp (value, "chained-keyring-password") == 0)
		return 3; /* GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD */
	if (strcmp (value, "encryption-key-password") == 0)
		return 4; /* GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD */
	if (strcmp (value, "pk-storage") == 0)
		return 0x100; /* GNOME_KEYRING_ITEM_PK_STORAGE */

	/* The default: GNOME_KEYRING_ITEM_GENERIC_SECRET */
	return 0;
}

const gchar*
gck_secret_compat_format_item_type (guint value)
{
	/* Only GNOME_KEYRING_ITEM_TYPE_MASK */
	switch (value & 0x0000ffff)
	{
	case 0: /* GNOME_KEYRING_ITEM_GENERIC_SECRET */
		return "generic-secret";
	case 1: /* GNOME_KEYRING_ITEM_NETWORK_PASSWORD */
		return "network-password";
	case 2: /* GNOME_KEYRING_ITEM_NOTE */
		return "note";
	case 3: /* GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD */
		return "chained-keyring-password";
	case 4: /* GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD */
		return "encryption-key-password";
	case 0x100: /* GNOME_KEYRING_ITEM_PK_STORAGE */
		return "pk-storage";
	default:
		return NULL;
	};
}
