/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyring-item.c - represents an item in a keyring

   Copyright (C) 2007 Stefan walter

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

#include <glib.h>

#include "gkr-keyring-item.h"
#include "gkr-keyring.h"

#include "library/gnome-keyring-memory.h"

G_DEFINE_TYPE (GkrKeyringItem, gkr_keyring_item, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static void
gkr_keyring_item_init (GkrKeyringItem *item)
{

}

static void 
gkr_keyring_item_dispose (GObject *obj)
{
	GkrKeyringItem *item = GKR_KEYRING_ITEM (obj);
	
	if (item->keyring) {
		gkr_keyring_remove_item (item->keyring, item);
		g_object_remove_weak_pointer (G_OBJECT (item->keyring), 
		                              (gpointer*)&(item->keyring));
		item->keyring = NULL;
	}
	
	G_OBJECT_CLASS (gkr_keyring_item_parent_class)->dispose (obj);
}

static void
gkr_keyring_item_finalize (GObject *obj)
{
	GkrKeyringItem *item = GKR_KEYRING_ITEM (obj);
	
	gnome_keyring_attribute_list_free (item->attributes);
	if (item->acl != NULL) 
		gnome_keyring_acl_free (item->acl);
	g_free (item->display_name);
	gnome_keyring_memory_free (item->secret);

	G_OBJECT_CLASS (gkr_keyring_item_parent_class)->finalize (obj);
}

static void
gkr_keyring_item_class_init (GkrKeyringItemClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gkr_keyring_item_parent_class = g_type_class_peek_parent (klass);

	gobject_class->dispose = gkr_keyring_item_dispose;
	gobject_class->finalize = gkr_keyring_item_finalize;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkrKeyringItem*
gkr_keyring_item_new (GkrKeyring* keyring, guint id, GnomeKeyringItemType type)
{
	GkrKeyringItem *item = g_object_new (GKR_TYPE_KEYRING_ITEM, NULL);
	
	/* TODO: These should move into properties */
	
	g_assert (GKR_IS_KEYRING (keyring));
	
	item->keyring = keyring;
	item->id = id;
	item->type = type;
	
	/* Make sure we get disconnected when keyring goes away */
	g_object_add_weak_pointer (G_OBJECT (item->keyring), (gpointer*)&(item->keyring));
	
	return item;
}

GkrKeyringItem* 
gkr_keyring_item_create (GkrKeyring* keyring, GnomeKeyringItemType type)
{
	GkrKeyringItem *item;
	guint id;
	
	g_assert (!keyring->locked);
	
	id = gkr_keyring_get_new_id (keyring);
	g_return_val_if_fail (id != 0, NULL);
	
	item = gkr_keyring_item_new (keyring, id, type);
	item->locked = keyring->locked;
	item->ctime = item->mtime = time (NULL);
	item->type = type;
	
	return item;
}
