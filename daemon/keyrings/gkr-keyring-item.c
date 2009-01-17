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

#include "gkr-keyring-item.h"
#include "gkr-keyring.h"

#include "egg/egg-secure-memory.h"

#include <gcrypt.h>

#include <glib.h>

#include <string.h>

enum {
    PROP_0,
    PROP_NAME
};

G_DEFINE_TYPE (GkrKeyringItem, gkr_keyring_item, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * HELPERS
 */
 
static guint32
hash_int (guint32 x)
{
	/* Just random 32bit hash. Security here is not very important */
	return 0x18273645 ^ x ^ (x << 16 | x >> 16);
}

static char*
md5_digest_to_ascii (unsigned char digest[16])
{
	static char hex_digits[] = "0123456789abcdef";
	char *res;
	int i;
  
	res = g_malloc (33);
  
	for (i = 0; i < 16; i++) {
		res[2*i] = hex_digits[digest[i] >> 4];
		res[2*i+1] = hex_digits[digest[i] & 0xf];
	}
  
	res[32] = 0;
	return res;
}

static char *
hash_string (const char *str)
{
	guchar digest[16];

	if (str == NULL)
		return NULL;

	/* In case the world changes on us... */
	g_return_val_if_fail (gcry_md_get_algo_dlen (GCRY_MD_MD5) == sizeof (digest), NULL);
	
	gcry_md_hash_buffer (GCRY_MD_MD5, (void*)digest, str, strlen (str));
	return md5_digest_to_ascii (digest);
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static void
gkr_keyring_item_init (GkrKeyringItem *item)
{

}

static void
gkr_keyring_item_get_property (GObject *obj, guint prop_id, GValue *value, 
                               GParamSpec *pspec)
{
	GkrKeyringItem *item = GKR_KEYRING_ITEM (obj);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, item->display_name ? item->display_name : "");
		break;
	}
}

static void 
gkr_keyring_item_dispose (GObject *obj)
{
	GkrKeyringItem *item = GKR_KEYRING_ITEM (obj);
	
	if (item->keyring) {
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
	egg_secure_strfree (item->secret);

	G_OBJECT_CLASS (gkr_keyring_item_parent_class)->finalize (obj);
}

static void
gkr_keyring_item_class_init (GkrKeyringItemClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gkr_keyring_item_parent_class = g_type_class_peek_parent (klass);

	gobject_class->get_property = gkr_keyring_item_get_property;
	gobject_class->dispose = gkr_keyring_item_dispose;
	gobject_class->finalize = gkr_keyring_item_finalize;
	
	g_object_class_install_property (gobject_class, PROP_NAME,
		g_param_spec_string ("name", "Name", "Item Name",
		                     NULL, G_PARAM_READABLE));
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
	item->attributes = gnome_keyring_attribute_list_new ();
	
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

GkrKeyringItem*
gkr_keyring_item_clone (GkrKeyring* new_keyring, GkrKeyringItem *item)
{
	GkrKeyringItem *nitem = g_object_new (GKR_TYPE_KEYRING_ITEM, NULL);

	g_return_val_if_fail (GKR_IS_KEYRING (new_keyring), NULL);
	g_return_val_if_fail (GKR_IS_KEYRING_ITEM (item), NULL);
		
	nitem->keyring = new_keyring;
	nitem->id = gkr_keyring_get_new_id (new_keyring);
	nitem->locked = item->locked;

	nitem->type = item->type;
	nitem->secret = egg_secure_strdup (item->secret);
	nitem->display_name = g_strdup (item->display_name);

	nitem->attributes = gnome_keyring_attribute_list_copy (item->attributes);
	nitem->acl = gnome_keyring_acl_copy (item->acl);
	
	nitem->ctime = item->ctime;
	nitem->mtime = item->mtime;
	
	/* Make sure we get disconnected when keyring goes away */
	g_object_add_weak_pointer (G_OBJECT (item->keyring), (gpointer*)&(item->keyring));
		
	return nitem;
}

void
gkr_keyring_item_merge (GkrKeyringItem* merged, GkrKeyringItem* item)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute *attribute;
	gint i;
	
	attributes = item->attributes;
	for (i = 0; i < attributes->len; i++) {
		attribute = &gnome_keyring_attribute_list_index (attributes, i);
		gkr_attribute_list_set (merged->attributes, attribute);
	}
}

gboolean
gkr_keyring_item_match (GkrKeyringItem *item, GnomeKeyringItemType type, 
                        GnomeKeyringAttributeList *attributes, gboolean match_all)
{
	int i, j;
	GnomeKeyringAttribute *item_attribute;
	GnomeKeyringAttribute *attribute;
	gboolean found;
	int attributes_matching;

	if ((item->type & GNOME_KEYRING_ITEM_TYPE_MASK) != (type & GNOME_KEYRING_ITEM_TYPE_MASK))
		return FALSE;

	attributes_matching = 0;
	for (i = 0; i < attributes->len; i++) {
		found = FALSE;
		attribute = &g_array_index (attributes,
					    GnomeKeyringAttribute,
					    i);
		for (j = 0; j < item->attributes->len; j++) {
			item_attribute = &g_array_index (item->attributes,
							 GnomeKeyringAttribute,
							 j);
			if (strcmp (attribute->name, item_attribute->name) == 0) {
				found = TRUE;
				attributes_matching++;
				if (attribute->type != item_attribute->type) {
					return FALSE;
				}
				switch (attribute->type) {
				case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
					if (attribute->value.string != item_attribute->value.string) {
						if (attribute->value.string == NULL || item_attribute->value.string == NULL)
							return FALSE;
						if (strcmp (attribute->value.string, item_attribute->value.string) != 0)
							return FALSE;
					}
					break;
				case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
					if (attribute->value.integer != item_attribute->value.integer) {
						return FALSE;
					}
					break;
				default:
					g_assert_not_reached ();
				}
			}
		}
		if (!found) {
			return FALSE;
		}
	}
	if (match_all) {
		return attributes_matching == attributes->len;
	}
	
	return TRUE;
}

/* -----------------------------------------------------------------------------
 * ATTRIBUTE LIST FUNCTIONS
 */

void
gkr_attribute_list_set (GnomeKeyringAttributeList *attrs, GnomeKeyringAttribute *attr)
{
	GnomeKeyringAttribute *set;
	GnomeKeyringAttribute last;
	gchar *tofree = NULL;
	
	g_return_if_fail (attrs);
	g_return_if_fail (attr);
	g_return_if_fail (attr->name);
	
	set = gkr_attribute_list_find (attrs, attr->name);
	
	/* Found, appropriate for our own uses */
	if (set) {
		if (set->type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
			tofree = set->value.string;
			set->value.string = NULL;
		}
		
	/* Not found, add a new one to the end */
	} else {
		memset (&last, 0, sizeof (last));
		g_array_append_val (attrs, last);
		set = &g_array_index (attrs, GnomeKeyringAttribute, attrs->len - 1);
		set->name = g_strdup (attr->name);
	}
	
	/* Set the actual value */
	set->type = attr->type;
	switch (attr->type) {
	case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
		set->value.string = g_strdup (attr->value.string);
		break;
	case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
		set->value.integer = attr->value.integer;
		break;
	default:
		g_assert_not_reached ();
	}
	
	g_free (tofree);
}

GnomeKeyringAttribute*
gkr_attribute_list_find (GnomeKeyringAttributeList *attrs, const gchar *name)
{
	GnomeKeyringAttribute *attr;
	int i;
	
	g_return_val_if_fail (attrs, NULL);
	g_return_val_if_fail (name, NULL);
	
	for (i = 0; i < attrs->len; i++) {
		attr = &gnome_keyring_attribute_list_index (attrs, i);
		g_return_val_if_fail (attr->name, NULL);
		if (strcmp (attr->name, name) == 0)
			return attr;
	}

	return NULL;
}

void
gkr_attribute_list_delete (GnomeKeyringAttributeList *attrs, const gchar *name)
{
	GnomeKeyringAttribute *attr;
	int i;
	
	g_return_if_fail (attrs);
	g_return_if_fail (name);
	
	for (i = 0; i < attrs->len; i++) {
		attr = &gnome_keyring_attribute_list_index (attrs, i);
		g_return_if_fail (attr->name);
		if (strcmp (attr->name, name) == 0) {
			g_array_remove_index_fast (attrs, i);
			return;
		}
	}
}

GnomeKeyringAttributeList *
gkr_attribute_list_hash (GnomeKeyringAttributeList *attributes)
{
	GnomeKeyringAttributeList *hashed;
	GnomeKeyringAttribute *orig_attribute;
	GnomeKeyringAttribute attribute;
	int i;

	hashed = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));
	for (i = 0; i < attributes->len; i++) {
		orig_attribute = &gnome_keyring_attribute_list_index (attributes, i);
		attribute.name = g_strdup (orig_attribute->name);
		attribute.type = orig_attribute->type;
		switch (attribute.type) {
		case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
			attribute.value.string = hash_string (orig_attribute->value.string);
			break;
		case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
			attribute.value.integer = hash_int (orig_attribute->value.integer);
			break;
		default:
			g_assert_not_reached ();
		}
		g_array_append_val (hashed, attribute);
	}

	return hashed;
}
