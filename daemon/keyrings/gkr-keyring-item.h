/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyring-item.h - represents an item in a keyring

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

#ifndef __GKR_KEYRING_ITEM_H__
#define __GKR_KEYRING_ITEM_H__

/* 
 * TODO: The internals of a GkrKeyringItem should probably be further 
 * abstracted away and accessed via accessor methods and properties.
 */

#include <glib-object.h>
#include "library/gnome-keyring.h"

G_BEGIN_DECLS

#define GKR_TYPE_KEYRING_ITEM             (gkr_keyring_item_get_type())
#define GKR_KEYRING_ITEM(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GKR_TYPE_KEYRING_ITEM, GkrKeyringItem))
#define GKR_KEYRING_ITEM_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GKR_TYPE_KEYRING_ITEM, GObject))
#define GKR_IS_KEYRING_ITEM(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GKR_TYPE_KEYRING_ITEM))
#define GKR_IS_KEYRING_ITEM_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GKR_TYPE_KEYRING_ITEM))
#define GKR_KEYRING_ITEM_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), GKR_TYPE_KEYRING_ITEM, GkrKeyringItemClass))

struct _GkrKeyring;
typedef struct _GkrKeyring          GkrKeyring;
typedef struct _GkrKeyringItem      GkrKeyringItem;
typedef struct _GkrKeyringItemClass GkrKeyringItemClass;

struct _GkrKeyringItem {
	 GObject parent;

	/* 
	 * Can be null if the keyring goes away, and this object 
	 * was referenced 
	 */
	GkrKeyring *keyring;

	guint32 id;
	GnomeKeyringItemType type;

	gboolean locked;

	/* These are hashed if locked, normal if unlocked, encrypted on file: */
	GArray *attributes;

	/* Below is encrypted in file, invalid in memory if locked: */
	char *display_name;
	char *secret;
	GList *acl;
	time_t ctime;
	time_t mtime;
};

struct _GkrKeyringItemClass {
	GObjectClass parent_class;
};

GType              gkr_keyring_item_get_type    (void) G_GNUC_CONST;

GkrKeyringItem*    gkr_keyring_item_new         (GkrKeyring* keyring, guint id, 
                                                 GnomeKeyringItemType type);

GkrKeyringItem*    gkr_keyring_item_create      (GkrKeyring* keyring, 
                                                 GnomeKeyringItemType type);

GkrKeyringItem*    gkr_keyring_item_clone       (GkrKeyring* new_keyring, 
                                                 GkrKeyringItem *item);

void               gkr_keyring_item_merge       (GkrKeyringItem* merged,
                                                 GkrKeyringItem* item);

gboolean           gkr_keyring_item_match       (GkrKeyringItem *item, 
                                                 GnomeKeyringItemType type, 
                                                 GnomeKeyringAttributeList *attributes, 
                                                 gboolean match_all);

void                        gkr_attribute_list_set     (GnomeKeyringAttributeList *attrs, 
                                                        GnomeKeyringAttribute *attr);

GnomeKeyringAttribute*      gkr_attribute_list_find    (GnomeKeyringAttributeList *attrs,
                                                        const gchar *name);

void                        gkr_attribute_list_delete  (GnomeKeyringAttributeList *attrs,
                                                        const gchar *name);

GnomeKeyringAttributeList*  gkr_attribute_list_hash    (GnomeKeyringAttributeList *attrs);
                                                 
G_END_DECLS

#endif /* __GKR_KEYRING_ITEM_H__ */

