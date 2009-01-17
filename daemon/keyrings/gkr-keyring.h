/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyring.h - represents a keyring in memory, and functionality save/load

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

#ifndef __GKR_KEYRING_H__
#define __GKR_KEYRING_H__

/* 
 * TODO: The internals of a GkrKeyring should probably be further 
 * abstracted away and accessed via accessor methods and properties.
 */

#include <glib-object.h>

#include "gkr-keyring-item.h"

#include "egg/egg-buffer.h"

#include "library/gnome-keyring.h"

#include "ui/gkr-ask-request.h"

G_BEGIN_DECLS

#define GKR_TYPE_KEYRING             (gkr_keyring_get_type())
#define GKR_KEYRING(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GKR_TYPE_KEYRING, GkrKeyring))
#define GKR_KEYRING_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GKR_TYPE_KEYRING, GObject))
#define GKR_IS_KEYRING(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GKR_TYPE_KEYRING))
#define GKR_IS_KEYRING_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GKR_TYPE_KEYRING))
#define GKR_KEYRING_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), GKR_TYPE_KEYRING, GkrKeyringClass))

typedef struct _GkrKeyringClass GkrKeyringClass;

struct _GkrKeyring {
	GObject parent;
	
	/* NULL if memory only */
	GQuark location;

	/* If known: */
	char *password;
	gboolean locked;
	gboolean asking_password;

	/* Whether the salt and hash_iterations members are populated */
	gboolean salt_valid; 

	/* On disk data: */
	guchar salt[8];
	guint32 hash_iterations;
	   
	char *keyring_name;
	GList *items;

	time_t ctime;
	time_t mtime;

	gboolean lock_on_idle;
	guint lock_timeout;
};

struct _GkrKeyringClass {
	GObjectClass parent_class;
	
	void (*item_added) (GkrKeyring* keyring, GkrKeyringItem* item);
	
	void (*item_removed) (GkrKeyring* keyring, GkrKeyringItem* item);
};

GType            gkr_keyring_get_type           (void) G_GNUC_CONST;

GkrKeyring*      gkr_keyring_new                (const gchar* name, GQuark location);

GkrKeyring*      gkr_keyring_create             (GQuark volume, const gchar* name, const gchar* password);

guint            gkr_keyring_get_new_id         (GkrKeyring *keyring);

GkrKeyringItem*  gkr_keyring_get_item           (GkrKeyring *keyring, guint id);

GkrKeyringItem*  gkr_keyring_find_item          (GkrKeyring *keyring, GnomeKeyringItemType type, 
                                                 GnomeKeyringAttributeList *attrs, gboolean match_all);

void             gkr_keyring_add_item           (GkrKeyring* keyring, GkrKeyringItem* item);

void             gkr_keyring_remove_item        (GkrKeyring* keyring, GkrKeyringItem* item);

gboolean         gkr_keyring_update_from_disk   (GkrKeyring *keyring);

gboolean         gkr_keyring_remove_from_disk   (GkrKeyring *keyring);

gboolean         gkr_keyring_save_to_disk       (GkrKeyring *keyring);

gboolean         gkr_keyring_lock               (GkrKeyring *keyring);

gboolean         gkr_keyring_unlock             (GkrKeyring *keyring, const gchar *password);

void             gkr_keyrings_set_item          (GkrKeyring *keyring, GnomeKeyringItemType type,
                                                 const gchar *display_name, const gchar *secret,
                                                 GnomeKeyringAttributeList *attrs);

gboolean         gkr_keyring_is_insecure        (GkrKeyring *keyring);

/* Used with the check-request signal on GkrAskRequest to unlock a keyring */
gboolean         gkr_keyring_ask_check_unlock   (GkrAskRequest* ask);

/* -----------------------------------------------------------------------------
 * FILE FORMATS
 * 
 * gint return value: 
 *   -1 : error
 *    0 : unrecognized
 *    1 : successful 
 */

gboolean         gkr_keyring_textual_generate (GkrKeyring *keyring, EggBuffer *buffer);

gboolean         gkr_keyring_binary_generate  (GkrKeyring *keyring, EggBuffer *buffer);

gint             gkr_keyring_textual_parse    (GkrKeyring *keyring, EggBuffer *buffer); 

gint             gkr_keyring_binary_parse     (GkrKeyring *keyring, EggBuffer *buffer); 

G_END_DECLS

#endif /* __GKR_KEYRING_H__ */

