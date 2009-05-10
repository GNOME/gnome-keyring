/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyring.c - represents a keyring in memory, and functionality save/load

   Copyright (C) 2003 Red Hat, Inc
   Copyright (C) 2007 Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Alexander Larsson <alexl@redhat.com>
   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-keyring.h"
#include "gkr-keyring-item.h"
#include "gkr-keyring-login.h"
#include "gkr-keyrings.h"

#include "egg/egg-buffer.h"
#include "egg/egg-secure-memory.h"

#include "library/gnome-keyring-private.h"
#include "library/gnome-keyring-proto.h"

#include "util/gkr-location.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <gcrypt.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* -----------------------------------------------------------------------------
 * DECLARATIONS
 */

enum {
    ITEM_ADDED,
    ITEM_REMOVED,
    LAST_SIGNAL
};

enum {
    PROP_0,
    PROP_NAME,
    PROP_LOCATION
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (GkrKeyring, gkr_keyring, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static int
write_all (int fd, const guchar *buf, size_t len)
{
	size_t bytes;
	int res;

	bytes = 0;
	while (bytes < len) {
		res = write (fd, buf + bytes, len - bytes);
		if (res < 0) {
			if (errno != EINTR && errno != EAGAIN) {
				perror ("write_all write failure:");
				return -1;
			}
		} else {
			bytes += res;
		}
	}
	return 0;
}

static GQuark
get_default_location_for_name (GQuark volume, const char *keyring_name)
{
	gchar *path = NULL;
	gchar *base, *filename;
	int version;
	GQuark loc;
	
	g_assert (volume);
	g_assert (keyring_name && keyring_name[0]);

	base = g_filename_from_utf8 (keyring_name, -1, NULL, NULL, NULL);
	if (base == NULL)
		base = g_strdup ("keyring");

	version = 0;
	do {
		g_free (path);
		
		if (version == 0) 
			filename = g_strdup_printf ("%s/keyrings/%s.keyring", 
			                            g_quark_to_string (volume), base);
		else
			filename = g_strdup_printf ("%s/keyrings/%s%d.keyring", 
			                            g_quark_to_string (volume), base, version);

		loc = gkr_location_from_string (filename);
		g_free (filename);
		
		path = gkr_location_to_path (loc);
		g_return_val_if_fail (path, 0);

		version++;
	} while (g_file_test (path, G_FILE_TEST_EXISTS));

	g_free (base);
	
	loc = gkr_location_from_path (path);
	g_free (path);
	return loc;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_keyring_init (GkrKeyring *keyring)
{
	keyring->ctime = keyring->mtime = time (NULL);

	/* Default values: */
	keyring->lock_on_idle = FALSE;
	keyring->lock_timeout = 0;
}

static void
gkr_keyring_get_property (GObject *obj, guint prop_id, GValue *value, 
                          GParamSpec *pspec)
{
	GkrKeyring *keyring = GKR_KEYRING (obj);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, keyring->keyring_name);
		break;
	case PROP_LOCATION:
		g_value_set_uint (value, keyring->location);
		break;
	}
}

static void 
gkr_keyring_dispose (GObject *obj)
{
	GkrKeyring *keyring = GKR_KEYRING (obj);
	GkrKeyringItem *item;
	GList *l;
	
	/* Remove all references to items */
	for (l = keyring->items; l; l = g_list_next (l)) {
		item = GKR_KEYRING_ITEM (l->data);
		g_object_unref (item);
	}
	
	g_list_free (keyring->items);
	keyring->items = NULL;
	
	egg_secure_strfree (keyring->password);
	keyring->password = NULL;

	G_OBJECT_CLASS (gkr_keyring_parent_class)->dispose (obj);
}

static void
gkr_keyring_finalize (GObject *obj)
{
	GkrKeyring *keyring = GKR_KEYRING (obj);

	g_free (keyring->keyring_name);
	g_assert (keyring->password == NULL);
	
	G_OBJECT_CLASS (gkr_keyring_parent_class)->finalize (obj);
}

static void
gkr_keyring_class_init (GkrKeyringClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gkr_keyring_parent_class  = g_type_class_peek_parent (klass);
	
	gobject_class->get_property = gkr_keyring_get_property;
	gobject_class->dispose = gkr_keyring_dispose;
	gobject_class->finalize = gkr_keyring_finalize;
	
	g_object_class_install_property (gobject_class, PROP_NAME,
		g_param_spec_string ("name", "Name", "Keyring Name",
		                     NULL, G_PARAM_READABLE));
		                     
	g_object_class_install_property (gobject_class, PROP_LOCATION,
		g_param_spec_uint ("location", "Location", "File Location",
		                   0, G_MAXUINT, 0, G_PARAM_READABLE));
	
	signals[ITEM_ADDED] = g_signal_new ("item-added", GKR_TYPE_KEYRING, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrKeyringClass, item_added),
			NULL, NULL, g_cclosure_marshal_VOID__OBJECT, 
			G_TYPE_NONE, 1, GKR_TYPE_KEYRING_ITEM);

	signals[ITEM_REMOVED] = g_signal_new ("item-removed", GKR_TYPE_KEYRING, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrKeyringClass, item_removed),
			NULL, NULL, g_cclosure_marshal_VOID__OBJECT, 
			G_TYPE_NONE, 1, GKR_TYPE_KEYRING_ITEM);
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkrKeyring*
gkr_keyring_new (const char *name, GQuark location)
{
	GkrKeyring *keyring;
	
	/* TODO: This should be done using properties */
	
	keyring = g_object_new (GKR_TYPE_KEYRING, NULL);
	
	keyring->keyring_name = g_strdup (name);
	keyring->location = location;

	return keyring;
}

GkrKeyring*
gkr_keyring_create (GQuark location, const gchar *keyring_name, const gchar *password)
{
	GkrKeyring *keyring;
	
	if (!location)
		location = GKR_LOCATION_VOLUME_LOCAL;
	if (gkr_location_is_volume (location))
		location = get_default_location_for_name (location, keyring_name);
	
	keyring = gkr_keyring_new (keyring_name, 0);
	if (keyring != NULL) {
		keyring->location = location;
		keyring->locked = FALSE;
		keyring->password = egg_secure_strdup (password);
		keyring->salt_valid = FALSE;
		gkr_keyring_save_to_disk (keyring);
	}
	return keyring;
}

guint
gkr_keyring_get_new_id (GkrKeyring *keyring)
{
	GkrKeyringItem *item;
	GList *l;
	guint max;

	g_assert (GKR_IS_KEYRING (keyring));

	max = 0;
	for (l = keyring->items; l ; l = g_list_next (l)) {
		item = l->data;
		if (item->id >= max)
			max = item->id;
	}
	/* Naive unique id lookup, but avoid rollaround at lest: */
	
	if (max == 0xffffffff)
		return 0;
	
	return max + 1;
}

GkrKeyringItem*
gkr_keyring_get_item (GkrKeyring *keyring, guint id)
{
	GkrKeyringItem *item;
	GList *l;
	
	for (l = keyring->items; l; l = g_list_next (l)) {
		item = GKR_KEYRING_ITEM (l->data);
		if (item->id == id)
			return item;
	}
	
	return NULL;
}

GkrKeyringItem*  
gkr_keyring_find_item (GkrKeyring *keyring, GnomeKeyringItemType type, 
                       GnomeKeyringAttributeList *attrs, gboolean match_all)
{    
	GkrKeyringItem *item;
	GList *l;
	
	for (l = keyring->items; l; l = g_list_next (l)) {
		item = GKR_KEYRING_ITEM (l->data);
		if (gkr_keyring_item_match (item, type, attrs, match_all))
			return item;
	}
	
	return NULL;
}

void
gkr_keyring_add_item (GkrKeyring* keyring, GkrKeyringItem* item)
{
	g_assert (GKR_IS_KEYRING (keyring));
	g_assert (GKR_IS_KEYRING_ITEM (item));
	
	/* Must not be added twice */
	g_assert (g_list_find (keyring->items, item) == NULL);
	
	keyring->items = g_list_append (keyring->items, item);
	g_object_ref (item);
	
	g_signal_emit (keyring, signals[ITEM_ADDED], 0, item);

}

void
gkr_keyring_remove_item (GkrKeyring* keyring, GkrKeyringItem* item)
{
	g_assert (GKR_IS_KEYRING (keyring));
	g_assert (GKR_IS_KEYRING_ITEM (item));
	
	if (g_list_find (keyring->items, item)) {
		keyring->items = g_list_remove (keyring->items, item);

		/* Must not be added twice */
		g_assert (g_list_find (keyring->items, item) == NULL);
		
		/* Keep the reference until after the signal */
		g_signal_emit (keyring, signals[ITEM_REMOVED], 0, item);
		
		g_object_unref (item);
	}
}

gboolean
gkr_keyring_update_from_disk (GkrKeyring *keyring)
{
	EggBuffer buffer;
	GError *err = NULL;
	guchar *contents = NULL;
	gsize len;
	gint result; 

	if (!keyring->location)
		return TRUE;
	
	if (!gkr_location_read_file (keyring->location, &contents, &len, &err)) {
		g_warning ("couldn't read keyring: %s", err && err->message ? err->message : "");
		g_clear_error (&err);
		return FALSE;
	}
	
	egg_buffer_init_static (&buffer, contents, len);
	
	result = gkr_keyring_binary_parse (keyring, &buffer);
	if (result == 0)
		result = gkr_keyring_textual_parse (keyring, &buffer);
		
	egg_buffer_uninit (&buffer);
	g_free (contents);
		
	if (result > 0)
		return TRUE;
		
	if (result == 0)
		g_warning ("keyring has unknown format");
	else if (result < 0)
		g_warning ("error parsing keyring");
	
	return FALSE;
}

gboolean 
gkr_keyring_remove_from_disk (GkrKeyring *keyring)
{
	gchar *file;
	int res;

	/* Cannot remove session or memory based keyring */
	if (!keyring->location)
		return FALSE;
		
	file = gkr_location_to_path (keyring->location);
	if (!file)
		return FALSE;
		
	res = unlink (file);
	g_free (file);
	
	return (res == 0);
}

gboolean
gkr_keyring_save_to_disk (GkrKeyring *keyring)
{
	struct stat statbuf;
	EggBuffer out;
	int fd;
	char *dirname;
	char *template;
	gboolean result;
	gboolean ret = TRUE;
	gchar *file = NULL;
	
	/* Can't save locked keyrings */
	if (keyring->locked)
		return FALSE;

	/* Not file backed */
	if (!keyring->location)
		return TRUE;
		
	file = gkr_location_to_path (keyring->location);
	if (!file)
		return FALSE;
	
	egg_buffer_init_full (&out, 4096, g_realloc);

	/* Generate it */	
	if (!keyring->password || !keyring->password[0])
		result = gkr_keyring_textual_generate (keyring, &out);
	else
		result = gkr_keyring_binary_generate (keyring, &out);
		
	/* And write it to disk */
	if (result) {
		dirname = g_path_get_dirname (file);
		if (g_mkdir_with_parents (dirname, S_IRWXU) < 0)
			g_warning ("unable to create keyring dir");
		template = g_build_filename (dirname, ".keyringXXXXXX", NULL);
		
		fd = g_mkstemp (template);
		if (fd != -1) {
			fchmod (fd, S_IRUSR | S_IWUSR);
			if (write_all (fd, out.buf, out.len) == 0) {
#ifdef HAVE_FSYNC
			fsync (fd);
#endif
				close (fd);
				if (rename (template, file) == 0) {
					if (stat (file, &statbuf) == 0)
						gkr_location_manager_note_mtime (NULL, 
						              keyring->location, statbuf.st_mtime);
				} else {
					unlink (template);
				}
			} else {
				close (fd);
			}
		} else {
			g_warning ("Can't open keyring save file %s", template);
			perror ("mkstemp error: ");
			ret = FALSE;
		}
		g_free (template);
		g_free (dirname);
	} else {
		g_warning ("Internal error: Unable to generate data for keyring %s\n", keyring->keyring_name);
		ret = FALSE;
	}
	
	egg_buffer_uninit (&out);
	g_free (file);
	return ret;
}

gboolean
gkr_keyring_lock (GkrKeyring *keyring)
{
	if (keyring->locked)
		return TRUE;

	/* Never lock the session keyring */
	if (!keyring->location)
		return TRUE;

	/* Password will be null for textual keyrings */
	if (keyring->password != NULL) {
		egg_secure_strfree (keyring->password);
		keyring->password = NULL;
	}
	
	if (!gkr_keyring_update_from_disk (keyring)) {
		/* Failed to re-read, remove the keyring */
		g_warning ("Couldn't re-read keyring %s\n", keyring->keyring_name);
		gkr_keyrings_remove (keyring);
	}
	
	return TRUE;
}

gboolean
gkr_keyring_unlock (GkrKeyring *keyring, const gchar *password)
{
	if (!keyring->locked)
		return TRUE;
		
	g_return_val_if_fail (keyring->password == NULL, FALSE);
		
	keyring->password = egg_secure_strdup (password);
	if (!gkr_keyring_update_from_disk (keyring)) {
		egg_secure_strfree (keyring->password);
		keyring->password = NULL;
	}
	if (keyring->locked) {
		g_assert (keyring->password == NULL);
		return FALSE;
	} else {
		g_assert (keyring->password != NULL);
		return TRUE;
	}
}

gboolean
gkr_keyring_is_insecure (GkrKeyring *keyring)
{
	/* It's locked, must have encryption */
	if (keyring->locked)
		return FALSE;
		
	/* Only in memory == secure */
	if (!keyring->location)
		return FALSE;
		
	/* No or empty password == insecure */
	if (!keyring->password || !keyring->password[0])
		return TRUE;
		
	return FALSE;
}

gboolean 
gkr_keyring_ask_check_unlock (GkrAskRequest* ask)
{
	GkrKeyring *keyring;
	const gchar *password;
	gchar *display;
	
	keyring = GKR_KEYRING (gkr_ask_request_get_object (ask));
	g_assert (GKR_IS_KEYRING (keyring));

	if (!keyring->locked) {
		ask->response = GKR_ASK_RESPONSE_ALLOW;
		return GKR_ASK_STOP_REQUEST;
	}
	
	/* If they typed a password, try it out */
	if (ask->response >= GKR_ASK_RESPONSE_ALLOW) {
		
		g_assert (ask->typed_password);
		if (!gkr_keyring_unlock (keyring, ask->typed_password)) {
			/* Bad password, try again */
			ask->response = GKR_ASK_RESPONSE_NONE;
			return GKR_ASK_CONTINUE_REQUEST;
		}
		
		/* Did they ask us to remember the password? */
		if (ask->checked) {
			display = g_strdup_printf (_("Unlock password for %s keyring"), 
			                           keyring->keyring_name);
			gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD,
			                                 display, ask->typed_password, 
			                                 "keyring", gkr_location_to_string (keyring->location), NULL);
			g_free (display);
		}
	}
	
	/* 
	 * We can automatically unlock keyrings that have their password
	 * stored in the 'login' keyring.
	 */
	password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD,
	                                            "keyring", gkr_location_to_string (keyring->location), NULL);
	if (password) {
		if (gkr_keyring_unlock (keyring, password)) {
			
			/* A good password, unlocked, all done */
			ask->response = GKR_ASK_RESPONSE_ALLOW;
			return GKR_ASK_STOP_REQUEST;
			
		} else {
			
			/* A bad internal password */
			gkr_keyring_login_remove_secret (GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD,
			                                 "keyring", gkr_location_to_string (keyring->location), NULL);
		}
	}	

	/* If the keyring is unlocked then no need to continue */
	if (!keyring->locked) {
		ask->response = GKR_ASK_RESPONSE_ALLOW;
		return GKR_ASK_STOP_REQUEST;
	}
	
	return GKR_ASK_DONT_CARE;
}
