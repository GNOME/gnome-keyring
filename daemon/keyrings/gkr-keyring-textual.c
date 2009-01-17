/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyring-textual.c - Textual non-encrypted format for the keyring

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

#include "gkr-keyring.h"
#include "gkr-keyring-item.h"

#include "egg/egg-secure-memory.h"

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-private.h"

#include <glib.h>

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

static void
key_file_set_uint64 (GKeyFile *file, const gchar *group, 
                     const gchar *key, guint64 value)
{
	gchar buffer[64];
	g_snprintf (buffer, sizeof (buffer), "%llu", 
	            (long long unsigned int)value);
	g_key_file_set_value (file, group, key, buffer);
}

static gboolean
key_file_get_uint64 (GKeyFile *file, const gchar *group,
                     const gchar *key, guint64 *value)
{
	gchar *str, *end;
	
	str = g_key_file_get_value (file, group, key, NULL);
	if (!str)
		return FALSE;
		
	*value = g_ascii_strtoull (str, &end, 10);
	if (end[0]) {
		g_free (str);
		return FALSE;
	}
	
	g_free (str);
	return TRUE;
}

static void
generate_attributes (GKeyFile *file, GkrKeyringItem *item)
{
	GnomeKeyringAttribute *attr;
	gchar *groupname;
	gint i;
	
	g_return_if_fail (item->attributes);
	
	for (i = 0; i < item->attributes->len; ++i) {
		
		/* Build a group name */
		groupname = g_strdup_printf ("%d:attribute%d", item->id, i);

		attr = &gnome_keyring_attribute_list_index (item->attributes, i);
		
		g_key_file_set_string (file, groupname, "name", attr->name);
		
		switch (attr->type) {
		case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
			g_key_file_set_string (file, groupname, "type", "string");
			if (attr->value.string)
				g_key_file_set_string (file, groupname, "value", attr->value.string);
			break;
		case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
			g_key_file_set_string (file, groupname, "type", "uint32");
			key_file_set_uint64 (file, groupname, "value", attr->value.integer);
			break;
		default:
			g_return_if_reached ();
			break;
		};
		
		g_free (groupname);
	}
}

static void
parse_attributes (GKeyFile *file, GkrKeyringItem *item, const gchar **groups)
{
	const gchar **g;
	gchar *prefix;
	gchar *name, *type;
	gchar *strval;
	guint64 intval;
	
	/* Now do the attributes */
	
	prefix = g_strdup_printf ("%u:attribute", item->id);

	gnome_keyring_attribute_list_free (item->attributes);
	item->attributes = gnome_keyring_attribute_list_new ();
	
	for (g = groups; *g; ++g) {
		if (!g_str_has_prefix (*g, prefix)) 
			continue;
			
		name = g_key_file_get_string (file, *g, "name", NULL);
		type = g_key_file_get_string (file, *g, "type", NULL);
		 
		if (name && type && g_key_file_has_key (file, *g, "value", NULL)) {
			if (g_str_equal (type, "uint32")) {
				if (key_file_get_uint64 (file, *g, "value", &intval))
					gnome_keyring_attribute_list_append_uint32 (item->attributes, 
					                                            name, intval);			
			} else {
				strval = g_key_file_get_string (file, *g, "value", NULL);
				gnome_keyring_attribute_list_append_string (item->attributes, 
				                                            name, strval);
				g_free (strval);
			}
		}
		
		g_free (name);
		g_free (type);
	}
	
	g_free (prefix);
} 

static void 
generate_acl (GKeyFile *file, GkrKeyringItem *item)
{
	GnomeKeyringAccessControl *ac;
	gchar *groupname;
	GList *l;
	gint i;
	
	for (l = item->acl, i = 0; l != NULL; l = l->next, ++i) {
		ac = l->data;
		
		/* Build a group name */
		groupname = g_strdup_printf ("%d:acl%d", item->id, i);
		
		if (ac->application->display_name)
			g_key_file_set_string (file, groupname, "display-name", 
			                       ac->application->display_name);
		if (ac->application->pathname)
			g_key_file_set_string (file, groupname, "path",
			                       ac->application->pathname);

		g_key_file_set_boolean (file, groupname, "read-access", 
		                        ac->types_allowed & GNOME_KEYRING_ACCESS_READ); 
		g_key_file_set_boolean (file, groupname, "write-access", 
		                        ac->types_allowed & GNOME_KEYRING_ACCESS_WRITE); 
		g_key_file_set_boolean (file, groupname, "remove-access", 
		                        ac->types_allowed & GNOME_KEYRING_ACCESS_REMOVE);
		                        
		g_free (groupname); 
	}
}

static void 
parse_acl (GKeyFile *file, GkrKeyringItem *item, const gchar **groups)
{
	GnomeKeyringAccessType access_type;
	GnomeKeyringApplicationRef *app;
	const gchar **g;
	gchar *prefix;
	gchar *path, *display;
	GError *err = NULL;
	
	/* Now do the attributes */
	
	prefix = g_strdup_printf ("%u:acl", item->id);

	gnome_keyring_acl_free (item->acl);
	item->acl = NULL;
	
	for (g = groups; *g; ++g) {
		if (!g_str_has_prefix (*g, prefix)) 
			continue;
		path = g_key_file_get_string (file, *g, "path", NULL);
		if (!path)
			continue;
			
		display = g_key_file_get_string (file, *g, "display-name", NULL);

		access_type = 0;

		if (g_key_file_get_boolean (file, *g, "read-access", &err) && !err)
			access_type |= GNOME_KEYRING_ACCESS_READ;
		g_clear_error (&err);

		if (g_key_file_get_boolean (file, *g, "write-access", &err) && !err)
			access_type |= GNOME_KEYRING_ACCESS_WRITE;
		g_clear_error (&err);

		if (g_key_file_get_boolean (file, *g, "remove-access", &err) && !err)
			access_type |= GNOME_KEYRING_ACCESS_REMOVE;
		g_clear_error (&err);
			
		app = g_new0 (GnomeKeyringApplicationRef, 1);
		app->display_name = display;
		app->pathname = path;
		
		item->acl = g_list_prepend (item->acl, gnome_keyring_access_control_new (app, access_type));
	}
	
	g_free (prefix);
}

static void
generate_item (GKeyFile *file, GkrKeyringItem *item)
{
	gchar *groupname;
	
	groupname = g_strdup_printf ("%u", item->id);
	
	g_key_file_set_integer (file, groupname, "item-type", item->type);
	
	if (item->display_name)
		g_key_file_set_string (file, groupname, "display-name", item->display_name);
	
	if (item->secret)
		g_key_file_set_value (file, groupname, "secret", item->secret);

	key_file_set_uint64 (file, groupname, "mtime", item->mtime);
	key_file_set_uint64 (file, groupname, "ctime", item->ctime);
		
	g_free (groupname);
	
	generate_attributes (file, item);
	generate_acl (file, item);
}

static void 
parse_item (GKeyFile *file, GkrKeyringItem *item, const gchar **groups)
{
	gchar *groupname, *val;
	GError *err = NULL;
	guint64 num;
	
	/* First the main item data */
	
	groupname = g_strdup_printf ("%u", item->id);
	
	/* Never encrypted */
	item->locked = FALSE;
	
	item->type = g_key_file_get_integer (file, groupname, "item-type", &err);
	if (err) {
		g_clear_error (&err);
		item->type = 0;
	}
	
	g_free (item->display_name);
	item->display_name = g_key_file_get_string (file, groupname, "display-name", NULL);

	/* Even though this is from disk, use secure memory just to be consistent */
	egg_secure_free (item->secret);
	val = g_key_file_get_string (file, groupname, "secret", NULL);
	item->secret = egg_secure_strdup (val);
	g_free (val);

	item->mtime = 0; 
	if (key_file_get_uint64 (file, groupname, "mtime", &num))
		item->mtime = num;
	item->ctime = 0;
	if (key_file_get_uint64 (file, groupname, "ctime", &num))
		item->ctime = num;
	
	g_free (groupname);

	/* Now the other stuff */	
	parse_attributes (file, item, groups);
	parse_acl (file, item, groups);	
}

gboolean
gkr_keyring_textual_generate (GkrKeyring *keyring, EggBuffer *buffer)
{
	GkrKeyringItem *item;
	GKeyFile *file;
	gchar *data;
	GError *err = NULL;
	GList *l;
	gsize n_data;
	
	g_return_val_if_fail (!keyring->locked, FALSE);
	
	file = g_key_file_new ();
	
	if (keyring->keyring_name)
		g_key_file_set_string (file, "keyring", "display-name", keyring->keyring_name);
		
	key_file_set_uint64 (file, "keyring", "ctime", keyring->ctime);
	key_file_set_uint64 (file, "keyring", "mtime", keyring->mtime);
	
	g_key_file_set_boolean (file, "keyring", "lock-on-idle", keyring->lock_on_idle);
	g_key_file_set_integer (file, "keyring", "lock-timeout", keyring->lock_timeout);
	
	for (l = keyring->items; l; l = g_list_next (l)) {
		item = GKR_KEYRING_ITEM (l->data);
		generate_item (file, item);
	}

	data = g_key_file_to_data (file, &n_data, &err);
	g_key_file_free (file);
	
	if (!data) {
		g_warning ("couldn't generate textual keyring file: %s", err->message);
		return FALSE;
	}
	
	egg_buffer_uninit (buffer);
	egg_buffer_init_allocated (buffer, (guchar*)data, n_data, NULL);
	return TRUE;
}

static void 
remove_unavailable_item (gpointer key, gpointer dummy, GkrKeyring *keyring)
{
	/* Called to remove items from a keyring that no longer exist */
	
	GkrKeyringItem *item;
	guint id = GPOINTER_TO_UINT (key);
	
	g_assert (GKR_IS_KEYRING (keyring));
	
	item = gkr_keyring_get_item (keyring, id);
	if (item)
		gkr_keyring_remove_item (keyring, item);
}

gint
gkr_keyring_textual_parse (GkrKeyring *keyring, EggBuffer *buffer) 
{
	GkrKeyringItem *item;
	GError *err = NULL;
	GKeyFile *file = NULL;
	gchar **groups = NULL;
	gint ret = -1;
	gchar *start = NULL;
	GHashTable *checks = NULL;
	guint64 num;
	gint integer;
	GList *l;
	gchar **g;
	gchar *end;
	guint32 id;
	
	file = g_key_file_new ();
	
	if (!g_key_file_load_from_data (file, (const gchar*)buffer->buf, 
	                                buffer->len, G_KEY_FILE_NONE, &err)) {
		if (g_error_matches (err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE))
			ret = 0;
		goto done;
	}
	
	start = g_key_file_get_start_group (file);
	if (!start || !g_str_equal (start, "keyring")) {
		g_message ("invalid keyring file: wrong header group");
		goto done;
	}
	
	g_free (keyring->keyring_name);
	keyring->keyring_name = g_key_file_get_string (file, "keyring", "display-name", NULL);

	keyring->ctime = 0;
	if (key_file_get_uint64 (file, "keyring", "ctime", &num))
		keyring->ctime = num;
	keyring->mtime = 0;
	if (key_file_get_uint64 (file, "keyring", "mtime", &num))
		keyring->mtime = num;
	
	keyring->lock_on_idle = FALSE;
	if (g_key_file_get_boolean (file, "keyring", "lock-on-idle", &err) && !err)
		keyring->lock_on_idle = TRUE;
	g_clear_error (&err);
	
	integer = g_key_file_get_integer (file, "keyring", "lock-timeout", &err);
	if (!err)
		keyring->lock_timeout = integer;
	g_clear_error (&err);
	
	/* No encryption context for use when reencrypting */
	keyring->salt_valid = FALSE;
	memset (keyring->salt, 0, sizeof (keyring->salt));
	keyring->hash_iterations = 0;
	
	/* Build a Hash table where we can track ids we haven't yet seen */
	checks = g_hash_table_new (g_direct_hash, g_direct_equal);
	for (l = keyring->items; l; l = g_list_next (l)) {
		item = GKR_KEYRING_ITEM (l->data);
		g_hash_table_insert (checks, GUINT_TO_POINTER (item->id), "DUMMY");
	}
	
	groups = g_key_file_get_groups (file, NULL);
	for (g = groups; *g; ++g) {
		id = strtoul (*g, &end, 10);
		
		/* Wasn't a complete number */
		if (end[0]) 
			continue;

		/* We've seen this id */
		g_hash_table_remove (checks, GUINT_TO_POINTER (id));
		
		item = gkr_keyring_get_item (keyring, id);
		if (item == NULL) {
			item = gkr_keyring_item_new (keyring, id, 0);
			gkr_keyring_add_item (keyring, item);
			g_object_unref (item);
		}

		parse_item (file, item, (const gchar**)groups);
	}
	
	g_hash_table_foreach (checks, (GHFunc)remove_unavailable_item, keyring);
	ret = 1;
	
done:
	if (checks)
		g_hash_table_destroy (checks);
	if (file)
		g_key_file_free (file);
	g_strfreev (groups);
	g_free (start);
	g_clear_error (&err);

	return ret;	
}
