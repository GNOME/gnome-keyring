/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-secret-textual.c - Textual non-encrypted format for the keyring

   Copyright (C) 2007, 2009 Stefan Walter

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

#include "gck-secret-collection.h"
#include "gck-secret-compat.h"
#include "gck-secret-fields.h"
#include "gck-secret-item.h"
#include "gck-secret-textual.h"

#include "egg/egg-secure-memory.h"

#include "gck/gck-secret.h"

#include <glib.h>

#include <sys/types.h>

#include <ctype.h>
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

typedef struct _AttributesCtx {
	GckSecretItem *item;
	gint index;
	GKeyFile *file;
	const gchar *compat_uint32;
} AttributesCtx;

static gboolean
attribute_name_in_space_string (const gchar *string, const gchar *name)
{
	const gchar *at;
	gsize len = strlen (name);
	
	if (len == 0)
		return FALSE;

	for (;;) {
		at = strstr (string, name);
		if (at == NULL)
			return FALSE;
		
		/* The word exists, is at beginning or end, or spaces around it */
		if ((at == string || isspace (*(at - 1))) && 
		    (*(at + len) == 0 || isspace (*(at + len))))
			return TRUE;
	
		string = at + len;
	}

	g_assert_not_reached ();
}

static void
generate_each_attribute (gpointer key, gpointer value, gpointer user_data)
{
	AttributesCtx *ctx = user_data;
	const gchar *name = key;
	const gchar *string = value;
	gchar *groupname;
	
	groupname = g_strdup_printf ("%s:attribute%d", 
	                             gck_secret_object_get_identifier (GCK_SECRET_OBJECT (ctx->item)),
	                             ctx->index);
	
	g_key_file_set_string (ctx->file, groupname, "name", name);
	
	/* 
	 * COMPATIBILITY:
	 * 
	 * Our new Secrets API doesn't support integer attributes. However, to have 
	 * compatibility with old keyring code reading this file, we need to set 
	 * the type=uint32 attribute appropriately where expected. 
	 * 
	 * If there's an extra compat-uint32 attribute and the name of this attribute
	 * is contained in that list, then write as a uint32.
	 */
	
	/* Determine if it's a uint32 compatible value, and store as such if it is */
	if (attribute_name_in_space_string (ctx->compat_uint32, name))
		g_key_file_set_string (ctx->file, groupname, "type", "uint32");
	else
		g_key_file_set_string (ctx->file, groupname, "type", "string");
	
	g_key_file_set_string (ctx->file, groupname, "value", string);
	
	g_free (groupname);
	++ctx->index;
}

static void
generate_attributes (GKeyFile *file, GckSecretItem *item)
{
	GHashTable *attributes;
	AttributesCtx ctx;
	
	attributes = gck_secret_item_get_fields (item);
	if (!attributes)
		return;
	
	ctx.item = item;
	ctx.index = 0;
	ctx.file = file;
	ctx.compat_uint32 = g_hash_table_lookup (attributes, "compat-uint32");
	if (!ctx.compat_uint32)
		ctx.compat_uint32 = "";

	g_hash_table_foreach (attributes, generate_each_attribute, &ctx);
}

static void
parse_attributes (GKeyFile *file, GckSecretItem *item, const gchar **groups)
{
	GHashTable *attributes;
	GString *compat_uint32;
	const gchar *identifier;
	const gchar **g;
	gchar *prefix;
	gchar *name, *type;
	
	/* Now do the attributes */
	
	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (item));
	prefix = g_strdup_printf ("%s:attribute", identifier);
	attributes = gck_secret_fields_new ();
	compat_uint32 = NULL;
	
	for (g = groups; *g; ++g) {
		if (!g_str_has_prefix (*g, prefix)) 
			continue;
			
		name = g_key_file_get_string (file, *g, "name", NULL);
		if (!name || g_key_file_has_key (file, *g, "value", NULL))
			continue;

		type = g_key_file_get_string (file, *g, "type", NULL);
		if (type && g_str_equal (type, "uint32")) {
			if (!compat_uint32)
				compat_uint32 = g_string_new ("");
			g_string_append (compat_uint32, name);
			g_string_append_c (compat_uint32, ' ');
		}
		
		g_free (type);
			
		g_hash_table_replace (attributes, name, 
		                      g_key_file_get_string (file, *g, "value", NULL));
	}
	
	if (compat_uint32)
		g_hash_table_replace (attributes, g_strdup ("compat-uint32"),
		                      g_string_free (compat_uint32, FALSE));
	
	g_free (prefix);
} 

static void 
generate_acl (GKeyFile *file, GckSecretItem *item)
{
	const gchar *identifier;
	GckSecretAccess *ac;
	gchar *groupname;
	GList *acl;
	gint i;
	
	/* 
	 * COMPATIBILITY: If we loaded ACLs and they're set on the item,
	 * then store them back in.
	 */
	
	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (item));
	acl = g_object_get_data (G_OBJECT (item), "compat-acl");
	for (i = 0; acl != NULL; acl = g_list_next (acl), ++i) {
		ac = acl->data;

		/* Build a group name */
		groupname = g_strdup_printf ("%s:acl%d", identifier, i);

		if (ac->display_name)
			g_key_file_set_string (file, groupname, "display-name", ac->display_name);
		if (ac->pathname)
			g_key_file_set_string (file, groupname, "path", ac->pathname);

		g_key_file_set_boolean (file, groupname, "read-access", 
		                        ac->types_allowed & GCK_SECRET_ACCESS_READ); 
		g_key_file_set_boolean (file, groupname, "write-access", 
		                        ac->types_allowed & GCK_SECRET_ACCESS_WRITE); 
		g_key_file_set_boolean (file, groupname, "remove-access", 
		                        ac->types_allowed & GCK_SECRET_ACCESS_REMOVE);
		                        
		g_free (groupname);
	}
}

static void 
parse_acl (GKeyFile *file, GckSecretItem *item, const gchar **groups)
{
	GckSecretAccessType access_type;
	GckSecretAccess *ac;
	const gchar *identifier;
	const gchar **g;
	gchar *prefix;
	gchar *path, *display;
	GError *err = NULL;
	GList *acl;
	
	/* 
	 * COMPATIBILITY: We don't actually use ACLs, but if we find them in the 
	 * file, then load them and save back later.
	 */
	
	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (item));
	prefix = g_strdup_printf ("%s:acl", identifier);
	acl = NULL;
	
	for (g = groups; *g; ++g) {
		if (!g_str_has_prefix (*g, prefix)) 
			continue;
		path = g_key_file_get_string (file, *g, "path", NULL);
		if (!path)
			continue;
			
		display = g_key_file_get_string (file, *g, "display-name", NULL);

		access_type = 0;

		if (g_key_file_get_boolean (file, *g, "read-access", &err) && !err)
			access_type |= GCK_SECRET_ACCESS_READ;
		g_clear_error (&err);

		if (g_key_file_get_boolean (file, *g, "write-access", &err) && !err)
			access_type |= GCK_SECRET_ACCESS_WRITE;
		g_clear_error (&err);

		if (g_key_file_get_boolean (file, *g, "remove-access", &err) && !err)
			access_type |= GCK_SECRET_ACCESS_REMOVE;
		g_clear_error (&err);
		
		ac = g_new0 (GckSecretAccess, 1);
		ac->display_name = display;
		ac->pathname = path;
		ac->types_allowed = access_type;
		
		acl = g_list_prepend (acl, ac);
	}
	
	g_object_set_data_full (G_OBJECT (item), "compat-acl", acl, gck_secret_compat_acl_free);
	g_free (prefix);
}

static void
generate_item (GKeyFile *file, GckSecretItem *item)
{
	GckSecretObject *obj;
	GHashTable *attributes;
	const gchar *value;
	const gchar *groupname;
	GckSecret *secret;
	const gchar *password;
	gsize n_password;
	
	obj = GCK_SECRET_OBJECT (item);
	groupname = gck_secret_object_get_identifier (obj);
	attributes = gck_secret_item_get_fields (item);
	
	/* 
	 * COMPATIBILITY: We no longer have the concept of an item type.
	 * The gkr:item-type field serves that purpose.
	 */
	
	value = g_hash_table_lookup (attributes, "gkr:item-type");
	g_key_file_set_integer (file, groupname, "item-type",
	                        gck_secret_compat_parse_item_type (value));

	value = gck_secret_object_get_label (obj);
	if (value != NULL)
		g_key_file_set_string (file, groupname, "display-name", value);
	
	secret = gck_secret_item_get_secret (item);
	if (secret != NULL) {
		password = gck_secret_get_password (secret, &n_password);
		/* TODO: What about non-textual passwords? */
		if (password != NULL) 
			g_key_file_set_value (file, groupname, "secret", (gchar*)password);
	}

	key_file_set_uint64 (file, groupname, "mtime", gck_secret_object_get_modified (obj));
	key_file_set_uint64 (file, groupname, "ctime", gck_secret_object_get_created (obj));
	
	generate_attributes (file, item);
	generate_acl (file, item);
}

static void 
parse_item (GKeyFile *file, GckSecretItem *item, const gchar **groups)
{
	GckSecretObject *obj;
	GHashTable *attributes;
	const gchar *groupname;
	GError *err = NULL;
	GckSecret *secret;
	gchar *val;
	guint64 num;
	gint type;
	
	/* First the main item data */
	
	obj = GCK_SECRET_OBJECT (item);
	groupname = gck_secret_object_get_identifier (obj);
	attributes = gck_secret_item_get_fields (item);
	
	/* 
	 * COMPATIBILITY: We no longer have the concept of an item type.
	 * The gkr:item-type field serves that purpose.
	 */

	type = g_key_file_get_integer (file, groupname, "item-type", &err);
	if (err) {
		g_clear_error (&err);
		type = 0;
	}

	gck_secret_fields_add (attributes, "gkr:item-type",
	                       gck_secret_compat_format_item_type (type));

	val = g_key_file_get_string (file, groupname, "display-name", NULL);
	gck_secret_object_set_label (obj, val);
	g_free (val);

	val = g_key_file_get_string (file, groupname, "secret", NULL);
	if (val == NULL) {
		gck_secret_item_set_secret (item, NULL);
	} else {
		secret = gck_secret_new ((guchar*)val, strlen (val));
		gck_secret_item_set_secret (item, secret);
		g_object_unref (secret);
		g_free (val);
	}

	num = 0;
	if (key_file_get_uint64 (file, groupname, "mtime", &num))
		gck_secret_object_set_modified (obj, num);
	num = 0;
	if (key_file_get_uint64 (file, groupname, "ctime", &num))
		gck_secret_object_set_created (obj, num);

	/* Now the other stuff */	
	parse_attributes (file, item, groups);
	parse_acl (file, item, groups);	
}

GckDataResult
gck_secret_textual_write (GckSecretCollection *collection, guchar **result, gsize *n_result)
{
	GckSecretObject *obj;
	GList *items, *l;
	const gchar *value;
	GKeyFile *file;
	GError *err = NULL;
	gboolean idle_lock;
	gint idle_timeout;
	
	obj = GCK_SECRET_OBJECT (collection);
	g_return_val_if_fail (!gck_secret_collection_get_state (collection) == GCK_SECRET_COMPLETE, FALSE);

	file = g_key_file_new ();
	
	value = gck_secret_object_get_label (obj);
	if (value != NULL)
		g_key_file_set_string (file, "keyring", "display-name", value);
	
	key_file_set_uint64 (file, "keyring", "ctime", gck_secret_object_get_created (obj));
	key_file_set_uint64 (file, "keyring", "mtime", gck_secret_object_get_modified (obj));
	
	/* Not currently used :( */
	idle_lock = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (collection), "lock-on-idle"));
	g_key_file_set_boolean (file, "keyring", "lock-on-idle", idle_lock);
	idle_timeout = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (collection), "lock-timeout"));
	g_key_file_set_integer (file, "keyring", "lock-timeout", idle_timeout);
	
	items = gck_secret_collection_get_items (collection);
	for (l = items; l; l = g_list_next (l)) 
		generate_item (file, l->data);
	g_list_free (items);

	*result = (guchar*)g_key_file_to_data (file, n_result, &err);
	g_key_file_free (file);
	
	if (!*result) {
		g_warning ("couldn't generate textual keyring file: %s", err->message);
		return GCK_DATA_FAILURE;
	}
	
	return GCK_DATA_SUCCESS;
}

static void 
remove_unavailable_item (gpointer key, gpointer dummy, gpointer user_data)
{
	/* Called to remove items from a keyring that no longer exist */

	GckSecretCollection *collection = GCK_SECRET_COLLECTION (user_data);
	GckSecretItem *item;
	
	g_assert (GCK_IS_SECRET_COLLECTION (collection));
	
	item = gck_secret_collection_get_item (collection, key);
	if (item != NULL)
		gck_secret_collection_remove_item (collection, item);
}

GckDataResult
gck_secret_textual_read (GckSecretCollection *collection, const guchar *data, gsize n_data) 
{
	GckSecretObject *obj;
	GckSecretItem *item;
	GList *items, *l;
	GError *err = NULL;
	GKeyFile *file = NULL;
	gchar **groups = NULL;
	GckDataResult res = GCK_DATA_FAILURE;
	gchar *start = NULL;
	const gchar *identifier;
	GHashTable *checks = NULL;
	gboolean lock_idle;
	gint lock_timeout;
	gchar *value;
	guint64 num;
	gchar **g;
	
	file = g_key_file_new ();
	obj = GCK_SECRET_OBJECT (collection);
	
	if (!g_key_file_load_from_data (file, (const gchar*)data, n_data, G_KEY_FILE_NONE, &err)) {
		if (g_error_matches (err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE))
			res = GCK_DATA_UNRECOGNIZED;
		goto done;
	}
	
	start = g_key_file_get_start_group (file);
	if (!start || !g_str_equal (start, "keyring")) {
		g_message ("invalid keyring file: wrong header group");
		goto done;
	}
	
	value = g_key_file_get_string (file, "keyring", "display-name", NULL);
	gck_secret_object_set_label (obj, value);
	g_free (value);

	num = 0;
	key_file_get_uint64 (file, "keyring", "ctime", &num);
	gck_secret_object_set_created (obj, num);

	num = 0;
	key_file_get_uint64 (file, "keyring", "mtime", &num);
	gck_secret_object_set_modified (obj, num);
	
	/* Not currently used :( */
	lock_idle = g_key_file_get_boolean (file, "keyring", "lock-on-idle", NULL);
	g_object_set_data (G_OBJECT (collection), "lock-on-idle", GINT_TO_POINTER (lock_idle));
	lock_timeout = g_key_file_get_integer (file, "keyring", "lock-timeout", NULL);
	g_object_set_data (G_OBJECT (collection), "lock-timeout", GINT_TO_POINTER (lock_timeout));
	
	/* Build a Hash table where we can track ids we haven't yet seen */
	checks = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	items = gck_secret_collection_get_items (collection);
	for (l = items; l; l = g_list_next (l)) {
		identifier = gck_secret_object_get_identifier (l->data);
		g_hash_table_replace (checks, g_strdup (identifier), "unused");
	}
	
	groups = g_key_file_get_groups (file, NULL);
	for (g = groups; *g; ++g) {
		identifier = *g;
		if (g_str_equal (identifier, "keyring"))
			continue;

		/* We've seen this id */
		g_hash_table_remove (checks, identifier);
		
		item = gck_secret_collection_get_item (collection, identifier);
		if (item == NULL)
			item = gck_secret_collection_create_item (collection, identifier);
		parse_item (file, item, (const gchar**)groups);
	}
	
	g_hash_table_foreach (checks, (GHFunc)remove_unavailable_item, collection);
	res = GCK_DATA_SUCCESS;
	
done:
	if (checks)
		g_hash_table_destroy (checks);
	if (file)
		g_key_file_free (file);
	g_strfreev (groups);
	g_free (start);
	g_clear_error (&err);

	return res;	
}
