/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
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

#include "gkd-secret-util.h"

#include "pkcs11/pkcs11i.h"

#include <string.h>

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
encode_object_identifier (GString *result, const gchar* name, gssize length)
{
	g_assert (result);
	g_assert (name);

	if (length < 0)
		length = strlen (name);

	while (length > 0) {
		char ch = *(name++);
		--length;

		/* Normal characters can go right through */
		if (G_LIKELY ((ch >= 'A' && ch <= 'Z') ||
		              (ch >= 'a' && ch <= 'z') ||
		              (ch >= '0' && ch <= '9'))) {
			g_string_append_c_inline (result, ch);

		/* Special characters are encoded with a _ */
		} else {
			g_string_append_printf (result, "_%02x", (unsigned int)ch);
		}
	}
}

static gchar*
decode_object_identifier (const gchar* enc, gssize length)
{
	GString *result;

	g_assert (enc);

	if (length < 0)
		length = strlen (enc);

	result = g_string_sized_new (length);
	while (length > 0) {
		char ch = *(enc++);
		--length;

		/* Underscores get special handling */
		if (G_UNLIKELY (ch == '_' &&
		                g_ascii_isxdigit(enc[0]) &&
		                g_ascii_isxdigit (enc[1]))) {
			ch = (g_ascii_xdigit_value (enc[0]) * 16) +
			     (g_ascii_xdigit_value (enc[1]));
			enc += 2;
			length -= 2;
		}

		g_string_append_c_inline (result, ch);
	}

	return g_string_free (result, FALSE);
}

static gboolean
parse_collection_and_item_from_path (const gchar *path, gchar **collection, gchar **item)
{
	const gchar *pos;

	g_return_val_if_fail (path, FALSE);

	/* Make sure it starts with our prefix */
	if (!g_str_has_prefix (path, SECRET_COLLECTION_PREFIX))
		return FALSE;
	path += strlen (SECRET_COLLECTION_PREFIX);

	/* Skip the path separator */
	if (path[0] != '/')
		return FALSE;
	++path;

	/* Make sure we have something */
	if (path[0] == '\0')
		return FALSE;

	pos = strchr (path, '/');

	/* No item, just a collection */
	if (pos == NULL) {
		if (collection)
			*collection = decode_object_identifier (path, -1);
		if (item)
			*item = NULL;
		return TRUE;
	}

	/* Make sure we have an item, and no further path bits */
	if (pos[1] == '\0' || strchr (pos + 1, '/'))
		return FALSE;

	if (collection)
		*collection = decode_object_identifier (path, pos - path);
	if (item)
		*item = decode_object_identifier (pos + 1, -1);
	return TRUE;
}

static gchar*
get_cached_path (GP11Object *object)
{
	gchar *path = g_object_get_data (G_OBJECT (object), "gkd-util-cached-identifier");
	return g_strdup (path);
}

static void
set_cached_path (GP11Object *object, const gchar *path)
{
	g_object_set_data_full (G_OBJECT (object), "gkd-util-cached-identifier",
	                        g_strdup (path), g_free);
}

static GP11Object*
item_for_identifier (GP11Session *session, const gchar *coll_id, const gchar *item_id)
{
	GP11Object *object = NULL;
	GError *error = NULL;
	GList *objects;

	g_assert (coll_id);
	g_assert (item_id);

	/*
	 * TODO: I think this could benefit from some sort of
	 * caching?
	 */

	objects = gp11_session_find_objects (session, &error,
	                                     CKA_CLASS, GP11_ULONG, CKO_SECRET_KEY,
	                                     CKA_G_COLLECTION, strlen (coll_id), coll_id,
	                                     CKA_ID, strlen (item_id), item_id,
	                                     GP11_INVALID);

	if (error != NULL) {
		g_warning ("couldn't lookup '%s/%s' item: %s", coll_id, item_id, error->message);
		g_clear_error (&error);
		return NULL;
	}

	if (objects) {
		object = g_object_ref (objects->data);
		gp11_object_set_session (object, session);
	}

	gp11_list_unref_free (objects);
	return object;
}

static GP11Object*
collection_for_identifier (GP11Session *session, const gchar *coll_id)
{
	GP11Object *object = NULL;
	GError *error = NULL;
	GList *objects;

	g_assert (GP11_IS_SESSION (session));
	g_assert (coll_id);

	objects = gp11_session_find_objects (session, &error,
	                                     CKA_CLASS, GP11_ULONG, CKO_G_COLLECTION,
	                                     CKA_ID, strlen (coll_id), coll_id,
	                                     GP11_INVALID);

	if (error != NULL) {
		g_warning ("couldn't lookup '%s' collection: %s", coll_id, error->message);
		g_clear_error (&error);
		return NULL;
	}

	if (objects) {
		object = objects->data;
		gp11_object_set_session (object, session);
		g_object_set_data_full (G_OBJECT (object), "coll-identifier", g_strdup (coll_id), g_free);
		g_object_ref (object);
	}

	gp11_list_unref_free (objects);
	return object;
}

GP11Object*
gkd_secret_util_path_to_collection (GP11Session *session, const gchar *path)
{
	GP11Object *collection = NULL;
	gchar *coll_id;
	gchar *item_id;

	g_return_val_if_fail (GP11_IS_SESSION (session), NULL);
	g_return_val_if_fail (path, NULL);

	/* Figure out which collection or item we're talking about */
	if (!parse_collection_and_item_from_path (path, &coll_id, &item_id))
		return NULL;

	g_return_val_if_fail (coll_id, NULL);
	collection = collection_for_identifier (session, coll_id);

	g_free (coll_id);
	g_free (item_id);

	if (collection) {
		set_cached_path (collection, path);
		gp11_object_set_session (collection, session);
	}

	return collection;
}

gchar*
gkd_secret_util_path_for_collection (GP11Object *object)
{
	GError *error = NULL;
	GString *result;
	gpointer data;
	gsize n_data;
	gchar *path;

	g_return_val_if_fail (GP11_IS_OBJECT (object), NULL);

	path = get_cached_path (object);
	if (path != NULL)
		return path;

	data = gp11_object_get_data (object, CKA_ID, &n_data, &error);
	if (data == NULL) {
		g_warning ("couldn't lookup identifier for collection: %s",
		           error->message);
		g_clear_error (&error);
		g_return_val_if_reached (NULL);
	}

	result = g_string_new (SECRET_COLLECTION_PREFIX);
	g_string_append_c (result, '/');
	encode_object_identifier (result, data, n_data);
	g_free (data);

	path = g_string_free (result, FALSE);
	set_cached_path (object, path);
	return path;
}

GP11Object*
gkd_secret_util_path_to_item (GP11Session *session, const gchar *path)
{
	GP11Object *item = NULL;
	gchar *coll_id;
	gchar *item_id;

	g_return_val_if_fail (GP11_IS_SESSION (session), NULL);
	g_return_val_if_fail (path, NULL);

	/* Figure out which collection or item we're talking about */
	if (!parse_collection_and_item_from_path (path, &coll_id, &item_id))
		return NULL;

	if (coll_id && item_id)
		item = item_for_identifier (session, coll_id, item_id);
	g_free (coll_id);
	g_free (item_id);

	if (item) {
		set_cached_path (item, path);
		gp11_object_set_session (item, session);
	}

	return item;
}

gchar*
gkd_secret_util_path_for_item (GP11Object *object)
{
	GError *error = NULL;
	GP11Attributes *attrs;
	GP11Attribute *attr;
	GString *result;
	gchar *path;

	g_return_val_if_fail (GP11_IS_OBJECT (object), NULL);

	path = get_cached_path (object);
	if (path != NULL)
		return path;

	attrs = gp11_object_get (object, &error, CKA_ID, CKA_G_COLLECTION, GP11_INVALID);
	if (attrs == NULL) {
		g_warning ("couldn't lookup identifier for item: %s", error->message);
		g_clear_error (&error);
		g_return_val_if_reached (NULL);
	}

	result = g_string_new (SECRET_COLLECTION_PREFIX);

	g_string_append_c (result, '/');
	attr = gp11_attributes_find (attrs, CKA_G_COLLECTION);
	g_return_val_if_fail (attr && !gp11_attribute_is_invalid (attr), NULL);
	encode_object_identifier (result, (const gchar*)attr->value, attr->length);

	g_string_append_c (result, '/');
	attr = gp11_attributes_find (attrs, CKA_ID);
	g_return_val_if_fail (attr && !gp11_attribute_is_invalid (attr), NULL);
	encode_object_identifier (result, (const gchar*)attr->value, attr->length);

	gp11_attributes_unref (attrs);

	path = g_string_free (result, FALSE);
	set_cached_path (object, path);
	return path;
}

GP11Object*
gkd_secret_util_path_to_object (GP11Session *session, const gchar *path,
                                gboolean *is_item)
{
	GP11Object *object = NULL;
	gchar *coll_id;
	gchar *item_id;

	g_return_val_if_fail (GP11_IS_SESSION (session), NULL);
	g_return_val_if_fail (path, NULL);

	/* Figure out which collection or item we're talking about */
	if (!parse_collection_and_item_from_path (path, &coll_id, &item_id))
		return NULL;

	if (item_id) {
		object = item_for_identifier (session, coll_id, item_id);
		if (is_item)
			*is_item = TRUE;
	} else {
		object = collection_for_identifier (session, coll_id);
	}

	g_free (coll_id);
	g_free (item_id);

	if (object) {
		set_cached_path (object, path);
		gp11_object_set_session (object, session);
	}

	return object;
}


gchar*
gkd_secret_util_identifier_for_collection (GP11Object *collection)
{
	GError *error = NULL;
	gchar *identifier = NULL;
	gpointer data;
	gsize n_data;
	gchar *path;

	g_return_val_if_fail (GP11_IS_OBJECT (collection), NULL);

	/* Try to parse it out of the path */
	path = get_cached_path (collection);
	if (path != NULL) {
		parse_collection_and_item_from_path (path, &identifier, NULL);
		g_free (path);
	}

	/* Must do a lookup */
	if (identifier == NULL) {
		data = gp11_object_get_data (collection, CKA_ID, &n_data, &error);
		if (data == NULL) {
			g_warning ("couldn't get identifier for collection: %s", error->message);
			g_clear_error (&error);
		} else {
			identifier = g_strndup (data, n_data);
			g_free (data);
		}
	}

	return identifier;
}

GP11Attributes*
gkd_secret_util_attributes_for_item (GP11Object *item)
{
	gchar *coll, *identifier;
	GP11Attributes *attrs;
	gchar *path;

	path = gkd_secret_util_path_for_item (item);
	if (path == NULL)
		return NULL;

	if (!parse_collection_and_item_from_path (path, &coll, &identifier))
		g_return_val_if_reached (NULL);

	attrs = gp11_attributes_new ();
	gp11_attributes_add_string (attrs, CKA_G_COLLECTION, coll);
	gp11_attributes_add_string (attrs, CKA_ID, identifier);

	g_free (identifier);
	g_free (coll);
	g_free (path);
	return attrs;
}
