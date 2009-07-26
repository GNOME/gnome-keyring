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

#include "gck-secret-fields.h"

#include "gck/gck-attributes.h"

#include <ctype.h>
#include <string.h>

GType
gck_secret_fields_boxed_type (void)
{
	static GType type = 0;
	if (!type) 
		type = g_boxed_type_register_static ("GHashTable_Fields", 
		                                     (GBoxedCopyFunc)g_hash_table_ref,
		                                     (GBoxedFreeFunc)g_hash_table_unref);
	return type;
}

GHashTable*
gck_secret_fields_new (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

CK_RV
gck_secret_fields_parse (CK_ATTRIBUTE_PTR attr, GHashTable **fields)
{
	GHashTable *result;
	gchar *name;
	gsize n_name;
	gchar *value;
	gsize n_value;
	gchar *ptr;
	gchar *last;
	
	g_assert (attr);
	g_assert (fields);

	ptr = attr->pValue;
	last = ptr + attr->ulValueLen;
	
	if (!ptr && last != ptr)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	result = gck_secret_fields_new ();

	while (ptr && ptr != last) {
		g_assert (ptr < last);
		
		name = ptr;
		ptr = memchr (ptr, 0, last - ptr);
		
		/* No value is present? */
		if (!ptr) {
			g_hash_table_unref (result);
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		
		n_name = ptr - name;
		value = ptr;
		ptr = memchr (ptr, 0, last - ptr);
		
		/* The last value */
		if (ptr == NULL)
			ptr = last;
		
		n_value = ptr - value;

		/* Validate the name and value*/
		if (!g_utf8_validate (name, n_name, NULL) || 
		    !g_utf8_validate (value, n_value, NULL)) {
			g_hash_table_unref (result);
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		
		g_hash_table_replace (result, g_strndup (name, n_name), g_strndup (value, n_value));
	}
	
	*fields = result;
	return CKR_OK;
}

static void
each_field_append (gpointer key, gpointer value, gpointer user_data)
{
	GString *result = user_data;
	g_string_append (result, key);
	g_string_append_c (result, '\0');
	g_string_append (result, value);
	g_string_append_c (result, '\0');
}

static void
each_field_length (gpointer key, gpointer value, gpointer user_data)
{
	gsize *length = user_data;
	*length += strlen (key);
	*length += strlen (value);
	*length += 2;
}

CK_RV
gck_secret_fields_serialize (CK_ATTRIBUTE_PTR attr, GHashTable *fields)
{
	GString *result;
	gsize length;
	CK_RV rv;
	
	g_assert (attr);
	g_assert (fields);
	
	if (!attr->pValue) {
		length = 0;
		g_hash_table_foreach (fields, each_field_length, &length);
		attr->ulValueLen = length;
		return CKR_OK;
	}
	
	result = g_string_sized_new (256);
	g_hash_table_foreach (fields, each_field_append, result);
	
	rv = gck_attribute_set_data (attr, result->str, result->len);
	g_string_free (result, TRUE);
	
	return rv;
}

gboolean
gck_secret_fields_match (GHashTable *haystack, GHashTable *needle)
{
	GHashTableIter iter;
	gpointer key, value, hay;

	g_return_val_if_fail (haystack, FALSE);
	g_return_val_if_fail (needle, FALSE);

	g_hash_table_iter_init (&iter, needle);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		g_assert (key && value);
		hay = g_hash_table_lookup (haystack, key);
		if (hay == NULL)
			return FALSE;
		if (!g_str_equal (hay, value))
			return FALSE;
	}
	
	return TRUE;
}

gboolean
gck_secret_fields_has_word (GHashTable *fields, const gchar *name, const gchar *word)
{
	const gchar *string;
	const gchar *at;
	gsize len = strlen (word);

	if (len == 0)
		return FALSE;

	string = g_hash_table_lookup (fields, name);
	if (!string)
		return FALSE;

	for (;;) {
		at = strstr (string, word);
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
