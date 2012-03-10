/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-asn1.c - ASN.1 helper routines

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

#include "egg-asn1-defs.h"
#include "egg-asn1x.h"
#include "egg-dn.h"
#include "egg-oid.h"

#include <string.h>

static const char HEXC[] = "0123456789ABCDEF";

static gchar*
dn_print_hex_value (EggBytes *val)
{
	const gchar *data = egg_bytes_get_data (val);
	gsize size = egg_bytes_get_size (val);
	GString *result = g_string_sized_new (size * 2 + 1);
	gsize i;

	g_string_append_c (result, '#');
	for (i = 0; i < size; ++i) {
		g_string_append_c (result, HEXC[data[i] >> 4 & 0xf]);
		g_string_append_c (result, HEXC[data[i] & 0xf]);
	}

	return g_string_free (result, FALSE);
}

static gchar*
dn_print_oid_value_parsed (GQuark oid,
                           guint flags,
                           EggBytes *val)
{
	GNode *asn1, *node;
	EggBytes *value;
	const gchar *data;
	gsize size;
	gchar *result;

	g_assert (val != NULL);

	asn1 = egg_asn1x_create_quark (pkix_asn1_tab, oid);
	g_return_val_if_fail (asn1, NULL);

	if (!egg_asn1x_decode (asn1, val)) {
		g_message ("couldn't decode value for OID: %s: %s",
		           g_quark_to_string (oid), egg_asn1x_message (asn1));
		egg_asn1x_destroy (asn1);
		return NULL;
	}

	/*
	 * If it's a choice element, then we have to read depending
	 * on what's there.
	 */
	if (flags & EGG_OID_IS_CHOICE)
		node = egg_asn1x_get_choice (asn1);
	else
		node = asn1;

	value = egg_asn1x_get_raw_value (node);
	data = egg_bytes_get_data (value);
	size = egg_bytes_get_size (value);

	/*
	 * Now we make sure it's UTF-8.
	 */

	if (!value) {
		g_message ("couldn't read value for OID: %s", g_quark_to_string (oid));
		result = NULL;

	} else if (!g_utf8_validate (data, size, NULL)) {
		result = dn_print_hex_value (value);

	} else {
		result = g_strndup (data, size);
	}

	egg_bytes_unref (value);
	egg_asn1x_destroy (asn1);

	return result;
}

static gchar*
dn_print_oid_value (GQuark oid,
                    guint flags,
                    EggBytes *val)
{
	gchar *value;

	g_assert (val != NULL);

	if (flags & EGG_OID_PRINTABLE) {
		value = dn_print_oid_value_parsed (oid, flags, val);
		if (value != NULL)
			return value;
	}

	return dn_print_hex_value (val);
}

static gchar*
dn_parse_rdn (GNode *asn)
{
	const gchar *name;
	guint flags;
	GQuark oid;
	EggBytes *value;
	gchar *display;
	gchar *result;

	g_assert (asn);

	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "type", NULL));
	g_return_val_if_fail (oid, NULL);

	flags = egg_oid_get_flags (oid);
	name = egg_oid_get_name (oid);

	value = egg_asn1x_get_element_raw (egg_asn1x_node (asn, "value", NULL));
	g_return_val_if_fail (value, NULL);

	display = dn_print_oid_value (oid, flags, value);
	result = g_strconcat ((flags & EGG_OID_PRINTABLE) ? name : g_quark_to_string (oid),
	                      "=", display, NULL);
	g_free (display);

	egg_bytes_unref (value);
	return result;
}

gchar*
egg_dn_read (GNode* asn)
{
	gboolean done = FALSE;
	GString *result;
	GNode *node;
	gchar *rdn;
	gint i, j;

	g_return_val_if_fail (asn, NULL);

	result = g_string_sized_new (64);

	/* Each (possibly multi valued) RDN */
	for (i = 1; !done; ++i) {

		/* Each type=value pair of an RDN */
		for (j = 1; TRUE; ++j) {
			node = egg_asn1x_node (asn, i, j, NULL);
			if (!node) {
				done = j == 1;
				break;
			}

			rdn = dn_parse_rdn (node);
			g_return_val_if_fail (rdn, NULL);

			/* Account for multi valued RDNs */
			if (j > 1)
				g_string_append (result, "+");
			else if (i > 1)
				g_string_append (result, ", ");

			g_string_append (result, rdn);
			g_free (rdn);
		}
	}

	/* Returns null when string is empty */
	return g_string_free (result, (result->len == 0));
}

gchar*
egg_dn_read_part (GNode *asn, const gchar *match)
{
	gboolean done = FALSE;
	const gchar *name;
	EggBytes *value;
	GNode *node;
	GQuark oid;
	gint i, j;
	gchar *result;

	g_return_val_if_fail (asn, NULL);
	g_return_val_if_fail (match, NULL);

	/* Each (possibly multi valued) RDN */
	for (i = 1; !done; ++i) {

		/* Each type=value pair of an RDN */
		for (j = 1; TRUE; ++j) {
			node = egg_asn1x_node (asn, i, j, "type", NULL);
			if (!node) {
				done = j == 1;
				break;
			}

			oid = egg_asn1x_get_oid_as_quark (node);
			g_return_val_if_fail (oid, NULL);

			/* Does it match either the OID or the displayable? */
			if (g_ascii_strcasecmp (g_quark_to_string (oid), match) != 0) {
				name = egg_oid_get_name (oid);
				if (!g_ascii_strcasecmp (name, match) == 0)
					continue;
			}

			node = egg_asn1x_node (asn, i, j, "value", NULL);
			g_return_val_if_fail (node, NULL);

			value = egg_asn1x_get_element_raw (node);
			g_return_val_if_fail (value, NULL);

			result = dn_print_oid_value (oid, egg_oid_get_flags (oid), value);
			egg_bytes_unref (value);
			return result;
		}
	}

	return NULL;
}

gboolean
egg_dn_parse (GNode *asn, EggDnCallback callback, gpointer user_data)
{
	gboolean done = FALSE;
	GNode *node;
	EggBytes *value;
	GQuark oid;
	guint i, j;

	g_return_val_if_fail (asn, FALSE);

	/* Each (possibly multi valued) RDN */
	for (i = 1; !done; ++i) {

		/* Each type=value pair of an RDN */
		for (j = 1; TRUE; ++j) {

			/* Dig out the type */
			node = egg_asn1x_node (asn, i, j, "type", NULL);
			if (!node) {
				done = j == 1;
				break;
			}

			oid = egg_asn1x_get_oid_as_quark (node);
			g_return_val_if_fail (oid, FALSE);

			/* Dig out the value */
			node = egg_asn1x_node (asn, i, j, "value", NULL);
			if (!node) {
				done = j == 1;
				break;
			}

			value = egg_asn1x_get_element_raw (node);

			if (callback)
				(callback) (i, oid, value, user_data);

			egg_bytes_unref (value);
		}
	}

	return i > 1;
}

gchar *
egg_dn_print_value (GQuark oid,
                    EggBytes *value)
{
	g_return_val_if_fail (oid != 0, NULL);
	g_return_val_if_fail (value != NULL, NULL);

	return dn_print_oid_value (oid, egg_oid_get_flags (oid), value);
}

static gboolean
is_ascii_string (const gchar *string)
{
	const gchar *p = string;

	g_return_val_if_fail (string != NULL, FALSE);

	for (p = string; *p != '\0'; p++) {
		if (!g_ascii_isspace (*p) && *p < ' ')
			return FALSE;
	}

	return TRUE;
}

static gboolean
is_printable_string (const gchar *string)
{
	const gchar *p = string;

	g_return_val_if_fail (string != NULL, FALSE);

	for (p = string; *p != '\0'; p++) {
		if (!g_ascii_isalnum (*p) && !strchr (" '()+,-./:=?", *p))
			return FALSE;
	}

	return TRUE;
}

void
egg_dn_add_string_part (GNode *asn,
                        GQuark oid,
                        const gchar *string)
{
	EggBytes *bytes;
	GNode *node;
	GNode *value;
	GNode *val;
	guint flags;

	g_return_if_fail (asn != NULL);
	g_return_if_fail (oid != 0);
	g_return_if_fail (string != NULL);

	flags = egg_oid_get_flags (oid);
	g_return_if_fail (flags & EGG_OID_PRINTABLE);

	/* Add the RelativeDistinguishedName */
	node = egg_asn1x_append (asn);

	/* Add the AttributeTypeAndValue */
	node = egg_asn1x_append (node);

	egg_asn1x_set_oid_as_quark (egg_asn1x_node (node, "type", NULL), oid);

	value = egg_asn1x_create_quark (pkix_asn1_tab, oid);

	if (egg_asn1x_type (value) == EGG_ASN1X_CHOICE) {
		if (is_printable_string (string))
			val = egg_asn1x_node (value, "printableString", NULL);
		else if (is_ascii_string (string))
			val = egg_asn1x_node (value, "ia5String", NULL);
		else
			val = egg_asn1x_node (value, "utf8String", NULL);
		egg_asn1x_set_choice (value, val);
	} else {
		val = value;
	}

	egg_asn1x_set_string_as_utf8 (val, g_strdup (string), g_free);

	bytes = egg_asn1x_encode (value, NULL);
	if (bytes == NULL) {
		g_warning ("couldn't build dn string value: %s", egg_asn1x_message (value));
		return;
	}

	if (!egg_asn1x_set_element_raw (egg_asn1x_node (node, "value", NULL), bytes))
		g_return_if_reached ();

	egg_asn1x_destroy (value);
	egg_bytes_unref (bytes);
}
