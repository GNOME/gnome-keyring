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

#include "egg-asn1.h"
#include "egg-dn.h"
#include "egg-oid.h"

#include <libtasn1.h>

#include <string.h>

static const char HEXC[] = "0123456789ABCDEF";

static gboolean
ascii_length_equals (const gchar *str, gconstpointer data, gsize n_data)
{
	g_assert (str);
	if (!data)
		return FALSE;
	if (strlen (str) != n_data)
		return FALSE;
	return strncmp (str, data, n_data) == 0;
}

static gchar*
dn_print_hex_value (const guchar *data, gsize len)
{
	GString *result = g_string_sized_new (len * 2 + 1);
	gsize i;

	g_string_append_c (result, '#');
	for (i = 0; i < len; ++i) {
		g_string_append_c (result, HEXC[data[i] >> 4 & 0xf]);
		g_string_append_c (result, HEXC[data[i] & 0xf]);
	}

	return g_string_free (result, FALSE);
}

static gchar*
dn_print_oid_value_parsed (GQuark oid, guint flags, const guchar *data, gsize len)
{
	const gchar *asn_name;
	ASN1_TYPE asn1;
	gchar *part;
	gchar *value;
	gsize n_value;

	g_assert (data);
	g_assert (len);

	asn_name = asn1_find_structure_from_oid (egg_asn1_get_pkix_asn1type (),
	                                         g_quark_to_string (oid));
	g_return_val_if_fail (asn_name, NULL);

	part = g_strdup_printf ("PKIX1.%s", asn_name);
	asn1 = egg_asn1_decode (part, data, len);
	g_free (part);

	if (!asn1) {
		g_message ("couldn't decode value for OID: %s", g_quark_to_string (oid));
		return NULL;
	}

	value = (gchar*)egg_asn1_read_value (asn1, "", &n_value, NULL);

	/*
	 * If it's a choice element, then we have to read depending
	 * on what's there.
	 */
	if (value && (flags & EGG_OID_IS_CHOICE)) {
		if (ascii_length_equals ("printableString", value, n_value - 1) ||
			ascii_length_equals ("ia5String", value, n_value - 1 ) ||
			ascii_length_equals ("utf8String", value, n_value - 1) ||
			ascii_length_equals ("teletexString", value, n_value - 1)) {
			part = value;
			value = (gchar*)egg_asn1_read_value (asn1, part, &n_value, NULL);
			g_free (part);
		} else {
			g_free (value);
			return NULL;
		}
	}

	if (!value) {
		g_message ("couldn't read value for OID: %s", g_quark_to_string (oid));
		return NULL;
	}

	/*
	 * Now we make sure it's UTF-8.
	 */
	if (!g_utf8_validate (value, n_value, NULL)) {
		gchar *hex = dn_print_hex_value ((guchar*)value, n_value);
		g_free (value);
		value = hex;
	}

	return value;
}

static gchar*
dn_print_oid_value (GQuark oid, guint flags, const guchar *data, gsize len)
{
	gchar *value;

	g_assert (data);
	g_assert (len);

	if (flags & EGG_OID_PRINTABLE) {
		value = dn_print_oid_value_parsed (oid, flags, data, len);
		if (value != NULL)
			return value;
	}

	return dn_print_hex_value (data, len);
}

static gchar*
dn_parse_rdn (ASN1_TYPE asn, const gchar *part)
{
	const gchar *name;
	guint flags;
	GQuark oid;
	gchar *path;
	guchar *value;
	gsize n_value;
	gchar *display;
	gchar *result;

	g_assert (asn);
	g_assert (part);

	path = g_strdup_printf ("%s.type", part);
	oid = egg_asn1_read_oid (asn, path);
	g_free (path);

	if (!oid)
		return NULL;

	path = g_strdup_printf ("%s.value", part);
	value = egg_asn1_read_value (asn, path, &n_value, NULL);
	g_free (path);

	flags = egg_oid_get_flags (oid);
	name = egg_oid_get_name (oid);

	g_return_val_if_fail (value, NULL);
	display = dn_print_oid_value (oid, flags, value, n_value);

	result = g_strconcat ((flags & EGG_OID_PRINTABLE) ? name : g_quark_to_string (oid),
			      "=", display, NULL);
	g_free (display);

	return result;
}

gchar*
egg_dn_read (ASN1_TYPE asn, const gchar *part)
{
	gboolean done = FALSE;
	GString *result;
	gchar *path;
	gchar *rdn;
	gint i, j;

	g_return_val_if_fail (asn, NULL);
	g_return_val_if_fail (part, NULL);

	result = g_string_sized_new (64);

	/* Each (possibly multi valued) RDN */
	for (i = 1; !done; ++i) {

		/* Each type=value pair of an RDN */
		for (j = 1; TRUE; ++j) {
			path = g_strdup_printf ("%s%s?%u.?%u", part ? part : "",
			                        part ? "." : "", i, j);
			rdn = dn_parse_rdn (asn, path);
			g_free (path);

			if (!rdn) {
				done = j == 1;
				break;
			}

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
egg_dn_read_part (ASN1_TYPE asn, const gchar *part, const gchar *match)
{
	gboolean done = FALSE;
	const gchar *name;
	guchar *value;
	gsize n_value;
	gchar *path;
	GQuark oid;
	gint i, j;

	g_return_val_if_fail (asn, NULL);
	g_return_val_if_fail (part, NULL);
	g_return_val_if_fail (match, NULL);

	/* Each (possibly multi valued) RDN */
	for (i = 1; !done; ++i) {

		/* Each type=value pair of an RDN */
		for (j = 1; TRUE; ++j) {
			path = g_strdup_printf ("%s%s?%u.?%u.type",
			                        part ? part : "",
			                        part ? "." : "", i, j);
			oid = egg_asn1_read_oid (asn, path);
			g_free (path);

			if (!oid) {
				done = j == 1;
				break;
			}

			/* Does it match either the OID or the displayable? */
			if (g_ascii_strcasecmp (g_quark_to_string (oid), match) != 0) {
				name = egg_oid_get_name (oid);
				if (!g_ascii_strcasecmp (name, match) == 0)
					continue;
			}

			path = g_strdup_printf ("%s%s?%u.?%u.value",
			                        part ? part : "",
			                        part ? "." : "", i, j);
			value = egg_asn1_read_value (asn, path, &n_value, NULL);
			g_free (path);

			g_return_val_if_fail (value, NULL);
			return dn_print_oid_value (oid, egg_oid_get_flags (oid), value, n_value);
		}
	}

	return NULL;
}

gboolean
egg_dn_parse (ASN1_TYPE asn, const gchar *part,
              EggDnCallback callback, gpointer user_data)
{
	gboolean done = FALSE;
	gchar *path;
	guchar *value;
	gsize n_value;
	GQuark oid;
	guint i, j;

	g_return_val_if_fail (asn, FALSE);

	/* Each (possibly multi valued) RDN */
	for (i = 1; !done; ++i) {

		/* Each type=value pair of an RDN */
		for (j = 1; TRUE; ++j) {

			/* Dig out the type */
			path = g_strdup_printf ("%s%s?%u.?%u.type",
			                        part ? part : "",
			                        part ? "." : "", i, j);
			oid = egg_asn1_read_oid (asn, path);
			g_free (path);

			if (!oid) {
				done = j == 1;
				break;
			}

			/* Print the value as nicely as we can */
			path = g_strdup_printf ("%s%s?%u.?%u.value",
			                        part ? part : "",
			                        part ? "." : "", i, j);
			value = egg_asn1_read_value (asn, path, &n_value, NULL);
			g_free (path);

			if (!value) {
				done = j == 1;
				break;
			}

			if (callback)
				(callback) (i, oid, value, n_value, user_data);

			g_free (value);
		}
	}

	return i > 1;
}

gchar*
egg_dn_print_value (GQuark oid, const guchar *value, gsize n_value)
{
	g_return_val_if_fail (oid, NULL);
	g_return_val_if_fail (value || !n_value, NULL);

	return dn_print_oid_value (oid, egg_oid_get_flags (oid), value, n_value);
}
