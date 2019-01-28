/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-openssl.c - OpenSSL compatibility functionality

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "egg-hex.h"
#include "egg-armor.h"
#include "egg-secure-memory.h"

#include <gcrypt.h>

#include <glib.h>

#include <ctype.h>
#include <string.h>

/*
 * Armor looks like:
 *
 * 	-----BEGIN RSA PRIVATE KEY-----
 * 	Proc-Type: 4,ENCRYPTED
 * 	DEK-Info: DES-EDE3-CBC,704CFFD62FBA03E9
 *
 * 	4AV/g0BiTeb07hzo4/Ct47HGhHEshMhBPGJ843QzuAinpZBbg3OxwPsQsLgoPhJL
 * 	Bg6Oxyz9M4UN1Xlx6Lyo2lRT908mBP6dl/OItLsVArqAzM+e29KHQVNjV1h7xN9F
 *	u84tOgZftKun+ZkQUOoRvMLLu4yV4CUraks9tgyXquugGba/tbeyj2MYsC8wwSJX
 *	................................................................
 * 	=on29
 * 	-----END RSA PRIVATE KEY-----
 *
 * The last line before END is an option OpenPGP armor checksum
 */

EGG_SECURE_DECLARE (armor);

#define ARMOR_SUFF          "-----"
#define ARMOR_SUFF_L        5
#define ARMOR_PREF_BEGIN    "-----BEGIN "
#define ARMOR_PREF_BEGIN_L  11
#define ARMOR_PREF_END      "-----END "
#define ARMOR_PREF_END_L    9

static const gchar * const ORDERED_HEADERS[] = { "Proc-Type", "DEK-Info", NULL };

static void
parse_header_lines (const gchar *hbeg,
                    const gchar *hend,
                    GHashTable **result)
{
	gchar **lines, **l;
	gchar *line, *name, *value;
	gchar *copy;

	copy = g_strndup (hbeg, hend - hbeg);
	lines = g_strsplit (copy, "\n", 0);
	g_free (copy);

	for (l = lines; l && *l; ++l) {
		line = *l;
		g_strstrip (line);

		/* Look for the break between name: value */
		value = strchr (line, ':');
		if (value == NULL)
			continue;

		*value = 0;
		value = g_strdup (value + 1);
		g_strstrip (value);

		name = g_strdup (line);
		g_strstrip (name);

		if (!*result)
			*result = egg_armor_headers_new ();
		g_hash_table_replace (*result, name, value);
	}

	g_strfreev (lines);
}

static const gchar*
armor_find_begin (const gchar *data,
                  gsize n_data,
                  GQuark *type,
                  const gchar **outer)
{
	const gchar *pref, *suff;
	const gchar *at;
	gchar *stype;
	gsize len;

	/* Look for a prefix */
	pref = g_strstr_len ((gchar*)data, n_data, ARMOR_PREF_BEGIN);
	if (!pref)
		return NULL;

	len = n_data - ((pref - data) + ARMOR_PREF_BEGIN_L);
	at = pref + ARMOR_PREF_BEGIN_L;

	/* Look for the end of that begin */
	suff = g_strstr_len ((gchar *)at, len, ARMOR_SUFF);
	if (!suff)
		return NULL;

	/* Make sure on the same line */
	if (memchr (pref, '\n', suff - pref))
		return NULL;

	if (outer)
		*outer = pref;

	if (type) {
		*type = 0;
		pref += ARMOR_PREF_BEGIN_L;
		g_assert (suff > pref);
		stype = g_alloca (suff - pref + 1);
		memcpy (stype, pref, suff - pref);
		stype[suff - pref] = 0;
		*type = g_quark_from_string (stype);
	}

	/* The byte after this ---BEGIN--- */
	return suff + ARMOR_SUFF_L;
}

static const gchar*
armor_find_end (const gchar *data,
                gsize n_data,
                GQuark type,
                const gchar **outer)
{
	const gchar *stype;
	const gchar *pref;
	const gchar *line;
	const gchar *at;
	gsize len;
	gsize n_type;

	/* Look for a prefix */
	pref = g_strstr_len (data, n_data, ARMOR_PREF_END);
	if (!pref)
		return NULL;

	len = n_data - ((pref - data) + ARMOR_PREF_END_L);
	at = pref + ARMOR_PREF_END_L;

	/* Next comes the type string */
	stype = g_quark_to_string (type);
	n_type = strlen (stype);
	if (n_type > len || strncmp ((gchar*)at, stype, n_type) != 0)
		return NULL;

	len -= n_type;
	at += n_type;

	/* Next comes the suffix */
	if (ARMOR_SUFF_L > len || strncmp ((gchar *)at, ARMOR_SUFF, ARMOR_SUFF_L) != 0)
		return NULL;

	/*
	 * Check if there's a OpenPGP style armor checksum line. OpenPGP
	 * does not insist that we validate this line, and is more useful
	 * for PGP messages, rather than the keys we usually see.
	 */
	line = g_strrstr_len (data, (pref - 1) - data, "\n");
	if (line && line[1] == '=')
		pref = line;

	if (outer != NULL) {
		at += ARMOR_SUFF_L;
		if (isspace (at[0]))
			at++;
		*outer = at;
	}

	/* The end of the data */
	return pref;
}

static gboolean
armor_parse_block (const gchar *data,
                   gsize n_data,
                   guchar **decoded,
                   gsize *n_decoded,
                   GHashTable **headers)
{
	const gchar *x, *hbeg, *hend;
	const gchar *p, *end;
	gint state = 0;
	guint save = 0;

	g_assert (data);
	g_assert (n_data);

	g_assert (decoded);
	g_assert (n_decoded);

	p = data;
	end = p + n_data;

	hbeg = hend = NULL;

	/* Try and find a pair of blank lines with only white space between */
	while (hend == NULL) {
		x = memchr (p, '\n', end - p);
		if (!x)
			break;
		++x;
		while (isspace (*x)) {
			/* Found a second line, with only spaces between */
			if (*x == '\n') {
				hbeg = data;
				hend = x;
				break;
			/* Found a space between two lines */
			} else {
				++x;
			}
		}

		/* Try next line */
		p = x;
	}

	/* Headers found? */
	if (hbeg && hend) {
		data = hend;
		n_data = end - data;
	}

	*n_decoded = (n_data * 3) / 4 + 1;
	if (egg_secure_check (data))
		*decoded = egg_secure_alloc (*n_decoded);
	else
		*decoded = g_malloc0 (*n_decoded);
	g_return_val_if_fail (*decoded, FALSE);

	*n_decoded = g_base64_decode_step (data, n_data, *decoded, &state, &save);
	if (!*n_decoded) {
		egg_secure_free (*decoded);
		return FALSE;
	}

	if (headers && hbeg && hend)
		parse_header_lines (hbeg, hend, headers);

	return TRUE;
}

GHashTable*
egg_armor_headers_new (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

guint
egg_armor_parse (GBytes *data,
                 EggArmorCallback callback,
                 gpointer user_data)
{
	const gchar *beg, *end, *at;
	const gchar *outer_beg, *outer_end;
	guint nfound = 0;
	guchar *decoded = NULL;
	gsize n_decoded = 0;
	GHashTable *headers = NULL;
	GBytes *dec;
	GBytes *outer;
	GQuark type;
	gsize n_at;

	g_return_val_if_fail (data != NULL, 0);
	at = g_bytes_get_data (data, &n_at);

	while (n_at > 0) {

		/* This returns the first character after the PEM BEGIN header */
		beg = armor_find_begin (at, n_at, &type, &outer_beg);
		if (beg == NULL)
			break;

		g_assert (type);

		/* This returns the character position before the PEM END header */
		end = armor_find_end (beg, n_at - (beg - at), type, &outer_end);
		if (end == NULL)
			break;

		if (beg != end) {
			if (armor_parse_block (beg, end - beg, &decoded, &n_decoded, &headers)) {
				g_assert (outer_end > outer_beg);
				dec = g_bytes_new_with_free_func (decoded, n_decoded,
				                                    egg_secure_free, decoded);
				if (callback != NULL) {
					outer = g_bytes_new_with_free_func (outer_beg, outer_end - outer_beg,
					                                    (GDestroyNotify)g_bytes_unref,
					                                    g_bytes_ref (data));
					(callback) (type, dec, outer, headers, user_data);
					g_bytes_unref (outer);
				}
				g_bytes_unref (dec);
				++nfound;
				if (headers)
					g_hash_table_remove_all (headers);
			}
		}

		/* Try for another block */
		end += ARMOR_SUFF_L;
		n_at -= (const gchar*)end - (const gchar*)at;
		at = end;
	}

	if (headers)
		g_hash_table_destroy (headers);

	return nfound;
}

static void
append_each_header (gconstpointer key, gconstpointer value, gpointer user_data)
{
	GString *string = (GString*)user_data;

	if (g_strv_contains (ORDERED_HEADERS, (const gchar *) key))
		return;

	g_string_append (string, (const gchar *)key);
	g_string_append (string, ": ");
	g_string_append (string, (const gchar *)value);
	g_string_append_c (string, '\n');
}

guchar*
egg_armor_write (const guchar *data,
                 gsize n_data,
                 GQuark type,
                 GHashTable *headers,
                 gsize *n_result)
{
	GString *string;
	gint state, save;
	gsize i, length;
	gsize n_prefix, estimate;
	gchar *value;

	g_return_val_if_fail (data || !n_data, NULL);
	g_return_val_if_fail (type, NULL);
	g_return_val_if_fail (n_result, NULL);

	string = g_string_sized_new (4096);

	/* The prefix */
	g_string_append_len (string, ARMOR_PREF_BEGIN, ARMOR_PREF_BEGIN_L);
	g_string_append (string, g_quark_to_string (type));
	g_string_append_len (string, ARMOR_SUFF, ARMOR_SUFF_L);
	g_string_append_c (string, '\n');

	/* The headers. Some must come in a specific order. */
	for (i = 0; ORDERED_HEADERS[i] != NULL; i++) {
		value = g_hash_table_lookup (headers, ORDERED_HEADERS[i]);
		if (value != NULL)
			g_string_append_printf (string,
			                        "%s: %s\n",
			                        ORDERED_HEADERS[i],
			                        value);
	}

	/* And the rest we output in any arbitrary order. */
	if (headers && g_hash_table_size (headers) > 0) {
		g_hash_table_foreach (headers, (GHFunc) append_each_header, string);
		g_string_append_c (string, '\n');
	}

	/* Resize string to fit the base64 data. Algorithm from Glib reference */
	estimate = n_data * 4 / 3 + n_data * 4 / (3 * 65) + 7;
	n_prefix = string->len;
	g_string_set_size (string, n_prefix + estimate);

	/* The actual base64 data, without line breaks */
	state = save = 0;
	length = g_base64_encode_step (data, n_data, FALSE,
	                               string->str + n_prefix, &state, &save);
	length += g_base64_encode_close (TRUE, string->str + n_prefix + length,
	                                 &state, &save);

	g_assert (length <= estimate);
	g_string_set_size (string, n_prefix + length);

	/*
	 * OpenSSL is absolutely certain that it wants its PEM base64
	 * lines to be 64 characters in length. So go through and break
	 * those lines up.
	 */

	for (i = 64; i < length; i += 64) {
		g_string_insert_c (string, n_prefix + i, '\n');
		++length;
		++i;
	}

	/* The suffix */
	g_string_append_len (string, ARMOR_PREF_END, ARMOR_PREF_END_L);
	g_string_append (string, g_quark_to_string (type));
	g_string_append_len (string, ARMOR_SUFF, ARMOR_SUFF_L);
	g_string_append_c (string, '\n');

	*n_result = string->len;
	return (guchar*)g_string_free (string, FALSE);
}
