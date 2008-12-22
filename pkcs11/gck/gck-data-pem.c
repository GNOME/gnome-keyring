/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-pem.c - PEM base64 encoding helper routines

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

#include "gck-data-pem.h"

#include "common/gkr-secure-memory.h"

#include <glib.h>

#include <ctype.h>
#include <string.h>

/* 
 * PEM looks like:
 * 
 * 	-----BEGIN RSA PRIVATE KEY-----
 * 	Proc-Type: 4,ENCRYPTED
 * 	DEK-Info: DES-EDE3-CBC,704CFFD62FBA03E9
 * 
 * 	4AV/g0BiTeb07hzo4/Ct47HGhHEshMhBPGJ843QzuAinpZBbg3OxwPsQsLgoPhJL
 * 	Bg6Oxyz9M4UN1Xlx6Lyo2lRT908mBP6dl/OItLsVArqAzM+e29KHQVNjV1h7xN9F
 *	u84tOgZftKun+ZkQUOoRvMLLu4yV4CUraks9tgyXquugGba/tbeyj2MYsC8wwSJX
 * 	....
 * 	-----END RSA PRIVATE KEY-----
 */
 
#define PEM_SUFF          "-----"
#define PEM_SUFF_L        5
#define PEM_PREF_BEGIN    "-----BEGIN "
#define PEM_PREF_BEGIN_L  11
#define PEM_PREF_END      "-----END "
#define PEM_PREF_END_L    9

static void
parse_header_lines (const gchar *hbeg, const gchar *hend, GHashTable **result)
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
        		*result = gck_data_pem_headers_new ();
        	g_hash_table_replace (*result, name, value);
	}

	g_strfreev (lines);
} 

static const gchar*
pem_find_begin (const gchar *data, gsize n_data, GQuark *type)
{
	const gchar *pref, *suff;
	gchar *stype;
	
	/* Look for a prefix */
	pref = g_strstr_len ((gchar*)data, n_data, PEM_PREF_BEGIN);
	if (!pref)
		return NULL;
		
	n_data -= (pref - data) + PEM_PREF_BEGIN_L;
	data = pref + PEM_PREF_BEGIN_L;
		
	/* Look for the end of that begin */
	suff = g_strstr_len ((gchar*)data, n_data, PEM_SUFF);
	if (!suff)
		return NULL;
		
	/* Make sure on the same line */
	if (memchr (pref, '\n', suff - pref))
		return NULL;
		
	if (type) {
		*type = 0;
		pref += PEM_PREF_BEGIN_L;
		g_assert (suff > pref);
		stype = g_alloca (suff - pref + 1);
		memcpy (stype, pref, suff - pref);
		stype[suff - pref] = 0;
		*type = g_quark_from_string (stype);
	} 
	
	/* The byte after this ---BEGIN--- */
	return suff + PEM_SUFF_L;
}

static const gchar*
pem_find_end (const gchar *data, gsize n_data, GQuark type)
{
	const gchar *stype;
	const gchar *pref;
	gsize n_type;
	
	/* Look for a prefix */
	pref = g_strstr_len (data, n_data, PEM_PREF_END);
	if (!pref)
		return NULL;
		
	n_data -= (pref - data) + PEM_PREF_END_L;
	data = pref + PEM_PREF_END_L;
	
	/* Next comes the type string */
	stype = g_quark_to_string (type);
	n_type = strlen (stype);
	if (strncmp ((gchar*)data, stype, n_type) != 0)
		return NULL; 
		
	n_data -= n_type;
	data += n_type;
	
	/* Next comes the suffix */
	if (strncmp ((gchar*)data, PEM_SUFF, PEM_SUFF_L) != 0)
		return NULL;
		
	/* The beginning of this ---END--- */
	return pref;
}

static gboolean
pem_parse_block (const gchar *data, gsize n_data, guchar **decoded, gsize *n_decoded,
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
	if (gkr_secure_check (data))
		*decoded = gkr_secure_alloc (*n_decoded);
	else
		*decoded = g_malloc (*n_decoded);
	g_return_val_if_fail (*decoded, FALSE);
	
	*n_decoded = g_base64_decode_step (data, n_data, *decoded, &state, &save);
	if (!*n_decoded) {
		gkr_secure_free (*decoded);
		return FALSE;
	}
	
	if (headers && hbeg && hend) 
		parse_header_lines (hbeg, hend, headers);
	
	return TRUE;
}

GHashTable*
gck_data_pem_headers_new (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

guint
gck_data_pem_parse  (const guchar *data, gsize n_data, 
                     GckDataPemCallback callback, gpointer user_data)
{
	const gchar *beg, *end;
	guint nfound = 0;
	guchar *decoded = NULL;
	gsize n_decoded = 0;
	GHashTable *headers = NULL;
	GQuark type;
	
	g_return_val_if_fail (data, 0);
	g_return_val_if_fail (n_data, 0);
	g_return_val_if_fail (callback, 0);

	while (n_data > 0) {
		
		/* This returns the first character after the PEM BEGIN header */
		beg = pem_find_begin ((const gchar*)data, n_data, &type);
		if (!beg)
			break;
			
		g_assert (type);
		
		/* This returns the character position before the PEM END header */
		end = pem_find_end ((const gchar*)beg, n_data - ((const guchar*)beg - data), type);
		if (!end)
			break;

		if (beg != end) {
			if (pem_parse_block (beg, end - beg, &decoded, &n_decoded, &headers)) {
				(callback) (type, decoded, n_decoded, headers, user_data);
				++nfound;
				gkr_secure_free (decoded);
				if (headers)
					g_hash_table_remove_all (headers);
			}
		}
                     
		/* Try for another block */
		end += PEM_SUFF_L;
		n_data -= (const guchar*)end - data; 
		data = (const guchar*)end;
	}
	
	if (headers)
		g_hash_table_destroy (headers);

	return nfound;
}

#ifdef UNTESTED_CODE

static void 
append_each_header (gpointer key, gpointer value, gpointer user_data)
{
	GString *string = (GString*)user_data;
	
	g_string_append (string, (gchar*)key);
	g_string_append (string, ": ");
	g_string_append (string, (gchar*)value);
	g_string_append_c (string, '\n');
}

guchar*
gck_data_pem_write (const guchar *data, gsize n_data, GQuark type, 
                    GHashTable *headers, gsize *n_result)
{
	GString *string;
	gint state, save;
	gsize length, n_prefix;
	
	g_return_val_if_fail (data || !n_data, NULL);
	g_return_val_if_fail (type, NULL);
	g_return_val_if_fail (n_result, NULL);

	string = g_string_sized_new (4096);
	
	/* The prefix */
	g_string_append_len (string, PEM_PREF_BEGIN, PEM_PREF_BEGIN_L);
	g_string_append (string, g_quark_to_string (type));
	g_string_append_len (string, PEM_SUFF, PEM_SUFF_L);
	g_string_append_c (string, '\n');
	
	/* The headers */
	if (headers && g_hash_table_size (headers) > 0) {
		g_hash_table_foreach (headers, append_each_header, string);
		g_string_append_c (string, '\n');
	}

	/* Resize string to fit the base64 data. Algorithm from Glib reference */
	length = n_data * 4 / 3 + n_data * 4 / (3 * 72) + 7;
	n_prefix = string->len;
	g_string_set_size (string, n_prefix + length);
	
	/* The actual base64 data */
	state = save = 0;
	length = g_base64_encode_step (data, n_data, TRUE, 
	                               string->str + string->len, &state, &save);
	g_string_set_size (string, n_prefix + length);
	
	/* The suffix */
	g_string_append_c (string, '\n');
	g_string_append_len (string, PEM_PREF_END, PEM_PREF_END_L);
	g_string_append (string, g_quark_to_string (type));
	g_string_append_len (string, PEM_SUFF, PEM_SUFF_L);
	g_string_append_c (string, '\n');
	
	*n_result = string->len;
	return (guchar*)g_string_free (string, FALSE);
}

#endif /* UNTESTED_CODE */
