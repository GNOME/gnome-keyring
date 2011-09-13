/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
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
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gcr-openssh.h"
#include "gcr-internal.h"
#include "gcr-types.h"

#include "egg/egg-buffer.h"
#include "egg/egg-decimal.h"

#include "pkcs11/pkcs11.h"

#include <string.h>

typedef struct {
	GcrOpensshPubCallback callback;
	gpointer user_data;
} OpensshPubClosure;

static void
skip_spaces (const gchar ** line,
             gsize *n_line)
{
	while (*n_line > 0 && (*line)[0] == ' ') {
		(*line)++;
		(*n_line)--;
	}
}

static gboolean
next_word (const gchar **line,
           gsize *n_line,
           const gchar **word,
           gsize *n_word)
{
	const gchar *beg;
	const gchar *end;
	const gchar *at;
	gboolean quotes;

	skip_spaces (line, n_line);

	if (!*n_line) {
		*word = NULL;
		*n_word = 0;
		return FALSE;
	}

	beg = at = *line;
	end = beg + *n_line;
	quotes = FALSE;

	do {
		switch (*at) {
		case '"':
			quotes = !quotes;
			at++;
			break;
		case ' ':
			if (!quotes)
				end = at;
			else
				at++;
			break;
		default:
			at++;
			break;
		}
	} while (at < end);

	*word = beg;
	*n_word = end - beg;
	(*line) += *n_word;
	(*n_line) -= *n_word;
	return TRUE;
}

static gboolean
match_word (const gchar *word,
            gsize n_word,
            const gchar *matches)
{
	gsize len = strlen (matches);
	if (len != n_word)
		return FALSE;
	return memcmp (word, matches, n_word) == 0;
}

static gulong
keytype_to_algo (const gchar *algo,
                 gsize length)
{
	if (!algo)
		return G_MAXULONG;
	else if (match_word (algo, length, "ssh-rsa"))
		return CKK_RSA;
	else if (match_word (algo, length, "ssh-dss"))
		return CKK_DSA;
	return G_MAXULONG;
}

static gboolean
read_decimal_mpi (const gchar *decimal,
                  gsize n_decimal,
                  GckAttributes *attrs,
                  gulong attribute_type)
{
	gpointer data;
	gsize n_data;

	data = egg_decimal_decode (decimal, n_decimal, &n_data);
	if (data == NULL)
		return FALSE;

	gck_attributes_add_data (attrs, attribute_type, data, n_data);
	return TRUE;
}

static gint
atoin (const char *p, gint digits)
{
	gint ret = 0, base = 1;
	while(--digits >= 0) {
		if (p[digits] < '0' || p[digits] > '9')
			return -1;
		ret += (p[digits] - '0') * base;
		base *= 10;
	}
	return ret;
}

static GcrDataError
parse_v1_public_line (const gchar *line,
                      gsize length,
                      GcrOpensshPubCallback callback,
                      gpointer user_data)
{
	const gchar *word_bits, *word_exponent, *word_modulus, *word_options, *outer;
	gsize len_bits, len_exponent, len_modulus, len_options, n_outer;
	GckAttributes *attrs;
	gchar *label, *options;
	gint bits;

	g_assert (line);

	outer = line;
	n_outer = length;
	options = NULL;
	label = NULL;

	/* Eat space at the front */
	skip_spaces (&line, &length);

	/* Blank line or comment */
	if (length == 0 || line[0] == '#')
		return GCR_ERROR_UNRECOGNIZED;

	/*
	 * If the line starts with a digit, then no options:
	 *
	 * 2048 35 25213680043....93533757 Label
	 *
	 * If the line doesn't start with a digit, then have options:
	 *
	 * option,option 2048 35 25213680043....93533757 Label
	 */
	if (g_ascii_isdigit (line[0])) {
		word_options = NULL;
		len_options = 0;
	} else {
		if (!next_word (&line, &length, &word_options, &len_options))
			return GCR_ERROR_UNRECOGNIZED;
	}

	if (!next_word (&line, &length, &word_bits, &len_bits) ||
	    !next_word (&line, &length, &word_exponent, &len_exponent) ||
	    !next_word (&line, &length, &word_modulus, &len_modulus))
		return GCR_ERROR_UNRECOGNIZED;

	bits = atoin (word_bits, len_bits);
	if (bits <= 0)
		return GCR_ERROR_UNRECOGNIZED;

	attrs = gck_attributes_new ();

	if (!read_decimal_mpi (word_exponent, len_exponent, attrs, CKA_PUBLIC_EXPONENT) ||
	    !read_decimal_mpi (word_modulus, len_modulus, attrs, CKA_MODULUS)) {
		gck_attributes_unref (attrs);
		return GCR_ERROR_UNRECOGNIZED;
	}

	gck_attributes_add_ulong (attrs, CKA_KEY_TYPE, CKK_RSA);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);

	skip_spaces (&line, &length);
	if (length > 0) {
		label = g_strndup (line, length);
		g_strstrip (label);
		gck_attributes_add_string (attrs, CKA_LABEL, label);
	}

	if (word_options)
		options = g_strndup (word_options, len_options);

	if (callback != NULL)
		(callback) (attrs, label, options, outer, n_outer, user_data);

	gck_attributes_unref (attrs);
	g_free (options);
	g_free (label);
	return GCR_SUCCESS;
}

static gboolean
read_buffer_mpi (EggBuffer *buffer,
                 gsize *offset,
                 GckAttributes *attrs,
                 gulong attribute_type)
{
	const guchar *data;
	gsize len;

	if (!egg_buffer_get_byte_array (buffer, *offset, offset, &data, &len))
		return FALSE;

	gck_attributes_add_data (attrs, attribute_type, data, len);
	return TRUE;
}

static GckAttributes *
read_v2_public_dsa (EggBuffer *buffer,
                    gsize *offset)
{
	GckAttributes *attrs;

	attrs = gck_attributes_new ();

	if (!read_buffer_mpi (buffer, offset, attrs, CKA_PRIME) ||
	    !read_buffer_mpi (buffer, offset, attrs, CKA_SUBPRIME) ||
	    !read_buffer_mpi (buffer, offset, attrs, CKA_BASE) ||
	    !read_buffer_mpi (buffer, offset, attrs, CKA_VALUE)) {
		gck_attributes_unref (attrs);
		return NULL;
	}

	gck_attributes_add_ulong (attrs, CKA_KEY_TYPE, CKK_DSA);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);

	return attrs;
}

static GckAttributes *
read_v2_public_rsa (EggBuffer *buffer,
                    gsize *offset)
{
	GckAttributes *attrs;

	attrs = gck_attributes_new ();

	if (!read_buffer_mpi (buffer, offset, attrs, CKA_PUBLIC_EXPONENT) ||
	    !read_buffer_mpi (buffer, offset, attrs, CKA_MODULUS)) {
		gck_attributes_unref (attrs);
		return NULL;
	}

	gck_attributes_add_ulong (attrs, CKA_KEY_TYPE, CKK_RSA);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);

	return attrs;
}

static GckAttributes *
read_v2_public_key (gulong algo,
                    gconstpointer data,
                    gsize n_data)
{
	GckAttributes *attrs;
	EggBuffer buffer;
	gsize offset;
	gchar *stype;
	int alg;

	egg_buffer_init_static (&buffer, data, n_data);
	offset = 0;

	/* The string algorithm */
	if (!egg_buffer_get_string (&buffer, offset, &offset,
	                            &stype, (EggBufferAllocator)g_realloc))
		return NULL;

	alg = keytype_to_algo (stype, stype ? strlen (stype) : 0);
	g_free (stype);

	if (alg != algo) {
		g_message ("invalid or mis-matched algorithm in ssh public key: %s", stype);
		egg_buffer_uninit (&buffer);
		return NULL;
	}

	switch (algo) {
	case CKK_RSA:
		attrs = read_v2_public_rsa (&buffer, &offset);
		break;
	case CKK_DSA:
		attrs = read_v2_public_dsa (&buffer, &offset);
		break;
	default:
		g_assert_not_reached ();
		break;
	}

	egg_buffer_uninit (&buffer);
	return attrs;
}

static GckAttributes *
decode_v2_public_key (gulong algo,
                      const gchar *data,
                      gsize n_data)
{
	GckAttributes *attrs;
	gpointer decoded;
	gsize n_decoded;
	guint save;
	gint state;

	/* Decode the base64 key */
	save = state = 0;
	decoded = g_malloc (n_data * 3 / 4);
	n_decoded = g_base64_decode_step ((gchar*)data, n_data, decoded, &state, &save);

	if (!n_decoded) {
		g_free (decoded);
		return NULL;
	}

	/* Parse the actual key */
	attrs = read_v2_public_key (algo, decoded, n_decoded);

	g_free (decoded);

	return attrs;
}

static GcrDataError
parse_v2_public_line (const gchar *line,
                      gsize length,
                      GcrOpensshPubCallback callback,
                      gpointer user_data)
{
	const gchar *word_options, *word_algo, *word_key;
	gsize len_options, len_algo, len_key;
	GckAttributes *attrs;
	gchar *options;
	gchar *label = NULL;
	const gchar *outer = line;
	gsize n_outer = length;
	gulong algo;

	g_assert (line);

	/* Eat space at the front */
	skip_spaces (&line, &length);

	/* Blank line or comment */
	if (length == 0 || line[0] == '#')
		return GCR_ERROR_UNRECOGNIZED;

	if (!next_word (&line, &length, &word_algo, &len_algo))
		return GCR_ERROR_UNRECOGNIZED;

	/*
	 * If the first word is not the algorithm, then we have options:
	 *
	 * option,option ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAI...EAz8Ji= Label here
	 *
	 * If the first word is the algorithm, then we have no options:
	 *
	 * ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAI...EAz8Ji= Label here
	 */
	algo = keytype_to_algo (word_algo, len_algo);
	if (algo == G_MAXULONG) {
		word_options = word_algo;
		len_options = len_algo;
		if (!next_word (&line, &length, &word_algo, &len_algo))
			return GCR_ERROR_UNRECOGNIZED;
		algo = keytype_to_algo (word_algo, len_algo);
		if (algo == G_MAXULONG)
			return GCR_ERROR_UNRECOGNIZED;
	} else {
		word_options = NULL;
		len_options = 0;
	}

	/* Must have at least two words */
	if (!next_word (&line, &length, &word_key, &len_key))
		return GCR_ERROR_FAILURE;

	attrs = decode_v2_public_key (algo, word_key, len_key);
	if (attrs == NULL)
		return GCR_ERROR_FAILURE;

	if (word_options)
		options = g_strndup (word_options, len_options);
	else
		options = NULL;

	/* The remainder of the line is the label */
	skip_spaces (&line, &length);
	if (length > 0) {
		label = g_strndup (line, length);
		g_strstrip (label);
		gck_attributes_add_string (attrs, CKA_LABEL, label);
	}

	if (callback != NULL)
		(callback) (attrs, label, options, outer, n_outer, user_data);

	gck_attributes_unref (attrs);
	g_free (options);
	g_free (label);
	return GCR_SUCCESS;
}

guint
_gcr_openssh_pub_parse (gconstpointer data,
                        gsize n_data,
                        GcrOpensshPubCallback callback,
                        gpointer user_data)
{
	const gchar *line;
	const gchar *end;
	gsize length;
	gboolean last;
	GcrDataError res;
	guint num_parsed;

	g_return_val_if_fail (data, FALSE);

	line = data;
	length = n_data;
	last = FALSE;
	num_parsed = 0;

	for (;;) {
		end  = memchr (line, '\n', length);
		if (end == NULL) {
			end = line + length;
			last = TRUE;
		}

		if (line != end) {
			res = parse_v2_public_line (line, end - line, callback, user_data);
			if (res == GCR_ERROR_UNRECOGNIZED)
				res = parse_v1_public_line (line, end - line, callback, user_data);
			if (res == GCR_SUCCESS)
				num_parsed++;
		}

		if (last)
			break;

		end++;
		length -= (end - line);
		line = end;
	}

	return num_parsed;
}
