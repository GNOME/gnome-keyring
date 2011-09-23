/*
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

#include "gcr-gnupg-records.h"
#include "gcr-record.h"
#include "gcr-memory-icon.h"

#include "gck/gck.h"

#include <glib/gi18n-lib.h>

/* Copied from GPGME */
gboolean
_gcr_gnupg_records_parse_user_id (const gchar *user_id,
                                  gchar **rname,
                                  gchar **remail,
                                  gchar **rcomment)
{
	gchar *src, *tail, *x;
	int in_name = 0;
	int in_email = 0;
	int in_comment = 0;
	gboolean anything;
	const gchar *name = NULL;
	const gchar *email = NULL;
	const gchar *comment = NULL;

	x = tail = src = g_strdup (user_id);

	while (*src) {
		if (in_email) {
			/* Not legal but anyway.  */
			if (*src == '<')
				in_email++;
			else if (*src == '>') {
				if (!--in_email && !email) {
					email = tail;
					*src = 0;
					tail = src + 1;
				}
			}
		} else if (in_comment) {
			if (*src == '(')
				in_comment++;
			else if (*src == ')') {
				if (!--in_comment && !comment) {
					comment = tail;
					*src = 0;
					tail = src + 1;
				}
			}
		} else if (*src == '<') {
			if (in_name) {
				if (!name) {
					name = tail;
					*src = 0;
					tail = src + 1;
				}
				in_name = 0;
			} else
				tail = src + 1;

			in_email = 1;
		} else if (*src == '(') {
			if (in_name) {
				if (!name) {
					name = tail;
					*src = 0;
					tail = src + 1;
				}
				in_name = 0;
			}
			in_comment = 1;
		} else if (!in_name && *src != ' ' && *src != '\t') {
			in_name = 1;
		}
		src++;
	}

	if (in_name) {
		if (!name) {
			name = tail;
			*src = 0;
			tail = src + 1;
		}
	}

	anything = FALSE;

	if (rname) {
		*rname = g_strdup (name);
		if (name) {
			g_strstrip (*rname);
			anything = TRUE;
		}
	}

	if (remail) {
		*remail = g_strdup (email);
		if (email) {
			g_strstrip (*remail);
			anything = TRUE;
		}
	}

	if (rcomment) {
		*rcomment = g_strdup (comment);
		if (comment) {
			g_strstrip (*rcomment);
			anything = TRUE;
		}
	}

	g_free (x);
	return anything;
}

const gchar *
_gcr_gnupg_records_get_keyid (GPtrArray *records)
{
	GcrRecord *record;

	record = _gcr_records_find (records, GCR_RECORD_SCHEMA_PUB);
	if (record != NULL)
		return _gcr_record_get_raw (record, GCR_RECORD_KEY_KEYID);
	record = _gcr_records_find (records, GCR_RECORD_SCHEMA_SEC);
	if (record != NULL)
		return _gcr_record_get_raw (record, GCR_RECORD_KEY_KEYID);
	return NULL;
}

const gchar *
_gcr_gnupg_records_get_short_keyid (GPtrArray *records)
{
	const gchar *keyid;
	gsize length;

	keyid = _gcr_gnupg_records_get_keyid (records);
	if (keyid == NULL)
		return NULL;

	length = strlen (keyid);
	if (length > 8)
		keyid += (length - 8);

	return keyid;
}

gchar *
_gcr_gnupg_records_get_user_id (GPtrArray *records)
{
	GcrRecord *record;

	record = _gcr_records_find (records, GCR_RECORD_SCHEMA_UID);
	if (record != NULL)
		return _gcr_record_get_string (record, GCR_RECORD_UID_USERID);
	return NULL;
}

const gchar *
_gcr_gnupg_records_get_fingerprint (GPtrArray *records)
{
	GcrRecord *record;

	record = _gcr_records_find (records, GCR_RECORD_SCHEMA_FPR);
	if (record != NULL)
		return _gcr_record_get_raw (record, GCR_RECORD_FPR_FINGERPRINT);
	return NULL;
}

#define TYPE_IMAGE 0x01
#define IMAGE_HEADER_LEN 0x10
#define IMAGE_JPEG_SIG "\x10\x00\x01\x01"
#define IMAGE_JPEG_SIG_LEN 4

static void
add_emblem_to_icon (GIcon **icon,
                    const gchar *emblem_name)
{
	GIcon *emblem_icon;
	GIcon *result;
	GEmblem *emblem;

	emblem_icon = g_themed_icon_new (emblem_name);
	emblem = g_emblem_new_with_origin (emblem_icon, G_EMBLEM_ORIGIN_LIVEMETADATA);
	result = g_emblemed_icon_new (*icon, emblem);
	g_object_unref (*icon);
	*icon = result;
	g_object_unref (emblem);
	g_object_unref (emblem_icon);
}

GIcon *
_gcr_gnupg_records_get_icon (GPtrArray *records)
{
	GcrRecord *record;
	gchar validity;
	guchar *data;
	gsize n_data;
	guint type;
	GIcon *icon;
	guint i;

	for (i = 0; i < records->len; i++) {
		record = records->pdata[i];
		if (GCR_RECORD_SCHEMA_XA1 != _gcr_record_get_schema (record))
			continue;
		if (!_gcr_record_get_uint (record, GCR_RECORD_XA1_TYPE, &type))
			continue;
		if (type != TYPE_IMAGE)
			continue;

		data = _gcr_record_get_base64 (record, GCR_RECORD_XA1_DATA, &n_data);
		g_return_val_if_fail (data != NULL, NULL);

		/* Header is 16 bytes long */
		if (n_data <= IMAGE_HEADER_LEN) {
			g_free (data);
			continue;
		}

		/* These are the header bytes. See gnupg doc/DETAILS */
		g_assert (IMAGE_JPEG_SIG_LEN < IMAGE_HEADER_LEN);
		if (memcmp (data, IMAGE_JPEG_SIG, IMAGE_JPEG_SIG_LEN) != 0) {
			g_free (data);
			continue;
		}

		icon = G_ICON (_gcr_memory_icon_new_full ("image/jpeg", data,
		                                          n_data, IMAGE_HEADER_LEN,
		                                          g_free));

		validity = _gcr_record_get_char (record, GCR_RECORD_XA1_TRUST);
		if (validity != 0 && validity != 'm' && validity != 'f' && validity != 'u')
			add_emblem_to_icon (&icon, "dialog-question");

		/* We have a valid header */
		return icon;
	}

	if (_gcr_records_find (records, GCR_RECORD_SCHEMA_SEC))
		return g_themed_icon_new ("gcr-key-pair");
	else
		return g_themed_icon_new ("gcr-key");

	return NULL;
}
