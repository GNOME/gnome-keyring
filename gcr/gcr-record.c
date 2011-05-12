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

#include "gcr-record.h"
#define DEBUG_FLAG GCR_DEBUG_PARSE
#include "gcr-debug.h"

#include <string.h>

#define MAX_COLUMNS 32

struct _GcrRecord {
	gchar *data;
	gchar *columns[MAX_COLUMNS];
	guint n_columns;
};

static GcrRecord*
parse_internal (gchar *line, gsize n_line)
{
	GcrRecord *result;
	gchar *p;

	g_assert (line);
	g_assert (n_line);

	result = g_slice_new0 (GcrRecord);
	result->data = line;

	_gcr_debug ("parsing line %.*s", (gint)n_line, line);

	p = result->data;
	for (;;) {
		if (result->n_columns >= MAX_COLUMNS) {
			_gcr_debug ("too many record (%d) in gnupg line", MAX_COLUMNS);
			_gcr_record_free (result);
			return NULL;
		}

		result->columns[result->n_columns] = p;
		result->n_columns++;

		p = strchr (p, ':');
		if (p == NULL)
			break;
		p[0] = '\0';
		p++;
	}

	return result;
}

GcrRecord*
_gcr_record_parse_colons (const gchar *line, gssize n_line)
{
	g_return_val_if_fail (line, NULL);
	if (n_line < 0)
		n_line = strlen (line);

	return parse_internal (g_strndup (line, n_line), n_line);
}

GcrRecord*
_gcr_record_find (GPtrArray *records, GQuark schema)
{
	guint i;

	g_return_val_if_fail (records, NULL);
	g_return_val_if_fail (schema, NULL);

	for (i = 0; i < records->len; i++) {
		if (schema == _gcr_record_get_schema (records->pdata[i]))
			return records->pdata[i];
	}

	return NULL;
}

gchar*
_gcr_record_get_string (GcrRecord *record, guint column)
{
	const gchar *value;
	gchar *text;
	gchar *converted;

	g_return_val_if_fail (record, NULL);

	value = _gcr_record_get_raw (record, column);
	if (!value)
		return NULL;
	text = g_strcompress (value);
	if (g_utf8_validate (text, -1, NULL))
		return text;

	/* If it's not UTF-8, we guess that it's latin1 */
	converted = g_convert (text, -1, "UTF-8", "ISO-8859-1", NULL, NULL, NULL);
	g_free (text);

	if (!converted) {
		_gcr_debug ("failed to convert value from latin1 to utf-8: %s", text);
		return NULL;
	}

	return converted;
}

const gchar*
_gcr_record_get_raw (GcrRecord *record, guint column)
{
	g_return_val_if_fail (record, NULL);

	if (column >= record->n_columns) {
		_gcr_debug ("only %d columns exist, tried to access %d",
		            record->n_columns, column);
		return NULL;
	}

	return record->columns[column];
}

void
_gcr_record_free (gpointer record)
{
	if (!record)
		return;

	g_free (((GcrRecord*)record)->data);
	g_slice_free (GcrRecord, record);
}

GQuark
_gcr_record_get_schema (GcrRecord *record)
{
	const gchar *value;

	value = _gcr_record_get_raw (record, GCR_RECORD_SCHEMA);
	if (value != NULL)
		return g_quark_try_string (value);
	return 0;
}
