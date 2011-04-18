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

#include "gcr-colons.h"

#include <string.h>

#define MAX_COLUMNS 32

struct _GcrColons {
	gchar *data;
	gpointer columns[MAX_COLUMNS];
	guint n_columns;
};

GcrColons*
_gcr_colons_parse (const gchar *line, gssize n_line)
{
	GcrColons *result;
	gchar *p;

	g_return_val_if_fail (line, NULL);
	if (n_line < 0)
		n_line = strlen (line);

	result = g_slice_new0 (GcrColons);
	result->data = g_strndup (line, n_line);

	p = result->data;
	for (;;) {
		if (result->n_columns >= MAX_COLUMNS) {
			_gcr_colons_free (result);
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

GcrColons*
_gcr_colons_find (GPtrArray *dataset, GQuark schema)
{
	guint i;

	g_return_val_if_fail (dataset, NULL);
	g_return_val_if_fail (schema, NULL);

	for (i = 0; i < dataset->len; i++) {
		if (schema == _gcr_colons_get_schema (dataset->pdata[i]))
			return dataset->pdata[i];
	}

	return NULL;
}

gchar*
_gcr_colons_get_string (GcrColons *colons, guint column)
{
	const gchar *value;
	gchar *text;
	gchar *converted;

	g_return_val_if_fail (colons, NULL);

	value = _gcr_colons_get_raw (colons, column);
	if (!value)
		return NULL;
	text = g_strcompress (value);
	if (g_utf8_validate (text, -1, NULL))
		return text;

	/* If it's not UTF-8, we guess that it's latin1 */
	converted = g_convert (text, -1, "UTF-8", "ISO-8859-1", NULL, NULL, NULL);
	g_free (text);

	if (!converted)
		g_return_val_if_reached (NULL);

	return converted;
}

const gchar*
_gcr_colons_get_raw (GcrColons *colons, guint column)
{
	g_return_val_if_fail (colons, NULL);

	if (column >= colons->n_columns)
		return NULL;

	return colons->columns[column];
}

void
_gcr_colons_free (gpointer colons)
{
	if (!colons)
		return;

	g_free (((GcrColons*)colons)->data);
	g_slice_free (GcrColons, colons);
}

GQuark
_gcr_colons_get_schema (GcrColons *colons)
{
	const gchar *value;

	value = _gcr_colons_get_raw (colons, GCR_COLONS_SCHEMA);
	if (value != NULL)
		return g_quark_try_string (value);
	return 0;
}

GQuark
_gcr_colons_get_schema_uid_quark (void)
{
	return g_quark_from_static_string ("uid");
}

GQuark
_gcr_colons_get_schema_pub_quark (void)
{
	return g_quark_from_static_string ("pub");
}
