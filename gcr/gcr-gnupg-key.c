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

#include "gcr-colons.h"
#include "gcr-gnupg-key.h"

#include "gck/gck.h"

#include <gdk/gdk.h>
#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_DATASET,
	PROP_LABEL,
	PROP_MARKUP,
	PROP_DESCRIPTION,
	PROP_KEYID
};

struct _GcrGnupgKeyPrivate {
	GPtrArray *dataset;
};

G_DEFINE_TYPE (GcrGnupgKey, _gcr_gnupg_key, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar *
calculate_name (GcrGnupgKey *self)
{
	GcrColons* colons;

	colons = _gcr_colons_find (self->pv->dataset, GCR_COLONS_SCHEMA_UID);
	g_return_val_if_fail (colons, NULL);

	return _gcr_colons_get_string (colons, GCR_COLONS_UID_NAME);
}

static gchar *
calculate_markup (GcrGnupgKey *self)
{
	gchar *result = NULL;
	gchar *name;

	name = calculate_name (self);
	if (name)
		result = g_markup_escape_text (name, -1);
	g_free (name);

	return result;
}

static const gchar *
calculate_keyid (GcrGnupgKey *self)
{
	const gchar *keyid;
	gsize length;

	keyid = _gcr_gnupg_key_get_keyid_for_colons (self->pv->dataset);
	if (keyid == NULL)
		return NULL;

	length = strlen (keyid);
	if (length > 8)
		keyid += (length - 8);

	return keyid;
}

static void
_gcr_gnupg_key_init (GcrGnupgKey *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_GNUPG_KEY, GcrGnupgKeyPrivate));
}

static void
_gcr_gnupg_key_finalize (GObject *obj)
{
	GcrGnupgKey *self = GCR_GNUPG_KEY (obj);

	if (self->pv->dataset)
		g_ptr_array_free (self->pv->dataset, TRUE);
	self->pv->dataset = NULL;

	G_OBJECT_CLASS (_gcr_gnupg_key_parent_class)->finalize (obj);
}

static void
_gcr_gnupg_key_set_property (GObject *obj, guint prop_id, const GValue *value,
                             GParamSpec *pspec)
{
	GcrGnupgKey *self = GCR_GNUPG_KEY (obj);

	switch (prop_id) {
	case PROP_DATASET:
		g_return_if_fail (!self->pv->dataset);
		self->pv->dataset = g_value_dup_boxed (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_gnupg_key_get_property (GObject *obj, guint prop_id, GValue *value,
                             GParamSpec *pspec)
{
	GcrGnupgKey *self = GCR_GNUPG_KEY (obj);

	switch (prop_id) {
	case PROP_DATASET:
		g_value_set_boxed (value, self->pv->dataset);
		break;
	case PROP_LABEL:
		g_value_take_string (value, calculate_name (self));
		break;
	case PROP_DESCRIPTION:
		g_value_set_string (value, _("PGP Key"));
		break;
	case PROP_MARKUP:
		g_value_take_string (value, calculate_markup (self));
		break;
	case PROP_KEYID:
		g_value_set_string (value, calculate_keyid (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_gnupg_key_class_init (GcrGnupgKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	_gcr_gnupg_key_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GcrGnupgKeyPrivate));

	gobject_class->finalize = _gcr_gnupg_key_finalize;
	gobject_class->set_property = _gcr_gnupg_key_set_property;
	gobject_class->get_property = _gcr_gnupg_key_get_property;

	g_object_class_install_property (gobject_class, PROP_DATASET,
	         g_param_spec_boxed ("dataset", "Dataset", "Colon Dataset",
	                             G_TYPE_PTR_ARRAY, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_LABEL,
	         g_param_spec_string ("label", "Label", "Key label",
	                              "", G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_DESCRIPTION,
	         g_param_spec_string ("description", "Description", "Description of object type",
	                              "", G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_MARKUP,
	         g_param_spec_string ("markup", "Markup", "Markup which describes key",
	                              "", G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_KEYID,
	         g_param_spec_string ("keyid", "Key ID", "Display key identifier",
	                              "", G_PARAM_READABLE));
}

GcrGnupgKey*
_gcr_gnupg_key_new (GPtrArray *dataset)
{
	return g_object_new (GCR_TYPE_GNUPG_KEY, "dataset", dataset, NULL);
}


GPtrArray*
_gcr_gnupg_key_get_dataset (GcrGnupgKey *self)
{
	g_return_val_if_fail (GCR_IS_GNUPG_KEY (self), NULL);
	return self->pv->dataset;
}

void
_gcr_gnupg_key_set_dataset (GcrGnupgKey *self, GPtrArray *dataset)
{
	GObject *obj;

	g_return_if_fail (GCR_IS_GNUPG_KEY (self));
	g_return_if_fail (dataset);

	g_ptr_array_ref (dataset);
	if (self->pv->dataset)
		g_ptr_array_unref (self->pv->dataset);
	self->pv->dataset = dataset;

	obj = G_OBJECT (self);
	g_object_freeze_notify (obj);
	g_object_notify (obj, "dataset");
	g_object_notify (obj, "label");
	g_object_notify (obj, "markup");
	g_object_notify (obj, "keyid");
	g_object_thaw_notify (obj);
}

const gchar*
_gcr_gnupg_key_get_keyid_for_colons (GPtrArray *dataset)
{
	GcrColons *colons;

	colons = _gcr_colons_find (dataset, GCR_COLONS_SCHEMA_PUB);
	if (colons == NULL)
		return NULL;

	return _gcr_colons_get_raw (colons, GCR_COLONS_PUB_KEYID);
}

const GcrColumn*
_gcr_gnupg_key_get_columns (void)
{
	static GcrColumn columns[] = {
		{ "label", G_TYPE_STRING, G_TYPE_STRING, N_("Name"),
		  GCR_COLUMN_SORTABLE },
		{ "keyid", G_TYPE_STRING, G_TYPE_STRING, N_("Key ID"),
		  GCR_COLUMN_SORTABLE },
		{ NULL }
	};

	return columns;
}
