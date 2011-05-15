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
	PROP_KEYID,
	PROP_PUBLIC_DATASET,
	PROP_SECRET_DATASET,
	PROP_LABEL,
	PROP_MARKUP,
	PROP_DESCRIPTION,
	PROP_SHORT_KEYID
};

struct _GcrGnupgKeyPrivate {
	GPtrArray *public_dataset;
	GPtrArray *secret_dataset;
};

G_DEFINE_TYPE (GcrGnupgKey, _gcr_gnupg_key, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar *
calculate_name (GcrGnupgKey *self)
{
	GcrColons* colons;

	colons = _gcr_colons_find (self->pv->public_dataset, GCR_COLONS_SCHEMA_UID);
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
calculate_short_keyid (GcrGnupgKey *self)
{
	const gchar *keyid;
	gsize length;

	keyid = _gcr_gnupg_key_get_keyid_for_colons (self->pv->public_dataset);
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

	if (self->pv->public_dataset)
		g_ptr_array_free (self->pv->public_dataset, TRUE);
	if (self->pv->secret_dataset)
		g_ptr_array_free (self->pv->secret_dataset, TRUE);

	G_OBJECT_CLASS (_gcr_gnupg_key_parent_class)->finalize (obj);
}

static void
_gcr_gnupg_key_set_property (GObject *obj, guint prop_id, const GValue *value,
                             GParamSpec *pspec)
{
	GcrGnupgKey *self = GCR_GNUPG_KEY (obj);

	switch (prop_id) {
	case PROP_PUBLIC_DATASET:
		_gcr_gnupg_key_set_public_dataset (self, g_value_get_boxed (value));
		break;
	case PROP_SECRET_DATASET:
		_gcr_gnupg_key_set_secret_dataset (self, g_value_get_boxed (value));
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
	case PROP_PUBLIC_DATASET:
		g_value_set_boxed (value, self->pv->public_dataset);
		break;
	case PROP_SECRET_DATASET:
		g_value_set_boxed (value, self->pv->secret_dataset);
		break;
	case PROP_KEYID:
		g_value_set_string (value, _gcr_gnupg_key_get_keyid (self));
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
	case PROP_SHORT_KEYID:
		g_value_set_string (value, calculate_short_keyid (self));
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

	/**
	 * GcrGnupgKey::public-dataset:
	 *
	 * Public key data. Should always be present.
	 */
	g_object_class_install_property (gobject_class, PROP_PUBLIC_DATASET,
	         g_param_spec_boxed ("public-dataset", "Public Dataset", "Public Key Colon Dataset",
	                             G_TYPE_PTR_ARRAY, G_PARAM_READWRITE));

	/**
	 * GcrGnupgKey::secret-dataset:
	 *
	 * Secret key data. The keyid of this data must match public-dataset.
	 * If present, this key represents a secret key.
	 */
	g_object_class_install_property (gobject_class, PROP_SECRET_DATASET,
	         g_param_spec_boxed ("secret-dataset", "Secret Dataset", "Secret Key Colon Dataset",
	                             G_TYPE_PTR_ARRAY, G_PARAM_READWRITE));

	/**
	 * GcrGnupgKey::keyid:
	 *
	 * Key identifier.
	 */
	g_object_class_install_property (gobject_class, PROP_KEYID,
	         g_param_spec_string ("keyid", "Key ID", "Key identifier",
	                              "", G_PARAM_READABLE));

	/**
	 * GcrGnupgKey::label:
	 *
	 * User readable label for this key.
	 */
	g_object_class_install_property (gobject_class, PROP_LABEL,
	         g_param_spec_string ("label", "Label", "Key label",
	                              "", G_PARAM_READABLE));

	/**
	 * GcrGnupgKey::description:
	 *
	 * Description of type of key.
	 */
	g_object_class_install_property (gobject_class, PROP_DESCRIPTION,
	         g_param_spec_string ("description", "Description", "Description of object type",
	                              "", G_PARAM_READABLE));

	/**
	 * GcrGnupgKey::markup:
	 *
	 * User readable markup which contains key label.
	 */
	g_object_class_install_property (gobject_class, PROP_MARKUP,
	         g_param_spec_string ("markup", "Markup", "Markup which describes key",
	                              "", G_PARAM_READABLE));

	/**
	 * GcrGnupgKey::short-keyid:
	 *
	 * User readable key identifier.
	 */
	g_object_class_install_property (gobject_class, PROP_SHORT_KEYID,
	         g_param_spec_string ("short-keyid", "Short Key ID", "Display key identifier",
	                              "", G_PARAM_READABLE));
}

/**
 * _gcr_gnupg_key_new:
 * @pubset: array of GcrColons* representing public part of key
 * @secset: (allow-none): array of GcrColons* representing secret part of key.
 *
 * Create a new GcrGnupgKey for the colons data passed. If the secret part
 * of the key is set, then this represents a secret key; otherwise it represents
 * a public key.
 *
 * Returns: (transfer full): A newly allocated key.
 */
GcrGnupgKey*
_gcr_gnupg_key_new (GPtrArray *pubset, GPtrArray *secset)
{
	g_return_val_if_fail (pubset, NULL);
	return g_object_new (GCR_TYPE_GNUPG_KEY,
	                     "public-dataset", pubset,
	                     "secret-dataset", secset,
	                     NULL);
}

/**
 * _gcr_gnupg_key_get_public_dataset:
 * @self: The key
 *
 * Get the colons data this key is based on.
 *
 * Returns: (transfer none): An array of GcrColons*.
 */
GPtrArray*
_gcr_gnupg_key_get_public_dataset (GcrGnupgKey *self)
{
	g_return_val_if_fail (GCR_IS_GNUPG_KEY (self), NULL);
	return self->pv->public_dataset;
}

/**
 * _gcr_gnupg_key_set_public_dataset:
 * @self: The key
 * @dataset: The new array of GcrColons*
 *
 * Change the colons data that this key is based on.
 */
void
_gcr_gnupg_key_set_public_dataset (GcrGnupgKey *self, GPtrArray *dataset)
{
	GObject *obj;

	g_return_if_fail (GCR_IS_GNUPG_KEY (self));
	g_return_if_fail (dataset);

	/* Check that it matches previous */
	if (self->pv->public_dataset) {
		const gchar *old_keyid = _gcr_gnupg_key_get_keyid_for_colons (self->pv->public_dataset);
		const gchar *new_keyid = _gcr_gnupg_key_get_keyid_for_colons (dataset);

		if (g_strcmp0 (old_keyid, new_keyid) != 0) {
			g_warning ("it is an error to change a gnupg key so that the "
			           "fingerprint is no longer the same: %s != %s",
			           old_keyid, new_keyid);
			return;
		}
	}

	g_ptr_array_ref (dataset);
	if (self->pv->public_dataset)
		g_ptr_array_unref (self->pv->public_dataset);
	self->pv->public_dataset = dataset;

	obj = G_OBJECT (self);
	g_object_freeze_notify (obj);
	g_object_notify (obj, "public-dataset");
	g_object_notify (obj, "label");
	g_object_notify (obj, "markup");
	g_object_thaw_notify (obj);
}

/**
 * _gcr_gnupg_key_get_secret_dataset:
 * @self: The key
 *
 * Get the colons secret data this key is based on. %NULL if a public key.
 *
 * Returns: (transfer none) (allow-none): An array of GcrColons*.
 */
GPtrArray*
_gcr_gnupg_key_get_secret_dataset (GcrGnupgKey *self)
{
	g_return_val_if_fail (GCR_IS_GNUPG_KEY (self), NULL);
	return self->pv->secret_dataset;
}

/**
 * _gcr_gnupg_key_set_secret_dataset:
 * @self: The key
 * @dataset: (allow-none): The new array of GcrColons*
 *
 * Set the secret data for this key. %NULL if public key.
 */
void
_gcr_gnupg_key_set_secret_dataset (GcrGnupgKey *self, GPtrArray *dataset)
{
	GObject *obj;

	g_return_if_fail (GCR_IS_GNUPG_KEY (self));

	/* Check that it matches public key */
	if (self->pv->public_dataset && dataset) {
		const gchar *pub_keyid = _gcr_gnupg_key_get_keyid_for_colons (self->pv->public_dataset);
		const gchar *sec_keyid = _gcr_gnupg_key_get_keyid_for_colons (dataset);

		if (g_strcmp0 (pub_keyid, sec_keyid) != 0) {
			g_warning ("it is an error to create a gnupg key so that the "
			           "fingerprint of thet pub and sec parts are not the same: %s != %s",
			           pub_keyid, sec_keyid);
			return;
		}
	}

	if (dataset)
		g_ptr_array_ref (dataset);
	if (self->pv->secret_dataset)
		g_ptr_array_unref (self->pv->secret_dataset);
	self->pv->secret_dataset = dataset;

	obj = G_OBJECT (self);
	g_object_freeze_notify (obj);
	g_object_notify (obj, "secret-dataset");
	g_object_thaw_notify (obj);
}

/**
 * _gcr_gnupg_key_get_keyid:
 * @self: The key
 *
 * Get the keyid for this key.
 */
const gchar*
_gcr_gnupg_key_get_keyid (GcrGnupgKey *self)
{
	g_return_val_if_fail (GCR_IS_GNUPG_KEY (self), NULL);
	return _gcr_gnupg_key_get_keyid_for_colons (self->pv->public_dataset);
}

/**
 * _gcr_gnupg_key_get_keyid_for_colons:
 * @dataset: Array of GcrColons*
 *
 * Get the keyid for some colons data.
 *
 * Returns: (transfer none): The keyid.
 */
const gchar*
_gcr_gnupg_key_get_keyid_for_colons (GPtrArray *dataset)
{
	GcrColons *colons;

	colons = _gcr_colons_find (dataset, GCR_COLONS_SCHEMA_PUB);
	if (colons != NULL)
		return _gcr_colons_get_raw (colons, GCR_COLONS_PUB_KEYID);
	colons = _gcr_colons_find (dataset, GCR_COLONS_SCHEMA_SEC);
	if (colons != NULL)
		return _gcr_colons_get_raw (colons, GCR_COLONS_SEC_KEYID);
	return NULL;
}

/**
 * _gcr_gnupg_key_get_columns:
 *
 * Get the columns that we should display for gnupg keys.
 *
 * Returns: (transfer none): The columns, NULL terminated, should not be freed.
 */
const GcrColumn*
_gcr_gnupg_key_get_columns (void)
{
	static GcrColumn columns[] = {
		{ "label", G_TYPE_STRING, G_TYPE_STRING, NC_("column", "Name"),
		  GCR_COLUMN_SORTABLE },
		{ "short-keyid", G_TYPE_STRING, G_TYPE_STRING, NC_("column", "Key ID"),
		  GCR_COLUMN_SORTABLE },
		{ NULL }
	};

	return columns;
}
