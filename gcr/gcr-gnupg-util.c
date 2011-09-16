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

#include "egg/egg-hex.h"

#include "gcr-gnupg-util.h"

#include <gcrypt.h>

/**
 * _gcr_gnupg_build_xa1_record:
 * @meta: Status metadata record about the attribute data.
 * @attribute: Pointer to attribute data.
 * @n_attribute: Length of attribute data.
 *
 * Build a record for attribute data. We use this records to convert attribute
 * data into something we can keep with an array of GcrRecord.
 *
 * Returns: (transfer full): The newly allocated record.
 */
GcrRecord*
_gcr_gnupg_build_xa1_record (GcrRecord *meta, gpointer attribute,
                             gsize n_attribute)
{
	gchar hash[20];
	gchar *hex;
	gchar status = 0;
	GcrRecord *record;
	guint flags, type;
	const gchar *created, *expiry;

	g_return_val_if_fail (meta, NULL);

	record = _gcr_record_new (GCR_RECORD_SCHEMA_XA1, GCR_RECORD_XA1_MAX, ':');

	gcry_md_hash_buffer (GCRY_MD_RMD160, hash, attribute, n_attribute);
	hex = egg_hex_encode_full (hash, sizeof (hash), TRUE, 0, 1);
	_gcr_record_take_raw (record, GCR_RECORD_XA1_FINGERPRINT, hex);

	if (!_gcr_record_get_uint (meta, GCR_RECORD_ATTRIBUTE_FLAGS, &flags))
		flags = 0;

	if (_gcr_record_get_uint (meta, GCR_RECORD_ATTRIBUTE_TYPE, &type))
		_gcr_record_set_uint (record, GCR_RECORD_XA1_TYPE, type);

	created = _gcr_record_get_raw (meta, GCR_RECORD_ATTRIBUTE_TIMESTAMP);
	if (created == NULL)
		_gcr_record_set_raw (record, GCR_RECORD_XA1_TIMESTAMP, created);

	expiry = _gcr_record_get_raw (meta, GCR_RECORD_ATTRIBUTE_EXPIRY);
	if (expiry != NULL)
		_gcr_record_set_raw (record, GCR_RECORD_XA1_EXPIRY, expiry);

	/* These values are from gnupg doc/DETAILS */
	if (flags & 0x02)
		status = 'r';
	else if (flags & 0x04)
		status = 'e';
	else if (flags & 0x01)
		status = 'P';
	if (status != 0)
		_gcr_record_set_char (record, GCR_RECORD_XA1_TRUST, status);

	_gcr_record_set_base64 (record, GCR_RECORD_XA1_DATA, attribute, n_attribute);

	return record;
}
