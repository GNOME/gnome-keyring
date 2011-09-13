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

#include "gcr-openpgp.h"
#include "gcr-internal.h"
#include "gcr-record.h"
#include "gcr-types.h"

#include "pkcs11/pkcs11.h"

#include <string.h>

static gboolean
read_byte (const guchar **at,
           const guchar *end,
           guchar *result)
{
	g_assert (at);
	if (*at == end)
		*at = NULL;
	if (*at == NULL)
		return FALSE;
	*result = *((*at)++);
	return TRUE;
}

static gboolean
read_bytes (const guchar **at,
            const guchar *end,
            gpointer buffer,
            gsize length)
{
	g_assert (at);
	if (*at + length >= end)
		*at = NULL;
	if (*at == NULL)
		return FALSE;
	memcpy (buffer, *at, length);
	(*at) += length;
	return TRUE;
}

static gboolean
read_uint32 (const guchar **at,
             const guchar *end,
             guint32 *value)
{
	guchar buf[4];
	if (!read_bytes (at, end, buf, 4))
		return FALSE;
	*value = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
	return TRUE;
}

static gboolean
read_uint16 (const guchar **at,
             const guchar *end,
             guint16 *value)
{
	guchar buf[2];
	if (!read_bytes (at, end, buf, 2))
		return FALSE;
	*value = buf[0] << 8 | buf[1];
	return TRUE;
}

static gboolean
read_new_length (const guchar **at,
                 const guchar *end,
                 gsize *pkt_len)
{
	guchar c, c1;
	guint32 val;

	if (!read_byte (at, end, &c))
		return FALSE;
	if (c < 192) {
		*pkt_len = c;
	} else if (c >= 192 && c <= 223) {
		if (!read_byte (at, end, &c1))
			return FALSE;
		*pkt_len = ((c - 192) << 8) + c1 + 192;
	} else if (c == 255) {
		if (!read_uint32 (at, end, &val))
			return FALSE;
		*pkt_len = val;
	} else {
		/* We don't support partial length */
		return FALSE;
	}

	return TRUE;
}

static gboolean
read_old_length (const guchar **at,
                 const guchar *end,
                 guchar ctb,
                 gsize *pkt_len)
{
	gsize llen = ctb & 0x03;
	guint16 v16;
	guint32 v32;
	guchar c;

	if (llen == 0) {
		if (!read_byte (at, end, &c))
			return FALSE;
		*pkt_len = c;
	} else if (llen == 1) {
		if (!read_uint16 (at, end, &v16))
			return FALSE;
		*pkt_len = v16;
	} else if (llen == 2) {
		if (!read_uint32 (at, end, &v32))
			return FALSE;
		*pkt_len = v32;
	} else {
		*pkt_len = end - *at;
	}

	return TRUE;
}

static GcrDataError
read_openpgp_packet (const guchar **at,
                     const guchar *end,
                     GPtrArray *records,
                     gsize *length)
{
	guchar pkt_type;
	gboolean new_ctb;
	guchar ctb;
	gboolean ret;

	if (!read_byte (at, end, &ctb))
		return GCR_ERROR_UNRECOGNIZED;
	if (!(ctb & 0x80))
		return GCR_ERROR_UNRECOGNIZED;

	/* RFC2440 packet format. */
	if (ctb & 0x40) {
		pkt_type = ctb & 0x3f;
		new_ctb = TRUE;

	/* the old RFC1991 packet format. */
	} else {
		pkt_type = ctb & 0x3f;
		pkt_type >>= 2;
		new_ctb = FALSE;
	}

	if (pkt_type > 63)
		return GCR_ERROR_UNRECOGNIZED;

	if (new_ctb)
		ret = read_new_length (at, end, length);
	else
		ret = read_old_length (at, end, ctb, length);
	if (!ret)
		return GCR_ERROR_UNRECOGNIZED;

	if ((*at) + *length > end)
		return GCR_ERROR_FAILURE;
	return GCR_SUCCESS;
}

guint
_gcr_openpgp_parse (gconstpointer data,
                    gsize n_data,
                    GcrOpenpgpCallback callback,
                    gpointer user_data)
{
	const guchar *at;
	const guchar *beg;
	const guchar *end;
	GPtrArray *records;
	GcrDataError res;
	gsize length;
	guint num_packets = 0;

	g_return_val_if_fail (data != NULL, 0);

	at = data;
	end = at + n_data;

	while (at != NULL && at != end) {
		beg = at;
		records = g_ptr_array_new_with_free_func (_gcr_record_free);
		res = read_openpgp_packet (&at, end, records, &length);
		if (res == GCR_SUCCESS && callback != NULL)
			(callback) (records, beg, (at - beg) + length, user_data);

		g_ptr_array_unref (records);

		if (res != GCR_SUCCESS)
			break;

		at += length;
		num_packets++;
	}

	return num_packets;
}
