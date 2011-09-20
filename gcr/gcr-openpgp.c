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

#include "egg/egg-hex.h"

#include <gcrypt.h>

#include <string.h>

typedef enum {
	OPENPGP_PKT_RESERVED = 0,
	OPENPGP_PKT_PUBKEY_ENC = 1,
	OPENPGP_PKT_SIGNATURE = 2,
	OPENPGP_PKT_ONEPASS_SIG = 4,
	OPENPGP_PKT_SECRET_KEY = 5,
	OPENPGP_PKT_PUBLIC_KEY = 6,
	OPENPGP_PKT_SECRET_SUBKEY = 7,
	OPENPGP_PKT_COMPRESSED = 8,
	OPENPGP_PKT_MARKER = 10,
	OPENPGP_PKT_LITERAL = 11,
	OPENPGP_PKT_RING_TRUST = 12,
	OPENPGP_PKT_USER_ID = 13,
	OPENPGP_PKT_PUBLIC_SUBKEY = 14,
	OPENPGP_PKT_OLD_COMMENT = 16,
	OPENPGP_PKT_ATTRIBUTE = 17,
	OPENPGP_PKT_MDC = 19
} OpenpgpPktType;

typedef enum {
	OPENPGP_SIG_CREATION = 2,
	OPENPGP_SIG_EXPIRY = 3,
	OPENPGP_SIG_EXPORTABLE = 4,
	OPENPGP_SIG_TRUST = 5,
	OPENPGP_SIG_REGULAR_EXPRESSION = 6,
	OPENPGP_SIG_REVOCABLE = 7,
	OPENPGP_SIG_KEY_EXPIRY = 9,
	OPENPGP_SIG_SYMMETRIC_ALGOS = 11,
	OPENPGP_SIG_REVOCATION_KEY = 12,
	OPENPGP_SIG_ISSUER = 16,
	OPENPGP_SIG_NOTATION_DATA = 20,
	OPENPGP_SIG_HASH_ALGOS = 21,
	OPENPGP_SIG_COMPRESSION_ALGOS = 22,
	OPENPGP_SIG_KEYSERVER_PREFS = 23,
	OPENPGP_SIG_PREFERRED_KEYSERVER = 24,
	OPENPGP_SIG_PRIMARY_USERID = 25,
	OPENPGP_SIG_POLICY_URI = 26,
	OPENPGP_SIG_KEY_FLAGS = 27,
	OPENPGP_SIG_SIGNER_USERID = 28,
	OPENPGP_SIG_REVOCATION_REASON = 29,
	OPENPGP_SIG_FEATURES = 30,
	OPENPGP_SIG_TARGET = 31,
	OPENPGP_SIG_EMBEDDED_SIGNATURE = 32,
} OpenpgpSigPacket;

static gboolean
read_byte (const guchar **at,
           const guchar *end,
           guint8 *result)
{
	g_assert (at);
	if (*at == end)
		*at = NULL;
	if (*at == NULL)
		return FALSE;
	if (result)
		*result = *(*at);
	(*at)++;
	return TRUE;
}

static gboolean
read_bytes (const guchar **at,
            const guchar *end,
            gpointer buffer,
            gsize length)
{
	g_assert (at);
	if (*at + length > end)
		*at = NULL;
	if (*at == NULL)
		return FALSE;
	if (buffer != NULL)
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
	g_assert (at);
	if (!read_bytes (at, end, buf, 4))
		return FALSE;
	if (value)
		*value = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
	return TRUE;
}

static gboolean
read_uint16 (const guchar **at,
             const guchar *end,
             guint16 *value)
{
	guchar buf[2];
	g_assert (at);
	if (!read_bytes (at, end, buf, 2))
		return FALSE;
	if (value)
		*value = buf[0] << 8 | buf[1];
	return TRUE;
}

static gboolean
read_mpi (const guchar **at,
          const guchar *end,
          guint16 *bits,
          guchar **value)
{
	gsize bytes;
	guint16 b;
	g_assert (at);
	if (!bits)
		bits = &b;
	if (!read_uint16 (at, end, bits))
		return FALSE;
	bytes = (*bits + 7) / 8;
	if (bytes == 0)
		return FALSE;
	if (value)
		*value = g_malloc (bytes);
	if (!read_bytes (at, end, value ? *value : NULL, bytes)) {
		if (value)
			g_free (*value);
		return FALSE;
	}
	return TRUE;
}

static gboolean
read_new_length (const guchar **at,
                 const guchar *end,
                 gsize *pkt_len)
{
	guint8 c, c1;
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
	guint8 c;

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
                     guint8 *pkt_type,
                     gsize *length)
{
	gboolean new_ctb;
	guint8 ctb;
	gboolean ret;

	if (!read_byte (at, end, &ctb))
		return GCR_ERROR_UNRECOGNIZED;
	if (!(ctb & 0x80))
		return GCR_ERROR_UNRECOGNIZED;

	/* RFC2440 packet format. */
	if (ctb & 0x40) {
		*pkt_type = ctb & 0x3f;
		new_ctb = TRUE;

	/* the old RFC1991 packet format. */
	} else {
		*pkt_type = ctb & 0x3f;
		*pkt_type >>= 2;
		new_ctb = FALSE;
	}

	if (*pkt_type > 63)
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

static gchar *
hash_user_id_or_attribute (const guchar *beg,
                           const guchar *end)
{
	guint8 digest[20] = { 0, };

	g_assert (beg != NULL);
	g_assert (end > beg);

	gcry_md_hash_buffer (GCRY_MD_RMD160, digest, beg, end - beg);
	return egg_hex_encode_full (digest, sizeof (digest), TRUE, 0, 0);
}

static gboolean
parse_v3_rsa_bits_and_keyid (const guchar **at,
                             const guchar *end,
                             guint16 *bits,
                             gchar **keyid)
{
	guchar *n;
	gsize bytes;

	g_assert (bits);
	g_assert (keyid);

	/* Read in the modulus */
	if (!read_mpi (at, end, bits, &n))
		return FALSE;

	/* Last 64-bits of modulus are keyid */
	bytes = (*bits + 7) / 8;
	if (bytes < 8) {
		g_free (n);
		return FALSE;
	}

	*keyid = egg_hex_encode_full (n + (bytes - 8), 8, TRUE, 0, 0);
	return TRUE;
}

static gchar *
hash_v4_keyid (const guchar *data,
               const guchar *end,
               gchar **fingerprint)
{
	gcry_md_hd_t mdh;
	gcry_error_t gcry;
	guchar header[3];
	guint8 *digest;
	gchar *keyid;
	gsize len;

	/*
	 * Both primary and subkeys use the public key tag byte
	 * 0x99 to construct the hash. So we skip over that here.
	 */

	g_assert (data != NULL);
	g_assert (end > data);

	len = end - data;
	g_return_val_if_fail (len < G_MAXUSHORT, NULL);

	header[0] = 0x99;
	header[1] = len >> 8 & 0xff;
	header[2] = len & 0xff;

	gcry = gcry_md_open (&mdh, GCRY_MD_SHA1, 0);
	g_return_val_if_fail (gcry == 0, NULL);

	gcry_md_write (mdh, header, 3);
	gcry_md_write (mdh, data, len);

	digest = gcry_md_read (mdh, 0);
	keyid = egg_hex_encode_full (digest + 12, 8, TRUE, 0, 0);
	if (fingerprint)
		*fingerprint = egg_hex_encode_full (digest, 20, TRUE, 0, 0);
	gcry_md_close (mdh);

	return keyid;
}

static gboolean
parse_v4_algo_bits (const guchar **at,
                    const guchar *end,
                    guint8 algo,
                    guint16 *bits)
{
	switch (algo) {
	case GCR_OPENPGP_ALGO_RSA:
	case GCR_OPENPGP_ALGO_RSA_E:
	case GCR_OPENPGP_ALGO_RSA_S:
		if (!read_mpi (at, end, bits, NULL) ||
		    !read_mpi (at, end, NULL, NULL))
			return FALSE;
		return TRUE;
	case GCR_OPENPGP_ALGO_DSA:
		if (!read_mpi (at, end, bits, NULL) ||
		    !read_mpi (at, end, NULL, NULL) ||
		    !read_mpi (at, end, NULL, NULL) ||
		    !read_mpi (at, end, NULL, NULL))
			return FALSE;
		return TRUE;
	case GCR_OPENPGP_ALGO_ELG_E:
		if (!read_mpi (at, end, bits, NULL) ||
		    !read_mpi (at, end, NULL, NULL) ||
		    !read_mpi (at, end, NULL, NULL))
			return FALSE;
		return TRUE;
	default: /* Unsupported key */
		return FALSE;
	}
}

static const gchar *
default_caps_for_algo (guint8 algo)
{
	switch (algo) {
	case GCR_OPENPGP_ALGO_RSA:
		return "cse";
	case GCR_OPENPGP_ALGO_RSA_E:
		return "e";
	case GCR_OPENPGP_ALGO_RSA_S:
		return "s";
	case GCR_OPENPGP_ALGO_ELG_E:
		return "e";
	case GCR_OPENPGP_ALGO_DSA:
		return "sca";
	default:
		return "";
	}
}

static gboolean
parse_public_key_or_subkey (GQuark schema,
                            guint n_columns,
                            const guchar *beg,
                            const guchar **at,
                            const guchar *end,
                            GcrOpenpgpParseFlags flags,
                            GPtrArray *records)
{
	gchar *keyid;
	GcrRecord *record;
	guint8 version;
	guint32 timestamp;
	guint16 ndays = 0;
	guint8 algo;
	guint16 bits;
	gulong expiry;
	gchar *fingerprint;
	const guchar *data;

	/* Start of actual key data in packet */
	data = *at;

	/* First byte is version */
	if (!read_byte (at, end, &version))
		return FALSE;
	if (version < 2 || version > 4)
		return FALSE;

	/* Next a 4 byte create date */
	if (!read_uint32 (at, end, &timestamp))
		return FALSE;
	/* If version 2 or 3, validity days comes next */
	if (version < 4) {
		if (!read_uint16 (at, end, &ndays))
			return FALSE;
	}

	/* Algorithm */
	if (!read_byte (at, end, &algo))
		return FALSE;

	/* For version 2 and 3, only RSA, keyid is low 64-bits of modulus */
	if (version < 4) {
		if (!parse_v3_rsa_bits_and_keyid (at, end, &bits, &keyid))
			return FALSE;

	/* For version 4 */
	} else {
		if (!parse_v4_algo_bits (at, end, algo, &bits))
			return FALSE;
		keyid = hash_v4_keyid (data, *at, &fingerprint);
	}

	record = _gcr_record_new (schema, n_columns, ':');
	_gcr_record_set_uint (record, GCR_RECORD_KEY_BITS, bits);
	_gcr_record_set_uint (record, GCR_RECORD_KEY_ALGO, algo);
	_gcr_record_take_raw (record, GCR_RECORD_KEY_KEYID, keyid);
	_gcr_record_set_ulong (record, GCR_RECORD_KEY_TIMESTAMP, timestamp);
	if (schema != GCR_RECORD_SCHEMA_SEC && schema != GCR_RECORD_SCHEMA_SSB)
		_gcr_record_set_raw (record, GCR_RECORD_PUB_CAPS, default_caps_for_algo (algo));

	if (ndays > 0) {
		expiry = (gulong)timestamp + ((gulong)ndays * 86400);
		_gcr_record_set_ulong (record, GCR_RECORD_KEY_EXPIRY, expiry);
	}

	g_ptr_array_add (records, record);

	if (fingerprint && (schema == GCR_RECORD_SCHEMA_PUB || schema == GCR_RECORD_SCHEMA_SEC)) {
		record = _gcr_record_new (GCR_RECORD_SCHEMA_FPR, GCR_RECORD_FPR_MAX, ':');
		_gcr_record_take_raw (record, GCR_RECORD_FPR_FINGERPRINT, fingerprint);
		g_ptr_array_add (records, record);
		fingerprint = NULL;
	}

	g_free (fingerprint);
	return TRUE;
}

static gboolean
parse_secret_key_or_subkey (GQuark schema,
                            const guchar *beg,
                            const guchar **at,
                            const guchar *end,
                            GcrOpenpgpParseFlags flags,
                            GPtrArray *records)
{
	/*
	 * Identical to a public key, with extra crap after it. The
	 * extra crap is hard to parse and doesn't add anything to
	 * the records, so just skip over it.
	 *
	 * Also don't print out trust, that doesn't make sense for
	 * secret keys.
	 */

	if (!parse_public_key_or_subkey (schema, GCR_RECORD_SEC_MAX,
	                                 beg, at, end, flags, records))
		return FALSE;

	*at = end;
	return TRUE;
}

static gboolean
parse_user_id (const guchar *beg,
               const guchar **at,
               const guchar *end,
               GcrOpenpgpParseFlags flags,
               GPtrArray *records)
{
	gchar *string;
	GcrRecord *record;
	gchar *fingerprint;

	g_assert (at);
	if (!*at || !end || *at > end)
		return FALSE;

	string = g_strndup ((gchar *)*at, end - *at);

	fingerprint = hash_user_id_or_attribute (*at, end);
	record = _gcr_record_new (GCR_RECORD_SCHEMA_UID, GCR_RECORD_UID_MAX, ':');
	_gcr_record_take_raw (record, GCR_RECORD_UID_FINGERPRINT, fingerprint);
	_gcr_record_set_string (record, GCR_RECORD_UID_USERID, string);
	g_free (string);

	g_ptr_array_add (records, record);

	*at = end;
	return TRUE;
}

static gboolean
parse_user_attribute_packet (const guchar *beg,
                             const guchar **at,
                             const guchar *end,
                             guchar subpkt_type,
                             GPtrArray *records)
{
	GcrRecord *record;
	gchar *fingerprint;

	record = _gcr_record_new (GCR_RECORD_SCHEMA_XA1, GCR_RECORD_XA1_MAX, ':');
	_gcr_record_set_uint (record, GCR_RECORD_XA1_LENGTH, end - *at);
	_gcr_record_set_uint (record, GCR_RECORD_XA1_TYPE, subpkt_type);
	fingerprint = hash_user_id_or_attribute (*at, end);
	_gcr_record_take_raw (record, GCR_RECORD_XA1_FINGERPRINT, fingerprint);
	_gcr_record_set_base64 (record, GCR_RECORD_XA1_DATA, *at, end - *at);

	g_ptr_array_add (records, record);

	*at = end;
	return TRUE;
}

static gboolean
parse_user_attribute (const guchar *beg,
                      const guchar **at,
                      const guchar *end,
                      GcrOpenpgpParseFlags flags,
                      GPtrArray *records)
{
	gsize subpkt_len;
	guint count = 0;
	const guchar *start;
	const guchar *subpkt_beg;
	guint8 subpkt_type;
	gchar *fingerprint;
	gchar *string;
	GcrRecord *record;

	start = *at;
	while (*at != end) {
		subpkt_beg = *at;

		if (!read_new_length (at, end, &subpkt_len) ||
		    !read_byte (at, end, &subpkt_type))
			return FALSE;

		count++;

		if (flags & GCR_OPENPGP_PARSE_ATTRIBUTES) {
			if (!parse_user_attribute_packet (subpkt_beg, at,
			                                  *at + (subpkt_len - 1),
			                                  subpkt_type, records))
				return FALSE;

		/* We already progressed one extra byte for the subpkt_type */
		} else {
			*at += (subpkt_len - 1);
		}
	}

	fingerprint = hash_user_id_or_attribute (start, end);
	string = g_strdup_printf ("%d %d", count, (guint)(*at - start));
	record = _gcr_record_new (GCR_RECORD_SCHEMA_UAT, GCR_RECORD_UAT_MAX, ':');
	_gcr_record_take_raw (record, GCR_RECORD_UAT_FINGERPRINT, fingerprint);
	_gcr_record_take_raw (record, GCR_RECORD_UAT_COUNT_SIZE, string);

	g_ptr_array_add (records, record);
	return TRUE;
}

static gboolean
skip_signature_mpis (const guchar **at,
                     const guchar *end,
                     guint8 algo)
{
	switch (algo) {

	/* RSA signature value */
	case GCR_OPENPGP_ALGO_RSA:
		return read_mpi (at, end, NULL, NULL);

	/* DSA values r and s */
	case GCR_OPENPGP_ALGO_DSA:
		return read_mpi (at, end, NULL, NULL) &&
		       read_mpi (at, end, NULL, NULL);
	default:
		return FALSE;
	}
}

static gboolean
parse_v3_signature (const guchar **at,
                    const guchar *end,
                    GcrOpenpgpParseFlags flags,
                    GPtrArray *records)
{
	guchar keyid[8];
	guint8 sig_type;
	guint8 sig_len;
	guint32 sig_time;
	guint8 key_algo;
	guint8 hash_algo;
	guint16 left_bits;
	GcrRecord *record;
	gchar *value;

	if (!read_byte (at, end, &sig_len) || sig_len != 5)
		return FALSE;

	if (!read_byte (at, end, &sig_type) ||
	    !read_uint32 (at, end, &sig_time) ||
	    !read_bytes (at, end, keyid, 8) ||
	    !read_byte (at, end, &key_algo) ||
	    !read_byte (at, end, &hash_algo) ||
	    !read_uint16 (at, end, &left_bits) ||
	    !skip_signature_mpis (at, end, key_algo))
		return FALSE;

	if (flags & GCR_OPENPGP_PARSE_SIGNATURES) {
		record = _gcr_record_new (GCR_RECORD_SCHEMA_SIG, GCR_RECORD_SIG_MAX, ':');
		_gcr_record_set_uint (record, GCR_RECORD_SIG_ALGO, key_algo);
		value = egg_hex_encode_full (keyid, sizeof (keyid), TRUE, 0, 0);
		_gcr_record_take_raw (record, GCR_RECORD_SIG_KEYID, value);
		_gcr_record_set_ulong (record, GCR_RECORD_SIG_TIMESTAMP, sig_time);
		value = g_strdup_printf ("%02xx", (guint)sig_type);
		_gcr_record_take_raw (record, GCR_RECORD_SIG_CLASS, value);
		g_ptr_array_add (records, record);
	}

	return TRUE;
}

typedef struct {
	gulong key_expiry;
	gboolean exportable;
	gboolean primary;
	guint8 key_flags;
	GcrRecord *revocation;
} SigSubpacket;

static gboolean
parse_v4_signature_revocation (const guchar **at,
                               const guchar *end,
                               GcrRecord *revocation)
{
	guchar fingerprint[20];
	gchar *value;
	guint8 klass;
	guint8 algo;

	if (!read_byte (at, end, &klass) ||
	    !read_byte (at, end, &algo) ||
	    !read_bytes (at, end, fingerprint, 20))
		return FALSE;

	_gcr_record_set_uint (revocation, GCR_RECORD_RVK_ALGO, algo);
	value = egg_hex_encode_full (fingerprint, 20, TRUE, 0, 0);
	_gcr_record_take_raw (revocation, GCR_RECORD_RVK_FINGERPRINT, value);
	value = g_strdup_printf ("%02X", (guint)klass);
	_gcr_record_take_raw (revocation, GCR_RECORD_RVK_CLASS, value);

	return TRUE;
}

static gboolean
parse_v4_signature_subpacket (const guchar **at,
                              const guchar *end,
                              guint8 sub_type,
                              GcrRecord *record,
                              SigSubpacket *subpkt)
{
	guchar keyid[8];
	guint32 when;
	guint8 byte;
	gboolean critical;
	gchar *value;

	critical = (sub_type & 0x80) ? TRUE : FALSE;
	sub_type &= ~0xC0;

	switch (sub_type) {
	case OPENPGP_SIG_CREATION:
		if (!read_uint32 (at, end, &when))
			return FALSE;
		_gcr_record_set_ulong (record, GCR_RECORD_SIG_TIMESTAMP, when);
		return TRUE;
	case OPENPGP_SIG_ISSUER:
		if (!read_bytes (at, end, keyid, 8))
			return FALSE;
		value = egg_hex_encode_full (keyid, 8, TRUE, 0, 0);
		_gcr_record_take_raw (record, GCR_RECORD_SIG_KEYID, value);
		return TRUE;
	case OPENPGP_SIG_KEY_EXPIRY:
		if (!read_uint32 (at, end, &when))
			return FALSE;
		subpkt->key_expiry = when;
		return TRUE;
	case OPENPGP_SIG_EXPIRY:
		if (!read_uint32 (at, end, &when))
			return FALSE;
		_gcr_record_set_ulong (record, GCR_RECORD_SIG_EXPIRY, when);
		return TRUE;
	case OPENPGP_SIG_EXPORTABLE:
		if (!read_byte (at, end, &byte))
			return FALSE;
		if (byte != 0 && byte != 1)
			return FALSE;
		subpkt->exportable = (byte == 0 ? FALSE : TRUE);
		return TRUE;

	case OPENPGP_SIG_PRIMARY_USERID:
		if (!read_byte (at, end, &byte))
			return FALSE;
		if (byte != 0 && byte != 1)
			return FALSE;
		subpkt->primary = byte;
		return TRUE;

	case OPENPGP_SIG_KEY_FLAGS:
		if (!read_byte (at, end, &byte))
			return FALSE;
		*at = end; /* N octets of flags */
		subpkt->key_flags = byte;
		return TRUE;

	case OPENPGP_SIG_SIGNER_USERID:
		value = g_strndup ((gchar *)*at, end - *at);
		_gcr_record_set_string (record, GCR_RECORD_SIG_USERID, value);
		g_free (value);
		return TRUE;

	case OPENPGP_SIG_REVOCATION_KEY:
		_gcr_record_free (subpkt->revocation);
		subpkt->revocation = _gcr_record_new (GCR_RECORD_SCHEMA_RVK, GCR_RECORD_RVK_MAX, ':');
		return parse_v4_signature_revocation (at, end, subpkt->revocation);

	/* Ignored */
	case OPENPGP_SIG_SYMMETRIC_ALGOS:
	case OPENPGP_SIG_HASH_ALGOS:
	case OPENPGP_SIG_COMPRESSION_ALGOS:
	case OPENPGP_SIG_REVOCABLE:
	case OPENPGP_SIG_TRUST:
	case OPENPGP_SIG_REGULAR_EXPRESSION:
	case OPENPGP_SIG_NOTATION_DATA:
	case OPENPGP_SIG_KEYSERVER_PREFS:
	case OPENPGP_SIG_PREFERRED_KEYSERVER:
	case OPENPGP_SIG_POLICY_URI:
	case OPENPGP_SIG_REVOCATION_REASON:
	case OPENPGP_SIG_FEATURES:
	case OPENPGP_SIG_TARGET:
	case OPENPGP_SIG_EMBEDDED_SIGNATURE:
		*at = end;
		return TRUE;

	/* Unrecognized */
	default:
		/* Critical, but not recognized */
		if (critical)
			return FALSE;
		*at = end;
		return TRUE;
	}

}

static gboolean
parse_v4_signature_subpackets (const guchar **at,
                               const guchar *end,
                               GcrRecord *record,
                               SigSubpacket *subpkt)
{
	gsize length;
	guint8 sub_type;
	const guchar *stop;

	while (*at != end) {
		if (!read_new_length (at, end, &length) ||
		    !read_byte (at, end, &sub_type) ||
		    length == 0)
			return FALSE;

		/* The length includes the sub_type */
		length--;
		stop = *at + length;
		if (stop > end)
			return FALSE;

		/* Actually parse the sub packets */
		if (!parse_v4_signature_subpacket (at, stop, sub_type, record, subpkt))
			return FALSE;
		if (*at != stop)
			return FALSE;
	}

	return TRUE;
}

static GcrRecord *
uid_or_uat_find_for_self_signature (GPtrArray *records,
                                    guint8 sig_type)
{
	GcrRecord *record;
	GQuark schema;

	if (records->len == 0)
		return NULL;

	switch (sig_type) {
	/* Generic certification of a key or userid */
	case 0x10: case 0x11: case 0x12: case 0x13:
		record = records->pdata[records->len - 1];
		schema = _gcr_record_get_schema (record);
		if (schema == GCR_RECORD_SCHEMA_UID ||
		    schema == GCR_RECORD_SCHEMA_UAT)
			return record;
		return NULL;

	default:
		return NULL;
	}

}

static GcrRecord *
key_or_sub_find_for_self_signature (GPtrArray *records,
                                    guint8 sig_type,
                                    const gchar *keyid)
{
	GcrRecord *record;
	const gchar *check;
	GQuark schema;
	gint i;

	if (records->len == 0)
		return NULL;

	switch (sig_type) {
	/* Generic certification of a key or userid */
	case 0x10: case 0x11: case 0x12: case 0x13:
		for (i = records->len - 1; i >= 0; i--) {
			record = records->pdata[i];
			schema = _gcr_record_get_schema (record);
			if (schema == GCR_RECORD_SCHEMA_PUB || schema == GCR_RECORD_SCHEMA_SEC) {
				check = _gcr_record_get_raw (record, GCR_RECORD_KEY_KEYID);
				return (check != NULL && g_str_equal (check, keyid)) ? record : NULL;
			}
		}
		return NULL;

	/* (Primary) Subkey Binding Signature */
	case 0x18: case 0x19:
		record = records->pdata[records->len - 1];
		schema = _gcr_record_get_schema (record);
		if (schema == GCR_RECORD_SCHEMA_SUB)
			return record;
		return NULL;

	default:
		return NULL;
	}
}

static void
pub_or_sub_set_key_caps (GcrRecord *record,
                         guint8 key_flags)
{
	GString *string;
	GQuark schema;

	schema = _gcr_record_get_schema (record);
	if (schema == GCR_RECORD_SCHEMA_SEC || schema == GCR_RECORD_SCHEMA_SSB)
		return;

	string = g_string_sized_new (8);
	if (key_flags & 0x02)
		g_string_append_c (string, 's');
	if (key_flags & 0x01)
		g_string_append_c (string, 'c');
	if (key_flags & 0x04 || key_flags & 0x08)
		g_string_append_c (string, 'e');
	if (key_flags & 0x20)
		g_string_append_c (string, 'a');

	_gcr_record_take_raw (record, GCR_RECORD_PUB_CAPS,
	                      g_string_free (string, FALSE));
}

static gboolean
parse_v4_signature (const guchar **at,
                    const guchar *end,
                    GcrOpenpgpParseFlags flags,
                    GPtrArray *records)
{
	guint8 sig_type;
	guint8 key_algo;
	guint8 hash_algo;
	guint16 hashed_len;
	guint16 unhashed_len;
	guint16 left_bits;
	GcrRecord *record;
	GcrRecord *key, *uid;
	const gchar *keyid;
	gchar *value;
	const guchar *stop;
	gulong timestamp;

	/* Information to transfer back onto the key record */
	SigSubpacket subpkt = { 0, };
	subpkt.exportable = 1;

	if (!read_byte (at, end, &sig_type) ||
	    !read_byte (at, end, &key_algo) ||
	    !read_byte (at, end, &hash_algo) ||
	    !read_uint16 (at, end, &hashed_len))
		return FALSE;

	/* Hashed subpackets which we use */
	record = _gcr_record_new (GCR_RECORD_SCHEMA_SIG, GCR_RECORD_SIG_MAX, ':');
	stop = *at + hashed_len;
	if (stop > end ||
	    !parse_v4_signature_subpackets (at, stop, record, &subpkt)) {
		_gcr_record_free (record);
		_gcr_record_free (subpkt.revocation);
		return FALSE;
	}

	/* Includes unhashed subpackets, which we skip over */
	if (!read_uint16 (at, end, &unhashed_len)) {
		_gcr_record_free (record);
		_gcr_record_free (subpkt.revocation);
		return FALSE;
	}

	stop = *at + unhashed_len;
	if (stop > end ||
	    !parse_v4_signature_subpackets (at, stop, record, &subpkt) ||
	    !read_uint16 (at, end, &left_bits) ||
	    !skip_signature_mpis (at, end, key_algo)) {
		_gcr_record_free (record);
		_gcr_record_free (subpkt.revocation);
		return FALSE;
	}

	if (subpkt.revocation) {
		g_ptr_array_add (records, subpkt.revocation);
		subpkt.revocation = NULL;
	}

	/* Fill in information on previous key or subkey */
	keyid = _gcr_record_get_raw (record, GCR_RECORD_SIG_KEYID);
	key = key_or_sub_find_for_self_signature (records, sig_type, keyid);
	if (key != NULL) {
		if (subpkt.key_expiry != 0) {
			if (_gcr_record_get_ulong (key, GCR_RECORD_KEY_TIMESTAMP, &timestamp))
				_gcr_record_set_ulong (key, GCR_RECORD_KEY_EXPIRY, timestamp + subpkt.key_expiry);
		}
		if (subpkt.key_flags != 0)
			pub_or_sub_set_key_caps (key, subpkt.key_flags);
	}

	if (key && _gcr_record_get_schema (key) == GCR_RECORD_SCHEMA_PUB) {
		uid = uid_or_uat_find_for_self_signature (records, sig_type);
		if (uid != NULL) {
			if (_gcr_record_get_ulong (record, GCR_RECORD_SIG_TIMESTAMP, &timestamp))
				_gcr_record_set_ulong (uid, GCR_RECORD_UID_TIMESTAMP, timestamp);
		}
	}

	if (flags & GCR_OPENPGP_PARSE_SIGNATURES) {
		_gcr_record_set_uint (record, GCR_RECORD_SIG_ALGO, key_algo);
		value = g_strdup_printf ("%02x%s", (guint)sig_type,
		                         subpkt.exportable ? "x" : "l");
		_gcr_record_take_raw (record, GCR_RECORD_SIG_CLASS, value);
		g_ptr_array_add (records, record);
	} else {
		_gcr_record_free (record);
	}

	return TRUE;
}

static gboolean
parse_signature (const guchar *beg,
                 const guchar **at,
                 const guchar *end,
                 GcrOpenpgpParseFlags flags,
                 GPtrArray *records)
{
	guint8 version;

	if (!read_byte (at, end, &version))
		return FALSE;

	if (version == 3)
		return parse_v3_signature (at, end, flags, records);
	else if (version == 4)
		return parse_v4_signature (at, end, flags, records);
	else
		return FALSE;
}

static GcrDataFormat
parse_openpgp_packet (const guchar *beg,
                      const guchar *at,
                      const guchar *end,
                      guint8 pkt_type,
                      GcrOpenpgpParseFlags flags,
                      GPtrArray *records)
{
	gboolean ret;

	switch (pkt_type) {
	case OPENPGP_PKT_PUBLIC_KEY:
		ret = parse_public_key_or_subkey (GCR_RECORD_SCHEMA_PUB, GCR_RECORD_PUB_MAX,
		                                  beg, &at, end, flags, records);
		break;
	case OPENPGP_PKT_PUBLIC_SUBKEY:
		ret = parse_public_key_or_subkey (GCR_RECORD_SCHEMA_SUB, GCR_RECORD_PUB_MAX,
		                                  beg, &at, end, flags, records);
		break;
	case OPENPGP_PKT_USER_ID:
		ret = parse_user_id (beg, &at, end, flags, records);
		break;
	case OPENPGP_PKT_ATTRIBUTE:
		ret = parse_user_attribute (beg, &at, end, flags, records);
		break;
	case OPENPGP_PKT_SIGNATURE:
		ret = parse_signature (beg, &at, end, flags, records);
		break;
	case OPENPGP_PKT_SECRET_KEY:
		ret = parse_secret_key_or_subkey (GCR_RECORD_SCHEMA_SEC,
		                                  beg, &at, end, flags, records);
		break;
	case OPENPGP_PKT_SECRET_SUBKEY:
		ret = parse_secret_key_or_subkey (GCR_RECORD_SCHEMA_SSB,
		                                  beg, &at, end, flags, records);
		break;

	/* Stuff we don't want to be meddling with right now */
	case OPENPGP_PKT_RING_TRUST:
		return GCR_SUCCESS;

	/* Ignore packets we don't understand */
	default:
		return GCR_SUCCESS;
	}

	/* Key packet had extra data */
	if (ret == TRUE && at != end)
		ret = FALSE;

	return ret ? GCR_SUCCESS : GCR_ERROR_FAILURE;
}

static void
append_key_capabilities (GString *string,
                         const gchar *caps)
{
	guint i;
	gchar cap;

	for (i = 0; caps[i] != 0; i++) {
		cap = g_ascii_toupper (caps[i]);
		if (!strchr (string->str, cap))
			g_string_append_c (string, cap);
	}
}

static void
normalize_capabilities (GPtrArray *records)
{
	GString *string;
	GQuark schema;
	const gchar *caps;
	guint i;

	/* Gather the capabilities of all subkeys into the primary key */
	string = g_string_new (_gcr_record_get_raw (records->pdata[0], GCR_RECORD_PUB_CAPS));
	for (i = 0; i < records->len; i++) {
		schema = _gcr_record_get_schema (records->pdata[i]);
		if (schema == GCR_RECORD_SCHEMA_PUB || schema == GCR_RECORD_SCHEMA_SUB) {
			caps = _gcr_record_get_raw (records->pdata[i], GCR_RECORD_PUB_CAPS);
			append_key_capabilities (string, caps);
		}
	}
	_gcr_record_take_raw (records->pdata[0], GCR_RECORD_PUB_CAPS,
	                      g_string_free (string, FALSE));
}

static gboolean
check_key_expiry (GcrRecord *record)
{
	gulong expiry;
	time_t current;

	if (_gcr_record_get_ulong (record, GCR_RECORD_KEY_EXPIRY, &expiry)) {
		if (expiry == 0)
			return FALSE;
		current = time (NULL);
		if (current > expiry)
			return TRUE;
	}

	return FALSE;
}

static void
normalize_key_records (GPtrArray *records)
{
	GQuark schema;
	guchar trust = 0;
	const gchar *prev;
	gboolean force = FALSE;
	guint i;

	if (records->len == 0)
		return;

	schema = _gcr_record_get_schema (records->pdata[0]);
	if (schema == GCR_RECORD_SCHEMA_PUB) {

		if (check_key_expiry (records->pdata[0])) {
			trust = 'e';
			force = TRUE;

		/* Mark public keys as unknown trust */
		} else {
			normalize_capabilities (records);
			trust = 'o';
			force = FALSE;
		}

		/* Ownertrust unknown, new to system */
		_gcr_record_set_char (records->pdata[0], GCR_RECORD_KEY_OWNERTRUST, 'o');

	} else if (schema == GCR_RECORD_SCHEMA_SEC) {

		/* Trust doesn't make sense for secret keys */
		trust = 0;
		force = FALSE;
	}


	/* Setup default trust if necessary */
	if (trust != 0) {
		for (i = 0; i < records->len; i++) {
			if (!force) {
				prev = _gcr_record_get_raw (records->pdata[i], GCR_RECORD_TRUST);
				if (prev != NULL && prev[0])
					continue;
			}
			schema = _gcr_record_get_schema (records->pdata[i]);
			if (schema != GCR_RECORD_SCHEMA_SIG && schema != GCR_RECORD_SCHEMA_FPR)
				_gcr_record_set_char (records->pdata[i], GCR_RECORD_TRUST, trust);
		}
	}
}

typedef struct {
	GcrOpenpgpCallback callback;
	gpointer user_data;
	guint count;
	GPtrArray *records;
} openpgp_parse_closure;

static void
openpgp_parse_free (gpointer data)
{
	openpgp_parse_closure *closure = data;
	g_ptr_array_unref (closure->records);
	g_free (closure);
}

static void
maybe_emit_openpgp_block (openpgp_parse_closure *closure,
                          const guchar *block,
                          const guchar *end)
{
	gsize length;
	GPtrArray *records;

	if (block == NULL || block == end)
		return;

	g_assert (end != NULL);
	g_assert (end > block);

	length = end - block;
	closure->count++;

	records = closure->records;
	closure->records = g_ptr_array_new_with_free_func (_gcr_record_free);

	if (closure->callback)
		(closure->callback) (records, block, length, closure->user_data);

	g_ptr_array_unref (records);
}

guint
_gcr_openpgp_parse (gconstpointer data,
                    gsize n_data,
                    GcrOpenpgpParseFlags flags,
                    GcrOpenpgpCallback callback,
                    gpointer user_data)
{
	openpgp_parse_closure *closure;
	const guchar *at;
	const guchar *beg;
	const guchar *end;
	const guchar *block;
	guint8 pkt_type;
	GcrDataError res;
	gsize length;
	gboolean new_key;
	guint ret;

	g_return_val_if_fail (data != NULL, 0);

	/* For libgcrypt */
	_gcr_initialize_library ();

	at = data;
	end = at + n_data;
	block = NULL;

	closure = g_new0 (openpgp_parse_closure, 1);
	closure->callback = callback;
	closure->user_data = user_data;
	closure->records = g_ptr_array_new_with_free_func (_gcr_record_free);

	while (at != NULL && at != end) {
		beg = at;
		res = read_openpgp_packet (&at, end, &pkt_type, &length);

		if (res == GCR_SUCCESS) {
			new_key = (pkt_type == OPENPGP_PKT_PUBLIC_KEY ||
			           pkt_type == OPENPGP_PKT_SECRET_KEY);
			if (flags & GCR_OPENPGP_PARSE_KEYS && new_key)
				normalize_key_records (closure->records);
			/* Start of a new set of packets, per key */
			if (!(flags & GCR_OPENPGP_PARSE_KEYS) || new_key) {
				maybe_emit_openpgp_block (closure, block, beg);
				block = beg;
			}
			if (!(flags & GCR_OPENPGP_PARSE_NO_RECORDS))
				parse_openpgp_packet (beg, at, at + length, pkt_type,
				                      flags, closure->records);
		}

		if (res != GCR_SUCCESS) {
			if (block != NULL && block != beg)
				maybe_emit_openpgp_block (closure, block, beg);
			block = NULL;
			break;
		}

		at += length;
	}

	if (flags & GCR_OPENPGP_PARSE_KEYS)
		normalize_key_records (closure->records);
	maybe_emit_openpgp_block (closure, block, at);
	ret = closure->count;
	openpgp_parse_free (closure);
	return ret;
}
