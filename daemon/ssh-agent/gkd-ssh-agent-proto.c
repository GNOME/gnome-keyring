/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-ssh-agent-proto.c - SSH agent protocol helpers

   Copyright (C) 2007 Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkd-ssh-agent-private.h"

#include "gkm/gkm-data-der.h"

#include "egg/egg-buffer.h"

#include <gck/gck.h>

#include <glib.h>

#include <string.h>

/* -----------------------------------------------------------------------------
 * QUARKS
 */

static GQuark OID_ANSI_SECP256R1;
static GQuark OID_ANSI_SECP384R1;
static GQuark OID_ANSI_SECP521R1;

static void
init_quarks (void)
{
	static volatile gsize quarks_inited = 0;

	if (g_once_init_enter (&quarks_inited)) {

		#define QUARK(name, value) \
			name = g_quark_from_static_string(value)

		QUARK (OID_ANSI_SECP256R1, "1.2.840.10045.3.1.7");
		QUARK (OID_ANSI_SECP384R1, "1.3.132.0.34");
		QUARK (OID_ANSI_SECP521R1, "1.3.132.0.35");

		#undef QUARK

		g_once_init_leave (&quarks_inited, 1);
	}
}

gulong
gkd_ssh_agent_proto_keytype_to_algo (const gchar *salgo)
{
	g_return_val_if_fail (salgo, G_MAXULONG);
	if (strcmp (salgo, "ssh-rsa") == 0)
		return CKK_RSA;
	else if (strcmp (salgo, "ssh-dss") == 0)
		return CKK_DSA;
	else if (strcmp (salgo, "ecdsa-sha2-nistp256") == 0 ||
		 strcmp (salgo, "ecdsa-sha2-nistp384") == 0 ||
		 strcmp (salgo, "ecdsa-sha2-nistp521") == 0)
		return CKK_EC;
	return G_MAXULONG;
}

GQuark
gkd_ssh_agent_proto_curve_to_oid (const gchar *salgo)
{
	g_return_val_if_fail (salgo, 0);

	init_quarks ();

	if (g_str_equal (salgo, "nistp256"))
		return OID_ANSI_SECP256R1;
	else if (g_str_equal (salgo, "nistp384"))
		return OID_ANSI_SECP384R1;
	else if (g_str_equal (salgo, "nistp521"))
		return OID_ANSI_SECP521R1;

	return 0;
}

const gchar*
gkd_ssh_agent_proto_oid_to_curve (GQuark oid)
{
	g_return_val_if_fail (oid, NULL);

	init_quarks ();

	if (oid == OID_ANSI_SECP256R1)
		return "nistp256";
	else if (oid == OID_ANSI_SECP384R1)
		return "nistp384";
	else if (oid == OID_ANSI_SECP521R1)
		return "nistp521";

	return NULL;
}

gint
gkd_ssh_agent_proto_curve_oid_to_hash_algo (GQuark oid)
{
	g_return_val_if_fail (oid, -1);

	init_quarks ();

	/* from rfc5656 */
	if (oid == OID_ANSI_SECP256R1)
		return G_CHECKSUM_SHA256;
	else if (oid == OID_ANSI_SECP384R1)
		return G_CHECKSUM_SHA384;
	else if (oid == OID_ANSI_SECP521R1)
		return G_CHECKSUM_SHA512;

	return -1;
}

const gchar*
gkd_ssh_agent_proto_curve_oid_to_keytype (GQuark oid)
{
	g_return_val_if_fail (oid, NULL);

	init_quarks ();

	if (oid == OID_ANSI_SECP256R1)
		return "ecdsa-sha2-nistp256";
	else if (oid == OID_ANSI_SECP384R1)
		return "ecdsa-sha2-nistp384";
	else if (oid == OID_ANSI_SECP521R1)
		return "ecdsa-sha2-nistp521";

	return NULL;
}

const gchar*
gkd_ssh_agent_proto_algo_to_keytype (gulong algo, GQuark curve_oid)
{
	if (algo == CKK_RSA) {
		g_return_val_if_fail (curve_oid == 0, NULL);
		return "ssh-rsa";
	} else if (algo == CKK_DSA) {
		g_return_val_if_fail (curve_oid == 0, NULL);
		return "ssh-dss";
	} else if (algo == CKK_EC) {
		g_return_val_if_fail (curve_oid != 0, NULL);
		return gkd_ssh_agent_proto_curve_oid_to_keytype (curve_oid);
	}

	return NULL;
}


GQuark
gkd_ssh_agent_proto_find_curve_oid (GckAttributes *attrs)
{
	GBytes *bytes;
	const GckAttribute *attr;
	GQuark oid;

	g_assert (attrs);

	attr = gck_attributes_find (attrs, CKA_EC_PARAMS);
	if (attr == NULL)
		g_return_val_if_reached (0);

	bytes = g_bytes_new (attr->value, attr->length);

	oid = gkm_data_der_oid_from_ec_params (bytes);

	g_bytes_unref (bytes);

	return oid;
}

gboolean
gkd_ssh_agent_proto_read_mpi (EggBuffer *req, gsize *offset,
                              GckBuilder *builder,
                              CK_ATTRIBUTE_TYPE type)
{
	const guchar *data;
	gsize len;

	if (!egg_buffer_get_byte_array (req, *offset, offset, &data, &len))
		return FALSE;

	/* Convert to unsigned format */
	if (len >= 2 && data[0] == 0 && (data[1] & 0x80)) {
		++data;
		--len;
	}

	gck_builder_add_data (builder, type, data, len);
	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_mpi_v1 (EggBuffer *req,
                                 gsize *offset,
                                 GckBuilder *attrs,
                                 CK_ATTRIBUTE_TYPE type)
{
	const guchar *data;
	gsize bytes;
	guint16 bits;

	/* Get the number of bits */
	if (!egg_buffer_get_uint16 (req, *offset, offset, &bits))
		return FALSE;

	/* Figure out the number of binary bytes following */
	bytes = (bits + 7) / 8;
	if (bytes > 8 * 1024)
		return FALSE;

	/* Pull these out directly */
	if (req->len < *offset + bytes)
		return FALSE;
	data = req->buf + *offset;
	*offset += bytes;

	gck_builder_add_data (attrs, type, data, bytes);
	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_string_to_der (EggBuffer *req,
                                        gsize *offset,
                                        GckBuilder *attrs,
                                        CK_ATTRIBUTE_TYPE type)
{
	const guchar *data, *q_data;
	gsize len, q_len;
	GBytes *bytes;

	if (!egg_buffer_get_byte_array (req, *offset, offset, &data, &len))
		return FALSE;

	bytes = gkm_data_der_encode_ecdsa_q_str (data, len);

	q_data = g_bytes_get_data (bytes, &q_len);

	gck_builder_add_data (attrs, type, q_data, q_len);
	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_mpi (EggBuffer *resp,
                               const GckAttribute *attr)
{
	const guchar *value;
	guchar *data;
	gsize n_extra;

	g_assert (resp);
	g_assert (attr);

	/* Convert from unsigned format */
	n_extra = 0;
	value = attr->value;
	if (attr->length && (value[0] & 0x80))
		++n_extra;

	data = egg_buffer_add_byte_array_empty (resp, attr->length + n_extra);
	if (data == NULL)
		return FALSE;

	memset (data, 0, n_extra);
	memcpy (data + n_extra, attr->value, attr->length);
	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_mpi_v1 (EggBuffer *resp,
                                  const GckAttribute *attr)
{
	guchar *data;

	g_return_val_if_fail (attr->length * 8 < G_MAXUSHORT, FALSE);

	if (!egg_buffer_add_uint16 (resp, attr->length * 8))
		return FALSE;

	data = egg_buffer_add_empty (resp, attr->length);
	if (data == NULL)
		return FALSE;
	memcpy (data, attr->value, attr->length);
	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_string (EggBuffer *resp,
                                  const GckAttribute *attr)
{
       guchar *data;

       g_assert (resp);
       g_assert (attr);

       data = egg_buffer_add_byte_array_empty (resp, attr->length);
       if (data == NULL)
               return FALSE;

       memcpy (data, attr->value, attr->length);
       return TRUE;
}

const guchar*
gkd_ssh_agent_proto_read_challenge_v1 (EggBuffer *req, gsize *offset, gsize *n_challenge)
{
	const guchar *data;
	gsize bytes;
	guint16 bits;

	/* Get the number of bits */
	if (!egg_buffer_get_uint16 (req, *offset, offset, &bits))
		return FALSE;

	/* Figure out the number of binary bytes following */
	bytes = (bits + 7) / 8;
	if (bytes > 8 * 1024)
		return FALSE;

	/* Pull these out directly */
	if (req->len < *offset + bytes)
		return FALSE;
	data = req->buf + *offset;
	*offset += bytes;
	*n_challenge = bytes;
	return data;
}

gboolean
gkd_ssh_agent_proto_read_public (EggBuffer *req,
                                 gsize *offset,
                                 GckBuilder *attrs,
                                 gulong *algo)
{
	gboolean ret;
	gchar *stype;
	gulong alg;

	g_assert (req);
	g_assert (offset);

	/* The string algorithm */
	if (!egg_buffer_get_string (req, *offset, offset, &stype, (EggBufferAllocator)g_realloc))
		return FALSE;

	alg = gkd_ssh_agent_proto_keytype_to_algo (stype);
	if (alg == G_MAXULONG) {
		g_warning ("unsupported algorithm from SSH: %s", stype);
		g_free (stype);
		return FALSE;
	}

	g_free (stype);
	switch (alg) {
	case CKK_RSA:
		ret = gkd_ssh_agent_proto_read_public_rsa (req, offset, attrs);
		break;
	case CKK_DSA:
		ret = gkd_ssh_agent_proto_read_public_dsa (req, offset, attrs);
		break;
	case CKK_EC:
		ret = gkd_ssh_agent_proto_read_public_ecdsa (req, offset, attrs);
		break;
	default:
		g_assert_not_reached ();
		return FALSE;
	}

	if (!ret) {
		g_warning ("couldn't read incoming SSH public key");
		return FALSE;
	}

	if (algo)
		*algo = alg;
	return ret;
}

gboolean
gkd_ssh_agent_proto_read_pair_rsa (EggBuffer *req,
                                   gsize *offset,
                                   GckBuilder *priv_attrs,
                                   GckBuilder *pub_attrs)
{
	const GckAttribute *attr;

	g_assert (req);
	g_assert (offset);
	g_assert (priv_attrs);
	g_assert (pub_attrs);

	if (!gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_MODULUS) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PUBLIC_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PRIVATE_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_COEFFICIENT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PRIME_1) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PRIME_2))
		return FALSE;

	/* Copy attributes to the public key */
	attr = gck_builder_find (priv_attrs, CKA_MODULUS);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_PUBLIC_EXPONENT);
	gck_builder_add_attribute (pub_attrs, attr);

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (priv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
	gck_builder_add_ulong (priv_attrs, CKA_KEY_TYPE, CKK_RSA);
	gck_builder_add_ulong (pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (pub_attrs, CKA_KEY_TYPE, CKK_RSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_pair_v1 (EggBuffer *req,
                                  gsize *offset,
                                  GckBuilder *priv_attrs,
                                  GckBuilder *pub_attrs)
{
	const GckAttribute *attr;

	g_assert (req);
	g_assert (offset);
	g_assert (priv_attrs);
	g_assert (pub_attrs);

	if (!gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_MODULUS) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_PUBLIC_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_PRIVATE_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_COEFFICIENT) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_PRIME_1) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, priv_attrs, CKA_PRIME_2))
		return FALSE;

	/* Copy attributes to the public key */
	attr = gck_builder_find (priv_attrs, CKA_MODULUS);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_PUBLIC_EXPONENT);
	gck_builder_add_attribute (pub_attrs, attr);

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (priv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
	gck_builder_add_ulong (priv_attrs, CKA_KEY_TYPE, CKK_RSA);
	gck_builder_add_ulong (pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (pub_attrs, CKA_KEY_TYPE, CKK_RSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_public_rsa (EggBuffer *req,
                                     gsize *offset,
                                     GckBuilder *attrs)
{
	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	if (!gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_PUBLIC_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_MODULUS))
		return FALSE;

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (attrs, CKA_KEY_TYPE, CKK_RSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_public_v1 (EggBuffer *req,
                                    gsize *offset,
                                    GckBuilder *attrs)
{
	guint32 bits;

	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	if (!egg_buffer_get_uint32 (req, *offset, offset, &bits))
		return FALSE;

	if (!gkd_ssh_agent_proto_read_mpi_v1 (req, offset, attrs, CKA_PUBLIC_EXPONENT) ||
	    !gkd_ssh_agent_proto_read_mpi_v1 (req, offset, attrs, CKA_MODULUS))
		return FALSE;

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (attrs, CKA_KEY_TYPE, CKK_RSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_pair_dsa (EggBuffer *req,
                                   gsize *offset,
                                   GckBuilder *priv_attrs,
                                   GckBuilder *pub_attrs)
{
	const GckAttribute *attr;

	g_assert (req);
	g_assert (offset);
	g_assert (priv_attrs);
	g_assert (pub_attrs);

	if (!gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_PRIME) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_SUBPRIME) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_BASE) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, pub_attrs, CKA_VALUE) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_VALUE))
		return FALSE;

	/* Copy attributes to the public key */
	attr = gck_builder_find (priv_attrs, CKA_PRIME);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_SUBPRIME);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_BASE);
	gck_builder_add_attribute (pub_attrs, attr);

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (priv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
	gck_builder_add_ulong (priv_attrs, CKA_KEY_TYPE, CKK_DSA);
	gck_builder_add_ulong (pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (pub_attrs, CKA_KEY_TYPE, CKK_DSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_public_dsa (EggBuffer *req,
                                     gsize *offset,
                                     GckBuilder *attrs)
{
	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	if (!gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_PRIME) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_SUBPRIME) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_BASE) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, attrs, CKA_VALUE))
		return FALSE;

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (attrs, CKA_KEY_TYPE, CKK_DSA);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_ecdsa_curve (EggBuffer *req,
                                     gsize *offset,
                                     GckBuilder *attrs)
{
	GBytes *params;
	gchar *curve_name;
	const guchar *params_data;
	GQuark oid;
	gsize params_len;

	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	/* first part is the curve name (nistp* part of key name) and needs
	 * to be converted to CKA_EC_PARAMS
	 */
	if (!egg_buffer_get_string (req, *offset, offset, &curve_name,
                                    (EggBufferAllocator)g_realloc))
		return FALSE;

	oid = gkd_ssh_agent_proto_curve_to_oid (curve_name);
	g_return_val_if_fail (oid, FALSE);

	params = gkm_data_der_get_ec_params (oid);
	g_return_val_if_fail (params != NULL, FALSE);

	params_data = g_bytes_get_data (params, &params_len);
	gck_builder_add_data (attrs, CKA_EC_PARAMS, params_data, params_len);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_pair_ecdsa (EggBuffer *req,
                                     gsize *offset,
                                     GckBuilder *priv_attrs,
                                     GckBuilder *pub_attrs)
{
	const GckAttribute *attr;

	g_assert (req);
	g_assert (offset);
	g_assert (priv_attrs);
	g_assert (pub_attrs);

	if (!gkd_ssh_agent_proto_read_ecdsa_curve (req, offset, priv_attrs) ||
	    !gkd_ssh_agent_proto_read_string_to_der (req, offset, priv_attrs, CKA_EC_POINT) ||
	    !gkd_ssh_agent_proto_read_mpi (req, offset, priv_attrs, CKA_VALUE))
		return FALSE;

	/* Copy attributes to the public key */
	attr = gck_builder_find (priv_attrs, CKA_EC_POINT);
	gck_builder_add_attribute (pub_attrs, attr);
	attr = gck_builder_find (priv_attrs, CKA_EC_PARAMS);
	gck_builder_add_attribute (pub_attrs, attr);

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (priv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
	gck_builder_add_ulong (priv_attrs, CKA_KEY_TYPE, CKK_EC);
	gck_builder_add_ulong (pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (pub_attrs, CKA_KEY_TYPE, CKK_EC);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_read_public_ecdsa (EggBuffer *req,
                                       gsize *offset,
                                       GckBuilder *attrs)
{
	g_assert (req);
	g_assert (offset);
	g_assert (attrs);

	if (!gkd_ssh_agent_proto_read_ecdsa_curve (req, offset, attrs) ||
	    !gkd_ssh_agent_proto_read_string_to_der (req, offset, attrs, CKA_EC_POINT))
		return FALSE;

	/* Add in your basic other required attributes */
	gck_builder_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);
	gck_builder_add_ulong (attrs, CKA_KEY_TYPE, CKK_EC);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_public (EggBuffer *resp, GckAttributes *attrs)
{
	gboolean ret = FALSE;
	const gchar *salgo;
	GQuark oid = 0;
	gulong algo;

	g_assert (resp);
	g_assert (attrs);

	if (!gck_attributes_find_ulong (attrs, CKA_KEY_TYPE, &algo))
		g_return_val_if_reached (FALSE);
	if (algo == CKK_EC) {
		oid = gkd_ssh_agent_proto_find_curve_oid (attrs);
		if (!oid)
			return FALSE;
	}

	salgo = gkd_ssh_agent_proto_algo_to_keytype (algo, oid);
	g_assert (salgo);
	egg_buffer_add_string (resp, salgo);

	switch (algo) {
	case CKK_RSA:
		ret = gkd_ssh_agent_proto_write_public_rsa (resp, attrs);
		break;

	case CKK_DSA:
		ret = gkd_ssh_agent_proto_write_public_dsa (resp, attrs);
		break;

	case CKK_EC:
		ret = gkd_ssh_agent_proto_write_public_ecdsa (resp, attrs);
		break;

	default:
		g_return_val_if_reached (FALSE);
		break;
	}

	return ret;
}

gboolean
gkd_ssh_agent_proto_write_public_rsa (EggBuffer *resp, GckAttributes *attrs)
{
	const GckAttribute *attr;

	g_assert (resp);
	g_assert (attrs);

	attr = gck_attributes_find (attrs, CKA_PUBLIC_EXPONENT);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	attr = gck_attributes_find (attrs, CKA_MODULUS);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_public_dsa (EggBuffer *resp, GckAttributes *attrs)
{
	const GckAttribute *attr;

	g_assert (resp);
	g_assert (attrs);

	attr = gck_attributes_find (attrs, CKA_PRIME);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	attr = gck_attributes_find (attrs, CKA_SUBPRIME);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	attr = gck_attributes_find (attrs, CKA_BASE);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	attr = gck_attributes_find (attrs, CKA_VALUE);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi (resp, attr))
		return FALSE;

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_public_ecdsa (EggBuffer *resp, GckAttributes *attrs)
{
	const GckAttribute *attr;
	GQuark oid;
	const gchar *curve;
	guchar *data;
	const guchar *q_data;
	GBytes *bytes, *q;
	gboolean rv;
	gsize q_len;

	g_assert (resp);
	g_assert (attrs);

	/* decode curve name from EC_PARAMS */
	oid = gkd_ssh_agent_proto_find_curve_oid (attrs);
	g_return_val_if_fail (oid, FALSE);

	curve = gkd_ssh_agent_proto_oid_to_curve (oid);
	g_return_val_if_fail (curve != NULL, FALSE);

	data = egg_buffer_add_byte_array_empty (resp, strlen (curve));
	if (data == NULL)
		return FALSE;

	memcpy (data, curve, strlen(curve));

	/* decode DER-encoded value Q */
	attr = gck_attributes_find (attrs, CKA_EC_POINT);
	g_return_val_if_fail (attr, FALSE);

	bytes = g_bytes_new_static (attr->value, attr->length);
	rv = gkm_data_der_decode_ecdsa_q (bytes, &q);
	g_return_val_if_fail (rv, FALSE);
	g_bytes_unref (bytes);

	q_data = g_bytes_get_data (q, &q_len);

	data = egg_buffer_add_byte_array_empty (resp, q_len);
	if (data == NULL)
		return FALSE;

	memcpy (data, q_data, q_len);
	g_bytes_unref (q);

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_public_v1 (EggBuffer *resp, GckAttributes *attrs)
{
	const GckAttribute *attr;
	gulong bits;

	g_assert (resp);
	g_assert (attrs);

	/* This is always an RSA key. */

	/* Write out the number of bits of the key */
	if (!gck_attributes_find_ulong (attrs, CKA_MODULUS_BITS, &bits))
		g_return_val_if_reached (FALSE);
	egg_buffer_add_uint32 (resp, bits);

	/* Write out the exponent */
	attr = gck_attributes_find (attrs, CKA_PUBLIC_EXPONENT);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi_v1 (resp, attr))
		return FALSE;

	/* Write out the modulus */
	attr = gck_attributes_find (attrs, CKA_MODULUS);
	g_return_val_if_fail (attr, FALSE);

	if (!gkd_ssh_agent_proto_write_mpi_v1 (resp, attr))
		return FALSE;

	return TRUE;
}

gboolean
gkd_ssh_agent_proto_write_signature_rsa (EggBuffer *resp, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	return egg_buffer_add_byte_array (resp, signature, n_signature);
}

gboolean
gkd_ssh_agent_proto_write_signature_dsa (EggBuffer *resp, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	g_return_val_if_fail (n_signature == 40, FALSE);
	return egg_buffer_add_byte_array (resp, signature, n_signature);
}

static gboolean
gkd_ssh_agent_buffer_put_rfc_mpi (EggBuffer *buffer, const guchar *val,
                                  gsize len)
{
	gsize pad = 0;

	/*
	 * From RFC 4251:
	 * If the most significant bit would be set for a positive number,
	 * the number MUST be preceded by a zero byte.
	 */
	if ((val[0] & 0x80))
		pad = 1;

	if (!egg_buffer_add_uint32 (buffer, len + pad))
		return 0;
	if (pad && !egg_buffer_add_byte (buffer, 0x00))
		return 0;
	return egg_buffer_append (buffer, val, len);
}

gboolean
gkd_ssh_agent_proto_write_signature_ecdsa (EggBuffer *resp, CK_BYTE_PTR signature, CK_ULONG n_signature)
{
	gboolean rv;
	gsize mpi_size;
	gsize pads = 0;

	g_return_val_if_fail ((n_signature % 2) == 0, FALSE);

	/* PKCS#11 lists the MPIs concatenated, SSH-agent expects the size headers */
	mpi_size = n_signature/2;

	/*
	 * From RFC 4251, Section 5:
	 * If the most significant bit would be set for a positive number,
	 * the number MUST be preceded by a zero byte.
	 */
	pads = ((signature[0] & 0x80) == 0x80) + ((signature[mpi_size] & 0x80) == 0x80);

	/* First we need header for the whole signature blob
	 * (including 2 length headers and potential "padding")
	 */
	egg_buffer_add_uint32 (resp, n_signature + 8 + pads);

	rv = gkd_ssh_agent_buffer_put_rfc_mpi (resp, signature, mpi_size);
	g_return_val_if_fail (rv, FALSE);

	rv = gkd_ssh_agent_buffer_put_rfc_mpi (resp, signature + mpi_size, mpi_size);
	return rv;
}
