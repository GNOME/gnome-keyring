/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gcr-fingerprint.h"
#include "gcr-oids.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"

#include <glib.h>
#include <gcrypt.h>

/**
 * SECTION:gcr-fingerprint
 * @title: Key Fingerprints
 * @short_description: Fingerprints for public and private keys
 *
 * These functions generate key fingerprints for public keys, certificates and
 * key data. The fingerprints are created so that they they will be identical
 * for a key and its corresponding certificate.
 *
 * Note that in the case of certificates these are not fingerprints of the
 * actual certificate data, but rather of the public key contained in a
 * certificate.
 *
 * These fingerprints are created using the subjectPublicKeyInfo ASN.1 structure.
 */

/**
 * gcr_fingerprint_from_subject_public_key_info:
 * @key_info: (array length=n_key_info): DER encoded subjectPublicKeyInfo structure
 * @n_key_info: length of DER encoded structure
 * @checksum_type: the type of fingerprint to create
 * @n_fingerprint: the length of fingerprint returned
 *
 * Create a key fingerprint for a DER encoded subjectPublicKeyInfo.
 *
 * Returns: (transfer full) (allow-none) (array length=n_fingerprint): the
 *          fingerprint or %NULL if the input was invalid.
 */
guchar *
gcr_fingerprint_from_subject_public_key_info (const guchar *key_info,
                                              gsize n_key_info,
                                              GChecksumType checksum_type,
                                              gsize *n_fingerprint)
{
	GChecksum *check;
	guint8 *fingerprint;

	g_return_val_if_fail (key_info, NULL);
	g_return_val_if_fail (n_key_info, NULL);
	g_return_val_if_fail (n_fingerprint, NULL);

	check = g_checksum_new (checksum_type);
	g_return_val_if_fail (check, NULL);

	g_checksum_update (check, key_info, n_key_info);

	*n_fingerprint = g_checksum_type_get_length (checksum_type);
	fingerprint = g_malloc (*n_fingerprint);
	g_checksum_get_digest (check, fingerprint, n_fingerprint);

	g_checksum_free (check);
	return fingerprint;
}

static gboolean
rsa_subject_public_key_from_attributes (GckAttributes *attrs, GNode *info_asn)
{
	GckAttribute *modulus;
	GckAttribute *exponent;
	GNode *key_asn;
	GNode *params_asn;
	gpointer key, params;
	gsize n_key, n_params;

	_gcr_oids_init ();

	modulus = gck_attributes_find (attrs, CKA_MODULUS);
	exponent = gck_attributes_find (attrs, CKA_PUBLIC_EXPONENT);
	if (modulus == NULL || exponent == NULL)
		return FALSE;

	key_asn = egg_asn1x_create (pk_asn1_tab, "RSAPublicKey");
	g_return_val_if_fail (key_asn, FALSE);

	params_asn = egg_asn1x_create (pk_asn1_tab, "RSAParameters");
	g_return_val_if_fail (params_asn, FALSE);

	egg_asn1x_set_integer_as_usg (egg_asn1x_node (key_asn, "modulus", NULL),
	                              modulus->value, modulus->length, NULL);

	egg_asn1x_set_integer_as_usg (egg_asn1x_node (key_asn, "publicExponent", NULL),
	                              exponent->value, exponent->length, NULL);

	key = egg_asn1x_encode (key_asn, g_realloc, &n_key);
	egg_asn1x_destroy (key_asn);

	egg_asn1x_set_null (params_asn);

	params = egg_asn1x_encode (params_asn, g_realloc, &n_params);
	egg_asn1x_destroy (params_asn);

	egg_asn1x_set_bits_as_raw (egg_asn1x_node (info_asn, "subjectPublicKey", NULL),
	                           key, n_key * 8, g_free);

	egg_asn1x_set_oid_as_quark (egg_asn1x_node (info_asn, "algorithm", "algorithm", NULL), GCR_OID_PKIX1_RSA);
	egg_asn1x_set_raw_element (egg_asn1x_node (info_asn, "algorithm", "parameters", NULL),
	                           params, n_params, g_free);

	return TRUE;
}

static gboolean
dsa_subject_public_key_from_private (GNode *key_asn, GckAttribute *ap,
                                     GckAttribute *aq, GckAttribute *ag, GckAttribute *ax)
{
	gcry_mpi_t mp, mq, mg, mx, my;
	size_t n_buffer;
	gcry_error_t gcry;
	unsigned char *buffer;

	gcry = gcry_mpi_scan (&mp, GCRYMPI_FMT_USG, ap->value, ap->length, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	gcry = gcry_mpi_scan (&mq, GCRYMPI_FMT_USG, aq->value, aq->length, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	gcry = gcry_mpi_scan (&mg, GCRYMPI_FMT_USG, ag->value, ag->length, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	gcry = gcry_mpi_scan (&mx, GCRYMPI_FMT_USG, ax->value, ax->length, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Calculate the public part from the private */
	my = gcry_mpi_snew (gcry_mpi_get_nbits (mx));
	g_return_val_if_fail (my, FALSE);
	gcry_mpi_powm (my, mg, mx, mp);

	gcry = gcry_mpi_aprint (GCRYMPI_FMT_STD, &buffer, &n_buffer, my);
	g_return_val_if_fail (gcry == 0, FALSE);
	egg_asn1x_set_integer_as_raw (key_asn, buffer, n_buffer, gcry_free);

	gcry_mpi_release (mp);
	gcry_mpi_release (mq);
	gcry_mpi_release (mg);
	gcry_mpi_release (mx);
	gcry_mpi_release (my);

	return TRUE;
}

static gboolean
dsa_subject_public_key_from_attributes (GckAttributes *attrs,
                                        gulong klass,
                                        GNode *info_asn)
{
	GckAttribute *value, *g, *q, *p;
	GNode *key_asn, *params_asn;
	gpointer key, params;
	gsize n_key, n_params;

	_gcr_oids_init ();

	p = gck_attributes_find (attrs, CKA_PRIME);
	q = gck_attributes_find (attrs, CKA_SUBPRIME);
	g = gck_attributes_find (attrs, CKA_BASE);
	value = gck_attributes_find (attrs, CKA_VALUE);

	if (p == NULL || q == NULL || g == NULL || value == NULL)
		return FALSE;

	key_asn = egg_asn1x_create (pk_asn1_tab, "DSAPublicPart");
	g_return_val_if_fail (key_asn, FALSE);

	params_asn = egg_asn1x_create (pk_asn1_tab, "DSAParameters");
	g_return_val_if_fail (params_asn, FALSE);

	egg_asn1x_set_integer_as_usg (egg_asn1x_node (params_asn, "p", NULL), p->value, p->length, NULL);
	egg_asn1x_set_integer_as_usg (egg_asn1x_node (params_asn, "q", NULL), q->value, q->length, NULL);
	egg_asn1x_set_integer_as_usg (egg_asn1x_node (params_asn, "g", NULL), g->value, g->length, NULL);

	/* Are these attributes for a public or private key? */
	if (klass == CKO_PRIVATE_KEY) {

		/* We need to calculate the public from the private key */
		if (!dsa_subject_public_key_from_private (key_asn, p, q, g, value))
			g_return_val_if_reached (FALSE);

	} else if (klass == CKO_PUBLIC_KEY) {
		egg_asn1x_set_integer_as_usg (key_asn, value->value, value->length, NULL);

	} else {
		g_assert_not_reached ();
	}

	key = egg_asn1x_encode (key_asn, g_realloc, &n_key);
	egg_asn1x_destroy (key_asn);

	params = egg_asn1x_encode (params_asn, g_realloc, &n_params);
	egg_asn1x_destroy (params_asn);

	egg_asn1x_set_bits_as_raw (egg_asn1x_node (info_asn, "subjectPublicKey", NULL),
	                           key, n_key * 8, g_free);
	egg_asn1x_set_raw_element (egg_asn1x_node (info_asn, "algorithm", "parameters", NULL),
	                           params, n_params, g_free);

	egg_asn1x_set_oid_as_quark (egg_asn1x_node (info_asn, "algorithm", "algorithm", NULL), GCR_OID_PKIX1_DSA);

	return TRUE;
}

static gpointer
fingerprint_from_key_attributes (GckAttributes *attrs,
                                 gulong klass,
                                 GChecksumType checksum_type,
                                 gsize *n_fingerprint)
{
	gpointer fingerprint = NULL;
	gboolean ret = FALSE;
	GNode *info_asn;
	gpointer info;
	gulong key_type;
	gsize n_info;

	if (!gck_attributes_find_ulong (attrs, CKA_KEY_TYPE, &key_type))
		return NULL;

	info_asn = egg_asn1x_create (pkix_asn1_tab, "SubjectPublicKeyInfo");
	g_return_val_if_fail (info_asn, NULL);

	if (key_type == CKK_RSA)
		ret = rsa_subject_public_key_from_attributes (attrs, info_asn);

	else if (key_type == CKK_DSA)
		ret = dsa_subject_public_key_from_attributes (attrs, klass, info_asn);

	else
		ret = FALSE;

	if (ret) {
		info = egg_asn1x_encode (info_asn, g_realloc, &n_info);
		fingerprint = gcr_fingerprint_from_subject_public_key_info (info, n_info,
		                                                            checksum_type,
		                                                            n_fingerprint);
		g_free (info);
	}

	egg_asn1x_destroy (info_asn);
	return fingerprint;
}

static guchar *
fingerprint_from_cert_value (const guchar *der_data,
                             gsize n_der_data,
                             GChecksumType checksum_type,
                             gsize *n_fingerprint)
{
	guchar *fingerprint;
	GNode *cert_asn;
	gconstpointer info;
	gsize n_info;

	cert_asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate",
	                                        der_data, n_der_data);
	if (cert_asn == NULL)
		return NULL;

	info = egg_asn1x_get_raw_element (egg_asn1x_node (cert_asn, "tbsCertificate", "subjectPublicKeyInfo", NULL), &n_info);
	g_return_val_if_fail (info != NULL, NULL);

	fingerprint = gcr_fingerprint_from_subject_public_key_info (info, n_info,
	                                                            checksum_type,
	                                                            n_fingerprint);

	egg_asn1x_destroy (cert_asn);
	return fingerprint;
}

static guchar *
fingerprint_from_cert_attributes (GckAttributes *attrs,
                                  GChecksumType checksum_type,
                                  gsize *n_fingerprint)
{
	GckAttribute *attr;

	attr = gck_attributes_find (attrs, CKA_VALUE);
	if (attr == NULL)
		return NULL;

	return fingerprint_from_cert_value (attr->value, attr->length, checksum_type,
	                                    n_fingerprint);
}

/**
 * gcr_fingerprint_from_attributes:
 * @attrs: attributes for key or certificate
 * @checksum_type: the type of fingerprint to create
 * @n_fingerprint: the length of fingerprint returned
 *
 * Create a key fingerprint for a certificate, public key or private key.
 * Note that this is not a fingerprint of certificate data, which you would
 * use gcr_certificate_get_fingerprint() for.
 *
 * Returns: (transfer full) (allow-none) (array length=n_fingerprint): the
 *          fingerprint or %NULL if the input was invalid.
 */
guchar *
gcr_fingerprint_from_attributes (GckAttributes *attrs,
                                  GChecksumType checksum_type,
                                  gsize *n_fingerprint)
{
	gulong klass;

	g_return_val_if_fail (attrs, FALSE);
	g_return_val_if_fail (n_fingerprint, FALSE);

	if (!gck_attributes_find_ulong (attrs, CKA_CLASS, &klass))
		return NULL;

	if (klass == CKO_CERTIFICATE)
		return fingerprint_from_cert_attributes (attrs, checksum_type,
		                                         n_fingerprint);

	else if (klass == CKO_PUBLIC_KEY || klass == CKO_PRIVATE_KEY)
		return fingerprint_from_key_attributes (attrs, klass,
		                                        checksum_type,
		                                        n_fingerprint);

	else
		return NULL;
}

/**
 * gcr_fingerprint_from_attributes:
 * @attrs: attributes for key or certificate
 * @checksum_type: the type of fingerprint to create
 * @n_fingerprint: the length of fingerprint returned
 *
 * Create a key fingerprint for a certificate's public key. Note that this is
 * not a fingerprint of certificate data, which you would use
 * gcr_certificate_get_fingerprint() for.
 *
 * Returns: (transfer full) (allow-none) (array length=n_fingerprint): the
 *          fingerprint or %NULL if the input was invalid.
 */
guchar *
gcr_fingerprint_from_certificate_public_key (GcrCertificate *certificate,
                                             GChecksumType checksum_type,
                                             gsize *n_fingerprint)
{
	const guchar *der_data;
	gsize n_der_data;

	g_return_val_if_fail (GCR_IS_CERTIFICATE (certificate), NULL);

	der_data = gcr_certificate_get_der_data (certificate, &n_der_data);
	g_return_val_if_fail (der_data != NULL, NULL);

	return fingerprint_from_cert_value (der_data, n_der_data, checksum_type,
	                                    n_fingerprint);
}
