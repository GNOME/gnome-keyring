/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
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
 */

#include "config.h"

#include "gcr-internal.h"
#include "gcr-certificate.h"

#include "egg/egg-asn1.h"
#include "egg/egg-hex.h"

#include <string.h>

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */


typedef struct _Asn1Cache {
	ASN1_TYPE asn1;
	gconstpointer der;
	gsize length;
} Asn1Cache;

static GQuark ASN1_CACHE = 0;

static void
free_asn1_cache (gpointer data)
{
	Asn1Cache *cache = (Asn1Cache*)data;
	if (cache) {
		g_assert (cache->asn1);
		asn1_delete_structure (&cache->asn1);
		g_free (cache);
	}
}

static ASN1_TYPE
parse_certificate_asn1 (GcrCertificate *cert)
{
	Asn1Cache *cache;
	ASN1_TYPE asn1;
	const guchar *der;
	gsize n_der;
	
	g_assert (cert);
	
	der = gcr_certificate_get_der_data (cert, &n_der);
	g_return_val_if_fail (der, NULL);

	cache = (Asn1Cache*)g_object_get_qdata (G_OBJECT (cert), ASN1_CACHE);
	if (cache) {
		if (n_der == cache->length && memcmp (der, cache->der, n_der) == 0)
			return cache->asn1;
	}
	
	/* Cache is invalid or non existent */
	asn1 = egg_asn1_decode ("PKIX1.Certificate", der, n_der);
	if (asn1 == NULL) {
		g_warning ("a derived class provided an invalid or unparseable X509 DER certificate data.");
		return NULL;
	}
	
	cache = g_new0 (Asn1Cache, 1);
	cache->der = der;
	cache->length = n_der;
	cache->asn1 = asn1;
	
	g_object_set_qdata_full (G_OBJECT (cert), ASN1_CACHE, cache, free_asn1_cache);
	return asn1;
}

static GChecksum*
digest_certificate (GcrCertificate *self, GChecksumType type)
{
	GChecksum *digest;
	const guchar *der;
	gsize n_der;
	
	g_assert (GCR_IS_CERTIFICATE (self));

	der = gcr_certificate_get_der_data (self, &n_der);
	g_return_val_if_fail (der, NULL);
	
	digest = g_checksum_new (type);
	g_return_val_if_fail (digest, NULL);
	
	g_checksum_update (digest, der, n_der);
	return digest;
}

/* ---------------------------------------------------------------------------------
 * INTERFACE
 */

static void
gcr_certificate_base_init (gpointer g_class)
{
	static gboolean initialized = FALSE;
	if (!initialized) {
		ASN1_CACHE = g_quark_from_static_string ("_gcr_certificate_asn1_cache");
		
		/* Add properties and signals to the interface */
		
		
		initialized = TRUE;
	}
}

GType
gcr_certificate_get_type (void)
{
	static GType type = 0;
	if (!type) {
		static const GTypeInfo info = {
			sizeof (GcrCertificateIface),
			gcr_certificate_base_init,               /* base init */
			NULL,             /* base finalize */
			NULL,             /* class_init */
			NULL,             /* class finalize */
			NULL,             /* class data */
			0,
			0,                /* n_preallocs */
			NULL,             /* instance init */
		};
		type = g_type_register_static (G_TYPE_INTERFACE, "GcrCertificateIface", &info, 0);
		g_type_interface_add_prerequisite (type, G_TYPE_OBJECT);
	}
	
	return type;
}


/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

const guchar*
gcr_certificate_get_der_data (GcrCertificate *self, gsize *n_length)
{
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (GCR_CERTIFICATE_GET_INTERFACE (self)->get_der_data, NULL);
	return GCR_CERTIFICATE_GET_INTERFACE (self)->get_der_data (self, n_length);
}

gchar*
gcr_certificate_get_issuer_cn (GcrCertificate *self)
{
	return gcr_certificate_get_issuer_part (self, "cn");
}

gchar*
gcr_certificate_get_issuer_part (GcrCertificate *self, const char *part)
{
	ASN1_TYPE asn1;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	asn1 = parse_certificate_asn1 (self);
	g_return_val_if_fail (asn1, NULL);
	
	return egg_asn1_read_dn_part (asn1, "tbsCertificate.issuer.rdnSequence", part);
}

gchar*
gcr_certificate_get_issuer_dn (GcrCertificate *self)
{
	ASN1_TYPE asn1;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	asn1 = parse_certificate_asn1 (self);
	g_return_val_if_fail (asn1, NULL);
	
	return egg_asn1_read_dn (asn1, "tbsCertificate.issuer.rdnSequence"); 
}

gchar* 
gcr_certificate_get_subject_cn (GcrCertificate *self)
{
	return gcr_certificate_get_subject_part (self, "cn");
}

gchar* 
gcr_certificate_get_subject_part (GcrCertificate *self, const char *part)
{
	ASN1_TYPE asn1;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	asn1 = parse_certificate_asn1 (self);
	g_return_val_if_fail (asn1, NULL);
	
	return egg_asn1_read_dn_part (asn1, "tbsCertificate.subject.rdnSequence", part); 
}

gchar* 
gcr_certificate_get_subject_dn (GcrCertificate *self)
{
	ASN1_TYPE asn1;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	asn1 = parse_certificate_asn1 (self);
	g_return_val_if_fail (asn1, NULL);
	
	return egg_asn1_read_dn (asn1, "tbsCertificate.issuer.rdnSequence"); 	
}

GDate* 
gcr_certificate_get_issued_date (GcrCertificate *self)
{
	ASN1_TYPE asn1;
	GDate *date;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	asn1 = parse_certificate_asn1 (self);
	g_return_val_if_fail (asn1, NULL);
	
	date = g_date_new ();
	if (!egg_asn1_read_date (asn1, "tbsCertificate.validity.notBefore", date)) {
		g_date_free (date);
		return NULL;
	}
	
	return date;
}

GDate* 
gcr_certificate_get_expiry_date (GcrCertificate *self)
{
	ASN1_TYPE asn1;
	GDate *date;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	asn1 = parse_certificate_asn1 (self);
	g_return_val_if_fail (asn1, NULL);
	
	date = g_date_new ();
	if (!egg_asn1_read_date (asn1, "tbsCertificate.validity.notAfter", date)) {
		g_date_free (date);
		return NULL;
	}
	
	return date;
}

guchar*
gcr_certificate_get_fingerprint (GcrCertificate *self, GChecksumType type, gsize *n_digest)
{
	GChecksum *sum;
	guchar *digest;
	gssize length;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (n_digest, NULL);
	
	sum = digest_certificate (self, type);
	g_return_val_if_fail (sum, NULL);
	length = g_checksum_type_get_length (type);
	g_return_val_if_fail (length > 0, NULL);
	digest = g_malloc (length);
	*n_digest = length;
	g_checksum_get_digest (sum, digest, n_digest);
	g_checksum_free (sum);
	
	return digest;
}

gchar*
gcr_certificate_get_fingerprint_hex (GcrCertificate *self, GChecksumType type)
{
	GChecksum *sum;
	guchar *digest;
	gsize n_digest;
	gssize length;
	gchar *hex;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	sum = digest_certificate (self, type);
	g_return_val_if_fail (sum, NULL);
	length = g_checksum_type_get_length (type);
	g_return_val_if_fail (length > 0, NULL);
	digest = g_malloc (length);
	n_digest = length;
	g_checksum_get_digest (sum, digest, &n_digest);
	hex = egg_hex_encode_full (digest, n_digest, TRUE, ' ', 1);
	g_checksum_free (sum);
	g_free (digest);
	return hex;
}

guchar*
gcr_certificate_get_serial_number (GcrCertificate *self, gsize *n_length)
{
	ASN1_TYPE asn1;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	asn1 = parse_certificate_asn1 (self);
	g_return_val_if_fail (asn1, NULL);
	
	return egg_asn1_read_value (asn1, "tbsCertificate.serialNumber", n_length, g_realloc); 
}

gchar*
gcr_certificate_get_serial_number_hex (GcrCertificate *self)
{
	guchar *serial;
	gsize n_serial;
	gchar *hex;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	serial = gcr_certificate_get_serial_number (self, &n_serial);
	if (serial == NULL)
		return NULL;
	
	hex = egg_hex_encode (serial, n_serial);
	g_free (serial);
	return hex;
}
