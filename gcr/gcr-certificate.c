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

struct _GcrCertificatePrivate {
	/* Cache of data returned  from get_der_data() */ 
	ASN1_TYPE asn1;
	gconstpointer data;
	gsize n_data;
	
	/* When initialized with gcr_certificate_new_for_data() */
	guchar *owned_data;
	gsize n_owned_data;
};

G_DEFINE_TYPE (GcrCertificate, gcr_certificate, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static ASN1_TYPE
parse_certificate_asn1 (GcrCertificate *self)
{
	const guchar *data;
	gsize n_data;
	
	g_assert (GCR_IS_CERTIFICATE (self));
	
	data = gcr_certificate_get_der_data (self, &n_data);
	g_return_val_if_fail (data, NULL);

	if (self->pv->asn1 && n_data == self->pv->n_data && 
	    memcmp (data, self->pv->data, n_data) == 0)
		return self->pv->asn1;
	
	if (self->pv->asn1) {
		asn1_delete_structure (&self->pv->asn1);
		self->pv->asn1 = NULL;
		self->pv->data = NULL;
		self->pv->n_data = 0;
	}
	
	/* Cache is invalid or non existent */
	self->pv->asn1 = egg_asn1_decode ("PKIX1.Certificate", data, n_data);
	if (self->pv->asn1 == NULL) {
		g_warning ("encountered invalid or unparseable X509 DER certificate data.");
		return NULL;
	}
	
	self->pv->data = data;
	self->pv->n_data = n_data;

	return self->pv->asn1;
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

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static const guchar* 
gcr_certificate_real_get_der_data (GcrCertificate *self, gsize *n_data)
{
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (n_data, NULL);
	g_return_val_if_fail (self->pv->owned_data, NULL);
	
	/* This is called when we're not a base class */
	*n_data = self->pv->n_owned_data;
	return self->pv->owned_data;
}

static GObject* 
gcr_certificate_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GcrCertificate *self = GCR_CERTIFICATE (G_OBJECT_CLASS (gcr_certificate_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	
	
	return G_OBJECT (self);
}

static void
gcr_certificate_init (GcrCertificate *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_CERTIFICATE, GcrCertificatePrivate);
}

static void
gcr_certificate_dispose (GObject *obj)
{
	GcrCertificate *self = GCR_CERTIFICATE (obj);

	if (self->pv->asn1) {
		asn1_delete_structure (&self->pv->asn1);
		self->pv->data = NULL;
		self->pv->n_data = 0;
	}
    
	G_OBJECT_CLASS (gcr_certificate_parent_class)->dispose (obj);
}

static void
gcr_certificate_finalize (GObject *obj)
{
	GcrCertificate *self = GCR_CERTIFICATE (obj);
	
	g_assert (self->pv->asn1 == NULL);
	g_free (self->pv->owned_data);
	self->pv->owned_data = NULL;
	self->pv->n_owned_data = 0;

	G_OBJECT_CLASS (gcr_certificate_parent_class)->finalize (obj);
}

static void
gcr_certificate_set_property (GObject *obj, guint prop_id, const GValue *value, 
                              GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_certificate_get_property (GObject *obj, guint prop_id, GValue *value, 
                              GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_certificate_class_init (GcrCertificateClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
	gobject_class->constructor = gcr_certificate_constructor;
	gobject_class->dispose = gcr_certificate_dispose;
	gobject_class->finalize = gcr_certificate_finalize;
	gobject_class->set_property = gcr_certificate_set_property;
	gobject_class->get_property = gcr_certificate_get_property;
	
	klass->get_der_data = gcr_certificate_real_get_der_data;
    
	g_type_class_add_private (gobject_class, sizeof (GcrCertificatePrivate));

	_gcr_initialize ();
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GcrCertificate*
gcr_certificate_new_for_data (const guchar *data, gsize n_data)
{
	GcrCertificate *cert;
	
	g_return_val_if_fail (data, NULL);
	g_return_val_if_fail (n_data, NULL);
	
	cert = g_object_new (GCR_TYPE_CERTIFICATE, NULL);
	
	cert->pv->owned_data = g_memdup (data, n_data);
	cert->pv->n_owned_data = n_data;
	return cert;
}

const guchar*
gcr_certificate_get_der_data (GcrCertificate *self, gsize *n_length)
{
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (GCR_CERTIFICATE_GET_CLASS (self)->get_der_data, NULL);
	return GCR_CERTIFICATE_GET_CLASS (self)->get_der_data (self, n_length);
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
	gchar *hex;
	
	g_return_val_if_fail (GCR_IS_CERTIFICATE (self), NULL);
	
	sum = digest_certificate (self, type);
	g_return_val_if_fail (sum, NULL);
	hex = g_strdup (g_checksum_get_string (sum));
	g_checksum_free (sum);
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
