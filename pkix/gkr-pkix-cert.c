/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-cert.c - An x509 certificate

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-pkix-asn1.h"
#include "gkr-pkix-cert.h"
#include "gkr-pkix-der.h"

#include "common/gkr-crypto.h"
#include "common/gkr-location.h"

#include "pk/gkr-pk-pubkey.h"
#include "pk/gkr-pk-object.h"
#include "pk/gkr-pk-object-manager.h"
#include "pk/gkr-pk-util.h"

#include <glib.h>
#include <glib-object.h>

#include <gcrypt.h>
#include <libtasn1.h>

#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------------------
 * DECLARATIONS
 */

enum {
	PROP_0,
	PROP_ASN1_TREE
};

struct _GkrPkixCertData {
	ASN1_TYPE asn1;
	GkrPkPubkey *pubkey;
	guchar *raw;
	gsize n_raw;
};

G_DEFINE_TYPE (GkrPkixCert, gkr_pkix_cert, GKR_TYPE_PK_OBJECT);

static GQuark OID_BASIC_CONSTRAINTS;

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void
init_quarks (void)
{
	#define QUARK(name, value) \
		name = g_quark_from_static_string(value)
 
 	QUARK (OID_BASIC_CONSTRAINTS, "2.5.29.19");
	
	#undef QUARK
}

static GkrPkPubkey* 
get_public_key (GkrPkixCert *cert)
{
	gcry_sexp_t s_key = NULL;
	GkrPkObject *obj;
	GkrParseResult res;
	guchar *data;
	gsize n_data;

	g_return_val_if_fail (cert->data->asn1, NULL);
	
	if (cert->data->pubkey)
		return cert->data->pubkey;

	obj = GKR_PK_OBJECT (cert);
	
	/* Generate a raw public key from our certificate */
	data = gkr_pkix_asn1_encode (cert->data->asn1, "tbsCertificate.subjectPublicKeyInfo", &n_data, NULL);
	g_return_val_if_fail (data, NULL);
	
	res = gkr_pkix_der_read_public_key_info (data, n_data, &s_key);
	g_free (data);
	
	if (res != GKR_PARSE_SUCCESS) {
		g_warning ("invalid public-key in certificate: %s", g_quark_to_string (obj->location));
		return NULL;
	}
	
	g_return_val_if_fail (s_key, NULL);
	cert->data->pubkey = gkr_pk_pubkey_instance (obj->location, s_key);
	
	return cert->data->pubkey;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pkix_cert_init (GkrPkixCert *cert)
{
	cert->data = G_TYPE_INSTANCE_GET_PRIVATE (cert, GKR_TYPE_PKIX_CERT, GkrPkixCertData);
	memset (cert->data, 0, sizeof (GkrPkixCertData));
}

static void
gkr_pkix_cert_get_property (GObject *obj, guint prop_id, GValue *value, 
                          GParamSpec *pspec)
{
	GkrPkixCert *cert = GKR_PKIX_CERT (obj);

	switch (prop_id) {
	case PROP_ASN1_TREE:
		g_value_set_pointer (value, cert->data->asn1);
		break;
	}
}

static void
gkr_pkix_cert_set_property (GObject *obj, guint prop_id, const GValue *value, 
                          GParamSpec *pspec)
{
	GkrPkixCert *cert = GKR_PKIX_CERT (obj);

	switch (prop_id) {
	case PROP_ASN1_TREE:
		if (cert->data->asn1)
			asn1_delete_structure (&cert->data->asn1);
		g_free(cert->data->raw);
		cert->data->raw = NULL;
		cert->data->n_raw = 0;
		/* TODO: Verify the certificate */
		cert->data->asn1 = g_value_get_pointer (value);
		if (cert->data->asn1) {
			cert->data->raw = gkr_pkix_asn1_encode (cert->data->asn1, "", 
			                                        &cert->data->n_raw, NULL);
			g_return_if_fail (cert->data->raw);			
		}
		break;
	}
}
            
static CK_RV 
gkr_pkix_cert_get_bool_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	gboolean val;
	
	switch (attr->type)
	{
	case CKA_TOKEN:
		val = TRUE;
		break;
	
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
		val = FALSE;
		break;

	/* TODO: Until we can figure out a trust system */
	case CKA_TRUSTED:
		val = FALSE;
		break;
		
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	gkr_pk_attribute_set_boolean (attr, val);
	return CKR_OK;
}

static CK_RV 
gkr_pkix_cert_get_ulong_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkixCert *cert = GKR_PKIX_CERT (obj);
	guint val;
	guchar *extension;
	gsize n_extension;
	gboolean is_ca;
	int res;
	
	switch (attr->type)
	{
	case CKA_CLASS:
		val = CKO_CERTIFICATE;
		break;
		
	case CKA_CERTIFICATE_TYPE:
		val = CKC_X_509;
		break;
		
	case CKA_CERTIFICATE_CATEGORY:
		extension = gkr_pkix_cert_get_extension (cert, OID_BASIC_CONSTRAINTS, &n_extension, NULL);
		if (!extension)
			return CKR_GENERAL_ERROR;
		
		res = gkr_pkix_der_read_basic_constraints (extension, n_extension, &is_ca, NULL);
		g_free (extension);
		if(res != GKR_PARSE_SUCCESS)
			return CKR_GENERAL_ERROR;
		
		if(is_ca)
			val = 2; /* authority */
		else 
			val = 0; /* unknown */
		break;
		
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	gkr_pk_attribute_set_uint (attr, val);
	return CKR_OK;
}

static CK_RV
gkr_pkix_cert_get_data_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkixCert *cert = GKR_PKIX_CERT (obj);
	const guchar *cdata = NULL;
	gkrconstunique keyid;
	gchar *label;
	guchar *data;
	gsize n_data;
	
	g_assert (!attr->pValue);
	
	switch (attr->type)
	{
	case CKA_LABEL:
		g_object_get (obj, "label", &label, NULL);
		if (!label)
			label = gkr_location_to_display (obj->location);
		gkr_pk_attribute_set_string (attr, label);
		g_free (label);
		return CKR_OK;
		
	case CKA_ID:
		keyid = gkr_pkix_cert_get_keyid (cert);
		if (!keyid) 
			return CKR_GENERAL_ERROR;
		data = (CK_VOID_PTR)gkr_unique_get_raw (keyid, &n_data);
		gkr_pk_attribute_set_data (attr, data, n_data);
		return CKR_OK;


	case CKA_SUBJECT:
		cdata = gkr_pkix_asn1_read_element (cert->data->asn1, cert->data->raw, cert->data->n_raw, 
		                                    "tbsCertificate.subject", &n_data);
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		gkr_pk_attribute_set_data (attr, cdata, n_data);
		return CKR_OK;
		
	case CKA_ISSUER:
		cdata = gkr_pkix_asn1_read_element (cert->data->asn1, cert->data->raw, cert->data->n_raw, 
		                                    "tbsCertificate.issuer", &n_data);
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		gkr_pk_attribute_set_data (attr, cdata, n_data);
		return CKR_OK;
		
	case CKA_SERIAL_NUMBER:
		data = gkr_pkix_asn1_read_value (cert->data->asn1, "tbsCertificate.serialNumber", &n_data, NULL);
		g_return_val_if_fail (data, CKR_GENERAL_ERROR);
		gkr_pk_attribute_set_data (attr, data, n_data);
		g_free (data);
		return CKR_OK;
		
	case CKA_VALUE:
		gkr_pk_attribute_set_data (attr, cert->data->raw, cert->data->n_raw);
		return CKR_OK;

	case CKA_CHECK_VALUE:
		n_data = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
		g_return_val_if_fail (n_data && n_data > 3, CKR_GENERAL_ERROR);
		
		data = g_new0 (guchar, n_data);
		gcry_md_hash_buffer (GCRY_MD_SHA1, data, cert->data->raw, cert->data->n_raw);
		
		gkr_pk_attribute_set_data (attr, data, 3);
		g_free (data);
		return CKR_OK;
	
	/* These are only used for strange online certificates which we don't support */	
	case CKA_URL:
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		return CKR_ATTRIBUTE_TYPE_INVALID;	


	default:
		break;
	};

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV 
gkr_pkix_cert_get_date_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkixCert *cert = GKR_PKIX_CERT (obj);
	time_t time;
	
	switch (attr->type) 
	{
	case CKA_START_DATE:
		if (!gkr_pkix_asn1_read_time (cert->data->asn1, "tbsCertificate.validity.notBefore", &time))
			g_return_val_if_reached (CKR_GENERAL_ERROR);
		break;
	
	case CKA_END_DATE:
		if (!gkr_pkix_asn1_read_time (cert->data->asn1, "tbsCertificate.validity.notAfter", &time))
			g_return_val_if_reached (CKR_GENERAL_ERROR);
		break;
	
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	gkr_pk_attribute_set_date (attr, time);
	return CKR_OK;
}

static void
gkr_pkix_cert_finalize (GObject *obj)
{
	GkrPkixCert *cert = GKR_PKIX_CERT (obj);

	g_free (cert->data->raw);
	cert->data->raw = NULL;

	if (cert->data->asn1)
		asn1_delete_structure (&cert->data->asn1);
	cert->data->asn1 = NULL;
	
	G_OBJECT_CLASS (gkr_pkix_cert_parent_class)->finalize (obj);
}


static void
gkr_pkix_cert_class_init (GkrPkixCertClass *klass)
{
	GObjectClass *gobject_class;
	GkrPkObjectClass *parent_class;
	
	init_quarks ();
	
	gobject_class = (GObjectClass*)klass;

	gkr_pkix_cert_parent_class = g_type_class_peek_parent (klass);
	
	parent_class = GKR_PK_OBJECT_CLASS (klass);
	parent_class->get_bool_attribute = gkr_pkix_cert_get_bool_attribute;
	parent_class->get_ulong_attribute = gkr_pkix_cert_get_ulong_attribute;
	parent_class->get_data_attribute = gkr_pkix_cert_get_data_attribute;
	parent_class->get_date_attribute = gkr_pkix_cert_get_date_attribute;
	
	gobject_class->get_property = gkr_pkix_cert_get_property;
	gobject_class->set_property = gkr_pkix_cert_set_property;
	gobject_class->finalize = gkr_pkix_cert_finalize;
	
	g_object_class_install_property (gobject_class, PROP_ASN1_TREE,
		g_param_spec_pointer ("asn1-tree", "ASN1 Certificate", "Raw Certificate Object",
		              G_PARAM_READWRITE));

	g_type_class_add_private (gobject_class, sizeof (GkrPkixCertData));
}

GkrPkixCert*
gkr_pkix_cert_new (GQuark location, ASN1_TYPE asn1)
{
	return g_object_new (GKR_TYPE_PKIX_CERT, "location", location, "asn1-tree", asn1, NULL);
}

guchar*
gkr_pkix_cert_get_extension (GkrPkixCert *cert, GQuark oid, gsize *n_extension, 
                             gboolean *critical)
{
	GQuark exoid;
	gchar *name;
	guchar *val;
	gsize n_val;
	guint i;
	int len, res;
	
	g_return_val_if_fail (GKR_IS_PKIX_CERT (cert), NULL);
	g_return_val_if_fail (oid, NULL);
	g_return_val_if_fail (n_extension, NULL);
	
	
	for(i = 0; TRUE; ++i)
	{
		/* Make sure it is present */
		len = 0;
		name = g_strdup_printf ("tbsCertificate.extensions.?%u", i);
		res = asn1_read_value (cert->data->asn1, name, NULL, &len);
		g_free (name);
		if (res == ASN1_ELEMENT_NOT_FOUND)
			break;

		/* See if it's the same */
		name = g_strdup_printf ("tbsCertificate.extensions.?%u.extnID", i);
		exoid = gkr_pkix_asn1_read_quark (cert->data->asn1, name);
		g_free (name);

		if(exoid != oid)
			continue;
			
		/* Read the critical status */
		if(critical) {
			name = g_strdup_printf ("tbsCertificate.extensions.?%u.critical", i);
			val = gkr_pkix_asn1_read_value (cert->data->asn1, name, &n_val, NULL);
			g_free (name);
			if (!val || n_val < 1 || val[0] != 'T')
				*critical = FALSE;
			else
				*critical = TRUE;
			g_free (val);
		}
		
		/* And the extension value */
		name = g_strdup_printf ("tbsCertificate.extensions.?%u.extnValue", i);
		val = gkr_pkix_asn1_read_value (cert->data->asn1, name, n_extension, NULL);
		g_free (name);
		
		return val;
	}
	
	return NULL;	
}

gkrconstunique
gkr_pkix_cert_get_keyid (GkrPkixCert *cert)
{
	GkrPkPubkey *pub;
	
	g_return_val_if_fail (GKR_IS_PKIX_CERT (cert), NULL);
	
	/* Access via public key */
	pub = get_public_key (cert);
	return gkr_pk_pubkey_get_keyid (pub);
}
