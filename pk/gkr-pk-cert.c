/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-cert.c - An x509 certificate

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

#include "gkr-pk-cert.h"
#include "gkr-pk-index.h"
#include "gkr-pk-netscape-trust.h"
#include "gkr-pk-object.h"
#include "gkr-pk-object-manager.h"
#include "gkr-pk-object-storage.h"
#include "gkr-pk-privkey.h"
#include "gkr-pk-pubkey.h"
#include "gkr-pk-util.h"

#include "common/gkr-crypto.h"
#include "common/gkr-location.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"

#include "pkix/gkr-pkix-asn1.h"
#include "pkix/gkr-pkix-der.h"

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

struct _GkrPkCertData {
	ASN1_TYPE asn1;
	guchar *raw;
	gsize n_raw;
	
	GkrPkPubkey *pubkey;
	GkrPkNetscapeTrust *netscape_trust;
};

G_DEFINE_TYPE (GkrPkCert, gkr_pk_cert, GKR_TYPE_PK_OBJECT);

static GQuark OID_BASIC_CONSTRAINTS;
static GQuark OID_ENHANCED_USAGE;

static GQuark OID_USAGE_SSH_AUTH;
static GQuark OID_USAGE_SERVER_AUTH;
static GQuark OID_USAGE_CLIENT_AUTH;
static GQuark OID_USAGE_CODE_SIGNING;
static GQuark OID_USAGE_EMAIL;
static GQuark OID_USAGE_TIME_STAMPING;
static GQuark OID_USAGE_IPSEC_ENDPOINT;	
static GQuark OID_USAGE_IPSEC_TUNNEL;
static GQuark OID_USAGE_IPSEC_USER;
static GQuark OID_USAGE_IKE_INTERMEDIATE;


/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void
init_quarks (void)
{
	#define QUARK(name, value) \
		name = g_quark_from_static_string(value)
 
 	QUARK (OID_BASIC_CONSTRAINTS, "2.5.29.19");
 	QUARK (OID_ENHANCED_USAGE, "2.5.29.37");
 	
 	QUARK (OID_USAGE_SSH_AUTH, "ssh-authentication");
	QUARK (OID_USAGE_SERVER_AUTH, "1.3.6.1.5.5.7.3.1");
	QUARK (OID_USAGE_CLIENT_AUTH, "1.3.6.1.5.5.7.3.2");
	QUARK (OID_USAGE_CODE_SIGNING, "1.3.6.1.5.5.7.3.3");
	QUARK (OID_USAGE_EMAIL, "1.3.6.1.5.5.7.3.4");
	QUARK (OID_USAGE_TIME_STAMPING, "1.3.6.1.5.5.7.3.8");
	QUARK (OID_USAGE_IPSEC_ENDPOINT, "1.3.6.1.5.5.7.3.5");
	QUARK (OID_USAGE_IPSEC_TUNNEL, "1.3.6.1.5.5.7.3.6");
	QUARK (OID_USAGE_IPSEC_USER, "1.3.6.1.5.5.7.3.7");
	QUARK (OID_USAGE_IKE_INTERMEDIATE, "1.3.6.1.5.5.8.2.2");

	#undef QUARK
}

static CK_RV
load_certificate (GkrPkCert *cert)
{
	GkrPkObject *obj;
	GError *err = NULL;

	if (cert->data->asn1)
		return CKR_OK;
		
	obj = GKR_PK_OBJECT (cert);
	
	g_return_val_if_fail (obj->storage, CKR_GENERAL_ERROR);	
	if (!gkr_pk_object_storage_load_complete (obj->storage, obj, &err)) {
		g_message ("couldn't load certificate at: %s: %s", 
		           g_quark_to_string (obj->location),
		           err && err->message ? err->message : "");
		g_error_free (err);
		return CKR_GENERAL_ERROR;
	}

	/* This can happen if the user cancels out of a dialog */
	if (!cert->data->asn1)
		return CKR_FUNCTION_CANCELED;

	return CKR_OK;
}

static GkrPkPubkey* 
get_public_key (GkrPkCert *cert)
{
	gcry_sexp_t s_key = NULL;
	GkrPkObject *obj;
	GkrPkixResult res;
	guchar *data;
	gsize n_data;

	if (cert->data->pubkey)
		return cert->data->pubkey;

	if (load_certificate (cert) != CKR_OK)
		return NULL;
		
	obj = GKR_PK_OBJECT (cert);
	
	/* Generate a raw public key from our certificate */
	data = gkr_pkix_asn1_encode (cert->data->asn1, "tbsCertificate.subjectPublicKeyInfo", &n_data, NULL);
	g_return_val_if_fail (data, NULL);
	
	res = gkr_pkix_der_read_public_key_info (data, n_data, &s_key);
	g_free (data);
	
	if (res != GKR_PKIX_SUCCESS) {
		g_warning ("invalid public-key in certificate: %s", g_quark_to_string (obj->location));
		return NULL;
	}
	
	g_return_val_if_fail (s_key, NULL);
	cert->data->pubkey = gkr_pk_pubkey_instance (obj->manager, obj->location, s_key);
	
	return cert->data->pubkey;
}

static void
initialize_certificate (GkrPkCert *cert, ASN1_TYPE asn1)
{
	GkrPkCertData *data = cert->data;

	g_free(data->raw);
	data->raw = NULL;
	data->n_raw = 0;
	
	if (data->pubkey)
		g_object_unref (data->pubkey);
	data->pubkey = NULL;
	
	if (data->netscape_trust)
		g_object_unref (data->netscape_trust);
	data->netscape_trust = NULL;

	if (data->asn1)
		asn1_delete_structure (&data->asn1);
	data->asn1 = asn1;
			
	if (!asn1)
		return;

	/* The raw certificate data */
	data->raw = gkr_pkix_asn1_encode (data->asn1, "", &data->n_raw, NULL);
	g_return_if_fail (data->raw);
			
	/* We always have a companion netscape trust object */
	data->netscape_trust = gkr_pk_netscape_trust_new (GKR_PK_OBJECT (cert)->manager, cert);

	/* Try and initialize the public key object */
	get_public_key (cert);
}

static gboolean
has_private_key (GkrPkCert *cert)
{
	gkrconstunique uni;
	
	uni = gkr_pk_cert_get_keyid (cert);
	g_return_val_if_fail (uni, FALSE);
	
	return gkr_pk_object_manager_find_by_id (GKR_PK_OBJECT (cert)->manager, GKR_TYPE_PK_PRIVKEY, uni) != NULL;	
}

static gboolean 
has_certificate_purposes (GkrPkCert *cert)
{
	GkrPkObject *obj = GKR_PK_OBJECT (cert);
	
	/* Check if the index has such a value */
	if (gkr_pk_index_has_value (obj, "purposes"))
		return TRUE;

	if (gkr_pk_cert_has_extension (cert, OID_ENHANCED_USAGE, NULL))
		return TRUE;
		
	return FALSE;
}

static CK_RV
lookup_certificate_purposes (GkrPkCert *cert, GQuark **oids)
{
	GkrPkObject *obj = GKR_PK_OBJECT (cert);
	GkrPkixResult res;
	guchar *extension;
	gsize n_extension;
	CK_RV ret;
	
	if ((ret = load_certificate (cert)) != CKR_OK)
		return ret;
			
	*oids = NULL;
	
	/* Look in the index if the purposes have been overridden there */	
	if (gkr_pk_index_has_value (obj, "purposes")) {
		*oids = gkr_pk_index_get_quarks (obj, "purposes");

	/* Otherwise look in the certificate */		
	} else {	
		extension = gkr_pk_cert_get_extension (cert, OID_ENHANCED_USAGE, &n_extension, NULL);
	
		/* No enhanced usage noted, any are allowed */
		if (!extension)
			return CKR_OK;

		res = gkr_pkix_der_read_enhanced_usage (extension, n_extension, oids);
		g_free (extension);
	
		if (res != GKR_PKIX_SUCCESS) {
			g_warning ("invalid enhanced usage in certificate");
			return CKR_GENERAL_ERROR;
		}
	}
	
	return CKR_OK;
}


static gboolean
check_certificate_purpose (GkrPkCert *cert, GQuark oid)
{
	GQuark* usages;
	gboolean ret;
	
	if (lookup_certificate_purposes (cert, &usages) != CKR_OK)
		return FALSE;
		
	/* No usages noted, any are allowed */
	if (!usages)
		return TRUE;
		
	ret = gkr_pk_index_quarks_has (usages, oid);
	gkr_pk_index_quarks_free (usages);
	
	return ret;
}

static CK_RV
read_certificate_purpose (GkrPkCert *cert, GQuark oid, CK_ATTRIBUTE_PTR attr)
{
	gboolean value = check_certificate_purpose (cert, oid);
	gkr_pk_attribute_set_boolean (attr, value);
	return CKR_OK;
}

static CK_RV
read_certificate_purposes (GkrPkCert *cert, CK_ATTRIBUTE_PTR attr)
{
	GQuark *quarks, *q;
	GString *result;
	CK_RV ret;
	
	if ((ret = load_certificate (cert)) != CKR_OK)
		return ret;
	
	ret = lookup_certificate_purposes (cert, &quarks);
	if (ret != CKR_OK)
		return ret;
		
	/* Convert into a space delimited string */
	result = g_string_sized_new (128);
	for (q = quarks; q && *q; ++q) {
		g_string_append (result, g_quark_to_string (*q));
		g_string_append_c (result, ' ');
	}
	
	gkr_pk_index_quarks_free (quarks);
	
	attr->ulValueLen = result->len;
	attr->pValue = g_string_free (result, FALSE);
	return CKR_OK;
}

static gint
find_certificate_extension (GkrPkCert *cert, GQuark oid)
{
	GQuark exoid;
	gchar *name;
	guint i;
	int res, len;
	
	g_assert (oid);
	g_assert (GKR_IS_PK_CERT (cert));
	g_assert (cert->data->asn1);
	
	for(i = 1; TRUE; ++i) {
		
		/* Make sure it is present */
		len = 0;
		name = g_strdup_printf ("tbsCertificate.extensions.?%u", i);
		res = asn1_read_value (cert->data->asn1, name, NULL, &len);
		g_free (name);
		if (res == ASN1_ELEMENT_NOT_FOUND)
			break;

		/* See if it's the same */
		name = g_strdup_printf ("tbsCertificate.extensions.?%u.extnID", i);
		exoid = gkr_pkix_asn1_read_oid (cert->data->asn1, name);
		g_free (name);

		if(exoid == oid)
			return i;		
	}
	
	return 0;
} 

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_cert_init (GkrPkCert *cert)
{
	cert->data = G_TYPE_INSTANCE_GET_PRIVATE (cert, GKR_TYPE_PK_CERT, GkrPkCertData);
	memset (cert->data, 0, sizeof (GkrPkCertData));
}

static void
gkr_pk_cert_get_property (GObject *obj, guint prop_id, GValue *value, 
                          GParamSpec *pspec)
{
	GkrPkCert *cert = GKR_PK_CERT (obj);

	switch (prop_id) {
	case PROP_ASN1_TREE:
		g_value_set_pointer (value, cert->data->asn1);
		break;
	}
}

static void
gkr_pk_cert_set_property (GObject *obj, guint prop_id, const GValue *value, 
                          GParamSpec *pspec)
{
	GkrPkCert *cert = GKR_PK_CERT (obj);

	switch (prop_id) {
	case PROP_ASN1_TREE:
		initialize_certificate (cert, g_value_get_pointer (value));
		break;
	}
}

static CK_RV
gkr_pk_cert_get_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkCert *cert = GKR_PK_CERT (obj);
	const guchar *cdata = NULL;
	gkrconstunique keyid;
	CK_ULONG value;
	gchar *index;
	guchar *data;
	gsize n_data;
	time_t time;
	CK_RV ret;
	
	g_assert (!attr->pValue);
	
	switch (attr->type)
	{
	case CKA_GNOME_PURPOSE_RESTRICTED:
		gkr_pk_attribute_set_boolean (attr, has_certificate_purposes (cert));
		return CKR_OK;
		
	case CKA_GNOME_PURPOSE_SSH_AUTH:
		return read_certificate_purpose (cert, OID_USAGE_SSH_AUTH, attr);
		
	case CKA_GNOME_PURPOSE_SERVER_AUTH:
		return read_certificate_purpose (cert, OID_USAGE_SERVER_AUTH, attr);
		
	case CKA_GNOME_PURPOSE_CLIENT_AUTH:
		return read_certificate_purpose (cert, OID_USAGE_CLIENT_AUTH, attr);
		
	case CKA_GNOME_PURPOSE_CODE_SIGNING:
		return read_certificate_purpose (cert, OID_USAGE_CODE_SIGNING, attr);
		
	case CKA_GNOME_PURPOSE_EMAIL_PROTECTION:
		return read_certificate_purpose (cert, OID_USAGE_EMAIL, attr);
		
	case CKA_GNOME_PURPOSE_IPSEC_END_SYSTEM:
		return read_certificate_purpose (cert, OID_USAGE_IPSEC_ENDPOINT, attr);
		
	case CKA_GNOME_PURPOSE_IPSEC_TUNNEL:
		return read_certificate_purpose (cert, OID_USAGE_IPSEC_TUNNEL, attr);
		
	case CKA_GNOME_PURPOSE_IPSEC_USER:
		return read_certificate_purpose (cert, OID_USAGE_IPSEC_USER, attr);
		
	case CKA_GNOME_PURPOSE_TIME_STAMPING:
		return read_certificate_purpose (cert, OID_USAGE_TIME_STAMPING, attr);
		
	/* TODO: Until we can figure out a trust system */
	case CKA_TRUSTED:
		gkr_pk_attribute_set_boolean (attr, CK_FALSE);
		return CKR_OK;
		
	case CKA_CLASS:
		gkr_pk_attribute_set_ulong (attr, CKO_CERTIFICATE);
		return CKR_OK;
		
	case CKA_CERTIFICATE_TYPE:
		gkr_pk_attribute_set_ulong (attr, CKC_X_509);
		return CKR_OK;
		
	case CKA_CERTIFICATE_CATEGORY:
		if ((ret = load_certificate (cert)) != CKR_OK)
			return ret;
		value = 0; /* unknown */
		data = gkr_pk_cert_get_extension (cert, OID_BASIC_CONSTRAINTS, &n_data, NULL);
		if (data) {
			GkrPkixResult res;
			gboolean is_ca;

			res = gkr_pkix_der_read_basic_constraints (data, n_data, &is_ca, NULL);
			g_free (data);
			if (res != GKR_PKIX_SUCCESS)
				return CKR_GENERAL_ERROR;
			if (is_ca)
				value = 2; /* authority */
		}
		gkr_pk_attribute_set_ulong (attr, value);
		return CKR_OK;
	
	case CKA_GNOME_USER_TRUST:
		value = CKT_GNOME_UNKNOWN;
		
		/* Explicity set? */
		index = gkr_pk_index_get_string (obj, "user-trust");
		if (index) {
			if (g_str_equal (index, "trusted"))
				value = CKT_GNOME_TRUSTED;
			else if (g_str_equal (index, "untrusted"))
				value = CKT_GNOME_UNTRUSTED;
			g_free (index);

		/* With a private key it's trusted by default */				
		} else if (has_private_key (cert)) {
			value = CKT_GNOME_TRUSTED;	
		} 
		gkr_pk_attribute_set_ulong (attr, value);
		return CKR_OK;
		
	case CKA_ID:
		if ((ret = load_certificate (cert)) != CKR_OK)
			return ret;
		keyid = gkr_pk_cert_get_keyid (cert);
		if (!keyid) 
			return CKR_GENERAL_ERROR;
		data = (CK_VOID_PTR)gkr_unique_get_raw (keyid, &n_data);
		gkr_pk_attribute_set_data (attr, data, n_data);
		return CKR_OK;


	case CKA_SUBJECT:
		if ((ret = load_certificate (cert)) != CKR_OK)
			return ret;
		cdata = gkr_pkix_asn1_read_element (cert->data->asn1, cert->data->raw, cert->data->n_raw, 
		                                    "tbsCertificate.subject", &n_data);
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		gkr_pk_attribute_set_data (attr, cdata, n_data);
		return CKR_OK;
		
	case CKA_ISSUER:
		if ((ret = load_certificate (cert)) != CKR_OK)
			return ret;
		cdata = gkr_pkix_asn1_read_element (cert->data->asn1, cert->data->raw, cert->data->n_raw, 
		                                    "tbsCertificate.issuer", &n_data);
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		gkr_pk_attribute_set_data (attr, cdata, n_data);
		return CKR_OK;
		
	case CKA_SERIAL_NUMBER:
		if ((ret = load_certificate (cert)) != CKR_OK)
			return ret;
		data = gkr_pkix_asn1_read_value (cert->data->asn1, "tbsCertificate.serialNumber", &n_data, NULL);
		g_return_val_if_fail (data, CKR_GENERAL_ERROR);
		gkr_pk_attribute_set_data (attr, data, n_data);
		g_free (data);
		return CKR_OK;
		
	case CKA_VALUE:
		if ((ret = load_certificate (cert)) != CKR_OK)
			return ret;
		gkr_pk_attribute_set_data (attr, cert->data->raw, cert->data->n_raw);
		return CKR_OK;

	case CKA_CHECK_VALUE:
		if ((ret = load_certificate (cert)) != CKR_OK)
			return ret;
		n_data = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
		g_return_val_if_fail (n_data && n_data > 3, CKR_GENERAL_ERROR);
		
		data = g_new0 (guchar, n_data);
		gcry_md_hash_buffer (GCRY_MD_SHA1, data, cert->data->raw, cert->data->n_raw);
		
		gkr_pk_attribute_set_data (attr, data, 3);
		g_free (data);
		return CKR_OK;
		
	case CKA_START_DATE:
	case CKA_END_DATE:
		if ((ret = load_certificate (cert)) != CKR_OK)
			return ret;
		if (!gkr_pkix_asn1_read_time (cert->data->asn1, 
		                              attr->type == CKA_START_DATE ? 
		                                       "tbsCertificate.validity.notBefore" : 
		                                       "tbsCertificate.validity.notAfter",
		                              &time))
			g_return_val_if_reached (CKR_GENERAL_ERROR);
		gkr_pk_attribute_set_date (attr, time);
		return CKR_OK;
	
	/* These are only used for strange online certificates which we don't support */	
	case CKA_URL:
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		return CKR_ATTRIBUTE_TYPE_INVALID;	

	case CKA_GNOME_PURPOSE_OIDS:
		return read_certificate_purposes (cert, attr);

	default:
		break;
	};

	return GKR_PK_OBJECT_CLASS (gkr_pk_cert_parent_class)->get_attribute (obj, attr);
}

static guchar*
gkr_pk_cert_serialize (GkrPkObject *obj, const gchar *password, gsize *n_data)
{
	GkrPkCert *cert = GKR_PK_CERT (obj);

	if (load_certificate (cert) != CKR_OK)
		return NULL;

	g_return_val_if_fail (cert->data->raw, NULL);
	g_return_val_if_fail (cert->data->n_raw, NULL);
	
	*n_data = cert->data->n_raw;
	return g_memdup	(cert->data->raw, cert->data->n_raw);
}

static void
gkr_pk_cert_finalize (GObject *obj)
{
	GkrPkCert *cert = GKR_PK_CERT (obj);

	g_free (cert->data->raw);
	cert->data->raw = NULL;

	if (cert->data->asn1)
		asn1_delete_structure (&cert->data->asn1);
	cert->data->asn1 = NULL;
	
	G_OBJECT_CLASS (gkr_pk_cert_parent_class)->finalize (obj);
}


static void
gkr_pk_cert_class_init (GkrPkCertClass *klass)
{
	GObjectClass *gobject_class;
	GkrPkObjectClass *parent_class;
	
	init_quarks ();
	
	gobject_class = (GObjectClass*)klass;

	gkr_pk_cert_parent_class = g_type_class_peek_parent (klass);
	
	parent_class = GKR_PK_OBJECT_CLASS (klass);
	parent_class->get_attribute = gkr_pk_cert_get_attribute;
	parent_class->serialize = gkr_pk_cert_serialize;
	
	gobject_class->get_property = gkr_pk_cert_get_property;
	gobject_class->set_property = gkr_pk_cert_set_property;
	gobject_class->finalize = gkr_pk_cert_finalize;
	
	g_object_class_install_property (gobject_class, PROP_ASN1_TREE,
		g_param_spec_pointer ("asn1-tree", "ASN1 Certificate", "Raw Certificate Object",
		              G_PARAM_READWRITE));

	g_type_class_add_private (gobject_class, sizeof (GkrPkCertData));
}

GkrPkCert*
gkr_pk_cert_new (GkrPkObjectManager *manager, GQuark location, ASN1_TYPE asn1)
{
	gkrunique unique = NULL;
	GkrPkCert *cert;
	guchar *raw;
	gsize n_raw;
	
	/* TODO: A more efficient way? */
	if (asn1) {
		raw = gkr_pkix_asn1_encode (asn1, "", &n_raw, NULL);
		g_return_val_if_fail (raw, NULL);
		unique = gkr_unique_new_digest (raw, n_raw);
	}
	
	cert = g_object_new (GKR_TYPE_PK_CERT, "location", location, 
	                     "unique", unique, "manager", manager,  
	                     "asn1-tree", asn1, NULL);
	                     
	gkr_unique_free (unique);
	return cert;
}

CK_RV
gkr_pk_cert_create (GkrPkObjectManager* manager, GArray* array, 
                    GkrPkObject **object)
{
	ASN1_TYPE asn;
	CK_ATTRIBUTE_PTR attr;
 	CK_KEY_TYPE type;
 	
	g_return_val_if_fail (GKR_IS_PK_OBJECT_MANAGER (manager), CKR_GENERAL_ERROR);
	g_return_val_if_fail (array, CKR_GENERAL_ERROR);
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);
	
	*object = NULL;
	
	if (!gkr_pk_attributes_ulong (array, CKA_CERTIFICATE_TYPE, &type))
 		return CKR_TEMPLATE_INCOMPLETE;

	if (type != CKC_X_509)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	attr = gkr_pk_attributes_find (array, CKA_VALUE);
	if (!attr)
		return CKR_TEMPLATE_INCOMPLETE;
		
	g_return_val_if_fail (attr->pValue, CKR_GENERAL_ERROR);
	g_return_val_if_fail (attr->ulValueLen, CKR_GENERAL_ERROR);
	
	if (gkr_pkix_der_read_certificate (attr->pValue, attr->ulValueLen, &asn) != GKR_PKIX_SUCCESS)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	
	/* All the attributes that we used up */	
	gkr_pk_attributes_consume (array, CKA_CERTIFICATE_TYPE, CKA_VALUE, -1);
	
	*object = GKR_PK_OBJECT (gkr_pk_cert_new (manager, 0, asn));
	return CKR_OK;
}

gboolean
gkr_pk_cert_has_extension (GkrPkCert *cert, GQuark oid, gboolean *critical)
{
	gchar *name;
	guchar *val;
	gsize n_val;
	gint i;
	
	g_return_val_if_fail (GKR_IS_PK_CERT (cert), FALSE);
	g_return_val_if_fail (oid, FALSE);

	if (load_certificate (cert) != CKR_OK)
		return FALSE;

	i = find_certificate_extension (cert, oid);
	if (i <= 0)
		return FALSE;
			
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
	
	return TRUE;
}

guchar*
gkr_pk_cert_get_extension (GkrPkCert *cert, GQuark oid, gsize *n_extension, 
                           gboolean *critical)
{
	gchar *name;
	guchar *val;
	gsize n_val;
	gint i;
	
	g_return_val_if_fail (GKR_IS_PK_CERT (cert), NULL);
	g_return_val_if_fail (cert->data->asn1, NULL);
	g_return_val_if_fail (oid, NULL);
	g_return_val_if_fail (n_extension, NULL);
	
	i = find_certificate_extension (cert, oid);
	if (i <= 0)
		return NULL;
		
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

gkrconstunique
gkr_pk_cert_get_keyid (GkrPkCert *cert)
{
	GkrPkPubkey *pub;
	
	g_return_val_if_fail (GKR_IS_PK_CERT (cert), NULL);
	
	/* Access via public key */
	pub = get_public_key (cert);
	return gkr_pk_pubkey_get_keyid (pub);
}

const guchar*
gkr_pk_cert_get_raw (GkrPkCert *cert, gsize *n_raw)
{
	g_return_val_if_fail (GKR_IS_PK_CERT (cert), NULL);
	*n_raw = cert->data->n_raw;
	return cert->data->raw;	
}
