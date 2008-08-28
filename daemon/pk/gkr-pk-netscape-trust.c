/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-netscape-trust.c - Combination of Trust and Usage for a Certificate

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
#include "gkr-pk-netscape-trust.h"
#include "gkr-pk-object.h"
#include "gkr-pk-manager.h"
#include "gkr-pk-util.h"

#include "common/gkr-location.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11n.h"
#include "pkcs11/pkcs11g.h"

#include "pkix/gkr-pkix-constants.h"
#include "pkix/gkr-pkix-der.h"

#include <glib.h>
#include <glib-object.h>

#include <libtasn1.h>

#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------------------
 * DECLARATIONS
 */

enum {
	PROP_0,
	PROP_CERT
};

G_DEFINE_TYPE (GkrPkNetscapeTrust, gkr_pk_netscape_trust, GKR_TYPE_PK_OBJECT);

static GQuark OID_KEY_USAGE;

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void
init_quarks (void)
{
	#define QUARK(name, value) \
		name = g_quark_from_static_string(value)
 
 	QUARK (OID_KEY_USAGE, "2.5.29.15");

	#undef QUARK
}

static CK_RV
certificate_attribute (GkrPkNetscapeTrust *trust, CK_ATTRIBUTE_PTR result)
{
	g_return_val_if_fail (trust->certificate, CKR_GENERAL_ERROR);
	return gkr_pk_object_get_attribute (GKR_PK_OBJECT (trust->certificate), result);
}

static CK_RV
has_key_usage (GkrPkNetscapeTrust *trust, guint check, CK_ULONG *val)
{
	GkrPkixResult res;
	guchar *extension;
	gsize n_extension;
	guint usage;

	g_return_val_if_fail (trust->certificate, CKR_GENERAL_ERROR);
	*val = CKT_NETSCAPE_TRUST_UNKNOWN;
	
	/* Find out the key usage */
	extension = gkr_pk_cert_get_extension (trust->certificate, OID_KEY_USAGE, 
	                                       &n_extension, NULL);
	if (!extension)
		return CKR_OK;
	
	res = gkr_pkix_der_read_key_usage (extension, n_extension, &usage);
	g_free (extension);
	
	if (res == GKR_PKIX_CANCELLED)
		return CKR_FUNCTION_CANCELED;
	if (res != GKR_PKIX_SUCCESS) {
		g_warning ("invalid key usage in certificate");
		return CKR_GENERAL_ERROR;
	}
			
	if ((usage & check) == check)
		*val = CKT_NETSCAPE_TRUSTED;
	else
		*val = CKT_NETSCAPE_UNTRUSTED;

	return CKR_OK;
}

static CK_RV
read_key_usage (GkrPkNetscapeTrust *trust, guint check, CK_ATTRIBUTE_PTR attr)
{
	CK_ULONG value;
	CK_RV ret = has_key_usage (trust, check, &value);
	if (ret == CKR_OK)
		gkr_pk_attribute_set_ulong (attr, value);
	return ret;
}

static CK_RV
has_enhanced_usage (GkrPkNetscapeTrust *trust, CK_ATTRIBUTE_TYPE type, CK_ULONG *val)
{
	CK_RV ret;
	CK_BBOOL bval;
	CK_ULONG nval;

	g_return_val_if_fail (trust->certificate, CKR_GENERAL_ERROR);

	/* Check if we have the purpose setup */
	ret = gkr_pk_object_get_bool (GKR_PK_OBJECT (trust->certificate),
	                              type, &bval);
	if (ret != CKR_OK)
		return ret;
		
	/* Don't have the purpose */
	if (!bval) {
		*val = CKT_NETSCAPE_UNTRUSTED;
		return CKR_OK;
	}	
		
	/* Ascertain the trust in this certificate */
	ret = gkr_pk_object_get_ulong (GKR_PK_OBJECT (trust->certificate), 
	                               CKA_GNOME_USER_TRUST, &nval);
	if (ret != CKR_OK)
		return ret;
		
	switch (nval) {
	case CKT_GNOME_UNKNOWN:
		*val = CKT_NETSCAPE_TRUST_UNKNOWN;
		return CKR_OK;
	case CKT_GNOME_UNTRUSTED:
		*val = CKT_NETSCAPE_UNTRUSTED;
		return CKR_OK;
	case CKT_GNOME_TRUSTED:
		break;
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
		break;
	};
	
	/* See if we can delegate the purpase (ie: CA) */
	ret = gkr_pk_object_get_ulong (GKR_PK_OBJECT (trust->certificate),
	                               CKA_CERTIFICATE_CATEGORY, &nval);
	if (ret != CKR_OK)
		return ret;

	/* 2 is a certificate authority in PKCS#11 */
	*val = (nval == 2) ? CKT_NETSCAPE_TRUSTED_DELEGATOR : CKT_NETSCAPE_TRUSTED;
	return CKR_OK;
}

static CK_RV
read_enhanced_usage (GkrPkNetscapeTrust *trust, CK_ATTRIBUTE_TYPE type, 
                     CK_ATTRIBUTE_PTR attr)
{
	CK_ULONG value;
	CK_RV ret = has_enhanced_usage (trust, type, &value);
	if (ret == CKR_OK)
		gkr_pk_attribute_set_ulong (attr, value);
	return ret;
}

static CK_RV
hash_certificate (GkrPkNetscapeTrust *trust, int algo, CK_ATTRIBUTE_PTR result)
{
	const guchar *raw;
	gsize n_hash, n_raw;
	
	g_return_val_if_fail (trust->certificate, CKR_GENERAL_ERROR);
	
	raw = gkr_pk_cert_get_raw (trust->certificate, &n_raw);
	g_return_val_if_fail (raw, CKR_GENERAL_ERROR);
	
	n_hash = gcry_md_get_algo_dlen (algo);
	g_return_val_if_fail (n_hash > 0, CKR_GENERAL_ERROR);
	
	result->pValue = g_malloc0 (n_hash);
	gcry_md_hash_buffer (algo, result->pValue, raw, n_raw);
	result->ulValueLen = n_hash;
	
	return CKR_OK;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_netscape_trust_init (GkrPkNetscapeTrust *trust)
{

}

static void
gkr_pk_netscape_trust_get_property (GObject *obj, guint prop_id, GValue *value, 
                          GParamSpec *pspec)
{
	GkrPkNetscapeTrust *trust = GKR_PK_NETSCAPE_TRUST (obj);

	switch (prop_id) {
	case PROP_CERT:
		g_value_set_object (value, trust->certificate);
		break;
	}
}

static void
gkr_pk_netscape_trust_set_property (GObject *obj, guint prop_id, const GValue *value, 
                             GParamSpec *pspec)
{
	GkrPkNetscapeTrust *trust = GKR_PK_NETSCAPE_TRUST (obj);

	switch (prop_id) {
	case PROP_CERT:
		if (trust->certificate)
			g_object_remove_weak_pointer (G_OBJECT (trust->certificate), 
			                              (gpointer*)&trust->certificate);
		trust->certificate = GKR_PK_CERT (g_value_get_object (value));
		if (trust->certificate)
			g_object_add_weak_pointer (G_OBJECT (trust->certificate), 
			                           (gpointer*)&trust->certificate);
		gkr_pk_object_flush (GKR_PK_OBJECT (obj));
		break;
	}
}

static CK_RV
gkr_pk_netscape_trust_get_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkNetscapeTrust *trust = GKR_PK_NETSCAPE_TRUST (obj);
	
	g_assert (!attr->pValue);
	switch (attr->type)
	{
	case CKA_PRIVATE:
	case CKA_TRUST_STEP_UP_APPROVED:
		gkr_pk_attribute_set_boolean (attr, CK_FALSE);
		return CKR_OK;

	case CKA_CLASS:
		gkr_pk_attribute_set_ulong (attr, CKO_NETSCAPE_TRUST);
		return CKR_OK;
		
	/* Key restrictions */
	case CKA_TRUST_DIGITAL_SIGNATURE:
		return read_key_usage (trust, PKIX_KEY_USAGE_DIGITAL_SIGNATURE, attr);

	case CKA_TRUST_NON_REPUDIATION:
		return read_key_usage (trust, PKIX_KEY_USAGE_NON_REPUDIATION, attr);

	case CKA_TRUST_KEY_ENCIPHERMENT:
		return read_key_usage (trust, PKIX_KEY_USAGE_KEY_ENCIPHERMENT, attr);

	case CKA_TRUST_DATA_ENCIPHERMENT:
		return read_key_usage (trust, PKIX_KEY_USAGE_DATA_ENCIPHERMENT, attr);

	case CKA_TRUST_KEY_AGREEMENT:
		return read_key_usage (trust, PKIX_KEY_USAGE_KEY_AGREEMENT, attr);

	case CKA_TRUST_KEY_CERT_SIGN:
		return read_key_usage (trust, PKIX_KEY_USAGE_KEY_CERT_SIGN, attr);

	case CKA_TRUST_CRL_SIGN:
		return read_key_usage (trust, PKIX_KEY_USAGE_CRL_SIGN, attr);

	/* Various trust flags */
	case CKA_TRUST_SERVER_AUTH:
		return read_enhanced_usage (trust, CKA_GNOME_PURPOSE_SERVER_AUTH, attr);

	case CKA_TRUST_CLIENT_AUTH:
		return read_enhanced_usage (trust, CKA_GNOME_PURPOSE_CLIENT_AUTH, attr);

	case CKA_TRUST_CODE_SIGNING:
		return read_enhanced_usage (trust, CKA_GNOME_PURPOSE_CODE_SIGNING, attr);

	case CKA_TRUST_EMAIL_PROTECTION:
		return read_enhanced_usage (trust, CKA_GNOME_PURPOSE_EMAIL_PROTECTION, attr);

	case CKA_TRUST_IPSEC_END_SYSTEM:
		return read_enhanced_usage (trust, CKA_GNOME_PURPOSE_IPSEC_END_SYSTEM, attr);

	case CKA_TRUST_IPSEC_TUNNEL:
		return read_enhanced_usage (trust, CKA_GNOME_PURPOSE_IPSEC_TUNNEL, attr);

	case CKA_TRUST_IPSEC_USER:
		return read_enhanced_usage (trust, CKA_GNOME_PURPOSE_IPSEC_USER, attr);

	case CKA_TRUST_TIME_STAMPING:
		return read_enhanced_usage (trust, CKA_GNOME_PURPOSE_TIME_STAMPING, attr);

	case CKA_ID:
	case CKA_SUBJECT:
	case CKA_SERIAL_NUMBER:
	case CKA_ISSUER:
		return certificate_attribute (trust, attr);

	case CKA_CERT_MD5_HASH:
		return hash_certificate (trust, GCRY_MD_MD5, attr);
	case CKA_CERT_SHA1_HASH:
		return hash_certificate (trust, GCRY_MD_SHA1, attr);

	default:
		break;
	};

	return GKR_PK_OBJECT_CLASS (gkr_pk_netscape_trust_parent_class)->get_attribute (obj, attr);
}

static void
gkr_pk_netscape_trust_finalize (GObject *obj)
{
	GkrPkNetscapeTrust *trust = GKR_PK_NETSCAPE_TRUST (obj);
	
	if (trust->certificate)
		g_object_remove_weak_pointer (G_OBJECT (trust->certificate), 
		                              (gpointer*)&trust->certificate);
	trust->certificate = NULL;

	G_OBJECT_CLASS (gkr_pk_netscape_trust_parent_class)->finalize (obj);
}

static void
gkr_pk_netscape_trust_class_init (GkrPkNetscapeTrustClass *klass)
{
	GObjectClass *gobject_class;
	GkrPkObjectClass *parent_class;
	
	init_quarks ();
	
	gobject_class = (GObjectClass*)klass;

	gkr_pk_netscape_trust_parent_class = g_type_class_peek_parent (klass);
	
	parent_class = GKR_PK_OBJECT_CLASS (klass);
	parent_class->get_attribute = gkr_pk_netscape_trust_get_attribute;
	
	gobject_class->get_property = gkr_pk_netscape_trust_get_property;
	gobject_class->set_property = gkr_pk_netscape_trust_set_property;
	gobject_class->finalize = gkr_pk_netscape_trust_finalize;
	
	g_object_class_install_property (gobject_class, PROP_CERT,
		g_param_spec_object ("certificate", "Certificate", "Certificate which Purpose is for",
		                     GKR_TYPE_PK_CERT, G_PARAM_READWRITE));
}

GkrPkNetscapeTrust*
gkr_pk_netscape_trust_new (GkrPkManager *mgr, GkrPkCert *cert)
{
	GkrPkNetscapeTrust *trust;
	gkrid digest = NULL;
	GkrPkObject *obj;
	const guchar *raw;
	gsize n_raw;
	
	g_return_val_if_fail (GKR_IS_PK_MANAGER (mgr), NULL);
	g_return_val_if_fail (GKR_IS_PK_CERT (cert), NULL);
	obj = GKR_PK_OBJECT (cert);
	
	/* Make a new digest based on the certificate */
	if (obj->digest) {
		raw = gkr_id_get_raw (obj->digest, &n_raw);
		g_return_val_if_fail (raw, NULL);
		digest = gkr_id_new_digestv ((guchar*)"trust", 5, raw, n_raw, NULL);
	}
	
	trust = g_object_new (GKR_TYPE_PK_NETSCAPE_TRUST, "manager", mgr, 
	                      "digest", digest, "certificate", cert, NULL);
	                      
	gkr_id_free (digest);
	return trust;
}
