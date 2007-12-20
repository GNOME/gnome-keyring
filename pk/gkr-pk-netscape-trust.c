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
#include "gkr-pk-object-manager.h"
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
has_key_usage (GkrPkNetscapeTrust *trust, guint check, gulong *val)
{
	GkrParseResult res;
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
	
	if (res != GKR_PARSE_SUCCESS) {
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
has_enhanced_usage (GkrPkNetscapeTrust *trust, CK_ATTRIBUTE_TYPE type, gulong *val)
{
	CK_ATTRIBUTE attr;
	CK_ULONG value;
	CK_RV ret;
	gboolean has;

	g_return_val_if_fail (trust->certificate, CKR_GENERAL_ERROR);

	memset (&attr, 0, sizeof (attr));
	attr.type = CKA_GNOME_PURPOSE_RESTRICTED;
	ret = certificate_attribute (trust, &attr);
	if (ret != CKR_OK)
		return ret;
		
	/* Has any purposes? */
	g_return_val_if_fail (attr.ulValueLen == sizeof (CK_BBOOL), CKR_GENERAL_ERROR);
	has = *((CK_BBOOL*)attr.pValue) ? TRUE : FALSE;
	gkr_pk_attribute_clear (&attr);
	
	if (!has) {
		*val = CKT_NETSCAPE_TRUST_UNKNOWN;
		return CKR_OK;
	}
	
	/* Has this purpose? */
	attr.type = type;
	ret = certificate_attribute (trust, &attr);
	if (ret != CKR_OK)
		return ret;
	
	g_return_val_if_fail (attr.ulValueLen == sizeof (CK_BBOOL), CKR_GENERAL_ERROR);
	has = *((CK_BBOOL*)attr.pValue) ? TRUE : FALSE;
	gkr_pk_attribute_clear (&attr);

	/* Has the purpose set */	
	if (has) {
		attr.type = CKA_CERTIFICATE_CATEGORY;
		ret = certificate_attribute (trust, &attr);
		/* 2 is the PKCS#11 value for Certificate Authority */
		if (ret == CKR_OK)
			*val = (value == 2) ? CKT_NETSCAPE_TRUSTED_DELEGATOR : CKT_NETSCAPE_TRUSTED;
		gkr_pk_attribute_clear (&attr);
		return ret;
	} 
	
	
	*val = CKT_NETSCAPE_UNTRUSTED;
	return CKR_OK;
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
gkr_pk_netscape_trust_get_bool_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	gboolean val;
	
	switch (attr->type)
	{
	case CKA_TOKEN:
	case CKA_MODIFIABLE:
		val = TRUE;
		break;
		
	case CKA_PRIVATE:
	case CKA_TRUST_STEP_UP_APPROVED:
		val = FALSE;
		break;
	
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	gkr_pk_attribute_set_boolean (attr, val);
	return CKR_OK;
}

static CK_RV 
gkr_pk_netscape_trust_get_ulong_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkNetscapeTrust *trust = GKR_PK_NETSCAPE_TRUST (obj);
	CK_RV ret = CKR_OK;
	gulong val;
	
	switch (attr->type)
	{
	case CKA_CLASS:
		val = CKO_NETSCAPE_TRUST;
		break;
		
	/* Key restrictions */
	case CKA_TRUST_DIGITAL_SIGNATURE:
		ret = has_key_usage (trust, PKIX_KEY_USAGE_DIGITAL_SIGNATURE, &val);
		break;
	case CKA_TRUST_NON_REPUDIATION:
		ret = has_key_usage (trust, PKIX_KEY_USAGE_NON_REPUDIATION, &val);
		break;
	case CKA_TRUST_KEY_ENCIPHERMENT:
		ret = has_key_usage (trust, PKIX_KEY_USAGE_KEY_ENCIPHERMENT, &val);
		break;
	case CKA_TRUST_DATA_ENCIPHERMENT:
		ret = has_key_usage (trust, PKIX_KEY_USAGE_DATA_ENCIPHERMENT, &val);
		break;
	case CKA_TRUST_KEY_AGREEMENT:
		ret = has_key_usage (trust, PKIX_KEY_USAGE_KEY_AGREEMENT, &val);
		break;
	case CKA_TRUST_KEY_CERT_SIGN:
		ret = has_key_usage (trust, PKIX_KEY_USAGE_KEY_CERT_SIGN, &val);
		break;
	case CKA_TRUST_CRL_SIGN:
		ret = has_key_usage (trust, PKIX_KEY_USAGE_CRL_SIGN, &val);
		break;

	/* Various trust flags */
	case CKA_TRUST_SERVER_AUTH:
		ret = has_enhanced_usage (trust, CKA_GNOME_PURPOSE_SERVER_AUTH, &val);
		break;
	case CKA_TRUST_CLIENT_AUTH:
		ret = has_enhanced_usage (trust, CKA_GNOME_PURPOSE_CLIENT_AUTH, &val);
		break;
	case CKA_TRUST_CODE_SIGNING:
		ret = has_enhanced_usage (trust, CKA_GNOME_PURPOSE_CODE_SIGNING, &val);
		break;
	case CKA_TRUST_EMAIL_PROTECTION:
		ret = has_enhanced_usage (trust, CKA_GNOME_PURPOSE_EMAIL_PROTECTION, &val);
		break;
	case CKA_TRUST_IPSEC_END_SYSTEM:
		ret = has_enhanced_usage (trust, CKA_GNOME_PURPOSE_IPSEC_END_SYSTEM, &val);
		break;
	case CKA_TRUST_IPSEC_TUNNEL:
		ret = has_enhanced_usage (trust, CKA_GNOME_PURPOSE_IPSEC_TUNNEL, &val);
		break;
	case CKA_TRUST_IPSEC_USER:
		ret = has_enhanced_usage (trust, CKA_GNOME_PURPOSE_IPSEC_USER, &val);
		break;
	case CKA_TRUST_TIME_STAMPING:
		ret = has_enhanced_usage (trust, CKA_GNOME_PURPOSE_TIME_STAMPING, &val);
		break;

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	if (ret == CKR_OK)
		gkr_pk_attribute_set_ulong (attr, val);
	return ret;
}

static CK_RV
gkr_pk_netscape_trust_get_data_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkNetscapeTrust *trust = GKR_PK_NETSCAPE_TRUST (obj);
	
	g_assert (!attr->pValue);
	switch (attr->type)
	{
	case CKA_ID:
	case CKA_LABEL:
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

	return CKR_ATTRIBUTE_TYPE_INVALID;
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
	parent_class->get_bool_attribute = gkr_pk_netscape_trust_get_bool_attribute;
	parent_class->get_ulong_attribute = gkr_pk_netscape_trust_get_ulong_attribute;
	parent_class->get_data_attribute = gkr_pk_netscape_trust_get_data_attribute;
	
	gobject_class->get_property = gkr_pk_netscape_trust_get_property;
	gobject_class->set_property = gkr_pk_netscape_trust_set_property;
	gobject_class->finalize = gkr_pk_netscape_trust_finalize;
	
	g_object_class_install_property (gobject_class, PROP_CERT,
		g_param_spec_object ("certificate", "Certificate", "Certificate which Purpose is for",
		                     GKR_TYPE_PK_CERT, G_PARAM_READWRITE));
}

GkrPkNetscapeTrust*
gkr_pk_netscape_trust_new (GkrPkObjectManager *mgr, GkrPkCert *cert)
{
	GkrPkNetscapeTrust *trust;
	gkrunique unique = NULL;
	GkrPkObject *obj;
	const guchar *raw;
	gsize n_raw;
	
	g_return_val_if_fail (GKR_IS_PK_CERT (cert), NULL);
	obj = GKR_PK_OBJECT (cert);
	
	/* Make a new unique based on the certificate */
	if (obj->unique) {
		raw = gkr_unique_get_raw (obj->unique, &n_raw);
		g_return_val_if_fail (raw, NULL);
		unique = gkr_unique_new_digestv ((guchar*)"trust", 5, raw, n_raw, NULL);
	}
	
	trust = g_object_new (GKR_TYPE_PK_NETSCAPE_TRUST, "manager", mgr, 
	                      "unique", unique, "certificate", cert, NULL);
	                      
	gkr_unique_free (unique);
	return trust;
}
