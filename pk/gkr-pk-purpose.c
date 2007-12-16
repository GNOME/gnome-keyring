/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-purpose.c - Combination of Trust and Usage for a Certificate

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
#include "gkr-pk-purpose.h"
#include "gkr-pk-object.h"
#include "gkr-pk-object-manager.h"
#include "gkr-pk-util.h"

#include "common/gkr-location.h"

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

struct _GkrPkPurposeData {
	gboolean loaded;
	gboolean is_ca;
	
	gint key_usage;
	
	gboolean enhanced_usage_has;
	GSList *enhanced_usage;
};

G_DEFINE_TYPE (GkrPkPurpose, gkr_pk_purpose, GKR_TYPE_PK_OBJECT);


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

	QUARK(OID_USAGE_SERVER_AUTH, "1.3.6.1.5.5.7.3.1")
	QUARK(OID_USAGE_CLIENT_AUTH, "1.3.6.1.5.5.7.3.2")
	QUARK(OID_USAGE_CODE_SIGNING, "1.3.6.1.5.5.7.3.3")
	QUARK(OID_USAGE_EMAIL, "1.3.6.1.5.5.7.3.4")
	QUARK(OID_USAGE_TIME_STAMPING, "1.3.6.1.5.5.7.3.8")
	QUARK(OID_USAGE_IPSEC_ENDPOINT, "1.3.6.1.5.5.7.3.5")
	QUARK(OID_USAGE_IPSEC_TUNNEL, "1.3.6.1.5.5.7.3.6")
	QUARK(OID_USAGE_IPSEC_USER, "1.3.6.1.5.5.7.3.7")
	QUARK(OID_USAGE_IKE_INTERMEDIATE, "1.3.6.1.5.5.8.2.2")
	
	#undef QUARK
}

static CK_RV
load_certificate_purpose (GkrPkPurpose *purpose)
{
	GkrPkPurposeData *data = purpose->data;
	guchar *ext;
	gsize n_ext;
	guint usage;
	
	if (data->loaded)
		return CKR_OK;
		
	g_return_val_if_fail (purpose->certificate, CKR_GENERAL_ERROR);
	
	/* Find out if it is a CA or not */
	data->is_ca = FALSE;
	ext = gkr_pk_cert_get_extension (purpose->certificate, OID_EXTENSION_BASIC, &n_ext, NULL);
	if (ext) {
		if (gkr_pkix_der_read_basic_constraints (ext, n_ext, &data->is_ca, NULL) != GKR_PARSE_SUCCESS) {
			data->is_ca = FALSE;
			g_warning ("invalid basic contstraints in certificate");
		}
		g_free (ext);
	} 
	
	/* Find out the key usage */
	data->key_usage = -1;
	ext = gkr_pk_cert_get_extension (purpose->certificate, OID_EXTENSION_KEY_USAGE, &n_ext, NULL);
	if (ext) {
		if (gkr_pkix_der_read_key_usage (ext, n_ext, &usage) == GKR_PARSE_SUCCESS)
			data->key_usage = usage;
		else
			g_warning ("invalid key usage in certificate");
		g_free (ext);
	}
	
	/* Find out the enhanced usage */
	g_slist_free (data->enhanced_usage);
	data->enhanced_usage = NULL;
	ext = gkr_pk_cert_get_extension (purpose->certificate, OID_EXTENSION_ENHANCED_USAGE, &n_ext, NULL);
	if (ext) {
		if (gkr_pkix_der_read_enhanced_usage (ext, n_ext, &data->enhanced_usage) != GKR_PARSE_SUCCESS)
			g_warning ("invalid enhanced usage in certificate");
		g_free (ext);
	}
	
	/* TODO: Load custom stuff from index */
	return CKR_OK;
}

static CK_RV
has_key_usage (GkrPkPurpose *purpose, guint usage, gulong *val)
{
	CK_RV ret;

	ret = load_certificate_purpose (purpose);
	if (ret != CKR_OK)
		return ret;
			
	if (purpose->key_usage == -1)
		*val = CKT_NETSCAPE_TRUST_UNKNOWN;
	else if ((purpose->key_usage & usage) == usage)
		*val = CKT_NESCAPE_TRUSTED;
	else
		*val = CKT_NETSCAPE_UNTRUSTED;

	return CKR_OK;
}

static CK_RV
has_enhanced_usage (GkrPkPurpose *purpose, GQuark oid, gulong *val)
{
	CK_RV ret;
	
	ret = load_certificate_purpose (purpose);
	if (ret != CKR_OK)
		return ret;
		
	if (!purpose->data->enhanced_usage_has)
		*val = CKT_NETSCAPE_TRUST_UNKNOWN;
	else if (g_slist_find (puprose->data->enhanced_usage, oid))
		*val = purpose->data->is_ca ? CKT_NETSCAPE_TRUSTED_DELEGATOR : CKT_NETSCAPE_TRUSTED;
	else 
		*val = CKT_NETSCAPE_UNTRUSTED;
		
	return CKR_OK;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_purpose_init (GkrPkPurpose *purpose)
{
	purpose->data = G_TYPE_INSTANCE_GET_PRIVATE (purpose, GKR_TYPE_PK_PURPOSE, GkrPkPurposeData);
	memset (purpose->data, 0, sizeof (GkrPkPurposeData));
}

static void
gkr_pk_purpose_get_property (GObject *obj, guint prop_id, GValue *value, 
                          GParamSpec *pspec)
{
	GkrPkPurpose *purpose = GKR_PK_PURPOSE (obj);

	switch (prop_id) {
	case PROP_CERT:
		g_value_set_object (value, purpose->certificate);
		break;
	}
}

static void
gkr_pk_purpose_set_property (GObject *obj, guint prop_id, const GValue *value, 
                             GParamSpec *pspec)
{
	GkrPkPurpose *purpose = GKR_PK_PURPOSE (obj);

	switch (prop_id) {
	case PROP_CERT:
		clear_caches ();
		if (purpose->certificate)
			g_object_remove_weak_pointer (purpose->certificate, &purpose->certificate);
		purpose->certificate = GKR_PK_CERT (g_value_get_object (value));
		if (purpose->certificate)
			g_object_add_weak_pointer (purpose->certificate, &purpose->certificate);
		break;
	}
}
            
static CK_RV 
gkr_pk_purpose_get_bool_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	gboolean val;
	
	switch (attr->type)
	{
	case CKA_TOKEN:
	case CKA_MODIFIABLE:
		val = TRUE;
		break;
		
	case CKA_PRIVATE:
		val = FALSE;
		break;
		
	/* TODO: Figure out what this is. */
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
gkr_pk_purpose_get_ulong_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkPurpose *purpose = GKR_PK_PURPOSE (obj);
	gulong val;
	guchar *extension;
	gsize n_extension;
	gboolean is_ca;
	int res;
	
	switch (attr->type)
	{
	case CKA_CLASS:
		val = CKO_NETSCAPE_TRUST;
		break;
		
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	/* Key restrictions */
	case CKA_TRUST_DIGITAL_SIGNATURE:
		ret = has_key_usage (purpose, PKIX_KEY_USAGE_DIGITAL_SIGNATURE, &val);
		break;
	case CKA_TRUST_NON_REPUDIATION:
		ret = has_key_usage (purpose, PKIX_KEY_USAGE_NON_REPUDIATION);
		break;
	case CKA_TRUST_KEY_ENCIPHERMENT:
		ret = has_key_usage (purpose, PKIX_KEY_USAGE_KEY_ENCIPHERMENT);
		break;
	case CKA_TRUST_DATA_ENCIPHERMENT:
		ret = has_key_usage (purpose, PKIX_KEY_USAGE_DATA_ENCIPHERMENT);
		break;
	case CKA_TRUST_KEY_AGREEMENT:
		val = has_usage (purpose, PKIX_KEY_USAGE_KEY_AGREEMENT);
		break;
	case CKA_TRUST_KEY_CERT_SIGN:
		val = has_usage (purpose, PKIX_KEY_USAGE_KEY_CERT_SIGN);
		break;
	case CKA_TRUST_CRL_SIGN:
		val = has_usage (purpose, PKIX_KEY_USAGE_CRL_SIGN);
		break;

	/* Various trust flags */
	case CKA_TRUST_SERVER_AUTH:
		val = has_enhanced_usage (purpose, OID_USAGE_SERVER_AUTH);
		break;
	case CKA_TRUST_CLIENT_AUTH:
		val = has_enhanced_usage (purpose, OID_USAGE_CLIENT_AUTH);
		break;
	case CKA_TRUST_CODE_SIGNING:
		val = has_enhanced_usage (purpose, OID_USAGE_CODE_SIGNING);
		break;
	case CKA_TRUST_EMAIL_PROTECTION:
		val = has_enhanced_usage (purpose, OID_USAGE_EMAIL);
		break;
	case CKA_TRUST_IPSEC_END_SYSTEM:
		val = has_enhanced_usage (purpose, OID_USAGE_IPSEC_ENDPOINT);
		break;
	case CKA_TRUST_IPSEC_TUNNEL:
		val = has_enhanced_usage (purpose, OID_USAGE_IPSEC_TUNNEL);
		break;
	case CKA_TRUST_IPSEC_USER:
		val = has_enhanced_usage (purpose, OID_USAGE_IPSEC_USER);
		break;
	case CKA_TRUST_TIME_STAMPING:
		val = has_enhanced_usage (purpase, OID_USAGE_TIME_STAMPING);
		break;

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	};
	
	gkr_pk_attribute_set_ulong (attr, val);
	return CKR_OK;
}

static CK_RV
gkr_pk_purpose_get_data_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkPurpose *purpose = GKR_PK_PURPOSE (obj);
	const guchar *cdata = NULL;
	gkrconstunique keyid;
	gchar *label;
	guchar *data;
	gsize n_data;
	
	g_assert (!attr->pValue);
	
	switch (attr->type)
	{
	case CKA_LABEL:
	case CKA_SUBJECT:
	case CKA_SERIAL_NUMBER:
	case CKA_ISSUER:
		return certificate_attribute (purpose, attr);

	case CKA_CERT_MD5_HASH:
	case CKA_CERT_SHA1_HASH:
xxxx get certificate value and hash xxxx
		return CKR_OK;

	default:
		break;
	};

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static void
gkr_pk_purpose_finalize (GObject *obj)
{
	GkrPkPurpose *purpose = GKR_PK_PURPOSE (obj);

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	
	G_OBJECT_CLASS (gkr_pk_purpose_parent_class)->finalize (obj);
}


static void
gkr_pk_purpose_class_init (GkrPkPurposeClass *klass)
{
	GObjectClass *gobject_class;
	GkrPkObjectClass *parent_class;
	
	init_quarks ();
	
	gobject_class = (GObjectClass*)klass;

	gkr_pk_purpose_parent_class = g_type_class_peek_parent (klass);
	
	parent_class = GKR_PK_OBJECT_CLASS (klass);
	parent_class->get_bool_attribute = gkr_pk_purpose_get_bool_attribute;
	parent_class->get_ulong_attribute = gkr_pk_purpose_get_ulong_attribute;
	parent_class->get_data_attribute = gkr_pk_purpose_get_data_attribute;
	
	gobject_class->get_property = gkr_pk_purpose_get_property;
	gobject_class->set_property = gkr_pk_purpose_set_property;
	gobject_class->finalize = gkr_pk_purpose_finalize;
	
	g_object_class_install_property (gobject_class, PROP_CERT,
		g_param_spec_object ("cert", "Certificate", "Certificate which Purpose is for",
		                     G_PARAM_READWRITE));

	g_type_class_add_private (gobject_class, sizeof (GkrPkPurposeData));
}

GkrPkPurpose*
gkr_pk_purpose_new (GQuark location, ASN1_TYPE asn1)
{
	return g_object_new (GKR_TYPE_PK_PURPOSE, "certificate", NULL);
}
