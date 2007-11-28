/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-util.c - miscellaneous utilities for dealing with PKCS#11

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

#include "gkr-pk-util.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11n.h"

#include <glib.h>

#include <stdio.h>

GkrPkDataType
gkr_pk_attribute_data_type (CK_ATTRIBUTE_TYPE type)
{
	switch(type)
	{
	/* CK_ULONG attribute types */
	case CKA_CLASS:
	case CKA_CERTIFICATE_TYPE:
	case CKA_CERTIFICATE_CATEGORY:
	case CKA_KEY_TYPE:
	case CKA_MODULUS_BITS:
	case CKA_PRIME_BITS:
	/* case CKA_SUBPRIME_BITS: */
	case CKA_SUB_PRIME_BITS: 
	case CKA_VALUE_BITS:
	case CKA_VALUE_LEN:
	case CKA_KEY_GEN_MECHANISM:
	case CKA_HW_FEATURE_TYPE:
	case CKA_PIXEL_X:
	case CKA_PIXEL_Y:
	case CKA_RESOLUTION:
	case CKA_CHAR_ROWS:
	case CKA_CHAR_COLUMNS:
	case CKA_BITS_PER_PIXEL:
	case CKA_MECHANISM_TYPE:
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
	case CKA_TRUST_SERVER_AUTH:
	case CKA_TRUST_CLIENT_AUTH:
	case CKA_TRUST_CODE_SIGNING:
	case CKA_TRUST_EMAIL_PROTECTION:
	case CKA_TRUST_IPSEC_END_SYSTEM:
	case CKA_TRUST_IPSEC_TUNNEL:
	case CKA_TRUST_IPSEC_USER:
	case CKA_TRUST_TIME_STAMPING:
		return GKR_PK_DATA_ULONG;

	/* CK_BBOOL attribute types */
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
	case CKA_TRUSTED:
	case CKA_SENSITIVE:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_UNWRAP:
	case CKA_EXTRACTABLE:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_WRAP_WITH_TRUSTED:
	case CKA_ALWAYS_AUTHENTICATE:
	case CKA_ENCRYPT:
	case CKA_WRAP:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_DERIVE:
	case CKA_LOCAL:
	case CKA_RESET_ON_INIT:
	case CKA_HAS_RESET:
	case CKA_COLOR:
	case CKA_TRUST_STEP_UP_APPROVED:
		return GKR_PK_DATA_BOOL;

	/* Raw or string data */
	case CKA_LABEL:
	case CKA_APPLICATION:
	case CKA_VALUE:
	case CKA_OBJECT_ID:
	case CKA_CHECK_VALUE:
	case CKA_ISSUER:
	case CKA_SERIAL_NUMBER:
	case CKA_SUBJECT:
	case CKA_ID:
	case CKA_URL:
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
	case CKA_AC_ISSUER:
	case CKA_OWNER:
	case CKA_ATTR_TYPES:
	case CKA_MODULUS:
	case CKA_PUBLIC_EXPONENT:
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
	case CKA_PRIME:
	case CKA_SUBPRIME:
	case CKA_BASE:
	case CKA_ECDSA_PARAMS:
	/* case CKA_EC_PARAMS: */
	case CKA_EC_POINT:
	case CKA_CHAR_SETS:
	case CKA_ENCODING_METHODS:
	case CKA_MIME_TYPES:
	case CKA_REQUIRED_CMS_ATTRIBUTES:
	case CKA_DEFAULT_CMS_ATTRIBUTES:
	case CKA_SUPPORTED_CMS_ATTRIBUTES:
	case CKA_CERT_SHA1_HASH:
	case CKA_CERT_MD5_HASH:
		return GKR_PK_DATA_BYTES;

	/* CK_DATE data */
	case CKA_START_DATE:
	case CKA_END_DATE:
		return GKR_PK_DATA_DATE;

	/* Arrays are nasty */
	case CKA_WRAP_TEMPLATE:
	case CKA_ALLOWED_MECHANISMS:
	case CKA_UNWRAP_TEMPLATE:
	default:
		return GKR_PK_DATA_UNKNOWN;
	};
}

CK_ATTRIBUTE_PTR
gkr_pk_attribute_new (CK_ATTRIBUTE_TYPE type)
{
	CK_ATTRIBUTE_PTR attr;
	
	attr = g_slice_new0 (CK_ATTRIBUTE);
	attr->type = type;
	
	return attr;
} 

CK_ATTRIBUTE_PTR
gkr_pk_attribute_dup (const CK_ATTRIBUTE_PTR attr)
{
	CK_ATTRIBUTE_PTR nattr = gkr_pk_attribute_new (attr->type);
	gkr_pk_attribute_copy (nattr, attr);
	return nattr;
}

void
gkr_pk_attribute_steal (CK_ATTRIBUTE_PTR dest, CK_ATTRIBUTE_PTR attr)
{
	g_assert (dest && attr);
	memcpy (dest, attr, sizeof (CK_ATTRIBUTE));
	memset (attr, 0, sizeof (CK_ATTRIBUTE));
	attr->type = dest->type;
}

void
gkr_pk_attribute_copy (CK_ATTRIBUTE_PTR dest, const CK_ATTRIBUTE_PTR attr)
{
	g_assert (dest && attr);
	gkr_pk_attribute_set_data (dest, attr->pValue, attr->ulValueLen);
	dest->type = attr->type;
}

void
gkr_pk_attribute_set_invalid (CK_ATTRIBUTE_PTR attr)
{
	g_assert (attr);
	gkr_pk_attribute_clear (attr);	
	attr->ulValueLen = (CK_ULONG)-1;
}

void
gkr_pk_attribute_set_data (CK_ATTRIBUTE_PTR attr, gconstpointer value, gsize n_value)
{
	g_assert (attr);

	gkr_pk_attribute_clear (attr);

	attr->ulValueLen = n_value;
	if (n_value > 0) {
		g_assert (value);
		attr->pValue = g_slice_alloc (n_value);
		memcpy (attr->pValue, value, n_value);
	}
}

void
gkr_pk_attribute_set_string (CK_ATTRIBUTE_PTR attr, const gchar *str)
{
	g_assert (attr);
	g_assert (str);
	
	gkr_pk_attribute_set_data (attr, str, strlen (str) + 1);
}

void
gkr_pk_attribute_set_boolean (CK_ATTRIBUTE_PTR attr, gboolean value)
{
	g_assert (attr);
	
	gkr_pk_attribute_clear (attr);
	attr->pValue = g_slice_new (CK_BBOOL);
	*((CK_BBOOL*)attr->pValue) = value ? CK_TRUE : CK_FALSE;
	attr->ulValueLen = sizeof (CK_BBOOL);
}

void
gkr_pk_attribute_set_date (CK_ATTRIBUTE_PTR attr, time_t time)
{
	CK_DATE *date;
	struct tm tm;
	
	/* 'Empty' date as defined in PKCS#11 */
	if (time == (time_t)-1) {
		gkr_pk_attribute_set_data (attr, NULL, 0);
		return;
	}
	
	gkr_pk_attribute_clear (attr);
	
	if (!gmtime_r (&time, &tm))
		g_return_if_reached ();
		
	date = g_new0 (CK_DATE, 1);
	snprintf ((char*)date->year, sizeof (date->year), "%04d", 1900 + tm.tm_year); 
	snprintf ((char*)date->month, sizeof (date->month), "%02d", tm.tm_mon);
	snprintf ((char*)date->day, sizeof (date->day), "%02d", tm.tm_mday);
	
	attr->pValue = date;
	attr->ulValueLen = sizeof (CK_DATE);
}

void
gkr_pk_attribute_set_unique (CK_ATTRIBUTE_PTR attr, gkrconstunique uni)
{
	const guchar* data;
	gsize n_data;
	
	g_assert (attr);
	
	data = gkr_unique_get_raw (uni, &n_data);
	g_return_if_fail (data && n_data);
	
	gkr_pk_attribute_set_data (attr, data, n_data);
}

void
gkr_pk_attribute_set_uint (CK_ATTRIBUTE_PTR attr, guint value)
{
	g_assert (attr);
	
	gkr_pk_attribute_clear (attr);
	attr->pValue = g_slice_new (CK_ULONG);
	*((CK_ULONG*)attr->pValue) = value;
	attr->ulValueLen = sizeof (CK_ULONG);	
}

void
gkr_pk_attribute_set_mpi (CK_ATTRIBUTE_PTR attr, gcry_mpi_t mpi)
{
	gsize len;
  	gcry_error_t gcry;

	g_assert (attr);
	g_assert (mpi);
	
	gkr_pk_attribute_clear (attr);
	
	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &len, mpi);
	g_return_if_fail (gcry == 0);
	
	if (!len)
		return;

	attr->pValue = g_slice_alloc (len);
	attr->ulValueLen = len;
	
	/* Write in directly to attribute */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, attr->pValue, len, &len, mpi);	
	g_return_if_fail (gcry == 0);
}

void
gkr_pk_attribute_clear (CK_ATTRIBUTE_PTR attr)
{
	if (attr->pValue) {
		g_assert (attr->ulValueLen > 0);
		g_assert (attr->ulValueLen != (CK_ULONG)-1);
		g_slice_free1 (attr->ulValueLen, attr->pValue);
		attr->pValue = NULL;
	}
	attr->ulValueLen = 0;
}

void
gkr_pk_attribute_free (gpointer v)
{
	if (v) {
		CK_ATTRIBUTE_PTR attr = (CK_ATTRIBUTE_PTR)v;
		gkr_pk_attribute_clear (attr);
		g_slice_free (CK_ATTRIBUTE, attr);
	}
}

gpointer
gkr_pk_attribute_array_find (const GArray* attrs, CK_ATTRIBUTE_TYPE type)
{
	CK_ATTRIBUTE_PTR attr;
	guint i;

	for (i = 0; i < attrs->len; ++i) {
		attr = &(g_array_index (attrs, CK_ATTRIBUTE, i));
		if (attr->type == type)
			return attr->pValue;
	}

	return NULL;
}

 
void
gkr_pk_attribute_array_free (GArray *attrs)
{
	CK_ATTRIBUTE_PTR attr;
	guint i;

	if (!attrs)
		return;
		
	for (i = 0; i < attrs->len; ++i) {
		attr = &(g_array_index (attrs, CK_ATTRIBUTE, i));
		gkr_pk_attribute_clear (attr);
	}

	g_array_free (attrs, TRUE);
}
