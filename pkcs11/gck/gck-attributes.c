/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
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
 */

#include "config.h"

#include "gck-attributes.h"
#include "gck-util.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>


CK_RV
gck_attribute_get_bool (CK_ATTRIBUTE_PTR attr, gboolean *value)
{
	CK_BBOOL* bool;

	g_return_val_if_fail (attr, CKR_GENERAL_ERROR);
	g_return_val_if_fail (value, CKR_GENERAL_ERROR);

	if (attr->ulValueLen != sizeof (CK_BBOOL) || attr->pValue == NULL)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	bool = attr->pValue;
	*value = *bool ? TRUE : FALSE;
	return CKR_OK;
}

#ifndef HAVE_TIMEGM
static time_t
timegm (struct tm *t)
{
	time_t tl, tb;
	struct tm *tg;

	tl = mktime (t);
	if (tl == -1)
	{
		t->tm_hour--;
		tl = mktime (t);
		if (tl == -1)
			return -1; /* can't deal with output from strptime */
		tl += 3600;
	}
	tg = gmtime (&tl);
	tg->tm_isdst = 0;
	tb = mktime (tg);
	if (tb == -1)
	{
		tg->tm_hour--;
		tb = mktime (tg);
		if (tb == -1)
			return -1; /* can't deal with output from gmtime */
		tb += 3600;
	}
	return (tl - (tb - tl));
}
#endif // NOT_HAVE_TIMEGM

CK_RV
gck_attribute_get_time (CK_ATTRIBUTE_PTR attr, glong *when)
{
	struct tm tm;
	gchar buf[15];
	time_t time;

	g_return_val_if_fail (attr, CKR_GENERAL_ERROR);
	g_return_val_if_fail (when, CKR_GENERAL_ERROR);

	if (attr->ulValueLen == 0) {
		*when = (glong)-1;
		return CKR_OK;
	}

	if (!attr->pValue || attr->ulValueLen != 16)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	memset (&tm, 0, sizeof (tm));
	memcpy (buf, attr->pValue, 14);
	buf[14] = 0;

	if (!strptime(buf, "%Y%m%d%H%M%S", &tm))
		return CKR_ATTRIBUTE_VALUE_INVALID;

	/* Convert to seconds since epoch */
	time = timegm (&tm);
	if (time < 0)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*when = time;
	return CKR_OK;
}

CK_RV
gck_attribute_set_bool (CK_ATTRIBUTE_PTR attr, CK_BBOOL value)
{
	return gck_attribute_set_data (attr, &value, sizeof (CK_BBOOL));
}

CK_RV
gck_attribute_set_ulong (CK_ATTRIBUTE_PTR attr, CK_ULONG value)
{
	return gck_attribute_set_data (attr, &value, sizeof (CK_ULONG));
}

CK_RV
gck_attribute_set_string (CK_ATTRIBUTE_PTR attr, const gchar* string)
{
	return gck_attribute_set_data (attr, (CK_VOID_PTR)string, 
	                               string ? strlen (string) : 0);
}

CK_RV
gck_attribute_set_date (CK_ATTRIBUTE_PTR attr, time_t time)
{
	CK_DATE date;
	struct tm tm;
	gchar buf[16];
	
	/* 'Empty' date as defined in PKCS#11 */
	if (time == (time_t)-1)
		return gck_attribute_set_data (attr, NULL, 0);
	
	if (!attr->pValue) {
		attr->ulValueLen = sizeof (CK_DATE);
		return CKR_OK;
	}

	if (!gmtime_r (&time, &tm))
		g_return_val_if_reached (CKR_GENERAL_ERROR);
		
	g_assert (sizeof (date.year) == 4);
	snprintf ((char*)buf, 5, "%04d", 1900 + tm.tm_year);
	memcpy (date.year, buf, 4);
	 
	g_assert (sizeof (date.month) == 2);
	snprintf ((char*)buf, 3, "%02d", tm.tm_mon + 1);
	memcpy (date.month, buf, 2);
	
	g_assert (sizeof (date.day) == 2);
	snprintf ((char*)buf, 3, "%02d", tm.tm_mday);
	memcpy (date.day, buf, 2);
		
	return gck_attribute_set_data (attr, &date, sizeof (date));
}

CK_RV
gck_attribute_set_time (CK_ATTRIBUTE_PTR attr, glong when)
{
	struct tm tm;
	gchar buf[20];

	/* 'Empty' time as defined in PKCS#11 */
	if (when == (glong)-1)
		return gck_attribute_set_data (attr, NULL, 0);

	if (!attr->pValue) {
		attr->ulValueLen = 16;
		return CKR_OK;
	}

	time_t time = when;
	if (!gmtime_r (&time, &tm))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	if (!strftime(buf, sizeof (buf), "%Y%m%d%H%M%S00", &tm))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	return gck_attribute_set_data (attr, buf, 16);
}

CK_RV
gck_attribute_set_data (CK_ATTRIBUTE_PTR attr, gconstpointer value, gsize n_value)
{
	CK_RV rv = gck_util_return_data (attr->pValue, &(attr->ulValueLen), value, n_value);
	if (rv == CKR_BUFFER_TOO_SMALL)
		attr->ulValueLen = (CK_ULONG)-1;
	return rv;
}

CK_RV
gck_attribute_set_mpi (CK_ATTRIBUTE_PTR attr, gcry_mpi_t mpi)
{
	gsize len;
  	gcry_error_t gcry;

	g_assert (attr);
	g_assert (mpi);
	
	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &len, mpi);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);

	if (!attr->pValue) {
		attr->ulValueLen = len;
		return CKR_OK;
	}
	
	if (len > attr->ulValueLen) {
		attr->ulValueLen = len;
		return CKR_BUFFER_TOO_SMALL;
	}

	/* Write in directly to attribute */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, attr->pValue, len, &len, mpi);	
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	
	attr->ulValueLen = len;
	return CKR_OK;
}

gboolean
gck_attribute_equal (gconstpointer v1, gconstpointer v2)
{
	const CK_ATTRIBUTE *a1 = v1;
	const CK_ATTRIBUTE *a2 = v2;
	
	g_assert (a1);
	g_assert (a2);
	
	if (a1 == a2)
		return TRUE;
	if (a1->type != a2->type)
		return FALSE;
	if (a1->ulValueLen != a2->ulValueLen)
		return FALSE;
	if (a1->pValue == a2->pValue)
		return TRUE;
	if (a1->ulValueLen == 0)
		return TRUE;

	g_assert (a1->pValue);
	g_assert (a2->pValue);
	
	return memcmp (a1->pValue, a2->pValue, a1->ulValueLen) == 0;
}

guint
gck_attribute_hash (gconstpointer v)
{
	const CK_ATTRIBUTE *a = v;
	const signed char *p;
	guint i, h;
	
	g_assert (a);
	
	p = (const signed char*)&(a->type);
	h = *p;
	for(i = 0; i < sizeof (CK_ATTRIBUTE_PTR); ++i)
		h = (h << 5) - h + *(p++);
	
	p = a->pValue;
	for(i = 0; i < a->ulValueLen; ++i)
		h = (h << 5) - h + *(p++);
	
	return h;
}

gboolean
gck_attribute_consumed (CK_ATTRIBUTE_PTR attr)
{
	g_return_val_if_fail (attr, FALSE);
	return attr->type == (CK_ULONG)-1;
}

void
gck_attribute_consume (CK_ATTRIBUTE_PTR attr)
{
	attr->type = (CK_ULONG)-1;
}

void
gck_attributes_consume (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, ...)
{
	CK_ATTRIBUTE_TYPE type;
	GArray *types;
	guint i, j;
	va_list va;

	/* Convert the var args into an array */
	types = g_array_new (FALSE, TRUE, sizeof (CK_ATTRIBUTE_TYPE));
	va_start (va, n_attrs);
	while ((type = va_arg (va, CK_ATTRIBUTE_TYPE)) != G_MAXULONG)
		 g_array_append_val (types, type);
	va_end (va);
	
	/* Consume each attribute whose type was in the var args */
	for (i = 0; i < n_attrs; ++i) {
		if (gck_attribute_consumed (&attrs[i]))
			continue;
		for (j = 0; j < types->len; ++j) {
			if (attrs[i].type == g_array_index (types, CK_ATTRIBUTE_TYPE, j)) {
				attrs[i].type = (CK_ULONG)-1;
				break;
			}
		}
	}
	
	g_array_free (types, TRUE);
}

gboolean
gck_attributes_contains (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, CK_ATTRIBUTE_PTR attr)
{
	CK_ULONG i;
	
	g_assert (attrs || !n_attrs);
	g_assert (attr);
	
	for (i = 0; i < n_attrs; ++i) {
		if (gck_attribute_equal (attr, &attrs[i]))
			return TRUE;
	}
	
	return FALSE;
}

CK_ATTRIBUTE_PTR
gck_attributes_find (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;
	
	g_assert (attrs || !n_attrs);
	
	for (i = 0; i < n_attrs; ++i) {
		if(attrs[i].type == type)
			return &attrs[i];
	}
	
	return NULL;
}

gboolean
gck_attributes_find_boolean (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, CK_ATTRIBUTE_TYPE type, gboolean *value)
{
	CK_ATTRIBUTE_PTR attr;
	
	g_assert (attrs || !n_attrs);
	
	attr = gck_attributes_find (attrs, n_attrs, type);
	if (attr == NULL)
		return FALSE;
	
	if (attr->ulValueLen != sizeof (CK_BBOOL))
		return FALSE;
	
	if (value != NULL)
		*value = *((CK_BBOOL*)attr->pValue) == CK_TRUE ? TRUE : FALSE;

	return TRUE;
}

gboolean
gck_attributes_find_ulong (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, CK_ATTRIBUTE_TYPE type, gulong *value)
{
	CK_ATTRIBUTE_PTR attr;
	
	g_assert (attrs || !n_attrs);
	
	attr = gck_attributes_find (attrs, n_attrs, type);
	if (attr == NULL)
		return FALSE;
	
	if (attr->ulValueLen != sizeof (CK_ULONG))
		return FALSE;
	
	if (value != NULL)
		*value = *((CK_ULONG*)attr->pValue);

	return TRUE;
}

gboolean
gck_attributes_find_mpi (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, CK_ATTRIBUTE_TYPE type, gcry_mpi_t *value)
{
	CK_ATTRIBUTE_PTR attr;
	gcry_error_t gcry;
	
	g_assert (attrs || !n_attrs);
	
	attr = gck_attributes_find (attrs, n_attrs, type);
	if (attr == NULL)
		return FALSE;
	
	if (value != NULL) {
		gcry = gcry_mpi_scan (value, GCRYMPI_FMT_USG, attr->pValue, attr->ulValueLen, NULL);
		if (gcry != 0)
			return FALSE;
	}
	
	return TRUE;
}
