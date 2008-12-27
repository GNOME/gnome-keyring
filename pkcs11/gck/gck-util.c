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

#include "gck-util.h"

#include <stdio.h>
#include <string.h>

/* Only access using atomic operations */
static gint next_handle = 0x00000010;

gulong*
gck_util_ulong_alloc (gulong value)
{
	return g_slice_dup (gulong, &value);
}

void
gck_util_ulong_free (gpointer ptr_to_ulong)
{
	g_slice_free (gulong, ptr_to_ulong);
}

guint
gck_util_ulong_hash (gconstpointer v)
{
	const signed char *p = v;
	guint32 i, h = *p;
	for(i = 0; i < sizeof (gulong); ++i)
		h = (h << 5) - h + *(p++);
	return h;
}

gboolean
gck_util_ulong_equal (gconstpointer v1, gconstpointer v2)
{
	return *((const gulong*)v1) == *((const gulong*)v2);
}

CK_RV
gck_util_set_bool (CK_ATTRIBUTE_PTR attr, CK_BBOOL value)
{
	return gck_util_set_data (attr, &value, sizeof (CK_BBOOL));
}

CK_RV
gck_util_set_ulong (CK_ATTRIBUTE_PTR attr, CK_ULONG value)
{
	return gck_util_set_data (attr, &value, sizeof (CK_ULONG));
}

CK_RV
gck_util_set_string (CK_ATTRIBUTE_PTR attr, const gchar* string)
{
	g_return_val_if_fail (string, CKR_GENERAL_ERROR);
	return gck_util_set_data (attr, (CK_VOID_PTR)string, strlen (string));
}

CK_RV
gck_util_set_date (CK_ATTRIBUTE_PTR attr, time_t time)
{
	CK_DATE date;
	struct tm tm;
	gchar buf[16];
	
	/* 'Empty' date as defined in PKCS#11 */
	if (time == (time_t)-1)
		return gck_util_set_data (attr, NULL, 0);
	
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
		
	return gck_util_set_data (attr, &date, sizeof (date));
}
CK_RV
gck_util_set_data (CK_ATTRIBUTE_PTR attr, gconstpointer value, gsize n_value)
{
	return gck_util_return_data (attr->pValue, &(attr->ulValueLen), value, n_value);
}

CK_RV
gck_util_return_data (CK_VOID_PTR output, CK_ULONG_PTR n_output,
                      gconstpointer input, gsize n_input)
{
	g_return_val_if_fail (n_output, CKR_GENERAL_ERROR);
	g_return_val_if_fail (input, CKR_GENERAL_ERROR);
	
	/* Just asking for the length */
	if (!output) {
		*n_output = n_input;
		return CKR_OK;
	}
	
	/* Buffer is too short */
	if (n_input > *n_output) {
		*n_output = n_input;
		return CKR_BUFFER_TOO_SMALL;
	}

	*n_output = n_input;
	memcpy (output, input, n_input);
	return CKR_OK;
}

CK_RV
gck_util_set_mpi (CK_ATTRIBUTE_PTR attr, gcry_mpi_t mpi)
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

CK_ULONG
gck_util_next_handle (void)
{
	return (CK_ULONG)g_atomic_int_exchange_and_add (&next_handle, 1);
}
