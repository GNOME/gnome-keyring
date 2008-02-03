/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-asn1.c - ASN.1 helper routines

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

#include "common/gkr-buffer.h"
#include "common/gkr-secure-memory.h"

#include <libtasn1.h>


/* 
 * HACK: asn1Parser defines these arrays as extern const, which gives 
 * gcc a fit. So we def it out. 
 */
 
#define extern 
#include "asn1-def-pk.h"
#include "asn1-def-pkix.h"
#undef extern 

static gboolean asn1_initialized = FALSE;
static ASN1_TYPE asn1_pk = NULL; 
static ASN1_TYPE asn1_pkix = NULL;

ASN1_TYPE 
gkr_pkix_asn1_get_pk_asn1type (void)
{
	int res;
	
	if (!asn1_initialized) {
		asn1_check_version (LIBTASN1_VERSION);
		asn1_initialized = TRUE;
	}
	
	if (!asn1_pk) {
		res = asn1_array2tree (pk_asn1_tab, &asn1_pk, NULL);
		g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	}
	
	return asn1_pk;
}

ASN1_TYPE 
gkr_pkix_asn1_get_pkix_asn1type (void)
{
	int res;

	if (!asn1_initialized) {
		asn1_check_version (LIBTASN1_VERSION);
		asn1_initialized = TRUE;
	}
	
	if (!asn1_pkix) {
		res = asn1_array2tree (pkix_asn1_tab, &asn1_pkix, NULL);
		g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	}
	
	return asn1_pkix;
}

	
ASN1_TYPE
gkr_pkix_asn1_decode (const gchar *type, const guchar *data, gsize n_data)
{
	ASN1_TYPE base = ASN1_TYPE_EMPTY;
	ASN1_TYPE asn;
	int res;
	
	if (strncmp (type, "PKIX1.", 6) == 0)
		base = gkr_pkix_asn1_get_pkix_asn1type ();
	else if (strncmp (type, "PK.", 3) == 0)
		base = gkr_pkix_asn1_get_pk_asn1type ();
	else
		g_return_val_if_reached (NULL);
		
	res = asn1_create_element (base, type, &asn); 
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	
	res = asn1_der_decoding (&asn, data, n_data, NULL);
	if (res != ASN1_SUCCESS) {
		asn1_delete_structure (&asn);
		return NULL;
	}
	
	return asn;
}

guchar*
gkr_pkix_asn1_encode (ASN1_TYPE asn, const gchar* part, gsize *n_data, 
                      GkrBufferAllocator alloc)
{
	guchar *data;
	int res, len;
	
	g_assert (asn);
	g_assert (n_data);
	
	len = 0;
	res = asn1_der_coding (asn, part, NULL, &len, NULL); 
	g_return_val_if_fail (res == ASN1_MEM_ERROR, NULL);
	
	if (!alloc)
		alloc = (GkrBufferAllocator)g_realloc;

	data = (alloc) (NULL, len);
	g_return_val_if_fail (data != NULL, NULL);
	
	res = asn1_der_coding (asn, part, data, &len, NULL);
	if (res != ASN1_SUCCESS) {
		(alloc) (data, 0);
		return NULL;
	}
	
	*n_data = len;
	return data;
}

gint
gkr_pkix_asn1_element_length (const guchar *data, gsize n_data)
{
	guchar cls;
	int counter = 0;
	int cb, len;
	gulong tag;
	
	if (asn1_get_tag_der (data, n_data, &cls, &cb, &tag) == ASN1_SUCCESS) {
		counter += cb;
		len = asn1_get_length_der (data + cb, n_data - cb, &cb);
		counter += cb;
		if (len >= 0) {
			len += counter;
			if (n_data >= len)
				return len;
		}
	}
	
	return -1;
}

const guchar*
gkr_pkix_asn1_read_element (ASN1_TYPE asn, const guchar *data, gsize n_data, 
                            const gchar *part, gsize *n_element)
{
	int beg, end, res;
	
	g_return_val_if_fail (asn != NULL, NULL);
	g_return_val_if_fail (part != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (n_element != NULL, NULL);
	
	res = asn1_der_decoding_startEnd (asn, data, n_data, part, &beg, &end);
	if (res != ASN1_SUCCESS) 
		return NULL;
		
	*n_element = end - beg + 1;
	return data + beg;
}                                                               

const guchar*
gkr_pkix_asn1_read_content (ASN1_TYPE asn, const guchar *data, gsize n_data, 
                            const gchar *part, gsize *n_content)
{
	const guchar *raw;
	gsize n_raw;
	
	g_return_val_if_fail (asn != NULL, NULL);
	g_return_val_if_fail (part != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (n_content != NULL, NULL);
	
	raw = gkr_pkix_asn1_read_element (asn, data, n_data, part, &n_raw);
	if (!raw)
		return NULL;

	return gkr_pkix_asn1_element_content (raw, n_raw, n_content);		
}

const guchar*
gkr_pkix_asn1_element_content (const guchar *data, gsize n_data, gsize *n_content)
{
	int counter = 0;
	guchar cls;
	gulong tag;
	int cb, len;
	
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (n_content != NULL, NULL);
	
	/* Now get the data out of this element */	
	if (asn1_get_tag_der (data, n_data, &cls, &cb, &tag) != ASN1_SUCCESS)
		return NULL;
			
	counter += cb;
	len = asn1_get_length_der (data + cb, n_data - cb, &cb);
	if (len < 0)
		return NULL;
	counter += cb;
	
	*n_content = len;
	return data + counter;	
}

guchar*
gkr_pkix_asn1_read_value (ASN1_TYPE asn, const gchar *part, gsize *len, 
                          GkrBufferAllocator allocator)
{
	int l, res;
	guchar *buf;
	
	g_return_val_if_fail (asn != NULL, NULL);
	g_return_val_if_fail (part != NULL, NULL);
	g_return_val_if_fail (len != NULL, NULL);
	
	if (allocator == NULL)
		allocator = (GkrBufferAllocator)g_realloc;
	
	*len = 0;

	l = 0;
	res = asn1_read_value (asn, part, NULL, &l);
	g_return_val_if_fail (res != ASN1_SUCCESS, NULL);
	if (res != ASN1_MEM_ERROR)
		return NULL;
		
	/* Always null terminate it, just for convenience */
	buf = (allocator) (NULL, l + 1);
	g_return_val_if_fail (buf, NULL);
	memset (buf, 0, *len + 1);
	
	res = asn1_read_value (asn, part, buf, &l);
	if (res != ASN1_SUCCESS) {
		(allocator) (buf, 0);
		buf = NULL;
	} else {
		*len = l;
	}
	
	return buf;
}

gboolean
gkr_pkix_asn1_write_value (ASN1_TYPE asn, const gchar *part, 
		                   const guchar* value, gsize len)
{
	int res;

	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (part, FALSE);
	g_return_val_if_fail (!len || value, FALSE);
	
	res = asn1_write_value (asn, part, (const void*)value, (int)len);
	return res == ASN1_SUCCESS;
}

gboolean
gkr_pkix_asn1_read_boolean (ASN1_TYPE asn, const gchar *part, gboolean *val)
{
	gchar buffer[32];
	int n_buffer = sizeof (buffer) - 1;
	int res;
	
	memset (buffer, 0, sizeof (buffer));
	
	res = asn1_read_value (asn, part, buffer, &n_buffer);
	if (res != ASN1_SUCCESS)
		return FALSE;
		
	if (g_ascii_strcasecmp (buffer, "TRUE") == 0)
		*val = TRUE;
	else
		*val = FALSE;
		
	return TRUE;
}

gboolean
gkr_pkix_asn1_read_uint (ASN1_TYPE asn, const gchar *part, guint *val)
{
	guchar buf[4];
	int n_buf = sizeof (buf);
	gsize i;
	int res;
	
	res = asn1_read_value (asn, part, buf, &n_buf);
	if(res != ASN1_SUCCESS)
		return FALSE;

	if (n_buf > 4 || n_buf < 1)
		return FALSE;

	*val = 0;
	for (i = 0; i < n_buf; ++i)
		*val |= buf[i] << (8 * ((n_buf - 1) - i));

	return TRUE;
}

gboolean
gkr_pkix_asn1_write_uint (ASN1_TYPE asn, const gchar *part, guint32 val)
{
	guchar buf[4];
	int res, bytes;
		
	buf[0] = (val >> 24) & 0xff;
	buf[1] = (val >> 16) & 0xff;
	buf[2] = (val >> 8) & 0xff;
	buf[3] = (val >> 0) & 0xff;
	
	for (bytes = 3; bytes >= 0; --bytes)
		if (!buf[bytes])
			break;
			
	bytes = 4 - (bytes + 1);
	if (bytes == 0)
		bytes = 1;
	res = asn1_write_value (asn, part, buf + (4 - bytes), bytes);
	return res == ASN1_SUCCESS;	
}

GQuark
gkr_pkix_asn1_read_oid (ASN1_TYPE asn, const gchar *part)
{
	GQuark quark;
	guchar *buf;
	gsize n_buf;
	
	buf = gkr_pkix_asn1_read_value (asn, part, &n_buf, NULL);
	if (!buf)
		return 0;
		
	quark = g_quark_from_string ((gchar*)buf);
	g_free (buf);
	
	return quark;
}

gboolean
gkr_pkix_asn1_write_oid (ASN1_TYPE asn, const gchar *part, GQuark val)
{
	const gchar* oid;
	
	g_return_val_if_fail (val, FALSE);
	
	oid = g_quark_to_string (val);
	g_return_val_if_fail (oid, FALSE);
	
	return gkr_pkix_asn1_write_value (asn, part, (const guchar*)oid, 
			                          1 /* any non-null value for OID */);
}

gboolean
gkr_pkix_asn1_read_mpi (ASN1_TYPE asn, const gchar *part, gcry_mpi_t *mpi)
{
  	gcry_error_t gcry;
  	gsize sz;
  	guchar *buf;

	buf = gkr_pkix_asn1_read_value (asn, part, &sz, gkr_secure_realloc);
	if (!buf)
		return FALSE;
	
	gcry = gcry_mpi_scan (mpi, GCRYMPI_FMT_STD, buf, sz, &sz);
	gkr_secure_free (buf);

	if (gcry != 0)
		return FALSE;
	
	return TRUE;
}

gboolean
gkr_pkix_asn1_write_mpi (ASN1_TYPE asn, const gchar *part, gcry_mpi_t mpi)
{
	gcry_error_t gcry;
	gsize len;
	guchar *buf;
	int res;

	g_assert (asn);
	g_assert (part);
	g_assert (mpi);
	
	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_STD, NULL, 0, &len, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);
	g_return_val_if_fail (len > 0, FALSE); 

	buf = gkr_secure_alloc (len);
	
	gcry = gcry_mpi_print (GCRYMPI_FMT_STD, buf, len, &len, mpi);	
	g_return_val_if_fail (gcry == 0, FALSE);
	
	res = asn1_write_value (asn, part, buf, len);
	gkr_secure_free (buf);
	
	if (res != ASN1_SUCCESS)
		return FALSE;
		
	return TRUE;
}

static int
atoin (const char *p, int digits)
{
	int ret = 0, base = 1;
	while(--digits >= 0) {
		if (p[digits] < '0' || p[digits] > '9')
			return -1;
		ret += (p[digits] - '0') * base;
		base *= 10;
	}
	return ret;
}

static int
two_to_four_digit_year (int year)
{
	time_t now;
	struct tm tm;
	int century, current;
	
	g_return_val_if_fail (year > 0 && year <= 99, -1);
	
	/* Get the current year */
	now = time (NULL);
	g_return_val_if_fail (now >= 0, -1);
	if (!gmtime_r (&now, &tm))
		g_return_val_if_reached (-1);

	current = (tm.tm_year % 100);
	century = (tm.tm_year + 1900) - current;

	/* 
	 * Check if it's within 40 years before the 
	 * current date. 
	 */
	if (current < 40) {
		if (year < current)
			return century + year;
		if (year > 100 - (40 - current))
			return (century - 100) + year;
	} else {
		if (year < current && year > (current - 40))
			return century + year;
	}
	
	/* 
	 * If it's after then adjust for overflows to
	 * the next century.
	 */
	if (year < current)
		return century + 100 + year;
	else
		return century + year;
}

#ifndef HAVE_TIMEGM
time_t timegm(struct tm *t)
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
#endif //NOT_HAVE_TIMEGM

time_t
gkr_pkix_asn1_parse_utc_time (const gchar *time)
{
	struct tm when;
	guint n_time;
	time_t result;
	const char *p, *e;
	int year;

	g_assert (time);	
	n_time = strlen (time);
	
	/* YYMMDDhhmmss.ffff Z | +0000 */
	if (n_time < 6 || n_time >= 28) 
		return -1;
	
	/* Reset everything to default legal values */
	memset (&when, 0, sizeof (when));
	when.tm_mday = 1;
	
	/* Select the digits part of it */
	p = time;
	for (e = p; *e >= '0' && *e <= '9'; ++e);
	
	if (p + 2 <= e) {
		year = atoin (p, 2);
		p += 2;
		
		/* 
		 * 40 years in the past is our century. 60 years
		 * in the future is the next century. 
		 */
		when.tm_year = two_to_four_digit_year (year) - 1900;
	}
	if (p + 2 <= e) {
		when.tm_mon = atoin (p, 2) - 1;
		p += 2;
	}
	if (p + 2 <= e) {
		when.tm_mday = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when.tm_hour = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when.tm_min = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when.tm_sec = atoin (p, 2);
		p += 2;
	}

	if (when.tm_year < 0 || when.tm_year > 9999 ||
	    when.tm_mon < 0 || when.tm_mon > 11 ||
	    when.tm_mday < 1 || when.tm_mday > 31 ||
	    when.tm_hour < 0 || when.tm_hour > 23 ||
	    when.tm_min < 0 || when.tm_min > 59 ||
	    when.tm_sec < 0 || when.tm_sec > 59)
	    	return -1;
	    	
	/* Make sure all that got parsed */
	if (p != e)
		return -1;

	/* In order to work with 32 bit time_t. */
  	if (sizeof (time_t) <= 4 && when.tm_year >= 2038)
		return (time_t) 2145914603;  /* 2037-12-31 23:23:23 */
		
	/* Covnvert to seconds since epoch */
	result = timegm (&when);
	
	/* Now the remaining optional stuff */
	e = time + n_time;
		
	/* See if there's a fraction, and discard it if so */
	if (p < e && *p == '.' && p + 5 <= e)
		p += 5;
		
	/* See if it's UTC */
	if (p < e && *p == 'Z') {
		p += 1;

	/* See if it has a timezone */	
	} else if ((*p == '-' || *p == '+') && p + 3 <= e) { 
		int off, neg;
		
		neg = *p == '-';
		++p;
		
		off = atoin (p, 2) * 3600;
		if (off < 0 || off > 86400)
			return -1;
		p += 2;
		
		if (p + 2 <= e) {
			off += atoin (p, 2) * 60;
			p += 2;
		}

		/* Use TZ offset */		
		if (neg)
			result -= off;
		else
			result += off;
	}

	/* Make sure everything got parsed */	
	if (p != e)
		return -1;

	return result;
}

time_t
gkr_pkix_asn1_parse_general_time (const gchar *time)
{
	struct tm when;
	guint n_time;
	time_t result;
	const char *p, *e;

	g_assert (time);	
	n_time = strlen (time);
	
	/* YYYYMMDDhhmmss.ffff Z | +0000 */
	if (n_time < 8 || n_time >= 30) 
		return -1;
	
	/* Reset everything to default legal values */
	memset (&when, 0, sizeof (when));
	when.tm_mday = 1;
	
	/* Select the digits part of it */
	p = time;
	for (e = p; *e >= '0' && *e <= '9'; ++e);
	
	if (p + 4 <= e) {
		when.tm_year = atoin (p, 4) - 1900;
		p += 4;
	}
	if (p + 2 <= e) {
		when.tm_mon = atoin (p, 2) - 1;
		p += 2;
	}
	if (p + 2 <= e) {
		when.tm_mday = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when.tm_hour = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when.tm_min = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when.tm_sec = atoin (p, 2);
		p += 2;
	}

	if (when.tm_year < 0 || when.tm_year > 9999 ||
	    when.tm_mon < 0 || when.tm_mon > 11 ||
	    when.tm_mday < 1 || when.tm_mday > 31 ||
	    when.tm_hour < 0 || when.tm_hour > 23 ||
	    when.tm_min < 0 || when.tm_min > 59 ||
	    when.tm_sec < 0 || when.tm_sec > 59)
	    	return -1;
	
	/* Make sure all that got parsed */
	if (p != e)
		return -1;
		
	/* Covnvert to seconds since epoch */
	result = timegm (&when);
	
	/* Now the remaining optional stuff */
	e = time + n_time;
		
	/* See if there's a fraction, and discard it if so */
	if (p < e && *p == '.' && p + 5 <= e)
		p += 5;
		
	/* See if it's UTC */
	if (p < e && *p == 'Z') {
		p += 1;

	/* See if it has a timezone */	
	} else if ((*p == '-' || *p == '+') && p + 3 <= e) { 
		int off, neg;
		
		neg = *p == '-';
		++p;
		
		off = atoin (p, 2) * 3600;
		if (off < 0 || off > 86400)
			return -1;
		p += 2;
		
		if (p + 2 <= e) {
			off += atoin (p, 2) * 60;
			p += 2;
		}

		/* Use TZ offset */		
		if (neg)
			result -= off;
		else
			result += off;
	}

	/* Make sure everything got parsed */	
	if (p != e)
		return -1;

	return result;
}

gboolean
gkr_pkix_asn1_read_time (ASN1_TYPE asn, const gchar *part, time_t *val)
{
	#define MAX_TIME 1024
	gchar ttime[MAX_TIME];
	gchar *name;
	int len, res;

	len = sizeof (ttime) - 1;
	res = asn1_read_value (asn, part, ttime, &len);
	if (res != ASN1_SUCCESS)
		return FALSE;
		
	/* CHOICE */
	if (strcmp (ttime, "generalTime") == 0) {
		name = g_strconcat (part, ".generalTime", NULL);
		len = sizeof (ttime) - 1;
		res = asn1_read_value (asn, name, ttime, &len);
		g_free (name);
		if (res != ASN1_SUCCESS)
			return FALSE;
		
		*val = gkr_pkix_asn1_parse_general_time (ttime);
		
	/* UTCTIME */
	} else {
		name = g_strconcat (part, ".utcTime", NULL);
		len = sizeof (ttime) - 1;
		res = asn1_read_value (asn, name, ttime, &len);
		g_free (name);
		if (res != ASN1_SUCCESS)
			return FALSE;
	
		*val = gkr_pkix_asn1_parse_utc_time (ttime);
    	}

	if (*val < (time_t)0)
		return FALSE;
		
	return TRUE;	
}
