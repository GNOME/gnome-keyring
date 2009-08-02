/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-asn1.c - ASN.1 helper routines

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

#include "egg-asn1.h"
#include "egg-oid.h"

#include <libtasn1.h>

#include <string.h>

#include <glib/gi18n-lib.h>

/* 
 * HACK: asn1Parser defines these arrays as extern const, which gives 
 * gcc a fit. So we def it out. 
 */
 
#define extern 
#include "asn1-def-pk.h"
#include "asn1-def-pkix.h"
#undef extern 

static ASN1_TYPE asn1_pk = NULL; 
static ASN1_TYPE asn1_pkix = NULL;

static void
init_asn1_trees (void)
{
	static volatile gsize asn1_initialized = 0;
	int res;
	
	if (g_once_init_enter (&asn1_initialized)) {
		res = asn1_array2tree (pk_asn1_tab, &asn1_pk, NULL);
		g_return_if_fail (res == ASN1_SUCCESS);
		res = asn1_array2tree (pkix_asn1_tab, &asn1_pkix, NULL);
		g_return_if_fail (res == ASN1_SUCCESS);
		g_once_init_leave (&asn1_initialized, 1);
	}
}

ASN1_TYPE 
egg_asn1_get_pk_asn1type (void)
{
	init_asn1_trees ();
	return asn1_pk;
}

ASN1_TYPE 
egg_asn1_get_pkix_asn1type (void)
{
	init_asn1_trees ();
	return asn1_pkix;
}
	
ASN1_TYPE
egg_asn1_decode (const gchar *type, const guchar *data, gsize n_data)
{
	ASN1_TYPE base = ASN1_TYPE_EMPTY;
	ASN1_TYPE asn;
	int res;
	
	if (strncmp (type, "PKIX1.", 6) == 0)
		base = egg_asn1_get_pkix_asn1type ();
	else if (strncmp (type, "PK.", 3) == 0)
		base = egg_asn1_get_pk_asn1type ();
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
egg_asn1_encode (ASN1_TYPE asn, const gchar* part, gsize *n_data, EggAllocator alloc)
{
	guchar *data;
	int res, len;
	
	g_assert (asn);
	g_assert (n_data);
	
	len = 0;
	res = asn1_der_coding (asn, part, NULL, &len, NULL); 
	g_return_val_if_fail (res == ASN1_MEM_ERROR, NULL);
	
	if (!alloc)
		alloc = (EggAllocator)g_realloc;

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
egg_asn1_element_length (const guchar *data, gsize n_data)
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
egg_asn1_read_element (ASN1_TYPE asn, const guchar *data, gsize n_data, 
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
egg_asn1_read_content (ASN1_TYPE asn, const guchar *data, gsize n_data, 
                            const gchar *part, gsize *n_content)
{
	const guchar *raw;
	gsize n_raw;
	
	g_return_val_if_fail (asn != NULL, NULL);
	g_return_val_if_fail (part != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (n_content != NULL, NULL);
	
	raw = egg_asn1_read_element (asn, data, n_data, part, &n_raw);
	if (!raw)
		return NULL;

	return egg_asn1_element_content (raw, n_raw, n_content);		
}

const guchar*
egg_asn1_element_content (const guchar *data, gsize n_data, gsize *n_content)
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
egg_asn1_read_value (ASN1_TYPE asn, const gchar *part, gsize *len, EggAllocator allocator)
{
	int l, res;
	guchar *buf;
	
	g_return_val_if_fail (asn != NULL, NULL);
	g_return_val_if_fail (part != NULL, NULL);
	g_return_val_if_fail (len != NULL, NULL);
	
	if (allocator == NULL)
		allocator = (EggAllocator)g_realloc;
	
	l = 0;
	res = asn1_read_value (asn, part, NULL, &l);
	g_return_val_if_fail (res != ASN1_SUCCESS, NULL);
	if (res != ASN1_MEM_ERROR)
		return NULL;
		
	/* Always null terminate it, just for convenience */
	buf = (allocator) (NULL, l + 1);
	g_return_val_if_fail (buf, NULL);
	memset (buf, 0, l + 1);
	
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
egg_asn1_write_value (ASN1_TYPE asn, const gchar *part, 
		                   const guchar* value, gsize len)
{
	int res;

	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (part, FALSE);
	g_return_val_if_fail (!len || value, FALSE);
	
	res = asn1_write_value (asn, part, (const void*)value, (int)len);
	return res == ASN1_SUCCESS;
}

static gboolean
ascii_length_equals (const gchar *str, gconstpointer data, gsize n_data)
{
	g_assert (str);
	if (!data)
		return FALSE;
	if (strlen (str) != n_data)
		return FALSE;
	return strncmp (str, data, n_data) == 0;
}

static gboolean
ascii_length_case_equals (const gchar *str, gconstpointer data, gsize n_data)
{
	g_assert (str);
	if (!data)
		return FALSE;
	if (strlen (str) != n_data)
		return FALSE;
	return g_ascii_strncasecmp (str, data, n_data) == 0;
}

gboolean
egg_asn1_read_boolean (ASN1_TYPE asn, const gchar *part, gboolean *val)
{
	gchar buffer[32];
	int n_buffer = sizeof (buffer);
	int res;
	
	memset (buffer, 0, sizeof (buffer));
	
	res = asn1_read_value (asn, part, buffer, &n_buffer);
	if (res != ASN1_SUCCESS || !n_buffer)
		return FALSE;
		
	if (ascii_length_case_equals ("TRUE", buffer, n_buffer - 1))
		*val = TRUE;
	else
		*val = FALSE;
		
	return TRUE;
}

gboolean
egg_asn1_read_uint (ASN1_TYPE asn, const gchar *part, guint *val)
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
egg_asn1_write_uint (ASN1_TYPE asn, const gchar *part, guint32 val)
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
egg_asn1_read_oid (ASN1_TYPE asn, const gchar *part)
{
	GQuark quark;
	guchar *buf;
	gpointer end;
	gsize n_buf;
	
	buf = egg_asn1_read_value (asn, part, &n_buf, NULL);
	if (!buf || !n_buf)
		return 0;

	/* Make sure the string is actually that long */
	end = memchr (buf, 0, n_buf - 1);
	if (end != NULL)
		return 0;

	quark = g_quark_from_string ((gchar*)buf);
	g_free (buf);
	return quark;
}

gboolean
egg_asn1_write_oid (ASN1_TYPE asn, const gchar *part, GQuark val)
{
	const gchar* oid;
	
	g_return_val_if_fail (val, FALSE);
	
	oid = g_quark_to_string (val);
	g_return_val_if_fail (oid, FALSE);
	
	return egg_asn1_write_value (asn, part, (const guchar*)oid, strlen (oid));
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
	
	g_return_val_if_fail (year >= 0 && year <= 99, -1);
	
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

static gboolean
parse_utc_time (const gchar *time, gsize n_time,
                struct tm* when, gint *offset)
{
	const char *p, *e;
	int year;

	g_assert (when);
	g_assert (time);
	g_assert (offset);
	
	if (n_time != strlen (time))
		return FALSE;
	
	/* YYMMDDhhmmss.ffff Z | +0000 */
	if (n_time < 6 || n_time >= 28) 
		return FALSE;
	
	/* Reset everything to default legal values */
	memset (when, 0, sizeof (*when));
	*offset = 0;
	when->tm_mday = 1;
	
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
		when->tm_year = two_to_four_digit_year (year) - 1900;
	}
	if (p + 2 <= e) {
		when->tm_mon = atoin (p, 2) - 1;
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_mday = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_hour = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_min = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_sec = atoin (p, 2);
		p += 2;
	}

	if (when->tm_year < 0 || when->tm_year > 9999 ||
	    when->tm_mon < 0 || when->tm_mon > 11 ||
	    when->tm_mday < 1 || when->tm_mday > 31 ||
	    when->tm_hour < 0 || when->tm_hour > 23 ||
	    when->tm_min < 0 || when->tm_min > 59 ||
	    when->tm_sec < 0 || when->tm_sec > 59)
	    	return FALSE;
	    	
	/* Make sure all that got parsed */
	if (p != e)
		return FALSE;

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
			*offset = 0 - off;
		else
			*offset = off;
	}

	/* Make sure everything got parsed */	
	if (p != e)
		return FALSE;

	return TRUE;
}

static time_t
when_to_time (struct tm *when, gint offset)
{
	time_t result;
	
	g_assert (when);
	
	/* In order to work with 32 bit time_t. */
  	if (sizeof (time_t) <= 4 && when->tm_year >= 2038)
		return (time_t) 2145914603;  /* 2037-12-31 23:23:23 */
	
	/* Convert to seconds since epoch */
	result = timegm (when);
	if (result >= 0) 
		result += offset;
	
	return result;
}

glong
egg_asn1_time_parse_utc (const gchar *time, gssize n_time)
{
	struct tm when;
	gint offset;
	
	g_return_val_if_fail (time, -1);

	if (n_time == -1)
		n_time = strlen (time);
	
	if (!parse_utc_time (time, n_time, &when, &offset))
		return -1;
	
	return when_to_time (&when, offset);
}

static gboolean
parse_general_time (const gchar *time, gsize n_time,
                    struct tm* when, gint *offset)
{
	const char *p, *e;

	g_assert (time);
	g_assert (when);
	g_assert (offset);

	if (strlen (time) != n_time)
		return FALSE;
	
	/* YYYYMMDDhhmmss.ffff Z | +0000 */
	if (n_time < 8 || n_time >= 30) 
		return FALSE;
	
	/* Reset everything to default legal values */
	memset (when, 0, sizeof (*when));
	*offset = 0;
	when->tm_mday = 1;
	
	/* Select the digits part of it */
	p = time;
	for (e = p; *e >= '0' && *e <= '9'; ++e);
	
	if (p + 4 <= e) {
		when->tm_year = atoin (p, 4) - 1900;
		p += 4;
	}
	if (p + 2 <= e) {
		when->tm_mon = atoin (p, 2) - 1;
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_mday = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_hour = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_min = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_sec = atoin (p, 2);
		p += 2;
	}

	if (when->tm_year < 0 || when->tm_year > 9999 ||
	    when->tm_mon < 0 || when->tm_mon > 11 ||
	    when->tm_mday < 1 || when->tm_mday > 31 ||
	    when->tm_hour < 0 || when->tm_hour > 23 ||
	    when->tm_min < 0 || when->tm_min > 59 ||
	    when->tm_sec < 0 || when->tm_sec > 59)
	    	return FALSE;
	
	/* Make sure all that got parsed */
	if (p != e)
		return FALSE;
		
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
			*offset = 0 - off;
		else
			*offset = off;
	}

	/* Make sure everything got parsed */	
	if (p != e)
		return FALSE;

	return TRUE;
}

glong
egg_asn1_time_parse_general (const gchar *time, gssize n_time)
{
	struct tm when;
	gint offset;
	
	g_return_val_if_fail (time, -1);
	
	if (n_time == -1)
		n_time = strlen (time);

	if (!parse_general_time (time, n_time, &when, &offset))
		return -1;
	
	return when_to_time (&when, offset);
}

static gboolean
read_asn1_time (ASN1_TYPE asn, const gchar *part, struct tm *when, gint *offset)
{
	gchar ttime[256];
	gchar *name;
	int len, res;
	
	g_assert (asn);
	g_assert (part);
	g_assert (when);
	g_assert (offset);

	len = sizeof (ttime);
	res = asn1_read_value (asn, part, ttime, &len);
	if (res != ASN1_SUCCESS)
		return FALSE;
	--len; /* libtasn1 returns the null terminator in this count */

	/* CHOICE */
	if (ascii_length_equals ("generalTime", ttime, len)) {
		name = g_strconcat (part, ".generalTime", NULL);
		len = sizeof (ttime) - 1;
		res = asn1_read_value (asn, name, ttime, &len);
		g_free (name);
		if (res != ASN1_SUCCESS)
			return FALSE;
		return parse_general_time (ttime, len - 1, when, offset);
		
	/* UTCTIME */
	} else if (ascii_length_equals ("utcTime", ttime, len)) {
		name = g_strconcat (part, ".utcTime", NULL);
		len = sizeof (ttime) - 1;
		res = asn1_read_value (asn, name, ttime, &len);
		g_free (name);
		if (res != ASN1_SUCCESS)
			return FALSE;
		return parse_utc_time (ttime, len - 1, when, offset);
	}

	return FALSE;	
}

gboolean
egg_asn1_read_time (ASN1_TYPE asn, const gchar *part, time_t *val)
{
	struct tm when;
	gint offset;
	
	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (part, FALSE);
	g_return_val_if_fail (val, FALSE);
	
	if (!read_asn1_time (asn, part, &when, &offset))
		return FALSE;
	
	*val = when_to_time (&when, offset);
	return TRUE;
}

gboolean
egg_asn1_read_date (ASN1_TYPE asn, const gchar *part, GDate *date)
{
	struct tm when;
	gint offset;
	
	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (part, FALSE);
	g_return_val_if_fail (date, FALSE);
	
	if (!read_asn1_time (asn, part, &when, &offset))
		return FALSE;
	
	g_date_set_dmy (date, when.tm_mday, when.tm_mon + 1, when.tm_year + 1900);
	return g_date_valid (date);
}

/* -------------------------------------------------------------------------------
 * Reading DN's
 */

static const char HEXC[] = "0123456789ABCDEF";

static gchar*
dn_print_hex_value (const guchar *data, gsize len)
{
	GString *result = g_string_sized_new (len * 2 + 1);
	gsize i;
	
	g_string_append_c (result, '#');
	for (i = 0; i < len; ++i) {
		g_string_append_c (result, HEXC[data[i] >> 4 & 0xf]);
		g_string_append_c (result, HEXC[data[i] & 0xf]);
	}
	
	return g_string_free (result, FALSE);
}

static gchar* 
dn_print_oid_value_parsed (GQuark oid, guint flags, const guchar *data, gsize len)
{
	const gchar *asn_name;
	ASN1_TYPE asn1;
	gchar *part;
	gchar *value;
	gsize n_value;
	
	g_assert (data);
	g_assert (len);
	
	asn_name = asn1_find_structure_from_oid (egg_asn1_get_pkix_asn1type (), 
	                                         g_quark_to_string (oid));
	g_return_val_if_fail (asn_name, NULL);
	
	part = g_strdup_printf ("PKIX1.%s", asn_name);
	asn1 = egg_asn1_decode (part, data, len);
	g_free (part);
	
	if (!asn1) {
		g_message ("couldn't decode value for OID: %s", g_quark_to_string (oid));
		return NULL;
	}

	value = (gchar*)egg_asn1_read_value (asn1, "", &n_value, NULL);
	
	/*
	 * If it's a choice element, then we have to read depending
	 * on what's there.
	 */
	if (value && (flags & EGG_OID_IS_CHOICE)) {
		if (ascii_length_equals ("printableString", value, n_value - 1) ||
			ascii_length_equals ("ia5String", value, n_value - 1 ) ||
			ascii_length_equals ("utf8String", value, n_value - 1) ||
			ascii_length_equals ("teletexString", value, n_value - 1)) {
			part = value;
			value = (gchar*)egg_asn1_read_value (asn1, part, &n_value, NULL);
			g_free (part);
		} else {
			g_free (value);
			return NULL;
		}
	}

	if (!value) {
		g_message ("couldn't read value for OID: %s", g_quark_to_string (oid));
		return NULL;
	}

	/* 
	 * Now we make sure it's UTF-8. 
	 */
	if (!g_utf8_validate (value, n_value, NULL)) {
		gchar *hex = dn_print_hex_value ((guchar*)value, n_value);
		g_free (value);
		value = hex;
	}
	
	return value;
}

static gchar*
dn_print_oid_value (GQuark oid, guint flags, const guchar *data, gsize len)
{
	gchar *value;
	
	g_assert (data);
	g_assert (len);
	
	if (flags & EGG_OID_PRINTABLE) {
		value = dn_print_oid_value_parsed (oid, flags, data, len);
		if (value != NULL)
			return value;
	}
	
	return dn_print_hex_value (data, len);
}

static gchar* 
dn_parse_rdn (ASN1_TYPE asn, const gchar *part)
{
	const gchar *name;
	guint flags;
	GQuark oid;
	gchar *path;
	guchar *value;
	gsize n_value;
	gchar *display;
	gchar *result;
	
	g_assert (asn);
	g_assert (part);
	
	path = g_strdup_printf ("%s.type", part);
	oid = egg_asn1_read_oid (asn, path);
	g_free (path);

	if (!oid)
		return NULL;
	
	path = g_strdup_printf ("%s.value", part);
	value = egg_asn1_read_value (asn, path, &n_value, NULL);
	g_free (path);

	flags = egg_oid_get_flags (oid);
	name = egg_oid_get_name (oid);
	
	g_return_val_if_fail (value, NULL);
	display = dn_print_oid_value (oid, flags, value, n_value);
	
	result = g_strconcat ((flags & EGG_OID_PRINTABLE) ? name : g_quark_to_string (oid), 
			      "=", display, NULL);
	g_free (display);
	
	return result;
}

gchar*
egg_asn1_read_dn (ASN1_TYPE asn, const gchar *part)
{
	gboolean done = FALSE;
	GString *result;
	gchar *path;
	gchar *rdn;
	gint i, j;
	
	g_return_val_if_fail (asn, NULL);
	g_return_val_if_fail (part, NULL);
	
	result = g_string_sized_new (64);
	
	/* Each (possibly multi valued) RDN */
	for (i = 1; !done; ++i) {
		
		/* Each type=value pair of an RDN */
		for (j = 1; TRUE; ++j) {
			path = g_strdup_printf ("%s%s?%u.?%u", part ? part : "", 
			                        part ? "." : "", i, j);
			rdn = dn_parse_rdn (asn, path);
			g_free (path);

			if (!rdn) {
				done = j == 1;
				break;
			}
			
			/* Account for multi valued RDNs */
			if (j > 1)
				g_string_append (result, "+");
			else if (i > 1)
				g_string_append (result, ", ");
			
			g_string_append (result, rdn);
			g_free (rdn);
		}
	}

	/* Returns null when string is empty */
	return g_string_free (result, (result->len == 0));
}

gchar*
egg_asn1_read_dn_part (ASN1_TYPE asn, const gchar *part, const gchar *match)
{
	gboolean done = FALSE;
	const gchar *name;
	guchar *value;
	gsize n_value;
	gchar *path;
	GQuark oid;
	gint i, j;
	
	g_return_val_if_fail (asn, NULL);
	g_return_val_if_fail (part, NULL);
	g_return_val_if_fail (match, NULL);
	
	/* Each (possibly multi valued) RDN */
	for (i = 1; !done; ++i) {
		
		/* Each type=value pair of an RDN */
		for (j = 1; TRUE; ++j) {
			path = g_strdup_printf ("%s%s?%u.?%u.type", 
			                        part ? part : "", 
			                        part ? "." : "", i, j);
			oid = egg_asn1_read_oid (asn, path);
			g_free (path);

			if (!oid) {
				done = j == 1;
				break;
			}
			
			/* Does it match either the OID or the displayable? */
			if (g_ascii_strcasecmp (g_quark_to_string (oid), match) != 0) {
				name = egg_oid_get_name (oid);
				if (!g_ascii_strcasecmp (name, match) == 0)
					continue;
			}

			path = g_strdup_printf ("%s%s?%u.?%u.value", 
			                        part ? part : "", 
			                        part ? "." : "", i, j);
			value = egg_asn1_read_value (asn, path, &n_value, NULL);
			g_free (path);
			
			g_return_val_if_fail (value, NULL);
			return dn_print_oid_value (oid, egg_oid_get_flags (oid), value, n_value);
		}
	}
	
	return NULL;
}

gboolean
egg_asn1_dn_parse (ASN1_TYPE asn, const gchar *part, 
                   EggAsn1DnCallback callback, gpointer user_data)
{
	gboolean done = FALSE;
	gchar *path;
	guchar *value;
	gsize n_value;
	GQuark oid;
	guint i, j;
	
	g_return_val_if_fail (asn, FALSE);
	
	/* Each (possibly multi valued) RDN */
	for (i = 1; !done; ++i) {
		
		/* Each type=value pair of an RDN */
		for (j = 1; TRUE; ++j) {
			
			/* Dig out the type */
			path = g_strdup_printf ("%s%s?%u.?%u.type", 
			                        part ? part : "", 
			                        part ? "." : "", i, j);
			oid = egg_asn1_read_oid (asn, path);
			g_free (path);

			if (!oid) {
				done = j == 1;
				break;
			}

			/* Print the value as nicely as we can */
			path = g_strdup_printf ("%s%s?%u.?%u.value", 
			                        part ? part : "", 
			                        part ? "." : "", i, j);
			value = egg_asn1_read_value (asn, path, &n_value, NULL);
			g_free (path);

			if (!value) {
				done = j == 1;
				break;
			}
			
			if (callback) 
				(callback) (i, oid, value, n_value, user_data);
			
			g_free (value);
		}
	}
	
	return i > 1;
}

gchar*
egg_asn1_dn_print_value (GQuark oid, const guchar *value, gsize n_value)
{
	g_return_val_if_fail (oid, NULL);
	g_return_val_if_fail (value || !n_value, NULL);
	
	return dn_print_oid_value (oid, egg_oid_get_flags (oid), value, n_value);
}
