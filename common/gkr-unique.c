/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-unique.c - Unique binary identifiers

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

#include "gkr-unique.h"

#include <glib.h>
#include <gcrypt.h>

/* 
 * Memory is laid out like
 * 
 * - 32-bit uint length, including itself
 * - length bytes
 * - 
 */

#define DEBUG_HEADER 1

#ifdef DEBUG_HEADER
#define HEADER_V 0xABABABAB
#endif 

GType
gkr_unique_get_boxed_type (void)
{
	static GType type = 0;
	
	if (!type) {
		type = g_boxed_type_register_static ("gkrunique", 
	                                             (GBoxedCopyFunc)gkr_unique_dup,
	                                             gkr_unique_free);
	}
	
	return type;
}

gkrunique  
gkr_unique_new (const guchar *data, gsize n_data)
{
	guint *uni;
	guint len;

	g_assert (data != NULL);
	g_assert (n_data > 0);
	g_assert (n_data < GKR_UNIQUE_MAX_LENGTH);
	
	len = sizeof (guint) + n_data;
	
#ifdef DEBUG_HEADER
	len += sizeof (guint);
#endif

	uni = g_slice_alloc (len);
	
#ifdef DEBUG_HEADER
	len -= sizeof (guint);
	uni[0] = HEADER_V;
	++uni;
#endif

	uni[0] = len;
	memcpy (uni + 1, data, n_data);
	return uni;
}

gkrunique
gkr_unique_new_digest (const guchar *data, gsize n_data)
{
	guint *uni;
	guint len;
	
	g_assert (data != NULL);
	g_assert (n_data > 0);

	len = sizeof (guint) + 20;
	
#ifdef DEBUG_HEADER
	len += sizeof (guint);
#endif

	uni = g_slice_alloc (len);
	
#ifdef DEBUG_HEADER
	len -= sizeof (guint);
	uni[0] = HEADER_V;
	++uni;
#endif

	uni[0] = len;	
	gcry_md_hash_buffer (GCRY_MD_SHA1, uni + 1, data, n_data);

	return uni;
}

gkrunique
gkr_unique_new_digestv (const guchar *data, gsize n_data, ...)
{
	gcry_md_hd_t mdh;
	gcry_error_t gcry;
	const guchar *digest;
	gkrunique uni;
	va_list va;
	
	g_assert (data);
	g_assert (n_data > 0);
	
	gcry = gcry_md_open (&mdh, GCRY_MD_SHA1, 0);
	g_return_val_if_fail (gcry == 0, NULL);
	
	gcry_md_write (mdh, data, n_data);
	
	va_start (va, n_data);
	
	for (;;) {
		data = va_arg (va, const guchar*);
		if (!data)
			break;
		n_data = va_arg (va, gsize);
		
		g_assert (n_data > 0);
		gcry_md_write (mdh, data, n_data);
	}
	
	va_end (va);
	
	digest = gcry_md_read (mdh, 0);
	g_return_val_if_fail (digest != NULL, NULL);
	
	uni = gkr_unique_new (digest, 20);

	gcry_md_close (mdh);
	return uni;
}

guint
gkr_unique_hash (gkrconstunique v)
{
	const guint *uni = (guint*)v;
	const guchar *p;
	guint hash, i;

	hash = 0;	
	for (p = (guchar*)uni, i = *uni; i; i--, p++)
		 hash = hash * 33 + *p;
		 
	return hash;
}

gboolean
gkr_unique_equals (gkrconstunique v1, gkrconstunique v2)
{
	const guint *u1 = (guint*)v1;
	const guint *u2 = (guint*)v2;
	if (!u1 || !u2)
		return FALSE;
	g_assert (*u1 > 0 && *u2 > 0);
	g_assert (*u1 < GKR_UNIQUE_MAX_LENGTH && *u2 < GKR_UNIQUE_MAX_LENGTH);
	return (*u1 == *u2 && memcmp (u1, u2, *u1) == 0);
}

gkrunique
gkr_unique_dup (gkrconstunique v)
{
	const guint *uni = (guint*)v;
	guint *nuni;
	guint len;
	
	if (!uni)
		return NULL;

	g_assert (*uni > 0);
	g_assert (*uni < GKR_UNIQUE_MAX_LENGTH);
	len = uni[0];
	
#ifdef DEBUG_HEADER
	len += sizeof (guint);
#endif
	
	nuni = g_slice_alloc (len);
	
#ifdef DEBUG_HEADER
	nuni[0] = HEADER_V;
	len -= sizeof (guint);
	nuni++;
#endif

	memcpy (nuni, uni, len);
	return nuni;
}

gconstpointer
gkr_unique_get_raw (gkrconstunique v, gsize *len)
{
	const guint *uni = (guint*)v;
	if (!uni)
		return NULL;
	g_assert (*uni > 0);
	g_assert (*uni < GKR_UNIQUE_MAX_LENGTH);
	if (len)
		*len = *uni - sizeof (guint);
	return (uni + 1);	
}

void
gkr_unique_free (gkrunique v)
{
	guint *uni = (guint*)v;
	guint len;
	
	if (!uni)
		return;

	g_assert (uni[0] > 0);
	g_assert (uni[0] < GKR_UNIQUE_MAX_LENGTH);
	len = uni[0]; 
	
#ifdef DEBUG_HEADER
	--uni;
	g_assert (uni[0] == HEADER_V);
	len += sizeof (guint);
#endif
	
	g_slice_free1 (len, uni);
}
