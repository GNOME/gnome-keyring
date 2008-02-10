/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-id.c - Unique binary identifiers

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

#include "gkr-id.h"

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
gkr_id_get_boxed_type (void)
{
	static GType type = 0;
	
	if (!type) {
		type = g_boxed_type_register_static ("gkrid", 
		                                     (GBoxedCopyFunc)gkr_id_dup,
		                                     gkr_id_free);
	}
	
	return type;
}

gkrid  
gkr_id_new (const guchar *data, gsize n_data)
{
	guint *id;
	guint len;

	g_assert (data != NULL);
	g_assert (n_data > 0);
	g_assert (n_data < GKR_ID_MAX_LENGTH);
	
	len = sizeof (guint) + n_data;
	
#ifdef DEBUG_HEADER
	len += sizeof (guint);
#endif

	id = g_slice_alloc (len);
	
#ifdef DEBUG_HEADER
	len -= sizeof (guint);
	id[0] = HEADER_V;
	++id;
#endif

	id[0] = len;
	memcpy (id + 1, data, n_data);
	return id;
}

gkrid
gkr_id_new_digest (const guchar *data, gsize n_data)
{
	guint *id;
	guint len;
	
	g_assert (data != NULL);
	g_assert (n_data > 0);

	len = sizeof (guint) + 20;
	
#ifdef DEBUG_HEADER
	len += sizeof (guint);
#endif

	id = g_slice_alloc (len);
	
#ifdef DEBUG_HEADER
	len -= sizeof (guint);
	id[0] = HEADER_V;
	++id;
#endif

	id[0] = len;	
	gcry_md_hash_buffer (GCRY_MD_SHA1, id + 1, data, n_data);

	return id;
}

gkrid
gkr_id_new_digestv (const guchar *data, gsize n_data, ...)
{
	gcry_md_hd_t mdh;
	gcry_error_t gcry;
	const guchar *digest;
	gkrid id;
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
	
	id = gkr_id_new (digest, 20);

	gcry_md_close (mdh);
	return id;
}

guint
gkr_id_hash (gkrconstid v)
{
	const guint *id = (guint*)v;
	const guchar *p;
	guint hash, i;

	hash = 0;	
	for (p = (guchar*)id, i = *id; i; i--, p++)
		 hash = hash * 33 + *p;
		 
	return hash;
}

gboolean
gkr_id_equals (gkrconstid v1, gkrconstid v2)
{
	const guint *u1 = (guint*)v1;
	const guint *u2 = (guint*)v2;
	if (!u1 || !u2)
		return FALSE;
	g_assert (*u1 > 0 && *u2 > 0);
	g_assert (*u1 < GKR_ID_MAX_LENGTH && *u2 < GKR_ID_MAX_LENGTH);
	return (*u1 == *u2 && memcmp (u1, u2, *u1) == 0);
}

gkrid
gkr_id_dup (gkrconstid v)
{
	const guint *id = (guint*)v;
	guint *nid;
	guint len;
	
	if (!id)
		return NULL;

	g_assert (*id > 0);
	g_assert (*id < GKR_ID_MAX_LENGTH);
	len = id[0];
	
#ifdef DEBUG_HEADER
	len += sizeof (guint);
#endif
	
	nid = g_slice_alloc (len);
	
#ifdef DEBUG_HEADER
	nid[0] = HEADER_V;
	len -= sizeof (guint);
	nid++;
#endif

	memcpy (nid, id, len);
	return nid;
}

gconstpointer
gkr_id_get_raw (gkrconstid v, gsize *len)
{
	const guint *id = (guint*)v;
	if (!id)
		return NULL;
	g_assert (*id > 0);
	g_assert (*id < GKR_ID_MAX_LENGTH);
	if (len)
		*len = *id - sizeof (guint);
	return (id + 1);	
}

void
gkr_id_free (gkrid v)
{
	guint *id = (guint*)v;
	guint len;
	
	if (!id)
		return;

	g_assert (id[0] > 0);
	g_assert (id[0] < GKR_ID_MAX_LENGTH);
	len = id[0]; 
	
#ifdef DEBUG_HEADER
	--id;
	g_assert (id[0] == HEADER_V);
	len += sizeof (guint);
#endif
	
	g_slice_free1 (len, id);
}
