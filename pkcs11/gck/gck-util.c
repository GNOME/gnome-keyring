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

#include <glib.h>
#include <glib-object.h>

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
gck_util_return_data (CK_VOID_PTR output, CK_ULONG_PTR n_output,
                      gconstpointer input, gsize n_input)
{
	g_return_val_if_fail (n_output, CKR_GENERAL_ERROR);
	g_return_val_if_fail (input || !n_input, CKR_GENERAL_ERROR);
	
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
	if (n_input)
		memcpy (output, input, n_input);
	return CKR_OK;
}

CK_ULONG
gck_util_next_handle (void)
{
	return (CK_ULONG)g_atomic_int_exchange_and_add (&next_handle, 1);
}

void
gck_util_dispose_unref (gpointer object)
{
	g_return_if_fail (G_IS_OBJECT (object));
	g_object_run_dispose (G_OBJECT (object));
	g_object_unref (object);
}
