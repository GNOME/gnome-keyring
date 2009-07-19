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

#include "gck-sexp.h"

struct _GckSexp {
	gint refs;
	gcry_sexp_t real;
};

GckSexp*
gck_sexp_new (gcry_sexp_t real)
{
	GckSexp *sexp;
	g_return_val_if_fail (real, NULL);
	sexp = g_slice_new0 (GckSexp);
	sexp->refs = 1;
	sexp->real = real;
	return sexp;
}

GckSexp*
gck_sexp_ref (GckSexp *sexp)
{
	g_return_val_if_fail (sexp, NULL);
	++(sexp->refs);
	return sexp;
}

void
gck_sexp_unref (gpointer data)
{
	GckSexp *sexp = data;
	g_return_if_fail (sexp);
	if (--(sexp->refs) == 0) {
		g_assert (sexp->real);
		gcry_sexp_release (sexp->real);
		g_slice_free (GckSexp, sexp); 
	}
}

gcry_sexp_t
gck_sexp_get (GckSexp *sexp)
{
	g_return_val_if_fail (sexp, NULL);
	g_return_val_if_fail (sexp->real, NULL);
	return sexp->real;
}

GType
gck_sexp_boxed_type (void)
{
	static GType type = 0;
	if (!type) 
		type = g_boxed_type_register_static ("GckSexp", 
		                                     (GBoxedCopyFunc)gck_sexp_ref,
		                                     (GBoxedFreeFunc)gck_sexp_unref);
	return type;
}
