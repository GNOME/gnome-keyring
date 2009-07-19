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

#ifndef GCKSEXP_H_
#define GCKSEXP_H_

#include <gcrypt.h>

#include <glib-object.h>

#include "gck-types.h"

GckSexp*       gck_sexp_new           (gcry_sexp_t sexp);

GckSexp*       gck_sexp_ref           (GckSexp *sexp);

void           gck_sexp_unref         (gpointer sexp);

gcry_sexp_t    gck_sexp_get           (GckSexp *sexp);

#define        GCK_BOXED_SEXP         (gck_sexp_boxed_type ())

GType          gck_sexp_boxed_type    (void);

#endif /* GCKSEXPHANDLE_H_ */
