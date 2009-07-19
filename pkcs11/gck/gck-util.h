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

#ifndef GCKUTIL_H_
#define GCKUTIL_H_

#include <glib.h>

#include <gcrypt.h>

#include "pkcs11/pkcs11.h"

guint                 gck_util_ulong_hash                         (gconstpointer ptr_to_ulong);

gboolean              gck_util_ulong_equal                        (gconstpointer ptr_to_ulong_1, 
                                                                   gconstpointer ptr_to_ulong_2);

gulong*               gck_util_ulong_alloc                        (gulong value);

void                  gck_util_ulong_free                         (gpointer ptr_to_ulong);

CK_RV                 gck_util_return_data                        (CK_VOID_PTR output,
                                                                   CK_ULONG_PTR n_output,
                                                                   gconstpointer input,
                                                                   gsize n_input);

CK_RV                 gck_attribute_set_mpi                       (CK_ATTRIBUTE_PTR attr, 
                                                                   gcry_mpi_t mpi);

CK_ULONG              gck_util_next_handle                        (void);

void                  gck_util_dispose_unref                      (gpointer object); 

#endif /* GCKUTIL_H_ */
