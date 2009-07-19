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

#ifndef GCK_ATTRIBUTE_H_
#define GCK_ATTRIBUTE_H_

#include <glib.h>

#include <gcrypt.h>

#include "pkcs11/pkcs11.h"

CK_RV                 gck_attribute_get_bool                           (CK_ATTRIBUTE_PTR attr,
                                                                        gboolean *value);

CK_RV                 gck_attribute_get_time                           (CK_ATTRIBUTE_PTR attr,
                                                                        glong *value);

CK_RV                 gck_attribute_set_bool                           (CK_ATTRIBUTE_PTR attr,
                                                                        CK_BBOOL value);

CK_RV                 gck_attribute_set_ulong                          (CK_ATTRIBUTE_PTR attr, 
                                                                        CK_ULONG value);

CK_RV                 gck_attribute_set_string                         (CK_ATTRIBUTE_PTR attr, 
                                                                        const gchar* string);

CK_RV                 gck_attribute_set_date                           (CK_ATTRIBUTE_PTR attr,
                                                                        time_t when);

CK_RV                 gck_attribute_set_time                           (CK_ATTRIBUTE_PTR attr,
                                                                        glong when);

CK_RV                 gck_attribute_set_data                           (CK_ATTRIBUTE_PTR attr,
                                                                        gconstpointer value,
                                                                        gsize n_value);

CK_RV                 gck_attribute_return_data                        (CK_VOID_PTR output,
                                                                        CK_ULONG_PTR n_output,
                                                                        gconstpointer input,
                                                                        gsize n_input);

CK_RV                 gck_attribute_set_mpi                            (CK_ATTRIBUTE_PTR attr, 
                                                                        gcry_mpi_t mpi);

guint                 gck_attribute_hash                               (gconstpointer v);

gboolean              gck_attribute_equal                              (gconstpointer a,
                                                                        gconstpointer b);

void                  gck_attribute_consume                            (CK_ATTRIBUTE_PTR attr);

gboolean              gck_attribute_consumed                           (CK_ATTRIBUTE_PTR attr);



gboolean              gck_attributes_contains                          (CK_ATTRIBUTE_PTR attrs,
                                                                        CK_ULONG n_attrs,
                                                                        CK_ATTRIBUTE_PTR attr);

void                  gck_attributes_consume                           (CK_ATTRIBUTE_PTR attrs, 
                                                                        CK_ULONG n_attrs, ...);

CK_ATTRIBUTE_PTR      gck_attributes_find                              (CK_ATTRIBUTE_PTR attrs,
                                                                        CK_ULONG n_attrs,
                                                                        CK_ATTRIBUTE_TYPE type);

gboolean              gck_attributes_find_boolean                      (CK_ATTRIBUTE_PTR attrs,
                                                                        CK_ULONG n_attrs,
                                                                        CK_ATTRIBUTE_TYPE type,
                                                                        gboolean *value);

gboolean              gck_attributes_find_ulong                        (CK_ATTRIBUTE_PTR attrs,
                                                                        CK_ULONG n_attrs,
                                                                        CK_ATTRIBUTE_TYPE type,
                                                                        gulong *value);

gboolean              gck_attributes_find_mpi                          (CK_ATTRIBUTE_PTR attrs,
                                                                        CK_ULONG n_attrs,
                                                                        CK_ATTRIBUTE_TYPE type,
                                                                        gcry_mpi_t *mpi);

#endif /* GCK_ATTRIBUTE_H_ */
