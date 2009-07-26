/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *  
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef __GCK_SECRET_FIELDS_H__
#define __GCK_SECRET_FIELDS_H__

#include "pkcs11.h"

#include <glib.h>
#include <glib-object.h>

#define             GCK_BOXED_SECRET_FIELDS         (gck_secret_fields_boxed_type ())

GType               gck_secret_fields_boxed_type    (void);

GHashTable*         gck_secret_fields_new           (void);

void                gck_secret_fields_add           (GHashTable *fields,
                                                     const gchar *name,
                                                     const gchar *value);

CK_RV               gck_secret_fields_parse         (CK_ATTRIBUTE_PTR attr,
                                                     GHashTable **fields);

CK_RV               gck_secret_fields_serialize     (CK_ATTRIBUTE_PTR attr,
                                                     GHashTable *fields);

gboolean            gck_secret_fields_match         (GHashTable *haystack,
                                                     GHashTable *needle);

GHashTable*         gck_secret_fields_hash          (GHashTable *fields);

gboolean            gck_secret_fields_has_word      (GHashTable *fields,
                                                     const gchar *name,
                                                     const gchar *word);

#endif /* __GCK_SECRET_FIELDS_H__ */
