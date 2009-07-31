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

/*
 * This represents a set of attributes from the secrets API. We 
 * call them 'fields' here, so they don't get mixed up with the 
 * PKCS#11 API's notion of attributes.
 * 
 * Each field has a name, and a string value. 
 * 
 * Previous versions of gnome-keyring had the notion of attributes
 * that were integers. In this version everything is a string.
 * 
 * Compatibility attributes start with gkr:compat:
 * 
 * gkr:compat:uint32:xxxx  The presence of this attribute means that
 * the xxxx attribute is a uint32 in older versions of gnome-keyring.
 * The value of this attribute is insignificant.
 * 
 * gkr:compat:hashed:xxxx  This attribute contains a hashed version
 * of xxxx. 
 */

#define         GCK_BOXED_SECRET_FIELDS                       (gck_secret_fields_boxed_type ())

GType           gck_secret_fields_boxed_type                  (void);

GHashTable*     gck_secret_fields_new                         (void);

void            gck_secret_fields_add                         (GHashTable *fields,
                                                               const gchar *name,
                                                               const gchar *value);

const gchar*    gck_secret_fields_get                         (GHashTable *fields,
                                                               const gchar *name);

CK_RV           gck_secret_fields_parse                       (CK_ATTRIBUTE_PTR attr,
                                                               GHashTable **fields);

CK_RV           gck_secret_fields_serialize                   (CK_ATTRIBUTE_PTR attr,
                                                               GHashTable *fields);

gboolean        gck_secret_fields_match                       (GHashTable *haystack,
                                                               GHashTable *needle);

GList*          gck_secret_fields_get_names                   (GHashTable *fields);

/* COMPAT ------------------------------------------------------------------------ */

GList*          gck_secret_fields_get_compat_hashed_names     (GHashTable *fields);

void            gck_secret_fields_add_compat_uint32           (GHashTable *fields, 
                                                               const gchar *name,
                                                               guint32 value);

gboolean        gck_secret_fields_get_compat_uint32           (GHashTable *fields,
                                                               const gchar *name,
                                                               guint32 *value);

void            gck_secret_fields_add_compat_hashed_string    (GHashTable *fields, 
                                                               const gchar *name,
                                                               const gchar *value);

gboolean        gck_secret_fields_get_compat_hashed_string    (GHashTable *fields, 
                                                               const gchar *name,
                                                               gchar **value);

void            gck_secret_fields_add_compat_hashed_uint32    (GHashTable *fields, 
                                                               const gchar *name, 
                                                               guint32 value);

gboolean        gck_secret_fields_get_compat_hashed_uint32    (GHashTable *fields, 
                                                               const gchar *name,
                                                               guint32 *value);

#endif /* __GCK_SECRET_FIELDS_H__ */
