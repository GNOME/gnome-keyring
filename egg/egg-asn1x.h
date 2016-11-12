/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-asn1.h - ASN.1/DER parsing and encoding routines

   Copyright (C) 2009 Stefan Walter

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef EGG_ASN1X_H_
#define EGG_ASN1X_H_

#include <glib.h>

#ifndef HAVE_EGG_ALLOCATOR
typedef void* (*EggAllocator) (void* p, gsize);
#define HAVE_EGG_ALLOCATOR
#endif

typedef struct _EggAsn1xDef EggAsn1xDef;

typedef enum {
	EGG_ASN1X_CONSTANT = 1,
	EGG_ASN1X_IDENTIFIER = 2,
	EGG_ASN1X_INTEGER = 3,
	EGG_ASN1X_BOOLEAN = 4,
	EGG_ASN1X_SEQUENCE = 5,
	EGG_ASN1X_BIT_STRING = 6,
	EGG_ASN1X_OCTET_STRING = 7,
	EGG_ASN1X_TAG = 8,
	EGG_ASN1X_DEFAULT = 9,
	EGG_ASN1X_SIZE = 10,
	EGG_ASN1X_SEQUENCE_OF = 11,
	EGG_ASN1X_OBJECT_ID = 12,
	EGG_ASN1X_ANY = 13,
	EGG_ASN1X_SET = 14,
	EGG_ASN1X_SET_OF = 15,
	EGG_ASN1X_DEFINITIONS = 16,
	EGG_ASN1X_TIME = 17,
	EGG_ASN1X_CHOICE = 18,
	EGG_ASN1X_IMPORTS = 19,
	EGG_ASN1X_NULL = 20,
	EGG_ASN1X_ENUMERATED = 21,
	EGG_ASN1X_GENERAL_STRING = 27,
	EGG_ASN1X_NUMERIC_STRING = 28,
	EGG_ASN1X_IA5_STRING = 29,
	EGG_ASN1X_TELETEX_STRING = 30,
	EGG_ASN1X_PRINTABLE_STRING = 31,
	EGG_ASN1X_UNIVERSAL_STRING = 32,
	EGG_ASN1X_BMP_STRING = 33,
	EGG_ASN1X_UTF8_STRING = 34,
	EGG_ASN1X_VISIBLE_STRING = 35,
	EGG_ASN1X_UTC_TIME = 36,
	EGG_ASN1X_GENERALIZED_TIME = 37,
} EggAsn1xType;

typedef enum {
	EGG_ASN1X_NO_STRICT = 0x01,
} EggAsn1xFlags;

GNode*              egg_asn1x_create                 (const EggAsn1xDef *defs,
                                                      const gchar *type);

GNode*              egg_asn1x_create_quark           (const EggAsn1xDef *defs,
                                                      GQuark type);

GNode*              egg_asn1x_create_and_decode      (const EggAsn1xDef *defs,
                                                      const gchar *type,
                                                      GBytes *data);

GNode*              egg_asn1x_create_and_decode_full (const EggAsn1xDef *defs,
                                                      const gchar *type,
                                                      GBytes *data,
                                                      gint options);

void                egg_asn1x_dump                   (GNode *asn);

void                egg_asn1x_clear                  (GNode *asn);

gboolean            egg_asn1x_decode                 (GNode *asn,
                                                      GBytes *data);

gboolean            egg_asn1x_decode_full            (GNode *asn,
                                                      GBytes *data,
                                                      gint options);

void                egg_asn1x_set_any_from           (GNode *node,
                                                      GNode *from);

gboolean            egg_asn1x_set_any_raw            (GNode *node,
                                                      GBytes *raw);

gboolean            egg_asn1x_get_any_into           (GNode *node,
                                                      GNode *into);

gboolean            egg_asn1x_get_any_into_full      (GNode *node,
                                                      GNode *into,
                                                      gint options);

GNode *             egg_asn1x_get_any_as             (GNode *node,
                                                      const EggAsn1xDef *defs,
                                                      const gchar *type);

GNode *             egg_asn1x_get_any_as_full        (GNode *node,
                                                      const EggAsn1xDef *defs,
                                                      const gchar *type,
                                                      gint options);

GBytes *            egg_asn1x_get_any_raw            (GNode *node,
                                                      EggAllocator allocator);

gboolean            egg_asn1x_validate               (GNode *asn,
                                                      gboolean strict);

GBytes *            egg_asn1x_encode                 (GNode *asn,
                                                      EggAllocator allocator);

const gchar*        egg_asn1x_message                (GNode *asn);

GNode*              egg_asn1x_node                   (GNode *asn,
                                                      ...) G_GNUC_NULL_TERMINATED;

const gchar*        egg_asn1x_name                   (GNode *asn);

EggAsn1xType        egg_asn1x_type                   (GNode *asn);

guint               egg_asn1x_count                  (GNode *node);

GNode*              egg_asn1x_append                 (GNode *node);

gboolean            egg_asn1x_have                   (GNode *node);

GNode*              egg_asn1x_get_choice             (GNode *node);

gboolean            egg_asn1x_set_choice             (GNode *node,
                                                      GNode *choice);

gboolean            egg_asn1x_get_boolean            (GNode *node,
                                                      gboolean *value);

void                egg_asn1x_set_boolean            (GNode *node,
                                                      gboolean value);

void                egg_asn1x_set_null               (GNode *node);

GQuark              egg_asn1x_get_enumerated         (GNode *node);

void                egg_asn1x_set_enumerated         (GNode *node,
                                                      GQuark value);

gboolean            egg_asn1x_get_integer_as_ulong   (GNode *node,
                                                      gulong *value);

void                egg_asn1x_set_integer_as_ulong   (GNode *node,
                                                      gulong value);

GBytes *            egg_asn1x_get_integer_as_raw     (GNode *node);

void                egg_asn1x_set_integer_as_raw     (GNode *node,
                                                      GBytes *value);

void                egg_asn1x_take_integer_as_raw    (GNode *node,
                                                      GBytes *value);

GBytes *            egg_asn1x_get_integer_as_usg     (GNode *node);

void                egg_asn1x_set_integer_as_usg     (GNode *node,
                                                      GBytes *value);

void                egg_asn1x_take_integer_as_usg    (GNode *node,
                                                      GBytes *value);

GBytes *            egg_asn1x_get_value_raw          (GNode *node);

GBytes *            egg_asn1x_get_element_raw        (GNode *node);

guchar*             egg_asn1x_get_string_as_raw      (GNode *node,
                                                      EggAllocator allocator,
                                                      gsize *n_string);

void                egg_asn1x_set_string_as_raw      (GNode *node,
                                                      guchar *data,
                                                      gsize n_data,
                                                      GDestroyNotify destroy);

GBytes *            egg_asn1x_get_string_as_bytes    (GNode *node);

void                egg_asn1x_set_string_as_bytes    (GNode *node,
                                                      GBytes *bytes);

GBytes *            egg_asn1x_get_bits_as_raw        (GNode *node,
                                                      guint *n_bits);

void                egg_asn1x_set_bits_as_raw        (GNode *node,
                                                      GBytes *value,
                                                      guint n_bits);

void                egg_asn1x_take_bits_as_raw       (GNode *node,
                                                      GBytes *value,
                                                      guint n_bits);

gboolean            egg_asn1x_get_bits_as_ulong      (GNode *node,
                                                      gulong *value,
                                                      guint *n_bits);

void                egg_asn1x_set_bits_as_ulong      (GNode *node,
                                                      gulong value,
                                                      guint n_bits);

gchar *             egg_asn1x_get_string_as_utf8     (GNode *node,
                                                      EggAllocator allocator);

gboolean            egg_asn1x_set_string_as_utf8     (GNode *node,
                                                      gchar *data,
                                                      GDestroyNotify destroy);

gchar *             egg_asn1x_get_bmpstring_as_utf8  (GNode *node);

glong               egg_asn1x_get_time_as_long       (GNode *node);

gboolean            egg_asn1x_set_time_as_long       (GNode *node,
                                                      glong time);

gboolean            egg_asn1x_get_time_as_date       (GNode *node,
                                                      GDate *date);

gboolean            egg_asn1x_set_time_as_date       (GNode *node,
                                                      GDate *date);

GQuark              egg_asn1x_get_oid_as_quark       (GNode *node);

gboolean            egg_asn1x_set_oid_as_quark       (GNode *node,
                                                      GQuark oid);

gchar *             egg_asn1x_get_oid_as_string      (GNode *node);

gboolean            egg_asn1x_set_oid_as_string      (GNode *node,
                                                      const gchar *oid);

void                egg_asn1x_destroy                (gpointer asn);

glong               egg_asn1x_parse_time_general     (const gchar *time,
                                                      gssize n_time);

glong               egg_asn1x_parse_time_utc         (const gchar *time,
                                                      gssize n_time);

gssize              egg_asn1x_element_length         (const guchar *data,
                                                      gsize n_data);

gconstpointer       egg_asn1x_element_content        (const guchar *data,
                                                      gsize n_data,
                                                      gsize *n_content);

#define             egg_asn1x_assert(expr, node) \
	do { if G_LIKELY(expr) ; else \
		g_assertion_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
		                     egg_asn1x_message (node) ? \
		                     egg_asn1x_message (node) : "[no message]"); } while(0)

#define             egg_asn1x_assert_not_reached(node) \
		g_assertion_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
		                     egg_asn1x_message (node) ? \
		                     egg_asn1x_message (node) : "[no message]")

#endif /*EGG_ASN1X_H_*/
