/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
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
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#if !defined (__GCR_INSIDE_HEADER__) && !defined (GCR_COMPILATION)
#error "Only <gcr/gcr.h> or <gcr/gcr-base.h> can be included directly."
#endif

#ifndef GCR_RECORD_H
#define GCR_RECORD_H

#include <glib.h>
#include <glib-object.h>

/*
 * Gnupg's official format for listing keys is in the '--with-colons' format.
 * This is documented in doc/DETAILS in the gnupg distribution. Looks like:
 *
 * pub:f:1024:17:6C7EE1B8621CC013:899817715:1055898235::m:::scESC:
 * fpr:::::::::ECAF7590EB3443B5C7CF3ACB6C7EE1B8621CC013:
 * uid:f::::::::Werner Koch <wk@g10code.com>:
 * uid:f::::::::Werner Koch <wk@gnupg.org>:
 * sub:f:1536:16:06AD222CADF6A6E1:919537416:1036177416:::::e:
 * fpr:::::::::CF8BCC4B18DE08FCD8A1615906AD222CADF6A6E1:
 * sub:r:1536:20:5CE086B5B5A18FF4:899817788:1025961788:::::esc:
 * fpr:::::::::AB059359A3B81F410FCFF97F5CE086B5B5A18FF4:
 *
 * Each row is colon delimeted, and has a certain 'schema'. The first item
 * in the row tells us the schema. Then the various columns are numbered,
 * (schema is zero).
 */

G_BEGIN_DECLS

#define GCR_RECORD_SCHEMA_ATTRIBUTE  (g_quark_from_static_string ("ATTRIBUTE"))
#define GCR_RECORD_SCHEMA_IMPORT_OK  (g_quark_from_static_string ("IMPORT_OK"))
#define GCR_RECORD_SCHEMA_FPR  (g_quark_from_static_string ("fpr"))
#define GCR_RECORD_SCHEMA_PUB  (g_quark_from_static_string ("pub"))
#define GCR_RECORD_SCHEMA_SUB  (g_quark_from_static_string ("sub"))
#define GCR_RECORD_SCHEMA_SEC  (g_quark_from_static_string ("sec"))
#define GCR_RECORD_SCHEMA_SSB  (g_quark_from_static_string ("ssb"))
#define GCR_RECORD_SCHEMA_UID  (g_quark_from_static_string ("uid"))
#define GCR_RECORD_SCHEMA_UAT  (g_quark_from_static_string ("uat"))
#define GCR_RECORD_SCHEMA_XA1  (g_quark_from_static_string ("xa1"))
#define GCR_RECORD_SCHEMA_SIG  (g_quark_from_static_string ("sig"))
#define GCR_RECORD_SCHEMA_RVK  (g_quark_from_static_string ("rvk"))

/* Common columns for schemas */
typedef enum {
	GCR_RECORD_SCHEMA = 0,
	GCR_RECORD_TRUST = 1,
} GcrRecordColumns;

/*
 * Columns for ATTRIBUTE status message. eg:
 * [GNUPG:] ATTRIBUTE FBAFC70D60AE13D560764062B547B5580EEB5A80 10604 1 1 1 1227936754 0 1
 */
typedef enum {
	GCR_RECORD_ATTRIBUTE_KEY_FINGERPRINT = 1,
	GCR_RECORD_ATTRIBUTE_LENGTH = 2,
	GCR_RECORD_ATTRIBUTE_TYPE = 3,
	GCR_RECORD_ATTRIBUTE_TIMESTAMP = 6,
	GCR_RECORD_ATTRIBUTE_EXPIRY = 7,
	GCR_RECORD_ATTRIBUTE_FLAGS = 8
} GcrRecordAttributeColumns;

/*
 * Columns for IMPORT_OK and IMPORT_PROBLEM status message. eg:
 * [GNUPG:] IMPORT_OK 1 6BD9050FD8FC941B43412DCC68B7AB8957548DCD
 * [GNUPG:] IMPORT_PROBLEM 1
 */
typedef enum {
	GCR_RECORD_IMPORT_REASON = 1,
	GCR_RECORD_IMPORT_FINGERPRINT
} GcrRecordImportColumns;

/*
 * Columns for fpr schema, add them as they're used. eg:
 * fpr:::::::::ECAF7590EB3443B5C7CF3ACB6C7EE1B8621CC013:
 */
typedef enum {
	GCR_RECORD_FPR_FINGERPRINT = 9,
	GCR_RECORD_FPR_MAX = 10
} GcrRecordFprColumns;

/*
 * Columns for pub, sec, sub, and ssb schemas. eg:
 * pub:f:1024:17:6C7EE1B8621CC013:899817715:1055898235::m:::scESC:
 */
typedef enum {
	GCR_RECORD_KEY_BITS = 2,
	GCR_RECORD_KEY_ALGO = 3,
	GCR_RECORD_KEY_KEYID = 4,
	GCR_RECORD_KEY_TIMESTAMP = 5,
	GCR_RECORD_KEY_EXPIRY = 6,
	GCR_RECORD_KEY_OWNERTRUST = 8,
} GcrRecordKeyColumns;

typedef enum {
	GCR_RECORD_PUB_CAPS = 11,
	GCR_RECORD_PUB_MAX = 12
} GcrRecordPubColumns;

typedef enum {
	GCR_RECORD_SEC_MAX = 15
} GcrRecordSecColumns;

/*
 * Columns for uid schema, add them as they're used. eg:
 * uid:u::::1024442705::7A5C6648DAA1F5D12BD80BBED538439ABAFEE203::Test <test@example.com>:
 */
typedef enum {
	GCR_RECORD_UID_TIMESTAMP = 5,
	GCR_RECORD_UID_EXPIRY = 6,
	GCR_RECORD_UID_FINGERPRINT = 7,
	GCR_RECORD_UID_USERID = 9,
	GCR_RECORD_UID_MAX = 10,
} GcrRecordUidColumns;

/*
 * Columns for sig schema. eg:
 * sig:::17:FAD3A86D2505A4D5:1291829838::::Stef Walter <stefw@servingtfi.com>:10x:
 */
typedef enum {
	GCR_RECORD_SIG_STATUS = 1,
	GCR_RECORD_SIG_ALGO = 3,
	GCR_RECORD_SIG_KEYID = 4,
	GCR_RECORD_SIG_TIMESTAMP = 5,
	GCR_RECORD_SIG_EXPIRY = 6,
	GCR_RECORD_SIG_USERID = 9,
	GCR_RECORD_SIG_CLASS = 10,
	GCR_RECORD_SIG_MAX = 11,
} GcrRecordSigColumns;

/*
 * Columns for rvk schema. eg:
 * rvk:::17::::::3FC732041D23E9EA66DDB5009C9DBC21DF74DC61:80:
 */
typedef enum {
	GCR_RECORD_RVK_ALGO = 3,
	GCR_RECORD_RVK_FINGERPRINT = 9,
	GCR_RECORD_RVK_CLASS = 10,
	GCR_RECORD_RVK_MAX = 11,
} GcrRecordRvkColumns;

/*
 * Columns for uat schema, add them as they're used. eg:
 * uat:u::::1024442705::7A5C6648DAA1F5D12BD80BBED538439ABAFEE203::1 3233:
 */
typedef enum {
	GCR_RECORD_UAT_TRUST = 1,
	GCR_RECORD_UAT_FINGERPRINT = 7,
	GCR_RECORD_UAT_COUNT_SIZE = 9,
	GCR_RECORD_UAT_MAX = 10,
} GcrRecordUatColumns;

/*
 * Columns for xa1 schema. This is a schema that we've invented ourselves
 * for representing the actual data of openpgp attribute packets. eg:
 * xa1:e:10838:1:::1998-02-02:0:ECAF7590EB3443B5C7CF3ACB6C7EE1B8621CC013::...
 */
typedef enum {
	GCR_RECORD_XA1_TRUST = 1,
	GCR_RECORD_XA1_LENGTH = 2,
	GCR_RECORD_XA1_TYPE = 3,
	GCR_RECORD_XA1_TIMESTAMP = 5,
	GCR_RECORD_XA1_EXPIRY = 6,
	GCR_RECORD_XA1_FINGERPRINT = 7,
	GCR_RECORD_XA1_DATA = 9,
	GCR_RECORD_XA1_MAX = 11,
} GcrRecordXa1Columns;

typedef struct _GcrRecord GcrRecord;

#define        GCR_TYPE_RECORD                  (_gcr_record_get_type ())

GType          _gcr_record_get_type             (void) G_GNUC_CONST;

GcrRecord *    _gcr_record_new                  (GQuark schema,
                                                 guint n_columns,
                                                 gchar delimiter);

GcrRecord*     _gcr_record_copy                 (GcrRecord *record);

GcrRecord*     _gcr_record_parse_colons         (const gchar *line,
                                                 gssize n_line);

GcrRecord*     _gcr_record_parse_spaces         (const gchar *line,
                                                 gssize n_line);

gchar *        _gcr_record_format               (GcrRecord *record);

void           _gcr_record_free                 (gpointer record);

guint          _gcr_record_get_count            (GcrRecord *record);

gchar          _gcr_record_get_char             (GcrRecord *record,
                                                 guint column);

void           _gcr_record_set_char             (GcrRecord *record,
                                                 guint column,
                                                 gchar value);

gchar*         _gcr_record_get_string           (GcrRecord *record,
                                                 guint column);

void           _gcr_record_set_string           (GcrRecord *record,
                                                 guint column,
                                                 const gchar *value);

gboolean       _gcr_record_get_uint             (GcrRecord *record,
                                                 guint column,
                                                 guint *value);

void           _gcr_record_set_uint             (GcrRecord *record,
                                                 guint column,
                                                 guint value);

gboolean       _gcr_record_get_ulong            (GcrRecord *record,
                                                 guint column,
                                                 gulong *value);

void           _gcr_record_set_ulong            (GcrRecord *record,
                                                 guint column,
                                                 gulong value);

GDateTime *    _gcr_record_get_date             (GcrRecord *record,
                                                 guint column);

gpointer       _gcr_record_get_base64           (GcrRecord *record,
                                                 guint column,
                                                 gsize *n_data);

void           _gcr_record_set_base64           (GcrRecord *record,
                                                 guint column,
                                                 gconstpointer data,
                                                 gsize n_data);

const gchar*   _gcr_record_get_raw              (GcrRecord *record,
                                                 guint column);

void           _gcr_record_set_raw              (GcrRecord *record,
                                                 guint column,
                                                 const gchar *value);

void           _gcr_record_take_raw             (GcrRecord *record,
                                                 guint column,
                                                 gchar *value);

GQuark         _gcr_record_get_schema           (GcrRecord *record);

GPtrArray *    _gcr_records_parse_colons        (gconstpointer data,
                                                 gssize n_data);

gchar *        _gcr_records_format              (GPtrArray *records);

GcrRecord *    _gcr_records_find                (GPtrArray *records,
                                                 GQuark schema);

G_END_DECLS

#endif /* GCR_RECORD_H */
