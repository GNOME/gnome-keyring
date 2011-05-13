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

#if !defined (__GCR_H_INSIDE__) && !defined (GCR_COMPILATION)
#error "Only <gcr/gcr.h> can be included directly."
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

#define GCR_RECORD_SCHEMA_UID  (g_quark_from_static_string ("uid"))
#define GCR_RECORD_SCHEMA_PUB  (g_quark_from_static_string ("pub"))
#define GCR_RECORD_SCHEMA_SEC  (g_quark_from_static_string ("sec"))

/* Common columns for all schemas */
typedef enum {
	GCR_RECORD_SCHEMA = 0
} GcrRecordColumns;

/*
 * Columns for pub schema, add them as they're used. eg:
 * pub:f:1024:17:6C7EE1B8621CC013:899817715:1055898235::m:::scESC:
 */
typedef enum {
	GCR_RECORD_PUB_KEYID = 4
} GcrRecordPubColumns;

/*
 * Columns for sec schema, add them as they're used. eg:
 * sec::2048:1:293FC71A513189BD:1299771018::::::::::
 */
typedef enum {
	GCR_RECORD_SEC_KEYID = 4
} GcrRecordSecColumns;

/*
 * Columns for uid schema, add them as they're used. eg:
 * pub:f:1024:17:6C7EE1B8621CC013:899817715:1055898235::m:::scESC:
 */
typedef enum {
	GCR_RECORD_UID_NAME = 9
} GcrRecordUidColumns;

typedef struct _GcrRecord GcrRecord;

#define        GCR_TYPE_RECORD                  (_gcr_record_get_boxed_type ())

GType          _gcr_record_get_boxed_type       (void) G_GNUC_CONST;

GcrRecord*     _gcr_record_copy                 (GcrRecord *record);

GcrRecord*     _gcr_record_parse_colons         (const gchar *line,
                                                 gssize n_line);

GcrRecord*     _gcr_record_take_colons          (gchar *line);

GcrRecord*     _gcr_record_parse_spaces         (const gchar *line,
                                                 gssize n_line);

void           _gcr_record_free                 (gpointer record);

GcrRecord*     _gcr_record_find                 (GPtrArray *records,
                                                 GQuark schema);

guint          _gcr_record_get_count            (GcrRecord *record);

gchar*         _gcr_record_get_string           (GcrRecord *record,
                                                 guint column);

gboolean       _gcr_record_get_uint             (GcrRecord *record,
                                                 guint column,
                                                 guint *value);

const gchar*   _gcr_record_get_raw              (GcrRecord *record,
                                                 guint column);

GQuark         _gcr_record_get_schema           (GcrRecord *record);

G_END_DECLS

#endif /* GCR_RECORD_H */
