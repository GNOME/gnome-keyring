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

#ifndef GCR_GNUPG_COLONS_H
#define GCR_GNUPG_COLONS_H

#include <glib.h>

G_BEGIN_DECLS

#define GCR_COLONS_SCHEMA_UID  _gcr_colons_get_schema_uid_quark ()
#define GCR_COLONS_SCHEMA_PUB  _gcr_colons_get_schema_pub_quark ()

typedef enum {
	GCR_COLONS_SCHEMA = 0
} GcrColonColumns;

typedef enum {
	GCR_COLONS_PUB_KEYID = 4
} GcrColonPubColumns;

typedef enum {
	GCR_COLONS_UID_NAME = 9
} GcrColonUidColumns;

typedef struct _GcrColons GcrColons;

GcrColons*     _gcr_colons_parse                (const gchar *line,
                                                 gssize n_line);

void           _gcr_colons_free                 (gpointer colons);

GcrColons*     _gcr_colons_find                 (GPtrArray *dataset,
                                                 GQuark schema);

gchar*         _gcr_colons_get_string           (GcrColons *colons,
                                                 guint column);

const gchar*   _gcr_colons_get_raw              (GcrColons *colons,
                                                 guint column);

GQuark         _gcr_colons_get_schema           (GcrColons *colons);

GQuark         _gcr_colons_get_schema_uid_quark (void) G_GNUC_CONST;

GQuark         _gcr_colons_get_schema_pub_quark (void) G_GNUC_CONST;

G_END_DECLS

#endif /* GCR_GNUPG_COLONS_H */
