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

#ifndef __GCR_IMPORTER_H__
#define __GCR_IMPORTER_H__

#include "gcr-parser.h"

#include <glib-object.h>

G_BEGIN_DECLS

#define GCR_TYPE_IMPORTER                 (gcr_importer_get_type ())
#define GCR_IMPORTER(obj)                 (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_IMPORTER, GcrImporter))
#define GCR_IS_IMPORTER(obj)              (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_IMPORTER))
#define GCR_IMPORTER_GET_INTERFACE(inst)  (G_TYPE_INSTANCE_GET_INTERFACE ((inst), GCR_TYPE_IMPORTER, GcrImporterIface))

typedef struct _GcrImporter GcrImporter;
typedef struct _GcrImporterIface GcrImporterIface;

struct _GcrImporterIface {
	GTypeInterface parent;

	GList *     (*create_for_parsed)      (GcrParsed *parsed);

	gboolean    (*queue_for_parsed)       (GcrImporter *importer,
	                                       GcrParsed *parsed);

	gboolean    (*import_sync)            (GcrImporter *importer,
	                                       GCancellable *cancellable,
	                                       GError **error);

	void        (*import_async)           (GcrImporter *importer,
	                                       GCancellable *cancellable,
	                                       GAsyncReadyCallback callback,
	                                       gpointer user_data);

	gboolean    (*import_finish)          (GcrImporter *importer,
	                                       GAsyncResult *result,
	                                       GError **error);

	/*< private >*/
	gpointer reserved[14];
};

GType            gcr_importer_get_type                     (void);

GList *          gcr_importer_create_for_parsed            (GcrParsed *parsed);

gboolean         gcr_importer_queue_for_parsed             (GcrImporter *importer,
                                                            GcrParsed *parsed);

GList *          gcr_importer_queue_and_filter_for_parsed  (GList *importers,
                                                            GcrParsed *parsed);

gboolean         gcr_importer_import                       (GcrImporter *importer,
                                                            GCancellable *cancellable,
                                                            GError **error);

void             gcr_importer_import_async                 (GcrImporter *importer,
                                                            GCancellable *cancellable,
                                                            GAsyncReadyCallback callback,
                                                            gpointer user_data);

gboolean         gcr_importer_import_finish                (GcrImporter *importer,
                                                            GAsyncResult *result,
                                                            GError **error);

void             gcr_importer_register                     (GType importer_type,
                                                            GckAttributes *attrs);

void             gcr_importer_register_well_known          (void);

G_END_DECLS

#endif /* __GCR_IMPORTER_H__ */
