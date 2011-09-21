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

#ifndef __GCR_GNUPG_IMPORTER_H__
#define __GCR_GNUPG_IMPORTER_H__

#include "gcr-importer.h"

#include <glib-object.h>

G_BEGIN_DECLS

#define GCR_TYPE_GNUPG_IMPORTER               (_gcr_gnupg_importer_get_type ())
#define GCR_GNUPG_IMPORTER(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_GNUPG_IMPORTER, GcrGnupgImporter))
#define GCR_GNUPG_IMPORTER_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_GNUPG_IMPORTER, GcrGnupgImporterClass))
#define GCR_IS_GNUPG_IMPORTER(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_GNUPG_IMPORTER))
#define GCR_IS_GNUPG_IMPORTER_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_GNUPG_IMPORTER))
#define GCR_GNUPG_IMPORTER_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_GNUPG_IMPORTER, GcrGnupgImporterClass))

typedef struct _GcrGnupgImporter GcrGnupgImporter;
typedef struct _GcrGnupgImporterClass GcrGnupgImporterClass;
typedef struct _GcrGnupgImporterPrivate GcrGnupgImporterPrivate;

struct _GcrGnupgImporter {
	GObject parent;

	/*< private >*/
	GcrGnupgImporterPrivate *pv;
};

struct _GcrGnupgImporterClass {
	GObjectClass parent_class;
};

GType                   _gcr_gnupg_importer_get_type         (void) G_GNUC_CONST;

GcrImporter *           _gcr_gnupg_importer_new              (const gchar *directory);

const gchar **          _gcr_gnupg_importer_get_imported     (GcrGnupgImporter *self);

G_END_DECLS

#endif /* __GCR_IMPORTER_H__ */
