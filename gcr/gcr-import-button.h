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

#ifndef __GCR_IMPORT_BUTTON_H__
#define __GCR_IMPORT_BUTTON_H__

#include "gcr.h"

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define GCR_TYPE_IMPORT_BUTTON               (gcr_import_button_get_type ())
#define GCR_IMPORT_BUTTON(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_IMPORT_BUTTON, GcrImportButton))
#define GCR_IMPORT_BUTTON_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_IMPORT_BUTTON, GcrImportButtonClass))
#define GCR_IS_IMPORT_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_IMPORT_BUTTON))
#define GCR_IS_IMPORT_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_IMPORT_BUTTON))
#define GCR_IMPORT_BUTTON_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_IMPORT_BUTTON, GcrImportButtonClass))

typedef struct _GcrImportButton GcrImportButton;
typedef struct _GcrImportButtonClass GcrImportButtonClass;
typedef struct _GcrImportButtonPrivate GcrImportButtonPrivate;

struct _GcrImportButton {
	GtkButton parent;

	/*< private >*/
	GcrImportButtonPrivate *pv;
};

struct _GcrImportButtonClass {
	GtkButtonClass parent_class;

	void    (*imported)    (GcrImportButton *self,
	                        GcrImporter *importer,
	                        GError *error);
};

GType               gcr_import_button_get_type               (void) G_GNUC_CONST;

GcrImportButton *   gcr_import_button_new                    (const gchar *label);

void                gcr_import_button_add_parsed             (GcrImportButton *button,
                                                              GcrParser *parser);

G_END_DECLS

#endif /* __GCR_IMPORT_BUTTON_H__ */
