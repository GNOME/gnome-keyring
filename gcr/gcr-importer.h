/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
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

#ifndef __GCR_IMPORTER_H__
#define __GCR_IMPORTER_H__

#include <glib-object.h>

#define GCR_TYPE_IMPORTER               (gcr_importer_get_type ())
#define GCR_IMPORTER(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_IMPORTER, GcrImporter))
#define GCR_IMPORTER_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_IMPORTER, GcrImporterClass))
#define GCR_IS_IMPORTER(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_IMPORTER))
#define GCR_IS_IMPORTER_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_IMPORTER))
#define GCR_IMPORTER_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_IMPORTER, GcrImporterClass))

typedef struct _GcrImporter GcrImporter;
typedef struct _GcrImporterClass GcrImporterClass;

struct _GcrImporter {
	GObject parent;
};

struct _GcrImporterClass {
	GObjectClass parent_class;
    
	/* signals --------------------------------------------------------- */
    
	void (*signal) (GcrImporter *self, GkrImportedItem *item);
};

GType               gcr_importer_get_type               (void);

GcrImporter*        gcr_importer_new                    (void);

GcrImporter*        gcr_importer_new_for_module         (GP11Module *module);

GcrImporter*        gcr_importer_new_for_module_funcs   (gpointer pkcs11_funcs);

void                gcr_importer_set_slot               (GcrImporter *self,
                                                         GP11Slot *slot);

void                gcr_importer_set_slot_id            (GcrImporter *self,
                                                         gulong slot_id);

void                gcr_importer_set_parser             (GcrImporter *self,
                                                         GcrParser *parser);

void                gcr_importer_set_window             (GcrImporter *self,
                                                         GtkWindow *window);

void                gcr_importer_set_prompt_behavior    (GcrImporter *self,
                                                         GcrImporterPromptBehavior behavior);

gboolean            gcr_importer_import_data            (GcrImporter *self,
                                                         const guchar *data,
                                                         gsize n_data,
                                                         GError *error);

gboolean            gcr_importer_import_file            (GcrImporter *self,
                                                         const gchar *filename,
                                                         GError *error);

#endif /* __GCR_IMPORTER_H__ */
