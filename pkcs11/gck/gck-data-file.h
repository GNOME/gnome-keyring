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

#ifndef __GCK_DATA_FILE_H__
#define __GCK_DATA_FILE_H__

#include <glib-object.h>

#include "gck-data-types.h"
#include "gck-login.h"

enum {
	GCK_DATA_FILE_SECTION_PUBLIC  = 0x01,
	GCK_DATA_FILE_SECTION_PRIVATE = 0x02,
};

#define GCK_TYPE_DATA_FILE               (gck_data_file_get_type ())
#define GCK_DATA_FILE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_DATA_FILE, GckDataFile))
#define GCK_DATA_FILE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_DATA_FILE, GckDataFileClass))
#define GCK_IS_DATA_FILE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_DATA_FILE))
#define GCK_IS_DATA_FILE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_DATA_FILE))
#define GCK_DATA_FILE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_DATA_FILE, GckDataFileClass))

typedef struct _GckDataFile GckDataFile;
typedef struct _GckDataFileClass GckDataFileClass;
    
struct _GckDataFileClass {
	GObjectClass parent_class;
	
	/* signals */
	
	void (*entry_added) (GckDataFile *store, const gchar *identifier);
	
	void (*entry_changed) (GckDataFile *store, const gchar *identifier, CK_ATTRIBUTE_TYPE type);
	
	void (*entry_removed) (GckDataFile *store, const gchar *identifier);
};

typedef void (*GckDataFileFunc) (GckDataFile *file, const gchar *identifier, gpointer user_data);

GType                     gck_data_file_get_type               (void);

GckDataFile*              gck_data_file_new                    (void);

GckDataResult             gck_data_file_read_fd                (GckDataFile *self,
                                                                int fd, 
                                                                GckLogin *login);

GckDataResult             gck_data_file_write_fd               (GckDataFile *self,
                                                                int fd, 
                                                                GckLogin *login);

gboolean                  gck_data_file_have_section           (GckDataFile *self,
                                                                guint section);

gboolean                  gck_data_file_lookup_entry           (GckDataFile *self,
                                                                const gchar *identifier,
                                                                guint *section);

void                      gck_data_file_foreach_entry          (GckDataFile *self,
                                                                GckDataFileFunc func,
                                                                gpointer user_data);

GckDataResult             gck_data_file_unique_entry           (GckDataFile *self,
                                                                gchar **identifier);

GckDataResult             gck_data_file_create_entry           (GckDataFile *self, 
                                                                const gchar *identifier,
                                                                guint section);

GckDataResult             gck_data_file_destroy_entry          (GckDataFile *self, 
                                                                const gchar *identifier);

GckDataResult             gck_data_file_write_value            (GckDataFile *self,
                                                                const gchar *identifier,
                                                                gulong type,
                                                                gconstpointer value,
                                                                gsize n_value);

GckDataResult             gck_data_file_read_value             (GckDataFile *self,
                                                                const gchar *identifier,
                                                                gulong type,
                                                                gconstpointer *value,
                                                                gsize *n_value);

void                      gck_data_file_foreach_value          (GckDataFile *self,
                                                                const gchar *identifier);
     
void                      gck_data_file_dump                   (GckDataFile *self);

#endif /* __GCK_DATA_FILE_H__ */
