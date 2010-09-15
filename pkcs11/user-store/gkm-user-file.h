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

#ifndef __GKM_USER_FILE_H__
#define __GKM_USER_FILE_H__

#include <glib-object.h>

#include "gkm/gkm-data-types.h"
#include "gkm/gkm-secret.h"

enum {
	GKM_USER_FILE_SECTION_PUBLIC  = 0x01,
	GKM_USER_FILE_SECTION_PRIVATE = 0x02,
};

#define GKM_TYPE_USER_FILE               (gkm_user_file_get_type ())
#define GKM_USER_FILE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKM_TYPE_USER_FILE, GkmUserFile))
#define GKM_USER_FILE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKM_TYPE_USER_FILE, GkmUserFileClass))
#define GKM_IS_USER_FILE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKM_TYPE_USER_FILE))
#define GKM_IS_USER_FILE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKM_TYPE_USER_FILE))
#define GKM_USER_FILE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKM_TYPE_USER_FILE, GkmUserFileClass))

typedef struct _GkmUserFile GkmUserFile;
typedef struct _GkmUserFileClass GkmUserFileClass;

struct _GkmUserFileClass {
	GObjectClass parent_class;

	/* signals */

	void (*entry_added) (GkmUserFile *store, const gchar *identifier);

	void (*entry_changed) (GkmUserFile *store, const gchar *identifier, CK_ATTRIBUTE_TYPE type);

	void (*entry_removed) (GkmUserFile *store, const gchar *identifier);
};

typedef void (*GkmUserFileFunc) (GkmUserFile *file, const gchar *identifier, gpointer user_data);

GType                     gkm_user_file_get_type               (void);

GkmUserFile*              gkm_user_file_new                    (void);

GkmDataResult             gkm_user_file_read_fd                (GkmUserFile *self,
                                                                int fd,
                                                                GkmSecret *login);

GkmDataResult             gkm_user_file_write_fd               (GkmUserFile *self,
                                                                int fd,
                                                                GkmSecret *login);

gboolean                  gkm_user_file_have_section           (GkmUserFile *self,
                                                                guint section);

gboolean                  gkm_user_file_lookup_entry           (GkmUserFile *self,
                                                                const gchar *identifier,
                                                                guint *section);

void                      gkm_user_file_foreach_entry          (GkmUserFile *self,
                                                                GkmUserFileFunc func,
                                                                gpointer user_data);

GkmDataResult             gkm_user_file_unique_entry           (GkmUserFile *self,
                                                                gchar **identifier);

GkmDataResult             gkm_user_file_create_entry           (GkmUserFile *self,
                                                                const gchar *identifier,
                                                                guint section);

GkmDataResult             gkm_user_file_destroy_entry          (GkmUserFile *self,
                                                                const gchar *identifier);

GkmDataResult             gkm_user_file_write_value            (GkmUserFile *self,
                                                                const gchar *identifier,
                                                                gulong type,
                                                                gconstpointer value,
                                                                gsize n_value);

GkmDataResult             gkm_user_file_read_value             (GkmUserFile *self,
                                                                const gchar *identifier,
                                                                gulong type,
                                                                gconstpointer *value,
                                                                gsize *n_value);

void                      gkm_user_file_foreach_value          (GkmUserFile *self,
                                                                const gchar *identifier);

void                      gkm_user_file_dump                   (GkmUserFile *self);

#endif /* __GKM_USER_FILE_H__ */
