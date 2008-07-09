/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-import.h - Importing of PK Objects

   Copyright (C) 2007 Stefan Walter

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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef __GKR_PK_IMPORT_H__
#define __GKR_PK_IMPORT_H__

#include "pk/gkr-pk-object.h"

#include <libtasn1.h>

G_BEGIN_DECLS

#define GKR_TYPE_PK_IMPORT             (gkr_pk_import_get_type())
#define GKR_PK_IMPORT(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GKR_TYPE_PK_IMPORT, GkrPkImport))
#define GKR_PK_IMPORT_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GKR_TYPE_PK_IMPORT, GkrPkImport))
#define GKR_IS_PK_IMPORT(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GKR_TYPE_PK_IMPORT))
#define GKR_IS_PK_IMPORT_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GKR_TYPE_PK_IMPORT))
#define GKR_PK_IMPORT_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), GKR_TYPE_PK_IMPORT, GkrPkImportClass))

typedef struct _GkrPkImport      GkrPkImport;
typedef struct _GkrPkImportClass GkrPkImportClass;

struct _GkrPkImport {
	GkrPkObject parent;
	
	GSList *import_objects;
	gboolean import_token;
	GkrPkStorage *import_storage;
	GkrPkManager *import_manager;
	gchar *import_label;
};

struct _GkrPkImportClass {
	GkrPkObjectClass parent_class;
};

GType               gkr_pk_import_get_type           (void) G_GNUC_CONST;

CK_RV               gkr_pk_import_create             (GkrPkManager *manager,
                                                      GkrPkSession *session,
                                                      GArray *attrs, 
                                                      GkrPkObject **object);

GSList*             gkr_pk_import_get_objects        (GkrPkImport *import);

gboolean            gkr_pk_import_perform            (GkrPkImport *import, 
                                                      const guchar *data, 
                                                      gsize n_data,
                                                      GError **err);

G_END_DECLS

#endif /* __GKR_PK_IMPORT_H__ */
