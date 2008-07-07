/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-storage.h - Base class for storage of PK objects

   Copyright (C) 2008 Stefan Walter

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

#ifndef __GKR_PK_STORAGE_H__
#define __GKR_PK_STORAGE_H__

#include <gcrypt.h>
#include <glib-object.h>

#include "gkr-pk-index.h"
#include "gkr-pk-object.h"

G_BEGIN_DECLS

#define GKR_TYPE_PK_STORAGE             (gkr_pk_storage_get_type ())
#define GKR_PK_STORAGE(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_PK_STORAGE, GkrPkStorage))
#define GKR_PK_STORAGE_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_PK_STORAGE, GkrPkStorageClass))
#define GKR_IS_PK_STORAGE(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_PK_STORAGE))
#define GKR_IS_PK_STORAGE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_PK_STORAGE))
#define GKR_PK_STORAGE_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_PK_STORAGE, GkrPkStorageClass))

typedef struct _GkrPkStorageClass GkrPkStorageClass;

struct _GkrPkStorage {
	 GObject parent;
};

struct _GkrPkStorageClass {
	GObjectClass parent_class;

	/* virtual methods */
	void (*refresh) (GkrPkStorage *storage);
	gboolean (*load) (GkrPkStorage *storage, GkrPkObject *object, GError **err);
	gboolean (*store) (GkrPkStorage *storage, GkrPkObject *object, GError **err);
	gboolean (*remove) (GkrPkStorage *storage, GkrPkObject *object, GError **err);
	GkrPkIndex* (*index) (GkrPkStorage *storage, GQuark location);
};

GType                   gkr_pk_storage_get_type           (void) G_GNUC_CONST;

void                    gkr_pk_storage_register           (GkrPkStorage *storage, 
                                                           gboolean default_storage);

void                    gkr_pk_storage_refresh_all        (void);

void                    gkr_pk_storage_refresh            (GkrPkStorage *storage);

gboolean                gkr_pk_storage_load               (GkrPkStorage *storage, 
                                                           GkrPkObject *obj, GError **err);

gboolean                gkr_pk_storage_store              (GkrPkStorage *storage,
                                                           GkrPkObject *obj, GError **err);

gboolean                gkr_pk_storage_remove             (GkrPkStorage *storage,
                                                           GkrPkObject *obj, GError **err);

GkrPkIndex*             gkr_pk_storage_index              (GkrPkStorage *storage, 
                                                           GQuark location);

/* For use by derived classes */

GkrPkIndex*             gkr_pk_storage_create_index       (GkrPkStorage *storage,
                                                           GQuark index_location);

void                    gkr_pk_storage_set_object         (GkrPkStorage *storage, 
                                                           GkrPkObject *obj);

void                    gkr_pk_storage_add_object         (GkrPkStorage *storage, 
                                                           GkrPkObject *obj);

void                    gkr_pk_storage_del_object         (GkrPkStorage *storage, 
                                                           GkrPkObject *obj);

void                    gkr_pk_storage_clr_objects        (GkrPkStorage *storage, 
                                                           GQuark location);

typedef GHashTable GkrPkChecks;

GkrPkChecks*            gkr_pk_storage_checks_prepare     (GkrPkStorage *storage, 
                                                           GQuark location);

void                    gkr_pk_storage_checks_mark        (GkrPkChecks *checks,
                                                           GkrPkObject *object);

void                    gkr_pk_storage_checks_purge       (GkrPkStorage *storage, 
                                                           GkrPkChecks *checks);

#define GKR_PK_STORAGE_PASSWD_STATE  	 0
#define GKR_PK_STORAGE_PASSWD_PROMPT	 2

gboolean                gkr_pk_storage_get_store_password (GkrPkStorage *storage, 
                                                           GQuark location, GQuark type, 
                                                           const gchar *label, gboolean *save, 
                                                           gchar **passowrd);
	
gboolean                gkr_pk_storage_get_load_password  (GkrPkStorage *storage, 
                                                           GQuark location, gkrconstid digest, 
                                                           GQuark type, const gchar *label, 
                                                           gint *state, gchar **password);

G_END_DECLS

#endif /* __GKR_PK_STORAGE_H__ */
