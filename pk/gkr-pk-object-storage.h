/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-object-storage.h - Store general 'token' PK objects

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

#ifndef __GKR_PK_OBJECT_STORAGE_H__
#define __GKR_PK_OBJECT_STORAGE_H__

#include <gcrypt.h>
#include <glib-object.h>

#include "gkr-pk-storage.h"

G_BEGIN_DECLS

#define GKR_TYPE_PK_OBJECT_STORAGE             (gkr_pk_object_storage_get_type ())
#define GKR_PK_OBJECT_STORAGE(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_PK_OBJECT_STORAGE, GkrPkObjectStorage))
#define GKR_PK_OBJECT_STORAGE_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_PK_OBJECT_STORAGE, GkrPkObjectStorageClass))
#define GKR_IS_PK_OBJECT_STORAGE(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_PK_OBJECT_STORAGE))
#define GKR_IS_PK_OBJECT_STORAGE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_PK_OBJECT_STORAGE))
#define GKR_PK_OBJECT_STORAGE_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_PK_OBJECT_STORAGE, GkrPkObjectStorageClass))

typedef struct _GkrPkObjectStorage GkrPkObjectStorage;
typedef struct _GkrPkObjectStorageClass GkrPkObjectStorageClass;

struct _GkrPkObjectStorage {
	 GkrPkStorage parent;
};

struct _GkrPkObjectStorageClass {
	GkrPkStorageClass parent_class;
};

GType                   gkr_pk_object_storage_get_type           (void) G_GNUC_CONST;

gboolean                gkr_pk_object_storage_initialize         (void);

G_END_DECLS

#endif /* __GKR_PK_OBJECT_STORAGE_H__ */

