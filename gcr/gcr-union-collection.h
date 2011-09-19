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

#ifndef __GCR_UNION_COLLECTION_H__
#define __GCR_UNION_COLLECTION_H__

#include "gcr.h"
#include "gcr-collection.h"

#include <glib-object.h>

G_BEGIN_DECLS

#define GCR_TYPE_UNION_COLLECTION               (gcr_union_collection_get_type ())
#define GCR_UNION_COLLECTION(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_COLLECTION, GcrUnionCollection))
#define GCR_UNION_COLLECTION_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_COLLECTION, GcrUnionCollectionClass))
#define GCR_IS_UNION_COLLECTION(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_COLLECTION))
#define GCR_IS_UNION_COLLECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_COLLECTION))
#define GCR_UNION_COLLECTION_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_COLLECTION, GcrUnionCollectionClass))

typedef struct _GcrUnionCollection GcrUnionCollection;
typedef struct _GcrUnionCollectionClass GcrUnionCollectionClass;
typedef struct _GcrUnionCollectionPrivate GcrUnionCollectionPrivate;

struct _GcrUnionCollection {
	GObject parent;

	/*< private >*/
	GcrUnionCollectionPrivate *pv;
};

struct _GcrUnionCollectionClass {
	GObjectClass parent_class;
};

GType               gcr_union_collection_get_type                (void);

GcrCollection*      gcr_union_collection_new                     (void);

void                gcr_union_collection_add                     (GcrUnionCollection *self,
                                                                  GcrCollection *collection);

void                gcr_union_collection_take                    (GcrUnionCollection *self,
                                                                  GcrCollection *collection);

void                gcr_union_collection_remove                  (GcrUnionCollection *self,
                                                                  GcrCollection *collection);

gboolean            gcr_union_collection_have                    (GcrUnionCollection *self,
                                                                  GcrCollection *collection);

guint               gcr_union_collection_size                    (GcrUnionCollection *self);

G_END_DECLS

#endif /* __GCR_UNION_COLLECTION_H__ */
