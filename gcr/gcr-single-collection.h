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

#ifndef __GCR_SINGLE_COLLECTION_H__
#define __GCR_SINGLE_COLLECTION_H__

#include "gcr-base.h"
#include "gcr-collection.h"

#include <glib-object.h>

G_BEGIN_DECLS

#define GCR_TYPE_SINGLE_COLLECTION               (_gcr_single_collection_get_type ())
#define GCR_SINGLE_COLLECTION(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_COLLECTION, GcrSingleCollection))
#define GCR_SINGLE_COLLECTION_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_COLLECTION, GcrSingleCollectionClass))
#define GCR_IS_SINGLE_COLLECTION(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_COLLECTION))
#define GCR_IS_SINGLE_COLLECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_COLLECTION))
#define GCR_SINGLE_COLLECTION_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_COLLECTION, GcrSingleCollectionClass))

typedef struct _GcrSingleCollection GcrSingleCollection;
typedef struct _GcrSingleCollectionClass GcrSingleCollectionClass;

GType               _gcr_single_collection_get_type                (void);

GcrCollection *     _gcr_single_collection_new                     (GObject *object);

GObject *           _gcr_single_collection_get_object              (GcrSingleCollection *self);

void                _gcr_single_collection_set_object              (GcrSingleCollection *self,
                                                                   GObject *object);

G_END_DECLS

#endif /* __GCR_SINGLE_COLLECTION_H__ */
