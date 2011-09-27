/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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

#include "config.h"

#include "gcr-collection.h"
#include "gcr-single-collection.h"

#include <string.h>

/**
 * GcrSingleCollection:
 *
 * A single implementation of #GcrCollection.
 */

struct _GcrSingleCollection {
	GObject parent;
	GObject *object;
};

/**
 * GcrSingleCollectionClass:
 * @parent_class: The parent class
 *
 * The class for #GcrSingleCollection.
 */

struct _GcrSingleCollectionClass {
	GObjectClass parent_class;
};

static void _gcr_single_collection_iface (GcrCollectionIface *iface);
G_DEFINE_TYPE_WITH_CODE (GcrSingleCollection, _gcr_single_collection, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GCR_TYPE_COLLECTION, _gcr_single_collection_iface));

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
_gcr_single_collection_init (GcrSingleCollection *self)
{

}

static void
_gcr_single_collection_dispose (GObject *obj)
{
	GcrSingleCollection *self = GCR_SINGLE_COLLECTION (obj);

	_gcr_single_collection_set_object (self, NULL);

	G_OBJECT_CLASS (_gcr_single_collection_parent_class)->dispose (obj);
}

static void
_gcr_single_collection_class_init (GcrSingleCollectionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->dispose = _gcr_single_collection_dispose;
}

static guint
_gcr_single_collection_real_get_length (GcrCollection *coll)
{
	GcrSingleCollection *self = GCR_SINGLE_COLLECTION (coll);
	return self->object == NULL ? 0 : 1;
}

static GList*
_gcr_single_collection_real_get_objects (GcrCollection *coll)
{
	GcrSingleCollection *self = GCR_SINGLE_COLLECTION (coll);
	return self->object == NULL ? NULL : g_list_append (NULL, self->object);
}

static gboolean
_gcr_single_collection_real_contains (GcrCollection *collection,
                                      GObject *object)
{
	GcrSingleCollection *self = GCR_SINGLE_COLLECTION (collection);
	return self->object == object;
}

static void
_gcr_single_collection_iface (GcrCollectionIface *iface)
{
	iface->get_length = _gcr_single_collection_real_get_length;
	iface->get_objects = _gcr_single_collection_real_get_objects;
	iface->contains = _gcr_single_collection_real_contains;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GcrCollection *
_gcr_single_collection_new (GObject *object)
{
	GcrSingleCollection *self;

	self = g_object_new (GCR_TYPE_SINGLE_COLLECTION, NULL);
	_gcr_single_collection_set_object (self, object);

	return GCR_COLLECTION (self);
}

GObject *
_gcr_single_collection_get_object (GcrSingleCollection *self)
{
	g_return_val_if_fail (GCR_IS_SINGLE_COLLECTION (self), NULL);
	return self->object;
}

void
_gcr_single_collection_set_object (GcrSingleCollection *self,
                                   GObject *object)
{
	GObject *obj;

	g_return_if_fail (GCR_IS_SINGLE_COLLECTION (self));
	g_return_if_fail (object == NULL || G_IS_OBJECT (object));

	if (object == self->object)
		return;

	if (self->object) {
		obj = self->object;
		self->object = NULL;
		gcr_collection_emit_removed (GCR_COLLECTION (self), obj);
		g_object_unref (obj);
	}

	if (object) {
		self->object = g_object_ref (object);
		gcr_collection_emit_added (GCR_COLLECTION (self), self->object);
	}
}
