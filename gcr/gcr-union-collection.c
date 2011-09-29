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

#include "config.h"

#include "gcr-collection.h"
#include "gcr-internal.h"
#include "gcr-union-collection.h"

#include <string.h>

/**
 * SECTION:gcr-union-collection
 * @title: GcrUnionCollection
 * @short_description: A GcrCollection which combines other collections
 *
 * An implementation of #GcrCollection, which combines the objects in
 * other #GcrCollections. Use gcr_union_collection_add() to add and
 * gcr_union_collection_remove() to remove them.
 */

/**
 * GcrUnionCollection:
 *
 * A union implementation of #GcrCollection.
 */

/**
 * GcrUnionCollectionClass:
 * @parent_class: The parent class
 *
 * The class for #GcrUnionCollection.
 */

struct _GcrUnionCollectionPrivate {
	GHashTable *items;
	GHashTable *collections;
};

static void      gcr_collection_iface       (GcrCollectionIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrUnionCollection, gcr_union_collection, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GCR_TYPE_COLLECTION, gcr_collection_iface));

static void
on_collection_added (GcrCollection *collection,
                     GObject *object,
                     gpointer user_data)
{
	GcrUnionCollection *self = GCR_UNION_COLLECTION (user_data);
	gint *count;

	g_object_ref (object);

	count = g_hash_table_lookup (self->pv->items, object);
	if (count == NULL) {
		count = g_new0 (gint, 1);
		*count = 1;
		g_hash_table_insert (self->pv->items, object, count);
		gcr_collection_emit_added (GCR_COLLECTION (self), object);
	} else {
		g_assert (*count > 0);
		(*count)++;
	}

	g_object_unref (object);
}

static void
on_collection_removed (GcrCollection *collection,
                       GObject *object,
                       gpointer user_data)
{
	GcrUnionCollection *self = GCR_UNION_COLLECTION (user_data);
	gint *count;

	g_object_ref (object);

	count = g_hash_table_lookup (self->pv->items, object);
	if (count != NULL) {
		g_assert (*count > 0);
		(*count)--;

		if (*count == 0) {
			g_hash_table_remove (self->pv->items, object);
			gcr_collection_emit_removed (GCR_COLLECTION (self), object);
		}
	} else {
		g_warning ("Object of type %s that exists in an underlying "
		           "collection of a GcrUnionCollection appeared without "
		           "emitting 'added' signal.", G_OBJECT_TYPE_NAME (object));
	}

	g_object_unref (object);

}

static void
connect_to_collection (GcrUnionCollection *self,
                       GcrCollection *collection)
{
	g_signal_connect (collection, "added", G_CALLBACK (on_collection_added), self);
	g_signal_connect (collection, "removed", G_CALLBACK (on_collection_removed), self);
}

static void
disconnect_from_collection (GcrUnionCollection *self,
                            GcrCollection *collection)
{
	g_signal_handlers_disconnect_by_func (collection, on_collection_added, self);
	g_signal_handlers_disconnect_by_func (collection, on_collection_removed, self);
}

static void
gcr_union_collection_init (GcrUnionCollection *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_UNION_COLLECTION, GcrUnionCollectionPrivate);
	self->pv->items = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                         NULL, g_free);
	self->pv->collections = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                               g_object_unref, NULL);
}

static void
gcr_union_collection_dispose (GObject *obj)
{
	GcrUnionCollection *self = GCR_UNION_COLLECTION (obj);
	GHashTableIter iter;
	GcrCollection *collection;

	g_hash_table_iter_init (&iter, self->pv->collections);
	while (g_hash_table_iter_next (&iter, (gpointer *)&collection, NULL))
		disconnect_from_collection (self, collection);
	g_hash_table_remove_all (self->pv->collections);
	g_hash_table_remove_all (self->pv->items);

	G_OBJECT_CLASS (gcr_union_collection_parent_class)->dispose (obj);
}

static void
gcr_union_collection_finalize (GObject *obj)
{
	GcrUnionCollection *self = GCR_UNION_COLLECTION (obj);

	g_assert (g_hash_table_size (self->pv->items) == 0);
	g_hash_table_destroy (self->pv->items);

	g_assert (g_hash_table_size (self->pv->collections) == 0);
	g_hash_table_destroy (self->pv->collections);

	G_OBJECT_CLASS (gcr_union_collection_parent_class)->finalize (obj);
}

static void
gcr_union_collection_class_init (GcrUnionCollectionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->dispose = gcr_union_collection_dispose;
	gobject_class->finalize = gcr_union_collection_finalize;
	g_type_class_add_private (gobject_class, sizeof (GcrUnionCollectionPrivate));
}

static guint
gcr_union_collection_real_get_length (GcrCollection *coll)
{
	GcrUnionCollection *self = GCR_UNION_COLLECTION (coll);
	return g_hash_table_size (self->pv->items);
}

static GList*
gcr_union_collection_real_get_objects (GcrCollection *coll)
{
	GcrUnionCollection *self = GCR_UNION_COLLECTION (coll);
	return g_hash_table_get_keys (self->pv->items);
}

static gboolean
gcr_union_collection_real_contains (GcrCollection *collection,
                                    GObject *object)
{
	GcrUnionCollection *self = GCR_UNION_COLLECTION (collection);
	return g_hash_table_lookup (self->pv->items, object) ? TRUE : FALSE;
}

static void
gcr_collection_iface (GcrCollectionIface *iface)
{
	iface->get_length = gcr_union_collection_real_get_length;
	iface->get_objects = gcr_union_collection_real_get_objects;
	iface->contains = gcr_union_collection_real_contains;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

/**
 * gcr_union_collection_new:
 *
 * Create a new #GcrUnionCollection.
 *
 * Returns: (transfer full) (type Gcr.UnionCollection): a newly allocated
 *          collection, which should be freed with g_object_unref()
 */
GcrCollection *
gcr_union_collection_new (void)
{
	return g_object_new (GCR_TYPE_UNION_COLLECTION, NULL);
}

/**
 * gcr_union_collection_add:
 * @self: The union collection
 * @collection: The collection whose objects to add
 *
 * Add objects from this collection to the union
 */
void
gcr_union_collection_add (GcrUnionCollection *self,
                          GcrCollection *collection)
{
	g_return_if_fail (GCR_IS_UNION_COLLECTION (self));
	g_return_if_fail (GCR_IS_COLLECTION (collection));
	gcr_union_collection_take (self, g_object_ref (collection));
}

/**
 * gcr_union_collection_take:
 * @self: The union collection
 * @collection: The collection whose objects to add
 *
 * Add objects from this collection to the union. Do not add an additional
 * reference to the collection.
 */
void
gcr_union_collection_take (GcrUnionCollection *self,
                           GcrCollection *collection)
{
	GList *objects, *l;

	g_return_if_fail (GCR_IS_UNION_COLLECTION (self));
	g_return_if_fail (GCR_IS_COLLECTION (collection));
	g_return_if_fail (!g_hash_table_lookup (self->pv->collections, collection));

	g_object_ref (collection);

	g_hash_table_insert (self->pv->collections, collection, collection);
	connect_to_collection (self, collection);

	objects = gcr_collection_get_objects (collection);
	for (l = objects; l != NULL; l = g_list_next (l))
		on_collection_added (collection, l->data, self);
	g_list_free (objects);

	g_object_unref (collection);
}

/**
 * gcr_union_collection_remove:
 * @self: The collection
 * @collection: The collection whose objects to remove
 *
 * Remove an object from the collection.
 */
void
gcr_union_collection_remove (GcrUnionCollection *self,
                             GcrCollection *collection)
{
	GList *objects, *l;

	g_return_if_fail (GCR_IS_UNION_COLLECTION (self));
	g_return_if_fail (GCR_IS_COLLECTION (collection));
	g_return_if_fail (g_hash_table_lookup (self->pv->collections, collection));

	g_object_ref (collection);

	g_hash_table_remove (self->pv->collections, collection);
	disconnect_from_collection (self, collection);

	objects = gcr_collection_get_objects (collection);
	for (l = objects; l != NULL; l = g_list_next (l))
		on_collection_removed (collection, l->data, self);
	g_list_free (objects);

	g_object_unref (collection);
}

/**
 * gcr_union_collection_have:
 * @self: the union collection
 * @collection: the collection to check
 *
 * Check whether the collection is present in the union.
 *
 * Returns: whether present or not
 */
gboolean
gcr_union_collection_have (GcrUnionCollection *self,
                           GcrCollection *collection)
{
	g_return_val_if_fail (GCR_IS_UNION_COLLECTION (self), FALSE);
	g_return_val_if_fail (GCR_IS_COLLECTION (collection), FALSE);
	return g_hash_table_lookup (self->pv->collections, collection) != NULL;
}

/**
 * gcr_union_collection_size:
 * @self: the union collection
 *
 * Return the number of collections in this union. This does not reflect
 * the number of objects in the combined collection.
 *
 * Returns: number of collections inlcuded
 */
guint
gcr_union_collection_size (GcrUnionCollection *self)
{
	g_return_val_if_fail (GCR_IS_UNION_COLLECTION (self), FALSE);
	return g_hash_table_size (self->pv->collections);
}
