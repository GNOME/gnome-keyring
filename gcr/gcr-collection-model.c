/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "config.h"

#include "gcr-collection-model.h"

#include <string.h>

enum {
	PROP_0,
	PROP_COLLECTION
};

struct _GcrCollectionModelPrivate {
	GcrCollection *collection;
	GHashTable *object_to_index;

	gint cache_stamp;
	gint last_stamp;

	GPtrArray *objects;

	gchar **column_names;
	guint n_columns;
	GType *column_types;
};

/* Forward declarations */
static void gcr_collection_model_tree_model (GtkTreeModelIface *iface);

G_DEFINE_TYPE_EXTENDED (GcrCollectionModel, gcr_collection_model, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (GTK_TYPE_TREE_MODEL, gcr_collection_model_tree_model));

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gint
index_for_iter (GcrCollectionModel *self, const GtkTreeIter *iter)
{
	gint index;

	g_return_val_if_fail (iter, -1);
	g_return_val_if_fail (iter->stamp == self->pv->last_stamp, -1);
	g_return_val_if_fail (G_IS_OBJECT (iter->user_data), -1);

	index = GPOINTER_TO_INT (iter->user_data2);
	g_assert (index >= 0 && index < self->pv->objects->len);
	return index;
}

static gboolean
iter_for_index (GcrCollectionModel *self, gint index, GtkTreeIter *iter)
{
	GObject *object;

	if (index < 0 || index >= self->pv->objects->len)
		return FALSE;

	object = g_ptr_array_index (self->pv->objects, index);
	g_return_val_if_fail (G_IS_OBJECT (object), FALSE);

	memset (iter, 0, sizeof (*iter));
	iter->stamp = self->pv->last_stamp;
	iter->user_data = object;
	iter->user_data2 = GINT_TO_POINTER (index);
	return TRUE;
}

static gint
index_for_object (GcrCollectionModel *self, GObject *object)
{
	gpointer value;
	guint i;

	/* Build the index if not valid */
	if (self->pv->cache_stamp != self->pv->last_stamp) {
		g_hash_table_remove_all (self->pv->object_to_index);
		for (i = 0; i < self->pv->objects->len; ++i) {
			g_hash_table_insert (self->pv->object_to_index,
			                     g_ptr_array_index (self->pv->objects, i),
			                     GUINT_TO_POINTER (i));
		}
		self->pv->cache_stamp = self->pv->last_stamp;
	}

	if (!g_hash_table_lookup_extended (self->pv->object_to_index, object, NULL, &value))
		return -1;

	return GPOINTER_TO_INT (value);
}

static void
on_object_notify (GObject *object, GParamSpec *spec, GcrCollectionModel *self)
{
	GtkTreeIter iter;
	GtkTreePath *path;
	guint i;

	g_return_if_fail (spec->name);

	for (i = 0; i < self->pv->n_columns; ++i) {
		g_assert (self->pv->column_names[i]);
		if (g_str_equal (self->pv->column_names[i], spec->name)) {
			if (!gcr_collection_model_iter_for_object (self, object, &iter))
				g_return_if_reached ();

			path = gtk_tree_model_get_path (GTK_TREE_MODEL (self), &iter);
			g_return_if_fail (path);

			gtk_tree_model_row_changed (GTK_TREE_MODEL (self), path, &iter);
			gtk_tree_path_free (path);

			return;
		}
	}
}

static void
on_object_gone (gpointer unused, GObject *was_object)
{
	g_warning ("object contained in GcrCollection and included in GcrCollectionModel "
	           "was destroyed before it was removed from the collection");
}

static gint
add_object (GcrCollectionModel *self, GObject *object)
{
	GtkTreeIter iter;
	GtkTreePath *path;
	gint index;

	g_assert (GCR_IS_COLLECTION_MODEL (self));
	g_assert (G_IS_OBJECT (object));

	index = self->pv->objects->len;

	g_ptr_array_add (self->pv->objects, object);
	g_object_weak_ref (G_OBJECT (object), (GWeakNotify)on_object_gone, self);
	g_signal_connect (object, "notify", G_CALLBACK (on_object_notify), self);

	self->pv->last_stamp++;

	/* Fire signal for this added row */
	if (!iter_for_index (self, self->pv->objects->len - 1, &iter))
		g_assert_not_reached ();

	path = gtk_tree_model_get_path (GTK_TREE_MODEL (self), &iter);
	g_return_val_if_fail (path, -1);

	gtk_tree_model_row_inserted (GTK_TREE_MODEL (self), path, &iter);
	gtk_tree_path_free (path);

	return index;
}

static void
disconnect_object (GcrCollectionModel *self, GObject *object)
{
	g_object_weak_unref (G_OBJECT (object), on_object_gone, self);
	g_signal_handlers_disconnect_by_func (object, on_object_notify, self);
}

static void
remove_object (GcrCollectionModel *self, gint index, GObject *object)
{
	GtkTreePath *path;

	path = gtk_tree_path_new ();
	gtk_tree_path_append_index (path, index);

	disconnect_object (self, object);
	g_assert (g_ptr_array_index (self->pv->objects, index) == object);
	g_ptr_array_remove_index (self->pv->objects, index);

	self->pv->last_stamp++;

	/* Fire signal for this removed row */
	gtk_tree_model_row_deleted (GTK_TREE_MODEL (self), path);
	gtk_tree_path_free (path);
}

static void
on_collection_added (GcrCollection *collection, GObject *object, GcrCollectionModel *self)
{
	g_return_if_fail (GCR_COLLECTION_MODEL (self));
	g_return_if_fail (G_IS_OBJECT (object));

	add_object (self, object);
}

static void
on_collection_removed (GcrCollection *collection, GObject *object,
                       GcrCollectionModel *self)
{
	gint index;

	g_return_if_fail (GCR_COLLECTION_MODEL (self));
	g_return_if_fail (G_IS_OBJECT (object));

	index = index_for_object (self, object);
	g_return_if_fail (index < 0);

	remove_object (self, index, object);
}

static void
populate_model (GcrCollectionModel *self)
{
	GList *objects, *l;
	objects = gcr_collection_get_objects (self->pv->collection);
	for (l = objects; l; l = g_list_next (l))
		on_collection_added (self->pv->collection, G_OBJECT (l->data), self);
	g_list_free (objects);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GtkTreeModelFlags
gcr_collection_model_real_get_flags (GtkTreeModel *model)
{
	/* TODO: Maybe we can eventually GTK_TREE_MODEL_ITERS_PERSIST */
	return 0;
}

static gint
gcr_collection_model_real_get_n_columns (GtkTreeModel *model)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	return self->pv->n_columns;
}

static GType
gcr_collection_model_real_get_column_type (GtkTreeModel *model, gint index)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	g_return_val_if_fail (index >= 0 && index < self->pv->n_columns, 0);
	return self->pv->column_types[index];
}

static gboolean
gcr_collection_model_real_get_iter (GtkTreeModel *model, GtkTreeIter *iter, GtkTreePath *path)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	const gint *indices;
	gint count;

	count = gtk_tree_path_get_depth (path);
	if (count != 1)
		return FALSE;

	indices = gtk_tree_path_get_indices (path);
	return iter_for_index (self, indices[0], iter);
}

static GtkTreePath*
gcr_collection_model_real_get_path (GtkTreeModel *model, GtkTreeIter *iter)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	GtkTreePath *path;
	gint index;

	index = index_for_iter (self, iter);
	g_return_val_if_fail (index >= 0, NULL);

	path = gtk_tree_path_new ();
	gtk_tree_path_prepend_index (path, index);
	return path;
}

static void
gcr_collection_model_real_get_value (GtkTreeModel *model, GtkTreeIter *iter,
                                     gint column, GValue *value)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	const gchar *property;
	GParamSpec *spec;
	GObject *object;
	GValue original;
	GType type;

	object = gcr_collection_model_object_for_iter (self, iter);
	g_return_if_fail (G_IS_OBJECT (object));
	g_return_if_fail (column >= 0 && column < self->pv->n_columns);

	/* Figure out which property */
	type = self->pv->column_types[column];
	property = self->pv->column_names[column];
	g_assert (property);
	g_value_init (value, type);

	/* Lookup the property on the object */
	spec = g_object_class_find_property (G_OBJECT_GET_CLASS (object), property);
	if (spec) {

		/* Simple, no transformation necessary */
		if (spec->value_type == type) {
			g_object_get_property (object, property, value);

		/* Not the same type, try to transform */
		} else {

			memset (&original, 0, sizeof (original));
			g_value_init (&original, spec->value_type);

			g_object_get_property (object, property, &original);
			if (!g_value_transform (&original, value)) {
				g_warning ("%s property of %s class was of type %s instead of type %s"
				           " and cannot be converted", property, G_OBJECT_TYPE_NAME (object),
				           g_type_name (spec->value_type), g_type_name (type));
				spec = NULL;
			}
		}
	}

	/* No property present */
	if (spec == NULL) {

		/* All the number types have sane defaults */
		if (type == G_TYPE_STRING)
			g_value_set_string (value, "");
	}
}

static gboolean
gcr_collection_model_real_iter_next (GtkTreeModel *model, GtkTreeIter *iter)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	gint index;

	index = index_for_iter (self, iter);
	g_return_val_if_fail (index >= 0, FALSE);

	return iter_for_index (self, index + 1, iter);
}

static gboolean
gcr_collection_model_real_iter_children (GtkTreeModel *model, GtkTreeIter *iter, GtkTreeIter *parent)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);

	if (parent != NULL)
		return FALSE;

	return iter_for_index (self, 0, iter);
}

static gboolean
gcr_collection_model_real_iter_has_child (GtkTreeModel *model, GtkTreeIter *iter)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	if (iter == NULL)
		return self->pv->objects->len > 0;
	return FALSE;
}

static gint
gcr_collection_model_real_iter_n_children (GtkTreeModel *model, GtkTreeIter *iter)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	if (iter == NULL)
		return self->pv->objects->len;
	return 0;
}

static gboolean
gcr_collection_model_real_iter_nth_child (GtkTreeModel *model, GtkTreeIter *iter,
                                          GtkTreeIter *parent, gint n)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	if (parent != NULL)
		return FALSE;
	return iter_for_index (self, n, iter);
}

static gboolean
gcr_collection_model_real_iter_parent (GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *child)
{
	return FALSE;
}

static void
gcr_collection_model_real_ref_node (GtkTreeModel *model, GtkTreeIter *iter)
{
	/* Nothing to do */
}

static void
gcr_collection_model_real_unref_node (GtkTreeModel *model, GtkTreeIter *iter)
{
	/* Nothing to do */
}

static void
gcr_collection_model_tree_model (GtkTreeModelIface *iface)
{
	iface->get_flags = gcr_collection_model_real_get_flags;
	iface->get_n_columns = gcr_collection_model_real_get_n_columns;
	iface->get_column_type = gcr_collection_model_real_get_column_type;
	iface->get_iter = gcr_collection_model_real_get_iter;
	iface->get_path = gcr_collection_model_real_get_path;
	iface->get_value = gcr_collection_model_real_get_value;
	iface->iter_next = gcr_collection_model_real_iter_next;
	iface->iter_children = gcr_collection_model_real_iter_children;
	iface->iter_has_child = gcr_collection_model_real_iter_has_child;
	iface->iter_n_children = gcr_collection_model_real_iter_n_children;
	iface->iter_nth_child = gcr_collection_model_real_iter_nth_child;
	iface->iter_parent = gcr_collection_model_real_iter_parent;
	iface->ref_node = gcr_collection_model_real_ref_node;
	iface->unref_node = gcr_collection_model_real_unref_node;
}

static void
gcr_collection_model_init (GcrCollectionModel *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_COLLECTION_MODEL, GcrCollectionModelPrivate);

	self->pv->object_to_index = g_hash_table_new (g_direct_hash, g_direct_equal);
	self->pv->objects = g_ptr_array_new ();
	self->pv->column_names = NULL;
	self->pv->n_columns = 0;
	self->pv->column_types = NULL;
	self->pv->last_stamp = 0x1000;
}

static void
gcr_collection_model_set_property (GObject *object, guint prop_id,
                                   const GValue *value, GParamSpec *pspec)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (object);

	switch (prop_id) {
	case PROP_COLLECTION:
		g_return_if_fail (self->pv->collection == NULL);
		self->pv->collection = g_value_dup_object (value);
		if (self->pv->collection) {
			g_signal_connect_after (self->pv->collection, "added", G_CALLBACK (on_collection_added), self);
			g_signal_connect_after (self->pv->collection, "removed", G_CALLBACK (on_collection_removed), self);
			populate_model (self);
		}
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gcr_collection_model_get_property (GObject *object, guint prop_id,
                                   GValue *value, GParamSpec *pspec)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (object);

	switch (prop_id) {
	case PROP_COLLECTION:
		g_value_set_object (value, self->pv->collection);
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gcr_collection_model_dispose (GObject *object)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (object);
	GObject *obj;
	guint i;

	/* Disconnect from all rows */
	for (i = self->pv->objects->len; i > 0; --i) {
		obj = g_ptr_array_index (self->pv->objects, i - 1);
		disconnect_object (self, object);
	}

	/* Disconnect from the collection */
	if (self->pv->collection) {
		g_signal_handlers_disconnect_by_func (self->pv->collection, on_collection_added, self);
		g_signal_handlers_disconnect_by_func (self->pv->collection, on_collection_removed, self);
		g_object_unref (self->pv->collection);
		self->pv->collection = NULL;
	}

	G_OBJECT_CLASS (gcr_collection_model_parent_class)->dispose (object);
}

static void
gcr_collection_model_finalize (GObject *object)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (object);

	g_assert (!self->pv->collection);

	g_assert (self->pv->object_to_index);
	g_assert (g_hash_table_size (self->pv->object_to_index) == 0);
	g_hash_table_destroy (self->pv->object_to_index);
	self->pv->object_to_index = NULL;

	g_assert (self->pv->objects);
	g_ptr_array_free (self->pv->objects, TRUE);
	self->pv->objects = NULL;

	if (self->pv->column_names) {
		g_strfreev (self->pv->column_names);
		self->pv->column_names = NULL;
		self->pv->n_columns = 0;
	}

	if (self->pv->column_types) {
		g_free (self->pv->column_types);
		self->pv->column_types = NULL;
	}

	G_OBJECT_CLASS (gcr_collection_model_parent_class)->finalize (object);
}

static void
gcr_collection_model_class_init (GcrCollectionModelClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gcr_collection_model_parent_class = g_type_class_peek_parent (klass);

	gobject_class->dispose = gcr_collection_model_dispose;
	gobject_class->finalize = gcr_collection_model_finalize;
	gobject_class->set_property = gcr_collection_model_set_property;
	gobject_class->get_property = gcr_collection_model_get_property;

	g_object_class_install_property (gobject_class, PROP_COLLECTION,
		g_param_spec_object ("collection", "Object Collection", "Collection to get objects from",
		                     GCR_TYPE_COLLECTION, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_type_class_add_private (klass, sizeof (GcrCollectionModelPrivate));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GcrCollectionModel*
gcr_collection_model_new (GcrCollection *collection, ...)
{
	GcrCollectionModelColumn column;
	GcrCollectionModel *self;
	const gchar *arg;
	GArray *array;
	va_list va;

	array = g_array_new (TRUE, TRUE, sizeof (GcrCollectionModelColumn));

	va_start (va, collection);
	while ((arg = va_arg (va, const gchar*)) != NULL) {
		column.property = arg;
		column.type = va_arg (va, GType);
		column.data = NULL;
		g_array_append_val (array, column);
	}
	va_end (va);

	self = gcr_collection_model_new_full (collection, (GcrCollectionModelColumn*)array->data, array->len);
	g_array_free (array, TRUE);
	return self;
}

GcrCollectionModel*
gcr_collection_model_new_full (GcrCollection *collection, const GcrCollectionModelColumn *columns, guint n_columns)
{
	GcrCollectionModel *self = g_object_new (GCR_TYPE_COLLECTION_MODEL, "collection", collection, NULL);
	gcr_collection_model_set_columns (self, columns, n_columns);
	return self;
}

gint
gcr_collection_model_set_columns (GcrCollectionModel *self, const GcrCollectionModelColumn *columns,
                                  guint n_columns)
{
	guint i;

	g_return_val_if_fail (GCR_IS_COLLECTION_MODEL (self), -1);
	g_return_val_if_fail (self->pv->n_columns == 0, -1);

	self->pv->column_names = g_new0 (gchar*, n_columns + 1);
	self->pv->column_types = g_new0 (GType, n_columns + 1);
	self->pv->n_columns = n_columns;

	for (i = 0; i < n_columns; ++i) {
		self->pv->column_names[i] = g_strdup (columns[i].property);
		self->pv->column_types[i] = columns[i].type;
	}

	return n_columns - 1;
}

GObject*
gcr_collection_model_object_for_iter (GcrCollectionModel *self, const GtkTreeIter *iter)
{
	g_return_val_if_fail (GCR_IS_COLLECTION_MODEL (self), NULL);
	g_return_val_if_fail (iter, NULL);
	g_return_val_if_fail (iter->stamp == self->pv->last_stamp, NULL);
	g_return_val_if_fail (G_IS_OBJECT (iter->user_data), NULL);

	return G_OBJECT (iter->user_data);
}

gboolean
gcr_collection_model_iter_for_object (GcrCollectionModel *self, GObject *object,
                                      GtkTreeIter *iter)
{
	gint index;

	g_return_val_if_fail (GCR_IS_COLLECTION_MODEL (self), FALSE);
	g_return_val_if_fail (G_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (iter, FALSE);

	index = index_for_object (self, object);
	if (index < 0)
		return FALSE;

	return iter_for_index (self, index, iter);
}
