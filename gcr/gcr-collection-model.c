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

#include <gtk/gtk.h>

#include <string.h>
#include <unistd.h>

/**
 * SECTION:gcr-collection-model
 * @title: GcrCollectionModel
 * @short_description: A GtkTreeModel that represents a collection
 *
 * This is an implementation of #GtkTreeModel which represents the objects in
 * the a #GcrCollection. As objects are added or removed from the collection,
 * rows are added and removed from this model.
 *
 * The row values come from the properties of the objects in the collection. Use
 * gcr_collection_model_new() to create a new collection model. To have more
 * control over the values use a set of #GcrColumn structures to define the
 * columns. This can be done with gcr_collection_model_new_full() or
 * gcr_collection_model_set_columns().
 *
 * Each row can have a selected state, which is represented by a boolean column.
 * The selected state can be toggled with gcr_collection_model_toggle_selected()
 * or set with gcr_collection_model_set_selected_objects() and retrieved with
 * gcr_collection_model_get_selected_objects().
 *
 * To determine which object a row represents and vice versa, use the
 * gcr_collection_model_iter_for_object() or gcr_collection_model_object_for_iter()
 * functions.
 */

/**
 * GcrCollectionModel:
 * @parent: The parent object
 *
 * A #GtkTreeModel which contains a row for each object in a #GcrCollection.
 */

/**
 * GcrCollectionModelClass:
 * @parent_class: The parent class
 *
 * The class for #GcrCollectionModel.
 */

#define COLLECTION_MODEL_STAMP 0xAABBCCDD

enum {
	PROP_0,
	PROP_COLLECTION,
	PROP_COLUMNS
};

typedef struct {
	GObject *object;
	GSequenceIter *parent;
	GSequence *children;
} GcrCollectionRow;

typedef struct {
	GtkTreeIterCompareFunc sort_func;
	gpointer user_data;
	GDestroyNotify destroy_func;
} GcrCollectionSortClosure;

typedef struct _GcrCollectionColumn {
	gchar *property;
	GType *type;
	GtkTreeIterCompareFunc sort_func;
	gpointer sort_data;
	GDestroyNotify sort_destroy;
} GcrCollectionColumn;

struct _GcrCollectionModelPrivate {
	GcrCollection *collection;
	GHashTable *selected;
	GSequence *root_sequence;
	GHashTable *object_to_seq;

	const GcrColumn *columns;
	guint n_columns;

	/* Sort information */
	gint sort_column_id;
	GtkSortType sort_order_type;
	GcrCollectionSortClosure *column_sort_closures;
	GcrCollectionSortClosure default_sort_closure;

	/* Sequence ordering information */
	GCompareDataFunc order_current;
	gpointer order_argument;
};

/* Forward declarations */
static void gcr_collection_model_tree_model_init (GtkTreeModelIface *iface);
static void gcr_collection_model_tree_sortable_init (GtkTreeSortableIface *iface);

G_DEFINE_TYPE_EXTENDED (GcrCollectionModel, gcr_collection_model, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (GTK_TYPE_TREE_MODEL, gcr_collection_model_tree_model_init)
                        G_IMPLEMENT_INTERFACE (GTK_TYPE_TREE_SORTABLE, gcr_collection_model_tree_sortable_init)
);

typedef gint (*CompareValueFunc) (const GValue *va,
                                  const GValue *vb);

static gint
compare_int_value (const GValue *va,
                   const GValue *vb)
{
	gint a = g_value_get_int (va);
	gint b = g_value_get_int (vb);
	if (a > b) return 1;
	else if (a < b) return -1;
	return 0;
}

static gint
compare_uint_value (const GValue *va,
                    const GValue *vb)
{
	guint a = g_value_get_uint (va);
	guint b = g_value_get_uint (vb);
	if (a > b) return 1;
	else if (a < b) return -1;
	return 0;
}

static gint
compare_long_value (const GValue *va,
                    const GValue *vb)
{
	glong a = g_value_get_long (va);
	glong b = g_value_get_long (vb);
	if (a > b) return 1;
	else if (a < b) return -1;
	return 0;
}

static gint
compare_ulong_value (const GValue *va,
                     const GValue *vb)
{
	gulong a = g_value_get_ulong (va);
	gulong b = g_value_get_ulong (vb);
	if (a > b) return 1;
	else if (a < b) return -1;
	return 0;
}

static gint
compare_string_value (const GValue *va,
                      const GValue *vb)
{
	const gchar *a = g_value_get_string (va);
	const gchar *b = g_value_get_string (vb);
	gchar *case_a;
	gchar *case_b;
	gboolean ret;

	if (a == b)
		return 0;
	else if (!a)
		return -1;
	else if (!b)
		return 1;

	case_a = g_utf8_casefold (a, -1);
	case_b = g_utf8_casefold (b, -1);
	ret = g_utf8_collate (case_a, case_b);
	g_free (case_a);
	g_free (case_b);

	return ret;
}

static gint
compare_date_value (const GValue *va,
                    const GValue *vb)
{
	GDate *a = g_value_get_boxed (va);
	GDate *b = g_value_get_boxed (vb);

	if (a == b)
		return 0;
	else if (!a)
		return -1;
	else if (!b)
		return 1;
	else
		return g_date_compare (a, b);
}

static CompareValueFunc
lookup_compare_func (GType type)
{
	switch (type) {
	case G_TYPE_INT:
		return compare_int_value;
	case G_TYPE_UINT:
		return compare_uint_value;
	case G_TYPE_LONG:
		return compare_long_value;
	case G_TYPE_ULONG:
		return compare_ulong_value;
	case G_TYPE_STRING:
		return compare_string_value;
	}

	if (type == G_TYPE_DATE)
		return compare_date_value;

	return NULL;
}

static gint
order_sequence_by_closure (gconstpointer a,
                           gconstpointer b,
                           gpointer user_data)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (user_data);
	GcrCollectionSortClosure *closure = self->pv->order_argument;
	const GcrCollectionRow *row_a = a;
	const GcrCollectionRow *row_b = b;
	GtkTreeIter iter_a;
	GtkTreeIter iter_b;

	g_assert (closure);
	g_assert (closure->sort_func);

	if (!gcr_collection_model_iter_for_object (self, row_a->object, &iter_a))
		g_return_val_if_reached (0);
	if (!gcr_collection_model_iter_for_object (self, row_b->object, &iter_b))
		g_return_val_if_reached (0);

	return (closure->sort_func) (GTK_TREE_MODEL (self),
	                             &iter_a, &iter_b, closure->user_data);
}

static gint
order_sequence_by_closure_reverse (gconstpointer a,
                                   gconstpointer b,
                                   gpointer user_data)
{
	return 0 - order_sequence_by_closure (a, b, user_data);
}

static gint
order_sequence_as_unsorted (gconstpointer a,
                            gconstpointer b,
                            gpointer user_data)
{
	const GcrCollectionRow *row_a = a;
	const GcrCollectionRow *row_b = b;
	return GPOINTER_TO_INT (row_a->object) - GPOINTER_TO_INT (row_b->object);
}

static gint
order_sequence_as_unsorted_reverse (gconstpointer a,
                                    gconstpointer b,
                                    gpointer user_data)
{
	const GcrCollectionRow *row_a = a;
	const GcrCollectionRow *row_b = b;
	return GPOINTER_TO_INT (row_b->object) - GPOINTER_TO_INT (row_a->object);
}

static void
lookup_object_property (GObject *object,
                        const gchar *property_name,
                        GValue *value)
{
	if (g_object_class_find_property (G_OBJECT_GET_CLASS (object), property_name))
		g_object_get_property (object, property_name, value);

	/* Other types have sane defaults */
	else if (G_VALUE_TYPE (value) == G_TYPE_STRING)
		g_value_set_string (value, "");
}

static gint
order_sequence_by_property (gconstpointer a,
                            gconstpointer b,
                            gpointer user_data)
{
	const GcrCollectionRow *row_a = a;
	const GcrCollectionRow *row_b = b;
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (user_data);
	const GcrColumn *column = self->pv->order_argument;
	GValue value_a = { 0, };
	GValue value_b = { 0, };
	CompareValueFunc compare;
	gint ret;

	g_assert (column);

	/* Sort according to property values */
	column = &self->pv->columns[self->pv->sort_column_id];
	g_value_init (&value_a, column->property_type);
	lookup_object_property (row_a->object, column->property_name, &value_a);
	g_value_init (&value_b, column->property_type);
	lookup_object_property (row_b->object, column->property_name, &value_b);

	compare = lookup_compare_func (column->property_type);
	g_assert (compare != NULL);

	ret = (compare) (&value_a, &value_b);

	g_value_unset (&value_a);
	g_value_unset (&value_b);

	return ret;
}

static gint
order_sequence_by_property_reverse (gconstpointer a,
                                    gconstpointer b,
                                    gpointer user_data)
{
	return 0 - order_sequence_by_property (a, b, user_data);
}

static GHashTable*
selected_hash_table_new (void)
{
	return g_hash_table_new (g_direct_hash, g_direct_equal);
}

static gboolean
sequence_iter_to_tree (GcrCollectionModel *self,
                       GSequenceIter *seq,
                       GtkTreeIter *iter)
{
	GcrCollectionRow *row;

	g_return_val_if_fail (seq != NULL, FALSE);

	if (g_sequence_iter_is_end (seq))
		return FALSE;

	row = g_sequence_get (seq);
	g_return_val_if_fail (row != NULL && G_IS_OBJECT (row->object), FALSE);

	memset (iter, 0, sizeof (*iter));
	iter->stamp = COLLECTION_MODEL_STAMP;
	iter->user_data = row->object;
	iter->user_data2 = seq;
	return TRUE;
}

static GSequenceIter *
sequence_iter_for_tree (GcrCollectionModel *self,
                        GtkTreeIter *iter)
{
	g_return_val_if_fail (iter != NULL, NULL);
	g_return_val_if_fail (iter->stamp == COLLECTION_MODEL_STAMP, NULL);
	return iter->user_data2;
}

static GtkTreePath *
sequence_iter_to_path (GcrCollectionModel *self,
                       GSequenceIter *seq)
{
	GcrCollectionRow *row;
	GtkTreePath *path;

	path = gtk_tree_path_new ();
	while (seq) {
		gtk_tree_path_prepend_index (path, g_sequence_iter_get_position (seq));
		row = g_sequence_get (seq);
		seq = row->parent;
	}
	return path;
}

static GSequence *
child_sequence_for_tree (GcrCollectionModel *self,
                         GtkTreeIter *iter)
{
	GcrCollectionRow *row;
	GSequenceIter *seq;

	if (iter == NULL) {
		return self->pv->root_sequence;
	} else {
		seq = sequence_iter_for_tree (self, iter);
		g_return_val_if_fail (seq != NULL, NULL);
		row = g_sequence_get (seq);
		return row->children;
	}
}

static void
on_object_notify (GObject *object, GParamSpec *spec, GcrCollectionModel *self)
{
	GtkTreeIter iter;
	GtkTreePath *path;
	gboolean found = FALSE;
	guint i;

	g_return_if_fail (spec->name);

	for (i = 0; i < self->pv->n_columns - 1; ++i) {
		g_assert (self->pv->columns[i].property_name);
		if (g_str_equal (self->pv->columns[i].property_name, spec->name)) {
			found = TRUE;
			break;
		}
	}

	/* Tell the tree view that this row changed */
	if (found) {
		if (!gcr_collection_model_iter_for_object (self, object, &iter))
			g_return_if_reached ();
		path = gtk_tree_model_get_path (GTK_TREE_MODEL (self), &iter);
		g_return_if_fail (path);
		gtk_tree_model_row_changed (GTK_TREE_MODEL (self), path, &iter);
		gtk_tree_path_free (path);
	}
}

static void
on_object_gone (gpointer unused, GObject *was_object)
{
	g_warning ("object contained in GcrCollection and included in GcrCollectionModel "
	           "was destroyed before it was removed from the collection");
}

static void      on_collection_added              (GcrCollection *collection,
                                                   GObject *object,
                                                   gpointer user_data);

static void      on_collection_removed            (GcrCollection *collection,
                                                   GObject *object,
                                                   gpointer user_data);

static void      add_object_to_sequence           (GcrCollectionModel *self,
                                                   GSequence *sequence,
                                                   GSequenceIter *parent,
                                                   GObject *object,
                                                   gboolean emit);

static void      remove_object_from_sequence      (GcrCollectionModel *self,
                                                   GSequence *sequence,
                                                   GSequenceIter *seq,
                                                   GObject *object,
                                                   gboolean emit);

static void
add_children_to_sequence (GcrCollectionModel *self,
                          GSequence *sequence,
                          GSequenceIter *parent,
                          GcrCollection *collection,
                          gboolean emit)
{
	GList *children, *l;

	children = gcr_collection_get_objects (collection);
	for (l = children; l; l = g_list_next (l))
		add_object_to_sequence (self, sequence, parent, l->data, emit);
	g_list_free (children);

	/* Now listen in for any changes */
	g_signal_connect_after (collection, "added", G_CALLBACK (on_collection_added), self);
	g_signal_connect_after (collection, "removed", G_CALLBACK (on_collection_removed), self);
}

static void
add_object_to_sequence (GcrCollectionModel *self,
                        GSequence *sequence,
                        GSequenceIter *parent,
                        GObject *object,
                        gboolean emit)
{
	GcrCollectionRow *row;
	GSequenceIter *seq;
	GtkTreeIter iter;
	GtkTreePath *path;

	g_assert (GCR_IS_COLLECTION_MODEL (self));
	g_assert (G_IS_OBJECT (object));
	g_assert (self->pv->order_current);

	if (g_hash_table_lookup (self->pv->object_to_seq, object)) {
		g_warning ("object was already added to the GcrCollectionModel. Perhaps "
		           "a loop exists in a tree structure?");
		return;
	}

	row = g_slice_new0 (GcrCollectionRow);
	row->object = object;
	row->parent = parent;
	row->children = NULL;

	seq = g_sequence_insert_sorted (sequence, row, self->pv->order_current, self);
	g_hash_table_insert (self->pv->object_to_seq, object, seq);
	g_object_weak_ref (G_OBJECT (object), (GWeakNotify)on_object_gone, self);
	g_signal_connect (object, "notify", G_CALLBACK (on_object_notify), self);

	if (emit) {
		if (!sequence_iter_to_tree (self, seq, &iter))
			g_assert_not_reached ();
		path = sequence_iter_to_path (self, seq);
		g_assert (path != NULL);
		gtk_tree_model_row_inserted (GTK_TREE_MODEL (self), path, &iter);
		gtk_tree_path_free (path);
	}

	if (GCR_IS_COLLECTION (object)) {
		row->children = g_sequence_new (NULL);
		add_children_to_sequence (self, row->children, seq,
		                          GCR_COLLECTION (object), emit);
	}
}

static void
on_collection_added (GcrCollection *collection,
                     GObject *object,
                     gpointer user_data)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (user_data);
	GSequence *sequence;
	GSequenceIter *parent;
	GcrCollectionRow *row;

	if (collection == self->pv->collection) {
		sequence = self->pv->root_sequence;
		parent = NULL;
	} else {
		parent = g_hash_table_lookup (self->pv->object_to_seq, G_OBJECT (collection));
		row = g_sequence_get (parent);
		g_assert (row->children);
		sequence = row->children;
	}

	add_object_to_sequence (self, sequence, parent, object, TRUE);
}

static void
remove_children_from_sequence (GcrCollectionModel *self,
                               GSequence *sequence,
                               GcrCollection *collection,
                               gboolean emit)
{
	GSequenceIter *seq, *next;
	GcrCollectionRow *row;

	g_signal_handlers_disconnect_by_func (collection, on_collection_added, self);
	g_signal_handlers_disconnect_by_func (collection, on_collection_removed, self);

	for (seq = g_sequence_get_begin_iter (sequence);
	     !g_sequence_iter_is_end (seq); seq = next) {
		next = g_sequence_iter_next (seq);
		row = g_sequence_get (seq);
		remove_object_from_sequence (self, sequence, seq, row->object, emit);
	}
}

static void
remove_object_from_sequence (GcrCollectionModel *self,
                             GSequence *sequence,
                             GSequenceIter *seq,
                             GObject *object,
                             gboolean emit)
{
	GcrCollectionRow *row;
	GtkTreePath *path = NULL;

	if (emit) {
		path = sequence_iter_to_path (self, seq);
		g_assert (path != NULL);
	}

	row = g_sequence_get (seq);
	g_assert (row->object == object);

	g_object_weak_unref (object, on_object_gone, self);
	g_signal_handlers_disconnect_by_func (object, on_object_notify, self);

	if (row->children) {
		g_assert (GCR_IS_COLLECTION (object));
		remove_children_from_sequence (self, row->children, GCR_COLLECTION (object), emit);
		g_assert (g_sequence_get_length (row->children) == 0);
		g_sequence_free (row->children);
		row->children = NULL;
	}

	g_hash_table_remove (self->pv->selected, object);
	if (!g_hash_table_remove (self->pv->object_to_seq, object))
		g_assert_not_reached ();

	g_sequence_remove (seq);
	g_slice_free (GcrCollectionRow, row);

	/* Fire signal for this removed row */
	if (path != NULL) {
		gtk_tree_model_row_deleted (GTK_TREE_MODEL (self), path);
		gtk_tree_path_free (path);
	}

}

static void
on_collection_removed (GcrCollection *collection,
                       GObject *object,
                       gpointer user_data)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (user_data);
	GSequenceIter *seq;
	GSequence *sequence;

	seq = g_hash_table_lookup (self->pv->object_to_seq, object);
	g_return_if_fail (seq != NULL);

	sequence = g_sequence_iter_get_sequence (seq);
	g_assert (sequence != NULL);

	remove_object_from_sequence (self, sequence, seq, object, TRUE);
}

static void
free_owned_columns (gpointer data)
{
	GcrColumn *columns;
	g_assert (data);

	/* Only the property column is in use */
	for (columns = data; columns->property_name; ++columns)
		g_free ((gchar*)columns->property_name);
	g_free (data);
}

static GtkTreeModelFlags
gcr_collection_model_real_get_flags (GtkTreeModel *model)
{
	return GTK_TREE_MODEL_ITERS_PERSIST;
}

static gint
gcr_collection_model_real_get_n_columns (GtkTreeModel *model)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	return self->pv->n_columns;
}

static GType
gcr_collection_model_real_get_column_type (GtkTreeModel *model,
                                           gint column_id)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	g_return_val_if_fail (column_id >= 0 && column_id <= self->pv->n_columns, 0);

	/* The last is the selected column */
	if (column_id == self->pv->n_columns)
		return G_TYPE_BOOLEAN;

	return self->pv->columns[column_id].column_type;
}

static gboolean
gcr_collection_model_real_get_iter (GtkTreeModel *model,
                                    GtkTreeIter *iter,
                                    GtkTreePath *path)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	const gint *indices;
	GSequence *sequence;
	GSequenceIter *seq;
	GcrCollectionRow *row;
	gint count;
	gint i;

	sequence = self->pv->root_sequence;
	seq = NULL;

	indices = gtk_tree_path_get_indices_with_depth (path, &count);
	if (count == 0)
		return FALSE;

	for (i = 0; i < count; i++) {
		if (!sequence)
			return FALSE;
		seq = g_sequence_get_iter_at_pos (sequence, indices[i]);
		if (g_sequence_iter_is_end (seq))
			return FALSE;
		row = g_sequence_get (seq);
		sequence = row->children;
	}

	return sequence_iter_to_tree (self, seq, iter);
}

static GtkTreePath*
gcr_collection_model_real_get_path (GtkTreeModel *model,
                                    GtkTreeIter *iter)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	GSequenceIter *seq;

	if (iter == NULL)
		return gtk_tree_path_new ();

	seq = sequence_iter_for_tree (self, iter);
	g_return_val_if_fail (seq != NULL, NULL);
	return sequence_iter_to_path (self, seq);
}

static void
gcr_collection_model_real_get_value (GtkTreeModel *model,
                                     GtkTreeIter *iter,
                                     gint column_id,
                                     GValue *value)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	GObject *object;
	GValue original;
	const GcrColumn *column;
	GParamSpec *spec;

	object = gcr_collection_model_object_for_iter (self, iter);
	g_return_if_fail (G_IS_OBJECT (object));
	g_return_if_fail (column_id >= 0 && column_id < self->pv->n_columns);

	/* The selected column? Last one */
	if (column_id == self->pv->n_columns - 1) {
		g_value_init (value, G_TYPE_BOOLEAN);
		g_value_set_boolean (value, gcr_collection_model_is_selected (self, iter));
		return;
	}

	/* Figure out which property */
	column = &self->pv->columns[column_id];
	g_assert (column->property_name);
	g_value_init (value, column->column_type);

	/* Lookup the property on the object */
	spec = g_object_class_find_property (G_OBJECT_GET_CLASS (object), column->property_name);
	if (spec != NULL) {
		/* A transformer is specified, or mismatched types */
		if (column->transformer || column->column_type != column->property_type) {
			memset (&original, 0, sizeof (original));
			g_value_init (&original, column->property_type);
			g_object_get_property (object, column->property_name, &original);

			if (column->transformer) {
				(column->transformer) (&original, value);
			} else {
				g_warning ("%s property of %s class was of type %s instead of type %s"
				           " and cannot be converted due to lack of transformer",
				           column->property_name, G_OBJECT_TYPE_NAME (object),
				           g_type_name (column->property_type),
				           g_type_name (column->column_type));
				spec = NULL;
			}

		/* Simple, no transformation necessary */
		} else {
			g_object_get_property (object, column->property_name, value);
		}
	}

	if (spec == NULL) {

		/* All the number types have sane defaults */
		if (column->column_type == G_TYPE_STRING)
			g_value_set_string (value, "");
	}
}

static gboolean
gcr_collection_model_real_iter_next (GtkTreeModel *model,
                                     GtkTreeIter *iter)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	GSequenceIter *seq = sequence_iter_for_tree (self, iter);
	g_return_val_if_fail (seq != NULL, FALSE);
	return sequence_iter_to_tree (self, g_sequence_iter_next (seq), iter);
}

static gboolean
gcr_collection_model_real_iter_children (GtkTreeModel *model,
                                         GtkTreeIter *iter,
                                         GtkTreeIter *parent)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	GSequence *sequence = child_sequence_for_tree (self, parent);
	return sequence && sequence_iter_to_tree (self, g_sequence_get_begin_iter (sequence), iter);
}

static gboolean
gcr_collection_model_real_iter_has_child (GtkTreeModel *model,
                                          GtkTreeIter *iter)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	GSequence *sequence = child_sequence_for_tree (self, iter);
	return sequence && !g_sequence_iter_is_end (g_sequence_get_begin_iter (sequence));
}

static gint
gcr_collection_model_real_iter_n_children (GtkTreeModel *model,
                                           GtkTreeIter *iter)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	GSequence *sequence = child_sequence_for_tree (self, iter);
	return sequence ? g_sequence_get_length (sequence) : 0;
}

static gboolean
gcr_collection_model_real_iter_nth_child (GtkTreeModel *model,
                                          GtkTreeIter *iter,
                                          GtkTreeIter *parent,
                                          gint n)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	GSequence *sequence;
	GSequenceIter *seq;

	sequence = child_sequence_for_tree (self, parent);
	if (sequence == NULL)
		return FALSE;
	seq = g_sequence_get_iter_at_pos (sequence, n);
	return sequence_iter_to_tree (self, seq, iter);
}

static gboolean
gcr_collection_model_real_iter_parent (GtkTreeModel *model,
                                       GtkTreeIter *iter,
                                       GtkTreeIter *child)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (model);
	GSequenceIter *seq;
	GcrCollectionRow *row;

	seq = sequence_iter_for_tree (self, child);
	g_return_val_if_fail (seq != NULL, FALSE);
	row = g_sequence_get (seq);
	if (row->parent == NULL)
		return FALSE;
	return sequence_iter_to_tree (self, row->parent, iter);
}

static void
gcr_collection_model_real_ref_node (GtkTreeModel *model,
                                    GtkTreeIter *iter)
{
	/* Nothing to do */
}

static void
gcr_collection_model_real_unref_node (GtkTreeModel *model,
                                      GtkTreeIter *iter)
{
	/* Nothing to do */
}

static void
gcr_collection_model_tree_model_init (GtkTreeModelIface *iface)
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
collection_resort_sequence (GcrCollectionModel *self,
                            GSequenceIter *parent,
                            GSequence *sequence)
{
	GPtrArray *previous;
	GSequenceIter *seq, *next;
	gint *new_order;
	GtkTreePath *path;
	GtkTreeIter iter;
	GcrCollectionRow *row;
	gint index;
	gint i;

	/* Make note of how things stand, and at same time resort all kids */
	previous = g_ptr_array_new ();
	for (seq = g_sequence_get_begin_iter (sequence);
	     !g_sequence_iter_is_end (seq); seq = next) {
		next = g_sequence_iter_next (seq);
		row = g_sequence_get (seq);
		if (row->children)
			collection_resort_sequence (self, seq, row->children);
		g_ptr_array_add (previous, row->object);
	}

	/* Actually perform the sort */
	g_sequence_sort (sequence, self->pv->order_current, self);

	/* Now go through and map out how things changed */
	new_order = g_new0 (gint, previous->len);
	for (i = 0; i < previous->len; i++) {
		seq = g_hash_table_lookup (self->pv->object_to_seq, previous->pdata[i]);
		g_assert (seq != NULL);
		index = g_sequence_iter_get_position (seq);
		g_assert (index >= 0 && index < previous->len);
		new_order[index] = i;
	}

	g_ptr_array_free (previous, TRUE);

	path = sequence_iter_to_path (self, parent);
	if (parent == NULL) {
		gtk_tree_model_rows_reordered (GTK_TREE_MODEL (self), path, NULL, new_order);
	} else {
		if (!sequence_iter_to_tree (self, parent, &iter))
			g_assert_not_reached ();
		gtk_tree_model_rows_reordered (GTK_TREE_MODEL (self), path, &iter, new_order);
	}
	gtk_tree_path_free (path);
	g_free (new_order);
}

static gboolean
gcr_collection_model_get_sort_column_id (GtkTreeSortable *sortable,
                                         gint *sort_column_id,
                                         GtkSortType *order)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (sortable);

	if (order)
		*order = self->pv->sort_order_type;
	if (sort_column_id)
		*sort_column_id = self->pv->sort_column_id;
	return (self->pv->sort_column_id != GTK_TREE_SORTABLE_DEFAULT_SORT_COLUMN_ID &&
		self->pv->sort_column_id != GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID);
}

static void
gcr_collection_model_set_sort_column_id (GtkTreeSortable *sortable,
                                         gint sort_column_id,
                                         GtkSortType order)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (sortable);
	GCompareDataFunc func;
	gpointer argument;
	const GcrColumn *column;
	gboolean reverse;

	reverse = (order == GTK_SORT_DESCENDING);

	if (sort_column_id == GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID) {
		func = reverse ? order_sequence_as_unsorted_reverse : order_sequence_as_unsorted;
		argument = NULL;

	} else if (sort_column_id == GTK_TREE_SORTABLE_DEFAULT_SORT_COLUMN_ID) {
		func = reverse ? order_sequence_by_closure_reverse : order_sequence_by_closure;
		argument = &self->pv->default_sort_closure;

	} else if (sort_column_id >= 0 && sort_column_id < self->pv->n_columns) {
		if (self->pv->column_sort_closures[sort_column_id].sort_func) {
			func = reverse ? order_sequence_by_closure_reverse : order_sequence_by_closure;
			argument = &self->pv->column_sort_closures[sort_column_id];
		} else {
			column = &self->pv->columns[sort_column_id];
			if (!(column->flags & GCR_COLUMN_SORTABLE))
				return;
			if (!lookup_compare_func (column->property_type)) {
				g_warning ("no sort implementation defined for type '%s' on column '%s'",
				           g_type_name (column->property_type), column->property_name);
				return;
			}

			func = reverse ? order_sequence_by_property_reverse : order_sequence_by_property;
			argument = (gpointer)column;
		}
	} else {
		g_warning ("invalid sort_column_id passed to gtk_tree_sortable_set_sort_column_id(): %d",
		           sort_column_id);
		return;
	}

	if (sort_column_id != self->pv->sort_column_id ||
	    order != self->pv->sort_order_type) {
		self->pv->sort_column_id = sort_column_id;
		self->pv->sort_order_type = order;
		gtk_tree_sortable_sort_column_changed (sortable);
	}

	if (func != self->pv->order_current ||
	    argument != self->pv->order_argument) {
		self->pv->order_current = func;
		self->pv->order_argument = (gpointer)argument;
		collection_resort_sequence (self, NULL, self->pv->root_sequence);
	}
}

static void
clear_sort_closure (GcrCollectionSortClosure *closure)
{
	if (closure->destroy_func)
		(closure->destroy_func) (closure->user_data);
	closure->sort_func = NULL;
	closure->destroy_func = NULL;
	closure->user_data = NULL;
}

static void
set_sort_closure (GcrCollectionSortClosure *closure,
                  GtkTreeIterCompareFunc func,
                  gpointer data,
                  GDestroyNotify destroy)
{
	clear_sort_closure (closure);
	closure->sort_func = func;
	closure->user_data = data;
	closure->destroy_func = destroy;
}

static void
gcr_collection_model_set_sort_func (GtkTreeSortable *sortable,
                                    gint sort_column_id,
                                    GtkTreeIterCompareFunc func,
                                    gpointer data,
                                    GDestroyNotify destroy)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (sortable);

	g_return_if_fail (sort_column_id >= 0 && sort_column_id < self->pv->n_columns);

	set_sort_closure (&self->pv->column_sort_closures[sort_column_id],
	                  func, data, destroy);

	/* Resorts if necessary */
	if (self->pv->sort_column_id == sort_column_id) {
		gcr_collection_model_set_sort_column_id (sortable,
		                                         self->pv->sort_column_id,
		                                         self->pv->sort_order_type);
	}
}

static void
gcr_collection_model_set_default_sort_func (GtkTreeSortable *sortable,
                                            GtkTreeIterCompareFunc func,
                                            gpointer data, GDestroyNotify destroy)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (sortable);

	set_sort_closure (&self->pv->default_sort_closure,
	                  func, data, destroy);

	/* Resorts if necessary */
	if (self->pv->sort_column_id == GTK_TREE_SORTABLE_DEFAULT_SORT_COLUMN_ID) {
		gcr_collection_model_set_sort_column_id (sortable,
		                                         self->pv->sort_column_id,
		                                         self->pv->sort_order_type);
	}
}

static gboolean
gcr_collection_model_has_default_sort_func (GtkTreeSortable *sortable)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (sortable);

	return (self->pv->default_sort_closure.sort_func != NULL);
}

static void
gcr_collection_model_tree_sortable_init (GtkTreeSortableIface *iface)
{
	iface->get_sort_column_id = gcr_collection_model_get_sort_column_id;
	iface->set_sort_column_id = gcr_collection_model_set_sort_column_id;
	iface->set_sort_func = gcr_collection_model_set_sort_func;
	iface->set_default_sort_func = gcr_collection_model_set_default_sort_func;
	iface->has_default_sort_func = gcr_collection_model_has_default_sort_func;
}

static void
gcr_collection_model_init (GcrCollectionModel *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_COLLECTION_MODEL, GcrCollectionModelPrivate);

	self->pv->root_sequence = g_sequence_new (NULL);
	self->pv->object_to_seq = g_hash_table_new (g_direct_hash, g_direct_equal);
	self->pv->sort_column_id = GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID;
	self->pv->sort_order_type = GTK_SORT_ASCENDING;
	self->pv->order_current = order_sequence_as_unsorted;
}

static void
gcr_collection_model_set_property (GObject *object, guint prop_id,
                                   const GValue *value, GParamSpec *pspec)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (object);
	GcrColumn *columns;

	switch (prop_id) {
	case PROP_COLLECTION:
		g_return_if_fail (self->pv->collection == NULL);
		self->pv->collection = g_value_dup_object (value);

		/* During construction, so we don't emit anything */
		if (self->pv->collection) {
			add_children_to_sequence (self, self->pv->root_sequence,
			                          NULL, self->pv->collection, FALSE);
		}
		break;

	case PROP_COLUMNS:
		columns = g_value_get_pointer (value);
		if (columns)
			gcr_collection_model_set_columns (self, columns);
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

	case PROP_COLUMNS:
		g_value_set_pointer (value, (gpointer)self->pv->columns);
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

	/* Disconnect from all rows */
	if (self->pv->collection) {
		remove_children_from_sequence (self, self->pv->root_sequence,
		                               self->pv->collection, FALSE);
		g_object_unref (self->pv->collection);
		self->pv->collection = NULL;
	}

	G_OBJECT_CLASS (gcr_collection_model_parent_class)->dispose (object);
}

static void
gcr_collection_model_finalize (GObject *object)
{
	GcrCollectionModel *self = GCR_COLLECTION_MODEL (object);
	guint i;

	g_assert (!self->pv->collection);

	g_assert (g_sequence_get_length (self->pv->root_sequence) == 0);
	g_sequence_free (self->pv->root_sequence);
	g_assert (g_hash_table_size (self->pv->object_to_seq) == 0);
	g_hash_table_destroy (self->pv->object_to_seq);

	g_assert (g_hash_table_size (self->pv->selected) == 0);
	if (self->pv->selected)
		g_hash_table_destroy (self->pv->selected);
	self->pv->selected = NULL;

	self->pv->columns = NULL;
	for (i = 0; i < self->pv->n_columns; i++)
		clear_sort_closure (&self->pv->column_sort_closures[i]);
	g_free (self->pv->column_sort_closures);
	clear_sort_closure (&self->pv->default_sort_closure);

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

	g_object_class_install_property (gobject_class, PROP_COLUMNS,
		g_param_spec_pointer ("columns", "Columns", "Columns for the model",
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_type_class_add_private (klass, sizeof (GcrCollectionModelPrivate));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

/**
 * gcr_collection_model_new:
 * @collection: The collection to represent
 * @...: The column names and types.
 *
 * Create a new #GcrCollectionModel. The variable argument list should contain
 * pairs of property names, and #GType values. The variable argument list should
 * be terminated with %NULL.
 *
 * Returns: A newly allocated model, which should be released with g_object_unref().
 */
GcrCollectionModel*
gcr_collection_model_new (GcrCollection *collection, ...)
{
	GcrColumn column;
	GcrCollectionModel *self;
	const gchar *arg;
	GArray *array;
	va_list va;

	/* With a null terminator */
	array = g_array_new (TRUE, TRUE, sizeof (GcrColumn));

	va_start (va, collection);
	while ((arg = va_arg (va, const gchar*)) != NULL) {
		memset (&column, 0, sizeof (column));
		column.property_name = g_strdup (arg);
		column.property_type = va_arg (va, GType);
		column.column_type = column.property_type;
		g_array_append_val (array, column);
	}
	va_end (va);

	self = gcr_collection_model_new_full (collection, (GcrColumn*)array->data);
	g_object_set_data_full (G_OBJECT (self), "gcr_collection_model_new",
	                        g_array_free (array, FALSE), free_owned_columns);
	return self;
}

/**
 * gcr_collection_model_new_full:
 * @collection: The collection to represent
 * @columns: The columns the model should contain
 *
 * Create a new #GcrCollectionModel.
 *
 * Returns: A newly allocated model, which should be released with g_object_unref().
 */
GcrCollectionModel*
gcr_collection_model_new_full (GcrCollection *collection, const GcrColumn *columns)
{
	GcrCollectionModel *self = g_object_new (GCR_TYPE_COLLECTION_MODEL, "collection", collection, NULL);
	gcr_collection_model_set_columns (self, columns);
	return self;
}

/**
 * gcr_collection_model_set_columns:
 * @self: The model
 * @columns: The columns the model should contain
 *
 * Set the columns that the model should contain. @columns is an array of
 * #GcrColumn structures, with the last one containing %NULL for all values.
 *
 * This function can only be called once, and only if the model was not created
 * without a set of columns. This function cannot be called after the model
 * has been added to a view.
 *
 * The columns are accessed as static data. They should continue to remain
 * in memory for longer than the GcrCollectionModel object.
 */
void
gcr_collection_model_set_columns (GcrCollectionModel *self, const GcrColumn *columns)
{
	const GcrColumn *col;
	guint n_columns;

	g_return_if_fail (GCR_IS_COLLECTION_MODEL (self));
	g_return_if_fail (columns);
	g_return_if_fail (self->pv->n_columns == 0);

	/* Count the number of columns, extra column for selected */
	for (col = columns, n_columns = 1; col->property_name; ++col)
		++n_columns;

	/* We expect the columns to stay around */
	self->pv->columns = columns;
	self->pv->n_columns = n_columns;
	self->pv->column_sort_closures = g_new0 (GcrCollectionSortClosure, self->pv->n_columns);
}

/**
 * gcr_collection_model_object_for_iter:
 * @self: The model
 * @iter: The row
 *
 * Get the object that is represented by the given row in the model.
 *
 * Returns: The object, owned by the model.
 */
GObject*
gcr_collection_model_object_for_iter (GcrCollectionModel *self, const GtkTreeIter *iter)
{
	g_return_val_if_fail (GCR_IS_COLLECTION_MODEL (self), NULL);
	g_return_val_if_fail (iter, NULL);
	g_return_val_if_fail (iter->stamp == COLLECTION_MODEL_STAMP, NULL);
	g_return_val_if_fail (G_IS_OBJECT (iter->user_data), NULL);

	return G_OBJECT (iter->user_data);
}

/**
 * gcr_collection_model_iter_for_object:
 * @self: The model
 * @object: The object
 * @iter: The row for the object
 *
 * Set @iter to the row for the given object. If the object is not in this
 * model, then %FALSE will be returned.
 *
 * Returns: %TRUE if the object was present.
 */
gboolean
gcr_collection_model_iter_for_object (GcrCollectionModel *self, GObject *object,
                                      GtkTreeIter *iter)
{
	GSequenceIter *seq;

	g_return_val_if_fail (GCR_IS_COLLECTION_MODEL (self), FALSE);
	g_return_val_if_fail (G_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (iter, FALSE);

	seq = g_hash_table_lookup (self->pv->object_to_seq, object);
	if (seq == NULL)
		return FALSE;

	return sequence_iter_to_tree (self, seq, iter);
}

/**
 * gcr_collection_model_column_for_selected:
 * @self: The model
 *
 * Get the column identifier for the column that contains the values
 * of the selected state.
 *
 * Returns: The column identifier.
 */
gint
gcr_collection_model_column_for_selected (GcrCollectionModel *self)
{
	g_return_val_if_fail (GCR_IS_COLLECTION_MODEL (self), 0);
	g_assert (self->pv->n_columns > 0);
	return self->pv->n_columns - 1;
}

/**
 * gcr_collection_model_toggle_selected:
 * @self: The model
 * @iter: The row
 *
 * Toggle the selected state of a given row.
 */
void
gcr_collection_model_toggle_selected (GcrCollectionModel *self, GtkTreeIter *iter)
{
	GObject *object;

	g_return_if_fail (GCR_IS_COLLECTION_MODEL (self));

	object = gcr_collection_model_object_for_iter (self, iter);
	g_return_if_fail (G_IS_OBJECT (object));

	if (!self->pv->selected)
		self->pv->selected = selected_hash_table_new ();

	if (g_hash_table_lookup (self->pv->selected, object))
		g_hash_table_remove (self->pv->selected, object);
	else
		g_hash_table_insert (self->pv->selected, object, object);
}

/**
 * gcr_collection_model_change_selected:
 * @self: The model
 * @iter: The row
 * @selected: Whether the row should be selected or not.
 *
 * Set whether a given row is toggled selected or not.
 */
void
gcr_collection_model_change_selected (GcrCollectionModel *self, GtkTreeIter *iter, gboolean selected)
{
	GtkTreePath *path;
	GObject *object;

	g_return_if_fail (GCR_IS_COLLECTION_MODEL (self));

	object = gcr_collection_model_object_for_iter (self, iter);
	g_return_if_fail (G_IS_OBJECT (object));

	if (!self->pv->selected)
		self->pv->selected = g_hash_table_new (g_direct_hash, g_direct_equal);

	if (selected)
		g_hash_table_insert (self->pv->selected, object, object);
	else
		g_hash_table_remove (self->pv->selected, object);

	/* Tell the view that this row changed */
	path = gtk_tree_model_get_path (GTK_TREE_MODEL (self), iter);
	g_return_if_fail (path);
	gtk_tree_model_row_changed (GTK_TREE_MODEL (self), path, iter);
	gtk_tree_path_free (path);
}

/**
 * gcr_collection_model_is_selected:
 * @self: The model
 * @iter: The row
 *
 * Check whether a given row has been toggled as selected.
 *
 * Returns: Whether the row has been selected.
 */
gboolean
gcr_collection_model_is_selected (GcrCollectionModel *self, GtkTreeIter *iter)
{
	GObject *object;

	g_return_val_if_fail (GCR_IS_COLLECTION_MODEL (self), FALSE);

	object = gcr_collection_model_object_for_iter (self, iter);
	g_return_val_if_fail (G_IS_OBJECT (object), FALSE);

	if (!self->pv->selected)
		return FALSE;

	return g_hash_table_lookup (self->pv->selected, object) ? TRUE : FALSE;
}

GList*
gcr_collection_model_get_selected_objects (GcrCollectionModel *self)
{
	GHashTableIter iter;
	GList *result = NULL;
	gpointer key;

	g_return_val_if_fail (GCR_IS_COLLECTION_MODEL (self), NULL);

	if (!self->pv->selected)
		return NULL;

	g_hash_table_iter_init (&iter, self->pv->selected);
	while (g_hash_table_iter_next (&iter, &key, NULL))
		result = g_list_prepend (result, key);
	return result;
}

void
gcr_collection_model_set_selected_objects (GcrCollectionModel *self, GList *selected)
{
	GHashTable *newly_selected;
	GList *old_selection;
	GtkTreeIter iter;
	GList *l;

	old_selection = gcr_collection_model_get_selected_objects (self);
	newly_selected = selected_hash_table_new ();

	/* Select all the objects in selected which aren't already selected */
	for (l = selected; l; l = g_list_next (l)) {
		if (!self->pv->selected || !g_hash_table_lookup (self->pv->selected, l->data)) {
			if (!gcr_collection_model_iter_for_object (self, l->data, &iter))
				g_return_if_reached ();
			gcr_collection_model_change_selected (self, &iter, TRUE);
		}

		/* Note that we've seen this one */
		g_hash_table_insert (newly_selected, l->data, l->data);
	}

	/* Unselect all the objects which aren't supposed to be selected */
	for (l = old_selection; l; l = g_list_next (l)) {
		if (!g_hash_table_lookup (newly_selected, l->data)) {
			if (!gcr_collection_model_iter_for_object (self, l->data, &iter))
				g_return_if_reached ();
			gcr_collection_model_change_selected (self, &iter, FALSE);
		}
	}

	g_list_free (old_selection);
	g_hash_table_destroy (newly_selected);
}
