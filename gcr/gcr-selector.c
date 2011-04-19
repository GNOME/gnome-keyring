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

#include "gcr-collection-model.h"
#include "gcr-internal.h"
#include "gcr-selector.h"

#include <string.h>

/**
 * SECTION:gcr-selector
 * @title: GcrSelector
 * @short_description: A selector widget to select certificates or keys.
 *
 * The #GcrSelector can be used to select certificates or keys. The selector
 * comes in one of two modes: %GCR_SELECTOR_MODE_SINGLE and
 * %GCR_SELECTOR_MODE_MULTIPLE. The single selector mode allows the user to
 * select one object at a time, and the multiple selector allows the user
 * to select multiple objects from a list.
 */

/**
 * GcrSelector:
 *
 * A selector widget.
 */

/**
 * GcrSelectorClass:
 *
 * The class for #GcrSelector.
 */

/**
 * GcrSelectorMode:
 * @GCR_SELECTOR_MODE_SINGLE: User can select a single object.
 * @GCR_SELECTOR_MODE_MULTIPLE: The user can select multiple objects.
 *
 * The mode for the selector.
 */

enum {
	PROP_0,
	PROP_COLLECTION,
	PROP_COLUMNS,
	PROP_MODE
};

struct _GcrSelector {
	GtkAlignment parent;

	/*< private >*/
	GcrSelectorPrivate *pv;
};

struct _GcrSelectorClass {
	/*< private >*/
	GtkAlignmentClass parent_class;
};

struct _GcrSelectorPrivate {
	GtkComboBox *combo;
	GtkTreeView *tree;
	GcrCollection *collection;
	const GcrColumn *columns;
	GtkTreeModel *sort;
	GcrCollectionModel *model;
	GcrSelectorMode mode;
};

G_DEFINE_TYPE (GcrSelector, gcr_selector, GTK_TYPE_ALIGNMENT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
on_check_column_toggled (GtkCellRendererToggle *cell, gchar *path, GcrCollectionModel *model)
{
	GtkTreeIter iter;

	g_assert (path != NULL);

	if (gtk_tree_model_get_iter_from_string (GTK_TREE_MODEL (model), &iter, path))
		gcr_collection_model_toggle_selected (model, &iter);
}

typedef gint (*SortFunc) (GValue *, GValue *);

static gint
sort_string (GValue *val_a, GValue *val_b)
{
	const gchar *str_a = g_value_get_string (val_a);
	const gchar *str_b = g_value_get_string (val_b);

	if (str_a == str_b)
		return 0;
	else if (!str_a)
		return -1;
	else if (!str_b)
		return 1;
	else
		return g_utf8_collate (str_a, str_b);
}

static gint
sort_date (GValue *val_a, GValue *val_b)
{
	GDate *date_a = g_value_get_boxed (val_a);
	GDate *date_b = g_value_get_boxed (val_b);

	if (date_a == date_b)
		return 0;
	else if (!date_a)
		return -1;
	else if (!date_b)
		return 1;
	else
		return g_date_compare (date_a, date_b);
}

static inline SortFunc
sort_implementation_for_type (GType type)
{
	if (type == G_TYPE_STRING)
		return sort_string;
	else if (type == G_TYPE_DATE)
		return sort_date;
	else
		return NULL;
}

static gint
on_sort_column (GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b,
                gpointer user_data)
{
	GcrColumn *column = user_data;
	SortFunc func;
	GObject *object_a;
	GObject *object_b;
	GValue val_a;
	GValue val_b;
	gint ret;

	object_a = gcr_collection_model_object_for_iter (GCR_COLLECTION_MODEL (model), a);
	g_return_val_if_fail (G_IS_OBJECT (object_a), 0);
	object_b = gcr_collection_model_object_for_iter (GCR_COLLECTION_MODEL (model), b);
	g_return_val_if_fail (G_IS_OBJECT (object_b), 0);

	memset (&val_a, 0, sizeof (val_a));
	memset (&val_b, 0, sizeof (val_b));

	g_value_init (&val_a, column->property_type);
	g_value_init (&val_b, column->property_type);

	g_object_get_property (object_a, column->property_name, &val_a);
	g_object_get_property (object_b, column->property_name, &val_b);

	func = sort_implementation_for_type (column->property_type);
	g_return_val_if_fail (func, 0);

	ret = (func) (&val_a, &val_b);

	g_value_unset (&val_a);
	g_value_unset (&val_b);

	return ret;
}

static void
add_string_column (GcrSelector *self, const GcrColumn *column, gint column_id)
{
	GtkCellRenderer *cell;
	GtkTreeViewColumn *col;

	g_assert (column->column_type == G_TYPE_STRING);
	g_assert (!(column->flags & GCR_COLUMN_HIDDEN));

	cell = gtk_cell_renderer_text_new ();
	g_object_set (G_OBJECT (cell), "ellipsize", PANGO_ELLIPSIZE_END, NULL);
	col = gtk_tree_view_column_new_with_attributes (column->label, cell, "text", column_id, NULL);
	gtk_tree_view_column_set_resizable (col, TRUE);
	if (column->flags & GCR_COLUMN_SORTABLE)
		gtk_tree_view_column_set_sort_column_id (col, column_id);
	gtk_tree_view_append_column (self->pv->tree, col);
}

static void
add_icon_column (GcrSelector *self, const GcrColumn *column, gint column_id)
{
	GtkCellRenderer *cell;
	GtkTreeViewColumn *col;

	g_assert (column->column_type == G_TYPE_ICON);
	g_assert (!(column->flags & GCR_COLUMN_HIDDEN));

	cell = gtk_cell_renderer_pixbuf_new ();
	g_object_set (cell, "stock-size", GTK_ICON_SIZE_BUTTON, NULL);
	col = gtk_tree_view_column_new_with_attributes (column->label, cell, "gicon", column_id, NULL);
	gtk_tree_view_column_set_resizable (col, TRUE);
	if (column->flags & GCR_COLUMN_SORTABLE)
		gtk_tree_view_column_set_sort_column_id (col, column_id);
	gtk_tree_view_append_column (self->pv->tree, col);
}

static void
add_check_column (GcrSelector *self, guint column_id)
{
	GtkCellRenderer *cell;
	GtkTreeViewColumn *col;

	cell = gtk_cell_renderer_toggle_new ();
	g_signal_connect (cell, "toggled", G_CALLBACK (on_check_column_toggled), self->pv->model);

	col = gtk_tree_view_column_new_with_attributes ("", cell, "active", column_id, NULL);
	gtk_tree_view_column_set_resizable (col, FALSE);
	gtk_tree_view_append_column (self->pv->tree, col);
}

static void
construct_single_selector (GcrSelector *self)
{
	GtkCellRenderer *cell;
	GtkWidget *widget;

	self->pv->model = gcr_collection_model_new (self->pv->collection,
	                                            "icon", G_TYPE_ICON,
	                                            "markup", G_TYPE_STRING,
	                                            NULL);

	widget = gtk_combo_box_new_with_model (GTK_TREE_MODEL (self->pv->model));
	self->pv->combo = GTK_COMBO_BOX (widget);

	/* The icon */
	cell = gtk_cell_renderer_pixbuf_new ();
	g_object_set (cell, "stock-size", GTK_ICON_SIZE_DND, NULL);
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (widget), cell, FALSE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (widget), cell, "gicon", 0);

	/* The markup */
	cell = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (widget), cell, TRUE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (widget), cell, "markup", 1);

	gtk_widget_show (widget);
	gtk_container_add (GTK_CONTAINER (self), widget);
}

static void
construct_multiple_selector (GcrSelector *self)
{
	const GcrColumn *column;
	GtkWidget *widget, *scroll;
	GtkTreeSortable *sortable;
	guint i;

	self->pv->model = gcr_collection_model_new_full (self->pv->collection,
	                                                 self->pv->columns);

	self->pv->sort = gtk_tree_model_sort_new_with_model (GTK_TREE_MODEL (self->pv->model));
	sortable = GTK_TREE_SORTABLE (self->pv->sort);

	widget = gtk_tree_view_new_with_model (GTK_TREE_MODEL (self->pv->sort));
	self->pv->tree = GTK_TREE_VIEW (widget);

	/* First add the check mark column */
	add_check_column (self, gcr_collection_model_column_for_selected (self->pv->model));

	for (column = self->pv->columns, i = 0; column->property_name; ++column, ++i) {
		if (column->flags & GCR_COLUMN_HIDDEN)
			continue;

		if (column->column_type == G_TYPE_STRING)
			add_string_column (self, column, i);
		else if (column->column_type == G_TYPE_ICON)
			add_icon_column (self, column, i);
		else
			g_warning ("skipping unsupported column '%s' of type: %s",
			           column->property_name, g_type_name (column->column_type));

		/* Setup the column itself */
		if (column->flags & GCR_COLUMN_SORTABLE) {
			if (sort_implementation_for_type (column->property_type))
				gtk_tree_sortable_set_sort_func (sortable, i, on_sort_column,
				                                 (gpointer)column, NULL);
			else
				g_warning ("no sort implementation defined for type '%s' on column '%s'",
				           g_type_name (column->property_type), column->property_name);
		}
	}

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), widget);
	gtk_container_add (GTK_CONTAINER (self), scroll);

	gtk_widget_show_all (scroll);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

GType
gcr_selector_mode_get_type (void)
{
	static GType type = 0;
	static GEnumValue values[] = {
		{ GCR_SELECTOR_MODE_SINGLE, "single", "Single"},
		{ GCR_SELECTOR_MODE_MULTIPLE, "multiple", "Multiple"},
		{ 0, NULL, NULL }
	};
	if (!type)
		type = g_enum_register_static ("GcrSelectorMode", values);
	return type;
}

static GObject*
gcr_selector_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GcrSelector *self = GCR_SELECTOR (G_OBJECT_CLASS (gcr_selector_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);

	g_return_val_if_fail (self->pv->columns, NULL);

	switch (self->pv->mode) {
	case GCR_SELECTOR_MODE_SINGLE:
		construct_single_selector (self);
		break;
	case GCR_SELECTOR_MODE_MULTIPLE:
		construct_multiple_selector (self);
		break;
	default:
		g_assert_not_reached ();
		break;
	}

	return G_OBJECT (self);
}

static void
gcr_selector_init (GcrSelector *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_SELECTOR, GcrSelectorPrivate);
}

static void
gcr_selector_dispose (GObject *obj)
{
	GcrSelector *self = GCR_SELECTOR (obj);

	if (self->pv->model)
		g_object_unref (self->pv->model);
	self->pv->model = NULL;

	if (self->pv->collection)
		g_object_unref (self->pv->collection);
	self->pv->collection = NULL;

	if (self->pv->sort)
		g_object_unref (self->pv->sort);
	self->pv->sort = NULL;

	G_OBJECT_CLASS (gcr_selector_parent_class)->dispose (obj);
}

static void
gcr_selector_finalize (GObject *obj)
{
	GcrSelector *self = GCR_SELECTOR (obj);

	g_assert (!self->pv->collection);
	g_assert (!self->pv->model);
	self->pv->combo = NULL;
	self->pv->tree = NULL;

	G_OBJECT_CLASS (gcr_selector_parent_class)->finalize (obj);
}

static void
gcr_selector_set_property (GObject *obj, guint prop_id, const GValue *value,
                           GParamSpec *pspec)
{
	GcrSelector *self = GCR_SELECTOR (obj);
	switch (prop_id) {
	case PROP_COLLECTION:
		g_return_if_fail (!self->pv->collection);
		self->pv->collection = g_value_dup_object (value);
		g_return_if_fail (self->pv->collection);
		break;
	case PROP_COLUMNS:
		g_return_if_fail (!self->pv->columns);
		self->pv->columns = g_value_get_pointer (value);
		g_return_if_fail (self->pv->columns);
		break;
	case PROP_MODE:
		self->pv->mode = g_value_get_enum (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_selector_get_property (GObject *obj, guint prop_id, GValue *value,
                         GParamSpec *pspec)
{
	GcrSelector *self = GCR_SELECTOR (obj);

	switch (prop_id) {
	case PROP_COLLECTION:
		g_value_set_object (value, gcr_selector_get_collection (self));
		break;
	case PROP_COLUMNS:
		g_value_set_pointer (value, (gpointer)gcr_selector_get_columns (self));
		break;
	case PROP_MODE:
		g_value_set_enum (value, gcr_selector_get_mode (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_selector_class_init (GcrSelectorClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gcr_selector_constructor;
	gobject_class->dispose = gcr_selector_dispose;
	gobject_class->finalize = gcr_selector_finalize;
	gobject_class->set_property = gcr_selector_set_property;
	gobject_class->get_property = gcr_selector_get_property;

	g_type_class_add_private (gobject_class, sizeof (GcrSelectorPrivate));

	/**
	 * GcrSelector:collection:
	 *
	 * The collection which contains the objects to display in the selector.
	 */
	g_object_class_install_property (gobject_class, PROP_COLLECTION,
	           g_param_spec_object ("collection", "Collection", "Collection to select from",
	                                GCR_TYPE_COLLECTION, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/**
	 * GcrSelector:columns:
	 *
	 * The columns to use to display the objects.
	 */
	g_object_class_install_property (gobject_class, PROP_COLUMNS,
	           g_param_spec_pointer ("columns", "Columns", "Columns to display in multiple selector",
	                                 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/**
	 * GcrSelector:mode:
	 *
	 * The mode of the selector.
	 */
	g_object_class_install_property (gobject_class, PROP_MODE,
	           g_param_spec_enum ("mode", "Mode", "The mode of the selector",
	                              GCR_TYPE_SELECTOR_MODE, GCR_SELECTOR_MODE_SINGLE,
	                              G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	_gcr_initialize ();
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

/**
 * gcr_selector_new:
 * @collection: The collection that contains the objects to display
 * @columns: The columns to use to display the objects
 * @mode: The mode of the selector
 *
 * Create a new #GcrSelector.
 *
 * Returns: A newly allocated selector, which should be released with
 *     g_object_unref().
 */
GcrSelector*
gcr_selector_new (GcrCollection *collection, const GcrColumn *columns, GcrSelectorMode mode)
{
	return g_object_new (GCR_TYPE_SELECTOR,
	                     "collection", collection,
	                     "columns", columns,
	                     "mode", mode,
	                     NULL);
}

/**
 * gcr_selector_get_collection:
 * @self: The selector
 *
 * Get the collection that this selector is displaying objects from.
 *
 * Returns: The collection, owned by the selector.
 */
GcrCollection*
gcr_selector_get_collection (GcrSelector *self)
{
	g_return_val_if_fail (GCR_IS_SELECTOR (self), NULL);
	return self->pv->collection;
}

/**
 * gcr_selector_get_columns:
 * @self: The selector
 *
 * Get the columns displayed in a selector in multiple mode.
 *
 * Returns: The columns, owned by the selector.
 */
const GcrColumn*
gcr_selector_get_columns (GcrSelector *self)
{
	g_return_val_if_fail (GCR_IS_SELECTOR (self), NULL);
	return self->pv->columns;
}

/**
 * gcr_selector_get_mode:
 * @self: The selector
 *
 * Get the mode of the selector, whether single or multiple selection.
 *
 * Returns: The mode of the selector.
 */
GcrSelectorMode
gcr_selector_get_mode (GcrSelector *self)
{
	g_return_val_if_fail (GCR_IS_SELECTOR (self), 0);
	return self->pv->mode;
}
