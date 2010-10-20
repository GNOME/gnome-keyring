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

enum {
	PROP_0,
	PROP_COLLECTION,
	PROP_COLUMNS,
	PROP_MODE
};

#if 0
enum {
	XXXX,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };
#endif

struct _GcrSelectorPrivate {
	GtkComboBox *combo;
	GtkTreeView *tree;
	GcrCollection *collection;
	const GcrColumn *columns;
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

static void
add_string_column (GcrSelector *self, const GcrColumn *column, guint index)
{
	GtkCellRenderer *cell;
	GtkTreeViewColumn *col;

	g_assert (column->type == G_TYPE_STRING);

	cell = gtk_cell_renderer_text_new ();
	g_object_set (G_OBJECT (cell), "ellipsize", PANGO_ELLIPSIZE_END, NULL);
	col = gtk_tree_view_column_new_with_attributes (column->label, cell, "text", index, NULL);
	gtk_tree_view_column_set_resizable (col, TRUE);
	gtk_tree_view_append_column (self->pv->tree, col);
}

static void
add_icon_column (GcrSelector *self, const GcrColumn *column, guint index)
{
	GtkCellRenderer *cell;
	GtkTreeViewColumn *col;

	g_assert (column->type == G_TYPE_ICON);

	cell = gtk_cell_renderer_pixbuf_new ();
	g_object_set (cell, "stock-size", GTK_ICON_SIZE_BUTTON, NULL);
	col = gtk_tree_view_column_new_with_attributes (column->label, cell, "gicon", index, NULL);
	gtk_tree_view_column_set_resizable (col, TRUE);
	gtk_tree_view_append_column (self->pv->tree, col);
}

static void
add_check_column (GcrSelector *self, guint index)
{
	GtkCellRenderer *cell;
	GtkTreeViewColumn *col;

	cell = gtk_cell_renderer_toggle_new ();
	g_signal_connect (cell, "toggled", G_CALLBACK (on_check_column_toggled), self->pv->model);

	col = gtk_tree_view_column_new_with_attributes ("", cell, "active", index, NULL);
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
	guint i;

	self->pv->model = gcr_collection_model_new_full (self->pv->collection,
	                                                 self->pv->columns);

	widget = gtk_tree_view_new_with_model (GTK_TREE_MODEL (self->pv->model));
	self->pv->tree = GTK_TREE_VIEW (widget);

	/* First add the check mark column */
	add_check_column (self, gcr_collection_model_column_selected (self->pv->model));

	for (column = self->pv->columns, i = 0; column->property; ++column, ++i) {
		if (column->type == G_TYPE_STRING)
			add_string_column (self, column, i);
		else if (column->type == G_TYPE_ICON)
			add_icon_column (self, column, i);
		else {
			g_warning ("skipping unsupported column '%s' of type: %s",
			           column->label, g_type_name (column->type));
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

	g_object_class_install_property (gobject_class, PROP_COLLECTION,
	           g_param_spec_object ("collection", "Collection", "Collection to select from",
	                                GCR_TYPE_COLLECTION, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_COLUMNS,
	           g_param_spec_pointer ("columns", "Columns", "Columns to display in multiple selector",
	                                 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_MODE,
	           g_param_spec_enum ("mode", "Mode", "The mode of the selector",
	                              GCR_TYPE_SELECTOR_MODE, GCR_SELECTOR_MODE_SINGLE,
	                              G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	_gcr_initialize ();
}

/* -----------------------------------------------------------------------------
 * PUBLIC
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

GcrCollection*
gcr_selector_get_collection (GcrSelector *self)
{
	g_return_val_if_fail (GCR_IS_SELECTOR (self), NULL);
	return self->pv->collection;
}

const GcrColumn*
gcr_selector_get_columns (GcrSelector *self)
{
	g_return_val_if_fail (GCR_IS_SELECTOR (self), NULL);
	return self->pv->columns;
}

GcrSelectorMode
gcr_selector_get_mode (GcrSelector *self)
{
	g_return_val_if_fail (GCR_IS_SELECTOR (self), 0);
	return self->pv->mode;
}
