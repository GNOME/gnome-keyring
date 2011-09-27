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

#include "gcr-import-button.h"
#include "gcr-internal.h"
#include "gcr-marshal.h"
#include "gcr-parser.h"

#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_LABEL
};

/**
 * SECTION:gcr-import-button
 * @title: GcrImportButton
 * @short_description: Button which imports parsed certificates and keys
 *
 * A button which imports keys and certificates. Shows a spinner when the
 * button is activated. When more than one importer is available shows
 * a drop down to select which to import to.
 */

/**
 * GcrImportButton:
 *
 * Button which imports parsed certificates and keys.
 */

/**
 * GcrImportButtonClass:
 * @parent_class: The parent class
 * @imported: Emitted when the import completes, or fails.
 *
 * Class for #GcrImportButton.
 */

struct _GcrImportButtonPrivate {
	GList *queued;
	GList *importers;
	gboolean ready;
	gboolean created;
	gboolean importing;
	gchar *imported;
	GtkWidget *spinner;
	GtkWidget *arrow;
	GtkWidget *label;
	GCancellable *cancellable;
	GtkMenu *menu;
};

enum {
	IMPORTED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static GQuark QUARK_IMPORTER = 0;

G_DEFINE_TYPE (GcrImportButton, gcr_import_button, GTK_TYPE_BUTTON);

static void
gcr_import_button_init (GcrImportButton *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_IMPORT_BUTTON, GcrImportButtonPrivate);
	self->pv->cancellable = g_cancellable_new ();
	self->pv->label = gtk_label_new ("");
}

static void
update_import_button (GcrImportButton *self)
{
	gchar *message;
	gchar *label;

	/* Initializing, set a spinner */
	if (!self->pv->ready) {
		gtk_widget_show (self->pv->spinner);
		gtk_widget_hide (self->pv->arrow);
		gtk_widget_set_sensitive (GTK_WIDGET (self), FALSE);
		gtk_widget_set_tooltip_text (GTK_WIDGET (self), _("Initializing..."));

	/* Importing, set a spinner */
	} else if (self->pv->importing) {
		gtk_widget_show (self->pv->spinner);
		gtk_widget_hide (self->pv->arrow);
		gtk_widget_set_sensitive (GTK_WIDGET (self), FALSE);
		gtk_widget_set_tooltip_text (GTK_WIDGET (self), _("Import is in progress..."));

	} else if (self->pv->imported) {
		gtk_widget_hide (self->pv->spinner);
		gtk_widget_hide (self->pv->arrow);
		gtk_widget_set_sensitive (GTK_WIDGET (self), FALSE);
		message = g_strdup_printf (_("Imported to: %s"), self->pv->imported);
		gtk_widget_set_tooltip_text (GTK_WIDGET (self), message);
		g_free (message);

	/* Not importing, but have importers */
	} else if (self->pv->importers) {
		gtk_widget_hide (self->pv->spinner);
		gtk_widget_set_sensitive (GTK_WIDGET (self), TRUE);

		/* More than one importer */
		if (self->pv->importers->next) {
			gtk_widget_show (self->pv->arrow);
			gtk_widget_set_tooltip_text (GTK_WIDGET (self), NULL);

		/* Only one importer */
		} else {
			gtk_widget_hide (self->pv->arrow);
			g_object_get (self->pv->importers->data, "label", &label, NULL);
			message = g_strdup_printf (_("Import to: %s"), label);
			gtk_widget_set_tooltip_text (GTK_WIDGET (self), message);
			g_free (message);
			g_free (label);
		}

	/* No importers, none compatible */
	} else if (self->pv->created) {
		gtk_widget_hide (self->pv->spinner);
		gtk_widget_hide (self->pv->arrow);

		gtk_widget_set_sensitive (GTK_WIDGET (self), FALSE);
		gtk_widget_set_tooltip_text (GTK_WIDGET (self), _("Cannot import because there are no compatible importers"));

	/* No importers yet added */
	} else {
		gtk_widget_hide (self->pv->spinner);
		gtk_widget_hide (self->pv->arrow);

		gtk_widget_set_sensitive (GTK_WIDGET (self), FALSE);
		gtk_widget_set_tooltip_text (GTK_WIDGET (self), _("No data to import"));
	}
}

static void
on_library_pkcs11_ready (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (user_data);
	GList *queued, *l;

	self->pv->ready = TRUE;

	/* Process the parsed items that have been seen */
	queued = self->pv->queued;
	self->pv->queued = NULL;
	for (l = queued; l != NULL; l = g_list_next (l))
		gcr_import_button_add_parsed (self, l->data);
	g_assert (self->pv->queued == NULL);
	g_list_free_full (queued, gcr_parsed_unref);
}

static void
gcr_import_button_constructed (GObject *obj)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (obj);
	GtkWidget *grid;

	G_OBJECT_CLASS (gcr_import_button_parent_class)->constructed (obj);

	self->pv->spinner = gtk_spinner_new ();
	self->pv->arrow = gtk_arrow_new (GTK_ARROW_DOWN, GTK_SHADOW_NONE);
	grid = gtk_grid_new ();

	gtk_orientable_set_orientation (GTK_ORIENTABLE (grid), GTK_ORIENTATION_HORIZONTAL);
	gtk_container_add (GTK_CONTAINER (grid), self->pv->spinner);
	gtk_container_add (GTK_CONTAINER (grid), self->pv->label);
	gtk_container_add (GTK_CONTAINER (grid), self->pv->arrow);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 3);
	gtk_widget_set_hexpand (grid, TRUE);
	gtk_widget_set_halign (grid, GTK_ALIGN_CENTER);

	gtk_widget_show (self->pv->label);
	gtk_widget_show (grid);

	gtk_container_add (GTK_CONTAINER (self), grid);

	update_import_button (self);

	gcr_pkcs11_initialize_async (NULL, on_library_pkcs11_ready, g_object_ref (self));
}

static void
gcr_import_button_set_property (GObject *obj,
                                guint prop_id,
                                const GValue *value,
                                GParamSpec *pspec)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (obj);

	switch (prop_id) {
	case PROP_LABEL:
		gtk_label_set_label (GTK_LABEL (self->pv->label), g_value_get_string (value));
		g_object_notify (obj, "label");
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_import_button_get_property (GObject *obj,
                                guint prop_id,
                                GValue *value,
                                GParamSpec *pspec)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_set_string (value, gtk_label_get_label (GTK_LABEL (self->pv->label)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_import_button_dispose (GObject *obj)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (obj);

	gck_list_unref_free (self->pv->importers);
	self->pv->importers = NULL;
	g_cancellable_cancel (self->pv->cancellable);
	g_clear_object (&self->pv->menu);

	g_list_free_full (self->pv->queued, gcr_parsed_unref);
	self->pv->queued = NULL;

	G_OBJECT_CLASS (gcr_import_button_parent_class)->dispose (obj);
}

static void
gcr_import_button_finalize (GObject *obj)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (obj);

	g_object_unref (self->pv->cancellable);

	G_OBJECT_CLASS (gcr_import_button_parent_class)->finalize (obj);
}

static void
on_import_complete (GObject *importer,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (user_data);
	GError *error = NULL;

	g_return_if_fail (self->pv->imported == NULL);

	self->pv->importing = FALSE;

	gcr_importer_import_finish (GCR_IMPORTER (importer), result, &error);
	if (error == NULL) {
		g_object_get (importer, "label", &self->pv->imported, NULL);
		gck_list_unref_free (self->pv->importers);
		self->pv->importers = NULL;
	}

	g_signal_emit (self, signals[IMPORTED], 0, importer, error);
	g_clear_error (&error);

	update_import_button (self);
}

static void
begin_import (GcrImportButton *self,
              GcrImporter *importer)
{
	g_return_if_fail (self->pv->importing == FALSE);

	self->pv->importing = TRUE;
	g_free (self->pv->imported);
	self->pv->imported = NULL;

	gcr_importer_import_async (importer,
	                           self->pv->cancellable,
	                           on_import_complete,
	                           g_object_ref (self));
}

static void
on_importer_menu_activated (GtkMenuItem *menu_item,
                            gpointer user_data)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (user_data);
	GcrImporter *importer;

	importer = g_object_get_qdata (G_OBJECT (menu_item), QUARK_IMPORTER);
	g_return_if_fail (GCR_IMPORTER (importer));
	g_return_if_fail (self->pv->importing == FALSE);

	begin_import (self, importer);
	update_import_button (self);
}

static void
update_importer_menu (GcrImportButton *self)
{
	GtkWidget *menu_item;
	GtkWidget *image;
	GList *children, *l;
	GIcon *icon;
	gchar *label;

	if (!self->pv->menu) {
		self->pv->menu = GTK_MENU (gtk_menu_new ());
		g_object_ref_sink (self->pv->menu);
	}

	children = gtk_container_get_children (GTK_CONTAINER (self->pv->menu));
	for (l = children; l != NULL; l = g_list_next (l))
		gtk_container_remove (GTK_CONTAINER (self->pv->menu), l->data);
	g_list_free (children);

	for (l = self->pv->importers; l != NULL; l = g_list_next (l)) {
		g_object_get (l->data, "label", &label, "icon", &icon, NULL);
		menu_item = gtk_image_menu_item_new_with_label (label);
		g_signal_connect (menu_item, "activate", G_CALLBACK (on_importer_menu_activated), self);
		g_object_set_qdata (G_OBJECT (menu_item), QUARK_IMPORTER, l->data);
		image = gtk_image_new_from_gicon (icon, GTK_ICON_SIZE_MENU);
		gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (menu_item), image);
		gtk_image_menu_item_set_always_show_image (GTK_IMAGE_MENU_ITEM (menu_item), TRUE);
		gtk_widget_show (image);
		gtk_widget_show (menu_item);
		gtk_container_add (GTK_CONTAINER (self->pv->menu), menu_item);
		g_object_unref (icon);
		g_free (label);
	}
}

static void
on_menu_position (GtkMenu *menu,
                  gint *x,
                  gint *y,
                  gboolean *push_in,
                  gpointer user_data)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (user_data);
	GtkWidget *widget = GTK_WIDGET (self);
	GtkAllocation allocation;
	GtkRequisition menu_req;
	GdkRectangle monitor;
	GdkWindow *window;
	GtkWidget *toplevel;
	GdkScreen *screen;
	gint monitor_num;
	gint sx = 0;
	gint sy = 0;

	g_return_if_fail (x != NULL);
	g_return_if_fail (y != NULL);
	g_return_if_fail (push_in != NULL);

	gtk_widget_get_allocation (widget, &allocation);

	if (!gtk_widget_get_has_window (widget)) {
		sx += allocation.x;
		sy += allocation.y;
	}

	window = gtk_widget_get_window (widget);
	gdk_window_get_root_coords (window, sx, sy, &sx, &sy);

	gtk_widget_get_preferred_size (GTK_WIDGET (menu), NULL, &menu_req);
	if (gtk_widget_get_direction (widget) == GTK_TEXT_DIR_LTR)
		*x = sx;
	else
		*x = sx + allocation.width - menu_req.width;
	*y = sy;

	screen = gtk_widget_get_screen (widget);
	monitor_num = gdk_screen_get_monitor_at_window (screen, window);
	if (monitor_num < 0)
		monitor_num = 0;
	gdk_screen_get_monitor_geometry (screen, monitor_num, &monitor);

	if (*x < monitor.x)
		*x = monitor.x;
	else if (*x + menu_req.width > monitor.x + monitor.width)
		*x = monitor.x + monitor.width - menu_req.width;

	if (monitor.y + monitor.height - *y - allocation.height >= menu_req.height)
		*y += allocation.height;
	else if (*y - monitor.y >= menu_req.height)
		*y -= menu_req.height;
	else if (monitor.y + monitor.height - *y - allocation.height > *y - monitor.y)
		*y += allocation.height;
	else
		*y -= menu_req.height;

	gtk_menu_set_monitor (menu, monitor_num);

	toplevel = gtk_widget_get_parent (GTK_WIDGET (menu));
	if (GTK_IS_WINDOW (toplevel) && gtk_widget_get_visible (toplevel))
		gtk_window_set_type_hint (GTK_WINDOW (window), GDK_WINDOW_TYPE_HINT_DROPDOWN_MENU);

	*push_in = FALSE;
}

static void
gcr_import_button_clicked (GtkButton *button)
{
	GcrImportButton *self = GCR_IMPORT_BUTTON (button);

	g_return_if_fail (self->pv->importing == FALSE);
	g_return_if_fail (self->pv->importers != NULL);

	/* More than one importer, show the menu */
	if (self->pv->importers->next) {
		update_importer_menu (self);
		gtk_menu_popup (self->pv->menu, NULL, NULL, on_menu_position,
		                self, 1, gtk_get_current_event_time ());

	/* Only one importer, import on click */
	} else {
		begin_import (self, self->pv->importers->data);
	}

	update_import_button (self);
}

static void
gcr_import_button_class_init (GcrImportButtonClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GtkButtonClass *button_class = GTK_BUTTON_CLASS (klass);

	gobject_class->constructed = gcr_import_button_constructed;
	gobject_class->dispose = gcr_import_button_dispose;
	gobject_class->finalize = gcr_import_button_finalize;
	gobject_class->get_property = gcr_import_button_get_property;
	gobject_class->set_property = gcr_import_button_set_property;

	button_class->clicked = gcr_import_button_clicked;

	g_object_class_override_property (gobject_class, PROP_LABEL, "label");

	/**
	 * GcrImportButton::imported:
	 * @self: the import button
	 * @importer: the importer that was imported to
	 * @error: if import was successful %NULL, or an error
	 *
	 * Signal emitted when an import completes or fails.
	 */
	signals[IMPORTED] = g_signal_new ("imported", GCR_TYPE_IMPORT_BUTTON, G_SIGNAL_RUN_LAST,
	                                  G_STRUCT_OFFSET (GcrImportButtonClass, imported),
	                                  NULL, NULL, _gcr_marshal_VOID__OBJECT_BOXED,
	                                  G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_ERROR);

	QUARK_IMPORTER = g_quark_from_static_string ("gcr-import-button-importer");

	g_type_class_add_private (klass, sizeof (GcrImportButtonPrivate));
}

GcrImportButton*
gcr_import_button_new (const gchar *label)
{
	return g_object_new (GCR_TYPE_IMPORT_BUTTON,
	                     "label", label,
	                     NULL);
}

void
gcr_import_button_add_parsed (GcrImportButton *self,
                              GcrParsed *parsed)
{
	GList *importers;

	g_return_if_fail (GCR_IS_IMPORT_BUTTON (self));
	g_return_if_fail (parsed != NULL);

	if (!self->pv->ready) {
		self->pv->queued = g_list_prepend (self->pv->queued, gcr_parsed_ref (parsed));
		return;
	}

	g_free (self->pv->imported);
	self->pv->imported = NULL;

	if (self->pv->created) {
		importers = gcr_importer_queue_and_filter_for_parsed (self->pv->importers, parsed);
	} else {
		importers = gcr_importer_create_for_parsed (parsed);
		self->pv->created = TRUE;
	}

	gck_list_unref_free (self->pv->importers);
	self->pv->importers = importers;

	update_import_button (self);
}
