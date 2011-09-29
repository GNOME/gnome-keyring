/*
 * Copyright (C) 2011 Alexander Larsson <alexl@redhat.com>
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gcr-menu-button.h"

enum {
	PROP_0,
	PROP_LABEL,
	PROP_MENU
};

struct _GcrMenuButtonPrivate {
	GtkMenu *menu;
	gboolean popup_in_progress;
	gchar *label;
};

G_DEFINE_TYPE (GcrMenuButton, _gcr_menu_button, GTK_TYPE_TOGGLE_BUTTON);

static void
_gcr_menu_button_init (GcrMenuButton *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_MENU_BUTTON,
	                                         GcrMenuButtonPrivate));
}

static void
_gcr_menu_button_constructed (GObject *obj)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (obj);
	GtkWidget *label_widget;
	GtkWidget *arrow;
	GtkWidget *grid;

	G_OBJECT_CLASS (_gcr_menu_button_parent_class)->constructed (obj);

	gtk_button_set_focus_on_click (GTK_BUTTON (self), FALSE);

	label_widget = gtk_label_new (self->pv->label);
	arrow = gtk_arrow_new (GTK_ARROW_DOWN, GTK_SHADOW_NONE);
	grid = gtk_grid_new ();

	gtk_orientable_set_orientation (GTK_ORIENTABLE (grid), GTK_ORIENTATION_HORIZONTAL);
	gtk_container_add (GTK_CONTAINER (grid), label_widget);
	gtk_container_add (GTK_CONTAINER (grid), arrow);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 3);
	gtk_widget_set_hexpand (grid, TRUE);
	gtk_widget_set_halign (grid, GTK_ALIGN_CENTER);

	gtk_container_add (GTK_CONTAINER (self), grid);
}

static void
_gcr_menu_button_get_property (GObject *obj,
                               guint prop_id,
                               GValue *value,
                               GParamSpec *pspec)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (obj);

	switch (prop_id) {
	case PROP_MENU:
		g_value_set_object (value, _gcr_menu_button_get_menu (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_menu_button_set_property (GObject *obj,
                               guint prop_id,
                               const GValue *value,
                               GParamSpec *pspec)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (obj);

	switch (prop_id) {
	case PROP_LABEL:
		self->pv->label = g_value_dup_string (value);
		break;
	case PROP_MENU:
		_gcr_menu_button_set_menu (self, g_value_get_object (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_menu_button_finalize (GObject *obj)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (obj);

	_gcr_menu_button_set_menu (self, NULL);
	g_free (self->pv->label);

	G_OBJECT_CLASS (_gcr_menu_button_parent_class)->finalize (obj);
}


static void
on_menu_position (GtkMenu *menu,
                  gint *x,
                  gint *y,
                  gboolean *push_in,
                  gpointer user_data)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (user_data);
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
_gcr_menu_button_toggled (GtkToggleButton *togglebutton)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (togglebutton);
	GtkStyleContext *context;

	context = gtk_widget_get_style_context (GTK_WIDGET (self));
	if (gtk_toggle_button_get_active (togglebutton)) {
		if (!self->pv->popup_in_progress)
			gtk_menu_popup (self->pv->menu, NULL, NULL,
			                on_menu_position, self, 1,
			                gtk_get_current_event_time ());
		gtk_style_context_add_class (context, GTK_STYLE_CLASS_MENUBAR);
		gtk_style_context_add_class (context, GTK_STYLE_CLASS_MENUITEM);
	} else {
		gtk_style_context_remove_class (context, GTK_STYLE_CLASS_MENUBAR);
		gtk_style_context_remove_class (context, GTK_STYLE_CLASS_MENUITEM);
		gtk_menu_popdown (self->pv->menu);
	}

	gtk_widget_reset_style (GTK_WIDGET (self));
}

static gboolean
_gcr_menu_button_press_event (GtkWidget *widget,
                              GdkEventButton *event)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (widget);
	GtkWidget *ewidget;

	ewidget = gtk_get_event_widget ((GdkEvent *)event);
	if (ewidget != widget || gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		return FALSE;

	gtk_menu_popup (self->pv->menu, NULL, NULL, on_menu_position, self,
	                1, gtk_get_current_event_time ());
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	self->pv->popup_in_progress = TRUE;
	return TRUE;
}

static gboolean
_gcr_menu_button_release_event (GtkWidget *widget,
                                GdkEventButton *event)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (widget);
	gboolean popup_in_progress_saved;
	GtkWidget *ewidget;

	popup_in_progress_saved = self->pv->popup_in_progress;
	self->pv->popup_in_progress = FALSE;

	ewidget = gtk_get_event_widget ((GdkEvent *)event);

	if (ewidget == widget && !popup_in_progress_saved &&
	    gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		gtk_menu_popdown (self->pv->menu);
		return TRUE;
	}

	if (ewidget != widget) {
		gtk_menu_popdown (self->pv->menu);
		return TRUE;
	}

	return FALSE;
}

static gboolean
_gcr_menu_button_draw (GtkWidget *widget,
                       cairo_t *cr)
{
	GTK_WIDGET_GET_CLASS (widget)->draw (widget, cr);
	return FALSE;
}

static void
_gcr_menu_button_class_init (GcrMenuButtonClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GtkToggleButtonClass *toggle_class = GTK_TOGGLE_BUTTON_CLASS (klass);
	GtkWidgetClass *widget_class  = GTK_WIDGET_CLASS (klass);

	gobject_class->constructed = _gcr_menu_button_constructed;
	gobject_class->get_property = _gcr_menu_button_get_property;
	gobject_class->set_property = _gcr_menu_button_set_property;
	gobject_class->finalize = _gcr_menu_button_finalize;

	widget_class->button_press_event = _gcr_menu_button_press_event;
	widget_class->button_release_event = _gcr_menu_button_release_event;
	widget_class->draw = _gcr_menu_button_draw;

	toggle_class->toggled = _gcr_menu_button_toggled;

	g_type_class_add_private (klass, sizeof (GcrMenuButtonPrivate));

	g_object_class_install_property (gobject_class, PROP_LABEL,
	           g_param_spec_string ("label", "Label", "Label for the button",
	                                "", G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_MENU,
	           g_param_spec_object ("menu", "Menu", "Menu for the button",
	                                GTK_TYPE_MENU, G_PARAM_READWRITE));

}

/**
 * _gcr_menu_button_new:
 * @label: (allow-none): the label
 *
 * Returns: (transfer full) (type Gcr.MenuButton): the new menu button
 */
GtkWidget *
_gcr_menu_button_new (const gchar *label)
{
	return g_object_new (GCR_TYPE_MENU_BUTTON,
	                     "label", label,
	                     NULL);
}

static void
on_menu_show (GtkWidget *menu,
              gpointer user_data)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (user_data);
	self->pv->popup_in_progress = TRUE;
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self), TRUE);
	self->pv->popup_in_progress = FALSE;
}

static void
on_menu_hide (GtkWidget *menu,
              gpointer user_data)
{
	GcrMenuButton *self = GCR_MENU_BUTTON (user_data);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self), FALSE);
}

static void
on_menu_detach (GtkWidget *attach_widget,
                GtkMenu *menu)
{

}

GtkMenu *
_gcr_menu_button_get_menu (GcrMenuButton *self)
{
	g_return_val_if_fail (GCR_IS_MENU_BUTTON (self), NULL);
	return self->pv->menu;
}

void
_gcr_menu_button_set_menu (GcrMenuButton *self,
                           GtkMenu *menu)
{
	g_return_if_fail (GCR_IS_MENU_BUTTON (self));
	g_return_if_fail (menu == NULL || GTK_IS_MENU (menu));

	if (menu == self->pv->menu)
		return;

	if (self->pv->menu != NULL) {
		g_signal_handlers_disconnect_by_func (self->pv->menu, on_menu_show, self);
		g_signal_handlers_disconnect_by_func (self->pv->menu, on_menu_hide, self);
		gtk_menu_detach (self->pv->menu);
		g_object_unref (self->pv->menu);
	}

	self->pv->menu = menu;

	if (self->pv->menu != NULL) {
		g_object_ref (self->pv->menu);
		g_signal_connect (self->pv->menu, "show", G_CALLBACK (on_menu_show), self);
		g_signal_connect (self->pv->menu, "hide", G_CALLBACK (on_menu_hide), self);
		gtk_menu_attach_to_widget (self->pv->menu, GTK_WIDGET (self), on_menu_detach);
	}

	g_object_notify (G_OBJECT (self), "menu");
}
