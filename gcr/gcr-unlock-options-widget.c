/*
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

#include "gcr-unlock-options-widget.h"

#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_UNLOCK_TIMEOUT,
	PROP_UNLOCK_IDLE
};

struct _GcrUnlockOptionsWidgetPrivate {
	GtkBuilder *builder;
	GtkToggleButton *lock_logout;
	GtkToggleButton *lock_after;
	GtkToggleButton *lock_idle;
	GtkSpinButton *spin_minutes;
};

G_DEFINE_TYPE (GcrUnlockOptionsWidget, gcr_unlock_options_widget, GTK_TYPE_ALIGNMENT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static GtkToggleButton*
builder_get_toggle_button (GtkBuilder *builder, const gchar *name)
{
	GObject *object = gtk_builder_get_object (builder, name);
	g_return_val_if_fail (GTK_IS_TOGGLE_BUTTON (object), NULL);
	return GTK_TOGGLE_BUTTON (object);
}

static GtkSpinButton*
builder_get_spin_button (GtkBuilder *builder, const gchar *name)
{
	GObject *object = gtk_builder_get_object (builder, name);
	g_return_val_if_fail (GTK_IS_SPIN_BUTTON (object), NULL);
	return GTK_SPIN_BUTTON (object);
}

static void
on_timeout_choices_toggled (GtkToggleButton *unused, GtkBuilder *builder)
{
	GtkWidget *spin;
	GtkToggleButton *after, *idle;

	spin = GTK_WIDGET (gtk_builder_get_object (builder, "lock_minutes_spin"));
	after = builder_get_toggle_button (builder, "lock_after_choice");
	idle = builder_get_toggle_button (builder, "lock_idle_choice");
	gtk_widget_set_sensitive (spin, gtk_toggle_button_get_active (after) ||
	                                gtk_toggle_button_get_active (idle));

}

static const gchar*
widget_name_for_option (guint option)
{
	switch (option) {
	case GCR_UNLOCK_OPTION_SESSION:
		return "lock_logout_choice";
	case GCR_UNLOCK_OPTION_TIMEOUT:
		return "lock_after_choice";
	case GCR_UNLOCK_OPTION_IDLE:
		return "lock_idle_choice";
	default:
		return NULL;
	}
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */


static GObject*
gcr_unlock_options_widget_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GObject *obj = G_OBJECT_CLASS (gcr_unlock_options_widget_parent_class)->constructor (type, n_props, props);
	GcrUnlockOptionsWidget *self = NULL;
	GtkToggleButton *button;
	GtkWidget *widget;

	if (obj) {
		self = GCR_UNLOCK_OPTIONS_WIDGET (obj);

		if (!gtk_builder_add_from_file (self->pv->builder, UIDIR "gcr-unlock-options-widget.ui", NULL))
			g_return_val_if_reached (obj);

		widget = GTK_WIDGET (gtk_builder_get_object (self->pv->builder, "unlock-options-widget"));
		g_return_val_if_fail (GTK_IS_WIDGET (widget), obj);
		gtk_container_add (GTK_CONTAINER (self), widget);
		gtk_widget_show (widget);

		button = builder_get_toggle_button (self->pv->builder, "lock_logout_choice");
		g_signal_connect (button, "toggled", G_CALLBACK (on_timeout_choices_toggled), self->pv->builder);
		button = builder_get_toggle_button (self->pv->builder, "lock_after_choice");
		g_signal_connect (button, "toggled", G_CALLBACK (on_timeout_choices_toggled), self->pv->builder);
		button = builder_get_toggle_button (self->pv->builder, "lock_idle_choice");
		g_signal_connect (button, "toggled", G_CALLBACK (on_timeout_choices_toggled), self->pv->builder);
		on_timeout_choices_toggled (button, self->pv->builder);
	}

	return obj;
}

static void
gcr_unlock_options_widget_init (GcrUnlockOptionsWidget *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_UNLOCK_OPTIONS_WIDGET, GcrUnlockOptionsWidgetPrivate));
	self->pv->builder = gtk_builder_new ();
}

static void
gcr_unlock_options_widget_dispose (GObject *obj)
{
	GcrUnlockOptionsWidget *self = GCR_UNLOCK_OPTIONS_WIDGET (obj);

	if (self->pv->builder)
		g_object_unref (self->pv->builder);
	self->pv->builder = NULL;

	G_OBJECT_CLASS (gcr_unlock_options_widget_parent_class)->dispose (obj);
}

static void
gcr_unlock_options_widget_finalize (GObject *obj)
{
	GcrUnlockOptionsWidget *self = GCR_UNLOCK_OPTIONS_WIDGET (obj);

	g_assert (!self->pv->builder);

	G_OBJECT_CLASS (gcr_unlock_options_widget_parent_class)->finalize (obj);
}

static void
gcr_unlock_options_widget_set_property (GObject *obj, guint prop_id, const GValue *value,
                                        GParamSpec *pspec)
{
	GcrUnlockOptionsWidget *self = GCR_UNLOCK_OPTIONS_WIDGET (obj);
	GtkToggleButton *button;
	GtkSpinButton *spin;
	gint seconds;

	spin = builder_get_spin_button (self->pv->builder, "lock_minutes_spin");

	switch (prop_id) {
	case PROP_UNLOCK_TIMEOUT:
		button = builder_get_toggle_button (self->pv->builder, "lock_after_choice");
		seconds = g_value_get_int (value);
		if (seconds <= 0) {
			gtk_toggle_button_set_active (button, FALSE);
		} else {
			gtk_toggle_button_set_active (button, TRUE);
			spin = builder_get_spin_button (self->pv->builder, "lock_minutes_spin");
			gtk_spin_button_set_value (spin, seconds / 60);
		}
		break;
	case PROP_UNLOCK_IDLE:
		button = builder_get_toggle_button (self->pv->builder, "lock_idle_choice");
		seconds = g_value_get_int (value);
		if (seconds <= 0) {
			gtk_toggle_button_set_active (button, FALSE);
		} else {
			gtk_toggle_button_set_active (button, TRUE);
			spin = builder_get_spin_button (self->pv->builder, "lock_minutes_spin");
			gtk_spin_button_set_value (spin, seconds / 60);
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_unlock_options_widget_get_property (GObject *obj, guint prop_id, GValue *value,
                                        GParamSpec *pspec)
{
	GcrUnlockOptionsWidget *self = GCR_UNLOCK_OPTIONS_WIDGET (obj);
	GtkToggleButton *button;
	GtkSpinButton *spin;
	gint minutes;

	spin = builder_get_spin_button (self->pv->builder, "lock_minutes_spin");
	minutes = gtk_spin_button_get_value_as_int (spin);

	switch (prop_id) {
	case PROP_UNLOCK_TIMEOUT:
		button = builder_get_toggle_button (self->pv->builder, "lock_after_choice");
		if (!gtk_toggle_button_get_active (button))
			g_value_set_int (value, 0);
		else
			g_value_set_int (value, minutes * 60);
		break;
	case PROP_UNLOCK_IDLE:
		button = builder_get_toggle_button (self->pv->builder, "lock_idle_choice");
		if (!gtk_toggle_button_get_active (button))
			g_value_set_int (value, 0);
		else
			g_value_set_int (value, minutes * 60);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_unlock_options_widget_class_init (GcrUnlockOptionsWidgetClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gcr_unlock_options_widget_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GcrUnlockOptionsWidgetPrivate));

	gobject_class->constructor = gcr_unlock_options_widget_constructor;
	gobject_class->dispose = gcr_unlock_options_widget_dispose;
	gobject_class->finalize = gcr_unlock_options_widget_finalize;
	gobject_class->set_property = gcr_unlock_options_widget_set_property;
	gobject_class->get_property = gcr_unlock_options_widget_get_property;

	g_object_class_install_property (gobject_class, PROP_UNLOCK_TIMEOUT,
	               g_param_spec_int ("unlock-timeout", "Unlock Timeout", "Unlock Timeout",
	                                 0, G_MAXINT, 0, G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_UNLOCK_IDLE,
	               g_param_spec_int ("unlock-idle", "Unlock Idle", "Unlock Idle Timeout",
	                                 0, G_MAXINT, 0, G_PARAM_READWRITE));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GtkWidget*
gcr_unlock_options_widget_new (void)
{
	return g_object_new (GCR_TYPE_UNLOCK_OPTIONS_WIDGET, NULL);
}

const gchar*
gcr_unlock_options_widget_get_label (GcrUnlockOptionsWidget *self, guint option)
{
	GtkToggleButton *button;
	const gchar *name;

	g_return_val_if_fail (GCR_IS_UNLOCK_OPTIONS_WIDGET (self), NULL);

	name = widget_name_for_option (option);
	g_return_val_if_fail (name, NULL);

	button = builder_get_toggle_button (self->pv->builder, name);
	g_return_val_if_fail (button, NULL);

	return gtk_button_get_label (GTK_BUTTON (button));
}

void
gcr_unlock_options_widget_set_label (GcrUnlockOptionsWidget *self, guint option,
                                     const gchar *text)
{
	GtkToggleButton *button;
	const gchar *name;

	g_return_if_fail (GCR_IS_UNLOCK_OPTIONS_WIDGET (self));
	g_return_if_fail (text);

	name = widget_name_for_option (option);
	g_return_if_fail (name);

	button = builder_get_toggle_button (self->pv->builder, name);
	g_return_if_fail (button);

	gtk_button_set_label (GTK_BUTTON (button), text);
}
