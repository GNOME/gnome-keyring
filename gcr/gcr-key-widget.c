/*
 * Copyright (C) 2008 Stefan Walter
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

#include "gcr-key-widget.h"
#include "gcr-display-view.h"
#include "gcr-icons.h"
#include "gcr-view.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-oid.h"
#include "egg/egg-hex.h"

#include "gp11/gp11.h"

#include <gdk/gdk.h>
#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_LABEL,
	PROP_ATTRIBUTES
};

struct _GcrKeyWidgetPrivate {
	GcrDisplayView *view;
	guint key_size;
	gchar *label;
	GP11Attributes *attributes;
};

static void gcr_view_iface_init (GcrViewIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrKeyWidget, gcr_key_widget, GTK_TYPE_ALIGNMENT,
                         G_IMPLEMENT_INTERFACE (GCR_TYPE_VIEW, gcr_view_iface_init));

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar*
calculate_label (GcrKeyWidget *self)
{
	gchar *label;

	if (self->pv->label)
		return g_strdup (self->pv->label);

	if (self->pv->attributes) {
		if (gp11_attributes_find_string (self->pv->attributes, CKA_LABEL, &label))
			return label;
	}

	return g_strdup (_("Key"));
}

static gint
calculate_rsa_key_size (GP11Attributes *attrs)
{
	GP11Attribute *attr;
	gulong bits;

	attr = gp11_attributes_find (attrs, CKA_MODULUS);

	/* Calculate the bit length, and remove the complement */
	if (attr != NULL)
		return (attr->length / 2) * 2 * 8;

	if (gp11_attributes_find_ulong (attrs, CKA_MODULUS_BITS, &bits))
		return (gint)bits;

	return -1;
}

static guint
calculate_dsa_key_size (GP11Attributes *attrs)
{
	GP11Attribute *attr;
	gulong bits;

	attr = gp11_attributes_find (attrs, CKA_PRIME);

	/* Calculate the bit length, and remove the complement */
	if (attr != NULL)
		return (attr->length / 2) * 2 * 8;

	if (gp11_attributes_find_ulong (attrs, CKA_PRIME_BITS, &bits))
		return (gint)bits;

	return -1;
}

static gint
calculate_key_size (GP11Attributes *attrs, gulong key_type)
{
	if (key_type == CKK_RSA)
		return calculate_rsa_key_size (attrs);
	else if (key_type == CKK_DSA)
		return calculate_dsa_key_size (attrs);
	else
		return -1;
}

static void
refresh_display (GcrKeyWidget *self)
{
	const gchar *text;
	gchar *display;
	gulong klass;
	gulong key_type;
	gint size;

	if (!self->pv->view)
		return;

	_gcr_display_view_clear (self->pv->view);

	if (!self->pv->attributes)
		return;

	if (!gp11_attributes_find_ulong (self->pv->attributes, CKA_CLASS, &klass) ||
	    !gp11_attributes_find_ulong (self->pv->attributes, CKA_KEY_TYPE, &key_type)) {
		g_warning ("private key does not have the CKA_CLASS and CKA_KEY_TYPE attributes");
		return;
	}

	display = calculate_label (self);
	_gcr_display_view_append_title (self->pv->view, display);
	g_free (display);

	if (klass == CKO_PRIVATE_KEY) {
		if (key_type == CKK_RSA)
			text = _("Private RSA Key");
		else if (key_type == CKK_DSA)
			text = _("Private DSA Key");
		else
			text = _("Private Key");
	} else if (klass == CKO_PUBLIC_KEY) {
		if (key_type == CKK_RSA)
			text = _("Public DSA Key");
		else if (key_type == CKK_DSA)
			text = _("Public DSA Key");
		else
			text = _("Public Key");
	}

	_gcr_display_view_append_content (self->pv->view, text, NULL);

	size = calculate_key_size (self->pv->attributes, key_type);
	if (size >= 0) {
		display = g_strdup_printf (_("%d bits"), size);
		_gcr_display_view_append_content (self->pv->view, _("Strength"), display);
		g_free (display);
	}

	_gcr_display_view_start_details (self->pv->view);


	if (key_type == CKK_RSA)
		text = _("RSA");
	else if (key_type == CKK_DSA)
		text = _("DSA");
	else
		text = _("Unknown");
	_gcr_display_view_append_value (self->pv->view, _("Algorithm"), text, FALSE);

	size = calculate_key_size (self->pv->attributes, key_type);
	if (size < 0)
		display = g_strdup (_("Unknown"));
	else
		display = g_strdup_printf ("%d", size);
	_gcr_display_view_append_value (self->pv->view, _("Size"), display, FALSE);
	g_free (display);

	/* TODO: We need to have consistent key fingerprints. */
	_gcr_display_view_append_value (self->pv->view, _("Fingerprint"), "XX XX XX XX XX XX XX XX XX XX", TRUE);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gcr_key_widget_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GObject *obj = G_OBJECT_CLASS (gcr_key_widget_parent_class)->constructor (type, n_props, props);
	GcrKeyWidget *self = NULL;
	GtkWidget *scroll;

	g_return_val_if_fail (obj, NULL);

	self = GCR_KEY_WIDGET (obj);

	self->pv->view = _gcr_display_view_new ();
	_gcr_display_view_set_stock_image (self->pv->view, GTK_STOCK_DIALOG_AUTHENTICATION);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_ETCHED_IN);
	gtk_container_add (GTK_CONTAINER (scroll), GTK_WIDGET (self->pv->view));

	gtk_container_add (GTK_CONTAINER (self), scroll);
	gtk_widget_show_all (scroll);

	refresh_display (self);

	return obj;
}

static void
gcr_key_widget_init (GcrKeyWidget *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_KEY_WIDGET, GcrKeyWidgetPrivate));
}

static void
gcr_key_widget_dispose (GObject *obj)
{
	G_OBJECT_CLASS (gcr_key_widget_parent_class)->dispose (obj);
}

static void
gcr_key_widget_finalize (GObject *obj)
{
	GcrKeyWidget *self = GCR_KEY_WIDGET (obj);

	if (self->pv->attributes)
		gp11_attributes_unref (self->pv->attributes);
	self->pv->attributes = NULL;

	g_free (self->pv->label);
	self->pv->label = NULL;

	G_OBJECT_CLASS (gcr_key_widget_parent_class)->finalize (obj);
}

static void
gcr_key_widget_set_property (GObject *obj, guint prop_id, const GValue *value,
                                     GParamSpec *pspec)
{
	GcrKeyWidget *self = GCR_KEY_WIDGET (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_free (self->pv->label);
		self->pv->label = g_value_dup_string (value);
		g_object_notify (obj, "label");
		refresh_display (self);
		break;
	case PROP_ATTRIBUTES:
		g_return_if_fail (!self->pv->attributes);
		self->pv->attributes = g_value_dup_boxed (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_key_widget_get_property (GObject *obj, guint prop_id, GValue *value,
                                     GParamSpec *pspec)
{
	GcrKeyWidget *self = GCR_KEY_WIDGET (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_take_string (value, calculate_label (self));
		break;
	case PROP_ATTRIBUTES:
		g_value_set_boxed (value, self->pv->attributes);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_key_widget_class_init (GcrKeyWidgetClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GP11Attributes *registered;

	gcr_key_widget_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GcrKeyWidgetPrivate));

	gobject_class->constructor = gcr_key_widget_constructor;
	gobject_class->dispose = gcr_key_widget_dispose;
	gobject_class->finalize = gcr_key_widget_finalize;
	gobject_class->set_property = gcr_key_widget_set_property;
	gobject_class->get_property = gcr_key_widget_get_property;

	g_object_class_override_property (gobject_class, PROP_LABEL, "label");
	g_object_class_override_property (gobject_class, PROP_ATTRIBUTES, "attributes");

	_gcr_icons_register ();

	/* Register this as a view which can be loaded */
	registered = gp11_attributes_new ();
	gp11_attributes_add_ulong (registered, CKA_CLASS, CKO_PRIVATE_KEY);
	gcr_view_register (GCR_TYPE_KEY_WIDGET, registered);
	gp11_attributes_unref (registered);
}

static void
gcr_view_iface_init (GcrViewIface *iface)
{
	/* Nothing to do */
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GcrKeyWidget*
gcr_key_widget_new (const gchar *label, GP11Attributes *attrs)
{
	return g_object_new (GCR_TYPE_KEY_WIDGET, "label", label, "attributes", attrs, NULL);
}
