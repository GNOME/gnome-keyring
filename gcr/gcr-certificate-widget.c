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

#include "gcr-certificate.h"
#include "gcr-certificate-widget.h"
#include "gcr-display-view.h"
#include "gcr-icons.h"
#include "gcr-simple-certificate.h"
#include "gcr-view.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"
#include "egg/egg-dn.h"
#include "egg/egg-oid.h"
#include "egg/egg-hex.h"

#include <gdk/gdk.h>
#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_CERTIFICATE,
	PROP_LABEL,
	PROP_ATTRIBUTES
};

struct _GcrCertificateWidgetPrivate {
	GcrCertificate *certificate;
	GcrDisplayView *view;
	guint key_size;
	gchar *label;
	GP11Attributes *attributes;
};

static void gcr_view_iface_init (GcrViewIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrCertificateWidget, gcr_certificate_widget, GTK_TYPE_ALIGNMENT,
                         G_IMPLEMENT_INTERFACE (GCR_TYPE_VIEW, gcr_view_iface_init));

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar*
calculate_label (GcrCertificateWidget *self, GNode *asn)
{
	gchar *label;

	if (self->pv->label)
		return g_strdup (self->pv->label);

	if (self->pv->attributes) {
		if (gp11_attributes_find_string (self->pv->attributes, CKA_LABEL, &label))
			return label;
	}

	if (asn != NULL) {
		label = egg_dn_read_part (egg_asn1x_node (asn, "tbsCertificate", "subject", "rdnSequence", NULL), "CN");
		if (label != NULL)
			return label;
	}

	return g_strdup (_("Certificate"));
}

static gboolean
append_extension (GcrCertificateWidget *self, GNode *asn,
                  const guchar *data, gsize n_data, gint index)
{
	GNode *node;
	GQuark oid;
	gchar *display;
	gsize n_value;
	const guchar *value;
	const gchar *text;
	gboolean critical;

	/* Make sure it is present */
	node = egg_asn1x_node (asn, "tbsCertificate", "extensions", index, NULL);
	if (node == NULL)
		return FALSE;

	/* Dig out the OID */
	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (node, "extnID", NULL));
	g_return_val_if_fail (oid, FALSE);

	_gcr_display_view_append_heading (self->pv->view, _("Extension"));


	/* Extension type */
	text = egg_oid_get_description (oid);
	_gcr_display_view_append_value (self->pv->view, _("Identifier"), text, FALSE);


	/* Extension value */
	value = egg_asn1x_get_raw_value (egg_asn1x_node (node, "extnValue", NULL), &n_value);

	/* TODO: Parsing of extensions that we understand */
	display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
	_gcr_display_view_append_value (self->pv->view, _("Value"), display, TRUE);
	g_free (display);


	/* Critical */
	if (egg_asn1x_get_boolean (egg_asn1x_node (node, "critical", NULL), &critical))
		_gcr_display_view_append_value (self->pv->view, _("Critical"), critical ? _("Yes") : _("No"), FALSE);

	return TRUE;
}

static void
on_parsed_dn_part (guint index, GQuark oid, const guchar *value,
                   gsize n_value, gpointer user_data)
{
	GcrCertificateWidget *self = user_data;
	const gchar *attr;
	const gchar *desc;
	gchar *field;
	gchar *display;

	g_return_if_fail (GCR_IS_CERTIFICATE_WIDGET (self));

	attr = egg_oid_get_name (oid);
	desc = egg_oid_get_description (oid);

	/* Combine them into something sane */
	if (attr && desc) {
		if (strcmp (attr, desc) == 0)
			field = g_strdup (attr);
		else
			field = g_strdup_printf ("%s (%s)", attr, desc);
	} else if (!attr && !desc) {
		field = g_strdup ("");
	} else if (attr) {
		field = g_strdup (attr);
	} else if (desc) {
		field = g_strdup (desc);
	} else {
		g_assert_not_reached ();
	}

	display = egg_dn_print_value (oid, value, n_value);
	if (display == NULL)
		display = g_strdup ("");

	_gcr_display_view_append_value (self->pv->view, field, display, FALSE);
	g_free (field);
	g_free (display);
}

static void
refresh_display (GcrCertificateWidget *self)
{
	const guchar *data, *value;
	gsize n_data, n_value, n_raw;
	const gchar *text;
	gpointer raw;
	gulong version;
	guint bits, index;
	gchar *display;
	GNode *asn;
	GQuark oid;
	GDate date;

	_gcr_display_view_clear (self->pv->view);

	if (!self->pv->certificate)
		return;

	data = gcr_certificate_get_der_data (self->pv->certificate, &n_data);
	g_return_if_fail (data);

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate", data, n_data);
	g_return_if_fail (asn);

	display = calculate_label (self, asn);
	_gcr_display_view_append_title (self->pv->view, display);
	g_free (display);

	display = egg_dn_read_part (egg_asn1x_node (asn, "tbsCertificate", "subject", "rdnSequence", NULL), "CN");
	_gcr_display_view_append_content (self->pv->view, _("Identity"), display);
	g_free (display);

	display = egg_dn_read_part (egg_asn1x_node (asn, "tbsCertificate", "issuer", "rdnSequence", NULL), "CN");
	_gcr_display_view_append_content (self->pv->view, _("Verified by"), display);
	g_free (display);

	if (egg_asn1x_get_time_as_date (egg_asn1x_node (asn, "tbsCertificate", "validity", "notAfter", NULL), &date)) {
		display = g_malloc0 (128);
		if (!g_date_strftime (display, 128, "%x", &date))
			g_return_if_reached ();
		_gcr_display_view_append_content (self->pv->view, _("Expires"), display);
		g_free (display);
	}

	_gcr_display_view_start_details (self->pv->view);

	/* The subject */
	_gcr_display_view_append_heading (self->pv->view, _("Subject Name"));
	egg_dn_parse (egg_asn1x_node (asn, "tbsCertificate", "subject", "rdnSequence", NULL), on_parsed_dn_part, self);

	/* The Issuer */
	_gcr_display_view_append_heading (self->pv->view, _("Issuer Name"));
	egg_dn_parse (egg_asn1x_node (asn, "tbsCertificate", "issuer", "rdnSequence", NULL), on_parsed_dn_part, self);

	/* The Issued Parameters */
	_gcr_display_view_append_heading (self->pv->view, _("Issued Certificate"));

	if (!egg_asn1x_get_integer_as_ulong (egg_asn1x_node (asn, "tbsCertificate", "version", NULL), &version))
		g_return_if_reached ();
	display = g_strdup_printf ("%lu", version + 1);
	_gcr_display_view_append_value (self->pv->view, _("Version"), display, FALSE);
	g_free (display);

	raw = egg_asn1x_get_integer_as_raw (egg_asn1x_node (asn, "tbsCertificate", "serialNumber", NULL), NULL, &n_raw);
	g_return_if_fail (raw);
	display = egg_hex_encode_full (raw, n_raw, TRUE, ' ', 1);
	_gcr_display_view_append_value (self->pv->view, _("Serial Number"), display, TRUE);
	g_free (display);
	g_free (raw);

	display = g_malloc0 (128);
	if (egg_asn1x_get_time_as_date (egg_asn1x_node (asn, "tbsCertificate", "validity", "notBefore", NULL), &date)) {
		if (!g_date_strftime (display, 128, "%Y-%m-%d", &date))
			g_return_if_reached ();
		_gcr_display_view_append_value (self->pv->view, _("Not Valid Before"), display, FALSE);
	}
	if (egg_asn1x_get_time_as_date (egg_asn1x_node (asn, "tbsCertificate", "validity", "notAfter", NULL), &date)) {
		if (!g_date_strftime (display, 128, "%Y-%m-%d", &date))
			g_return_if_reached ();
		_gcr_display_view_append_value (self->pv->view, _("Not Valid After"), display, FALSE);
	}
	g_free (display);

	/* Signature */
	_gcr_display_view_append_heading (self->pv->view, _("Signature"));

	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "signatureAlgorithm", "algorithm", NULL));
	text = egg_oid_get_description (oid);
	_gcr_display_view_append_value (self->pv->view, _("Signature Algorithm"), text, FALSE);

	value = egg_asn1x_get_raw_element (egg_asn1x_node (asn, "signatureAlgorithm", "parameters", NULL), &n_value);
	if (value && n_value) {
		display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
		_gcr_display_view_append_value (self->pv->view, _("Signature Parameters"), display, TRUE);
		g_free (display);
	}

	raw = egg_asn1x_get_bits_as_raw (egg_asn1x_node (asn, "signature", NULL), NULL, &bits);
	g_return_if_fail (raw);
	display = egg_hex_encode_full (raw, bits / 8, TRUE, ' ', 1);
	_gcr_display_view_append_value (self->pv->view, _("Signature"), display, TRUE);
	g_free (display);
	g_free (raw);

	/* Public Key Info */
	_gcr_display_view_append_heading (self->pv->view, _("Public Key Info"));

	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "tbsCertificate", "subjectPublicKeyInfo",
	                                                  "algorithm", "algorithm", NULL));
	text = egg_oid_get_description (oid);
	_gcr_display_view_append_value (self->pv->view, _("Key Algorithm"), text, FALSE);

	value = egg_asn1x_get_raw_element (egg_asn1x_node (asn, "tbsCertificate", "subjectPublicKeyInfo",
	                                                   "algorithm", "parameters", NULL), &n_value);
	if (value && n_value) {
		display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
		_gcr_display_view_append_value (self->pv->view, _("Key Parameters"), display, TRUE);
		g_free (display);
	}

	bits = gcr_certificate_get_key_size (self->pv->certificate);
	if (bits > 0) {
		display = g_strdup_printf ("%u", bits);
		_gcr_display_view_append_value (self->pv->view, _("Key Size"), display, FALSE);
		g_free (display);
	}

	raw = egg_asn1x_get_bits_as_raw (egg_asn1x_node (asn, "tbsCertificate", "subjectPublicKeyInfo",
	                                                 "subjectPublicKey", NULL), NULL, &bits);
	g_return_if_fail (raw);
	display = egg_hex_encode_full (raw, bits / 8, TRUE, ' ', 1);
	_gcr_display_view_append_value (self->pv->view, _("Public Key"), display, TRUE);
	g_free (display);
	g_free (raw);

	/* Fingerprints */
	_gcr_display_view_append_heading (self->pv->view, _("Fingerprints"));

	_gcr_display_view_append_fingerprint (self->pv->view, data, n_data, "SHA1", G_CHECKSUM_SHA1);
	_gcr_display_view_append_fingerprint (self->pv->view, data, n_data, "MD5", G_CHECKSUM_MD5);

	/* Extensions */
	for (index = 1; TRUE; ++index) {
		if (!append_extension (self, asn, data, n_data, index))
			break;
	}

	egg_asn1x_destroy (asn);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gcr_certificate_widget_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GObject *obj = G_OBJECT_CLASS (gcr_certificate_widget_parent_class)->constructor (type, n_props, props);
	GcrCertificateWidget *self = NULL;
	GtkWidget *scroll;

	g_return_val_if_fail (obj, NULL);

	self = GCR_CERTIFICATE_WIDGET (obj);

	self->pv->view = _gcr_display_view_new ();
	_gcr_display_view_set_stock_image (self->pv->view, GCR_ICON_CERTIFICATE);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), GTK_WIDGET (self->pv->view));

	gtk_container_add (GTK_CONTAINER (self), scroll);
	gtk_widget_show_all (scroll);

	return obj;
}

static void
gcr_certificate_widget_init (GcrCertificateWidget *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_CERTIFICATE_WIDGET, GcrCertificateWidgetPrivate));
}

static void
gcr_certificate_widget_dispose (GObject *obj)
{
	GcrCertificateWidget *self = GCR_CERTIFICATE_WIDGET (obj);

	if (self->pv->certificate)
		g_object_unref (self->pv->certificate);
	self->pv->certificate = NULL;

	G_OBJECT_CLASS (gcr_certificate_widget_parent_class)->dispose (obj);
}

static void
gcr_certificate_widget_finalize (GObject *obj)
{
	GcrCertificateWidget *self = GCR_CERTIFICATE_WIDGET (obj);

	g_assert (!self->pv->certificate);

	if (self->pv->attributes)
		gp11_attributes_unref (self->pv->attributes);
	self->pv->attributes = NULL;

	g_free (self->pv->label);
	self->pv->label = NULL;

	G_OBJECT_CLASS (gcr_certificate_widget_parent_class)->finalize (obj);
}

static void
gcr_certificate_widget_set_property (GObject *obj, guint prop_id, const GValue *value,
                                     GParamSpec *pspec)
{
	GcrCertificateWidget *self = GCR_CERTIFICATE_WIDGET (obj);
	GcrCertificate *cert;
	GP11Attribute *attr;

	switch (prop_id) {
	case PROP_CERTIFICATE:
		gcr_certificate_widget_set_certificate (self, g_value_get_object (value));
		break;
	case PROP_LABEL:
		g_free (self->pv->label);
		self->pv->label = g_value_dup_string (value);
		g_object_notify (obj, "label");
		break;
	case PROP_ATTRIBUTES:
		g_return_if_fail (!self->pv->attributes);
		self->pv->attributes = g_value_dup_boxed (value);
		if (self->pv->attributes) {
			attr = gp11_attributes_find (self->pv->attributes, CKA_VALUE);
			if (attr) {
				/* Create a new certificate object refferring to same memory */
				cert = gcr_simple_certificate_new_static (attr->value, attr->length);
				g_object_set_data_full (G_OBJECT (cert), "attributes",
				                        gp11_attributes_ref (self->pv->attributes),
				                        (GDestroyNotify)gp11_attributes_unref);
				gcr_certificate_widget_set_certificate (self, cert);
				g_object_unref (cert);
			}
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_certificate_widget_get_property (GObject *obj, guint prop_id, GValue *value,
                                     GParamSpec *pspec)
{
	GcrCertificateWidget *self = GCR_CERTIFICATE_WIDGET (obj);

	switch (prop_id) {
	case PROP_CERTIFICATE:
		g_value_set_object (value, self->pv->certificate);
		break;
	case PROP_LABEL:
		g_value_take_string (value, calculate_label (self, NULL));
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
gcr_certificate_widget_class_init (GcrCertificateWidgetClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GP11Attributes *registered;

	gcr_certificate_widget_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GcrCertificateWidgetPrivate));

	gobject_class->constructor = gcr_certificate_widget_constructor;
	gobject_class->dispose = gcr_certificate_widget_dispose;
	gobject_class->finalize = gcr_certificate_widget_finalize;
	gobject_class->set_property = gcr_certificate_widget_set_property;
	gobject_class->get_property = gcr_certificate_widget_get_property;

	g_object_class_install_property (gobject_class, PROP_CERTIFICATE,
	           g_param_spec_object("certificate", "Certificate", "Certificate to display.",
	                               GCR_TYPE_CERTIFICATE, G_PARAM_READWRITE));

	g_object_class_override_property (gobject_class, PROP_LABEL, "label");
	g_object_class_override_property (gobject_class, PROP_ATTRIBUTES, "attributes");

	_gcr_icons_register ();

	/* Register this as a view which can be loaded */
	registered = gp11_attributes_new ();
	gp11_attributes_add_ulong (registered, CKA_CLASS, CKO_CERTIFICATE);
	gcr_view_register (GCR_TYPE_CERTIFICATE_WIDGET, registered);
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

GcrCertificateWidget*
gcr_certificate_widget_new (GcrCertificate *certificate)
{
	return g_object_new (GCR_TYPE_CERTIFICATE_WIDGET, "certificate", certificate, NULL);
}

GcrCertificate*
gcr_certificate_widget_get_certificate (GcrCertificateWidget *self)
{
	g_return_val_if_fail (GCR_IS_CERTIFICATE_WIDGET (self), NULL);
	return self->pv->certificate;
}

void
gcr_certificate_widget_set_certificate (GcrCertificateWidget *self, GcrCertificate *cert)
{
	g_return_if_fail (GCR_IS_CERTIFICATE_WIDGET (self));

	if (self->pv->certificate)
		g_object_unref (self->pv->certificate);
	self->pv->certificate = cert;
	if (self->pv->certificate)
		g_object_ref (self->pv->certificate);

	refresh_display (self);
	g_object_notify (G_OBJECT (self), "certificate");
}
