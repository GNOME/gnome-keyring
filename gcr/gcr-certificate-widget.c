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

#include "egg/egg-asn1.h"
#include "egg/egg-oid.h"
#include "egg/egg-hex.h"

#include <gdk/gdk.h>
#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_CERTIFICATE
};

struct _GcrCertificateWidgetPrivate {
	GcrCertificate *certificate;
	GcrDisplayView *view;
	guint key_size;
};

G_DEFINE_TYPE (GcrCertificateWidget, gcr_certificate_widget, GTK_TYPE_ALIGNMENT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gboolean
append_extension (GcrCertificateWidget *self, ASN1_TYPE asn,
                  const guchar *data, gsize n_data, gint index)
{
	GQuark oid;
	gchar *name, *display;
	gsize n_value;
	const guchar *value;
	const gchar *text;
	gboolean critical;
	int len, res;

	/* Make sure it is present */
	len = 0;
	name = g_strdup_printf ("tbsCertificate.extensions.?%u", index);
	res = asn1_read_value (asn, name, NULL, &len);
	g_free (name);

	if (res == ASN1_ELEMENT_NOT_FOUND)
		return FALSE;

	/* Dig out the OID */
	name = g_strdup_printf ("tbsCertificate.extensions.?%u.extnID", index);
	oid = egg_asn1_read_oid (asn, name);
	g_free (name);
	g_return_val_if_fail (oid, FALSE);


	_gcr_display_view_append_heading (self->pv->view, _("Extension"));


	/* Extension type */
	text = egg_oid_get_description (oid);
	_gcr_display_view_append_value (self->pv->view, _("Identifier"), text, FALSE);


	/* Extension value */
	name = g_strdup_printf ("tbsCertificate.extensions.?%u.extnValue", index);
	value = egg_asn1_read_content (asn, data, n_data, name, &n_value);
	g_free (name);

	/* TODO: Parsing of extensions that we understand */
	display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
	_gcr_display_view_append_value (self->pv->view, _("Value"), display, TRUE);
	g_free (display);


	/* Critical */
	name = g_strdup_printf ("tbsCertificate.extensions.?%u.critical", index);
	if (egg_asn1_read_boolean (asn, name, &critical))
		_gcr_display_view_append_value (self->pv->view, _("Critical"), critical ? _("Yes") : _("No"), FALSE);
	g_free (name);

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

	display = egg_asn1_dn_print_value (oid, value, n_value);
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
	gsize n_data, n_value;
	const gchar *text;
	guint version, size;
	guint index;
	gchar *display;
	ASN1_TYPE asn;
	GQuark oid;
	GDate date;

	_gcr_display_view_clear (self->pv->view);

	if (!self->pv->certificate)
		return;

	data = gcr_certificate_get_der_data (self->pv->certificate, &n_data);
	g_return_if_fail (data);

	asn = egg_asn1_decode ("PKIX1.Certificate", data, n_data);
	g_return_if_fail (asn);

	/* TODO: Calculate name properly */
	_gcr_display_view_append_title (self->pv->view, "Certificate Name");

	display = egg_asn1_read_dn_part (asn, "tbsCertificate.subject.rdnSequence", "CN");
	_gcr_display_view_append_content (self->pv->view, _("Identity"), display);
	g_free (display);

	display = egg_asn1_read_dn_part (asn, "tbsCertificate.issuer.rdnSequence", "CN");
	_gcr_display_view_append_content (self->pv->view, _("Verified by"), display);
	g_free (display);

	if (egg_asn1_read_date (asn, "tbsCertificate.validity.notAfter", &date)) {
		display = g_malloc0 (128);
		if (!g_date_strftime (display, 128, "%x", &date))
			g_return_if_reached ();
		_gcr_display_view_append_content (self->pv->view, _("Expires"), display);
		g_free (display);
	}

	_gcr_display_view_start_details (self->pv->view);

	/* The subject */
	_gcr_display_view_append_heading (self->pv->view, _("Subject Name"));
	egg_asn1_dn_parse (asn, "tbsCertificate.subject.rdnSequence", on_parsed_dn_part, self);

	/* The Issuer */
	_gcr_display_view_append_heading (self->pv->view, _("Issuer Name"));
	egg_asn1_dn_parse (asn, "tbsCertificate.issuer.rdnSequence", on_parsed_dn_part, self);

	/* The Issued Parameters */
	_gcr_display_view_append_heading (self->pv->view, _("Issued Certificate"));

	if (!egg_asn1_read_uint (asn, "tbsCertificate.version", &version))
		g_return_if_reached ();
	display = g_strdup_printf ("%u", version + 1);
	_gcr_display_view_append_value (self->pv->view, _("Version"), display, FALSE);
	g_free (display);

	value = egg_asn1_read_content (asn, data, n_data, "tbsCertificate.serialNumber", &n_value);
	g_return_if_fail (value);
	display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
	_gcr_display_view_append_value (self->pv->view, _("Serial Number"), display, TRUE);
	g_free (display);

	display = g_malloc0 (128);
	if (egg_asn1_read_date (asn, "tbsCertificate.validity.notBefore", &date)) {
		if (!g_date_strftime (display, 128, "%Y-%m-%d", &date))
			g_return_if_reached ();
		_gcr_display_view_append_value (self->pv->view, _("Not Valid Before"), display, FALSE);
	}
	if (egg_asn1_read_date (asn, "tbsCertificate.validity.notAfter", &date)) {
		if (!g_date_strftime (display, 128, "%Y-%m-%d", &date))
			g_return_if_reached ();
		_gcr_display_view_append_value (self->pv->view, _("Not Valid After"), display, FALSE);
	}
	g_free (display);

	/* Signature */
	_gcr_display_view_append_heading (self->pv->view, _("Signature"));

	oid = egg_asn1_read_oid (asn, "signatureAlgorithm.algorithm");
	text = egg_oid_get_description (oid);
	_gcr_display_view_append_value (self->pv->view, _("Signature Algorithm"), text, FALSE);

	value = egg_asn1_read_content (asn, data, n_data, "signatureAlgorithm.parameters", &n_value);
	if (value && n_value) {
		display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
		_gcr_display_view_append_value (self->pv->view, _("Signature Parameters"), display, TRUE);
		g_free (display);
	}

	value = egg_asn1_read_content (asn, data, n_data, "signature", &n_value);
	g_return_if_fail (value);
	display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
	_gcr_display_view_append_value (self->pv->view, _("Signature"), display, TRUE);
	g_free (display);

	/* Public Key Info */
	_gcr_display_view_append_heading (self->pv->view, _("Public Key Info"));

	oid = egg_asn1_read_oid (asn, "tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm");
	text = egg_oid_get_description (oid);
	_gcr_display_view_append_value (self->pv->view, _("Key Algorithm"), text, FALSE);

	value = egg_asn1_read_content (asn, data, n_data, "tbsCertificate.subjectPublicKeyInfo.algorithm.parameters", &n_value);
	if (value && n_value) {
		display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
		_gcr_display_view_append_value (self->pv->view, _("Key Parameters"), display, TRUE);
		g_free (display);
	}

	size = gcr_certificate_get_key_size (self->pv->certificate);
	if (size > 0) {
		display = g_strdup_printf ("%u", size);
		_gcr_display_view_append_value (self->pv->view, _("Key Size"), display, FALSE);
		g_free (display);
	}

	value = egg_asn1_read_content (asn, data, n_data, "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey", &n_value);
	g_return_if_fail (value);
	display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
	_gcr_display_view_append_value (self->pv->view, _("Public Key"), display, TRUE);
	g_free (display);

	/* Fingerprints */
	_gcr_display_view_append_heading (self->pv->view, _("Fingerprints"));

	_gcr_display_view_append_fingerprint (self->pv->view, data, n_data, "SHA1", G_CHECKSUM_SHA1);
	_gcr_display_view_append_fingerprint (self->pv->view, data, n_data, "MD5", G_CHECKSUM_MD5);

	/* Extensions */
	for (index = 1; TRUE; ++index) {
		if (!append_extension (self, asn, data, n_data, index))
			break;
	}

	asn1_delete_structure (&asn);
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

	G_OBJECT_CLASS (gcr_certificate_widget_parent_class)->finalize (obj);
}

static void
gcr_certificate_widget_set_property (GObject *obj, guint prop_id, const GValue *value,
                                             GParamSpec *pspec)
{
	GcrCertificateWidget *self = GCR_CERTIFICATE_WIDGET (obj);

	switch (prop_id) {
	case PROP_CERTIFICATE:
		gcr_certificate_widget_set_certificate (self, g_value_get_object (value));
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
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_certificate_widget_class_init (GcrCertificateWidgetClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

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

	_gcr_icons_register ();
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
	refresh_display (self);
	g_object_notify (G_OBJECT (self), "certificate");
}
