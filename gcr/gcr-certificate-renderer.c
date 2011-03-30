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

#include "gcr-certificate.h"
#include "gcr-certificate-exporter.h"
#include "gcr-certificate-renderer.h"
#include "gcr-display-view.h"
#include "gcr-icons.h"
#include "gcr-simple-certificate.h"
#include "gcr-renderer.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"
#include "egg/egg-dn.h"
#include "egg/egg-oid.h"
#include "egg/egg-hex.h"

#include "gck/gck.h"

#include <gdk/gdk.h>
#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_CERTIFICATE,
	PROP_LABEL,
	PROP_ATTRIBUTES
};

struct _GcrCertificateRendererPrivate {
	GcrCertificate *certificate;
	GckAttributes *attributes;
	guint key_size;
	gchar *label;
};

static void gcr_renderer_iface_init (GcrRendererIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrCertificateRenderer, gcr_certificate_renderer, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GCR_TYPE_RENDERER, gcr_renderer_iface_init));

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar*
calculate_label (GcrCertificateRenderer *self, GNode *asn)
{
	gchar *label;

	if (self->pv->label)
		return g_strdup (self->pv->label);

	if (self->pv->attributes) {
		if (gck_attributes_find_string (self->pv->attributes, CKA_LABEL, &label))
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
append_extension (GcrCertificateRenderer *self, GcrDisplayView *view,
                  GNode *asn, const guchar *data, gsize n_data, gint index)
{
	GcrRenderer *renderer = GCR_RENDERER (self);
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

	_gcr_display_view_append_heading (view, renderer, _("Extension"));


	/* Extension type */
	text = egg_oid_get_description (oid);
	_gcr_display_view_append_value (view, renderer, _("Identifier"), text, FALSE);


	/* Extension value */
	value = egg_asn1x_get_raw_value (egg_asn1x_node (node, "extnValue", NULL), &n_value);

	/* TODO: Parsing of extensions that we understand */
	display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
	_gcr_display_view_append_value (view, renderer, _("Value"), display, TRUE);
	g_free (display);


	/* Critical */
	if (egg_asn1x_get_boolean (egg_asn1x_node (node, "critical", NULL), &critical))
		_gcr_display_view_append_value (view, renderer, _("Critical"), critical ? _("Yes") : _("No"), FALSE);

	return TRUE;
}

typedef struct _on_parsed_dn_args {
	GcrCertificateRenderer *renderer;
	GcrDisplayView *view;
} on_parsed_dn_args;

static void
on_parsed_dn_part (guint index, GQuark oid, const guchar *value,
                   gsize n_value, gpointer user_data)
{
	GcrCertificateRenderer *self = ((on_parsed_dn_args*)user_data)->renderer;
	GcrDisplayView *view = ((on_parsed_dn_args*)user_data)->view;
	const gchar *attr;
	const gchar *desc;
	gchar *field;
	gchar *display;

	g_return_if_fail (GCR_IS_CERTIFICATE_RENDERER (self));

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

	_gcr_display_view_append_value (view, GCR_RENDERER (self), field, display, FALSE);
	g_free (field);
	g_free (display);
}

static gboolean
on_delete_unref_dialog (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	g_object_unref (widget);
	return FALSE;
}

static void
on_export_completed (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GtkWindow *parent = GTK_WINDOW (user_data);
	GcrCertificateExporter *exporter = GCR_CERTIFICATE_EXPORTER (source);
	GError *error = NULL;
	GtkWidget *dialog;

	if (!_gcr_certificate_exporter_export_finish (exporter, result, &error)) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			dialog = gtk_message_dialog_new_with_markup (parent,
				  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,
				  GTK_BUTTONS_OK, "<big>%s</big>\n\n%s",
				  _("Couldn't export the certificate."),
				  error->message);
			gtk_widget_show (dialog);
			g_signal_connect (dialog, "delete-event",
					  G_CALLBACK (on_delete_unref_dialog), NULL);
		}
	}

	/* Matches ref in on_certificate_export */
	if (parent)
		g_object_unref (parent);
}

static void
on_certificate_export (GtkMenuItem *menuitem, gpointer user_data)
{
	GcrCertificateRenderer *self = GCR_CERTIFICATE_RENDERER (user_data);
	GcrCertificateExporter *exporter;
	gchar *label;
	GtkWidget *parent;

	label = calculate_label (self, NULL);

	parent = gtk_widget_get_toplevel (GTK_WIDGET (menuitem));
	if (parent && !GTK_IS_WINDOW (parent))
		parent = NULL;

	exporter = _gcr_certificate_exporter_new (self->pv->certificate, label,
	                                          GTK_WINDOW (parent));

	g_free (label);

	_gcr_certificate_exporter_export_async (exporter, NULL, on_export_completed,
	                                        parent ? g_object_ref (parent) : NULL);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gcr_certificate_renderer_init (GcrCertificateRenderer *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_CERTIFICATE_RENDERER, GcrCertificateRendererPrivate));
}

static void
gcr_certificate_renderer_dispose (GObject *obj)
{
	GcrCertificateRenderer *self = GCR_CERTIFICATE_RENDERER (obj);

	if (self->pv->certificate)
		g_object_unref (self->pv->certificate);
	self->pv->certificate = NULL;

	G_OBJECT_CLASS (gcr_certificate_renderer_parent_class)->dispose (obj);
}

static void
gcr_certificate_renderer_finalize (GObject *obj)
{
	GcrCertificateRenderer *self = GCR_CERTIFICATE_RENDERER (obj);

	g_assert (!self->pv->certificate);

	if (self->pv->attributes)
		gck_attributes_unref (self->pv->attributes);
	self->pv->attributes = NULL;

	g_free (self->pv->label);
	self->pv->label = NULL;

	G_OBJECT_CLASS (gcr_certificate_renderer_parent_class)->finalize (obj);
}

static void
gcr_certificate_renderer_set_property (GObject *obj, guint prop_id, const GValue *value,
                                     GParamSpec *pspec)
{
	GcrCertificateRenderer *self = GCR_CERTIFICATE_RENDERER (obj);

	switch (prop_id) {
	case PROP_CERTIFICATE:
		gcr_certificate_renderer_set_certificate (self, g_value_get_object (value));
		break;
	case PROP_LABEL:
		g_free (self->pv->label);
		self->pv->label = g_value_dup_string (value);
		g_object_notify (obj, "label");
		gcr_renderer_emit_data_changed (GCR_RENDERER (self));
		break;
	case PROP_ATTRIBUTES:
		gcr_certificate_renderer_set_attributes (self, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_certificate_renderer_get_property (GObject *obj, guint prop_id, GValue *value,
                                     GParamSpec *pspec)
{
	GcrCertificateRenderer *self = GCR_CERTIFICATE_RENDERER (obj);

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
gcr_certificate_renderer_class_init (GcrCertificateRendererClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckAttributes *registered;

	gcr_certificate_renderer_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GcrCertificateRendererPrivate));

	gobject_class->dispose = gcr_certificate_renderer_dispose;
	gobject_class->finalize = gcr_certificate_renderer_finalize;
	gobject_class->set_property = gcr_certificate_renderer_set_property;
	gobject_class->get_property = gcr_certificate_renderer_get_property;

	g_object_class_install_property (gobject_class, PROP_CERTIFICATE,
	           g_param_spec_object("certificate", "Certificate", "Certificate to display.",
	                               GCR_TYPE_CERTIFICATE, G_PARAM_READWRITE));

	g_object_class_override_property (gobject_class, PROP_LABEL, "label");
	g_object_class_override_property (gobject_class, PROP_ATTRIBUTES, "attributes");

	_gcr_icons_register ();

	/* Register this as a renderer which can be loaded */
	registered = gck_attributes_new ();
	gck_attributes_add_ulong (registered, CKA_CLASS, CKO_CERTIFICATE);
	gcr_renderer_register (GCR_TYPE_CERTIFICATE_RENDERER, registered);
	gck_attributes_unref (registered);
}

static void
gcr_certificate_renderer_render (GcrRenderer *renderer, GcrViewer *viewer)
{
	GcrCertificateRenderer *self;
	gconstpointer data, value;
	gsize n_data, n_value, n_raw;
	GcrDisplayView *view;
	on_parsed_dn_args args;
	const gchar *text;
	gpointer raw;
	gulong version;
	guint bits, index;
	gchar *display;
	GNode *asn;
	GQuark oid;
	GDate date;

	self = GCR_CERTIFICATE_RENDERER (renderer);

	if (GCR_IS_DISPLAY_VIEW (viewer)) {
		view = GCR_DISPLAY_VIEW (viewer);

	} else {
		g_warning ("GcrCertificateRenderer only works with internal specific "
		           "GcrViewer returned by gcr_viewer_new().");
		return;
	}

	_gcr_display_view_clear (view, renderer);

	if (!self->pv->certificate)
		return;

	_gcr_display_view_set_stock_image (view, GCR_RENDERER (self), GCR_ICON_CERTIFICATE);

	data = gcr_certificate_get_der_data (self->pv->certificate, &n_data);
	g_return_if_fail (data);

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, "Certificate", data, n_data);
	g_return_if_fail (asn);

	display = calculate_label (self, asn);
	_gcr_display_view_append_title (view, renderer, display);
	g_free (display);

	display = egg_dn_read_part (egg_asn1x_node (asn, "tbsCertificate", "subject", "rdnSequence", NULL), "CN");
	_gcr_display_view_append_content (view, renderer, _("Identity"), display);
	g_free (display);

	display = egg_dn_read_part (egg_asn1x_node (asn, "tbsCertificate", "issuer", "rdnSequence", NULL), "CN");
	_gcr_display_view_append_content (view, renderer, _("Verified by"), display);
	g_free (display);

	if (egg_asn1x_get_time_as_date (egg_asn1x_node (asn, "tbsCertificate", "validity", "notAfter", NULL), &date)) {
		display = g_malloc0 (128);
		if (!g_date_strftime (display, 128, "%x", &date))
			g_return_if_reached ();
		_gcr_display_view_append_content (view, renderer, _("Expires"), display);
		g_free (display);
	}

	_gcr_display_view_start_details (view, renderer);

	args.renderer = self;
	args.view = view;

	/* The subject */
	_gcr_display_view_append_heading (view, renderer, _("Subject Name"));
	egg_dn_parse (egg_asn1x_node (asn, "tbsCertificate", "subject", "rdnSequence", NULL), on_parsed_dn_part, &args);

	/* The Issuer */
	_gcr_display_view_append_heading (view, renderer, _("Issuer Name"));
	egg_dn_parse (egg_asn1x_node (asn, "tbsCertificate", "issuer", "rdnSequence", NULL), on_parsed_dn_part, &args);

	/* The Issued Parameters */
	_gcr_display_view_append_heading (view, renderer, _("Issued Certificate"));

	if (!egg_asn1x_get_integer_as_ulong (egg_asn1x_node (asn, "tbsCertificate", "version", NULL), &version))
		g_return_if_reached ();
	display = g_strdup_printf ("%lu", version + 1);
	_gcr_display_view_append_value (view, renderer, _("Version"), display, FALSE);
	g_free (display);

	raw = egg_asn1x_get_integer_as_raw (egg_asn1x_node (asn, "tbsCertificate", "serialNumber", NULL), NULL, &n_raw);
	g_return_if_fail (raw);
	display = egg_hex_encode_full (raw, n_raw, TRUE, ' ', 1);
	_gcr_display_view_append_value (view, renderer, _("Serial Number"), display, TRUE);
	g_free (display);
	g_free (raw);

	display = g_malloc0 (128);
	if (egg_asn1x_get_time_as_date (egg_asn1x_node (asn, "tbsCertificate", "validity", "notBefore", NULL), &date)) {
		if (!g_date_strftime (display, 128, "%Y-%m-%d", &date))
			g_return_if_reached ();
		_gcr_display_view_append_value (view, renderer, _("Not Valid Before"), display, FALSE);
	}
	if (egg_asn1x_get_time_as_date (egg_asn1x_node (asn, "tbsCertificate", "validity", "notAfter", NULL), &date)) {
		if (!g_date_strftime (display, 128, "%Y-%m-%d", &date))
			g_return_if_reached ();
		_gcr_display_view_append_value (view, renderer, _("Not Valid After"), display, FALSE);
	}
	g_free (display);

	/* Signature */
	_gcr_display_view_append_heading (view, renderer, _("Signature"));

	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "signatureAlgorithm", "algorithm", NULL));
	text = egg_oid_get_description (oid);
	_gcr_display_view_append_value (view, renderer, _("Signature Algorithm"), text, FALSE);

	value = egg_asn1x_get_raw_element (egg_asn1x_node (asn, "signatureAlgorithm", "parameters", NULL), &n_value);
	if (value && n_value) {
		display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
		_gcr_display_view_append_value (view, renderer, _("Signature Parameters"), display, TRUE);
		g_free (display);
	}

	raw = egg_asn1x_get_bits_as_raw (egg_asn1x_node (asn, "signature", NULL), NULL, &bits);
	g_return_if_fail (raw);
	display = egg_hex_encode_full (raw, bits / 8, TRUE, ' ', 1);
	_gcr_display_view_append_value (view, renderer, _("Signature"), display, TRUE);
	g_free (display);
	g_free (raw);

	/* Public Key Info */
	_gcr_display_view_append_heading (view, renderer, _("Public Key Info"));

	oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (asn, "tbsCertificate", "subjectPublicKeyInfo",
	                                                  "algorithm", "algorithm", NULL));
	text = egg_oid_get_description (oid);
	_gcr_display_view_append_value (view, renderer, _("Key Algorithm"), text, FALSE);

	value = egg_asn1x_get_raw_element (egg_asn1x_node (asn, "tbsCertificate", "subjectPublicKeyInfo",
	                                                   "algorithm", "parameters", NULL), &n_value);
	if (value && n_value) {
		display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
		_gcr_display_view_append_value (view, renderer, _("Key Parameters"), display, TRUE);
		g_free (display);
	}

	bits = gcr_certificate_get_key_size (self->pv->certificate);
	if (bits > 0) {
		display = g_strdup_printf ("%u", bits);
		_gcr_display_view_append_value (view, renderer, _("Key Size"), display, FALSE);
		g_free (display);
	}

	raw = egg_asn1x_get_bits_as_raw (egg_asn1x_node (asn, "tbsCertificate", "subjectPublicKeyInfo",
	                                                 "subjectPublicKey", NULL), NULL, &bits);
	g_return_if_fail (raw);
	display = egg_hex_encode_full (raw, bits / 8, TRUE, ' ', 1);
	_gcr_display_view_append_value (view, renderer, _("Public Key"), display, TRUE);
	g_free (display);
	g_free (raw);

	/* Fingerprints */
	_gcr_display_view_append_heading (view, renderer, _("Fingerprints"));

	_gcr_display_view_append_fingerprint (view, renderer, data, n_data, "SHA1", G_CHECKSUM_SHA1);
	_gcr_display_view_append_fingerprint (view, renderer, data, n_data, "MD5", G_CHECKSUM_MD5);

	/* Extensions */
	for (index = 1; TRUE; ++index) {
		if (!append_extension (self, view, asn, data, n_data, index))
			break;
	}

	egg_asn1x_destroy (asn);
}

static void
gcr_certificate_renderer_populate_popup (GcrRenderer *self, GcrViewer *viewer,
                                         GtkMenu *menu)
{
	GtkWidget *item;

	item = gtk_separator_menu_item_new ();
	gtk_widget_show (item);
	gtk_menu_shell_prepend (GTK_MENU_SHELL (menu), item);

	item = gtk_menu_item_new_with_label ("Export Certificate...");
	gtk_widget_show (item);
	g_signal_connect_data (item, "activate", G_CALLBACK (on_certificate_export),
	                       g_object_ref (self), (GClosureNotify)g_object_unref, 0);
	gtk_menu_shell_prepend (GTK_MENU_SHELL (menu), item);
}

static void
gcr_renderer_iface_init (GcrRendererIface *iface)
{
	iface->render = gcr_certificate_renderer_render;
	iface->populate_popup = gcr_certificate_renderer_populate_popup;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GcrCertificateRenderer*
gcr_certificate_renderer_new (GcrCertificate *certificate)
{
	return g_object_new (GCR_TYPE_CERTIFICATE_RENDERER, "certificate", certificate, NULL);
}

GcrCertificate*
gcr_certificate_renderer_get_certificate (GcrCertificateRenderer *self)
{
	g_return_val_if_fail (GCR_IS_CERTIFICATE_RENDERER (self), NULL);
	return self->pv->certificate;
}

void
gcr_certificate_renderer_set_certificate (GcrCertificateRenderer *self, GcrCertificate *cert)
{
	g_return_if_fail (GCR_IS_CERTIFICATE_RENDERER (self));

	if (self->pv->certificate)
		g_object_unref (self->pv->certificate);
	self->pv->certificate = cert;
	if (self->pv->certificate)
		g_object_ref (self->pv->certificate);

	gcr_renderer_emit_data_changed (GCR_RENDERER (self));
	g_object_notify (G_OBJECT (self), "certificate");
}

GckAttributes*
gcr_certificate_renderer_get_attributes (GcrCertificateRenderer *self)
{
	g_return_val_if_fail (GCR_IS_CERTIFICATE_RENDERER (self), NULL);
	return self->pv->attributes;
}

void
gcr_certificate_renderer_set_attributes (GcrCertificateRenderer *self, GckAttributes *attrs)
{
	GcrCertificate *cert;
	GckAttribute *attr;
	gboolean emit = TRUE;

	g_return_if_fail (GCR_IS_CERTIFICATE_RENDERER (self));

	gck_attributes_unref (self->pv->attributes);
	self->pv->attributes = attrs;\

	if (self->pv->attributes) {
		gck_attributes_ref (self->pv->attributes);
		attr = gck_attributes_find (self->pv->attributes, CKA_VALUE);
		if (attr) {
			/* Create a new certificate object refferring to same memory */
			cert = gcr_simple_certificate_new_static (attr->value, attr->length);
			g_object_set_data_full (G_OBJECT (cert), "attributes",
			                        gck_attributes_ref (self->pv->attributes),
			                        (GDestroyNotify)gck_attributes_unref);
			gcr_certificate_renderer_set_certificate (self, cert);
			g_object_unref (cert);
			emit = FALSE;
		} else {
			gcr_certificate_renderer_set_certificate (self, NULL);
		}
	}

	if (emit)
		gcr_renderer_emit_data_changed (GCR_RENDERER (self));

}
