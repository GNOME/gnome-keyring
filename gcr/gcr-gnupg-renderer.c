/*
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

#include "gcr-display-view.h"
#include "gcr-icons.h"
#include "gcr-gnupg-records.h"
#include "gcr-gnupg-renderer.h"
#include "gcr-openpgp.h"
#include "gcr-simple-certificate.h"
#include "gcr-renderer.h"
#include "gcr-types.h"

#include "gck/gck.h"

#include "egg/egg-hex.h"

#include <gdk/gdk.h>
#include <glib/gi18n-lib.h>

#include <stdlib.h>

enum {
	PROP_0,
	PROP_RECORDS,
	PROP_LABEL,
	PROP_ATTRIBUTES
};

struct _GcrGnupgRendererPrivate {
	GPtrArray *records;
	GckAttributes *attrs;
	gchar *label;
};

static void _gcr_gnupg_renderer_iface_init (GcrRendererIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrGnupgRenderer, _gcr_gnupg_renderer, G_TYPE_OBJECT,
	G_IMPLEMENT_INTERFACE (GCR_TYPE_RENDERER, _gcr_gnupg_renderer_iface_init);
);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar *
calculate_label (GcrGnupgRenderer *self)
{
	gchar *userid;
	gchar *label;

	if (self->pv->attrs) {
		if (gck_attributes_find_string (self->pv->attrs, CKA_LABEL, &label))
			return label;
	}

	userid = _gcr_gnupg_records_get_user_id (self->pv->records);
	if (userid != NULL) {
		if (!_gcr_gnupg_records_parse_user_id (userid, &label, NULL, NULL))
			label = NULL;
	}

	if (label != NULL)
		return label;

	if (self->pv->label)
		return g_strdup (self->pv->label);

	return g_strdup (_("PGP Key"));
}

static void
_gcr_gnupg_renderer_init (GcrGnupgRenderer *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_GNUPG_RENDERER,
	                                         GcrGnupgRendererPrivate));
}

static void
_gcr_gnupg_renderer_finalize (GObject *obj)
{
	GcrGnupgRenderer *self = GCR_GNUPG_RENDERER (obj);

	gck_attributes_unref (self->pv->attrs);
	g_free (self->pv->label);
	if (self->pv->records)
		g_ptr_array_unref (self->pv->records);

	G_OBJECT_CLASS (_gcr_gnupg_renderer_parent_class)->finalize (obj);
}

static void
_gcr_gnupg_renderer_set_property (GObject *obj,
                                  guint prop_id,
                                  const GValue *value,
                                  GParamSpec *pspec)
{
	GcrGnupgRenderer *self = GCR_GNUPG_RENDERER (obj);

	switch (prop_id) {
	case PROP_RECORDS:
		_gcr_gnupg_renderer_set_records (self, g_value_get_boxed (value));
		break;
	case PROP_LABEL:
		g_free (self->pv->label);
		self->pv->label = g_value_dup_string (value);
		g_object_notify (obj, "label");
		gcr_renderer_emit_data_changed (GCR_RENDERER (self));
		break;
	case PROP_ATTRIBUTES:
		_gcr_gnupg_renderer_set_attributes (self, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_gnupg_renderer_get_property (GObject *obj,
                                  guint prop_id,
                                  GValue *value,
                                  GParamSpec *pspec)
{
	GcrGnupgRenderer *self = GCR_GNUPG_RENDERER (obj);

	switch (prop_id) {
	case PROP_RECORDS:
		g_value_set_object (value, self->pv->records);
		break;
	case PROP_LABEL:
		g_value_take_string (value, calculate_label (self));
		break;
	case PROP_ATTRIBUTES:
		g_value_set_boxed (value, self->pv->attrs);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_gnupg_renderer_class_init (GcrGnupgRendererClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckAttributes *registered;

	_gcr_gnupg_renderer_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GcrGnupgRendererPrivate));

	gobject_class->finalize = _gcr_gnupg_renderer_finalize;
	gobject_class->set_property = _gcr_gnupg_renderer_set_property;
	gobject_class->get_property = _gcr_gnupg_renderer_get_property;

	g_object_class_install_property (gobject_class, PROP_RECORDS,
	           g_param_spec_boxed ("records", "Records", "Gnupg records to display",
	                               G_TYPE_PTR_ARRAY, G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_ATTRIBUTES,
	           g_param_spec_boxed ("attributes", "Attributes", "Certificate pkcs11 attributes",
	                               GCK_TYPE_ATTRIBUTES, G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_LABEL,
	           g_param_spec_string ("label", "Label", "Certificate Label",
	                                "", G_PARAM_READWRITE));

	/* Register this as a renderer which can be loaded */
	registered = gck_attributes_new ();
	gck_attributes_add_ulong (registered, CKA_CLASS, CKO_GCR_GNUPG_RECORDS);
	gcr_renderer_register (GCR_TYPE_GNUPG_RENDERER, registered);
	gck_attributes_unref (registered);
}

static const gchar *
name_for_algo (guint algo)
{
	switch (algo)
	{
	case GCR_OPENPGP_ALGO_RSA:
	case GCR_OPENPGP_ALGO_RSA_E:
	case GCR_OPENPGP_ALGO_RSA_S:
		return _("RSA");
	case GCR_OPENPGP_ALGO_ELG_E:
		return _("Elgamal");
	case GCR_OPENPGP_ALGO_DSA:
		return _("DSA");
	default:
		return NULL;
	}
}

static const gchar *
capability_for_code (gchar code)
{
	switch (code) {
	case 'e': case 'E':
		return _("Encrypt");
	case 's': case 'S':
		return _("Sign");
	case 'c': case 'C':
		return _("Certify");
	case 'a': case 'A':
		return _("Authenticate");
	case 'D':
		return _("Disabled");
	default:
		return NULL;
	}
}

static gchar *
capabilities_for_codes (const gchar *codes)
{
	const gchar *cap;
	GString *result;
	guint i;

	result = g_string_new ("");
	for (i = 0; codes[i] != 0; i++) {
		if (result->len)
			g_string_append_unichar (result, GCR_DISPLAY_VIEW_LINE_BREAK);
		cap = capability_for_code (codes[i]);
		if (cap != NULL)
			g_string_append (result, cap);
		else
			g_string_append_c (result, codes[i]);
	}
	return g_string_free (result, FALSE);
}

static const gchar *
status_for_code (gchar code)
{
	switch (code) {
	case 'o':
		return _("Unknown");
	case 'i':
		return _("Invalid");
	case 'd':
		return _("Disabled");
	case 'r':
		return _("Revoked");
	case 'e':
		return _("Expired");
	case 'q': case '-':
		return _("Undefined trust");
	case 'n':
		return _("Distrusted");
	case 'm':
		return _("Marginally trusted");
	case 'f':
		return _("Fully trusted");
	case 'u':
		return _("Ultimately trusted");
	default:
		return NULL;
	}
}

#ifdef TODO
static const gchar *
description_for_code (gchar code, gboolean *warning)
{
	*warning = FALSE;
	switch (code) {
	case 'o':
		*warning = TRUE;
		return _("This key has not been verified");
	case 'i':
		*warning = TRUE;
		return _("This key is invalid");
	case 'd':
		*warning = TRUE;
		return _("This key has been disabled");
	case 'r':
		*warning = TRUE;
		return _("This key has been revoked");
	case 'e':
		*warning = TRUE;
		return _("This key has expired");
	case 'q': case '-':
		return _("The trust in this key is undefined");
	case 'n':
		*warning = TRUE;
		return _("This key is distrusted");
	case 'm':
		return _("Marginally trusted");
	case 'f':
		return _("Fully trusted");
	case 'u':
		return _("Ultimately trusted");
	default:
		return NULL;
	}
}
#endif

static void
append_key_record (GcrGnupgRenderer *self,
                   GcrDisplayView *view,
                   GcrRecord *record,
                   const gchar *title)
{
	GcrRenderer *renderer = GCR_RENDERER (self);
	const gchar *value;
	gchar *display;
	GDateTime *date;
	gchar code;
	guint algo;
	guint bits;

	_gcr_display_view_append_heading (view, renderer, title);

	/* Key ID */
	value = _gcr_record_get_raw (record, GCR_RECORD_KEY_KEYID);
	if (value != NULL)
		_gcr_display_view_append_value (view, renderer, _("Key ID"), value, TRUE);

	/* Algorithm */
	if (_gcr_record_get_uint (record, GCR_RECORD_KEY_ALGO, &algo)) {
		display = NULL;
		value = name_for_algo (algo);
		if (value == NULL)
			value = display = g_strdup_printf ("%u", algo);
		_gcr_display_view_append_value (view, renderer, _("Algorithm"), value, FALSE);
		g_free (display);
	}

	/* Key Size */
	if (_gcr_record_get_uint (record, GCR_RECORD_KEY_BITS, &bits)) {
		display = g_strdup_printf ("%u", bits);
		_gcr_display_view_append_value (view, renderer, _("Key Size"), display, FALSE);
		g_free (display);
	}

	/* Created */
	date = _gcr_record_get_date (record, GCR_RECORD_KEY_TIMESTAMP);
	if (date != NULL) {
		display = g_date_time_format (date, "%x");
		_gcr_display_view_append_value (view, renderer, _("Created"), display, FALSE);
		g_free (display);
		g_date_time_unref (date);
	}

	/* Expiry */
	date = _gcr_record_get_date (record, GCR_RECORD_KEY_EXPIRY);
	if (date != NULL) {
		display = g_date_time_format (date, "%x");
		_gcr_display_view_append_value (view, renderer, _("Expiry"), display, FALSE);
		g_free (display);
		g_date_time_unref (date);
	}

	/* Capabilities */
	value = _gcr_record_get_raw (record, GCR_RECORD_PUB_CAPS);
	if (value != NULL) {
		display = capabilities_for_codes (value);
		_gcr_display_view_append_value (view, renderer, _("Capabilities"), display, FALSE);
		g_free (display);
	}

	/* Owner Trust */
	code = _gcr_record_get_char (record, GCR_RECORD_KEY_OWNERTRUST);
	if (code != 0) {
		display = NULL;
		value = status_for_code (code);
		if (value == NULL) {
			value = display = g_new0 (gchar, 2);
			display[0] = code;
		}
		_gcr_display_view_append_value (view, renderer, _("Owner trust"), value, FALSE);
		g_free (display);
	}
}

static void
append_uid_record (GcrGnupgRenderer *self,
                   GcrDisplayView *view,
                   GcrRecord *record)
{
	GcrRenderer *renderer = GCR_RENDERER (self);
	gchar *userid;
	gchar *name;
	gchar *comment;
	gchar *email;
	GDateTime *date;
	gchar *display;

	_gcr_display_view_append_heading (view, renderer, _("User ID"));

	userid = _gcr_record_get_string (record, GCR_RECORD_UID_USERID);
	if (userid == NULL) {
		_gcr_display_view_append_value (view, renderer, _("Value"), _("Unknown"), FALSE);
		return;
	}

	if (_gcr_gnupg_records_parse_user_id (userid, &name, &email, &comment)) {
		if (name != NULL)
			_gcr_display_view_append_value (view, renderer, _("Name"), name, FALSE);
		g_free (name);
		if (email != NULL)
			_gcr_display_view_append_value (view, renderer, _("Email"), email, FALSE);
		g_free (email);
		if (comment != NULL)
			_gcr_display_view_append_value (view, renderer, _("Comment"), comment, FALSE);
		g_free (comment);

	/* Unparseable user id */
	} else {
		_gcr_display_view_append_value (view, renderer, _("Value"), userid, FALSE);
	}

	/* Created */
	date = _gcr_record_get_date (record, GCR_RECORD_UID_TIMESTAMP);
	if (date != NULL) {
		display = g_date_time_format (date, "%x");
		_gcr_display_view_append_value (view, renderer, _("Created"), display, FALSE);
		g_free (display);
		g_date_time_unref (date);
	}

	/* Expiry */
	date = _gcr_record_get_date (record, GCR_RECORD_UID_EXPIRY);
	if (date != NULL) {
		display = g_date_time_format (date, "%x");
		_gcr_display_view_append_value (view, renderer, _("Expiry"), display, FALSE);
		g_free (display);
		g_date_time_unref (date);
	}

	g_free (userid);
}

static void
append_uat_record (GcrGnupgRenderer *self,
                   GcrDisplayView *view,
                   GcrRecord *record)
{
	GcrRenderer *renderer = GCR_RENDERER (self);
	gchar **parts;
	gchar *display;
	const gchar *value;
	GDateTime *date;

	_gcr_display_view_append_heading (view, renderer, _("User Attribute"));

	/* Size */
	value = _gcr_record_get_raw (record, GCR_RECORD_UAT_COUNT_SIZE);
	if (value != NULL) {
		parts = g_strsplit (value, " ", 2);
		if (parts && parts[0] && parts[1])
			_gcr_display_view_append_value (view, renderer, _("Size"), parts[1], FALSE);
		g_strfreev (parts);
	}

	/* Created */
	date = _gcr_record_get_date (record, GCR_RECORD_KEY_TIMESTAMP);
	if (date != NULL) {
		display = g_date_time_format (date, "%x");
		_gcr_display_view_append_value (view, renderer, _("Created"), display, FALSE);
		g_free (display);
		g_date_time_unref (date);
	}

	/* Expiry */
	date = _gcr_record_get_date (record, GCR_RECORD_KEY_EXPIRY);
	if (date != NULL) {
		display = g_date_time_format (date, "%x");
		_gcr_display_view_append_value (view, renderer, _("Expiry"), display, FALSE);
		g_free (display);
		g_date_time_unref (date);
	}
}

static const gchar *
signature_klass_string (const gchar *klass)
{
	char *end;
	guint val;

	val = strtoul (klass, &end, 16);
	if (end != klass + 2)
		return NULL;

	switch (val) {
	case 0x00:
		return _("Signature of a binary document");
	case 0x01:
		return _("Signature of a canonical text document");
	case 0x02:
		return _("Standalone signature");
	case 0x10:
		return _("Generic certification of key");
	case 0x11:
		return _("Persona certification of key");
	case 0x12:
		return _("Casual certification of key");
	case 0x13:
		return _("Positive certification of key");
	case 0x18:
		return _("Subkey binding signature");
	case 0x19:
		return _("Primary key binding signature");
	case 0x1F:
		return _("Signature directly on key");
	case 0x20:
		return _("Key revocation signature");
	case 0x28:
		return _("Subkey revocation signature");
	case 0x30:
		return _("Certification revocation signature");
	case 0x40:
		return _("Timestamp signature");
	case 0x50:
		return _("Third-party confirmation signature");
	default:
		return NULL;
	}
}

static void
append_sig_record (GcrGnupgRenderer *self,
                   GcrDisplayView *view,
                   GcrRecord *record,
                   const gchar *keyid)
{
	GcrRenderer *renderer = GCR_RENDERER (self);
	const gchar *sigid;
	gchar *display;
	const gchar *value;
	const gchar *klass;
	guint algo;

	/* Hide self-signatures. There's so many of them */
	sigid = _gcr_record_get_raw (record, GCR_RECORD_SIG_KEYID);
	if (sigid && keyid && g_str_equal (sigid, keyid))
		return;

	_gcr_display_view_append_heading (view, renderer, _("Signature"));

	/* Key ID */
	if (sigid != NULL)
		_gcr_display_view_append_value (view, renderer, _("Key ID"), sigid, TRUE);

	/* Algorithm */
	if (_gcr_record_get_uint (record, GCR_RECORD_SIG_ALGO, &algo)) {
		display = NULL;
		value = name_for_algo (algo);
		if (value == NULL)
			value = display = g_strdup_printf ("%u", algo);
		_gcr_display_view_append_value (view, renderer, _("Algorithm"), value, FALSE);
		g_free (display);
	}

	/* User ID */
	display = _gcr_record_get_string (record, GCR_RECORD_SIG_USERID);
	if (display != NULL)
		_gcr_display_view_append_value (view, renderer, _("User ID"), display, FALSE);
	g_free (display);

	/* Signature class */
	klass = _gcr_record_get_raw (record, GCR_RECORD_SIG_CLASS);
	if (klass != NULL) {
		value = NULL;
		if (strlen (klass) >= 2) {
			value = signature_klass_string (klass);
			if (value != NULL) {
				_gcr_display_view_append_value (view, renderer, _("Class"), value, FALSE);
				if (klass[2] == 'l')
					_gcr_display_view_append_value (view, renderer, _("Type"), _("Local only"), FALSE);
				else if (klass[2] == 'x')
					_gcr_display_view_append_value (view, renderer, _("Type"), _("Exportable"), FALSE);
			}
		}
		if (value == NULL)
			_gcr_display_view_append_value (view, renderer, _("Class"), klass, FALSE);
	}
}

static void
append_rvk_record (GcrGnupgRenderer *self,
                   GcrDisplayView *view,
                   GcrRecord *record)
{
	GcrRenderer *renderer = GCR_RENDERER (self);
	const gchar *value;
	gchar *display;
	guint algo;

	_gcr_display_view_append_heading (view, renderer, _("Revocation Key"));

	/* Algorithm */
	if (_gcr_record_get_uint (record, GCR_RECORD_RVK_ALGO, &algo)) {
		display = NULL;
		value = name_for_algo (algo);
		if (value == NULL)
			value = display = g_strdup_printf ("%u", algo);
		_gcr_display_view_append_value (view, renderer, _("Algorithm"), value, FALSE);
		g_free (display);
	}

	value = _gcr_record_get_raw (record, GCR_RECORD_RVK_FINGERPRINT);
	if (value != NULL)
		_gcr_display_view_append_value (view, renderer, _("Fingerprint"), value, TRUE);
}

static void
append_fpr_record (GcrGnupgRenderer *self,
                   GcrDisplayView *view,
                   GcrRecord *record,
                   GQuark last_schema)
{
	GcrRenderer *renderer = GCR_RENDERER (self);
	const gchar *value;
	gpointer raw;
	gsize n_raw;

	if (last_schema != GCR_RECORD_SCHEMA_PUB &&
	    last_schema != GCR_RECORD_SCHEMA_SUB &&
	    last_schema != GCR_RECORD_SCHEMA_SEC &&
	    last_schema != GCR_RECORD_SCHEMA_SSB)
		return;

	value = _gcr_record_get_raw (record, GCR_RECORD_FPR_FINGERPRINT);
	if (value != NULL) {
		raw = egg_hex_decode (value, -1, &n_raw);
		if (raw != NULL)
			_gcr_display_view_append_hex (view, renderer, _("Fingerprint"), raw, n_raw);
		else
			_gcr_display_view_append_value (view, renderer, _("Fingerprint"), value, TRUE);
		g_free (raw);
	}
}

static void
_gcr_gnupg_renderer_render (GcrRenderer *renderer,
                            GcrViewer *viewer)
{
	GcrGnupgRenderer *self;
	GcrDisplayView *view;
	GDateTime *date;
	const gchar *value;
	gchar *display;
	gchar *userid;
	gchar *email;
	gchar *comment;
	GIcon *icon;
	GQuark schema;
	GQuark last_schema;
	gchar code;
	guint i;

	self = GCR_GNUPG_RENDERER (renderer);

	if (GCR_IS_DISPLAY_VIEW (viewer)) {
		view = GCR_DISPLAY_VIEW (viewer);

	} else {
		g_warning ("GcrGnupgRenderer only works with internal specific "
		           "GcrViewer returned by gcr_viewer_new().");
		return;
	}

	_gcr_display_view_begin (view, renderer);

	if (self->pv->records == NULL || self->pv->records->len == 0) {
		_gcr_display_view_end (view, renderer);
		return;
	}

	icon = _gcr_gnupg_records_get_icon (self->pv->records);
	_gcr_display_view_set_icon (view, GCR_RENDERER (self), icon);
	g_object_unref (icon);

	display = calculate_label (self);
	_gcr_display_view_append_title (view, renderer, display);
	g_free (display);

	userid = _gcr_gnupg_records_get_user_id (self->pv->records);
	if (userid != NULL) {
		if (_gcr_gnupg_records_parse_user_id (userid, NULL, &email, &comment)) {
			if (email != NULL)
				_gcr_display_view_append_content (view, renderer, _("Email"), email);
			g_free (email);
			if (comment != NULL)
				_gcr_display_view_append_content (view, renderer, _("Comment"), comment);
			g_free (comment);
		}
		g_free (userid);
	}

	value = _gcr_gnupg_records_get_short_keyid (self->pv->records);
	if (value != NULL)
		_gcr_display_view_append_content (view, renderer, _("Key ID"), value);

	code = _gcr_record_get_char (self->pv->records->pdata[0], GCR_RECORD_TRUST);
	if (code != 'e') {
		date = _gcr_record_get_date (self->pv->records->pdata[0], GCR_RECORD_KEY_EXPIRY);
		if (date != NULL) {
			display = g_date_time_format (date, "%x");
			_gcr_display_view_append_content (view, renderer, _("Expires"), display);
			g_date_time_unref (date);
			g_free (display);
		}
	}

	/* TODO: Warning */


	_gcr_display_view_start_details (view, renderer);

	value = _gcr_gnupg_records_get_keyid (self->pv->records);
	last_schema = 0;

	for (i = 0; i < self->pv->records->len; i++) {
		schema = _gcr_record_get_schema (self->pv->records->pdata[i]);
		if (schema == GCR_RECORD_SCHEMA_PUB)
			append_key_record (self, view, self->pv->records->pdata[i], _("Public Key"));
		else if (schema == GCR_RECORD_SCHEMA_SUB)
			append_key_record (self, view, self->pv->records->pdata[i], _("Public Subkey"));
		else if (schema == GCR_RECORD_SCHEMA_SEC)
			append_key_record (self, view, self->pv->records->pdata[i], _("Secret Key"));
		else if (schema == GCR_RECORD_SCHEMA_SSB)
			append_key_record (self, view, self->pv->records->pdata[i], _("Secret Subkey"));
		else if (schema == GCR_RECORD_SCHEMA_UID)
			append_uid_record (self, view, self->pv->records->pdata[i]);
		else if (schema == GCR_RECORD_SCHEMA_UAT)
			append_uat_record (self, view, self->pv->records->pdata[i]);
		else if (schema == GCR_RECORD_SCHEMA_SIG)
			append_sig_record (self, view, self->pv->records->pdata[i], value);
		else if (schema == GCR_RECORD_SCHEMA_RVK)
			append_rvk_record (self, view, self->pv->records->pdata[i]);
		else if (schema == GCR_RECORD_SCHEMA_FPR)
			append_fpr_record (self, view, self->pv->records->pdata[i], last_schema);
		last_schema = schema;
	}

	_gcr_display_view_end (view, renderer);
}

static void
_gcr_gnupg_renderer_iface_init (GcrRendererIface *iface)
{
	iface->render_view = _gcr_gnupg_renderer_render;
}

GcrGnupgRenderer *
_gcr_gnupg_renderer_new (GPtrArray *records)
{
	g_return_val_if_fail (records != NULL, NULL);

	return g_object_new (GCR_TYPE_GNUPG_RENDERER,
	                     "records", records,
	                     NULL);
}

GcrGnupgRenderer *
_gcr_gnupg_renderer_new_for_attributes (const gchar *label,
                                        GckAttributes *attrs)
{
	g_return_val_if_fail (attrs != NULL, NULL);

	return g_object_new (GCR_TYPE_GNUPG_RENDERER,
	                     "label", label,
	                     "attributes", attrs,
	                     NULL);
}

GPtrArray *
_gcr_gnupg_renderer_get_records (GcrGnupgRenderer *self)
{
	g_return_val_if_fail (GCR_IS_GNUPG_RENDERER (self), NULL);
	return self->pv->records;
}

void
_gcr_gnupg_renderer_set_records (GcrGnupgRenderer *self,
                                 GPtrArray *records)
{
	g_return_if_fail (GCR_IS_GNUPG_RENDERER (self));

	if (records)
		g_ptr_array_ref (records);
	if (self->pv->records)
		g_ptr_array_unref (self->pv->records);
	self->pv->records = records;

	if (self->pv->attrs) {
		gck_attributes_unref (self->pv->attrs);
		self->pv->attrs = NULL;
		g_object_notify (G_OBJECT (self), "attributes");
	}

	gcr_renderer_emit_data_changed (GCR_RENDERER (self));
	g_object_notify (G_OBJECT (self), "records");
}

GckAttributes*
_gcr_gnupg_renderer_get_attributes (GcrGnupgRenderer *self)
{
	g_return_val_if_fail (GCR_IS_GNUPG_RENDERER (self), NULL);
	return self->pv->attrs;
}

void
_gcr_gnupg_renderer_set_attributes (GcrGnupgRenderer *self,
                                    GckAttributes *attrs)
{
	GckAttribute *attr;
	GPtrArray *records;

	g_return_if_fail (GCR_IS_GNUPG_RENDERER (self));

	attr = gck_attributes_find (attrs, CKA_VALUE);
	g_return_if_fail (attr != NULL);
	records = _gcr_records_parse_colons (attr->value, attr->length);
	g_return_if_fail (records != NULL);

	if (attrs)
		gck_attributes_ref (attrs);
	gck_attributes_unref (self->pv->attrs);
	self->pv->attrs = attrs;

	if (self->pv->records)
		g_ptr_array_unref (self->pv->records);
	self->pv->records = records;
	g_object_notify (G_OBJECT (self), "records");

	gcr_renderer_emit_data_changed (GCR_RENDERER (self));
	g_object_notify (G_OBJECT (self), "attributes");

}
