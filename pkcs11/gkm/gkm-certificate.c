/*
 * gnome-keyring
 *
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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkm-attributes.h"
#include "gkm-certificate.h"
#include "gkm-certificate-key.h"
#include "gkm-crypto.h"
#include "gkm-data-asn1.h"
#include "gkm-data-der.h"
#define DEBUG_FLAG GKM_DEBUG_STORAGE
#include "gkm-debug.h"
#include "gkm-factory.h"
#include "gkm-sexp-key.h"
#include "gkm-manager.h"
#include "gkm-session.h"
#include "gkm-sexp.h"
#include "gkm-serializable.h"
#include "gkm-transaction.h"
#include "gkm-util.h"

#include "egg/egg-dn.h"
#include "egg/egg-asn1x.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11i.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_LABEL,
	PROP_PUBLIC_KEY
};

struct _GkmCertificatePrivate {
	GkmCertificateKey *key;
	GNode *asn1;
	GBytes *der;
	gchar *label;
};

static GQuark OID_BASIC_CONSTRAINTS;
static GQuark OID_ENHANCED_USAGE;

static void gkm_certificate_serializable (GkmSerializableIface *iface);

G_DEFINE_TYPE_EXTENDED (GkmCertificate, gkm_certificate, GKM_TYPE_OBJECT, 0,
               G_ADD_PRIVATE (GkmCertificate)
               G_IMPLEMENT_INTERFACE (GKM_TYPE_SERIALIZABLE, gkm_certificate_serializable));

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
init_quarks (void)
{
	static gsize quarks_inited = 0;

	if (g_once_init_enter (&quarks_inited)) {
		#define QUARK(name, value) \
			name = g_quark_from_static_string(value)

		QUARK (OID_BASIC_CONSTRAINTS, "2.5.29.19");
		QUARK (OID_ENHANCED_USAGE, "2.5.29.37");

		#undef QUARK

		g_once_init_leave (&quarks_inited, 1);
	}
}

static gint
find_certificate_extension (GkmCertificate *self, GQuark oid)
{
	GQuark exoid;
	GNode *node;
	guint index;

	g_assert (oid);
	g_assert (GKM_IS_CERTIFICATE (self));
	g_assert (self->pv->asn1);

	for (index = 1; TRUE; ++index) {

		/* Make sure it is present */
		node = egg_asn1x_node (self->pv->asn1, "tbsCertificate", "extensions", index, NULL);
		if (node == NULL)
			break;

		/* See if it's the same */
		exoid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (node, "extnID", NULL));

		if(exoid == oid)
			return index;
	}

	return 0;
}

static GkmObject*
factory_create_certificate (GkmSession *session, GkmTransaction *transaction,
                            CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	CK_ATTRIBUTE_PTR attr;
	GkmCertificate *cert;
	GBytes *bytes;
	gboolean ret;

	g_return_val_if_fail (GKM_IS_TRANSACTION (transaction), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);

	/* Dig out the value */
	attr = gkm_attributes_find (attrs, n_attrs, CKA_VALUE);
	if (attr == NULL) {
		gkm_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
		return NULL;
	}

	cert = g_object_new (GKM_TYPE_CERTIFICATE,
	                     "module", gkm_session_get_module (session),
	                     "manager", gkm_manager_for_template (attrs, n_attrs, session),
	                     NULL);

	/* Load the certificate from the data specified */
	bytes = g_bytes_new (attr->pValue, attr->ulValueLen);
	ret = gkm_serializable_load (GKM_SERIALIZABLE (cert), NULL, bytes);
	g_bytes_unref (bytes);

	if(!ret) {
		gkm_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
		g_object_unref (cert);
		return NULL;
	}

	/* We calculate these attributes automatically */
	gkm_attributes_consume (attrs, n_attrs,
	                        CKA_VALUE, CKA_SUBJECT, CKA_SERIAL_NUMBER, CKA_ID,
	                        G_MAXULONG);

	gkm_session_complete_object_creation (session, transaction, GKM_OBJECT (cert),
	                                      TRUE, attrs, n_attrs);
	return GKM_OBJECT (cert);
}

/* -----------------------------------------------------------------------------
 * KEY
 */

static CK_RV
gkm_certificate_real_get_attribute (GkmObject *base, GkmSession *session, CK_ATTRIBUTE* attr)
{
	GkmCertificate *self = GKM_CERTIFICATE (base);
	CK_ULONG category;
	GBytes *cdata;
	guchar *data;
	gsize n_data;
	time_t when;
	CK_RV rv;

	switch (attr->type) {

	case CKA_CLASS:
		return gkm_attribute_set_ulong (attr, CKO_CERTIFICATE);

	case CKA_PRIVATE:
		return gkm_attribute_set_bool (attr, FALSE);

	case CKA_LABEL:
		return gkm_attribute_set_string (attr, gkm_certificate_get_label (self));

	case CKA_CERTIFICATE_TYPE:
		return gkm_attribute_set_ulong (attr, CKC_X_509);

	case CKA_TRUSTED:
		return gkm_attribute_set_bool (attr, FALSE);

	case CKA_CERTIFICATE_CATEGORY:
		if (!gkm_certificate_calc_category (self, session, &category))
			return CKR_FUNCTION_FAILED;
		return gkm_attribute_set_ulong (attr, category);

	case CKA_CHECK_VALUE:
		g_return_val_if_fail (self->pv->der != NULL, CKR_GENERAL_ERROR);
		n_data = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
		g_return_val_if_fail (n_data && n_data > 3, CKR_GENERAL_ERROR);
		data = g_new0 (guchar, n_data);
		gcry_md_hash_buffer (GCRY_MD_SHA1, data,
		                     g_bytes_get_data (self->pv->der, NULL),
		                     g_bytes_get_size (self->pv->der));
		rv = gkm_attribute_set_data (attr, data, 3);
		g_free (data);
		return rv;

	case CKA_START_DATE:
	case CKA_END_DATE:
		g_return_val_if_fail (self->pv->asn1, CKR_GENERAL_ERROR);
		when = egg_asn1x_get_time_as_long (egg_asn1x_node (self->pv->asn1,
		                                                   "tbsCertificate", "validity",
		                                                   attr->type == CKA_START_DATE ? "notBefore" : "notAfter",
		                                                   NULL));
		if (when < 0)
			return CKR_FUNCTION_FAILED;
		return gkm_attribute_set_date (attr, when);

	case CKA_SUBJECT:
		g_return_val_if_fail (self->pv->asn1, CKR_GENERAL_ERROR);
		cdata = egg_asn1x_get_element_raw (egg_asn1x_node (self->pv->asn1, "tbsCertificate", "subject", NULL));
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		rv = gkm_attribute_set_bytes (attr, cdata);
		g_bytes_unref (cdata);
		return rv;

	case CKA_ID:
		if (!self->pv->key)
			return gkm_attribute_set_data (attr, NULL, 0);
		return gkm_object_get_attribute (GKM_OBJECT (self->pv->key), session, attr);

	case CKA_ISSUER:
		g_return_val_if_fail (self->pv->asn1, CKR_GENERAL_ERROR);
		cdata = egg_asn1x_get_element_raw (egg_asn1x_node (self->pv->asn1, "tbsCertificate", "issuer", NULL));
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		rv = gkm_attribute_set_bytes (attr, cdata);
		g_bytes_unref (cdata);
		return rv;

	case CKA_SERIAL_NUMBER:
		g_return_val_if_fail (self->pv->asn1, CKR_GENERAL_ERROR);
		cdata = egg_asn1x_get_element_raw (egg_asn1x_node (self->pv->asn1, "tbsCertificate", "serialNumber", NULL));
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		rv = gkm_attribute_set_bytes (attr, cdata);
		g_bytes_unref (cdata);
		return rv;

	case CKA_VALUE:
		g_return_val_if_fail (self->pv->der != NULL, CKR_GENERAL_ERROR);
		return gkm_attribute_set_bytes (attr, self->pv->der);

	/* These are only used for strange online certificates which we don't support */
	case CKA_URL:
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		return gkm_attribute_set_data (attr, "", 0);

	/* What in the world is this doing in the spec? */
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
		return gkm_attribute_set_ulong (attr, 0); /* 0 = unspecified */
	};

	return GKM_OBJECT_CLASS (gkm_certificate_parent_class)->get_attribute (base, session, attr);
}

static GObject*
gkm_certificate_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkmCertificate *self = GKM_CERTIFICATE (G_OBJECT_CLASS (gkm_certificate_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);


	return G_OBJECT (self);
}

static void
gkm_certificate_init (GkmCertificate *self)
{
	self->pv = gkm_certificate_get_instance_private (self);

}

static void
gkm_certificate_dispose (GObject *obj)
{
	GkmCertificate *self = GKM_CERTIFICATE (obj);

	if (self->pv->key)
		g_object_unref (self->pv->key);
	self->pv->key = NULL;

	G_OBJECT_CLASS (gkm_certificate_parent_class)->dispose (obj);
}

static void
gkm_certificate_finalize (GObject *obj)
{
	GkmCertificate *self = GKM_CERTIFICATE (obj);

	g_assert (!self->pv->key);
	if (self->pv->der)
		g_bytes_unref (self->pv->der);
	g_free (self->pv->label);
	egg_asn1x_destroy (self->pv->asn1);

	G_OBJECT_CLASS (gkm_certificate_parent_class)->finalize (obj);
}

static void
gkm_certificate_set_property (GObject *obj, guint prop_id, const GValue *value,
                              GParamSpec *pspec)
{
	GkmCertificate *self = GKM_CERTIFICATE (obj);

	switch (prop_id) {
	case PROP_LABEL:
		gkm_certificate_set_label (self, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkm_certificate_get_property (GObject *obj, guint prop_id, GValue *value,
                              GParamSpec *pspec)
{
	GkmCertificate *self = GKM_CERTIFICATE (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_set_string (value, gkm_certificate_get_label (self));
		break;
	case PROP_PUBLIC_KEY:
		g_value_set_object (value, gkm_certificate_get_public_key (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkm_certificate_class_init (GkmCertificateClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkmObjectClass *gkm_class = GKM_OBJECT_CLASS (klass);

	gobject_class->constructor = gkm_certificate_constructor;
	gobject_class->dispose = gkm_certificate_dispose;
	gobject_class->finalize = gkm_certificate_finalize;
	gobject_class->set_property = gkm_certificate_set_property;
	gobject_class->get_property = gkm_certificate_get_property;

	gkm_class->get_attribute = gkm_certificate_real_get_attribute;

	g_object_class_install_property (gobject_class, PROP_PUBLIC_KEY,
	           g_param_spec_object ("public-key", "Public Key", "Public key contained in certificate",
	                                GKM_TYPE_CERTIFICATE_KEY, G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_PUBLIC_KEY,
	           g_param_spec_string ("label", "Label", "Label of the certificate",
	                                "", G_PARAM_READWRITE));

	init_quarks ();
}

static gboolean
gkm_certificate_real_load (GkmSerializable *base,
                           GkmSecret *login,
                           GBytes *data)
{
	GkmCertificate *self = GKM_CERTIFICATE (base);
	GNode *asn1 = NULL;
	GkmDataResult res;
	GBytes *keydata;
	gcry_sexp_t sexp;
	GkmSexp *wrapper;

	if (g_bytes_get_size (data) == 0) {
		gkm_debug ("cannot load empty certificate file");
		return FALSE;
	}

	/* Parse the ASN1 data */
	res = gkm_data_der_read_certificate (data, &asn1);
	if (res != GKM_DATA_SUCCESS) {
		gkm_debug ("couldn't parse certificate data");
		return FALSE;
	}

	/* Generate a raw public key from our certificate */
	keydata = egg_asn1x_encode (egg_asn1x_node (asn1, "tbsCertificate", "subjectPublicKeyInfo", NULL), NULL);
	g_return_val_if_fail (keydata, FALSE);

	/* Now create us a nice public key with that identifier */
	res = gkm_data_der_read_public_key_info (keydata, &sexp);
	g_bytes_unref (keydata);

	switch (res) {

	/* Create ourselves a public key with that */
	case GKM_DATA_SUCCESS:
		wrapper = gkm_sexp_new (sexp);
		if (!self->pv->key)
			self->pv->key = gkm_certificate_key_new (gkm_object_get_module (GKM_OBJECT (self)),
			                                         gkm_object_get_manager (GKM_OBJECT (self)),
			                                         self);
		gkm_sexp_key_set_base (GKM_SEXP_KEY (self->pv->key), wrapper);
		gkm_sexp_unref (wrapper);
		break;

	/* Unknown type of public key for this certificate, just ignore */
	case GKM_DATA_UNRECOGNIZED:
		if (self->pv->key)
			g_object_unref (self->pv->key);
		self->pv->key = NULL;
		break;

	/* Bad key, drop certificate */
	case GKM_DATA_FAILURE:
	case GKM_DATA_LOCKED:
		g_warning ("couldn't parse certificate key data");
		egg_asn1x_destroy (asn1);
		return FALSE;

	default:
		g_assert_not_reached ();
		break;
	}

	g_bytes_ref (data);
	if (self->pv->der)
		g_bytes_unref (self->pv->der);
	self->pv->der = data;

	egg_asn1x_destroy (self->pv->asn1);
	self->pv->asn1 = asn1;

	return TRUE;
}

static GBytes *
gkm_certificate_real_save (GkmSerializable *base,
                           GkmSecret *login)
{
	GkmCertificate *self = GKM_CERTIFICATE (base);

	g_return_val_if_fail (GKM_IS_CERTIFICATE (self), FALSE);

	return g_bytes_ref (self->pv->der);
}

static void
gkm_certificate_serializable (GkmSerializableIface *iface)
{
	iface->extension = ".cer";
	iface->load = gkm_certificate_real_load;
	iface->save = gkm_certificate_real_save;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

gboolean
gkm_certificate_calc_category (GkmCertificate *self, GkmSession *session, CK_ULONG* category)
{
	GBytes *extension;
	GkmManager *manager;
	GkmDataResult res;
	gboolean is_ca;
	GkmObject *object;

	g_return_val_if_fail (GKM_IS_CERTIFICATE (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (category, CKR_GENERAL_ERROR);

	/* First see if we have a private key for this certificate */
	manager = gkm_object_get_manager (GKM_OBJECT (self));
	if (manager != NULL) {
		object = gkm_manager_find_related (manager, session, CKO_PRIVATE_KEY, GKM_OBJECT (self));
		if (object != NULL) {
			*category = 1; /* token user */
			return TRUE;
		}
	}

	/* Read in the Basic Constraints section */
	extension = gkm_certificate_get_extension (self, OID_BASIC_CONSTRAINTS, NULL);
	if (extension != NULL) {
		res = gkm_data_der_read_basic_constraints (extension, &is_ca, NULL);

		if (res != GKM_DATA_SUCCESS)
			return FALSE;

		if (is_ca)
			*category = 2; /* authority */
		else
			*category = 3; /* other entity */

	} else {
		*category = 0; /* unspecified */
	}

	return TRUE;
}

GkmCertificateKey*
gkm_certificate_get_public_key (GkmCertificate *self)
{
	g_return_val_if_fail (GKM_IS_CERTIFICATE (self), NULL);
	return self->pv->key;
}

GBytes *
gkm_certificate_get_extension (GkmCertificate *self, GQuark oid,
                               gboolean *critical)
{
	guchar *val;
	gsize n_val;
	gint index;

	g_return_val_if_fail (GKM_IS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (self->pv->asn1, NULL);
	g_return_val_if_fail (oid, NULL);

	index = find_certificate_extension (self, oid);
	if (index <= 0)
		return NULL;

	/* Read the critical status */
	if (critical) {
		val = egg_asn1x_get_string_as_raw (egg_asn1x_node (self->pv->asn1, "tbsCertificate",
		                                   "extensions", index, "critical", NULL), NULL, &n_val);

		/*
		 * We're pretty liberal in what we accept as critical. The goal
		 * here is not to accidentally mark as non-critical what some
		 * other x509 implementation meant to say critical.
		 */
		if (!val || n_val < 1 || g_ascii_toupper (val[0]) != 'T')
			*critical = FALSE;
		else
			*critical = TRUE;
		g_free (val);
	}

	/* And the extension value */
	return egg_asn1x_get_string_as_bytes (egg_asn1x_node (self->pv->asn1, "tbsCertificate",
	                                      "extensions", index, "extnValue", NULL));
}

const gchar*
gkm_certificate_get_label (GkmCertificate *self)
{
	gchar *label;

	g_return_val_if_fail (GKM_IS_CERTIFICATE (self), "");

	if (!self->pv->label) {
		g_return_val_if_fail (self->pv->asn1, "");

		/* Look for the CN in the certificate */
		label = egg_dn_read_part (egg_asn1x_node (self->pv->asn1, "tbsCertificate", "subject", "rdnSequence", NULL), "cn");

		/* Otherwise use the full DN */
		if (!label)
			label = egg_dn_read (egg_asn1x_node (self->pv->asn1, "tbsCertificate", "subject", "rdnSequence", NULL));

		if (!label)
			label = g_strdup (_("Unnamed Certificate"));

		self->pv->label = label;

	}

	return self->pv->label;
}

void
gkm_certificate_set_label (GkmCertificate *self, const gchar *label)
{
	g_return_if_fail (GKM_IS_CERTIFICATE (self));
	g_free (self->pv->label);
	self->pv->label = g_strdup (label);
	g_object_notify (G_OBJECT (self), "label");
}

guchar*
gkm_certificate_hash (GkmCertificate *self, int hash_algo, gsize *n_hash)
{
	guchar *hash;

	g_return_val_if_fail (GKM_IS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (self->pv->der != NULL, NULL);
	g_return_val_if_fail (n_hash, NULL);

	*n_hash = gcry_md_get_algo_dlen (hash_algo);
	g_return_val_if_fail (*n_hash > 0, NULL);

	hash = g_malloc0 (*n_hash);
	gcry_md_hash_buffer (hash_algo, hash, g_bytes_get_data (self->pv->der, NULL),
	                     g_bytes_get_size (self->pv->der));

	return hash;
}

gconstpointer
gkm_certificate_der_data (GkmCertificate *self, gsize *n_data)
{
	g_return_val_if_fail (GKM_IS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (self->pv->der != NULL, NULL);
	g_return_val_if_fail (n_data, NULL);

	*n_data = g_bytes_get_size (self->pv->der);
	return g_bytes_get_data (self->pv->der, NULL);
}

GkmFactory*
gkm_certificate_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
	static CK_CERTIFICATE_TYPE type = CKC_X_509;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_CERTIFICATE_TYPE, &type, sizeof (type) },
	};

	static GkmFactory factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_certificate
	};

	return &factory;
}
