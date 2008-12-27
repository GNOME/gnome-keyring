/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *  
 * You should have received a copy of the GNU Lesser General 
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "pkcs11/pkcs11.h"

#include "gck-certificate-key.h"
#include "gck-crypto.h"
#include "gck-data-asn1.h"
#include "gck-data-der.h"
#include "gck-key.h"
#include "gck-manager.h"
#include "gck-sexp.h"
#include "gck-util.h"

#include <glib/gi18n.h>

#include <libtasn1.h>

enum {
	PROP_0,
	PROP_LABEL,
	PROP_PUBLIC_KEY
};

struct _GckCertificatePrivate {
	GckCertificateKey *key;
	ASN1_TYPE asn1;
	guchar *data;
	gsize n_data;
	gchar *label;
};

static GQuark OID_BASIC_CONSTRAINTS;

G_DEFINE_TYPE (GckCertificate, gck_certificate, GCK_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static void
init_quarks (void)
{
	static volatile gsize quarks_inited = 0;
	
	if (g_once_init_enter (&quarks_inited)) {
		#define QUARK(name, value) \
			name = g_quark_from_static_string(value)
 
		QUARK (OID_BASIC_CONSTRAINTS, "2.5.29.19");

		#undef QUARK
		
		g_once_init_leave (&quarks_inited, 1);
	}
}

static gint
find_certificate_extension (GckCertificate *self, GQuark oid)
{
	GQuark exoid;
	gchar *name;
	guint index;
	int res, len;
	
	g_assert (oid);
	g_assert (GCK_IS_CERTIFICATE (self));
	g_assert (self->pv->asn1);
	
	for (index = 1; TRUE; ++index) {
		
		/* Make sure it is present */
		len = 0;
		name = g_strdup_printf ("tbsCertificate.extensions.?%u", index);
		res = asn1_read_value (self->pv->asn1, name, NULL, &len);
		g_free (name);
		if (res == ASN1_ELEMENT_NOT_FOUND)
			break;

		/* See if it's the same */
		name = g_strdup_printf ("tbsCertificate.extensions.?%u.extnID", index);
		exoid = gck_data_asn1_read_oid (self->pv->asn1, name);
		g_free (name);

		if(exoid == oid)
			return index;		
	}
	
	return 0;
}

/* -----------------------------------------------------------------------------
 * KEY 
 */

static CK_RV 
gck_certificate_real_get_attribute (GckObject *base, CK_ATTRIBUTE* attr)
{
	GckCertificate *self = GCK_CERTIFICATE (base);
	CK_ULONG category;
	const guchar *cdata;
	guchar *data;
	gsize n_data;
	time_t when;
	CK_RV rv;
	
	switch (attr->type) {
	
	case CKA_CLASS:
		return gck_util_set_ulong (attr, CKO_CERTIFICATE);
		
	case CKA_PRIVATE:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_LABEL:
		return gck_util_set_string (attr, gck_certificate_get_label (self)); 
		
	case CKA_CERTIFICATE_TYPE:
		return gck_util_set_ulong (attr, CKC_X_509);
		
	case CKA_TRUSTED:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_CERTIFICATE_CATEGORY:
		if (!gck_certificate_calc_category (self, &category))
			return CKR_FUNCTION_FAILED;
		return gck_util_set_ulong (attr, category);
		
	case CKA_CHECK_VALUE:
		g_return_val_if_fail (self->pv->data, CKR_GENERAL_ERROR);
		n_data = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
		g_return_val_if_fail (n_data && n_data > 3, CKR_GENERAL_ERROR);
		data = g_new0 (guchar, n_data);
		gcry_md_hash_buffer (GCRY_MD_SHA1, data, self->pv->data, self->pv->n_data);
		rv = gck_util_set_data (attr, data, 3);
		g_free (data);
		return rv;
	
	case CKA_START_DATE:
	case CKA_END_DATE:
		g_return_val_if_fail (self->pv->asn1, CKR_GENERAL_ERROR);
		if (!gck_data_asn1_read_time (self->pv->asn1, 
		                              attr->type == CKA_START_DATE ? 
		                                       "tbsCertificate.validity.notBefore" : 
		                                       "tbsCertificate.validity.notAfter",
		                              &when))
			return CKR_FUNCTION_FAILED;
		return gck_util_set_date (attr, when);

	case CKA_SUBJECT:
		g_return_val_if_fail (self->pv->asn1, CKR_GENERAL_ERROR);
		cdata = gck_data_asn1_read_element (self->pv->asn1, self->pv->data, self->pv->n_data, 
		                                    "tbsCertificate.subject", &n_data);
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		return gck_util_set_data (attr, cdata, n_data);

	case CKA_ID:
		g_return_val_if_fail (self->pv->key, CKR_GENERAL_ERROR);
		return gck_object_get_attribute (GCK_OBJECT (self->pv->key), attr);

	case CKA_ISSUER:
		g_return_val_if_fail (self->pv->asn1, CKR_GENERAL_ERROR);
		cdata = gck_data_asn1_read_element (self->pv->asn1, self->pv->data, self->pv->n_data, 
		                                    "tbsCertificate.issuer", &n_data);
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		return gck_util_set_data (attr, cdata, n_data);
		
	case CKA_SERIAL_NUMBER:
		g_return_val_if_fail (self->pv->asn1, CKR_GENERAL_ERROR);
		cdata = gck_data_asn1_read_element (self->pv->asn1, self->pv->data, self->pv->n_data, 
		                                    "tbsCertificate.serialNumber", &n_data);
		g_return_val_if_fail (cdata, CKR_GENERAL_ERROR);
		return gck_util_set_data (attr, cdata, n_data);		
		
	case CKA_VALUE:
		g_return_val_if_fail (self->pv->data, CKR_GENERAL_ERROR);
		return gck_util_set_data (attr, self->pv->data, self->pv->n_data);

	/* These are only used for strange online certificates which we don't support */	
	case CKA_URL:
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		return gck_util_set_data (attr, "", 0);
	
	/* What in the world is this doing in the spec? */
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
		return gck_util_set_ulong (attr, 0); /* 0 = unspecified */
	};

	return GCK_OBJECT_CLASS (gck_certificate_parent_class)->get_attribute (base, attr);
}

static GObject* 
gck_certificate_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckCertificate *self = GCK_CERTIFICATE (G_OBJECT_CLASS (gck_certificate_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	


	return G_OBJECT (self);
}

static void
gck_certificate_init (GckCertificate *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_CERTIFICATE, GckCertificatePrivate);

}

static void
gck_certificate_dispose (GObject *obj)
{
	GckCertificate *self = GCK_CERTIFICATE (obj);
	
	if (self->pv->key)
		g_object_unref (self->pv->key);
	self->pv->key = NULL;
	
	G_OBJECT_CLASS (gck_certificate_parent_class)->dispose (obj);
}

static void
gck_certificate_finalize (GObject *obj)
{
	GckCertificate *self = GCK_CERTIFICATE (obj);
	
	g_assert (!self->pv->key);
	g_free (self->pv->data);
	g_free (self->pv->label);
	asn1_delete_structure (&self->pv->asn1);

	G_OBJECT_CLASS (gck_certificate_parent_class)->finalize (obj);
}

static void
gck_certificate_set_property (GObject *obj, guint prop_id, const GValue *value, 
                              GParamSpec *pspec)
{
	GckCertificate *self = GCK_CERTIFICATE (obj);
	
	switch (prop_id) {
	case PROP_LABEL:
		gck_certificate_set_label (self, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_certificate_get_property (GObject *obj, guint prop_id, GValue *value, 
                              GParamSpec *pspec)
{
	GckCertificate *self = GCK_CERTIFICATE (obj);
	
	switch (prop_id) {
	case PROP_LABEL:
		g_value_set_string (value, gck_certificate_get_label (self));
		break;
	case PROP_PUBLIC_KEY:
		g_value_set_object (value, gck_certificate_get_public_key (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_certificate_class_init (GckCertificateClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	
	gck_certificate_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GckCertificatePrivate));

	gobject_class->constructor = gck_certificate_constructor;
	gobject_class->dispose = gck_certificate_dispose;
	gobject_class->finalize = gck_certificate_finalize;
	gobject_class->set_property = gck_certificate_set_property;
	gobject_class->get_property = gck_certificate_get_property;
	
	gck_class->get_attribute = gck_certificate_real_get_attribute;
    
	g_object_class_install_property (gobject_class, PROP_PUBLIC_KEY,
	           g_param_spec_object ("public-key", "Public Key", "Public key contained in certificate", 
	                                GCK_TYPE_CERTIFICATE_KEY, G_PARAM_READABLE));
	
	g_object_class_install_property (gobject_class, PROP_PUBLIC_KEY,
	           g_param_spec_string ("label", "Label", "Label of the certificate", 
	                                "", G_PARAM_READWRITE));
	
	init_quarks ();
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

gboolean
gck_certificate_load_data (GckCertificate *self, const guchar *data, gsize n_data)
{
	ASN1_TYPE asn1 = ASN1_TYPE_EMPTY;
	GckDataResult res;
	guchar *copy, *keydata;
	gsize n_keydata;
	gcry_sexp_t sexp;
	GckSexp *wrapper;
	
	g_return_val_if_fail (GCK_IS_CERTIFICATE (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);
	
	copy = g_memdup (data, n_data);
	
	/* Parse the ASN1 data */
	res = gck_data_der_read_certificate (copy, n_data, &asn1);
	if (res != GCK_DATA_SUCCESS) {
		g_warning ("couldn't parse certificate data");
		g_free (copy);
		return FALSE;
	}
	
	/* Generate a raw public key from our certificate */
	keydata = gck_data_asn1_encode (asn1, "tbsCertificate.subjectPublicKeyInfo", &n_keydata, NULL);
	g_return_val_if_fail (keydata, FALSE);

	/* Now create us a nice public key with that identifier */
	res = gck_data_der_read_public_key_info (keydata, n_keydata, &sexp);
	g_free (keydata);
	if (res != GCK_DATA_SUCCESS) {
		g_warning ("couldn't parse certificate key data");
		g_free (copy);
		asn1_delete_structure (&asn1);
		return FALSE;
	}
	
	/* Create ourselves a public key with that */
	wrapper = gck_sexp_new (sexp);
	if (!self->pv->key)
		self->pv->key = gck_certificate_key_new (self);
	gck_key_set_base_sexp (GCK_KEY (self->pv->key), wrapper);
	gck_sexp_unref (wrapper);
	
	g_free (self->pv->data);
	self->pv->data = copy;
	self->pv->n_data = n_data;
	
	asn1_delete_structure (&self->pv->asn1);
	self->pv->asn1 = asn1;
	
	return TRUE;
}

gboolean
gck_certificate_calc_category (GckCertificate *self, CK_ULONG* category)
{
	const guchar *extension;
	GckManager *manager;
	gsize n_extension;
	GckDataResult res;
	gboolean is_ca;
	GckObject *object;
	
	g_return_val_if_fail (GCK_IS_CERTIFICATE (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (category, CKR_GENERAL_ERROR);
	
	/* First see if we have a private key for this certificate */
	manager = gck_object_get_manager (GCK_OBJECT (self));
	if (manager != NULL) {
		object = gck_manager_find_related (manager, CKO_PRIVATE_KEY, GCK_OBJECT (self));
		if (object != NULL) {
			*category = 1; /* token user */
			return TRUE;
		}
	}
	
	/* Read in the Basic Constraints section */
	extension = gck_certificate_get_extension (self, OID_BASIC_CONSTRAINTS, &n_extension, NULL);
	if (extension != NULL) {
		res = gck_data_der_read_basic_constraints (extension, n_extension, &is_ca, NULL);
		
		if (res != GCK_DATA_SUCCESS)
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

GckCertificateKey*
gck_certificate_get_public_key (GckCertificate *self)
{
	g_return_val_if_fail (GCK_IS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (GCK_IS_CERTIFICATE_KEY (self->pv->key), NULL);
	return self->pv->key;
}

const guchar*
gck_certificate_get_extension (GckCertificate *self, GQuark oid, 
                               gsize *n_extension, gboolean *critical)
{
	const guchar *result;
	gchar *name;
	guchar *val;
	gsize n_val;
	gint index;
	
	g_return_val_if_fail (GCK_IS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (self->pv->asn1, NULL);
	g_return_val_if_fail (oid, NULL);
	g_return_val_if_fail (n_extension, NULL);
	
	index = find_certificate_extension (self, oid);
	if (index <= 0)
		return NULL;
		
	/* Read the critical status */
	if (critical) {
		name = g_strdup_printf ("tbsCertificate.extensions.?%u.critical", index);
		val = gck_data_asn1_read_value (self->pv->asn1, name, &n_val, NULL);
		g_free (name);
		
		if (!val || n_val < 1 || val[0] != 'T')
			*critical = FALSE;
		else
			*critical = TRUE;
		g_free (val);
	}
		
	/* And the extension value */
	name = g_strdup_printf ("tbsCertificate.extensions.?%u.extnValue", index);
	result = gck_data_asn1_read_content (self->pv->asn1, self->pv->data, self->pv->n_data, 
	                                     name, n_extension);
	g_free (name);
		
	return result;
}

const gchar*
gck_certificate_get_label (GckCertificate *self)
{
	gchar *label;
		
	g_return_val_if_fail (GCK_IS_CERTIFICATE (self), "");
		
	if (!self->pv->label) {
		g_return_val_if_fail (self->pv->asn1, "");
		
		/* Look for the CN in the certificate */
		label = gck_data_asn1_read_dn_part (self->pv->asn1, "tbsCertificate.subject.rdnSequence", "cn");
			
		/* Otherwise use the full DN */
		if (!label)
			label = gck_data_asn1_read_dn (self->pv->asn1, "tbsCertificate.subject.rdnSequence");
		
		if (!label)
			label = g_strdup (_("Unnamed Certificate"));
			
		self->pv->label = label;

	}
		
	return self->pv->label;
}

void 
gck_certificate_set_label (GckCertificate *self, const gchar *label)
{
	g_return_if_fail (GCK_IS_CERTIFICATE (self));
	g_free (self->pv->label);
	self->pv->label = g_strdup (label);
	g_object_notify (G_OBJECT (self), "label");
}
