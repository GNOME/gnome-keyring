/*
 * gnome-keyring
 *
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

#include "gkm-xdg-trust.h"

#include "egg/egg-asn1x.h"

#include "gkm/gkm-attributes.h"
#include "gkm/gkm-object.h"
#include "gkm/gkm-serializable.h"
#include "gkm/gkm-session.h"
#include "gkm/gkm-transaction.h"
#include "gkm/gkm-util.h"

#include "pkcs11/pkcs11g.h"
#include "pkcs11/pkcs11n.h"

#include <libtasn1.h>

#include <glib/gi18n.h>

struct _GkmXdgTrustPrivate {
	GNode *asn;
	GHashTable *pairs;
	gpointer data;
	gsize n_data;
};

/* From asn1-def-xdg.c */
extern const ASN1_ARRAY_TYPE xdg_asn1_tab[];

static void gkm_xdg_trust_serializable (GkmSerializableIface *iface);

G_DEFINE_TYPE_EXTENDED (GkmXdgTrust, gkm_xdg_trust, GKM_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (GKM_TYPE_SERIALIZABLE, gkm_xdg_trust_serializable));

enum {
	TRUST_UNKNOWN = 0,
	TRUST_UNTRUSTED = 1,
	TRUST_MUST_VERIFY = 2,
	TRUST_TRUSTED = 3,
	TRUST_TRUSTED_DELEGATOR = 4
};

/* -----------------------------------------------------------------------------
 * QUARKS
 */

static GQuark OID_HASH_SHA1;
static GQuark OID_HASH_MD5;

static GQuark OID_USAGE_DIGITAL_SIGNATURE;
static GQuark OID_USAGE_NON_REPUDIATION;
static GQuark OID_USAGE_KEY_ENCIPHERMENT;
static GQuark OID_USAGE_DATA_ENCIPHERMENT;
static GQuark OID_USAGE_KEY_AGREEMENT;
static GQuark OID_USAGE_KEY_CERT_SIGN;
static GQuark OID_USAGE_CRL_SIGN;
static GQuark OID_USAGE_ENCIPHER_ONLY;

/* OID's for these purposes */
static GQuark OID_PURPOSE_SERVER_AUTH;
static GQuark OID_PURPOSE_CLIENT_AUTH;
static GQuark OID_PURPOSE_CODE_SIGNING;
static GQuark OID_PURPOSE_EMAIL;
static GQuark OID_PURPOSE_TIME_STAMPING;
static GQuark OID_PURPOSE_IPSEC_ENDPOINT;
static GQuark OID_PURPOSE_IPSEC_TUNNEL;
static GQuark OID_PURPOSE_IPSEC_USER;
static GQuark OID_PURPOSE_IKE_INTERMEDIATE;

static void
init_quarks (void)
{
	static volatile gsize quarks_inited = 0;

	if (g_once_init_enter (&quarks_inited)) {

		#define QUARK(name, value) \
			name = g_quark_from_static_string(value)

		QUARK (OID_HASH_SHA1, "1.3.14.3.2.26");
		QUARK (OID_HASH_MD5, "1.2.840.113549.2.5");

		/* These OIDs are in GNOME's space */
		QUARK (OID_USAGE_DIGITAL_SIGNATURE, "1.3.6.1.4.1.3319.1.6.3.128");
		QUARK (OID_USAGE_NON_REPUDIATION, "1.3.6.1.4.1.3319.1.6.3.64");
		QUARK (OID_USAGE_KEY_ENCIPHERMENT, "1.3.6.1.4.1.3319.1.6.3.32");
		QUARK (OID_USAGE_DATA_ENCIPHERMENT, "1.3.6.1.4.1.3319.1.6.3.16");
		QUARK (OID_USAGE_KEY_AGREEMENT, "1.3.6.1.4.1.3319.1.6.3.8");
		QUARK (OID_USAGE_KEY_CERT_SIGN, "1.3.6.1.4.1.3319.1.6.3.4");
		QUARK (OID_USAGE_CRL_SIGN, "1.3.6.1.4.1.3319.1.6.3.2");
		QUARK (OID_USAGE_ENCIPHER_ONLY, "1.3.6.1.4.1.3319.1.6.3.1");

		QUARK (OID_PURPOSE_SERVER_AUTH, "1.3.6.1.5.5.7.3.1");
		QUARK (OID_PURPOSE_CLIENT_AUTH, "1.3.6.1.5.5.7.3.2");
		QUARK (OID_PURPOSE_CODE_SIGNING, "1.3.6.1.5.5.7.3.3");
		QUARK (OID_PURPOSE_EMAIL, "1.3.6.1.5.5.7.3.4");
		QUARK (OID_PURPOSE_TIME_STAMPING, "1.3.6.1.5.5.7.3.8");
		QUARK (OID_PURPOSE_IPSEC_ENDPOINT, "1.3.6.1.5.5.7.3.5");
		QUARK (OID_PURPOSE_IPSEC_TUNNEL, "1.3.6.1.5.5.7.3.6");
		QUARK (OID_PURPOSE_IPSEC_USER, "1.3.6.1.5.5.7.3.7");
		QUARK (OID_PURPOSE_IKE_INTERMEDIATE, "1.3.6.1.5.5.8.2.2");

		#undef QUARK

		g_once_init_leave (&quarks_inited, 1);
	}
}

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static CK_ULONG
lookup_usage (GkmXdgTrust *self, GQuark purpose)
{
	CK_ULONG *trust;

	trust = g_hash_table_lookup (self->pv->pairs, GUINT_TO_POINTER (purpose));
	if (!trust)
		return CKT_NETSCAPE_TRUST_UNKNOWN;
	else
		return *trust;
}

static CK_RV
trust_get_usage (GkmXdgTrust *self, GQuark purpose, CK_ATTRIBUTE_PTR attr)
{
	g_assert (GKM_XDG_IS_TRUST (self));
	return gkm_attribute_set_ulong (attr, lookup_usage (self, purpose));
}

static CK_RV
trust_get_der (GkmXdgTrust *self, const gchar *part, CK_ATTRIBUTE_PTR attr)
{
	GNode *node;
	gconstpointer element;
	gsize n_element;

	g_assert (GKM_XDG_IS_TRUST (self));

	node = egg_asn1x_node (self->pv->asn, "reference", "certReference", NULL);
	g_return_val_if_fail (node, CKR_GENERAL_ERROR);

	node = egg_asn1x_node (node, part, NULL);
	if (node == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	element = egg_asn1x_get_raw_element (node, &n_element);
	return gkm_attribute_set_data (attr, element, n_element);
}

static CK_RV
trust_get_integer (GkmXdgTrust *self, const gchar *part, CK_ATTRIBUTE_PTR attr)
{
	GNode *node;
	gpointer integer;
	gsize n_integer;
	CK_RV rv;

	g_assert (GKM_XDG_IS_TRUST (self));

	node = egg_asn1x_node (self->pv->asn, "reference", "certReference", NULL);
	g_return_val_if_fail (node, CKR_GENERAL_ERROR);

	node = egg_asn1x_node (self->pv->asn, part, NULL);
	if (node == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	integer = egg_asn1x_get_integer_as_raw (node, NULL, &n_integer);
	rv = gkm_attribute_set_data (attr, integer, n_integer);
	g_free (integer);

	return rv;
}

static CK_RV
trust_get_hash (GkmXdgTrust *self, GQuark oid, CK_ATTRIBUTE_PTR attr)
{
	CK_RV rv = CKR_ATTRIBUTE_VALUE_INVALID;
	GNode *digests, *digest;
	gpointer hash;
	gsize n_hash;
	guint count, i;
	GQuark check;

	digests = egg_asn1x_node (self->pv->asn, "reference", "certReference", "digests", NULL);
	g_return_val_if_fail (digests, CKR_GENERAL_ERROR);

	count = egg_asn1x_count (digests);
	for (i = 0; i < count; ++i) {
		digest = egg_asn1x_node (digests, i + 1, NULL);
		g_return_val_if_fail (digest, CKR_GENERAL_ERROR);

		check = egg_asn1x_get_oid_as_quark (egg_asn1x_node (digest, "algorithm", NULL));
		if (oid == check) {
			hash = egg_asn1x_get_string_as_raw (egg_asn1x_node (digest, "digest", NULL),
			                                    NULL, &n_hash);
			g_return_val_if_fail (hash, CKR_GENERAL_ERROR);

			rv = gkm_attribute_set_data (attr, hash, n_hash);
			g_free (hash);
			break;
		}
	}

	return rv;
}

static gboolean
validate_der (CK_ATTRIBUTE_PTR attr)
{
	return attr->pValue != NULL &&
	       attr->ulValueLen != (CK_ULONG)-1 &&
	       egg_asn1x_element_length (attr->pValue, attr->ulValueLen) >= 0;
}

static gboolean
validate_integer (CK_ATTRIBUTE_PTR attr)
{
	return attr->pValue != NULL &&
	       attr->ulValueLen > 0 &&
	       attr->ulValueLen != (CK_ULONG)-1;
}

static gboolean
validate_hash (CK_ATTRIBUTE_PTR attr, GChecksumType type)
{
	return attr->pValue != NULL &&
	       attr->ulValueLen == g_checksum_type_get_length (type);
}

static void
append_reference_hash (GNode *asn, GQuark oid, CK_ATTRIBUTE_PTR attr)
{
	GNode *node;

	node = egg_asn1x_node (asn, "reference", "certReference", "digests", NULL);
	g_return_if_fail (node);

	/* Add another digest */
	node = egg_asn1x_append (node);
	g_return_if_fail (node);

	egg_asn1x_set_oid_as_quark (egg_asn1x_node (node, "algorithm", NULL), oid);
	egg_asn1x_set_string_as_raw (egg_asn1x_node (node, "digest", NULL),
	                             g_memdup (attr->pValue, attr->ulValueLen),
	                             attr->ulValueLen, g_free);
}

static gint
trust_ulong_to_level_enum (CK_ULONG trust)
{
	switch (trust) {
	case CKT_NETSCAPE_TRUST_UNKNOWN:
		return TRUST_UNKNOWN;
	case CKT_NETSCAPE_UNTRUSTED:
		return TRUST_UNTRUSTED;
	case CKT_NETSCAPE_TRUSTED_DELEGATOR:
		return TRUST_TRUSTED_DELEGATOR;
	case CKT_NETSCAPE_TRUSTED:
		return TRUST_TRUSTED;
	case CKT_NETSCAPE_MUST_VERIFY:
		return TRUST_MUST_VERIFY;
	default:
		return -1;
	};
}

static CK_ULONG
level_enum_to_trust_ulong (guint level)
{
	switch (level) {
	case TRUST_UNKNOWN:
		return CKT_NETSCAPE_TRUST_UNKNOWN;
	case TRUST_UNTRUSTED:
		return CKT_NETSCAPE_UNTRUSTED;
	case TRUST_TRUSTED_DELEGATOR:
		return CKT_NETSCAPE_TRUSTED_DELEGATOR;
	case TRUST_TRUSTED:
		return CKT_NETSCAPE_TRUSTED;
	case TRUST_MUST_VERIFY:
		return CKT_NETSCAPE_MUST_VERIFY;
	default:
		return (CK_ULONG)-1;
	};
}

static GkmObject*
factory_create_trust (GkmSession *session, GkmTransaction *transaction,
                      CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	GkmXdgTrust *trust;
	CK_ATTRIBUTE_PTR serial, issuer, subject;
	CK_ATTRIBUTE_PTR md5, sha1;
	GNode *asn;

	g_return_val_if_fail (attrs || !n_attrs, NULL);

	subject = gkm_attributes_find (attrs, n_attrs, CKA_SUBJECT);
	serial = gkm_attributes_find (attrs, n_attrs, CKA_SERIAL_NUMBER);
	issuer = gkm_attributes_find (attrs, n_attrs, CKA_ISSUER);

	if (serial == NULL || issuer == NULL) {
		gkm_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
		return NULL;
	}

	if (!validate_der (issuer) || (subject && !validate_der (subject))) {
		gkm_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
		return NULL;
	}

	if (!validate_integer (serial)) {
		gkm_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
		return NULL;
	}

	md5 = gkm_attributes_find (attrs, n_attrs, CKA_CERT_MD5_HASH);
	sha1 = gkm_attributes_find (attrs, n_attrs, CKA_CERT_SHA1_HASH);

	if ((md5 && !validate_hash (md5, G_CHECKSUM_MD5)) ||
	    (sha1 && !validate_hash (sha1, G_CHECKSUM_SHA1))) {
		gkm_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
		return NULL;
	}

	asn = egg_asn1x_create (xdg_asn1_tab, "trust-1");
	g_return_val_if_fail (asn, NULL);

	egg_asn1x_set_integer_as_raw (egg_asn1x_node (asn, "reference", "certReference", "serialNumber", NULL),
	                              g_memdup (serial->pValue, serial->ulValueLen),
	                              serial->ulValueLen, g_free);

	egg_asn1x_set_raw_element (egg_asn1x_node (asn, "reference", "certReference", "issuer", NULL),
	                           g_memdup (issuer->pValue, issuer->ulValueLen),
	                           issuer->ulValueLen, g_free);

	if (subject)
		egg_asn1x_set_raw_element (egg_asn1x_node (asn, "reference", "certReference", "subject", NULL),
		                           g_memdup (subject->pValue, issuer->ulValueLen),
		                           issuer->ulValueLen, g_free);

	if (md5)
		append_reference_hash (asn, OID_HASH_MD5, md5);
	if (sha1)
		append_reference_hash (asn, OID_HASH_SHA1, sha1);

	trust = g_object_new (GKM_XDG_TYPE_TRUST,
	                    "module", gkm_session_get_module (session),
	                    "manager", gkm_manager_for_template (attrs, n_attrs, session),
	                    NULL);
	trust->pv->asn = asn;

	gkm_attributes_consume (attrs, n_attrs, CKA_CERT_MD5_HASH, CKA_CERT_SHA1_HASH,
	                        CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER, G_MAXULONG);

	gkm_session_complete_object_creation (session, transaction, GKM_OBJECT (trust),
	                                      TRUE, attrs, n_attrs);
	return GKM_OBJECT (trust);
}

static gboolean
load_trust_pairs (GHashTable *pairs, GNode *asn)
{
	GNode *pair;
	guint count, i;
	gulong level;
	gulong trust;
	GQuark oid;

	g_assert (pairs);
	g_assert (asn);

	g_hash_table_remove_all (pairs);

	count = egg_asn1x_count (egg_asn1x_node (asn, "trusts", NULL));

	for (i = 0; i < count; ++i) {
		pair = egg_asn1x_node (asn, "trusts", i + 1, NULL);
		g_return_val_if_fail (pair, FALSE);

		/* Get the usage */
		if (!egg_asn1x_get_integer_as_ulong (egg_asn1x_node (pair, "level", NULL), &level))
			g_return_val_if_reached (FALSE);

		trust = level_enum_to_trust_ulong (level);
		if (trust == (CK_ULONG)-1) {
			g_message ("unsupported trust level %u in trust object", (guint)level);
			continue;
		}

		/* A key usage */
		oid = egg_asn1x_get_oid_as_quark (egg_asn1x_node (pair, "purpose", NULL));
		g_return_val_if_fail (oid, FALSE);

		g_hash_table_replace (pairs, GUINT_TO_POINTER (oid),
		                      gkm_util_ulong_alloc (trust));
	}

	return TRUE;
}

static gboolean
save_trust_pairs (GHashTable *pairs, GNode *asn)
{
	GHashTableIter iter;
	GNode *pair, *node;
	gpointer key, value;
	gulong level;
	GQuark oid;

	g_assert (pairs);
	g_assert (asn);

	node = egg_asn1x_node (asn, "trusts", NULL);
	egg_asn1x_clear (node);

	g_hash_table_iter_init (&iter, pairs);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		oid = GPOINTER_TO_UINT (key);
		level = trust_ulong_to_level_enum (*((CK_ULONG_PTR)value));

		pair = egg_asn1x_append (node);
		g_return_val_if_fail (pair, FALSE);

		egg_asn1x_set_oid_as_quark (egg_asn1x_node (pair, "purpose", NULL), oid);
		egg_asn1x_set_integer_as_ulong (egg_asn1x_node (pair, "level", NULL), level);
	}

	return TRUE;
}
/* -----------------------------------------------------------------------------
 * OBJECT
 */

static CK_RV
gkm_xdg_trust_get_attribute (GkmObject *base, GkmSession *session, CK_ATTRIBUTE_PTR attr)
{
	GkmXdgTrust *self = GKM_XDG_TRUST (base);

	switch (attr->type)
	{
	case CKA_PRIVATE:
		return gkm_attribute_set_bool (attr, CK_FALSE);
	case CKA_TRUST_STEP_UP_APPROVED:
		return gkm_attribute_set_bool (attr, CK_FALSE);
	case CKA_CLASS:
		return gkm_attribute_set_ulong (attr, CKO_NETSCAPE_TRUST);
	case CKA_MODIFIABLE:
		return gkm_attribute_set_bool (attr, CK_TRUE);

	/* Key restrictions */
	case CKA_TRUST_DIGITAL_SIGNATURE:
		return trust_get_usage (self, OID_USAGE_DIGITAL_SIGNATURE, attr);
	case CKA_TRUST_NON_REPUDIATION:
		return trust_get_usage (self, OID_USAGE_NON_REPUDIATION, attr);
	case CKA_TRUST_KEY_ENCIPHERMENT:
		return trust_get_usage (self, OID_USAGE_KEY_ENCIPHERMENT, attr);
	case CKA_TRUST_DATA_ENCIPHERMENT:
		return trust_get_usage (self, OID_USAGE_DATA_ENCIPHERMENT, attr);
	case CKA_TRUST_KEY_AGREEMENT:
		return trust_get_usage (self, OID_USAGE_KEY_AGREEMENT, attr);
	case CKA_TRUST_KEY_CERT_SIGN:
		return trust_get_usage (self, OID_USAGE_KEY_CERT_SIGN, attr);
	case CKA_TRUST_CRL_SIGN:
		return trust_get_usage (self, OID_USAGE_CRL_SIGN, attr);

	/* Various trust flags */
	case CKA_TRUST_SERVER_AUTH:
		return trust_get_usage (self, OID_PURPOSE_SERVER_AUTH, attr);
	case CKA_TRUST_CLIENT_AUTH:
		return trust_get_usage (self, OID_PURPOSE_CLIENT_AUTH, attr);
	case CKA_TRUST_CODE_SIGNING:
		return trust_get_usage (self, OID_PURPOSE_CODE_SIGNING, attr);
	case CKA_TRUST_EMAIL_PROTECTION:
		return trust_get_usage (self, OID_PURPOSE_EMAIL, attr);
	case CKA_TRUST_IPSEC_END_SYSTEM:
		return trust_get_usage (self, OID_PURPOSE_IPSEC_ENDPOINT, attr);
	case CKA_TRUST_IPSEC_TUNNEL:
		return trust_get_usage (self, OID_PURPOSE_IPSEC_TUNNEL, attr);
	case CKA_TRUST_IPSEC_USER:
		return trust_get_usage (self, OID_PURPOSE_IPSEC_USER, attr);
	case CKA_TRUST_TIME_STAMPING:
		return trust_get_usage (self, OID_PURPOSE_TIME_STAMPING, attr);

	/* Certificate reference values */
	case CKA_SUBJECT:
		return trust_get_der (self, "subject", attr);
	case CKA_SERIAL_NUMBER:
		return trust_get_der (self, "serialNumber", attr);
	case CKA_ISSUER:
		return trust_get_integer (self, "issuer", attr);

	/* Certificate hash values */
	case CKA_CERT_MD5_HASH:
		return trust_get_hash (self, OID_HASH_MD5, attr);
	case CKA_CERT_SHA1_HASH:
		return trust_get_hash (self, OID_HASH_SHA1, attr);

	default:
		break;
	};

	return GKM_OBJECT_CLASS (gkm_xdg_trust_parent_class)->get_attribute (base, session, attr);
}

static void
gkm_xdg_trust_set_attribute (GkmObject *base, GkmSession *session,
                             GkmTransaction* transaction, CK_ATTRIBUTE* attr)
{
	GkmXdgTrust *self = GKM_XDG_TRUST (base);
	CK_ULONG value;
	GQuark oid = 0;
	CK_RV rv;

	switch (attr->type)
	{

	/* Key restrictions */
	case CKA_TRUST_DIGITAL_SIGNATURE:
		oid = OID_USAGE_DIGITAL_SIGNATURE;
		break;
	case CKA_TRUST_NON_REPUDIATION:
		oid = OID_USAGE_NON_REPUDIATION;
		break;
	case CKA_TRUST_KEY_ENCIPHERMENT:
		oid = OID_USAGE_KEY_ENCIPHERMENT;
		break;
	case CKA_TRUST_DATA_ENCIPHERMENT:
		oid = OID_USAGE_DATA_ENCIPHERMENT;
		break;
	case CKA_TRUST_KEY_AGREEMENT:
		oid = OID_USAGE_KEY_AGREEMENT;
		break;
	case CKA_TRUST_KEY_CERT_SIGN:
		oid = OID_USAGE_KEY_CERT_SIGN;
		break;
	case CKA_TRUST_CRL_SIGN:
		oid = OID_USAGE_CRL_SIGN;
		break;

	/* Various trust flags */
	case CKA_TRUST_SERVER_AUTH:
		oid = OID_PURPOSE_SERVER_AUTH;
		break;
	case CKA_TRUST_CLIENT_AUTH:
		oid = OID_PURPOSE_CLIENT_AUTH;
		break;
	case CKA_TRUST_CODE_SIGNING:
		oid = OID_PURPOSE_CODE_SIGNING;
		break;
	case CKA_TRUST_EMAIL_PROTECTION:
		oid = OID_PURPOSE_EMAIL;
		break;
	case CKA_TRUST_IPSEC_END_SYSTEM:
		oid = OID_PURPOSE_IPSEC_ENDPOINT;
		break;
	case CKA_TRUST_IPSEC_TUNNEL:
		oid = OID_PURPOSE_IPSEC_TUNNEL;
		break;
	case CKA_TRUST_IPSEC_USER:
		oid = OID_PURPOSE_IPSEC_USER;
		break;
	case CKA_TRUST_TIME_STAMPING:
		oid = OID_PURPOSE_TIME_STAMPING;
		break;

	default:
		break;
	};

	if (oid != 0) {
		rv = gkm_attribute_get_ulong (attr, &value);
		if (rv != CKR_OK)
			gkm_transaction_fail (transaction, rv);
		else if (trust_ulong_to_level_enum (value) < 0)
			gkm_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
		else
			g_hash_table_replace (self->pv->pairs, GUINT_TO_POINTER (oid),
			                      gkm_util_ulong_alloc (value));
		return;
	}

	GKM_OBJECT_CLASS (gkm_xdg_trust_parent_class)->set_attribute (base, session, transaction, attr);
}

static void
gkm_xdg_trust_init (GkmXdgTrust *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GKM_XDG_TYPE_TRUST, GkmXdgTrustPrivate);
	self->pv->pairs = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, gkm_util_ulong_free);
}

static void
gkm_xdg_trust_finalize (GObject *obj)
{
	GkmXdgTrust *self = GKM_XDG_TRUST (obj);

	if (self->pv->asn)
		egg_asn1x_destroy (self->pv->asn);
	self->pv->asn = NULL;

	if (self->pv->pairs)
		g_hash_table_destroy (self->pv->pairs);
	self->pv->pairs = NULL;

	G_OBJECT_CLASS (gkm_xdg_trust_parent_class)->finalize (obj);
}

static void
gkm_xdg_trust_class_init (GkmXdgTrustClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkmObjectClass *gkm_class = GKM_OBJECT_CLASS (klass);

	gobject_class->finalize = gkm_xdg_trust_finalize;
	gkm_class->get_attribute = gkm_xdg_trust_get_attribute;
	gkm_class->set_attribute = gkm_xdg_trust_set_attribute;

	g_type_class_add_private (klass, sizeof (GkmXdgTrustPrivate));

	init_quarks ();
}

static gboolean
gkm_xdg_trust_real_load (GkmSerializable *base, GkmSecret *login, gconstpointer data, gsize n_data)
{
	GkmXdgTrust *self = GKM_XDG_TRUST (base);
	GNode *asn = NULL;
	gpointer copy;

	g_return_val_if_fail (GKM_XDG_IS_TRUST (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	copy = g_memdup (data, n_data);

	asn = egg_asn1x_create_and_decode (xdg_asn1_tab, "trust-1", copy, n_data);
	if (asn == NULL) {
		g_warning ("couldn't parse trust data");
		g_free (copy);
		return FALSE;
	}

	/* Next parse out all the pairs */
	if (!load_trust_pairs (self->pv->pairs, asn)) {
		egg_asn1x_destroy (asn);
		g_free (copy);
		return FALSE;
	}

	/* Take ownership of this new data */
	g_free (self->pv->data);
	self->pv->data = copy;
	self->pv->n_data = n_data;
	egg_asn1x_destroy (self->pv->asn);
	self->pv->asn = asn;

	return TRUE;
}

static gboolean
gkm_xdg_trust_real_save (GkmSerializable *base, GkmSecret *login, gpointer *data, gsize *n_data)
{
	GkmXdgTrust *self = GKM_XDG_TRUST (base);

	g_return_val_if_fail (GKM_XDG_IS_TRUST (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);
	g_return_val_if_fail (self->pv->asn, FALSE);

	if (!save_trust_pairs (self->pv->pairs, self->pv->asn))
		return FALSE;

	*data = egg_asn1x_encode (self->pv->asn, NULL, n_data);
	if (*data == NULL) {
		g_warning ("encoding trust failed: %s", egg_asn1x_message (self->pv->asn));
		return FALSE;
	}

	/* ASN.1 now refers to this data, take ownership */
	g_free (self->pv->data);
	self->pv->data = *data;
	self->pv->n_data = *n_data;

	/* Return a duplicate, since we own encoded */
	*data = g_memdup (*data, *n_data);
	return TRUE;
}

static void
gkm_xdg_trust_serializable (GkmSerializableIface *iface)
{
	iface->extension = ".trust";
	iface->load = gkm_xdg_trust_real_load;
	iface->save = gkm_xdg_trust_real_save;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */


GkmFactory*
gkm_xdg_trust_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
	};

	static GkmFactory factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_trust
	};

	init_quarks ();
	return &factory;
}
