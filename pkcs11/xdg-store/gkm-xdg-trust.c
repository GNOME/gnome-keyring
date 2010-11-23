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
#include "egg/egg-asn1-defs.h"
#include "egg/egg-byte-array.h"

#include "gkm/gkm-assertion.h"
#include "gkm/gkm-attributes.h"
#include "gkm/gkm-object.h"
#include "gkm/gkm-oids.h"
#include "gkm/gkm-serializable.h"
#include "gkm/gkm-session.h"
#include "gkm/gkm-transaction.h"
#include "gkm/gkm-util.h"

#include "pkcs11/pkcs11i.h"
#include "pkcs11/pkcs11n.h"

#include <libtasn1.h>

#include <glib/gi18n.h>

/* COMPAT: netscape's usages */
typedef struct _NetscapeFlags {
	CK_ULONG server_auth;
	CK_ULONG client_auth;
	CK_ULONG code_signing;
	CK_ULONG email_protection;
	CK_ULONG ipsec_end_system;
	CK_ULONG ipsec_tunnel;
	CK_ULONG ipsec_user;
	CK_ULONG time_stamping;
} NetscapeFlags;

struct _GkmXdgTrustPrivate {
	GNode *asn;
	GHashTable *assertions;
	gpointer data;
	gsize n_data;
	NetscapeFlags netscape;
};

/* From asn1-def-xdg.c */
extern const ASN1_ARRAY_TYPE xdg_asn1_tab[];

static void gkm_xdg_trust_serializable (GkmSerializableIface *iface);

G_DEFINE_TYPE_EXTENDED (GkmXdgTrust, gkm_xdg_trust, GKM_TYPE_TRUST, 0,
                        G_IMPLEMENT_INTERFACE (GKM_TYPE_SERIALIZABLE, gkm_xdg_trust_serializable));

/* -----------------------------------------------------------------------------
 * QUARKS
 */

static GQuark TRUST_UNKNOWN;
static GQuark TRUST_UNTRUSTED;
static GQuark TRUST_TRUSTED;
static GQuark TRUST_TRUSTED_ANCHOR;

static void
init_quarks (void)
{
	static volatile gsize quarks_inited = 0;

	if (g_once_init_enter (&quarks_inited)) {

		#define QUARK(name, value) \
			name = g_quark_from_static_string(value)

		QUARK (TRUST_UNKNOWN, "trustUnknown");
		QUARK (TRUST_UNTRUSTED, "untrusted");
		QUARK (TRUST_TRUSTED, "trusted");
		QUARK (TRUST_TRUSTED_ANCHOR, "trustedAnchor");

		#undef QUARK

		g_once_init_leave (&quarks_inited, 1);
	}
}

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static CK_RV
trust_get_der (GkmXdgTrust *self, const gchar *part, CK_ATTRIBUTE_PTR attr)
{
	GNode *node;
	gconstpointer element;
	gsize n_element;

	g_assert (GKM_XDG_IS_TRUST (self));

	node = egg_asn1x_node (self->pv->asn, "reference", "certReference", part, NULL);

	/* If the assertion doesn't contain this info ... */
	if (node == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	element = egg_asn1x_get_raw_element (node, &n_element);
	if (element == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;

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

	node = egg_asn1x_node (self->pv->asn, "reference", "certReference", part, NULL);

	/* If the assertion doesn't contain this info ... */
	if (node == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	integer = egg_asn1x_get_integer_as_raw (node, NULL, &n_integer);
	rv = gkm_attribute_set_data (attr, integer, n_integer);
	g_free (integer);

	return rv;
}

static CK_RV
trust_get_hash (GkmXdgTrust *self, GChecksumType ctype, CK_ATTRIBUTE_PTR attr)
{
	GNode *cert;
	gconstpointer element;
	gsize n_element;

	cert = egg_asn1x_node (self->pv->asn, "reference", "certComplete", NULL);

	/* If it's not stored, then this attribute is not present */
	if (cert == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	element = egg_asn1x_get_raw_element (cert, &n_element);
	g_return_val_if_fail (element, CKR_GENERAL_ERROR);

	return gkm_attribute_set_checksum (attr, ctype, element, n_element);
}

static gboolean
validate_der (CK_ATTRIBUTE_PTR attr, const gchar *asn_type)
{
	GNode *asn;

	if (!attr->pValue || attr->ulValueLen == (CK_ULONG)-1)
		return FALSE;

	asn = egg_asn1x_create_and_decode (pkix_asn1_tab, asn_type, attr->pValue, attr->ulValueLen);
	if (!asn)
		return FALSE;

	/* Yes, this is an expensive check, but worthwhile */
	egg_asn1x_destroy (asn);
	return TRUE;
}

static gboolean
validate_integer (CK_ATTRIBUTE_PTR attr)
{
	return attr->pValue != NULL &&
	       attr->ulValueLen > 0 &&
	       attr->ulValueLen != (CK_ULONG)-1;
}

static GQuark
assertion_type_to_level_enum (CK_ASSERTION_TYPE type)
{
	switch (type) {
	case CKT_G_CERTIFICATE_UNTRUSTED:
		return TRUST_UNTRUSTED;
	case CKT_G_CERTIFICATE_TRUST_ANCHOR:
		return TRUST_TRUSTED_ANCHOR;
	case CKT_NETSCAPE_TRUSTED:
		return TRUST_TRUSTED;
	default:
		return 0;
	};
}

static gboolean
level_enum_to_assertion_type (GQuark level, CK_ASSERTION_TYPE *type)
{
	if (level == TRUST_UNTRUSTED)
		*type = CKT_G_CERTIFICATE_UNTRUSTED;
	else if (level == TRUST_TRUSTED_ANCHOR)
		*type = CKT_G_CERTIFICATE_TRUST_ANCHOR;
	else if (level == TRUST_TRUSTED)
		*type = CKT_G_CERTIFICATE_TRUST_EXCEPTION;
	else if (level == TRUST_UNKNOWN)
		*type = 0;
	else
		return FALSE;
	return TRUE;
}

static void
init_netscape_trust (NetscapeFlags *netscape)
{
	netscape->server_auth = CKT_NETSCAPE_TRUST_UNKNOWN;
	netscape->client_auth = CKT_NETSCAPE_TRUST_UNKNOWN;
	netscape->code_signing = CKT_NETSCAPE_TRUST_UNKNOWN;
	netscape->email_protection = CKT_NETSCAPE_TRUST_UNKNOWN;
	netscape->ipsec_end_system = CKT_NETSCAPE_TRUST_UNKNOWN;
	netscape->ipsec_tunnel = CKT_NETSCAPE_TRUST_UNKNOWN;
	netscape->ipsec_user = CKT_NETSCAPE_TRUST_UNKNOWN;
	netscape->time_stamping = CKT_NETSCAPE_TRUST_UNKNOWN;
}

static void
parse_netscape_trust (NetscapeFlags *netscape, GQuark level, const gchar *purpose)
{
	CK_TRUST trust;

	if (level == TRUST_UNTRUSTED)
		trust = CKT_NETSCAPE_TRUSTED;
	else if (level == TRUST_TRUSTED_ANCHOR)
		trust = CKT_NETSCAPE_TRUSTED_DELEGATOR;
	else if (level == TRUST_TRUSTED)
		trust = CKT_NETSCAPE_TRUSTED;
	else if (level == TRUST_UNKNOWN)
		trust = CKT_NETSCAPE_TRUST_UNKNOWN;
	else
		return;

	if (g_str_equal (purpose, GKM_OID_EXTUSAGE_SERVER_AUTH))
		netscape->server_auth = trust;
	else if (g_str_equal (purpose, GKM_OID_EXTUSAGE_CLIENT_AUTH))
		netscape->client_auth = trust;
	else if (g_str_equal (purpose, GKM_OID_EXTUSAGE_CODE_SIGNING))
		netscape->code_signing = trust;
	else if (g_str_equal (purpose, GKM_OID_EXTUSAGE_EMAIL))
		netscape->email_protection = trust;
	else if (g_str_equal (purpose, GKM_OID_EXTUSAGE_IPSEC_ENDPOINT))
		netscape->ipsec_end_system = trust;
	else if (g_str_equal (purpose, GKM_OID_EXTUSAGE_IPSEC_TUNNEL))
		netscape->ipsec_tunnel = trust;
	else if (g_str_equal (purpose, GKM_OID_EXTUSAGE_IPSEC_USER))
		netscape->ipsec_user = trust;
	else if (g_str_equal (purpose, GKM_OID_EXTUSAGE_TIME_STAMPING))
		netscape->time_stamping = trust;
}

static void
dispose_each_assertion (gpointer key, gpointer value, gpointer user_data)
{
	g_assert (GKM_IS_ASSERTION (value));
	g_object_run_dispose (G_OBJECT (value));
}

static GHashTable*
create_assertions (void)
{
	return g_hash_table_new_full (egg_byte_array_hash, egg_byte_array_equal,
	                              (GDestroyNotify)g_byte_array_unref, gkm_util_dispose_unref);
}

static GkmAssertion*
create_assertion (GkmXdgTrust *self, GNode *asn, NetscapeFlags *netscape)
{
	CK_ASSERTION_TYPE type;
	GkmAssertion *assertion;
	GQuark level;
	gchar *purpose;
	gchar *remote;
	GNode *node;

	/* Get the trust level */
	level = egg_asn1x_get_enumerated (egg_asn1x_node (asn, "level", NULL));
	if (level == 0)
		g_return_val_if_reached (NULL);
	if (!level_enum_to_assertion_type (level, &type))
		g_message ("unsupported trust level %s in trust object", g_quark_to_string (level));
	else if (type == 0)
		return NULL;

	/* A purpose */
	purpose = egg_asn1x_get_oid_as_string (egg_asn1x_node (asn, "purpose", NULL));
	g_return_val_if_fail (purpose, NULL);

	/* A remote name */
	node = egg_asn1x_node (asn, "remote", NULL);
	if (egg_asn1x_have (node))
		remote = egg_asn1x_get_string_as_utf8 (node, NULL);
	else
		remote = NULL;

	assertion = gkm_assertion_new (GKM_TRUST (self), type, purpose, remote);

	/* Parse netscape trust flags */
	if (remote == NULL)
		parse_netscape_trust (netscape, level, purpose);

	g_free (purpose);
	g_free (remote);

	return assertion;
}

static gboolean
load_assertions (GkmXdgTrust *self, GNode *asn)
{
	gconstpointer element;
	GHashTable *assertions;
	GkmAssertion *assertion;
	NetscapeFlags netscape;
	gsize n_element;
	GByteArray *key;
	GNode *node;
	guint count, i;

	g_assert (self);
	g_assert (asn);

	assertions = create_assertions ();
	init_netscape_trust (&netscape);

	count = egg_asn1x_count (egg_asn1x_node (asn, "assertions", NULL));

	for (i = 0; i < count; ++i) {
		node = egg_asn1x_node (asn, "assertions", i + 1, NULL);
		g_return_val_if_fail (node, FALSE);

		/* We use the raw DER encoding as an assertion */
		element = egg_asn1x_get_raw_element (node, &n_element);
		g_return_val_if_fail (node, FALSE);

		/* Double check that this is valid, because it's how we hash */
		key = g_byte_array_new ();
		g_byte_array_append (key, element, n_element);

		/* Already have this assertion? */
		assertion = g_hash_table_lookup (self->pv->assertions, key);
		if (assertion) {
			g_object_ref (assertion);
			g_hash_table_remove (self->pv->assertions, key);

		/* Create a new assertion */
		} else {
			assertion = create_assertion (self, node, &netscape);
		}

		if (assertion)
			g_hash_table_insert (assertions, g_byte_array_ref (key), assertion);
		g_byte_array_unref (key);
	}

	/* Override the stored assertions and netscape trust */
	g_hash_table_foreach (self->pv->assertions, dispose_each_assertion, NULL);
	g_hash_table_unref (self->pv->assertions);
	self->pv->assertions = assertions;
	memcpy (&self->pv->netscape, &netscape, sizeof (netscape));

	return TRUE;
}

static gboolean
save_assertions (GkmXdgTrust *self, GNode *asn)
{
	GkmAssertion *assertion;
	GHashTableIter iter;
	GNode *pair, *node;
	const gchar *purpose;
	const gchar *remote;
	gpointer value;
	GQuark level;

	g_assert (GKM_XDG_IS_TRUST (self));
	g_assert (asn);

	node = egg_asn1x_node (asn, "trusts", NULL);
	egg_asn1x_clear (node);

	g_hash_table_iter_init (&iter, self->pv->assertions);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		assertion = GKM_ASSERTION (value);
		level = assertion_type_to_level_enum (gkm_assertion_get_trust_type (assertion));
		purpose = gkm_assertion_get_purpose (assertion);
		remote = gkm_assertion_get_remote (assertion);

		pair = egg_asn1x_append (node);
		g_return_val_if_fail (pair, FALSE);

		egg_asn1x_set_oid_as_string (egg_asn1x_node (pair, "purpose", NULL), purpose);
		egg_asn1x_set_enumerated (egg_asn1x_node (pair, "level", NULL), level);

		if (remote) {
			egg_asn1x_set_string_as_utf8 (egg_asn1x_node (pair, "remote", NULL),
			                              g_strdup (remote), g_free);
		}
	}

	return TRUE;
}

static GkmXdgTrust*
create_trust_for_reference (GkmModule *module, GkmManager *manager,
                            CK_ATTRIBUTE_PTR serial, CK_ATTRIBUTE_PTR issuer)
{
	GkmXdgTrust *trust;
	GNode *asn;

	asn = egg_asn1x_create (xdg_asn1_tab, "trust-1");
	g_return_val_if_fail (asn, NULL);

	egg_asn1x_set_integer_as_raw (egg_asn1x_node (asn, "reference", "certReference", "serialNumber", NULL),
	                              g_memdup (serial->pValue, serial->ulValueLen),
	                              serial->ulValueLen, g_free);

	egg_asn1x_set_raw_element (egg_asn1x_node (asn, "reference", "certReference", "issuer", NULL),
	                           g_memdup (issuer->pValue, issuer->ulValueLen),
	                           issuer->ulValueLen, g_free);

	trust = g_object_new (GKM_XDG_TYPE_TRUST, "module", module, "manager", manager, NULL);
	trust->pv->asn = asn;

	return trust;
}

static GkmXdgTrust*
create_trust_for_certificate (GkmModule *module, GkmManager *manager,
                              CK_ATTRIBUTE_PTR cert)
{
	GkmXdgTrust *trust;
	GNode *asn;

	asn = egg_asn1x_create (xdg_asn1_tab, "trust-1");
	g_return_val_if_fail (asn, NULL);

	egg_asn1x_set_raw_element (egg_asn1x_node (asn, "reference", "certComplete", NULL),
	                           g_memdup (cert->pValue, cert->ulValueLen),
	                           cert->ulValueLen, g_free);

	trust = g_object_new (GKM_XDG_TYPE_TRUST, "module", module, "manager", manager, NULL);
	trust->pv->asn = asn;

	return trust;
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
		return gkm_attribute_set_bool (attr, CK_FALSE);

	/* Various trust flags */
	case CKA_TRUST_SERVER_AUTH:
		return gkm_attribute_set_ulong (attr, self->pv->netscape.server_auth);
	case CKA_TRUST_CLIENT_AUTH:
		return gkm_attribute_set_ulong (attr, self->pv->netscape.client_auth);
	case CKA_TRUST_CODE_SIGNING:
		return gkm_attribute_set_ulong (attr, self->pv->netscape.code_signing);
	case CKA_TRUST_EMAIL_PROTECTION:
		return gkm_attribute_set_ulong (attr, self->pv->netscape.email_protection);
	case CKA_TRUST_IPSEC_END_SYSTEM:
		return gkm_attribute_set_ulong (attr, self->pv->netscape.ipsec_end_system);
	case CKA_TRUST_IPSEC_TUNNEL:
		return gkm_attribute_set_ulong (attr, self->pv->netscape.ipsec_tunnel);
	case CKA_TRUST_IPSEC_USER:
		return gkm_attribute_set_ulong (attr, self->pv->netscape.ipsec_user);
	case CKA_TRUST_TIME_STAMPING:
		return gkm_attribute_set_ulong (attr, self->pv->netscape.time_stamping);

	/* Certificate reference values */
	case CKA_SUBJECT:
		return trust_get_der (self, "subject", attr);
	case CKA_SERIAL_NUMBER:
		return trust_get_integer (self, "serialNumber", attr);
	case CKA_ISSUER:
		return trust_get_der (self, "issuer", attr);

	/* Certificate hash values */
	case CKA_CERT_MD5_HASH:
		return trust_get_hash (self, G_CHECKSUM_MD5, attr);
	case CKA_CERT_SHA1_HASH:
		return trust_get_hash (self, G_CHECKSUM_SHA1, attr);

	default:
		break;
	};

	return GKM_OBJECT_CLASS (gkm_xdg_trust_parent_class)->get_attribute (base, session, attr);
}

static void
gkm_xdg_trust_init (GkmXdgTrust *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GKM_XDG_TYPE_TRUST, GkmXdgTrustPrivate);
	self->pv->assertions = create_assertions ();
}

static void
gkm_xdg_trust_finalize (GObject *obj)
{
	GkmXdgTrust *self = GKM_XDG_TRUST (obj);

	if (self->pv->asn)
		egg_asn1x_destroy (self->pv->asn);
	self->pv->asn = NULL;

	if (self->pv->assertions)
		g_hash_table_destroy (self->pv->assertions);
	self->pv->assertions = NULL;

	G_OBJECT_CLASS (gkm_xdg_trust_parent_class)->finalize (obj);
}

static void
gkm_xdg_trust_class_init (GkmXdgTrustClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkmObjectClass *gkm_class = GKM_OBJECT_CLASS (klass);

	gobject_class->finalize = gkm_xdg_trust_finalize;
	gkm_class->get_attribute = gkm_xdg_trust_get_attribute;

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

	if (n_data == 0)
		return FALSE;

	copy = g_memdup (data, n_data);

	asn = egg_asn1x_create_and_decode (xdg_asn1_tab, "trust-1", copy, n_data);
	if (asn == NULL) {
		g_warning ("couldn't parse trust data");
		g_free (copy);
		return FALSE;
	}

	/* Next parse out all the pairs */
	if (!load_assertions (self, asn)) {
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

	if (!save_assertions (self, self->pv->asn))
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

GkmTrust*
gkm_xdg_trust_create_for_assertion (GkmModule *module, GkmManager *manager,
                                    GkmTransaction *transaction,
                                    CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{

	CK_ATTRIBUTE_PTR serial, issuer, cert;
	GkmXdgTrust *trust;

	g_return_val_if_fail (GKM_IS_MODULE (module), NULL);
	g_return_val_if_fail (GKM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);

	serial = gkm_attributes_find (attrs, n_attrs, CKA_SERIAL_NUMBER);
	issuer = gkm_attributes_find (attrs, n_attrs, CKA_ISSUER);
	cert = gkm_attributes_find (attrs, n_attrs, CKA_G_CERTIFICATE_VALUE);

	/* A trust object with just serial + issuer */
	if (serial != NULL && issuer != NULL) {
		if (cert != NULL) {
			gkm_transaction_fail (transaction, CKR_TEMPLATE_INCONSISTENT);
			return NULL;
		}
		if (!validate_der (issuer, "Name") || !validate_integer (serial)) {
			gkm_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
			return NULL;
		}

		trust = create_trust_for_reference (module, manager, serial, issuer);

	/* A trust object with a full certificate */
	} else if (cert != NULL) {
		if (serial != NULL || issuer != NULL) {
			gkm_transaction_fail (transaction, CKR_TEMPLATE_INCONSISTENT);
			return NULL;
		}
		if (!validate_der (cert, "TBSCertificate")) {
			gkm_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
			return NULL;
		}

		trust = create_trust_for_certificate (module, manager, cert);

	/* Not sure what this is */
	} else {
		gkm_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
		return NULL;
	}

	gkm_attributes_consume (attrs, n_attrs, CKA_G_CERTIFICATE_VALUE, CKA_ISSUER,
	                        CKA_SERIAL_NUMBER, G_MAXULONG);

	return GKM_TRUST (trust);
}
