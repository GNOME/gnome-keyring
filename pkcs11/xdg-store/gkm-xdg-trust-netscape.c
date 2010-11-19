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

#include "gkm-xdg-trust-netscape.h"

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

struct _GkmXdgTrustNetscapePrivate {
	GHashTable *assertions;
};

G_DEFINE_TYPE (GkmXdgTrustNetscape, gkm_xdg_trust_netscape, GKM_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static GkmXdgTrustNetscape*
lookup_or_create_matching_netscape_trust (GkmXdgTrust *assertion)
{
	CK_OBJECT_CLASS klass = CKO_NETSCAPE_TRUST;
	GkmXdgTrustNetscape *netscape;
	GkmManager *manager;
	GkmModule *module;
	CK_ATTRIBUTE attrs[5];
	GList *objects;

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &klass;
	attrs[0].ulValueLen = sizeof (klass);

	switch (gkm_xdg_trust_get_assertion_type (assertion)) {
	case GKM_XDG_TRUST_ROOT:
		data = gkm_xdg_trust_get_hash (assertion, G_CHECKSUM_SHA1, &n_data);
		g_return_val_if_fail (data, NULL);
		attrs[1].type = CKA_CERT_SHA1_HASH;
		attrs[1].pValue = data;
		attrs[1].ulValueLen = n_data;
		n_attrs = 2;
		break;
	case GKM_XDG_TRUST_EXCEPTION:
		data = gkm_xdg_trust_get_serial (assertion, &n_data);
		g_return_val_if_fail (data, NULL);
		attrs[1].type = CKA_SERIAL_NUMBER;
		attrs[1].pValue = data;
		attrs[1].ulValueLen = n_data;
		data = gkm_xdg_trust_get_issuer (assertion, &n_data);
		g_return_val_if_fail (data, NULL);
		attrs[2].type = CKA_ISSUER;
		attrs[2].pValue = data;
		attrs[2].ulValueLen = n_data;
		n_attrs = 3;
		break;
	default:
		g_return_val_if_reached (NULL);
	};

	manager = gkm_object_get_manager (GKM_OBJECT (assertion));
	objects = gkm_manager_find_by_attributes (manager, NULL, attrs, n_attrs);

	if (objects) {
		g_assert (objects->data);
		netscape = GKM_XDG_TRUST_NETSCAPE (objects->data);
		g_list_free (objects->data);
	} else {
		trust = g_object_new (GKM_XDG_TYPE_TRUST_NETSCAPE,
		                      "module", gkm_object_get_module (assertion),
		                      "manager", manager,
		                      NULL);
		gkm_object_expose (GKM_OBJECT (trust), TRUE);

#if XXXX
		/* Certificate reference values */
		case CKA_SUBJECT:
			return trust_get_der (self, "subject", attr);
		case CKA_SERIAL_NUMBER:
			return trust_get_integer (self, "serialNumber", attr);
		case CKA_ISSUER:
			return trust_get_der (self, "issuer", attr);

		/* Certificate hash values */
		case CKA_CERT_MD5_HASH:
			return trust_get_hash (self, OID_HASH_MD5, attr);
		case CKA_CERT_SHA1_HASH:
			return trust_get_hash (self, OID_HASH_SHA1, attr);
#endif

	}

	xxxx ownership xxxx;

	return trust;
}

static CK_RV
lookup_certificate_hash (GkmXdgTrustNetscape *self, CK_ATTRIBUTE_PTR attr, GChecksumType type)
{
	GkmXdgAssertion *assertion;
	GChecksum *checksum;
	gpointer value, hash;
	gconstpointer data;
	gsize n_data, n_hash;
	CK_RV rv;

	if (self->pv->assertion_type != CKT_G_CERTIFICATE_ROOT)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	/* Find the first assertion */
	g_hash_table_iter_init (&iter, self->pv->assertions);
	if (!g_hash_table_iter_next (&iter, NULL, &value))
		g_assert_not_reached ();
	assertion = GKM_XDG_ASSERTION (value);

	g_assert (gkm_xdg_assertion_get_assertion_type (assertion) == CKT_G_CERTIFICATE_ROOT);
	data = gkm_xdg_assertion_get_certificate_value (assertion, &n_data);
	g_return_val_if_fail (data, CKR_GENERAL_ERROR);

	checksum = g_checksum_new (type);
	g_checksum_update (checksum, data, n_data);
	n_hash = g_checksum_type_get_length (type);
	hash = g_malloc (n_hash);
	g_checksum_get_digest (checksum, hash, &n_hash);
	g_checksum_free (checksum);

	rv = gkm_attribute_set_data (attr, hash, n_hash);
	g_free (hash);

	return rv;
}

static CK_RV
lookup_assertion_attr (GkmXdgTrustNetscape *self, GkmSession *session, CK_ATTRIBUTE_PTR attr)
{
	GHashTableIter iter;
	gpointer value;

	/* Find the  first assertion, any will do */
	g_hash_table_iter_init (&iter, self->pv->assertions);
	if (!g_hash_table_iter_next (&iter, NULL, &value))
		g_assert_not_reached ();

	return gkm_object_get_attribute (GKM_OBJECT (value), session, attr);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static CK_RV
gkm_xdg_trust_get_attribute (GkmObject *base, GkmSession *session, CK_ATTRIBUTE_PTR attr)
{
	GkmXdgTrustNetscape *self = GKM_XDG_TRUST (base);
	GkmXdgAssertion *assertion;
	CK_ULONG value;

	/* Attributes like subject, issuer, cert hashes */
	for (i = 0; i < self->pv->n_attrs; ++i) {
		if (self->pv->attrs[i].type == attr->type) {
			gkm_attribute_set_data (attr, self->pv->attrs[i].pValue,
			                        self->pv->attrs[i].ulValueLen);
			return;
		}
	}

	/* Look for overrides of the default flags and restrictions below */
	assertion = g_hash_table_lookup (self->pv->assertions, &(attr->type));
	if (assertion) {
		level = gkm_xdg_assertion_get_level (assertion);
		return gkm_attribute_set_ulong (attr, level_to_netscape_trust (level));
	}

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

	/* Key restrictions */
	case CKA_TRUST_DIGITAL_SIGNATURE:
	case CKA_TRUST_NON_REPUDIATION:
	case CKA_TRUST_KEY_ENCIPHERMENT:
	case CKA_TRUST_DATA_ENCIPHERMENT:
	case CKA_TRUST_KEY_AGREEMENT:
	case CKA_TRUST_KEY_CERT_SIGN:
	case CKA_TRUST_CRL_SIGN:
		return gkm_attribute_set_ulong (attr, CKT_NETSCAPE_TRUST_UNKNOWN);

	/* Various trust flags */
	case CKA_TRUST_SERVER_AUTH:
	case CKA_TRUST_CLIENT_AUTH:
	case CKA_TRUST_CODE_SIGNING:
	case CKA_TRUST_EMAIL_PROTECTION:
	case CKA_TRUST_IPSEC_END_SYSTEM:
	case CKA_TRUST_IPSEC_TUNNEL:
	case CKA_TRUST_IPSEC_USER:
	case CKA_TRUST_TIME_STAMPING:
		return gkm_attribute_set_ulong (attr, CKT_NETSCAPE_TRUST_UNKNOWN);

	case CKA_CERT_MD5_HASH:
		return lookup_certificate_hash (self, attr, G_CHECKSUM_MD5);
	case CKA_CERT_SHA1_HASH:
		return lookup_certificate_hash (self, attr, G_CHECKSUM_SHA1);

	case CKA_LABEL:
	case CKA_SUBJECT:
	case CKA_ISSUER:
	case CKA_SERIAL_NUMBER:
		return lookup_assertion_value (self, session, attr);

	default:
		break;
	};

	return GKM_OBJECT_CLASS (gkm_xdg_trust_parent_class)->get_attribute (base, session, attr);
}

static void
gkm_xdg_trust_init (GkmXdgTrust *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GKM_XDG_TYPE_TRUST, GkmXdgTrustPrivate);
	self->pv->assertions = g_hash_table_new (gkm_util_ulong_hash, gkm_util_ulong_equal);
}

static void
gkm_xdg_trust_finalize (GObject *obj)
{
	GkmXdgTrust *self = GKM_XDG_TRUST (obj);

	g_assert (self->pv->assertions);
	g_hash_table_destroy (self->pv->assertions);
	self->pv->assertions = NULL;

	g_free (self->pv->attrs);
	self->pv->attrs = NULL;
	self->pv->n_attrs = 0;

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
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

void
gkm_xdg_trust_netscape_register_assertion (GkmXdgTrustAssertion *assertion)
{
	GHashTable *netscape_trusts;
	GkmXdgTrustLevel level;
	const gchar *purpose;

	g_return_if_fail (GKM_IS_MODULE (module));
	g_return_if_fail (GKM_XDG_IS_TRUST_ASSERTION (assertion));

	trust = lookup_or_create_matching_netscape_trust (assertion);

	level = gkm_xdg_trust_get_level (assertion);
	purpose = gkm_xdg_trust_get_purpose (assertion);
	g_return_if_fail (purpose);

	type = netscape_type_for_purpose (purpose);
	value = netscape_trust_for_level (level);

}
