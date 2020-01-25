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

#include "pkcs11/pkcs11.h"

#include "gkm-attributes.h"
#define DEBUG_FLAG GKM_DEBUG_OBJECT
#include "gkm-debug.h"
#include "gkm-dsa-mechanism.h"
#include "gkm-ecdsa-mechanism.h"
#include "gkm-rsa-mechanism.h"
#include "gkm-sexp-key.h"
#include "gkm-data-der.h"
#include "gkm-util.h"

enum {
	PROP_0,
	PROP_BASE_SEXP,
	PROP_ALGORITHM
};

struct _GkmSexpKeyPrivate {
	GkmSexp *base_sexp;
};

G_DEFINE_TYPE_WITH_PRIVATE (GkmSexpKey, gkm_sexp_key, GKM_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

/* -----------------------------------------------------------------------------
 * KEY
 */

static CK_RV
gkm_sexp_key_real_get_attribute (GkmObject *base, GkmSession *session, CK_ATTRIBUTE* attr)
{
	GkmSexpKey *self = GKM_SEXP_KEY (base);

	switch (attr->type) {
	case CKA_KEY_TYPE:
		{
			switch (gkm_sexp_key_get_algorithm (self)) {
			case GCRY_PK_RSA:
				return gkm_attribute_set_ulong (attr, CKK_RSA);
			case GCRY_PK_DSA:
				return gkm_attribute_set_ulong (attr, CKK_DSA);
			case GCRY_PK_ECC:
				return gkm_attribute_set_ulong (attr, CKK_ECDSA);
			default:
				g_return_val_if_reached (CKR_GENERAL_ERROR);
			};
		}
		break;

	case CKA_ID:
		{
			guchar hash[20];
			g_return_val_if_fail (self->pv->base_sexp, CKR_GENERAL_ERROR);
			if (!gcry_pk_get_keygrip (gkm_sexp_get (self->pv->base_sexp), hash))
				g_return_val_if_reached (CKR_GENERAL_ERROR);
			return gkm_attribute_set_data (attr, hash, sizeof (hash));
		}
		break;

	case CKA_START_DATE:
	case CKA_END_DATE:
		return gkm_attribute_set_data (attr, "", 0);

	case CKA_DERIVE:
		return gkm_attribute_set_bool (attr, FALSE);

	case CKA_LOCAL:
		return gkm_attribute_set_bool (attr, FALSE);

	case CKA_KEY_GEN_MECHANISM:
		return gkm_attribute_set_ulong (attr, CK_UNAVAILABLE_INFORMATION);

	case CKA_ALLOWED_MECHANISMS:
		switch (gkm_sexp_key_get_algorithm (self)) {
		case GCRY_PK_RSA:
			return gkm_attribute_set_data (attr, (CK_VOID_PTR)GKM_RSA_MECHANISMS,
			                               sizeof (GKM_RSA_MECHANISMS));
		case GCRY_PK_DSA:
			return gkm_attribute_set_data (attr, (CK_VOID_PTR)GKM_DSA_MECHANISMS,
			                               sizeof (GKM_DSA_MECHANISMS));
		case GCRY_PK_ECC:
			return gkm_attribute_set_data (attr, (CK_VOID_PTR)GKM_ECDSA_MECHANISMS,
			                               sizeof (GKM_ECDSA_MECHANISMS));
		default:
			g_return_val_if_reached (CKR_GENERAL_ERROR);
		};

	/* Lookup the certificate subject */
	case CKA_SUBJECT:
		/* TODO: When we have certificates, implement this */
		return gkm_attribute_set_data (attr, "", 0);
	};

	return GKM_OBJECT_CLASS (gkm_sexp_key_parent_class)->get_attribute (base, session, attr);
}

static void
gkm_sexp_key_init (GkmSexpKey *self)
{
	self->pv = gkm_sexp_key_get_instance_private (self);
}

static void
gkm_sexp_key_finalize (GObject *obj)
{
	GkmSexpKey *self = GKM_SEXP_KEY (obj);

	if (self->pv->base_sexp)
		gkm_sexp_unref (self->pv->base_sexp);
	self->pv->base_sexp = NULL;

	G_OBJECT_CLASS (gkm_sexp_key_parent_class)->finalize (obj);
}

static void
gkm_sexp_key_set_property (GObject *obj, guint prop_id, const GValue *value,
                      GParamSpec *pspec)
{
	GkmSexpKey *self = GKM_SEXP_KEY (obj);

	switch (prop_id) {
	case PROP_BASE_SEXP:
		gkm_sexp_key_set_base (self, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkm_sexp_key_get_property (GObject *obj, guint prop_id, GValue *value,
                      GParamSpec *pspec)
{
	GkmSexpKey *self = GKM_SEXP_KEY (obj);

	switch (prop_id) {
	case PROP_BASE_SEXP:
		g_value_set_boxed (value, gkm_sexp_key_get_base (self));
		break;
	case PROP_ALGORITHM:
		g_value_set_int (value, gkm_sexp_key_get_algorithm (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkm_sexp_key_class_init (GkmSexpKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkmObjectClass *gkm_class = GKM_OBJECT_CLASS (klass);

	gobject_class->finalize = gkm_sexp_key_finalize;
	gobject_class->set_property = gkm_sexp_key_set_property;
	gobject_class->get_property = gkm_sexp_key_get_property;

	gkm_class->get_attribute = gkm_sexp_key_real_get_attribute;

	g_object_class_install_property (gobject_class, PROP_BASE_SEXP,
	           g_param_spec_boxed ("base-sexp", "Base S-Exp", "Base Key S-Expression",
	                               GKM_BOXED_SEXP, G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_ALGORITHM,
	           g_param_spec_int ("algorithm", "Algorithm", "GCrypt Algorithm",
	                             0, G_MAXINT, 0, G_PARAM_READABLE));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkmSexp*
gkm_sexp_key_get_base (GkmSexpKey *self)
{
	g_return_val_if_fail (GKM_IS_SEXP_KEY (self), NULL);
	return self->pv->base_sexp;
}

void
gkm_sexp_key_set_base (GkmSexpKey *self, GkmSexp *sexp)
{
	g_return_if_fail (GKM_IS_SEXP_KEY (self));
	if (sexp)
		gkm_sexp_ref (sexp);
	if (self->pv->base_sexp)
		gkm_sexp_unref (self->pv->base_sexp);
	self->pv->base_sexp = sexp;
	g_object_notify (G_OBJECT (self), "base-sexp");
	g_object_notify (G_OBJECT (self), "algorithm");
}

int
gkm_sexp_key_get_algorithm (GkmSexpKey *self)
{
	int algorithm;
	g_return_val_if_fail (self->pv->base_sexp, 0);
	if (!gkm_sexp_parse_key (gkm_sexp_get (self->pv->base_sexp), &algorithm, NULL, NULL))
		g_return_val_if_reached (0);
	return algorithm;
}

static CK_RV
gkm_sexp_key_set_part_encode (GkmSexpKey *self, int algo, const char *part,
                              CK_ATTRIBUTE_PTR attr, int der_encode)
{
	gcry_sexp_t numbers;
	gcry_mpi_t mpi;
	int algorithm;
	CK_RV rv;

	g_return_val_if_fail (GKM_IS_SEXP_KEY (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (self->pv->base_sexp, CKR_GENERAL_ERROR);

	if (!gkm_sexp_parse_key (gkm_sexp_get (self->pv->base_sexp),
				 &algorithm, NULL, &numbers))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	if (algorithm != algo) {
		gcry_sexp_release (numbers);
		gkm_debug ("CKR_ATTRIBUTE_TYPE_INVALID: attribute %s not valid for key algorithm: %s",
		           gkm_log_attr_type (attr->type), gcry_pk_algo_name (algo));
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	if (!gkm_sexp_extract_mpi (numbers, &mpi, part, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	if (der_encode) {
		/* convert mpi to DER encoded OCTET string */
		GBytes *data;

		rv = gkm_data_der_encode_ecdsa_q (mpi, &data);
		g_return_val_if_fail (rv, CKR_GENERAL_ERROR);

		rv = gkm_attribute_set_bytes (attr, data);
		g_bytes_unref (data);
	} else {
		rv = gkm_attribute_set_mpi (attr, mpi);
	}

	gcry_sexp_release (numbers);
	gcry_mpi_release (mpi);

	return rv;
}

CK_RV
gkm_sexp_key_set_part (GkmSexpKey *self, int algo, const char *part, CK_ATTRIBUTE_PTR attr)
{
	return gkm_sexp_key_set_part_encode (self, algo, part, attr, 0);
}

CK_RV
gkm_sexp_key_set_ec_q (GkmSexpKey *self, int algo, CK_ATTRIBUTE_PTR attr)
{
	return gkm_sexp_key_set_part_encode (self, algo, "q", attr, 1);
}

CK_RV
gkm_sexp_key_set_ec_params (GkmSexpKey *self, int algo, CK_ATTRIBUTE_PTR attr)
{
	CK_RV rv;
	gchar *curve_name;
	GBytes *data;
	int algorithm;
	gcry_sexp_t numbers;

	g_return_val_if_fail (GKM_IS_SEXP_KEY (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (self->pv->base_sexp, CKR_GENERAL_ERROR);

	if (!gkm_sexp_parse_key (gkm_sexp_get (self->pv->base_sexp),
				 &algorithm, NULL, &numbers))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	if (algorithm != algo) {
		gcry_sexp_release (numbers);
		gkm_debug ("CKR_ATTRIBUTE_TYPE_INVALID: attribute %s not valid for key algorithm: %s",
		           gkm_log_attr_type (attr->type), gcry_pk_algo_name (algo));
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	rv = gkm_sexp_extract_string (numbers, &curve_name, "curve", NULL);
	g_return_val_if_fail (rv, CKR_GENERAL_ERROR);

	data = gkm_data_der_curve_to_ec_params (curve_name);
	g_return_val_if_fail (data != NULL, CKR_GENERAL_ERROR);

	rv = gkm_attribute_set_bytes (attr, data);
	g_bytes_unref (data);
	gcry_sexp_release (numbers);
	g_free (curve_name);

	return rv;
}

GkmSexp*
gkm_sexp_key_acquire_crypto_sexp (GkmSexpKey *self, GkmSession *session)
{
	g_return_val_if_fail (GKM_IS_SEXP_KEY (self), NULL);
	g_return_val_if_fail (GKM_SEXP_KEY_GET_CLASS (self)->acquire_crypto_sexp, NULL);
	return GKM_SEXP_KEY_GET_CLASS (self)->acquire_crypto_sexp (self, session);
}
