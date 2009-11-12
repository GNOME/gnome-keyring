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

#include "gck-attributes.h"
#include "gck-mechanism-dsa.h"
#include "gck-mechanism-rsa.h"
#include "gck-sexp-key.h"
#include "gck-util.h"

enum {
	PROP_0,
	PROP_BASE_SEXP,
	PROP_ALGORITHM
};

struct _GckSexpKeyPrivate {
	GckSexp *base_sexp;
};

G_DEFINE_TYPE (GckSexpKey, gck_sexp_key, GCK_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

/* -----------------------------------------------------------------------------
 * KEY
 */

static CK_RV
gck_sexp_key_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE* attr)
{
	GckSexpKey *self = GCK_SEXP_KEY (base);

	switch (attr->type) {
	case CKA_KEY_TYPE:
		{
			switch (gck_sexp_key_get_algorithm (self)) {
			case GCRY_PK_RSA:
				return gck_attribute_set_ulong (attr, CKK_RSA);
			case GCRY_PK_DSA:
				return gck_attribute_set_ulong (attr, CKK_DSA);
			default:
				g_return_val_if_reached (CKR_GENERAL_ERROR);
			};
		}
		break;

	case CKA_ID:
		{
			guchar hash[20];
			g_return_val_if_fail (self->pv->base_sexp, CKR_GENERAL_ERROR);
			if (!gcry_pk_get_keygrip (gck_sexp_get (self->pv->base_sexp), hash))
				g_return_val_if_reached (CKR_GENERAL_ERROR);
			return gck_attribute_set_data (attr, hash, sizeof (hash));
		}
		break;

	case CKA_START_DATE:
	case CKA_END_DATE:
		return gck_attribute_set_data (attr, "", 0);

	case CKA_DERIVE:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_LOCAL:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_KEY_GEN_MECHANISM:
		return gck_attribute_set_ulong (attr, CK_UNAVAILABLE_INFORMATION);

	case CKA_ALLOWED_MECHANISMS:
		switch (gck_sexp_key_get_algorithm (self)) {
		case GCRY_PK_RSA:
			return gck_attribute_set_data (attr, (CK_VOID_PTR)GCK_CRYPTO_RSA_MECHANISMS,
			                               sizeof (GCK_CRYPTO_RSA_MECHANISMS));
		case GCRY_PK_DSA:
			return gck_attribute_set_data (attr, (CK_VOID_PTR)GCK_CRYPTO_DSA_MECHANISMS,
			                               sizeof (GCK_CRYPTO_DSA_MECHANISMS));
		default:
			g_return_val_if_reached (CKR_GENERAL_ERROR);
		};

	/* Lookup the certificate subject */
	case CKA_SUBJECT:
		/* TODO: When we have certificates, implement this */
		return gck_attribute_set_data (attr, "", 0);
	};

	return GCK_OBJECT_CLASS (gck_sexp_key_parent_class)->get_attribute (base, session, attr);
}

static void
gck_sexp_key_init (GckSexpKey *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_SEXP_KEY, GckSexpKeyPrivate);
}

static void
gck_sexp_key_finalize (GObject *obj)
{
	GckSexpKey *self = GCK_SEXP_KEY (obj);

	if (self->pv->base_sexp)
		gck_sexp_unref (self->pv->base_sexp);
	self->pv->base_sexp = NULL;

	G_OBJECT_CLASS (gck_sexp_key_parent_class)->finalize (obj);
}

static void
gck_sexp_key_set_property (GObject *obj, guint prop_id, const GValue *value,
                      GParamSpec *pspec)
{
	GckSexpKey *self = GCK_SEXP_KEY (obj);

	switch (prop_id) {
	case PROP_BASE_SEXP:
		gck_sexp_key_set_base (self, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_sexp_key_get_property (GObject *obj, guint prop_id, GValue *value,
                      GParamSpec *pspec)
{
	GckSexpKey *self = GCK_SEXP_KEY (obj);

	switch (prop_id) {
	case PROP_BASE_SEXP:
		g_value_set_boxed (value, gck_sexp_key_get_base (self));
		break;
	case PROP_ALGORITHM:
		g_value_set_int (value, gck_sexp_key_get_algorithm (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_sexp_key_class_init (GckSexpKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);

	gck_sexp_key_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GckSexpKeyPrivate));

	gobject_class->finalize = gck_sexp_key_finalize;
	gobject_class->set_property = gck_sexp_key_set_property;
	gobject_class->get_property = gck_sexp_key_get_property;

	gck_class->get_attribute = gck_sexp_key_real_get_attribute;

	g_object_class_install_property (gobject_class, PROP_BASE_SEXP,
	           g_param_spec_boxed ("base-sexp", "Base S-Exp", "Base Key S-Expression",
	                               GCK_BOXED_SEXP, G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_ALGORITHM,
	           g_param_spec_int ("algorithm", "Algorithm", "GCrypt Algorithm",
	                             0, G_MAXINT, 0, G_PARAM_READABLE));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GckSexp*
gck_sexp_key_get_base (GckSexpKey *self)
{
	g_return_val_if_fail (GCK_IS_SEXP_KEY (self), NULL);
	return self->pv->base_sexp;
}

void
gck_sexp_key_set_base (GckSexpKey *self, GckSexp *sexp)
{
	g_return_if_fail (GCK_IS_SEXP_KEY (self));
	if (sexp)
		gck_sexp_ref (sexp);
	if (self->pv->base_sexp)
		gck_sexp_unref (self->pv->base_sexp);
	self->pv->base_sexp = sexp;
	g_object_notify (G_OBJECT (self), "base-sexp");
	g_object_notify (G_OBJECT (self), "algorithm");
}

int
gck_sexp_key_get_algorithm (GckSexpKey *self)
{
	int algorithm;
	g_return_val_if_fail (self->pv->base_sexp, 0);
	if (!gck_sexp_parse_key (gck_sexp_get (self->pv->base_sexp), &algorithm, NULL, NULL))
		g_return_val_if_reached (0);
	return algorithm;
}

CK_RV
gck_sexp_key_set_part (GckSexpKey *self, int algo, const char *part, CK_ATTRIBUTE_PTR attr)
{
	gcry_sexp_t numbers;
	gcry_mpi_t mpi;
	int algorithm;
	CK_RV rv;

	g_return_val_if_fail (GCK_IS_SEXP_KEY (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (self->pv->base_sexp, CKR_GENERAL_ERROR);

	if (!gck_sexp_parse_key (gck_sexp_get (self->pv->base_sexp),
	                                &algorithm, NULL, &numbers))
		g_return_val_if_reached (CKR_GENERAL_ERROR);

	if (algorithm != algo) {
		gcry_sexp_release (numbers);
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	if (!gck_sexp_extract_mpi (numbers, &mpi, part, NULL))
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	rv = gck_attribute_set_mpi (attr, mpi);
	gcry_sexp_release (numbers);
	gcry_mpi_release (mpi);

	return rv;
}

GckSexp*
gck_sexp_key_acquire_crypto_sexp (GckSexpKey *self, GckSession *session)
{
	g_return_val_if_fail (GCK_IS_SEXP_KEY (self), NULL);
	g_return_val_if_fail (GCK_SEXP_KEY_GET_CLASS (self)->acquire_crypto_sexp, NULL);
	return GCK_SEXP_KEY_GET_CLASS (self)->acquire_crypto_sexp (self, session);
}
