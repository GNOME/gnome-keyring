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
 * You should have received a copy of the GNU Lesser General Private
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "pkcs11/pkcs11.h"

#include "gck-attributes.h"
#include "gck-credential.h"
#include "gck-factory.h"
#include "gck-private-xsa-key.h"
#include "gck-session.h"
#include "gck-transaction.h"
#include "gck-util.h"

struct _GckPrivateXsaKeyPrivate {
	GckSexp *sexp;
};

G_DEFINE_TYPE (GckPrivateXsaKey, gck_private_xsa_key, GCK_TYPE_KEY);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */


static CK_RV
create_rsa_private (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, gcry_sexp_t *skey)
{
	gcry_error_t gcry;
	gcry_mpi_t n = NULL;
	gcry_mpi_t e = NULL;
	gcry_mpi_t d = NULL;
	gcry_mpi_t p = NULL;
	gcry_mpi_t q = NULL;
	gcry_mpi_t u = NULL;
	CK_RV ret;

	if (!gck_attributes_find_mpi (attrs, n_attrs, CKA_MODULUS, &n) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_PUBLIC_EXPONENT, &e) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_PRIVATE_EXPONENT, &d) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_PRIME_1, &p) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_PRIME_2, &q)) {
		ret = CKR_TEMPLATE_INCOMPLETE;
		goto done;
	}

	/* Fix up the incoming key so gcrypt likes it */
	if (gcry_mpi_cmp (p, q) > 0)
		gcry_mpi_swap (p, q);

	/* Compute U.  */
	u = gcry_mpi_snew (gcry_mpi_get_nbits (n));
	gcry_mpi_invm (u, p, q);

	gcry = gcry_sexp_build (skey, NULL,
	                        "(private-key (rsa (n %m) (e %m) (d %m) (p %m) (q %m) (u %m)))",
	                        n, e, d, p, q, u);

	if (gcry != 0) {
		g_message ("couldn't create RSA key from passed attributes: %s", gcry_strerror (gcry));
		ret = CKR_FUNCTION_FAILED;
		goto done;
	}

	gck_attributes_consume (attrs, n_attrs, CKA_MODULUS, CKA_PUBLIC_EXPONENT,
	                        CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2,
	                        CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT, G_MAXULONG);
	ret = CKR_OK;

done:
	gcry_mpi_release (n);
	gcry_mpi_release (e);
	gcry_mpi_release (d);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (u);
	return ret;
}

static CK_RV
create_dsa_private (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, gcry_sexp_t *skey)
{
	gcry_error_t gcry;
	gcry_mpi_t p = NULL;
	gcry_mpi_t q = NULL;
	gcry_mpi_t g = NULL;
	gcry_mpi_t y = NULL;
	gcry_mpi_t value = NULL;
	CK_RV ret;

	if (!gck_attributes_find_mpi (attrs, n_attrs, CKA_PRIME, &p) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_SUBPRIME, &q) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_BASE, &g) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_VALUE, &value)) {
		ret = CKR_TEMPLATE_INCOMPLETE;
		goto done;
	}

	/* Calculate the public part from the private */
	y = gcry_mpi_snew (gcry_mpi_get_nbits (value));
	g_return_val_if_fail (y, CKR_GENERAL_ERROR);
	gcry_mpi_powm (y, g, value, p);

	gcry = gcry_sexp_build (skey, NULL,
	                        "(private-key (dsa (p %m) (q %m) (g %m) (y %m) (x %m)))",
	                        p, q, g, y, value);

	if (gcry != 0) {
		g_message ("couldn't create DSA key from passed attributes: %s", gcry_strerror (gcry));
		ret = CKR_FUNCTION_FAILED;
		goto done;
	}

	gck_attributes_consume (attrs, n_attrs, CKA_PRIME, CKA_SUBPRIME,
	                        CKA_BASE, CKA_VALUE, G_MAXULONG);
	ret = CKR_OK;

done:
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (value);
	return ret;
}

static void
factory_create_private_xsa_key (GckSession *session, GckTransaction *transaction,
                            CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, GckObject **object)
{
	GckPrivateXsaKey *key;
	GckSexp *sexp;

	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (attrs || !n_attrs);
	g_return_if_fail (object);

	sexp = gck_private_xsa_key_create_sexp (session, transaction, attrs, n_attrs);
	if (sexp == NULL)
		return;

	key = g_object_new (GCK_TYPE_PRIVATE_XSA_KEY, "base-sexp", sexp,
	                    "module", gck_session_get_module (session),
	                    "manager", gck_manager_for_template (attrs, n_attrs, session),
	                    NULL);
	key->pv->sexp = sexp;
	*object = GCK_OBJECT (key);
}

static gboolean
acquire_from_credential (GckCredential *cred, GckObject *object, gpointer user_data)
{
	GckSexp **result = user_data;

	g_assert (result);
	g_assert (!*result);

	/* The sexp we stored on the credential */
	*result = gck_credential_get_data (cred);
	if (*result != NULL) {
		*result = gck_sexp_ref (*result);
		gck_credential_throw_away_one_use (cred);
		return TRUE;
	}

	return FALSE;
}

static gboolean
have_from_credential (GckCredential *cred, GckObject *object, gpointer unused)
{
	/* The sexp we stored on the credential */
	return gck_credential_get_data (cred) ? TRUE : FALSE;
}

/* -----------------------------------------------------------------------------
 * PRIVATE_XSA_KEY
 */

static CK_RV
gck_private_xsa_key_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE* attr)
{
	GckPrivateXsaKey *self = GCK_PRIVATE_XSA_KEY (base);
	gboolean have;

	switch (attr->type) {
	case CKA_CLASS:
		return gck_attribute_set_ulong (attr, CKO_PRIVATE_KEY);

	case CKA_PRIVATE:
		return gck_attribute_set_bool (attr, TRUE);

	case CKA_SENSITIVE:
		return gck_attribute_set_bool (attr, TRUE);

	case CKA_DECRYPT:
		return gck_attribute_set_bool (attr, gck_key_get_algorithm (GCK_KEY (self)) == GCRY_PK_RSA);

	case CKA_SIGN:
		return gck_attribute_set_bool (attr, TRUE);

	case CKA_SIGN_RECOVER:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_UNWRAP:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_EXTRACTABLE:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_ALWAYS_SENSITIVE:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_NEVER_EXTRACTABLE:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_WRAP_WITH_TRUSTED:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_UNWRAP_TEMPLATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;

	case CKA_ALWAYS_AUTHENTICATE:
		have = self->pv->sexp ? TRUE : FALSE;
		if (!have && session)
			have = gck_session_for_each_credential (session, base, have_from_credential, NULL);
		return gck_attribute_set_bool (attr, !have);

	case CKA_MODULUS:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_RSA, "n", attr);

	case CKA_PUBLIC_EXPONENT:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_RSA, "e", attr);

	/* RSA private key parts */
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
		return CKR_ATTRIBUTE_SENSITIVE;

	case CKA_PRIME:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_DSA, "p", attr);

	case CKA_SUBPRIME:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_DSA, "q", attr);

	case CKA_BASE:
		return gck_key_set_key_part (GCK_KEY (self), GCRY_PK_DSA, "g", attr);

	/* DSA private parts */
	case CKA_VALUE:
		return CKR_ATTRIBUTE_SENSITIVE;
	};

	return GCK_OBJECT_CLASS (gck_private_xsa_key_parent_class)->get_attribute (base, session, attr);
}

static GckSexp*
gck_private_xsa_key_real_acquire_crypto_sexp (GckKey *base, GckSession *session)
{
	GckPrivateXsaKey *self = GCK_PRIVATE_XSA_KEY (base);
	GckSexp *sexp = NULL;

	/* We have an unlocked private key here */
	if (self->pv->sexp)
		sexp = gck_sexp_ref (self->pv->sexp);

	/* Find an credential, with an unlocked copy */
	else
		gck_session_for_each_credential (session, GCK_OBJECT (self),
		                                 acquire_from_credential, &sexp);

	return sexp;
}

static void
gck_private_xsa_key_init (GckPrivateXsaKey *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_PRIVATE_XSA_KEY, GckPrivateXsaKeyPrivate);
}

static void
gck_private_xsa_key_dispose (GObject *obj)
{
	GckPrivateXsaKey *self = GCK_PRIVATE_XSA_KEY (obj);

	if (self->pv->sexp)
		gck_sexp_unref (self->pv->sexp);
	self->pv->sexp = NULL;

	G_OBJECT_CLASS (gck_private_xsa_key_parent_class)->dispose (obj);
}

static void
gck_private_xsa_key_finalize (GObject *obj)
{
	GckPrivateXsaKey *self = GCK_PRIVATE_XSA_KEY (obj);

	g_assert (self->pv->sexp == NULL);

	G_OBJECT_CLASS (gck_private_xsa_key_parent_class)->finalize (obj);
}

static void
gck_private_xsa_key_class_init (GckPrivateXsaKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	GckKeyClass *key_class = GCK_KEY_CLASS (klass);

	gck_private_xsa_key_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GckPrivateXsaKeyPrivate));

	gobject_class->dispose = gck_private_xsa_key_dispose;
	gobject_class->finalize = gck_private_xsa_key_finalize;

	gck_class->get_attribute = gck_private_xsa_key_real_get_attribute;

	key_class->acquire_crypto_sexp = gck_private_xsa_key_real_acquire_crypto_sexp;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

void
gck_private_xsa_key_set_unlocked_private (GckPrivateXsaKey *self, GckSexp *sexp)
{
	g_return_if_fail (GCK_IS_PRIVATE_XSA_KEY (self));
	g_return_if_fail (sexp);

	if (sexp)
		gck_sexp_ref (sexp);
	if (self->pv->sexp)
		gck_sexp_unref (self->pv->sexp);
	self->pv->sexp = sexp;
}

void
gck_private_xsa_key_set_locked_private (GckPrivateXsaKey *self, GckCredential *cred,
                                        GckSexp *sexp)
{
	g_return_if_fail (GCK_IS_PRIVATE_XSA_KEY (self));
	g_return_if_fail (GCK_IS_CREDENTIAL (cred));
	g_return_if_fail (gck_credential_get_object (cred) == GCK_OBJECT (self));
	if (sexp != NULL)
		gck_sexp_ref (sexp);
	gck_credential_set_data (cred, sexp, gck_sexp_unref);
}

GckSexp*
gck_private_xsa_key_create_sexp (GckSession *session, GckTransaction *transaction,
                                 CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	CK_KEY_TYPE type;
	gcry_sexp_t sexp;
	CK_RV ret;

	g_return_val_if_fail (GCK_IS_TRANSACTION (transaction), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);

	if (!gck_attributes_find_ulong (attrs, n_attrs, CKA_KEY_TYPE, &type)) {
		gck_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
		return NULL;
	}

	gck_attributes_consume (attrs, n_attrs, CKA_KEY_TYPE, CKA_CLASS, G_MAXULONG);

	switch (type) {
	case CKK_RSA:
		ret = create_rsa_private (attrs, n_attrs, &sexp);
		break;
	case CKK_DSA:
		ret = create_dsa_private (attrs, n_attrs, &sexp);
		break;
	default:
		ret = CKR_ATTRIBUTE_VALUE_INVALID;
		break;
	};

	if (ret != CKR_OK) {
		gck_transaction_fail (transaction, ret);
		return NULL;
	}

	g_return_val_if_fail (sexp, NULL);
	return gck_sexp_new (sexp);
}

GckFactory*
gck_private_xsa_key_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) }
	};

	static GckFactory factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_private_xsa_key
	};

	return &factory;
}
