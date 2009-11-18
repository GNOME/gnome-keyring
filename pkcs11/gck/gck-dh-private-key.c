/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Private License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Private License for more details.
 *
 * You should have received a copy of the GNU Lesser General Private
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "pkcs11/pkcs11.h"

#include "gck-attributes.h"
#include "gck-crypto.h"
#include "gck-factory.h"
#include "gck-dh-private-key.h"
#include "gck-session.h"
#include "gck-transaction.h"
#include "gck-util.h"

struct _GckDhPrivateKey {
	GckDhKey parent;
	gcry_mpi_t value;
};

G_DEFINE_TYPE (GckDhPrivateKey, gck_dh_private_key, GCK_TYPE_DH_KEY);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
factory_create_dh_private_key (GckSession *session, GckTransaction *transaction,
                               CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, GckObject **object)
{
	GckManager *manager;
	gcry_mpi_t prime = NULL;
	gcry_mpi_t base = NULL;
	gcry_mpi_t value = NULL;
	CK_ATTRIBUTE_PTR idattr;

	if (!gck_attributes_find_mpi (attrs, n_attrs, CKA_PRIME, &prime) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_BASE, &base) ||
	    !gck_attributes_find_mpi (attrs, n_attrs, CKA_VALUE, &value)) {
		gcry_mpi_release (prime);
		gcry_mpi_release (base);
		gcry_mpi_release (value);
		return gck_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
	}

	manager = gck_manager_for_template (attrs, n_attrs, session);
	idattr = gck_attributes_find (attrs, n_attrs, CKA_ID);

	*object = GCK_OBJECT (gck_dh_private_key_new (gck_session_get_module (session),
	                                             manager, prime, base, value,
	                                             idattr ? g_memdup (idattr->pValue, idattr->ulValueLen) : NULL,
	                                             idattr ? idattr->ulValueLen : 0));
	gck_attributes_consume (attrs, n_attrs, CKA_PRIME, CKA_BASE, CKA_VALUE, G_MAXULONG);
}

/* -----------------------------------------------------------------------------
 * DH_PRIVATE_KEY
 */

static CK_RV
gck_dh_private_key_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE* attr)
{
	GckDhPrivateKey *self = GCK_DH_PRIVATE_KEY (base);

	switch (attr->type)
	{

	case CKA_CLASS:
		return gck_attribute_set_ulong (attr, CKO_PRIVATE_KEY);

	case CKA_PRIVATE:
		return gck_attribute_set_bool (attr, TRUE);

	case CKA_SENSITIVE:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_DECRYPT:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_SIGN:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_SIGN_RECOVER:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_DERIVE:
		return gck_attribute_set_bool (attr, TRUE);

	case CKA_UNWRAP:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_EXTRACTABLE:
		return gck_attribute_set_bool (attr, TRUE);

	case CKA_ALWAYS_SENSITIVE:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_NEVER_EXTRACTABLE:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_WRAP_WITH_TRUSTED:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_UNWRAP_TEMPLATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;

	case CKA_ALWAYS_AUTHENTICATE:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_VALUE:
		return gck_attribute_set_mpi (attr, self->value);

	case CKA_VALUE_BITS:
		return gck_attribute_set_ulong (attr, gcry_mpi_get_nbits (self->value));
	};

	return GCK_OBJECT_CLASS (gck_dh_private_key_parent_class)->get_attribute (base, session, attr);
}

static void
gck_dh_private_key_init (GckDhPrivateKey *self)
{

}

static void
gck_dh_private_key_finalize (GObject *obj)
{
	GckDhPrivateKey *self = GCK_DH_PRIVATE_KEY (obj);

	gcry_mpi_release (self->value);
	self->value = NULL;

	G_OBJECT_CLASS (gck_dh_private_key_parent_class)->finalize (obj);
}

static void
gck_dh_private_key_class_init (GckDhPrivateKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);

	gck_dh_private_key_parent_class = g_type_class_peek_parent (klass);

	gobject_class->finalize = gck_dh_private_key_finalize;

	gck_class->get_attribute = gck_dh_private_key_real_get_attribute;
}

/* -----------------------------------------------------------------------------
 * PRIVATE
 */

GckFactory*
gck_dh_private_key_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
	static CK_KEY_TYPE type = CKK_DH;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_KEY_TYPE, &type, sizeof (type) }
	};

	static GckFactory factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_dh_private_key
	};

	return &factory;
}

GckDhPrivateKey*
gck_dh_private_key_new (GckModule *module, GckManager *manager,
                        gcry_mpi_t prime, gcry_mpi_t base, gcry_mpi_t value,
                        gpointer id, gsize n_id)
{
	GckDhPrivateKey *key;

	key = g_object_new (GCK_TYPE_DH_PRIVATE_KEY,
	                    "manager", manager,
	                    "module", module,
	                    NULL);

	gck_dh_key_initialize (GCK_DH_KEY (key), prime, base, id, n_id);
	key->value = value;
	return key;
}

gcry_mpi_t
gck_dh_private_key_get_value (GckDhPrivateKey *self)
{
	g_return_val_if_fail (GCK_IS_DH_PRIVATE_KEY (self), NULL);
	return self->value;
}
