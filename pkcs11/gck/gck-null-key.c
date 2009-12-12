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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "gck-attributes.h"
#include "gck-null-mechanism.h"
#include "gck-null-key.h"
#include "gck-session.h"
#include "gck-util.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11i.h"

struct _GckNullKey {
	GckSecretKey parent;
};

G_DEFINE_TYPE (GckNullKey, gck_null_key, GCK_TYPE_SECRET_KEY);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static GckObject*
factory_create_null_key (GckSession *session, GckTransaction *transaction,
                         CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	GckNullKey *key;
	GckManager *manager;

	manager = gck_manager_for_template (attrs, n_attrs, session);
	key = g_object_new (GCK_TYPE_NULL_KEY,
	                    "module", gck_session_get_module (session),
	                    "manager", manager,
	                    NULL);

	gck_session_complete_object_creation (session, transaction, GCK_OBJECT (key), attrs, n_attrs);
	return GCK_OBJECT (key);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static CK_RV
gck_null_key_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE *attr)
{
	switch (attr->type)
	{
	case CKA_KEY_TYPE:
		return gck_attribute_set_ulong (attr, CKK_G_NULL);

	case CKA_UNWRAP:
	case CKA_WRAP:
		return gck_attribute_set_bool (attr, CK_TRUE);

	case CKA_VALUE:
		return gck_attribute_set_empty (attr);

	case CKA_VALUE_LEN:
		return gck_attribute_set_ulong (attr, 0);

	case CKA_CHECK_VALUE:
		return gck_attribute_set_data (attr, "\0\0\0", 3);

	case CKA_ALLOWED_MECHANISMS:
		return gck_attribute_set_data (attr, (CK_VOID_PTR)GCK_NULL_MECHANISMS,
		                               sizeof (GCK_NULL_MECHANISMS));
	};

	return GCK_OBJECT_CLASS (gck_null_key_parent_class)->get_attribute (base, session, attr);
}

static void
gck_null_key_init (GckNullKey *self)
{

}

static void
gck_null_key_class_init (GckNullKeyClass *klass)
{
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);

	gck_null_key_parent_class = g_type_class_peek_parent (klass);
	gck_class->get_attribute = gck_null_key_real_get_attribute;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GckFactory*
gck_null_key_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_SECRET_KEY;
	static CK_KEY_TYPE type = CKK_G_NULL;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_KEY_TYPE, &type, sizeof (type) }
	};

	static GckFactory factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_null_key
	};

	return &factory;
}
