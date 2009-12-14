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

#include "pkcs11/pkcs11.h"

#include "gck-attributes.h"
#include "gck-crypto.h"
#include "gck-dh-key.h"
#include "gck-dh-mechanism.h"
#include "gck-session.h"
#include "gck-util.h"

struct _GckDhKeyPrivate {
	gcry_mpi_t prime;
	gcry_mpi_t base;
	gpointer id;
	gsize n_id;
};

G_DEFINE_TYPE (GckDhKey, gck_dh_key, GCK_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

/* -----------------------------------------------------------------------------
 * PUBLIC_DH_KEY
 */

static CK_RV
gck_dh_key_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE* attr)
{
	GckDhKey *self = GCK_DH_KEY (base);

	switch (attr->type)
	{

	case CKA_KEY_TYPE:
		return gck_attribute_set_ulong (attr, CKK_DH);

	case CKA_START_DATE:
	case CKA_END_DATE:
		return gck_attribute_set_empty (attr);

	case CKA_LOCAL:
		return gck_attribute_set_bool (attr, FALSE);

	case CKA_KEY_GEN_MECHANISM:
		return gck_attribute_set_ulong (attr, CK_UNAVAILABLE_INFORMATION);

	case CKA_ALLOWED_MECHANISMS:
		return gck_attribute_set_data (attr, (CK_VOID_PTR)GCK_DH_MECHANISMS,
		                               sizeof (GCK_DH_MECHANISMS));

	case CKA_ID:
		return gck_attribute_set_data (attr, self->pv->id, self->pv->n_id);

	case CKA_SUBJECT:
		return gck_attribute_set_empty (attr);

	case CKA_PRIME:
		return gck_attribute_set_mpi (attr, self->pv->prime);

	case CKA_BASE:
		return gck_attribute_set_mpi (attr, self->pv->base);
	};

	return GCK_OBJECT_CLASS (gck_dh_key_parent_class)->get_attribute (base, session, attr);
}

static void
gck_dh_key_init (GckDhKey *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_DH_KEY, GckDhKeyPrivate);
}

static void
gck_dh_key_finalize (GObject *obj)
{
	GckDhKey *self = GCK_DH_KEY (obj);

	gcry_mpi_release (self->pv->prime);
	self->pv->prime = NULL;

	gcry_mpi_release (self->pv->base);
	self->pv->base = NULL;

	g_free (self->pv->id);
	self->pv->id = NULL;
	self->pv->n_id = 0;

	G_OBJECT_CLASS (gck_dh_key_parent_class)->finalize (obj);
}

static void
gck_dh_key_class_init (GckDhKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);

	gck_dh_key_parent_class = g_type_class_peek_parent (klass);

	gobject_class->finalize = gck_dh_key_finalize;

	gck_class->get_attribute = gck_dh_key_real_get_attribute;

	g_type_class_add_private (klass, sizeof (GckDhKeyPrivate));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

void
gck_dh_key_initialize (GckDhKey *self, gcry_mpi_t prime, gcry_mpi_t base,
                       gpointer id, gsize n_id)
{
	g_return_if_fail (GCK_IS_DH_KEY (self));
	g_return_if_fail (base);
	g_return_if_fail (prime);
	g_return_if_fail (!self->pv->base);
	g_return_if_fail (!self->pv->prime);

	self->pv->base = base;
	self->pv->prime = prime;
	self->pv->id = id;
	self->pv->n_id = n_id;
}

gcry_mpi_t
gck_dh_key_get_prime (GckDhKey *self)
{
	g_return_val_if_fail (GCK_IS_DH_KEY (self), NULL);
	return self->pv->prime;
}
