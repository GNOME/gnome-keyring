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

#include "gck-private-key.h"
#include "gck-util.h"

#if 0
enum {
	PROP_0
};
#endif

struct _GckPrivateKeyPrivate {
	guint sexp_uses;
	GckSexp *sexp;
};

G_DEFINE_TYPE (GckPrivateKey, gck_private_key, GCK_TYPE_KEY);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

/* -----------------------------------------------------------------------------
 * PRIVATE_KEY 
 */

static CK_RV 
gck_private_key_real_get_attribute (GckObject *base, CK_ATTRIBUTE* attr)
{
	GckPrivateKey *self = GCK_PRIVATE_KEY (base);
	
	switch (attr->type) {
	case CKA_CLASS:
		return gck_util_set_ulong (attr, CKO_PRIVATE_KEY);
		
	case CKA_PRIVATE:
		return gck_util_set_bool (attr, TRUE);

	case CKA_SENSITIVE:
		return gck_util_set_bool (attr, TRUE);
		
	case CKA_DECRYPT:
		return gck_util_set_bool (attr, gck_key_get_algorithm (GCK_KEY (self)) == GCRY_PK_RSA); 
		
	case CKA_SIGN:
		return gck_util_set_bool (attr, TRUE);
		
	case CKA_SIGN_RECOVER:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_UNWRAP:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_EXTRACTABLE:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_ALWAYS_SENSITIVE:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_NEVER_EXTRACTABLE:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_WRAP_WITH_TRUSTED:
		return gck_util_set_bool (attr, FALSE);
		
	case CKA_UNWRAP_TEMPLATE:
		return CKR_ATTRIBUTE_TYPE_INVALID;
		
	case CKA_ALWAYS_AUTHENTICATE:
		return gck_util_set_bool (attr, self->pv->sexp_uses <= 1);
		
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
	
	return GCK_OBJECT_CLASS (gck_private_key_parent_class)->get_attribute (base, attr);
}

#if 0
static CK_RV 
gck_private_key_real_set_attribute (GckPrivateKey *private_key, const CK_ATTRIBUTE* attr)
{
	switch (attr->type) {
	/* TODO: CKA_LABEL */

	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
		return CKR_ATTRIBUTE_READ_ONLY;
		
	case CKA_CLASS:
		return CKR_ATTRIBUTE_READ_ONLY;
	};
	
xxx
}
#endif

static GckSexp*
gck_private_key_real_acquire_crypto_sexp (GckKey *base)
{
	GckPrivateKey *self = GCK_PRIVATE_KEY (base);
	GckSexp *sexp;
	
	if (self->pv->sexp_uses == 0) {
		g_return_val_if_fail (!self->pv->sexp, NULL);
		return NULL;
	}
	
	g_return_val_if_fail (self->pv->sexp, NULL);
		
	sexp = gck_sexp_ref (self->pv->sexp);
	--(self->pv->sexp_uses);
		
	if (self->pv->sexp_uses == 0) {
		gck_sexp_unref (self->pv->sexp);
		self->pv->sexp = NULL;
	}
		
	return sexp;
}

static GObject* 
gck_private_key_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckPrivateKey *self = GCK_PRIVATE_KEY (G_OBJECT_CLASS (gck_private_key_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	


	
	return G_OBJECT (self);
}

static void
gck_private_key_init (GckPrivateKey *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_PRIVATE_KEY, GckPrivateKeyPrivate);

}

static void
gck_private_key_dispose (GObject *obj)
{
	GckPrivateKey *self = GCK_PRIVATE_KEY (obj);

	if (self->pv->sexp)
		gck_sexp_unref (self->pv->sexp);
	self->pv->sexp = NULL;

	G_OBJECT_CLASS (gck_private_key_parent_class)->dispose (obj);
}

static void
gck_private_key_finalize (GObject *obj)
{
	GckPrivateKey *self = GCK_PRIVATE_KEY (obj);

	g_assert (self->pv->sexp == NULL);
	
	G_OBJECT_CLASS (gck_private_key_parent_class)->finalize (obj);
}

static void
gck_private_key_set_property (GObject *obj, guint prop_id, const GValue *value, 
                              GParamSpec *pspec)
{
#if 0
	GckPrivateKey *self = GCK_PRIVATE_KEY (obj);
#endif
	
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_private_key_get_property (GObject *obj, guint prop_id, GValue *value, 
                              GParamSpec *pspec)
{
#if 0
	GckPrivateKey *self = GCK_PRIVATE_KEY (obj);
#endif
	
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_private_key_class_init (GckPrivateKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	GckKeyClass *key_class = GCK_KEY_CLASS (klass);
	
	gck_private_key_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GckPrivateKeyPrivate));

	gobject_class->constructor = gck_private_key_constructor;
	gobject_class->dispose = gck_private_key_dispose;
	gobject_class->finalize = gck_private_key_finalize;
	gobject_class->set_property = gck_private_key_set_property;
	gobject_class->get_property = gck_private_key_get_property;
	
	gck_class->get_attribute = gck_private_key_real_get_attribute;
#if 0
	gck_class->set_attribute = gck_private_key_real_set_attribute;
#endif
	
	key_class->acquire_crypto_sexp = gck_private_key_real_acquire_crypto_sexp;
    
#if 0
	g_private_key_class_install_property (gprivate_key_class, PROP_PRIVATE_KEY,
	           g_param_spec_pointer ("private_key", "PrivateKey", "PrivateKey.", G_PARAM_READWRITE));
    
	signals[SIGNAL] = g_signal_new ("signal", GCK_TYPE_PRIVATE_KEY, 
	                                G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GckPrivateKeyClass, signal),
	                                NULL, NULL, g_cclosure_marshal_VOID__OBJECT, 
	                                G_TYPE_NONE, 0);
#endif
}

/* -----------------------------------------------------------------------------
 * PRIVATE 
 */

void
gck_private_key_store_private (GckPrivateKey *self, GckSexp *sexp, guint num_uses)
{
	g_return_if_fail (GCK_IS_PRIVATE_KEY (self));
	g_return_if_fail (!sexp || num_uses);
	
	if (sexp)
		gck_sexp_ref (sexp);
	if (self->pv->sexp) 
		gck_sexp_unref (self->pv->sexp);
	self->pv->sexp = sexp;
	self->pv->sexp_uses = num_uses;
}
