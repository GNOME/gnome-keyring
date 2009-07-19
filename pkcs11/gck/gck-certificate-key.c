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
#include "gck-certificate.h"
#include "gck-certificate-key.h"

#include "gck-object.h"
#include "gck-util.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_CERTIFICATE
};

struct _GckCertificateKeyPrivate {
	GckCertificate *certificate;
};

G_DEFINE_TYPE (GckCertificateKey, gck_certificate_key, GCK_TYPE_PUBLIC_KEY);

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV
gck_certificate_key_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	GckCertificateKey *self = GCK_CERTIFICATE_KEY (base);
	
	switch (attr->type) {
	case CKA_LABEL:
		if (self->pv->certificate)
			return gck_object_get_attribute (GCK_OBJECT (self->pv->certificate), session, attr);
		return gck_attribute_set_string (attr, "");
	}
	
	return GCK_OBJECT_CLASS (gck_certificate_key_parent_class)->get_attribute (base, session, attr);
}

static void
gck_certificate_key_init (GckCertificateKey *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_CERTIFICATE_KEY, GckCertificateKeyPrivate);
}

static void
gck_certificate_key_finalize (GObject *obj)
{
	GckCertificateKey *self = GCK_CERTIFICATE_KEY (obj);
	
	if (self->pv->certificate)
		g_object_remove_weak_pointer (G_OBJECT (self->pv->certificate), (gpointer*)&(self->pv->certificate));
	self->pv->certificate = NULL;
		
	G_OBJECT_CLASS (gck_certificate_key_parent_class)->finalize (obj);
}

static void
gck_certificate_key_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	GckCertificateKey *self = GCK_CERTIFICATE_KEY (obj);

	switch (prop_id) {
	case PROP_CERTIFICATE:
		g_return_if_fail (!self->pv->certificate);
		self->pv->certificate = g_value_get_object (value);
		g_return_if_fail (self->pv->certificate);
		g_object_add_weak_pointer (G_OBJECT (self->pv->certificate), (gpointer*)&(self->pv->certificate));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_certificate_key_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
	GckCertificateKey *self = GCK_CERTIFICATE_KEY (obj);

	switch (prop_id) {
	case PROP_CERTIFICATE:
		g_value_set_object (value, gck_certificate_key_get_certificate (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_certificate_key_class_init (GckCertificateKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
    
	gobject_class->finalize = gck_certificate_key_finalize;
	gobject_class->set_property = gck_certificate_key_set_property;
	gobject_class->get_property = gck_certificate_key_get_property;
	
	gck_class->get_attribute = gck_certificate_key_get_attribute;
	
	g_type_class_add_private (klass, sizeof (GckCertificateKeyPrivate));
	
	g_object_class_install_property (gobject_class, PROP_CERTIFICATE,
	           g_param_spec_object ("certificate", "Certificate", "Certificate this key belongs to", 
	                                GCK_TYPE_CERTIFICATE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));	
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckCertificateKey*
gck_certificate_key_new (GckModule *module, GckCertificate *cert)
{
	return g_object_new (GCK_TYPE_CERTIFICATE_KEY, "module", module, "certificate", cert, NULL);
}

GckCertificate*
gck_certificate_key_get_certificate (GckCertificateKey *self)
{
	g_return_val_if_fail (GCK_IS_CERTIFICATE_KEY (self), NULL);
	g_return_val_if_fail (self->pv->certificate, NULL);
	return self->pv->certificate;
}
