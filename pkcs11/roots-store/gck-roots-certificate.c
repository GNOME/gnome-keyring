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

#include "gck-roots-certificate.h"

#include "gck/gck-attributes.h"
#include "gck/gck-certificate-trust.h"
#include "gck/gck-manager.h"
#include "gck/gck-object.h"
#include "gck/gck-sexp.h"
#include "gck/gck-util.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_PATH,
	PROP_NETSCAPE_TRUST,
};

struct _GckRootsCertificate {
	GckCertificate parent;
	GckCertificateTrust *trust;
	gchar *path;
};

G_DEFINE_TYPE (GckRootsCertificate, gck_roots_certificate, GCK_TYPE_CERTIFICATE);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */


/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV
gck_roots_certificate_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	GckRootsCertificate *self = GCK_ROOTS_CERTIFICATE (base);
	CK_ULONG category;
	
	switch (attr->type) {
	case CKA_TRUSTED:
		return gck_attribute_set_bool (attr, TRUE);
		
	case CKA_CERTIFICATE_CATEGORY:
		if (!gck_certificate_calc_category (GCK_CERTIFICATE (self), &category))
			return CKR_FUNCTION_FAILED;
		/* Unknown category, is CA by default in this slot */
		if (category == 0) 
			category = 2;
		return gck_attribute_set_ulong (attr, category);
	}
	
	return GCK_OBJECT_CLASS (gck_roots_certificate_parent_class)->get_attribute (base, session, attr);
}

static void
gck_roots_certificate_init (GckRootsCertificate *self)
{
	
}

static GObject* 
gck_roots_certificate_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckRootsCertificate *self = GCK_ROOTS_CERTIFICATE (G_OBJECT_CLASS (gck_roots_certificate_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	

	self->trust = gck_certificate_trust_new (gck_object_get_module (GCK_OBJECT (self)), 
	                                         GCK_CERTIFICATE (self));
	
	return G_OBJECT (self);
}

static void
gck_roots_certificate_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                    GParamSpec *pspec)
{
	GckRootsCertificate *self = GCK_ROOTS_CERTIFICATE (obj);
	
	switch (prop_id) {
	case PROP_PATH:
		g_return_if_fail (!self->path);
		self->path = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_roots_certificate_get_property (GObject *obj, guint prop_id, GValue *value, 
                                    GParamSpec *pspec)
{
	GckRootsCertificate *self = GCK_ROOTS_CERTIFICATE (obj);
	
	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, gck_roots_certificate_get_path (self));
		break;
	case PROP_NETSCAPE_TRUST:
		g_value_set_object (value, gck_roots_certificate_get_netscape_trust (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_roots_certificate_dispose (GObject *obj)
{
	GckRootsCertificate *self = GCK_ROOTS_CERTIFICATE (obj);
	
	if (self->trust)
		g_object_unref (self->trust);
	self->trust = NULL;

	G_OBJECT_CLASS (gck_roots_certificate_parent_class)->dispose (obj);
}

static void
gck_roots_certificate_finalize (GObject *obj)
{
	GckRootsCertificate *self = GCK_ROOTS_CERTIFICATE (obj);
	
	g_free (self->path);
	g_assert (!self->trust);

	G_OBJECT_CLASS (gck_roots_certificate_parent_class)->finalize (obj);
}

static void
gck_roots_certificate_class_init (GckRootsCertificateClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	
	gobject_class->constructor = gck_roots_certificate_constructor;
	gobject_class->dispose = gck_roots_certificate_dispose;
	gobject_class->finalize = gck_roots_certificate_finalize;
	gobject_class->set_property = gck_roots_certificate_set_property;
	gobject_class->get_property = gck_roots_certificate_get_property;

	gck_class->get_attribute = gck_roots_certificate_get_attribute;
	
	g_object_class_install_property (gobject_class, PROP_PATH,
	           g_param_spec_string ("path", "Path", "Certificate origin path", 
	                                "", G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property (gobject_class, PROP_NETSCAPE_TRUST,
	           g_param_spec_object ("netscape-trust", "Netscape Trust", "Netscape trust object", 
	                                GCK_TYPE_CERTIFICATE_TRUST, G_PARAM_READABLE));
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckRootsCertificate*
gck_roots_certificate_new (GckModule *module, const gchar *unique, const gchar *path)
{
	return g_object_new (GCK_TYPE_ROOTS_CERTIFICATE, "unique", unique, "path", path, 
	                     "module", module, NULL);
}

const gchar*
gck_roots_certificate_get_path (GckRootsCertificate *self)
{
	g_return_val_if_fail (GCK_IS_ROOTS_CERTIFICATE (self), "");
	return self->path;
}

GckCertificateTrust*
gck_roots_certificate_get_netscape_trust (GckRootsCertificate *self)
{
	g_return_val_if_fail (GCK_IS_ROOTS_CERTIFICATE (self), NULL);
	g_return_val_if_fail (GCK_IS_CERTIFICATE_TRUST (self->trust), NULL);
	return self->trust;
}
