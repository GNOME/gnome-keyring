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

#include "gck-ssh-public-key.h"

#include "gck/gck-attributes.h"
#include "gck/gck-object.h"
#include "gck/gck-util.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_LABEL
};

struct _GckSshPublicKey {
	GckPublicKey parent;
	gchar *label;
};

G_DEFINE_TYPE (GckSshPublicKey, gck_ssh_public_key, GCK_TYPE_PUBLIC_KEY);

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV
gck_ssh_public_key_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	GckSshPublicKey *self = GCK_SSH_PUBLIC_KEY (base);
	
	switch (attr->type) {
	case CKA_LABEL:
		return gck_attribute_set_string (attr, self->label ? self->label : "");
	}
	
	return GCK_OBJECT_CLASS (gck_ssh_public_key_parent_class)->get_attribute (base, session, attr);
}

static void
gck_ssh_public_key_init (GckSshPublicKey *self)
{
	
}

static void
gck_ssh_public_key_finalize (GObject *obj)
{
	GckSshPublicKey *self = GCK_SSH_PUBLIC_KEY (obj);
	
	g_free (self->label);
	self->label = NULL;

	G_OBJECT_CLASS (gck_ssh_public_key_parent_class)->finalize (obj);
}

static void
gck_ssh_public_key_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	GckSshPublicKey *self = GCK_SSH_PUBLIC_KEY (obj);

	switch (prop_id) {
	case PROP_LABEL:
		gck_ssh_public_key_set_label (self, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_ssh_public_key_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
	GckSshPublicKey *self = GCK_SSH_PUBLIC_KEY (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_set_string (value, gck_ssh_public_key_get_label (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_ssh_public_key_class_init (GckSshPublicKeyClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
    
	gobject_class->finalize = gck_ssh_public_key_finalize;
	gobject_class->set_property = gck_ssh_public_key_set_property;
	gobject_class->get_property = gck_ssh_public_key_get_property;
	
	gck_class->get_attribute = gck_ssh_public_key_get_attribute;
	
	g_object_class_install_property (gobject_class, PROP_LABEL,
	           g_param_spec_string ("label", "Label", "Object Label", 
	                                "", G_PARAM_READWRITE));	
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckSshPublicKey*
gck_ssh_public_key_new (GckModule *module, const gchar *unique)
{
	return g_object_new (GCK_TYPE_SSH_PUBLIC_KEY, "unique", unique, 
	                     "module", module, NULL);
}

const gchar*
gck_ssh_public_key_get_label (GckSshPublicKey *self)
{
	g_return_val_if_fail (GCK_IS_SSH_PUBLIC_KEY (self), NULL);
	return self->label;
}

void
gck_ssh_public_key_set_label (GckSshPublicKey *self, const gchar *label)
{
	g_return_if_fail (GCK_IS_SSH_PUBLIC_KEY (self));
	g_free (self->label);
	self->label = g_strdup (label);
	g_object_notify (G_OBJECT (self), "label");
}
