/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
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

#include "gck-secret-object.h"

#include "gck/gck-attributes.h"
#include "gck/gck-session.h"
#include "gck/gck-transaction.h"

#include "pkcs11/pkcs11i.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_LABEL,
	PROP_IDENTIFIER,
	PROP_CREATED,
	PROP_MODIFIED
};

struct _GckSecretObjectPrivate {
	gchar *identifier;
	gchar *label;
	glong created;
	glong modified;
};

G_DEFINE_TYPE (GckSecretObject, gck_secret_object, GCK_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static gboolean
complete_set_label (GckTransaction *transaction, GObject *obj, gpointer user_data)
{
	GckSecretObject *self = GCK_SECRET_OBJECT (obj);
	gchar *old_label = user_data;
	
	if (gck_transaction_get_failed (transaction)) {
		g_free (self->pv->label);
		self->pv->label = old_label;
	} else {
		gck_object_notify_attribute (GCK_OBJECT (obj), CKA_LABEL);
		g_object_notify (G_OBJECT (obj), "label");
		gck_secret_object_was_modified (self);
		g_free (old_label);
	}
	
	return TRUE;
}

static void
begin_set_label (GckSecretObject *self, GckTransaction *transaction, gchar *label)
{
	g_assert (GCK_IS_SECRET_OBJECT (self));
	g_assert (!gck_transaction_get_failed (transaction));
	
	gck_transaction_add (transaction, self, complete_set_label, self->pv->label);
	self->pv->label = label;
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV
gck_secret_object_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	GckSecretObject *self = GCK_SECRET_OBJECT (base);
	
	switch (attr->type) {
	case CKA_MODIFIABLE:
		return gck_attribute_set_bool (attr, TRUE);

	case CKA_ID:
		return gck_attribute_set_string (attr, gck_secret_object_get_identifier (self));
		
	case CKA_LABEL:
		return gck_attribute_set_string (attr, gck_secret_object_get_label (self));
		
	case CKA_G_LOCKED:
		return gck_attribute_set_bool (attr, gck_secret_object_is_locked (self, session));
		
	case CKA_G_CREATED:
		return gck_attribute_set_time (attr, gck_secret_object_get_created (self));
		
	case CKA_G_MODIFIED:
		return gck_attribute_set_time (attr, gck_secret_object_get_modified (self));
	}
	
	return GCK_OBJECT_CLASS (gck_secret_object_parent_class)->get_attribute (base, session, attr);
}

static void
gck_secret_object_set_attribute (GckObject *base, GckSession *session, 
                                 GckTransaction *transaction, CK_ATTRIBUTE_PTR attr)
{
	GckSecretObject *self = GCK_SECRET_OBJECT (base);
	gchar *label;
	CK_RV rv;

	switch (attr->type) {
	
	case CKA_LABEL:
		/* Check that the object is not locked */
		if (gck_secret_object_is_locked (self, session))
			rv = CKR_USER_NOT_LOGGED_IN;
		else
			rv = gck_attribute_get_string (attr, &label);
		if (rv != CKR_OK)
			gck_transaction_fail (transaction, rv);
		else
			begin_set_label (self, transaction, label);
		return;
	}
	
	GCK_OBJECT_CLASS (gck_secret_object_parent_class)->set_attribute (base, session, transaction, attr);
}

static gboolean
gck_secret_object_real_is_locked (GckSecretObject *self, GckSession *session)
{
	/* Derived classes override us */
	return FALSE;
}

static void
gck_secret_object_init (GckSecretObject *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_SECRET_OBJECT, GckSecretObjectPrivate);
}

static GObject* 
gck_secret_object_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckSecretObject *self = GCK_SECRET_OBJECT (G_OBJECT_CLASS (gck_secret_object_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);

	/* Must be created with an identifier */
	g_return_val_if_fail (self->pv->identifier, NULL);

	return G_OBJECT (self);
}

static void
gck_secret_object_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                GParamSpec *pspec)
{
	GckSecretObject *self = GCK_SECRET_OBJECT (obj);
	
	switch (prop_id) {
	case PROP_LABEL:
		gck_secret_object_set_label (self, g_value_get_string (value));
		break;
	case PROP_IDENTIFIER:
		g_return_if_fail (!self->pv->identifier);
		self->pv->identifier = g_value_dup_string (value);
		g_return_if_fail (self->pv->identifier);
		break;
	case PROP_CREATED:
		gck_secret_object_set_created (self, g_value_get_long (value));
		break;
	case PROP_MODIFIED:
		gck_secret_object_set_modified (self, g_value_get_long (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_object_get_property (GObject *obj, guint prop_id, GValue *value, 
                                    GParamSpec *pspec)
{
	GckSecretObject *self = GCK_SECRET_OBJECT (obj);
	
	switch (prop_id) {
	case PROP_LABEL:
		g_value_set_string (value, gck_secret_object_get_label (self));
		break;
	case PROP_IDENTIFIER:
		g_value_set_string (value, gck_secret_object_get_identifier (self));
		break;
	case PROP_CREATED:
		g_value_set_long (value, gck_secret_object_get_created (self));
		break;
	case PROP_MODIFIED:
		g_value_set_long (value, gck_secret_object_get_modified (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_object_dispose (GObject *obj)
{
	/* GckSecretObject *self = GCK_SECRET_OBJECT (obj); */
	G_OBJECT_CLASS (gck_secret_object_parent_class)->dispose (obj);
}

static void
gck_secret_object_finalize (GObject *obj)
{
	GckSecretObject *self = GCK_SECRET_OBJECT (obj);

	g_free (self->pv->identifier);
	self->pv->identifier = NULL;
	
	g_free (self->pv->label);
	self->pv->label = NULL;
	
	self->pv->created = 0;
	self->pv->modified = 0;

	G_OBJECT_CLASS (gck_secret_object_parent_class)->finalize (obj);
}

static void
gck_secret_object_class_init (GckSecretObjectClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);

	gck_secret_object_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GckSecretObjectPrivate));

	gobject_class->constructor = gck_secret_object_constructor;
	gobject_class->dispose = gck_secret_object_dispose;
	gobject_class->finalize = gck_secret_object_finalize;
	gobject_class->set_property = gck_secret_object_set_property;
	gobject_class->get_property = gck_secret_object_get_property;

	gck_class->get_attribute = gck_secret_object_get_attribute;
	gck_class->set_attribute = gck_secret_object_set_attribute;

	klass->is_locked = gck_secret_object_real_is_locked;

	g_object_class_install_property (gobject_class, PROP_IDENTIFIER,
	           g_param_spec_string ("identifier", "Identifier", "Object Identifier", 
	                                NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property (gobject_class, PROP_LABEL,
	           g_param_spec_string ("label", "Label", "Object Label", 
	                                "", G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	
	g_object_class_install_property (gobject_class, PROP_CREATED,
	           g_param_spec_long ("created", "Created", "Object Create Time",
	                              0, G_MAXLONG, 0, G_PARAM_READABLE));
	
	g_object_class_install_property (gobject_class, PROP_MODIFIED,
	           g_param_spec_long ("modified", "Modified", "Object Modify Time",
	                              0, G_MAXLONG, 0, G_PARAM_READABLE));
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

const gchar*
gck_secret_object_get_identifier (GckSecretObject *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_OBJECT (self), NULL);
	return self->pv->identifier;
}

const gchar*
gck_secret_object_get_label (GckSecretObject *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_OBJECT (self), NULL);
	return self->pv->label;	
}

void
gck_secret_object_set_label (GckSecretObject *self, const gchar *label)
{
	g_return_if_fail (GCK_IS_SECRET_OBJECT (self));

	if (self->pv->label == label)
		return;

	g_free (self->pv->label);
	self->pv->label = g_strdup (label);
	g_object_notify (G_OBJECT (self), "label");
}

glong
gck_secret_object_get_created (GckSecretObject *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_OBJECT (self), 0);
	return self->pv->created;
}

void
gck_secret_object_set_created (GckSecretObject *self, glong when)
{
	g_return_if_fail (GCK_IS_SECRET_OBJECT (self));
	self->pv->created = when;
	g_object_notify (G_OBJECT (self), "created");
}

glong
gck_secret_object_get_modified (GckSecretObject *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_OBJECT (self), 0);
	return self->pv->modified;
}

void
gck_secret_object_set_modified (GckSecretObject *self, glong when)
{
	g_return_if_fail (GCK_IS_SECRET_OBJECT (self));
	self->pv->modified = when;
	g_object_notify (G_OBJECT (self), "modified");
}

void
gck_secret_object_was_modified (GckSecretObject *self)
{
	GTimeVal tv;
	g_return_if_fail (GCK_IS_SECRET_OBJECT (self));
	g_get_current_time (&tv);
	gck_secret_object_set_modified (self, tv.tv_sec);
}

gboolean
gck_secret_object_is_locked (GckSecretObject *self, GckSession *session)
{
	g_return_val_if_fail (GCK_IS_SECRET_OBJECT (self), TRUE);
	g_return_val_if_fail (GCK_SECRET_OBJECT_GET_CLASS (self)->is_locked, TRUE);
	return GCK_SECRET_OBJECT_GET_CLASS (self)->is_locked (self, session);
}
