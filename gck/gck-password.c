/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-password.c - the GObject PKCS#11 wrapper library

   Copyright (C) 2011 Collabora Ltd.

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#include "config.h"

#include "gck.h"
#include "gck-private.h"

#include "egg/egg-timegm.h"

#include <string.h>

/**
 * SECTION:gck-password
 * @title: GckPassword
 * @short_description: Represents a password hich is requested of the user
 *
 * This is used in conjuction with GTlsInteraction. #GckPassword is a
 * GTlsPassword which contains additional information about which PKCS\#11
 * token or key the password is being requested for.
 */

/**
 * GckPassword:
 * @parent: parent object
 *
 * A #GTlsPasswordClass that contains information about the PKCS\#11 token
 * or key the password is being requested for.
 */

/**
 * GckPasswordClass:
 * @parent: parent class
 *
 * The class for #GTlsPassword.
 */
enum {
	PROP_0,
	PROP_MODULE,
	PROP_TOKEN,
	PROP_KEY
};

struct _GckPasswordPrivate {
	gboolean for_token;
	gpointer token_or_key;
};

G_DEFINE_TYPE (GckPassword, gck_password, G_TYPE_TLS_PASSWORD);

static void
gck_password_init (GckPassword *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_PASSWORD, GckPasswordPrivate);
}

static void
gck_password_constructed (GObject *obj)
{
	GckPassword *self = GCK_PASSWORD (obj);

	G_OBJECT_CLASS (gck_password_parent_class)->constructed (obj);

	g_return_if_fail (GCK_IS_SLOT (self->pv->token_or_key) ||
	                  GCK_IS_OBJECT (self->pv->token_or_key));
}

static void
gck_password_get_property (GObject *obj,
                           guint prop_id,
                           GValue *value,
                           GParamSpec *pspec)
{
	GckPassword *self = GCK_PASSWORD (obj);

	switch (prop_id) {
	case PROP_MODULE:
		g_value_take_object (value, gck_password_get_module (self));
		break;
	case PROP_TOKEN:
		g_value_take_object (value, gck_password_get_token (self));
		break;
	case PROP_KEY:
		g_value_take_object (value, gck_password_get_key (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_password_set_property (GObject *obj,
                           guint prop_id,
                           const GValue *value,
                           GParamSpec *pspec)
{
	GckPassword *self = GCK_PASSWORD (obj);
	gpointer object;

	/* All writes to data members below, happen only during construct phase */

	switch (prop_id) {
	case PROP_TOKEN:
		object = g_value_dup_object (value);
		if (object != NULL) {
			g_assert (self->pv->token_or_key == NULL);
			self->pv->token_or_key = object;
			self->pv->for_token = TRUE;
		}
		break;
	case PROP_KEY:
		object = g_value_dup_object (value);
		if (object != NULL) {
			g_assert (self->pv->token_or_key == NULL);
			self->pv->token_or_key = object;
			self->pv->for_token = FALSE;
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_password_finalize (GObject *obj)
{
	GckPassword *self = GCK_PASSWORD (obj);

	g_clear_object (&self->pv->token_or_key);

	G_OBJECT_CLASS (gck_password_parent_class)->finalize (obj);
}

static void
gck_password_class_init (GckPasswordClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gobject_class->constructed = gck_password_constructed;
	gobject_class->get_property = gck_password_get_property;
	gobject_class->set_property = gck_password_set_property;
	gobject_class->finalize = gck_password_finalize;

	/**
	 * GckPassword:module:
	 *
	 * The PKCS\#11 module that is requesting the password
	 */
	g_object_class_install_property (gobject_class, PROP_MODULE,
		g_param_spec_object ("module", "Module", "PKCS11 Module",
		                     GCK_TYPE_MODULE, G_PARAM_READABLE));

	/**
	 * GckPassword:token:
	 *
	 * The PKCS\#11 token the password is for, if this is set then
	 * the GckPassword:object property will be %NULL
	 */
	g_object_class_install_property (gobject_class, PROP_TOKEN,
		g_param_spec_object ("token", "Token", "PKCS11 Token",
		                     GCK_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/**
	 * GckPassword:key:
	 *
	 * The PKCS\#11 key that the password is being requested for. If this
	 * is set then the GckPassword:token property will be %NULL
	 */
	g_object_class_install_property (gobject_class, PROP_KEY,
		g_param_spec_object ("key", "Object", "PKCS11 Key Object",
		                     GCK_TYPE_OBJECT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_type_class_add_private (gobject_class, sizeof (GckPasswordPrivate));
}

/**
 * gck_password_get_module:
 * @self: the password object
 *
 * Get the PKCS\#11 module that is requesting the password.
 *
 * Returns: (transfer full): the module that is requesting the password, which
 *          must be unreferenced after use
 */
GckModule *
gck_password_get_module (GckPassword *self)
{
	g_return_val_if_fail (GCK_IS_PASSWORD (self), NULL);
	if (self->pv->for_token)
		return gck_slot_get_module (self->pv->token_or_key);
	else
		return gck_object_get_module (self->pv->token_or_key);
}

/**
 * gck_password_get_token:
 * @self: the password object
 *
 * If the password request is to unlock a PKCS\#11 token, then this is the
 * slot containing that token.
 *
 * Returns: (transfer full): the slot that contains the token, or %NULL if not
 *          being requested for a token; must be unreferenced after use
 */
GckSlot *
gck_password_get_token (GckPassword *self)
{
	g_return_val_if_fail (GCK_IS_PASSWORD (self), NULL);
	if (!self->pv->for_token)
		return NULL;
	g_return_val_if_fail (GCK_IS_SLOT (self->pv->token_or_key), NULL);
	return g_object_ref (self->pv->token_or_key);
}

/**
 * gck_password_get_key:
 * @self: the password object
 *
 * If the password request is to unlock a PKCS\#11 key, then this is the
 * the object representing that key.
 *
 * Returns: (transfer full): the password is for this key, or %NULL if not
 *          being requested for a key; must be unreferenced after use
 */
GckObject *
gck_password_get_key (GckPassword *self)
{
	g_return_val_if_fail (GCK_IS_PASSWORD (self), NULL);
	if (self->pv->for_token)
		return NULL;
	g_return_val_if_fail (GCK_IS_OBJECT (self->pv->token_or_key), NULL);
	return g_object_ref (self->pv->token_or_key);
}
