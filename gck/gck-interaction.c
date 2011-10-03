/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-interaction.c - the GObject PKCS#11 wrapper library

   Copyright (C) 2011 Collabora Ltd

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

#include "gck-private.h"

#include <string.h>

#define GCK_INTERACTION_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_INTERACTION, GckInteraction))
#define GCK_IS_INTERACTION_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_INTERACTION))
#define GCK_INTERACTION_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_INTERACTION, GckInteractionClass))

typedef struct _GckInteractionClass GckInteractionClass;

struct _GckInteraction {
	GTlsInteraction interaction;
	GckModule *module;
};

struct _GckInteractionClass {
	GTlsInteractionClass parent;
};

enum {
	PROP_0,
	PROP_MODULE
};

G_DEFINE_TYPE (GckInteraction, _gck_interaction, G_TYPE_TLS_INTERACTION);

static void
_gck_interaction_init (GckInteraction *self)
{

}

static void
_gck_interaction_get_property (GObject *obj,
                               guint prop_id,
                               GValue *value,
                               GParamSpec *pspec)
{
	GckInteraction *self = GCK_INTERACTION (obj);

	switch (prop_id) {
	case PROP_MODULE:
		g_value_set_object (value, self->module);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gck_interaction_set_property (GObject *obj,
                             guint prop_id,
                             const GValue *value,
                             GParamSpec *pspec)
{
	GckInteraction *self = GCK_INTERACTION (obj);

	switch (prop_id) {
	case PROP_MODULE:
		g_return_if_fail (self->module == NULL);
		self->module = g_value_dup_object (value);
		g_return_if_fail (self->module != NULL);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gck_interaction_dispose (GObject *obj)
{
	GckInteraction *self = GCK_INTERACTION (obj);

	g_clear_object (&self->module);

	G_OBJECT_CLASS (_gck_interaction_parent_class)->dispose (obj);
}

static GTlsInteractionResult
_gck_interaction_ask_password (GTlsInteraction *interaction,
                               GTlsPassword *password,
                               GCancellable *cancellable,
                               GError **error)
{
	GckInteraction *self = GCK_INTERACTION (interaction);
	gchar *value = NULL;
	gboolean ret = FALSE;
	GckSlot *token;
	GckObject *key;

	if (!self->module)
		return G_TLS_INTERACTION_UNHANDLED;

	token = gck_password_get_token (GCK_PASSWORD (password));
	if (token != NULL) {
		g_signal_emit_by_name (self->module, "authenticate-slot", token,
		                       g_tls_password_get_description (password),
		                       &value, &ret);
		g_object_unref (token);

	} else {
		key = gck_password_get_key (GCK_PASSWORD (password));
		g_return_val_if_fail (GCK_IS_OBJECT (key), G_TLS_INTERACTION_UNHANDLED);

		g_signal_emit_by_name (self->module, "authenticate-object", key,
		                       g_tls_password_get_description (password),
		                       &value, &ret);
	}

	if (ret) {
		g_tls_password_set_value_full (password, (guchar *)value, -1, g_free);
		return G_TLS_INTERACTION_HANDLED;
	} else {
		return G_TLS_INTERACTION_UNHANDLED;
	}
}

static void
_gck_interaction_class_init (GckInteractionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);

	object_class->get_property = _gck_interaction_get_property;
	object_class->set_property = _gck_interaction_set_property;
	object_class->dispose = _gck_interaction_dispose;

	interaction_class->ask_password = _gck_interaction_ask_password;

	g_object_class_install_property (object_class, PROP_MODULE,
		g_param_spec_object ("module", "Module", "PKCS11 Module",
		                     GCK_TYPE_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

GTlsInteraction *
_gck_interaction_new (gpointer token_or_key)
{
	GTlsInteraction *result;
	GModule *module = NULL;

	g_return_val_if_fail (GCK_IS_SLOT (token_or_key) ||
	                      GCK_IS_OBJECT (token_or_key), NULL);

	g_object_get (token_or_key, "module", &module, NULL);
	result = g_object_new (GCK_TYPE_INTERACTION, "module", module, NULL);
	g_object_unref (module);

	return result;
}
