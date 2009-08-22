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

#include "gkd-secrets-service.h"
#include "gkd-secrets-objects.h"
#include "gkd-secrets-types.h"

#include <string.h>

enum {
	PROP_0,
	PROP_PKCS11_SLOT,
	PROP_SERVICE
};

struct _GkdSecretsObjects {
	GObject parent;
	GkdSecretsService *service;
	GP11Slot *pkcs11_slot;
};

G_DEFINE_TYPE (GkdSecretsObjects, gkd_secrets_objects, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

/* -----------------------------------------------------------------------------
 * DBUS
 */

#if 0
static DBusHandlerResult
gkd_secrets_objects_close (GkdSecretsObjects *self, DBusConnection *conn, DBusMessage *message)
{
	DBusMessage *reply;

	g_return_val_if_fail (self->service, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	gkd_secrets_service_close_objects (self->service, self);

	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_INVALID);
	dbus_connection_send (conn, reply, NULL);
	dbus_message_unref (reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
gkd_sercets_objects_property_handler (DBusConnection *conn, DBusMessage *message, gpointer user_data)
{
	g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */

	/* org.freedesktop.DBus.Properties.Get */
	if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Get") &&
	    dbus_message_has_signature (message, "ss")) {
		xxx;

	/* org.freedesktop.DBus.Properties.Set */
	} else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Set") &&
	           dbus_message_has_signature (message, "ssv")) {
		xxx;

	/* org.freedesktop.DBus.Properties.GetAll */
	} else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "GetAll") &&
	           dbus_message_has_signature (message, "s")) {
		xxx;
	}
}
#endif

static DBusHandlerResult
gkd_secrets_objects_message_handler (DBusConnection *conn, DBusMessage *message, gpointer user_data)
{
	GkdSecretsObjects *self = user_data;
	DBusMessage *reply = NULL;

	g_return_val_if_fail (conn && message, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (GKD_SECRETS_IS_OBJECTS (self), DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

#if 0
	/* Check if it's properties, and hand off to property handler. */
	if (dbus_message_has_interface (message, PROPERTIES_INTERFACE))
		return gkd_sercets_objects_property_handler (conn, message, self);

	/* org.freedesktop.Secrets.Objects.Close() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "Close"))
		return gkd_secrets_objects_close (self, conn, message);

	/* org.freedesktop.Secrets.Objects.Negotiate() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "Negotiate"))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Objects.GetSecret() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "GetSecret"))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Objects.SetSecret() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "SetSecret"))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Objects.GetSecrets() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "GetSecrets"))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Objects.GetSecret() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "GetSecret"))
		g_return_val_if_reached (DBUS_HANDLER_RESULT_NOT_YET_HANDLED); /* TODO: Need to implement */
#endif

	if (reply == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_connection_send (conn, reply, NULL);
	dbus_message_unref (reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gkd_secrets_objects_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (G_OBJECT_CLASS (gkd_secrets_objects_parent_class)->constructor(type, n_props, props));

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->pkcs11_slot, NULL);
	g_return_val_if_fail (self->service, NULL);

	/* Register all the collections, and items paths */
	if (!dbus_connection_register_fallback (gkd_secrets_service_get_connection (self->service), SECRETS_COLLECTION_PREFIX,
	                                        &GKD_SECRETS_OBJECTS_GET_CLASS (self)->dbus_vtable, self))
		g_return_val_if_reached (NULL);

	return G_OBJECT (self);
}

static void
gkd_secrets_objects_init (GkdSecretsObjects *self)
{

}

static void
gkd_secrets_objects_dispose (GObject *obj)
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (obj);

	if (self->pkcs11_slot) {
		g_object_unref (self->pkcs11_slot);
		self->pkcs11_slot = NULL;
	}

	if (self->service) {
		if (!dbus_connection_unregister_object_path (gkd_secrets_service_get_connection (self->service), 
		                                             SECRETS_COLLECTION_PREFIX))
			g_return_if_reached ();
		g_object_remove_weak_pointer (G_OBJECT (self->service),
		                              (gpointer*)&(self->service));
		self->service = NULL;
	}

	G_OBJECT_CLASS (gkd_secrets_objects_parent_class)->dispose (obj);
}

static void
gkd_secrets_objects_finalize (GObject *obj)
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (obj);

	g_assert (!self->pkcs11_slot);
	g_assert (!self->service);

	G_OBJECT_CLASS (gkd_secrets_objects_parent_class)->finalize (obj);
}

static void
gkd_secrets_objects_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                  GParamSpec *pspec)
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (obj);

	switch (prop_id) {
	case PROP_PKCS11_SLOT:
		g_return_if_fail (!self->pkcs11_slot);
		self->pkcs11_slot = g_value_dup_object (value);
		g_return_if_fail (self->pkcs11_slot);
		break;
	case PROP_SERVICE:
		g_return_if_fail (!self->service);
		self->service = g_value_get_object (value);
		g_return_if_fail (self->service);
		g_object_add_weak_pointer (G_OBJECT (self->service),
		                           (gpointer*)&(self->service));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secrets_objects_get_property (GObject *obj, guint prop_id, GValue *value,
                                     GParamSpec *pspec)
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (obj);

	switch (prop_id) {
	case PROP_PKCS11_SLOT:
		g_value_set_object (value, gkd_secrets_objects_get_pkcs11_slot (self));
		break;
	case PROP_SERVICE:
		g_value_set_object (value, self->service);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secrets_objects_class_init (GkdSecretsObjectsClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkd_secrets_objects_constructor;
	gobject_class->dispose = gkd_secrets_objects_dispose;
	gobject_class->finalize = gkd_secrets_objects_finalize;
	gobject_class->set_property = gkd_secrets_objects_set_property;
	gobject_class->get_property = gkd_secrets_objects_get_property;

	klass->dbus_vtable.message_function = gkd_secrets_objects_message_handler;

	g_object_class_install_property (gobject_class, PROP_PKCS11_SLOT,
	        g_param_spec_object ("pkcs11-slot", "Pkcs11 Slot", "PKCS#11 slot that we use for secrets",
	                             GP11_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Service which owns this objects",
		                     GKD_SECRETS_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GP11Slot*
gkd_secrets_objects_get_pkcs11_slot (GkdSecretsObjects *self)
{
	g_return_val_if_fail (GKD_SECRETS_IS_OBJECTS (self), NULL);
	return self->pkcs11_slot;
}
