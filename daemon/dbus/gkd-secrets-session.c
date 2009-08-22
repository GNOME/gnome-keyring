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
#include "gkd-secrets-session.h"
#include "gkd-secrets-types.h"

#include <string.h>

enum {
	PROP_0,
	PROP_CALLER,
	PROP_CALLER_EXECUTABLE,
	PROP_OBJECT_PATH,
	PROP_SERVICE
};

struct _GkdSecretsSession {
	GObject parent;
	gchar *object_path;
	GkdSecretsService *service;
	gchar *caller_exec;
	gchar *caller;
};

G_DEFINE_TYPE (GkdSecretsSession, gkd_secrets_session, G_TYPE_OBJECT);

static guint unique_session_number = 0;

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

/* -----------------------------------------------------------------------------
 * DBUS
 */

static DBusMessage*
session_method_close (GkdSecretsSession *self, DBusMessage *message)
{
	DBusMessage *reply;

	g_return_val_if_fail (self->service, NULL);

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID))
		return NULL;

	gkd_secrets_service_close_session (self->service, self);

	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_INVALID);
	return reply;
}

static DBusMessage*
session_property_handler (GkdSecretsSession *self, DBusMessage *message)
{
	g_return_val_if_reached (NULL); /* TODO: Need to implement */
#if 0
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
#endif
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gkd_secrets_session_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GkdSecretsSession *self = GKD_SECRETS_SESSION (G_OBJECT_CLASS (gkd_secrets_session_parent_class)->constructor(type, n_props, props));

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->caller, NULL);
	g_return_val_if_fail (self->service, NULL);

	/* Setup the path for the object */
	self->object_path = g_strdup_printf (SECRETS_SESSION_PREFIX "/s%d", ++unique_session_number);

	return G_OBJECT (self);
}

static void
gkd_secrets_session_init (GkdSecretsSession *self)
{

}

static void
gkd_secrets_session_dispose (GObject *obj)
{
	GkdSecretsSession *self = GKD_SECRETS_SESSION (obj);

	g_free (self->object_path);
	self->object_path = NULL;

	if (self->service) {
		g_object_remove_weak_pointer (G_OBJECT (self->service),
		                              (gpointer*)&(self->service));
		self->service = NULL;
	}

	G_OBJECT_CLASS (gkd_secrets_session_parent_class)->dispose (obj);
}

static void
gkd_secrets_session_finalize (GObject *obj)
{
	GkdSecretsSession *self = GKD_SECRETS_SESSION (obj);

	g_assert (!self->object_path);
	g_assert (!self->service);

	g_free (self->caller_exec);
	self->caller_exec = NULL;

	g_free (self->caller);
	self->caller = NULL;

	G_OBJECT_CLASS (gkd_secrets_session_parent_class)->finalize (obj);
}

static void
gkd_secrets_session_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                  GParamSpec *pspec)
{
	GkdSecretsSession *self = GKD_SECRETS_SESSION (obj);

	switch (prop_id) {
	case PROP_CALLER:
		g_return_if_fail (!self->caller);
		self->caller = g_value_dup_string (value);
		break;
	case PROP_CALLER_EXECUTABLE:
		g_return_if_fail (!self->caller_exec);
		self->caller_exec = g_value_dup_string (value);
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
gkd_secrets_session_get_property (GObject *obj, guint prop_id, GValue *value,
                                     GParamSpec *pspec)
{
	GkdSecretsSession *self = GKD_SECRETS_SESSION (obj);

	switch (prop_id) {
	case PROP_CALLER:
		g_value_set_string (value, gkd_secrets_session_get_caller (self));
		break;
	case PROP_CALLER_EXECUTABLE:
		g_value_set_string (value, gkd_secrets_session_get_caller_executable (self));
		break;
	case PROP_OBJECT_PATH:
		g_value_set_boxed (value, gkd_secrets_session_get_object_path (self));
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
gkd_secrets_session_class_init (GkdSecretsSessionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkd_secrets_session_constructor;
	gobject_class->dispose = gkd_secrets_session_dispose;
	gobject_class->finalize = gkd_secrets_session_finalize;
	gobject_class->set_property = gkd_secrets_session_set_property;
	gobject_class->get_property = gkd_secrets_session_get_property;

	g_object_class_install_property (gobject_class, PROP_CALLER,
		g_param_spec_string ("caller", "Caller", "DBus caller name",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY ));

	g_object_class_install_property (gobject_class, PROP_CALLER_EXECUTABLE,
		g_param_spec_string ("caller-executable", "Caller Executable", "Executable of caller",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY ));

	g_object_class_install_property (gobject_class, PROP_OBJECT_PATH,
	        g_param_spec_string ("object-path", "Object Path", "DBus Object Path",
		                     NULL, G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Service which owns this session",
		                     GKD_SECRETS_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

DBusMessage*
gkd_secrets_session_dispatch (GkdSecretsSession *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	const gchar *caller;

	g_return_val_if_fail (message, NULL);
	g_return_val_if_fail (GKD_SECRETS_IS_SESSION (self), NULL);

	/* This should already have been caught elsewhere */
	caller = dbus_message_get_sender (message);
	if (!caller || !g_str_equal (caller, self->caller))
		g_return_val_if_reached (NULL);

	/* Check if it's properties, and hand off to property handler. */
	if (dbus_message_has_interface (message, PROPERTIES_INTERFACE))
		reply = session_property_handler (self, message);

	/* org.freedesktop.Secrets.Session.Close() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "Close"))
		reply = session_method_close (self, message);

	/* org.freedesktop.Secrets.Session.Negotiate() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "Negotiate"))
		g_return_val_if_reached (NULL); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Session.GetSecret() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "GetSecret"))
		g_return_val_if_reached (NULL); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Session.SetSecret() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "SetSecret"))
		g_return_val_if_reached (NULL); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Session.GetSecrets() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "GetSecrets"))
		g_return_val_if_reached (NULL); /* TODO: Need to implement */

	/* org.freedesktop.Secrets.Session.GetSecret() */
	else if (dbus_message_is_method_call (message, SECRETS_SERVICE_INTERFACE, "GetSecret"))
		g_return_val_if_reached (NULL); /* TODO: Need to implement */

	return reply;
}

const gchar*
gkd_secrets_session_get_caller (GkdSecretsSession *self)
{
	g_return_val_if_fail (GKD_SECRETS_IS_SESSION (self), NULL);
	return self->caller;
}

const gchar*
gkd_secrets_session_get_caller_executable (GkdSecretsSession *self)
{
	g_return_val_if_fail (GKD_SECRETS_IS_SESSION (self), NULL);
	return self->caller_exec;
}

const gchar*
gkd_secrets_session_get_object_path (GkdSecretsSession *self)
{
	g_return_val_if_fail (GKD_SECRETS_IS_SESSION (self), NULL);
	return self->object_path;
}
