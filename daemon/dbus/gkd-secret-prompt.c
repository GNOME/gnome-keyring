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

#include "gkd-dbus-util.h"
#include "gkd-secret-service.h"
#include "gkd-secret-prompt.h"
#include "gkd-secret-objects.h"
#include "gkd-secret-types.h"
#include "gkd-secret-util.h"

#include "prompt/gkd-prompt.h"

#include <string.h>

enum {
	PROP_0,
	PROP_CALLER,
	PROP_OBJECT_PATH,
	PROP_SERVICE
};

struct _GkdSecretPromptPrivate {
	GkdPrompt parent;
	gchar *object_path;
	GkdSecretService *service;
	gboolean prompted;
	gboolean completed;
	gchar *caller;
	gchar *window_id;
	GList *objects;
};

G_DEFINE_TYPE (GkdSecretPrompt, gkd_secret_prompt, GKD_TYPE_PROMPT);

static guint unique_prompt_number = 0;

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static GkdPrompt*
on_prompt_attention (gpointer user_data)
{
	GkdSecretPrompt *self = user_data;

	/* Check with the derived class */
	g_return_val_if_fail (GKD_SECRET_PROMPT_GET_CLASS (self)->prompt_ready, NULL);
	GKD_SECRET_PROMPT_GET_CLASS (self)->prompt_ready (self);

	if (self->pv->completed)
		return NULL;
	return g_object_ref (self);
}

static void
emit_completed (GkdSecretPrompt *self, gboolean dismissed)
{
	DBusMessage *signal;
	DBusMessageIter iter;
	dbus_bool_t bval;

	signal = dbus_message_new_signal (self->pv->object_path, SECRET_PROMPT_INTERFACE,
	                                  "Completed");
	dbus_message_set_destination (signal, self->pv->caller);
	dbus_message_iter_init_append (signal, &iter);

	g_return_if_fail (GKD_SECRET_PROMPT_GET_CLASS (self)->encode_result);
	GKD_SECRET_PROMPT_GET_CLASS (self)->encode_result (self, &iter);

	bval = dismissed;
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_BOOLEAN, &bval);

	gkd_secret_service_send (self->pv->service, signal);
	dbus_message_unref (signal);
}

/* -----------------------------------------------------------------------------
 * DBUS
 */

static DBusMessage*
prompt_method_prompt (GkdSecretPrompt *self, DBusMessage *message)
{
	DBusMessage *reply;
	const char *window_id;

	/* Act as if this object no longer exists */
	if (self->pv->completed)
		return NULL;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING,
	                            &window_id, DBUS_TYPE_INVALID))
		return NULL;

	/* Prompt can only be called once */
	if (self->pv->prompted)
		return dbus_message_new_error (message, SECRET_ERROR_ALREADY_EXISTS,
		                               "This prompt has already been shown.");

	gkd_prompt_set_window_id (GKD_PROMPT (self), window_id);
	gkd_prompt_request_attention_async (window_id, on_prompt_attention,
	                                    g_object_ref (self), g_object_unref);
	self->pv->prompted = TRUE;

	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_INVALID);
	return reply;
}

static DBusMessage*
prompt_method_dismiss (GkdSecretPrompt *self, DBusMessage *message)
{
	DBusMessage *reply;

	/* Act as if this object no longer exists */
	if (self->pv->completed)
		return NULL;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID))
		return NULL;

	gkd_secret_prompt_dismiss (self);

	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_INVALID);
	return reply;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static gboolean
gkd_secret_prompt_responded (GkdPrompt *base)
{
	GkdSecretPrompt *self = GKD_SECRET_PROMPT (base);
	gint res;

	res = gkd_prompt_get_response (GKD_PROMPT (self));
	if (res <= GKD_RESPONSE_NO) {
		gkd_secret_prompt_dismiss (self);
		return FALSE;
	}

	/* Check with the prompt ready guys */
	g_return_val_if_fail (GKD_SECRET_PROMPT_GET_CLASS (self)->prompt_ready, TRUE);
	GKD_SECRET_PROMPT_GET_CLASS (self)->prompt_ready (self);
	return !self->pv->completed;
}

static void
gkd_secret_prompt_ready (GkdSecretPrompt *self)
{
	/* Default implementation, unused */
	g_return_if_reached ();
}

static void
gkd_secret_prompt_encode_result (GkdSecretPrompt *self, DBusMessageIter *iter)
{
	/* Default implementation, unused */
	g_return_if_reached ();
}

static GObject*
gkd_secret_prompt_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkdSecretPrompt *self = GKD_SECRET_PROMPT (G_OBJECT_CLASS (gkd_secret_prompt_parent_class)->constructor(type, n_props, props));

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->pv->caller, NULL);
	g_return_val_if_fail (self->pv->service, NULL);

	/* Setup the path for the object */
	self->pv->object_path = g_strdup_printf (SECRET_PROMPT_PREFIX "/p%d", ++unique_prompt_number);

	return G_OBJECT (self);
}

static void
gkd_secret_prompt_init (GkdSecretPrompt *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GKD_SECRET_TYPE_PROMPT, GkdSecretPromptPrivate);
}

static void
gkd_secret_prompt_dispose (GObject *obj)
{
	GkdSecretPrompt *self = GKD_SECRET_PROMPT (obj);

	g_free (self->pv->object_path);
	self->pv->object_path = NULL;

	if (self->pv->service) {
		g_object_remove_weak_pointer (G_OBJECT (self->pv->service),
		                              (gpointer*)&(self->pv->service));
		self->pv->service = NULL;
	}

	G_OBJECT_CLASS (gkd_secret_prompt_parent_class)->dispose (obj);
}

static void
gkd_secret_prompt_finalize (GObject *obj)
{
	GkdSecretPrompt *self = GKD_SECRET_PROMPT (obj);

	g_assert (!self->pv->object_path);
	g_assert (!self->pv->service);

	g_free (self->pv->caller);
	self->pv->caller = NULL;

	G_OBJECT_CLASS (gkd_secret_prompt_parent_class)->finalize (obj);
}

static void
gkd_secret_prompt_set_property (GObject *obj, guint prop_id, const GValue *value,
                                GParamSpec *pspec)
{
	GkdSecretPrompt *self = GKD_SECRET_PROMPT (obj);

	switch (prop_id) {
	case PROP_CALLER:
		g_return_if_fail (!self->pv->caller);
		self->pv->caller = g_value_dup_string (value);
		break;
	case PROP_SERVICE:
		g_return_if_fail (!self->pv->service);
		self->pv->service = g_value_get_object (value);
		g_return_if_fail (self->pv->service);
		g_object_add_weak_pointer (G_OBJECT (self->pv->service),
		                           (gpointer*)&(self->pv->service));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_prompt_get_property (GObject *obj, guint prop_id, GValue *value,
                                GParamSpec *pspec)
{
	GkdSecretPrompt *self = GKD_SECRET_PROMPT (obj);

	switch (prop_id) {
	case PROP_CALLER:
		g_value_set_string (value, gkd_secret_prompt_get_caller (self));
		break;
	case PROP_OBJECT_PATH:
		g_value_set_boxed (value, gkd_secret_prompt_get_object_path (self));
		break;
	case PROP_SERVICE:
		g_value_set_object (value, self->pv->service);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_prompt_class_init (GkdSecretPromptClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkdPromptClass *prompt_class = GKD_PROMPT_CLASS (klass);

	gobject_class->constructor = gkd_secret_prompt_constructor;
	gobject_class->dispose = gkd_secret_prompt_dispose;
	gobject_class->finalize = gkd_secret_prompt_finalize;
	gobject_class->set_property = gkd_secret_prompt_set_property;
	gobject_class->get_property = gkd_secret_prompt_get_property;

	prompt_class->responded = gkd_secret_prompt_responded;

	klass->encode_result = gkd_secret_prompt_encode_result;
	klass->prompt_ready = gkd_secret_prompt_ready;

	g_type_class_add_private (klass, sizeof (GkdSecretPromptPrivate));

	g_object_class_install_property (gobject_class, PROP_CALLER,
		g_param_spec_string ("caller", "Caller", "DBus caller name",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY ));

	g_object_class_install_property (gobject_class, PROP_OBJECT_PATH,
	        g_param_spec_string ("object-path", "Object Path", "DBus Object Path",
		                     NULL, G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Service which owns this prompt",
		                     GKD_SECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

DBusMessage*
gkd_secret_prompt_dispatch (GkdSecretPrompt *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	const gchar *caller;

	g_return_val_if_fail (message, NULL);
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);

	/* This should already have been caught elsewhere */
	caller = dbus_message_get_sender (message);
	if (!caller || !g_str_equal (caller, self->pv->caller))
		g_return_val_if_reached (NULL);

	/* org.freedesktop.Secrets.Prompt.Prompt() */
	else if (dbus_message_is_method_call (message, SECRET_PROMPT_INTERFACE, "Prompt"))
		reply = prompt_method_prompt (self, message);

	/* org.freedesktop.Secrets.Prompt.Negotiate() */
	else if (dbus_message_is_method_call (message, SECRET_PROMPT_INTERFACE, "Dismiss"))
		reply = prompt_method_dismiss (self, message);

	else if (dbus_message_has_interface (message, DBUS_INTERFACE_INTROSPECTABLE))
		return gkd_dbus_introspect_handle (message, "prompt");

	return reply;
}

const gchar*
gkd_secret_prompt_get_caller (GkdSecretPrompt *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	return self->pv->caller;
}

const gchar*
gkd_secret_prompt_get_object_path (GkdSecretPrompt *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	return self->pv->object_path;
}

void
gkd_secret_prompt_complete (GkdSecretPrompt *self)
{
	g_return_if_fail (GKD_SECRET_IS_PROMPT (self));
	g_return_if_fail (!self->pv->completed);
	self->pv->completed = TRUE;
	emit_completed (self, FALSE);
}

void
gkd_secret_prompt_dismiss (GkdSecretPrompt *self)
{
	g_return_if_fail (GKD_SECRET_IS_PROMPT (self));
	g_return_if_fail (!self->pv->completed);
	self->pv->completed = TRUE;
	emit_completed (self, TRUE);
}

GP11Object*
gkd_secret_prompt_lookup_collection (GkdSecretPrompt *self, const gchar *path)
{
	GP11Session *session;

	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	g_return_val_if_fail (self->pv->service, NULL);
	g_return_val_if_fail (path, NULL);

	session = gkd_secret_service_get_pkcs11_session (self->pv->service, self->pv->caller);
	g_return_val_if_fail (session, NULL);

	return gkd_secret_util_path_to_collection (session, path);
}
