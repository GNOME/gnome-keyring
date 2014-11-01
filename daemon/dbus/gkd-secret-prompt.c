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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkd-secret-dispatch.h"
#include "gkd-secret-error.h"
#include "gkd-secret-exchange.h"
#include "gkd-secret-service.h"
#include "gkd-secret-prompt.h"
#include "gkd-secret-objects.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"
#include "gkd-secret-util.h"
#include "gkd-secrets-generated.h"

#include "egg/egg-dh.h"
#include "egg/egg-error.h"

#include <string.h>

enum {
	PROP_0,
	PROP_CALLER,
	PROP_OBJECT_PATH,
	PROP_SERVICE
};

struct _GkdSecretPromptPrivate {
	gchar *object_path;
	GkdSecretService *service;
	GkdSecretExchange *exchange;
	GkdOrgFreedesktopSecretPrompt *skeleton;
	GCancellable *cancellable;
	gboolean prompted;
	gboolean completed;
	gchar *caller;
	gchar *window_id;
	GList *objects;
};

static void gkd_secret_dispatch_iface (GkdSecretDispatchIface *iface);
G_DEFINE_TYPE_WITH_CODE (GkdSecretPrompt, gkd_secret_prompt, GCR_TYPE_SYSTEM_PROMPT,
                         G_IMPLEMENT_INTERFACE (GKD_SECRET_TYPE_DISPATCH, gkd_secret_dispatch_iface));

static guint unique_prompt_number = 0;

static void
emit_completed (GkdSecretPrompt *self, gboolean dismissed)
{
	GVariant *variant;

	g_return_if_fail (GKD_SECRET_PROMPT_GET_CLASS (self)->encode_result);
	variant = GKD_SECRET_PROMPT_GET_CLASS (self)->encode_result (self);

	gkd_org_freedesktop_secret_prompt_emit_completed (self->pv->skeleton,
							  dismissed, variant);
}

static void
on_system_prompt_inited (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	GkdSecretPrompt *self = GKD_SECRET_PROMPT (source);
	GkdSecretPromptClass *klass;
	GError *error = NULL;

	if (g_async_initable_init_finish (G_ASYNC_INITABLE (source), result, &error)) {
		klass = GKD_SECRET_PROMPT_GET_CLASS (self);
		g_assert (klass->prompt_ready);
		(klass->prompt_ready) (self);
	} else {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_message ("couldn't initialize prompt: %s", error->message);
		g_error_free (error);
		if (!self->pv->completed)
			gkd_secret_prompt_dismiss (self);
	}
}

static gboolean
prompt_method_prompt (GkdOrgFreedesktopSecretPrompt *skeleton,
		      GDBusMethodInvocation *invocation,
		      gchar *window_id,
		      GkdSecretPrompt *self)
{
	/* Act as if this object no longer exists */
	if (self->pv->completed)
		return FALSE;

	/* Prompt can only be called once */
	if (self->pv->prompted) {
		g_dbus_method_invocation_return_error_literal (invocation, GKD_SECRET_ERROR,
							       GKD_SECRET_ERROR_ALREADY_EXISTS,
							       "This prompt has already been shown.");
		return TRUE;
	}

	self->pv->prompted = TRUE;

	gcr_prompt_set_caller_window (GCR_PROMPT (self), window_id);

	g_async_initable_init_async (G_ASYNC_INITABLE (self), G_PRIORITY_DEFAULT,
	                             self->pv->cancellable, on_system_prompt_inited, NULL);

	gkd_org_freedesktop_secret_prompt_complete_prompt (skeleton, invocation);
	return TRUE;
}

static gboolean
prompt_method_dismiss (GkdOrgFreedesktopSecretPrompt *skeleton,
		       GDBusMethodInvocation *invocation,
		       GkdSecretPrompt *self)
{
	/* Act as if this object no longer exists */
	if (self->pv->completed)
		return FALSE;

	gkd_secret_prompt_dismiss (self);

	gkd_org_freedesktop_secret_prompt_complete_dismiss (skeleton, invocation);
	return TRUE;
}

static void
gkd_secret_prompt_real_prompt_ready (GkdSecretPrompt *self)
{
	/* Default implementation, unused */
	g_return_if_reached ();
}

static GVariant *
gkd_secret_prompt_real_encode_result (GkdSecretPrompt *self)
{
	/* Default implementation, unused */
	g_return_val_if_reached (NULL);
}

static void
gkd_secret_prompt_constructed (GObject *obj)
{
	GkdSecretPrompt *self = GKD_SECRET_PROMPT (obj);
	GError *error = NULL;

	G_OBJECT_CLASS (gkd_secret_prompt_parent_class)->constructed (obj);

	g_return_if_fail (self->pv->caller);
	g_return_if_fail (self->pv->service);

	/* Setup the path for the object */
	self->pv->object_path = g_strdup_printf (SECRET_PROMPT_PREFIX "/p%d", ++unique_prompt_number);

	self->pv->exchange = gkd_secret_exchange_new (self->pv->service, self->pv->caller);

	/* Set the exchange for the prompt */
	g_object_set (self, "secret-exchange", self->pv->exchange, NULL);

        self->pv->skeleton = gkd_org_freedesktop_secret_prompt_skeleton_new ();
        g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (self->pv->skeleton),
                                          gkd_secret_service_get_connection (self->pv->service), self->pv->object_path,
                                          &error);

        if (error != NULL) {
		g_warning ("could not register secret prompt on session bus: %s", error->message);
		g_error_free (error);
	}

	g_signal_connect (self->pv->skeleton, "handle-dismiss",
			  G_CALLBACK (prompt_method_dismiss), self);
	g_signal_connect (self->pv->skeleton, "handle-prompt",
			  G_CALLBACK (prompt_method_prompt), self);
}

static void
gkd_secret_prompt_init (GkdSecretPrompt *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GKD_SECRET_TYPE_PROMPT, GkdSecretPromptPrivate);
	self->pv->cancellable = g_cancellable_new ();
}

static void
gkd_secret_prompt_dispose (GObject *obj)
{
	GkdSecretPrompt *self = GKD_SECRET_PROMPT (obj);

	g_cancellable_cancel (self->pv->cancellable);

	g_free (self->pv->object_path);
	self->pv->object_path = NULL;

	if (self->pv->service) {
		g_object_remove_weak_pointer (G_OBJECT (self->pv->service),
		                              (gpointer*)&(self->pv->service));
		self->pv->service = NULL;
	}

	g_clear_object (&self->pv->exchange);

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

	g_clear_object (&self->pv->cancellable);

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
		g_value_set_pointer (value, self->pv->object_path);
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

	gobject_class->constructed = gkd_secret_prompt_constructed;
	gobject_class->dispose = gkd_secret_prompt_dispose;
	gobject_class->finalize = gkd_secret_prompt_finalize;
	gobject_class->set_property = gkd_secret_prompt_set_property;
	gobject_class->get_property = gkd_secret_prompt_get_property;

	klass->encode_result = gkd_secret_prompt_real_encode_result;
	klass->prompt_ready = gkd_secret_prompt_real_prompt_ready;

	g_type_class_add_private (klass, sizeof (GkdSecretPromptPrivate));

	g_object_class_install_property (gobject_class, PROP_CALLER,
		g_param_spec_string ("caller", "Caller", "DBus caller name",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY ));

	g_object_class_install_property (gobject_class, PROP_OBJECT_PATH,
	        g_param_spec_pointer ("object-path", "Object Path", "DBus Object Path",
		                      G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Service which owns this prompt",
		                     GKD_SECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
gkd_secret_dispatch_iface (GkdSecretDispatchIface *iface)
{
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

const gchar*
gkd_secret_prompt_get_caller (GkdSecretPrompt *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	return self->pv->caller;
}

const gchar*
gkd_secret_prompt_get_window_id (GkdSecretPrompt *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	return self->pv->window_id;
}

GckSession*
gkd_secret_prompt_get_pkcs11_session (GkdSecretPrompt *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	g_return_val_if_fail (self->pv->service, NULL);
	return gkd_secret_service_get_pkcs11_session (self->pv->service, self->pv->caller);
}

GkdSecretService*
gkd_secret_prompt_get_service (GkdSecretPrompt *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	g_return_val_if_fail (self->pv->service, NULL);
	return self->pv->service;
}

GkdSecretObjects*
gkd_secret_prompt_get_objects (GkdSecretPrompt *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	g_return_val_if_fail (self->pv->service, NULL);
	return gkd_secret_service_get_objects (self->pv->service);
}

void
gkd_secret_prompt_complete (GkdSecretPrompt *self)
{
	g_return_if_fail (GKD_SECRET_IS_PROMPT (self));
	g_return_if_fail (!self->pv->completed);
	self->pv->completed = TRUE;
	emit_completed (self, FALSE);

	/* Make this object go away */
	g_object_run_dispose (G_OBJECT (self));
}

void
gkd_secret_prompt_dismiss (GkdSecretPrompt *self)
{
	g_return_if_fail (GKD_SECRET_IS_PROMPT (self));
	g_return_if_fail (!self->pv->completed);
	self->pv->completed = TRUE;
	emit_completed (self, TRUE);

	/* Make this object go away */
	g_object_run_dispose (G_OBJECT (self));
}

void
gkd_secret_prompt_dismiss_with_error (GkdSecretPrompt *self,
                                      GError *error)
{
	g_warning ("prompting failed: %s", egg_error_message (error));
	gkd_secret_prompt_dismiss (self);
}

GckObject*
gkd_secret_prompt_lookup_collection (GkdSecretPrompt *self, const gchar *path)
{
	GkdSecretObjects *objects;

	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	g_return_val_if_fail (path, NULL);

	objects = gkd_secret_prompt_get_objects (GKD_SECRET_PROMPT (self));
	return gkd_secret_objects_lookup_collection (objects, self->pv->caller, path);
}

GkdSecretSecret *
gkd_secret_prompt_take_secret (GkdSecretPrompt *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);

	/* ... instead it stashes away the raw cipher text, and makes it available here */
	return gkd_secret_exchange_take_last_secret (self->pv->exchange);
}

GCancellable *
gkd_secret_prompt_get_cancellable (GkdSecretPrompt *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_PROMPT (self), NULL);
	return self->pv->cancellable;
}
