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

#include "gcr-dialog-util.h"
#include "gcr-import-interaction.h"
#include "gcr-pkcs11-import-interaction.h"

#include <glib/gi18n-lib.h>

#define GCR_PKCS11_IMPORT_INTERACTION_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_PKCS11_IMPORT_INTERACTION, GcrPkcs11ImportInteractionClass))
#define GCR_IS_PKCS11_IMPORT_INTERACTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_PKCS11_IMPORT_INTERACTION))
#define GCR_PKCS11_IMPORT_INTERACTION_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_PKCS11_IMPORT_INTERACTION, GcrPkcs11ImportInteractionClass))

enum {
	PROP_0,
	PROP_PARENT_WINDOW
};

typedef struct _GcrPkcs11ImportInteractionClass GcrPkcs11ImportInteractionClass;

struct _GcrPkcs11ImportInteraction {
	GTlsInteraction parent;
	gboolean supplemented;
	GtkWindow *parent_window;
	GcrPkcs11ImportDialog *dialog;
};

struct _GcrPkcs11ImportInteractionClass {
	GTlsInteractionClass parent_class;
};

static void _gcr_pkcs11_import_interaction_iface_init (GcrImportInteractionIface *iface);

G_DEFINE_TYPE_WITH_CODE(GcrPkcs11ImportInteraction, _gcr_pkcs11_import_interaction, G_TYPE_TLS_INTERACTION,
                        G_IMPLEMENT_INTERFACE (GCR_TYPE_IMPORT_INTERACTION, _gcr_pkcs11_import_interaction_iface_init));

static void
_gcr_pkcs11_import_interaction_init (GcrPkcs11ImportInteraction *self)
{
	self->dialog = _gcr_pkcs11_import_dialog_new (self->parent_window);
}

static void
_gcr_pkcs11_import_interaction_dispose (GObject *obj)
{
	GcrPkcs11ImportInteraction *self = GCR_PKCS11_IMPORT_INTERACTION (obj);

	g_clear_object (&self->dialog);

	G_OBJECT_CLASS (_gcr_pkcs11_import_interaction_parent_class)->dispose (obj);
}

static void
_gcr_pkcs11_import_interaction_set_property (GObject *obj,
                                             guint prop_id,
                                             const GValue *value,
                                             GParamSpec *pspec)
{
	GcrPkcs11ImportInteraction *self = GCR_PKCS11_IMPORT_INTERACTION (obj);

	switch (prop_id) {
	case PROP_PARENT_WINDOW:
		gtk_window_set_transient_for (GTK_WINDOW (self->dialog),
		                              g_value_get_object (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_pkcs11_import_interaction_get_property (GObject *obj,
                                             guint prop_id,
                                             GValue *value,
                                             GParamSpec *pspec)
{
	GcrPkcs11ImportInteraction *self = GCR_PKCS11_IMPORT_INTERACTION (obj);

	switch (prop_id) {
	case PROP_PARENT_WINDOW:
		g_value_set_object (value, gtk_window_get_transient_for (GTK_WINDOW (self->dialog)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static GTlsInteractionResult
_gcr_pkcs11_import_interaction_ask_password (GTlsInteraction *interaction,
                                             GTlsPassword *password,
                                             GCancellable *cancellable,
                                             GError **error)
{
	GcrPkcs11ImportInteraction *self = GCR_PKCS11_IMPORT_INTERACTION (interaction);

	g_return_val_if_fail (self->dialog != NULL, G_TLS_INTERACTION_UNHANDLED);

	self->supplemented = TRUE;
	return _gcr_pkcs11_import_dialog_run_ask_password (self->dialog, password, cancellable, error);
}

static void
_gcr_pkcs11_import_interaction_supplement_prep (GcrImportInteraction *interaction,
                                                GckAttributes *attributes)
{
	GcrPkcs11ImportInteraction *self = GCR_PKCS11_IMPORT_INTERACTION (interaction);

	self->supplemented = FALSE;
	_gcr_pkcs11_import_dialog_set_supplements (self->dialog, attributes);
}

static GTlsInteractionResult
_gcr_pkcs11_import_interaction_supplement (GcrImportInteraction *interaction,
                                           GckAttributes *attributes,
                                           GCancellable *cancellable,
                                           GError **error)
{
	GcrPkcs11ImportInteraction *self = GCR_PKCS11_IMPORT_INTERACTION (interaction);

	g_return_val_if_fail (self->dialog != NULL, G_TLS_INTERACTION_UNHANDLED);

	if (self->supplemented)
		return G_TLS_INTERACTION_HANDLED;

	self->supplemented = TRUE;
	if (_gcr_pkcs11_import_dialog_run (self->dialog)) {
		_gcr_pkcs11_import_dialog_get_supplements (self->dialog, attributes);
		return G_TLS_INTERACTION_HANDLED;

	} else {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, _("The user cancelled the operation"));
		return G_TLS_INTERACTION_FAILED;
	}
}

static void
on_dialog_run_async (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
_gcr_pkcs11_import_interaction_supplement_async (GcrImportInteraction *interaction,
                                                 GckAttributes *attributes,
                                                 GCancellable *cancellable,
                                                 GAsyncReadyCallback callback,
                                                 gpointer user_data)
{
	GcrPkcs11ImportInteraction *self = GCR_PKCS11_IMPORT_INTERACTION (interaction);
	GSimpleAsyncResult *res;

	g_return_if_fail (self->dialog != NULL);

	res = g_simple_async_result_new (G_OBJECT (interaction), callback, user_data,
	                                 _gcr_pkcs11_import_interaction_supplement_async);

	/* If dialog was already shown, then short circuit */
	if (self->supplemented) {
		g_simple_async_result_complete_in_idle (res);

	} else {
		self->supplemented = TRUE;
		g_simple_async_result_set_op_res_gpointer (res, gck_attributes_ref (attributes),
		                                           (GDestroyNotify)gck_attributes_unref);
		_gcr_pkcs11_import_dialog_run_async (self->dialog, cancellable,
		                                     on_dialog_run_async, g_object_ref (res));
	}

	g_object_unref (res);
}

static GTlsInteractionResult
_gcr_pkcs11_import_interaction_supplement_finish (GcrImportInteraction *interaction,
                                                  GAsyncResult *result,
                                                  GError **error)
{
	GcrPkcs11ImportInteraction *self = GCR_PKCS11_IMPORT_INTERACTION (interaction);
	GckAttributes *attributes;

	g_return_val_if_fail (self->dialog != NULL, G_TLS_INTERACTION_UNHANDLED);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (interaction),
	                      _gcr_pkcs11_import_interaction_supplement_async), G_TLS_INTERACTION_UNHANDLED);

	attributes = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (result));

	/* Didn't show the dialog */
	if (attributes == NULL)
		return G_TLS_INTERACTION_HANDLED;

	if (_gcr_pkcs11_import_dialog_run_finish (self->dialog, result)) {
		_gcr_pkcs11_import_dialog_get_supplements (self->dialog, attributes);
		return G_TLS_INTERACTION_HANDLED;
	} else {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, _("The user cancelled the operation"));
		return G_TLS_INTERACTION_FAILED;
	}
}

static void
_gcr_pkcs11_import_interaction_iface_init (GcrImportInteractionIface *iface)
{
	iface->supplement_prep = _gcr_pkcs11_import_interaction_supplement_prep;
	iface->supplement = _gcr_pkcs11_import_interaction_supplement;
	iface->supplement_async = _gcr_pkcs11_import_interaction_supplement_async;
	iface->supplement_finish = _gcr_pkcs11_import_interaction_supplement_finish;
}

static void
_gcr_pkcs11_import_interaction_class_init (GcrPkcs11ImportInteractionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);

	gobject_class->dispose = _gcr_pkcs11_import_interaction_dispose;
	gobject_class->set_property = _gcr_pkcs11_import_interaction_set_property;
	gobject_class->get_property = _gcr_pkcs11_import_interaction_get_property;

	interaction_class->ask_password = _gcr_pkcs11_import_interaction_ask_password;

	g_object_class_install_property (gobject_class, PROP_PARENT_WINDOW,
	              g_param_spec_object ("parent-window", "Parent Window", "Prompt Parent Window",
	                                   GTK_TYPE_WINDOW, G_PARAM_READWRITE));
}

GTlsInteraction *
_gcr_pkcs11_import_interaction_new (GtkWindow *parent_window)
{
	g_return_val_if_fail (parent_window == NULL || GTK_IS_WINDOW (parent_window), NULL);
	return g_object_new (GCR_TYPE_PKCS11_IMPORT_INTERACTION,
	                     "parent-window", parent_window,
	                     NULL);
}
