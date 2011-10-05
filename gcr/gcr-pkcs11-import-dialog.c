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
#include "gcr-pkcs11-import-dialog.h"

#include "egg/egg-entry-buffer.h"
#include "egg/egg-secure-memory.h"

#include <gtk/gtk.h>

#include <glib/gi18n-lib.h>

EGG_SECURE_DECLARE (import_dialog);

#define GCR_PKCS11_IMPORT_DIALOG_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_PKCS11_IMPORT_DIALOG, GcrPkcs11ImportDialogClass))
#define GCR_IS_PKCS11_IMPORT_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_PKCS11_IMPORT_DIALOG))
#define GCR_PKCS11_IMPORT_DIALOG_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_PKCS11_IMPORT_DIALOG, GcrPkcs11ImportDialogClass))

enum {
	PROP_0,
	PROP_IMPORTER
};

struct _GcrPkcs11ImportDialog {
	GtkDialog parent;
	GtkBuilder *builder;
	GtkWidget *password_area;
	GtkLabel *token_label;
	GtkImage *token_image;
	GtkEntry *password_entry;
	GtkEntry *label_entry;
	gboolean label_changed;
};

typedef struct _GcrPkcs11ImportDialogClass GcrPkcs11ImportDialogClass;

struct _GcrPkcs11ImportDialogClass {
	GtkDialogClass parent;
};

G_DEFINE_TYPE (GcrPkcs11ImportDialog, _gcr_pkcs11_import_dialog, GTK_TYPE_DIALOG);

static void
on_label_changed (GtkEditable *editable,
                  gpointer user_data)
{
	GcrPkcs11ImportDialog *self = GCR_PKCS11_IMPORT_DIALOG (user_data);
	self->label_changed = TRUE;
}

static void
_gcr_pkcs11_import_dialog_constructed (GObject *obj)
{
	GcrPkcs11ImportDialog *self = GCR_PKCS11_IMPORT_DIALOG (obj);
	GError *error = NULL;
	GtkEntryBuffer *buffer;
	GtkWidget *widget;
	GtkBox *contents;

	G_OBJECT_CLASS (_gcr_pkcs11_import_dialog_parent_class)->constructed (obj);

	if (!gtk_builder_add_from_file (self->builder, UIDIR "gcr-pkcs11-import-dialog.ui", &error)) {
		g_warning ("couldn't load ui builder file: %s", error->message);
		return;
	}

	/* Fill in the dialog from builder */
	widget = GTK_WIDGET (gtk_builder_get_object (self->builder, "pkcs11-import-dialog"));
	contents = GTK_BOX (gtk_dialog_get_content_area (GTK_DIALOG (self)));
	gtk_box_pack_start (contents, widget, TRUE, TRUE, 0);

	/* The password area */
	self->password_area = GTK_WIDGET (gtk_builder_get_object (self->builder, "unlock-area"));
	gtk_widget_hide (self->password_area);

	/* Add a secure entry */
	buffer = egg_entry_buffer_new ();
	self->password_entry = GTK_ENTRY (gtk_builder_get_object (self->builder, "password-entry"));
	gtk_entry_set_buffer (self->password_entry, buffer);
	gtk_entry_set_activates_default (self->password_entry, TRUE);
	g_object_unref (buffer);

	self->token_label = GTK_LABEL (gtk_builder_get_object (self->builder, "token-description"));
	self->token_image = GTK_IMAGE (gtk_builder_get_object (self->builder, "token-image"));

	/* Setup the label */
	self->label_entry = GTK_ENTRY (gtk_builder_get_object (self->builder, "label-entry"));
	g_signal_connect (self->label_entry, "changed", G_CALLBACK (on_label_changed), self);
	gtk_entry_set_activates_default (self->label_entry, TRUE);

	/* Add our various buttons */
	gtk_dialog_add_button (GTK_DIALOG (self), GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL);
	gtk_dialog_add_button (GTK_DIALOG (self), GTK_STOCK_OK, GTK_RESPONSE_OK);
	gtk_dialog_set_default_response (GTK_DIALOG (self), GTK_RESPONSE_OK);

	gtk_window_set_modal (GTK_WINDOW (self), TRUE);
}

static void
_gcr_pkcs11_import_dialog_init (GcrPkcs11ImportDialog *self)
{
	self->builder = gtk_builder_new ();
}

static void
_gcr_pkcs11_import_dialog_finalize (GObject *obj)
{
	GcrPkcs11ImportDialog *self = GCR_PKCS11_IMPORT_DIALOG (obj);

	g_object_unref (self->builder);

	G_OBJECT_CLASS (_gcr_pkcs11_import_dialog_parent_class)->finalize (obj);
}

static void
_gcr_pkcs11_import_dialog_class_init (GcrPkcs11ImportDialogClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructed = _gcr_pkcs11_import_dialog_constructed;
	gobject_class->finalize = _gcr_pkcs11_import_dialog_finalize;
}

GcrPkcs11ImportDialog *
_gcr_pkcs11_import_dialog_new (GtkWindow *parent)
{
	GcrPkcs11ImportDialog *dialog;

	g_return_val_if_fail (parent == NULL || GTK_IS_WINDOW (parent), NULL);

	dialog = g_object_new (GCR_TYPE_PKCS11_IMPORT_DIALOG,
	                       "transient-for", parent,
	                       NULL);

	return g_object_ref_sink (dialog);
}

void
_gcr_pkcs11_import_dialog_get_supplements (GcrPkcs11ImportDialog *self,
                                           GckAttributes *attributes)
{
	const gchar *label;

	g_return_if_fail (GCR_IS_PKCS11_IMPORT_DIALOG (self));
	g_return_if_fail (attributes != NULL);

	label = gtk_entry_get_text (self->label_entry);
	if (self->label_changed && label != NULL && label[0])
		gck_attributes_set_string (attributes, CKA_LABEL, label);
}

void
_gcr_pkcs11_import_dialog_set_supplements (GcrPkcs11ImportDialog *self,
                                           GckAttributes *attributes)
{
	gchar *label;

	g_return_if_fail (GCR_IS_PKCS11_IMPORT_DIALOG (self));
	g_return_if_fail (attributes != NULL);

	if (!gck_attributes_find_string (attributes, CKA_LABEL, &label))
		label = NULL;

	if (label == NULL)
		gtk_entry_set_placeholder_text (self->label_entry, _("Automatically chosen"));
	gtk_entry_set_text (self->label_entry, label == NULL ? "" : label);
	g_free (label);

	self->label_changed = FALSE;
}

gboolean
_gcr_pkcs11_import_dialog_run (GcrPkcs11ImportDialog *self)
{
	gboolean ret = FALSE;

	g_return_val_if_fail (GCR_IS_PKCS11_IMPORT_DIALOG (self), FALSE);

	if (gtk_dialog_run (GTK_DIALOG (self)) == GTK_RESPONSE_OK) {
		ret = TRUE;
	}

	gtk_widget_hide (GTK_WIDGET (self));

	return ret;
}

void
_gcr_pkcs11_import_dialog_run_async (GcrPkcs11ImportDialog *self,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	g_return_if_fail (GCR_IS_PKCS11_IMPORT_DIALOG (self));

	_gcr_dialog_util_run_async (GTK_DIALOG (self), cancellable, callback, user_data);
}

gboolean
_gcr_pkcs11_import_dialog_run_finish (GcrPkcs11ImportDialog *self,
                                      GAsyncResult *result)
{
	gint response;

	g_return_val_if_fail (GCR_IS_PKCS11_IMPORT_DIALOG (self), FALSE);

	response = _gcr_dialog_util_run_finish (GTK_DIALOG (self), result);

	gtk_widget_hide (GTK_WIDGET (self));

	return (response == GTK_RESPONSE_OK) ? TRUE : FALSE;
}

GTlsInteractionResult
_gcr_pkcs11_import_dialog_run_ask_password (GcrPkcs11ImportDialog *self,
                                            GTlsPassword *password,
                                            GCancellable *cancellable,
                                            GError **error)
{
	GckTokenInfo *token_info;
	const gchar *value;
	GckSlot *slot;
	GIcon *icon;
	gboolean ret;

	g_return_val_if_fail (GCR_IS_PKCS11_IMPORT_DIALOG (self), G_TLS_INTERACTION_UNHANDLED);
	g_return_val_if_fail (G_IS_TLS_PASSWORD (password), G_TLS_INTERACTION_UNHANDLED);
	g_return_val_if_fail (error == NULL || *error == NULL, G_TLS_INTERACTION_UNHANDLED);

	if (GCK_IS_PASSWORD (password)) {
		slot = gck_password_get_token (GCK_PASSWORD (password));
		token_info = gck_slot_get_token_info (slot);
		icon = gcr_icon_for_token (token_info);
		gtk_image_set_from_gicon (self->token_image, icon, GTK_ICON_SIZE_BUTTON);
		gck_token_info_free (token_info);
		g_object_unref (icon);
	}

	gtk_label_set_text (self->token_label, g_tls_password_get_description (password));

	gtk_widget_show (self->password_area);

	ret = _gcr_pkcs11_import_dialog_run (self);

	gtk_widget_hide (self->password_area);

	if (!ret) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
		             _("The user cancelled the operation"));
		return G_TLS_INTERACTION_FAILED;
	}

	value = gtk_entry_get_text (self->password_entry);
	g_tls_password_set_value_full (password, egg_secure_strdup (value),
	                               -1, egg_secure_free);
	return G_TLS_INTERACTION_HANDLED;
}
