/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2011 Collabora Ltd.
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
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#ifndef __GCR_PKCS11_IMPORT_DIALOG_H__
#define __GCR_PKCS11_IMPORT_DIALOG_H__

#include "gcr.h"

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define GCR_TYPE_PKCS11_IMPORT_DIALOG               (_gcr_pkcs11_import_dialog_get_type ())
#define GCR_PKCS11_IMPORT_DIALOG(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_PKCS11_IMPORT_DIALOG, GcrPkcs11ImportDialog))
#define GCR_IS_PKCS11_IMPORT_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_PKCS11_IMPORT_DIALOG))

typedef struct _GcrPkcs11ImportDialog GcrPkcs11ImportDialog;

GType                   _gcr_pkcs11_import_dialog_get_type          (void) G_GNUC_CONST;

GcrPkcs11ImportDialog * _gcr_pkcs11_import_dialog_new               (GtkWindow *parent);

void                    _gcr_pkcs11_import_dialog_get_supplements   (GcrPkcs11ImportDialog *self,
                                                                     GckAttributes *attributes);

void                    _gcr_pkcs11_import_dialog_set_supplements   (GcrPkcs11ImportDialog *self,
                                                                     GckAttributes *attributes);

gboolean                _gcr_pkcs11_import_dialog_run               (GcrPkcs11ImportDialog *self);

void                    _gcr_pkcs11_import_dialog_run_async         (GcrPkcs11ImportDialog *self,
                                                                     GCancellable *cancellable,
                                                                     GAsyncReadyCallback callback,
                                                                     gpointer user_data);

gboolean                _gcr_pkcs11_import_dialog_run_finish        (GcrPkcs11ImportDialog *self,
                                                                     GAsyncResult *result);

GTlsInteractionResult   _gcr_pkcs11_import_dialog_run_ask_password  (GcrPkcs11ImportDialog *self,
                                                                     GTlsPassword *password,
                                                                     GCancellable *cancellable,
                                                                     GError **error);

G_END_DECLS

#endif /* __GCR_PKCS11_IMPORT_DIALOG_H__ */
