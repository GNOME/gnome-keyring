/*
 * gnome-keyring
 *
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

#ifndef __GCR_PKCS11_IMPORT_INTERACTION_H__
#define __GCR_PKCS11_IMPORT_INTERACTION_H__

#include "gcr.h"

#include "gcr-pkcs11-import-dialog.h"

G_BEGIN_DECLS

#define GCR_TYPE_PKCS11_IMPORT_INTERACTION               (_gcr_pkcs11_import_interaction_get_type ())
#define GCR_PKCS11_IMPORT_INTERACTION(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_PKCS11_IMPORT_INTERACTION, GcrPkcs11ImportInteraction))
#define GCR_IS_PKCS11_IMPORT_INTERACTION(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_PKCS11_IMPORT_INTERACTION))

typedef struct _GcrPkcs11ImportInteraction GcrPkcs11ImportInteraction;

GType               _gcr_pkcs11_import_interaction_get_type     (void) G_GNUC_CONST;

GTlsInteraction *   _gcr_pkcs11_import_interaction_new          (GtkWindow *parent_window);

G_END_DECLS

#endif /* __GCR_PKCS11_IMPORT_INTERACTION_H__ */
