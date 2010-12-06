/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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

#if !defined (__GCR_H_INSIDE__) && !defined (GCR_COMPILATION)
#error "Only <gcr/gcr.h> can be included directly."
#endif

#ifndef __GCR_TRUST_H__
#define __GCR_TRUST_H__

#include "gcr-types.h"

G_BEGIN_DECLS

#define GCR_PURPOSE_SERVER_AUTH "1.3.6.1.5.5.7.3.1"
#define GCR_PURPOSE_CLIENT_AUTH "1.3.6.1.5.5.7.3.2"
#define GCR_PURPOSE_CODE_SIGNING "1.3.6.1.5.5.7.3.3"
#define GCR_PURPOSE_EMAIL "1.3.6.1.5.5.7.3.4"

gboolean       gcr_trust_is_certificate_exception              (GcrCertificate *cert,
                                                                const gchar *purpose,
                                                                const gchar *peer,
                                                                GCancellable *cancel,
                                                                GError **error);

void           gcr_trust_is_certificate_exception_async        (GcrCertificate *cert,
                                                                const gchar *purpose,
                                                                const gchar *peer,
                                                                GCancellable *cancel,
                                                                GAsyncReadyCallback callback,
                                                                gpointer user_data);

gboolean       gcr_trust_is_certificate_exception_finish       (GAsyncResult *res,
                                                                GError **error);

gboolean       gcr_trust_add_certificate_exception             (GcrCertificate *cert,
                                                                const gchar *purpose,
                                                                const gchar *peer,
                                                                GCancellable *cancel,
                                                                GError **error);

void           gcr_trust_add_certificate_exception_async       (GcrCertificate *cert,
                                                                const gchar *purpose,
                                                                const gchar *peer,
                                                                GCancellable *cancel,
                                                                GAsyncReadyCallback callback,
                                                                gpointer user_data);

gboolean       gcr_trust_add_certificate_exception_finish      (GAsyncResult *res,
                                                                GError **error);

gboolean       gcr_trust_remove_certificate_exception          (GcrCertificate *cert,
                                                                const gchar *purpose,
                                                                const gchar *peer,
                                                                GCancellable *cancel,
                                                                GError **error);

void           gcr_trust_remove_certificate_exception_async    (GcrCertificate *cert,
                                                                const gchar *purpose,
                                                                const gchar *peer,
                                                                GCancellable *cancel,
                                                                GAsyncReadyCallback callback,
                                                                gpointer user_data);

gboolean       gcr_trust_remove_certificate_exception_finish   (GAsyncResult *res,
                                                                GError **error);

gboolean       gcr_trust_is_certificate_anchor                 (GcrCertificate *cert,
                                                                const gchar *purpose,
                                                                GCancellable *cancel,
                                                                GError **error);

void           gcr_trust_is_certificate_anchor_async           (GcrCertificate *cert,
                                                                const gchar *purpose,
                                                                GCancellable *cancel,
                                                                GAsyncReadyCallback callback,
                                                                gpointer user_data);

gboolean       gcr_trust_is_certificate_anchor_finish          (GAsyncResult *res,
                                                                GError **error);

G_END_DECLS

#endif /* __GCR_TOKEN_MANAGER_H__ */
