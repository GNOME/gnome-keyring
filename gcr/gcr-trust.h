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

#ifndef __GCR_TRUST_H__
#define __GCR_TRUST_H__

#include "gcr-types.h"

G_BEGIN_DECLS

typedef enum _GcrTrust {
	GCR_TRUST_UNTRUSTED = -1,
	GCR_TRUST_UNKNOWN = 0,
	GCR_TRUST_TRUSTED,
} GcrTrust;

typedef enum _GcrPurpose {
	GCR_PURPOSE_SERVER_AUTH = 1,
	GCR_PURPOSE_CLIENT_AUTH,
	GCR_PURPOSE_CODE_SIGNING,
	GCR_PURPOSE_EMAIL,
	GCR_PURPOSE_TIME_STAMPING,
	GCR_PURPOSE_IPSEC_ENDPOINT,
	GCR_PURPOSE_IPSEC_TUNNEL,
	GCR_PURPOSE_IPSEC_USER,
	GCR_PURPOSE_IKE_INTERMEDIATE,
} GcrPurpose;

GcrTrust       gcr_trust_get_certificate_exception          (GcrCertificate *cert,
                                                             GcrPurpose purpose,
                                                             GCancellable *cancel,
                                                             GError **error);

void           gcr_trust_get_certificate_exception_async    (GcrCertificate *cert,
                                                             GcrPurpose purpose,
                                                             GCancellable *cancel,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

GcrTrust       gcr_trust_get_certificate_exception_finish   (GAsyncResult *res,
                                                             GError **error);

gboolean       gcr_trust_set_certificate_exception          (GcrCertificate *cert,
                                                             GcrPurpose purpose,
                                                             GcrTrust trust,
                                                             GCancellable *cancel,
                                                             GError **error);

void           gcr_trust_set_certificate_exception_async    (GcrCertificate *cert,
                                                             GcrPurpose purpose,
                                                             GcrTrust trust,
                                                             GCancellable *cancel,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

gboolean       gcr_trust_set_certificate_exception_finish   (GAsyncResult *res,
                                                             GError **error);

gboolean       gcr_trust_is_certificate_root                (GcrCertificate *cert,
                                                             GcrPurpose purpose,
                                                             GCancellable *cancel,
                                                             GError **error);

void           gcr_trust_is_certificate_root_async          (GcrCertificate *cert,
                                                             GcrPurpose purpose,
                                                             GCancellable *cancel,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

gboolean       gcr_trust_is_certificate_root_finish         (GAsyncResult *res,
                                                             GError **error);

G_END_DECLS

#endif /* __GCR_TOKEN_MANAGER_H__ */
