/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#if !defined (__GCR_INSIDE_HEADER__) && !defined (GCR_COMPILATION)
#error "Only <gcr/gcr.h> or <gcr/gcr-base.h> can be included directly."
#endif

#ifndef GCR_FINGERPRINT_H
#define GCR_FINGERPRINT_H

#include <glib.h>

#include "gcr-types.h"
#include "gcr-certificate.h"

guchar *        gcr_fingerprint_from_subject_public_key_info    (const guchar *key_info,
                                                                 gsize n_key_info,
                                                                 GChecksumType checksum_type,
                                                                 gsize *n_fingerprint);

guchar *        gcr_fingerprint_from_attributes                 (GckAttributes *attrs,
                                                                 GChecksumType checksum_type,
                                                                 gsize *n_fingerprint);

guchar *        gcr_fingerprint_from_certificate_public_key     (GcrCertificate *certificate,
                                                                 GChecksumType checksum_type,
                                                                 gsize *n_fingerprint);

#endif /* GCR_FINGERPRINT_H_ */
