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

#ifndef __GCR_CERTIFICATE_H__
#define __GCR_CERTIFICATE_H__

#include "gcr.h"

#include <glib-object.h>

#define GCR_TYPE_CERTIFICATE               (gcr_certificate_get_type ())
#define GCR_CERTIFICATE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_CERTIFICATE, GcrCertificate))
#define GCR_CERTIFICATE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_CERTIFICATE, GcrCertificateClass))
#define GCR_IS_CERTIFICATE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_CERTIFICATE))
#define GCR_IS_CERTIFICATE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_CERTIFICATE))
#define GCR_CERTIFICATE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_CERTIFICATE, GcrCertificateClass))

typedef struct _GcrCertificate GcrCertificate;
typedef struct _GcrCertificateClass GcrCertificateClass;
typedef struct _GcrCertificatePrivate GcrCertificatePrivate;

struct _GcrCertificate {
	GObject parent;
	GcrCertificatePrivate *pv;
};

struct _GcrCertificateClass {
	GObjectClass parent_class;
    
	/* virtual  */
    
	const guchar* (*get_der_data) (GcrCertificate *self, gsize *n_length);
};

GType               gcr_certificate_get_type               (void);

GcrCertificate*     gcr_certificate_new_for_data           (const guchar *data,
                                                            gsize n_data);

const guchar*       gcr_certificate_get_der_data           (GcrCertificate *self, 
                                                            gsize *n_data);

gchar*              gcr_certificate_get_issuer_cn          (GcrCertificate *self);

gchar*              gcr_certificate_get_issuer_dn          (GcrCertificate *self);

gchar*              gcr_certificate_get_issuer_part        (GcrCertificate *self, 
                                                            const gchar *part);

gchar*              gcr_certificate_get_subject_cn         (GcrCertificate *self);

gchar*              gcr_certificate_get_subject_dn         (GcrCertificate *self);

gchar*              gcr_certificate_get_subject_part       (GcrCertificate *self, 
                                                            const gchar *part);

GDate*              gcr_certificate_get_issued_date        (GcrCertificate *self);

GDate*              gcr_certificate_get_expiry_date        (GcrCertificate *self);

guchar*             gcr_certificate_get_serial_number      (GcrCertificate *self, 
                                                            gsize *n_length);

gchar*              gcr_certificate_get_serial_number_hex  (GcrCertificate *self);

guchar*             gcr_certificate_get_fingerprint        (GcrCertificate *self, 
                                                            GChecksumType type, 
                                                            gsize *n_length);

gchar*              gcr_certificate_get_fingerprint_hex    (GcrCertificate *self, 
                                                            GChecksumType type);

#endif /* __GCR_CERTIFICATE_H__ */
