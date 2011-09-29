/*
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
 * Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"
#include "gcr-certificate-details-widget.h"

#ifndef GCR_DISABLE_DEPRECATED

/* These are all stubs for GcrCertificateWidget */

GType
gcr_certificate_details_widget_get_type (void)
{
	return gcr_certificate_widget_get_type ();
}

/**
 * gcr_certificate_details_widget_new: (skip)
 *
 * Deprecated: Since 2.30
 *
 * Returns: (transfer full) (type Gcr.CertificateWidget): a new certificate widget
 */
GcrCertificateDetailsWidget *
gcr_certificate_details_widget_new (GcrCertificate *cert)
{
	return gcr_certificate_widget_new (cert);
}

/**
 * gcr_certificate_details_widget_get_certificate: (skip)
 *
 * Deprecated: Since 2.30
 *
 * Returns: (transfer none): the certificate
 */
GcrCertificate*
gcr_certificate_details_widget_get_certificate (GcrCertificateDetailsWidget *details)
{
	return gcr_certificate_widget_get_certificate (details);
}

/**
 * gcr_certificate_details_widget_set_certificate: (skip)
 * @details: the certificate widget
 * @cert: the certificate
 *
 * Deprecated: Since 2.30
 */
void
gcr_certificate_details_widget_set_certificate (GcrCertificateDetailsWidget *details,
                                                GcrCertificate *cert)
{
	return gcr_certificate_widget_set_certificate (details, cert);
}

#endif /* GCR_DISABLE_DEPRECATED */
