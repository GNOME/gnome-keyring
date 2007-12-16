/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-cert.h - An x509 certificate

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef __GKR_PK_CERT_H__
#define __GKR_PK_CERT_H__

#include "pk/gkr-pk-object.h"

#include <libtasn1.h>

G_BEGIN_DECLS

#define GKR_TYPE_PK_CERT             (gkr_pk_cert_get_type())
#define GKR_PK_CERT(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GKR_TYPE_PK_CERT, GkrPkCert))
#define GKR_PK_CERT_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GKR_TYPE_PK_CERT, GkrPkObject))
#define GKR_IS_PK_CERT(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GKR_TYPE_PK_CERT))
#define GKR_IS_PK_CERT_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GKR_TYPE_PK_CERT))
#define GKR_PK_CERT_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), GKR_TYPE_PK_CERT, GkrPkCertClass))

typedef struct _GkrPkCert      GkrPkCert;
typedef struct _GkrPkCertClass GkrPkCertClass;
typedef struct _GkrPkCertData  GkrPkCertData;

struct _GkrPkCert {
	GkrPkObject parent;
	GkrPkCertData *data;
};

struct _GkrPkCertClass {
	GkrPkObjectClass parent_class;
};

GType               gkr_pk_cert_get_type           (void) G_GNUC_CONST;

GkrPkCert*          gkr_pk_cert_new                (GQuark location, ASN1_TYPE asn1);

guchar*             gkr_pk_cert_get_extension      (GkrPkCert *cert, GQuark oid, 
                                                    gsize *n_extension, gboolean *critical);

gkrconstunique      gkr_pk_cert_get_keyid          (GkrPkCert *cert);

G_END_DECLS

#endif /* __GKR_PK_CERT_H__ */
