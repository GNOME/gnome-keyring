/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
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
 */

#ifndef __GCK_CERTIFICATE_H__
#define __GCK_CERTIFICATE_H__

#include <glib-object.h>

#include "gck-object.h"
#include "gck-types.h"

#define GCK_FACTORY_CERTIFICATE            (gck_certificate_get_factory ())

#define GCK_TYPE_CERTIFICATE               (gck_certificate_get_type ())
#define GCK_CERTIFICATE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_CERTIFICATE, GckCertificate))
#define GCK_CERTIFICATE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_CERTIFICATE, GckCertificateClass))
#define GCK_IS_CERTIFICATE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_CERTIFICATE))
#define GCK_IS_CERTIFICATE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_CERTIFICATE))
#define GCK_CERTIFICATE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_CERTIFICATE, GckCertificateClass))

typedef struct _GckCertificateClass GckCertificateClass;
typedef struct _GckCertificatePrivate GckCertificatePrivate;
    
struct _GckCertificate {
	GckObject parent;
	GckCertificatePrivate *pv;
};

struct _GckCertificateClass {
	GckObjectClass parent_class;
};

GType                      gck_certificate_get_type               (void);

GckFactoryInfo*            gck_certificate_get_factory            (void);

gboolean                   gck_certificate_calc_category          (GckCertificate *self, 
                                                                   CK_ULONG* category);

GckCertificateKey*         gck_certificate_get_public_key         (GckCertificate *self);

const guchar*              gck_certificate_get_extension          (GckCertificate *self, 
                                                                   GQuark oid, 
                                                                   gsize *n_extension, 
                                                                   gboolean *critical);

const gchar*               gck_certificate_get_label              (GckCertificate *self);

void                       gck_certificate_set_label              (GckCertificate *self, 
                                                                   const gchar *label);

guchar*                    gck_certificate_hash                   (GckCertificate *self,
                                                                   int hash_algo,
                                                                   gsize *n_hash);


#endif /* __GCK_CERTIFICATE_H__ */
