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

#ifndef __GCK_ROOTS_CERTIFICATE_H__
#define __GCK_ROOTS_CERTIFICATE_H__

#include <glib-object.h>

#include "gck/gck-certificate.h"

#define GCK_TYPE_ROOTS_CERTIFICATE               (gck_roots_certificate_get_type ())
#define GCK_ROOTS_CERTIFICATE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_ROOTS_CERTIFICATE, GckRootsCertificate))
#define GCK_ROOTS_CERTIFICATE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_ROOTS_CERTIFICATE, GckRootsCertificateClass))
#define GCK_IS_ROOTS_CERTIFICATE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_ROOTS_CERTIFICATE))
#define GCK_IS_ROOTS_CERTIFICATE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_ROOTS_CERTIFICATE))
#define GCK_ROOTS_CERTIFICATE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_ROOTS_CERTIFICATE, GckRootsCertificateClass))

typedef struct _GckRootsCertificate GckRootsCertificate;
typedef struct _GckRootsCertificateClass GckRootsCertificateClass;
    
struct _GckRootsCertificateClass {
	GckCertificateClass parent_class;
};

GType                 gck_roots_certificate_get_type               (void);

GckRootsCertificate*  gck_roots_certificate_new                    (GckModule *module,
                                                                    const gchar *hash, 
                                                                    const gchar *path);

const gchar*          gck_roots_certificate_get_unique             (GckRootsCertificate *self);

const gchar*          gck_roots_certificate_get_path               (GckRootsCertificate *self);

GckCertificateTrust*  gck_roots_certificate_get_netscape_trust     (GckRootsCertificate *self);

#endif /* __GCK_ROOTS_CERTIFICATE_H__ */
