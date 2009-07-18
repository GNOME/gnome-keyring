/* 
 * gnome-trustring
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

#ifndef __GCK_CERTIFICATE_TRUST_H__
#define __GCK_CERTIFICATE_TRUST_H__

#include <glib-object.h>

#include "gck-object.h"
#include "gck-types.h"

#define GCK_TYPE_CERTIFICATE_TRUST               (gck_certificate_trust_get_type ())
#define GCK_CERTIFICATE_TRUST(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_CERTIFICATE_TRUST, GckCertificateTrust))
#define GCK_CERTIFICATE_TRUST_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_CERTIFICATE_TRUST, GckCertificateTrustClass))
#define GCK_IS_CERTIFICATE_TRUST(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_CERTIFICATE_TRUST))
#define GCK_IS_CERTIFICATE_TRUST_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_CERTIFICATE_TRUST))
#define GCK_CERTIFICATE_TRUST_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_CERTIFICATE_TRUST, GckCertificateTrustClass))

typedef struct _GckCertificateTrustClass GckCertificateTrustClass;
typedef struct _GckCertificateTrustPrivate GckCertificateTrustPrivate;
    
struct _GckCertificateTrust {
	GckObject parent;
	GckCertificateTrustPrivate *pv;
};

struct _GckCertificateTrustClass {
	GckObjectClass parent_class;
};

GType                 gck_certificate_trust_get_type               (void);

GckCertificateTrust*  gck_certificate_trust_new                    (GckModule *module,
                                                                    GckCertificate *cert);

GckCertificate*       gck_certificate_trust_get_certificate        (GckCertificateTrust *self);

#endif /* __GCK_CERTIFICATE_TRUST_H__ */
