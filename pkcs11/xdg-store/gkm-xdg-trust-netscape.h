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

#ifndef __GKM_XDG_TRUST_NETSCAPE_H__
#define __GKM_XDG_TRUST_NETSCAPE_H__

#include <glib-object.h>

#include "gkm/gkm-object.h"

#define GKM_XDG_TYPE_TRUST_NETSCAPE      (gkm_xdg_trust_netscape_get_type ())
#define GKM_XDG_TRUST_NETSCAPE(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKM_XDG_TYPE_TRUST_NETSCAPE, GkmXdgTrustNetscape))
#define GKM_XDG_TRUST_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKM_XDG_TYPE_TRUST_NETSCAPE, GkmXdgTrustNetscapeClass))
#define GKM_XDG_IS_TRUST(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKM_XDG_TYPE_TRUST_NETSCAPE))
#define GKM_XDG_IS_TRUST_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKM_XDG_TYPE_TRUST_NETSCAPE))
#define GKM_XDG_TRUST_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKM_XDG_TYPE_TRUST_NETSCAPE, GkmXdgTrustClass))

typedef struct _GkmXdgTrustNetscape GkmXdgTrustNetscape;
typedef struct _GkmXdgTrustNetscapeClass GkmXdgTrustNetscapeClass;
typedef struct _GkmXdgTrustNetscapePrivate GkmXdgTrustNetscapePrivate;

struct _GkmXdgTrustNetscape {
	GkmObject parent;
	GkmXdgTrustNetscapePrivate *pv;
};

struct _GkmXdgTrustNetscapeClass {
	GkmObjectClass parent_class;
};

GType                 gkm_xdg_trust_netscape_get_type                   (void);

void                  gkm_xdg_trust_netscape_add_assertion_for_sha1     (GModule *module,
                                                                         gpointer sha1_hash,
                                                                         gsize n_sha1_hash);

void                  gkm_xdg_trust_netscape_add_assertion_for_issuer   (GModule *module,
                                                                         gpointer sha1_hash,
                                                                         gsize n_sha1_hash);

#endif /* __GKM_XDG_TRUST_NETSCAPE_H__ */
