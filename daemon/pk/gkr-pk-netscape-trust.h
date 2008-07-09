/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-netscape-trust.h - Combination of Trust and Usage for a Certificate

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

#ifndef __GKR_PK_NETSCAPE_TRUST_H__
#define __GKR_PK_NETSCAPE_TRUST_H__

#include "pk/gkr-pk-object.h"

#include <libtasn1.h>

G_BEGIN_DECLS

#define GKR_TYPE_PK_NETSCAPE_TRUST             (gkr_pk_netscape_trust_get_type())
#define GKR_PK_NETSCAPE_TRUST(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GKR_TYPE_PK_NETSCAPE_TRUST, GkrPkNetscapeTrust))
#define GKR_PK_NETSCAPE_TRUST_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GKR_TYPE_PK_NETSCAPE_TRUST, GkrPkObject))
#define GKR_IS_PK_NETSCAPE_TRUST(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GKR_TYPE_PK_NETSCAPE_TRUST))
#define GKR_IS_PK_NETSCAPE_TRUST_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GKR_TYPE_PK_NETSCAPE_TRUST))
#define GKR_PK_NETSCAPE_TRUST_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), GKR_TYPE_PK_NETSCAPE_TRUST, GkrPkNetscapeTrustClass))

typedef struct _GkrPkNetscapeTrust      GkrPkNetscapeTrust;
typedef struct _GkrPkNetscapeTrustClass GkrPkNetscapeTrustClass;

struct _GkrPkNetscapeTrust {
	GkrPkObject parent;
	GkrPkCert *certificate;
};

struct _GkrPkNetscapeTrustClass {
	GkrPkObjectClass parent_class;
};

GType                     gkr_pk_netscape_trust_get_type           (void) G_GNUC_CONST;

GkrPkNetscapeTrust*       gkr_pk_netscape_trust_new                (GkrPkManager* mgr, GkrPkCert *cert);

G_END_DECLS

#endif /* __GKR_PK_NETSCAPE_TRUST_H__ */
