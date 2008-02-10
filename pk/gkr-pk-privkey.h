/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-privkey.h - An PK private key

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

#ifndef __GKR_PK_PRIVKEY_H__
#define __GKR_PK_PRIVKEY_H__

#include "gkr-pk-object.h"
#include "gkr-pk-pubkey.h"

#include "common/gkr-id.h"

#include <gcrypt.h>

G_BEGIN_DECLS

#define GKR_TYPE_PK_PRIVKEY             (gkr_pk_privkey_get_type())
#define GKR_PK_PRIVKEY(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GKR_TYPE_PK_PRIVKEY, GkrPkPrivkey))
#define GKR_PK_PRIVKEY_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GKR_TYPE_PK_PRIVKEY, GkrPkPrivkey))
#define GKR_IS_PK_PRIVKEY(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GKR_TYPE_PK_PRIVKEY))
#define GKR_IS_PK_PRIVKEY_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GKR_TYPE_PK_PRIVKEY))
#define GKR_PK_PRIVKEY_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), GKR_TYPE_PK_PRIVKEY, GkrPkPrivKeyClass))

typedef struct _GkrPkPrivkey      GkrPkPrivkey;
typedef struct _GkrPkPrivkeyClass GkrPkPrivkeyClass;
typedef struct _GkrPkPrivkeyData  GkrPkPrivkeyData;

struct _GkrPkPrivkey {
	 GkrPkObject parent;
	 GkrPkPrivkeyData *priv;
};

struct _GkrPkPrivkeyClass {
	GkrPkObjectClass parent_class;
};

GType               gkr_pk_privkey_get_type           (void) G_GNUC_CONST;

GkrPkObject*        gkr_pk_privkey_new                (GkrPkObjectManager *mgr, 
                                                       GQuark location, gcry_sexp_t skey);

CK_RV               gkr_pk_privkey_create             (GkrPkObjectManager* manager, 
                                                       GArray* array, GkrPkObject **object);
                                                       
gkrconstid      gkr_pk_privkey_get_keyid          (GkrPkPrivkey *pkey);

gkrid               gkr_pk_privkey_make_keyid         (gcry_sexp_t skey);

gcry_sexp_t         gkr_pk_privkey_get_key            (GkrPkPrivkey *pkey);

int                 gkr_pk_privkey_get_algorithm      (GkrPkPrivkey *key);

GkrPkPubkey*        gkr_pk_privkey_get_public         (GkrPkPrivkey *key);

G_END_DECLS

#endif /* __GKR_PK_PRIVKEY_H__ */
