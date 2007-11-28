/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-pubkey.h - An PK public key

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

#ifndef __GKR_PK_PUBKEY_H__
#define __GKR_PK_PUBKEY_H__

#include "gkr-pk-object.h"

#include "common/gkr-unique.h"

#include <gcrypt.h>

G_BEGIN_DECLS

#define GKR_TYPE_PK_PUBKEY             (gkr_pk_pubkey_get_type())
#define GKR_PK_PUBKEY(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GKR_TYPE_PK_PUBKEY, GkrPkPubkey))
#define GKR_PK_PUBKEY_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GKR_TYPE_PK_PUBKEY, GkrPkPubkey))
#define GKR_IS_PK_PUBKEY(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GKR_TYPE_PK_PUBKEY))
#define GKR_IS_PK_PUBKEY_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GKR_TYPE_PK_PUBKEY))
#define GKR_PK_PUBKEY_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), GKR_TYPE_PK_PUBKEY, GkrPkPubKeyClass))

typedef struct _GkrPkPubkey      GkrPkPubkey;
typedef struct _GkrPkPubkeyClass GkrPkPubkeyClass;
typedef struct _GkrPkPubkeyData  GkrPkPubkeyData;

struct _GkrPkPubkey {
	 GkrPkObject parent;
	 GkrPkPubkeyData *pub;
};

struct _GkrPkPubkeyClass {
	GkrPkObjectClass parent_class;
};

GType               gkr_pk_pubkey_get_type           (void) G_GNUC_CONST;

GkrPkObject*        gkr_pk_pubkey_new                (GQuark location, gcry_sexp_t s_key);

gkrconstunique      gkr_pk_pubkey_get_keyid          (GkrPkPubkey *key);

gcry_sexp_t         gkr_pk_pubkey_get_key            (GkrPkPubkey *key);

int                 gkr_pk_pubkey_get_algorithm      (GkrPkPubkey *key);

G_END_DECLS

#endif /* __GKR_PK_PUBKEY_H__ */
