/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-session-storage.c - Storage of session or temporary objects

   Copyright (C) 2008 Stefan Walter

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

#include "config.h"

#include "gkr-pk-cert.h"
#include "gkr-pk-manager.h"
#include "gkr-pk-session-storage.h"
#include "gkr-pk-util.h"

#include "egg/egg-buffer.h"
#include "common/gkr-location.h"
#include "common/gkr-location-watch.h"
#include "egg/egg-secure-memory.h"

#include "keyrings/gkr-keyring-login.h"

#include "pkcs11/pkcs11.h"

#include "pkix/gkr-pkix-asn1.h"
#include "pkix/gkr-pkix-der.h"
#include "pkix/gkr-pkix-openssl.h"
#include "pkix/gkr-pkix-pem.h"
#include "pkix/gkr-pkix-types.h"

#include "ui/gkr-ask-daemon.h"
#include "ui/gkr-ask-request.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <stdarg.h>

G_DEFINE_TYPE(GkrPkSessionStorage, gkr_pk_session_storage, GKR_TYPE_PK_STORAGE);

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_session_storage_init (GkrPkSessionStorage *storage)
{
	GkrKeyring *keyring = gkr_keyring_new ("pk-session", 0);
	storage->index = gkr_pk_index_new (keyring, NULL);
	g_object_unref (keyring);
}

static GkrPkIndex*
gkr_pk_session_storage_index (GkrPkStorage *storage, GQuark location)
{
	return GKR_PK_SESSION_STORAGE (storage)->index;
}

static void
gkr_pk_session_storage_finalize (GObject *obj)
{
 	GkrPkSessionStorage *storage = GKR_PK_SESSION_STORAGE (obj);

 	if (storage->index)
 		g_object_unref (storage->index);
 	storage->index = NULL;
	
	G_OBJECT_CLASS (gkr_pk_session_storage_parent_class)->finalize (obj);
}

static void
gkr_pk_session_storage_class_init (GkrPkSessionStorageClass *klass)
{
	GkrPkStorageClass *storage_class = GKR_PK_STORAGE_CLASS (klass);
	GObjectClass *gobject_class;
	
	gobject_class = (GObjectClass*)klass;
	gobject_class->finalize = gkr_pk_session_storage_finalize;

	storage_class->index = gkr_pk_session_storage_index;
	
	gkr_pk_session_storage_parent_class = g_type_class_peek_parent (klass);
}

/* -------------------------------------------------------------------------------
 * PUBLIC FUNCTIONS
 */

GkrPkSessionStorage*
gkr_pk_session_storage_new (void)
{
	return g_object_new (GKR_TYPE_PK_SESSION_STORAGE, NULL);
}
