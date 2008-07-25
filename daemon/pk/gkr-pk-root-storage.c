/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-root-storage.c - Storage of Trusted Root CAs

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
#include "gkr-pk-root-storage.h"
#include "gkr-pk-util.h"

#include "common/gkr-buffer.h"
#include "common/gkr-location.h"
#include "common/gkr-location-watch.h"
#include "common/gkr-secure-memory.h"

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

typedef struct _GkrPkRootStoragePrivate GkrPkRootStoragePrivate;

struct _GkrPkRootStoragePrivate {
	gkrid specific_load_request;
	GkrLocationWatch *watch;
	GkrPkIndex *index;
};

#define GKR_PK_ROOT_STORAGE_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PK_ROOT_STORAGE, GkrPkRootStoragePrivate))

G_DEFINE_TYPE(GkrPkRootStorage, gkr_pk_root_storage, GKR_TYPE_PK_STORAGE);

typedef struct {
	GkrPkRootStorage *storage;         /* The object storage to parse into */
	GHashTable *checks;                /* The set of objects that existed before parse */
} ParseContext;

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static GkrPkObject*
prepare_object (GkrPkRootStorage *storage, GQuark location, gkrconstid digest)
{
	GkrPkManager *manager;
	GkrPkObject *object;
	
	manager = gkr_pk_manager_for_token ();
	object = gkr_pk_manager_find_by_digest (manager, digest);
	
	/* The object already exists just reference it */
	if (object) {
		gkr_pk_storage_add_object (GKR_PK_STORAGE (storage), object);
		return object;
	} 
	
	object = g_object_new (GKR_TYPE_PK_CERT, "manager", manager, "location", location, 
	                       "digest", digest, NULL);
	gkr_pk_storage_add_object (GKR_PK_STORAGE (storage), object);

	/* Object was reffed */
	g_object_unref (object);
	return object;
}

static gboolean
parser_parsed_asn1 (GkrPkixParser *parser, GQuark location, gkrconstid digest, 
                    GQuark type, ASN1_TYPE asn1, ParseContext *ctx)
{
 	GkrPkRootStoragePrivate *pv = GKR_PK_ROOT_STORAGE_GET_PRIVATE (ctx->storage);
	GkrPkObject *object;
	
 	g_return_val_if_fail (type != 0, FALSE);
 	
 	/* We only handle certificates */
 	if (type != GKR_PKIX_CERTIFICATE)
 		return FALSE;
 	
	object = prepare_object (ctx->storage, location, digest);
	g_return_val_if_fail (object != NULL, FALSE);

	/* Make note of having seen this object in load requests */
	if (gkr_id_equals (pv->specific_load_request, digest))
		pv->specific_load_request = NULL;
	
	/* Make note of having seen this one */
	gkr_pk_storage_checks_mark (ctx->checks, object);
	
	/* Setup the asn1, probably a certificate on this object */
	g_object_set (object, "asn1-tree", asn1, NULL); 
	
	return TRUE;
}

static gboolean
storage_load_certificate (GkrPkRootStorage *storage, GQuark loc, GError **err)
{
 	GkrPkixParser *parser;
 	GkrPkixResult ret;
	ParseContext ctx;
	
	g_return_val_if_fail (loc != 0, FALSE);

	ctx.storage = storage;

	/* Create a table of what is at the location */
	ctx.checks = gkr_pk_storage_checks_prepare (GKR_PK_STORAGE (storage), loc);

	/* TODO: Try and use a shared parser? */
	parser = gkr_pkix_parser_new ();
	g_signal_connect (parser, "parsed-asn1", G_CALLBACK (parser_parsed_asn1), &ctx);
	ret = gkr_pkix_parser_parse_location (parser, loc, err);
	g_object_unref (parser);

	/* Remove any still in checks array */
	gkr_pk_storage_checks_purge (GKR_PK_STORAGE (storage), ctx.checks);
	
	return ret;
}

static void
location_load (GkrLocationWatch *watch, GQuark loc, GkrPkRootStorage *storage)
{
	GError *err = NULL;

	/* We only get notified for private keys */
	if (!storage_load_certificate (storage, loc, &err)) {
		g_message ("couldn't load certificate data: %s: %s", g_quark_to_string (loc),
		           err && err->message ? err->message : "");
		g_error_free (err);
	}
}

static void
location_remove (GkrLocationWatch *watch, GQuark loc, GkrPkRootStorage *storage)
{
 	gkr_pk_storage_clr_objects (GKR_PK_STORAGE (storage), loc);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void 
gkr_pk_root_storage_refresh (GkrPkStorage *storage)
{
 	GkrPkRootStoragePrivate *pv = GKR_PK_ROOT_STORAGE_GET_PRIVATE (storage);
 	gkr_location_watch_refresh (pv->watch, FALSE);
}

static gboolean 
gkr_pk_root_storage_load (GkrPkStorage *storage, GkrPkObject *obj, GError **err)
{
	GkrPkRootStoragePrivate *pv = GKR_PK_ROOT_STORAGE_GET_PRIVATE (storage);
	gboolean ret = TRUE;
		
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (obj->storage == storage, FALSE);
	g_return_val_if_fail (obj->location, FALSE);
	g_return_val_if_fail (pv->specific_load_request == NULL, FALSE);

	g_object_ref (obj);
	
	/* Make note of the specific load request */
	pv->specific_load_request = obj->digest;
	
	/* Perform the actual load */
	location_load (pv->watch, obj->location, GKR_PK_ROOT_STORAGE (storage));
	
	/* See if it was seen */
	if (pv->specific_load_request != NULL) {
		g_set_error (err, GKR_PKIX_PARSE_ERROR, 0, "The object was not found at: %s",
		             g_quark_to_string (obj->location));
		pv->specific_load_request = NULL;
		ret = FALSE;
	}
		
	g_object_unref (obj);
	return ret;
}

static GkrPkIndex* 
gkr_pk_root_storage_index (GkrPkStorage *storage, GQuark unused)
{
 	GkrPkRootStoragePrivate *pv = GKR_PK_ROOT_STORAGE_GET_PRIVATE (storage);
 	GnomeKeyringAttributeList *attrs;
	
	if (!pv->index) {

		/* Default attributes for our index */
		attrs = gnome_keyring_attribute_list_new ();
		gnome_keyring_attribute_list_append_string (attrs, "user-trust", "trusted");

		pv->index = gkr_pk_index_open_login (attrs);
		if (!pv->index)
			pv->index = gkr_pk_index_open_session (attrs);
			
		gnome_keyring_attribute_list_free (attrs);
	}
	
	return pv->index;
}

static void
gkr_pk_root_storage_init (GkrPkRootStorage *storage)
{
 	GkrPkRootStoragePrivate *pv = GKR_PK_ROOT_STORAGE_GET_PRIVATE (storage);
 	
	pv->specific_load_request = NULL;
	
	/* The root certificates directory, mark as trusted anchors */
	pv->watch = gkr_location_watch_new (NULL, GKR_LOCATION_VOLUME_FILE, ROOT_CERTIFICATES, "*", "*.0");
	g_return_if_fail (pv->watch); 

	g_signal_connect (pv->watch, "location-added", G_CALLBACK (location_load), storage);
	g_signal_connect (pv->watch, "location-changed", G_CALLBACK (location_load), storage);
	g_signal_connect (pv->watch, "location-removed", G_CALLBACK (location_remove), storage);
}

static void
gkr_pk_root_storage_dispose (GObject *obj)
{
	GkrPkRootStorage *storage = GKR_PK_ROOT_STORAGE (obj);
 	GkrPkRootStoragePrivate *pv = GKR_PK_ROOT_STORAGE_GET_PRIVATE (obj);
 	
	if (pv->index)
		g_object_unref (pv->index);
	pv->index = NULL;

	g_signal_handlers_disconnect_by_func (pv->watch, location_load, storage);
	g_signal_handlers_disconnect_by_func (pv->watch, location_remove, storage);
 	
	G_OBJECT_CLASS (gkr_pk_root_storage_parent_class)->dispose (obj);
}

static void
gkr_pk_root_storage_finalize (GObject *obj)
{
 	GkrPkRootStoragePrivate *pv = GKR_PK_ROOT_STORAGE_GET_PRIVATE (obj);
 	
	g_object_unref (pv->watch);
 	pv->watch = NULL;
	
	G_OBJECT_CLASS (gkr_pk_root_storage_parent_class)->finalize (obj);
}

static void
gkr_pk_root_storage_class_init (GkrPkRootStorageClass *klass)
{
	GkrPkStorageClass *storage_class = GKR_PK_STORAGE_CLASS (klass);
	GObjectClass *gobject_class;
	
	gobject_class = (GObjectClass*)klass;
	gobject_class->dispose = gkr_pk_root_storage_dispose;
	gobject_class->finalize = gkr_pk_root_storage_finalize;

	storage_class->refresh = gkr_pk_root_storage_refresh;
	storage_class->load = gkr_pk_root_storage_load;
	storage_class->index = gkr_pk_root_storage_index;
	
	gkr_pk_root_storage_parent_class = g_type_class_peek_parent (klass);

	g_type_class_add_private (gobject_class, sizeof (GkrPkRootStoragePrivate));
}

/* -------------------------------------------------------------------------------
 * PUBLIC FUNCTIONS
 */

gboolean
gkr_pk_root_storage_initialize (void)
{
	GkrPkStorage *storage;
	
	storage = g_object_new (GKR_TYPE_PK_ROOT_STORAGE, NULL);
	gkr_pk_storage_register (storage, FALSE);
	g_object_unref (storage);
	
	return TRUE;
}
