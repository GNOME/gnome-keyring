/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-object-storage.c - Store general 'token' PK objects

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

#include "config.h"

#include "gkr-pk-cert.h"
#include "gkr-pk-index.h"
#include "gkr-pk-object-manager.h"
#include "gkr-pk-object-storage.h"
#include "gkr-pk-places.h"
#include "gkr-pk-privkey.h"
#include "gkr-pk-util.h"

#include "common/gkr-location.h"
#include "common/gkr-location-watch.h"

#include "pkcs11/pkcs11.h"

#include "pkix/gkr-pkix-parser.h"
#include "pkix/gkr-pkix-serialize.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <stdarg.h>

typedef struct _GkrPkObjectStoragePrivate GkrPkObjectStoragePrivate;

#define RELATIVE_DIRECTORY  "keystore" 
#define UNWANTED_FILENAME_CHARS  ":/\\<>|\t\n\r\v"

struct _GkrPkObjectStoragePrivate {
	GHashTable *specific_load_requests;
	GHashTable *denied_import_requests;
	GkrLocationWatch *watch;
};

#define GKR_PK_OBJECT_STORAGE_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PK_OBJECT_STORAGE, GkrPkObjectStoragePrivate))

G_DEFINE_TYPE(GkrPkObjectStorage, gkr_pk_object_storage, GKR_TYPE_PK_STORAGE);

typedef struct {
	GkrPkObjectStorage *storage;       /* The object storage to parse into */
	GQuark location;                   /* The location being parsed */
	GHashTable *checks;                /* The set of objects that existed before parse */
} ParseContext;


#define NO_VALUE GUINT_TO_POINTER (TRUE)

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static GQuark
location_for_storing (GkrPkObjectStorage *storage, GkrPkObject *obj, GQuark type)
{
	const gchar *label;
	const gchar *ext;
	gchar *filename;
	GQuark loc;
	
	/* A good extension */
	ext = gkr_pkix_serialize_get_extension (type);
	if (!ext) 
		ext = "pk";
	
	/* Come up with a good relative name for the object */
	label = gkr_pk_object_get_label (obj);
	filename = g_strconcat (RELATIVE_DIRECTORY, G_DIR_SEPARATOR_S, label, ".", ext, NULL);
	g_strdelimit (filename, UNWANTED_FILENAME_CHARS, '_');
	
	loc = gkr_location_from_child (GKR_LOCATION_VOLUME_LOCAL, filename);
	g_free (filename);
	
	return loc;
}

static gboolean
parser_ask_password (GkrPkixParser *parser, GQuark loc, gkrconstid digest, 
                     GQuark type, const gchar *label, gint *state, gchar **password,
                     gpointer user_data)
{
 	ParseContext *ctx = (ParseContext*)user_data;
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (ctx->storage);
	gboolean ret;
	
	g_return_val_if_fail (loc == ctx->location, FALSE);

	/* 
	 * If the user isn't specifically requesting this object, then we don't 
	 * necessarily prompt for a password. 
	 */
	if (!g_hash_table_lookup (pv->specific_load_requests, digest)) {
		
		/* If the user specifically denied this earlier, then don't prompt */
		if (g_hash_table_lookup (pv->denied_import_requests, digest)) {
			*password = NULL;
			return FALSE;
		}
	}

	/* TODO: Work out how imports work, add to denied import requests if necessary */
	
	ret = gkr_pk_storage_get_load_password (GKR_PK_STORAGE (ctx->storage), loc, digest, 
	                                        type, label, state, password);

	return ret;
}

static GkrPkObject*
prepare_object (GkrPkObjectStorage *storage, GQuark location, 
                gkrconstid digest, GQuark type)
{
	GkrPkObjectManager *manager;
	GkrPkObject *object;
	GType gtype;
	
	manager = gkr_pk_object_manager_for_token ();
	object = gkr_pk_object_manager_find_by_digest (manager, digest);
	
	/* The object already exists just reference it */
	if (object) {
		gkr_pk_storage_add_object (GKR_PK_STORAGE (storage), object);
		return object;
	} 
	
	if (type == GKR_PKIX_PRIVATE_KEY) 
		gtype = GKR_TYPE_PK_PRIVKEY;
	else if (type == GKR_PKIX_PUBLIC_KEY) 
		gtype = GKR_TYPE_PK_PUBKEY;
	else if (type == GKR_PKIX_CERTIFICATE)
		gtype = GKR_TYPE_PK_CERT;
	else 
		g_return_val_if_reached (NULL);
	
	object = g_object_new (gtype, "manager", manager, "location", location, 
	                       "digest", digest, NULL);
	gkr_pk_storage_add_object (GKR_PK_STORAGE (storage), object);

	/* Object was reffed */
	g_object_unref (object);
	return object;
}

static gboolean 
parser_parsed_partial (GkrPkixParser *parser, GQuark location, gkrid digest,
                       GQuark type, ParseContext *ctx)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (ctx->storage);
 	GkrPkObject *object;

 	/* TODO: What do we do if we don't know the type? */
	if (!type)
		return FALSE;
	
 	object = prepare_object (ctx->storage, location, digest, type);
	g_return_val_if_fail (object != NULL, FALSE);
 	
	/* Make note of having seen this object in load requests */
	g_hash_table_remove (pv->specific_load_requests, digest);

	/* Make note of having seen this one */
	gkr_pk_storage_checks_mark (ctx->checks, object);
	
	return TRUE;
}

static gboolean
parser_parsed_sexp (GkrPkixParser *parser, GQuark location, gkrid digest,
	                GQuark type, gcry_sexp_t sexp, ParseContext *ctx)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (ctx->storage);
 	GkrPkObject *object;
 	
 	g_return_val_if_fail (type != 0, FALSE);
 	
 	object = prepare_object (ctx->storage, location, digest, type);
 	g_return_val_if_fail (object != NULL, FALSE);
	
	/* Make note of having seen this object in load requests */
	g_hash_table_remove (pv->specific_load_requests, digest);
	
	/* Make note of having seen this one */
	g_hash_table_remove (ctx->checks, object);
		
	/* Make note of having seen this one */
	gkr_pk_storage_checks_mark (ctx->checks, object);
	
	/* TODO: Work how imports work */
	return TRUE;
}

static gboolean
parser_parsed_asn1 (GkrPkixParser *parser, GQuark location, gkrconstid digest, 
                    GQuark type, ASN1_TYPE asn1, ParseContext *ctx)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (ctx->storage);
	GkrPkObject *object;
	
 	g_return_val_if_fail (type != 0, FALSE);
 	
	object = prepare_object (ctx->storage, location, digest, type);
	g_return_val_if_fail (object != NULL, FALSE);

	/* Make note of having seen this object in load requests */
	g_hash_table_remove (pv->specific_load_requests, digest);
	
	/* Make note of having seen this one */
	g_hash_table_remove (ctx->checks, object);
	
	/* Setup the asn1, probably a certificate on this object */
	g_object_set (object, "asn1-tree", asn1, NULL); 
	
	/* TODO: Work out how imports work */
	return TRUE;
}

static gboolean
load_objects_at_location (GkrPkObjectStorage *storage, GQuark loc, GError **err)
{
 	GkrPkixParser *parser;
 	gboolean ret;
	ParseContext ctx;
	
	g_return_val_if_fail (loc != 0, FALSE);

	ctx.location = loc;
	ctx.storage = storage;
	ctx.checks = gkr_pk_storage_checks_prepare (GKR_PK_STORAGE (storage), loc);

	/* TODO: Try and use a shared parser? */
	parser = gkr_pkix_parser_new ();
	g_signal_connect (parser, "parsed-asn1", G_CALLBACK (parser_parsed_asn1), &ctx);
	g_signal_connect (parser, "parsed-sexp", G_CALLBACK (parser_parsed_sexp), &ctx);
	g_signal_connect (parser, "parsed-partial", G_CALLBACK (parser_parsed_partial), &ctx);
 	g_signal_connect (parser, "ask-password", G_CALLBACK (parser_ask_password), &ctx);

	ret = gkr_pkix_parser_parse_location (parser, loc, err);
	g_object_unref (parser);

	/* Remove any still in checks array */
	gkr_pk_storage_checks_purge (GKR_PK_STORAGE (storage), ctx.checks);

	return ret;
}

static void
location_load (GkrLocationWatch *watch, GQuark loc, GkrPkObjectStorage *storage)
{
	GError *err = NULL;
	
	if (!load_objects_at_location (storage, loc, &err)) {
		g_message ("couldn't parse data: %s: %s", g_quark_to_string (loc),
		           err && err->message ? err->message : "");
		g_error_free (err);
	}
}

static void
location_remove (GkrLocationWatch *watch, GQuark loc, GkrPkObjectStorage *storage)
{
	gkr_pk_storage_clr_objects (GKR_PK_STORAGE (storage), loc);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_object_storage_init (GkrPkObjectStorage *storage)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
 	
	pv->specific_load_requests = g_hash_table_new_full (gkr_id_hash, gkr_id_equals, gkr_id_free, NULL);
	pv->denied_import_requests = g_hash_table_new_full (gkr_id_hash, gkr_id_equals, gkr_id_free, NULL);
	
	/* The main key and certificate storage */
	pv->watch = gkr_location_watch_new (NULL, 0, RELATIVE_DIRECTORY, "*", "*.keystore");
	
	g_signal_connect (pv->watch, "location-added", G_CALLBACK (location_load), storage);
	g_signal_connect (pv->watch, "location-changed", G_CALLBACK (location_load), storage);
	g_signal_connect (pv->watch, "location-removed", G_CALLBACK (location_remove), storage);
}

static void
gkr_pk_object_storage_refresh (GkrPkStorage *storage)
{
	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
	gkr_location_watch_refresh (pv->watch, FALSE);
}

static gboolean
gkr_pk_object_storage_load (GkrPkStorage *storage, GkrPkObject *obj, GError **err)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
	gboolean ret = FALSE;
	
	g_return_val_if_fail (obj, FALSE);
	
	g_object_ref (obj);
	
	/* We need to have this object */
	if (!obj->location) {
		g_set_error (err, GKR_PK_STORAGE_ERROR, 0, "The object doesn't reside on disk");
		goto done;
	}

	/* Make note of the specific load request */
	g_hash_table_replace (pv->specific_load_requests, gkr_id_dup (obj->digest), NO_VALUE); 
	ret = load_objects_at_location (GKR_PK_OBJECT_STORAGE (storage), obj->location, err);

	if (!ret) 
		goto done;
	 
	/* See if it was seen */
	if (g_hash_table_lookup (pv->specific_load_requests, obj->digest)) {
		g_set_error (err, GKR_PK_STORAGE_ERROR, 0, "The object was not found at: %s",
		             g_quark_to_string (obj->location));
		goto done;
	}
	
	ret = TRUE;

done:
	g_hash_table_remove (pv->specific_load_requests, obj->digest);
	g_object_unref (obj);
	return ret;
}

static gboolean
gkr_pk_object_storage_store (GkrPkStorage *stor, GkrPkObject *obj, GError **err)
{
	GkrPkObjectStorage *storage;
	gpointer what;
	gchar *password;
	gkrid digest;
	gboolean ret;
	GQuark loc, type;
	GType gtype;
	guchar *data;
	gsize n_data;

	g_return_val_if_fail (!err || !*err, FALSE);
	g_return_val_if_fail (GKR_IS_PK_STORAGE (stor), FALSE);
	g_return_val_if_fail (obj->storage == NULL, FALSE);
	g_return_val_if_fail (obj->location == 0, FALSE);

	storage = GKR_PK_OBJECT_STORAGE (stor);

	/* What are we dealing with? */
	gtype = G_OBJECT_TYPE (obj);
	if (gtype == GKR_TYPE_PK_PRIVKEY) {
		type = GKR_PKIX_PRIVATE_KEY;
		g_object_get (obj, "gcrypt-sexp", &what, NULL);
	} else if (gtype == GKR_PKIX_PUBLIC_KEY) {
		type = GKR_TYPE_PK_PUBKEY;
		g_object_get (obj, "gcrypt-sexp", &what, NULL);
	} else if (gtype == GKR_PKIX_CERTIFICATE) {
		type = GKR_TYPE_PK_CERT;
		g_object_get (obj, "asn1-tree", &what, NULL);
	} else {
		g_return_val_if_reached (FALSE);
	}
	
	g_return_val_if_fail (what != NULL, FALSE);

	/* Find a good location to store this key */
	loc = location_for_storing (storage, obj, type);
	g_return_val_if_fail (loc, FALSE);
	
	/* Get a password for this key, determines whether encrypted or not */
	ret = gkr_pk_storage_get_store_password (stor, loc, obj->digest, type, 
	                                         gkr_pk_object_get_label (obj), 
	                                         &password);
	
	/* Prompt for a password was denied */
	if (!ret)
		return TRUE;

	/* Store the object into memory */
	data = gkr_pkix_serialize_to_data (type, what, password, &n_data);
	g_return_val_if_fail (data, FALSE);
	
	/* A digest for this object */
	digest = gkr_id_new_digest (data, n_data);
	
	/* Store the data to a file */
	ret = gkr_location_write_file (loc, data, n_data, err);
	g_free (data);

	if (ret) {
		/* The object now has a (possibly new) location, and possibly new digest */
		g_object_set (obj, "location", loc, "storage", stor, "digest", digest, NULL);
	}
	
	gkr_id_free (digest);
	return ret;
}

static gboolean
gkr_pk_object_storage_remove (GkrPkStorage *storage, GkrPkObject *obj, 
                              GError **err)
{
	GSList* objs;
	guint num;
	
	g_return_val_if_fail (!err || !*err, FALSE);
	g_return_val_if_fail (GKR_IS_PK_OBJECT_STORAGE (storage), FALSE);
	g_return_val_if_fail (obj->storage == storage, FALSE);
	g_return_val_if_fail (obj->location, FALSE);
	
	objs = gkr_pk_storage_get_objects (storage, obj->location);
	num = g_slist_length (objs);
	g_slist_free (objs);
	
	/* Are there multiple objects at this location? */	
	if (g_slist_length (objs) > 1) {
		g_set_error (err, GKR_PK_STORAGE_ERROR, 0, 
		             _("Cannot delete '%s' because it is tied to other objects."),
		             gkr_pk_object_get_label (obj));
		
		return FALSE;
	}

	/* Delete the object itself */
	if (!gkr_location_delete_file (obj->location, err))
		return FALSE;

	return TRUE;
}

static void
gkr_pk_object_storage_dispose (GObject *obj)
{
	GkrPkObjectStorage *storage = GKR_PK_OBJECT_STORAGE (obj);
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (obj);
 	
 	g_hash_table_remove_all (pv->specific_load_requests);
 	g_hash_table_remove_all (pv->denied_import_requests);
 	
 	if (pv->watch) {
 		g_signal_handlers_disconnect_by_func (pv->watch, location_load, storage);
 		g_signal_handlers_disconnect_by_func (pv->watch, location_remove, storage);
 		g_object_unref (pv->watch);
 	 	pv->watch = NULL;
 	}
 	
	G_OBJECT_CLASS (gkr_pk_object_storage_parent_class)->dispose (obj);
}

static void
gkr_pk_object_storage_finalize (GObject *obj)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (obj);
 	
	g_hash_table_destroy (pv->specific_load_requests);
	g_hash_table_destroy (pv->denied_import_requests);

	g_assert (pv->watch == NULL);
	
	G_OBJECT_CLASS (gkr_pk_object_storage_parent_class)->finalize (obj);
}

static void
gkr_pk_object_storage_class_init (GkrPkObjectStorageClass *klass)
{
	GkrPkStorageClass *storage_class = GKR_PK_STORAGE_CLASS (klass);
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gkr_pk_object_storage_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->dispose = gkr_pk_object_storage_dispose;
	gobject_class->finalize = gkr_pk_object_storage_finalize;
	
	storage_class->load = gkr_pk_object_storage_load;
	storage_class->refresh = gkr_pk_object_storage_refresh;
	storage_class->store = gkr_pk_object_storage_store;
	storage_class->remove = gkr_pk_object_storage_remove;

	g_type_class_add_private (gobject_class, sizeof (GkrPkObjectStoragePrivate));
}

/* -------------------------------------------------------------------------------
 * PUBLIC
 */

gboolean
gkr_pk_object_storage_initialize (void)
{
	GkrPkStorage *storage;
	
	storage = g_object_new (GKR_TYPE_PK_OBJECT_STORAGE, NULL);
	gkr_pk_storage_register (storage, FALSE);
	g_object_unref (storage);
	
	return TRUE;
}
