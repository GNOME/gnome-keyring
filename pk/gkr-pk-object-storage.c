/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-object-storage.c - Manage all 'token' PK objects

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

#include "common/gkr-cleanup.h"
#include "common/gkr-location.h"
#include "common/gkr-location-watch.h"
#include "common/gkr-secure-memory.h"

#include "keyrings/gkr-keyring-login.h"

#include "pkcs11/pkcs11.h"

#include "pkix/gkr-pkix-parser.h"

#include "ui/gkr-ask-daemon.h"
#include "ui/gkr-ask-request.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <stdarg.h>

typedef struct _GkrPkObjectStoragePrivate GkrPkObjectStoragePrivate;

struct _GkrPkObjectStoragePrivate {
	GHashTable *objects;
	GHashTable *objects_by_location;
	GHashTable *specific_load_requests;
	GHashTable *denied_import_requests;

	GSList *watches;
};

#define GKR_PK_OBJECT_STORAGE_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PK_OBJECT_STORAGE, GkrPkObjectStoragePrivate))

G_DEFINE_TYPE(GkrPkObjectStorage, gkr_pk_object_storage, G_TYPE_OBJECT);

static GkrPkObjectStorage *object_storage_singleton = NULL; 

typedef struct {
	GkrPkObjectStorage *storage;       /* The object storage to parse into */
	GQuark location;                   /* The location being parsed */
	GHashTable *checks;                /* The set of objects that existed before parse */
	GHashTable *types_by_digest;       /* The parse types for every object prompted for or seen */ 
} ParseContext;

#define NO_VALUE GUINT_TO_POINTER (TRUE)

/* -----------------------------------------------------------------------------
 * HELPERS
 */
 
static void 
cleanup_object_storage (void *unused)
{
	g_assert (object_storage_singleton);
	g_object_unref (object_storage_singleton);
	object_storage_singleton = NULL;
}

static const gchar*
prepare_ask_title (GQuark type)
{
	/*
	 * Yes this is unmaintainable and stupid, but is required 
	 * for translations to work properly.
	 */
	if (type == GKR_PKIX_PRIVATE_KEY)
		return _("Unlock private key");
	else if (type == GKR_PKIX_CERTIFICATE)
		return _("Unlock certificate");
	else if (type == GKR_PKIX_PUBLIC_KEY)
		return _("Unlock public key");
	else 
		return _("Unlock");
}

static const gchar*
prepare_ask_primary (GQuark type)
{
	/*
	 * Yes this is unmaintainable and stupid, but is required 
	 * for translations to work properly.
	 */
	if (type == GKR_PKIX_PRIVATE_KEY)
		return _("Enter password to unlock the private key");
	else if (type == GKR_PKIX_CERTIFICATE)
		return _("Enter password to unlock the certificate");
	else if (type == GKR_PKIX_PUBLIC_KEY)
		return _("Enter password to unlock the public key");
	else 
		return _("Enter password to unlock");
}

static const gchar*
prepare_ask_check (GQuark type)
{
	/*
	 * Yes this is unmaintainable and stupid, but is required 
	 * for translations to work properly.
	 */
	if (type == GKR_PKIX_PRIVATE_KEY)
		return _("Automatically unlock this private key when I log in.");
	else if (type == GKR_PKIX_CERTIFICATE)
		return _("Automatically unlock this certificate when I log in.");
	else if (type == GKR_PKIX_PUBLIC_KEY)
		return _("Automatically unlock this public key when I log in.");
	else 
		return _("Automatically unlock this when I log in");
}

static gchar*
prepare_ask_secondary (GQuark type, gboolean indexed, const gchar *label)
{
	/*
	 * Yes this is unmaintainable and stupid, but is required 
	 * for translations to work properly.
	 */

	/* When we've already indexed this data */
	if (indexed) {

		if (type == GKR_PKIX_PRIVATE_KEY)
			return g_strdup_printf (_("An application wants access to the private key '%s', but it is locked"), label);
		else if (type == GKR_PKIX_CERTIFICATE)
			return g_strdup_printf (_("An application wants access to the certificate '%s', but it is locked"), label);
		else if (type == GKR_PKIX_PUBLIC_KEY)
			return g_strdup_printf (_("An application wants access to the public key '%s', but it is locked"), label);
		else 
			return g_strdup_printf (_("An application wants access to '%s', but it is locked"), label);
	
	/* Never before seen this data */ 
	} else {

		if (type == GKR_PKIX_PRIVATE_KEY)
			return g_strdup_printf (_("The system wants to import the private key '%s', but it is locked"), label);
		else if (type == GKR_PKIX_CERTIFICATE)
			return g_strdup_printf (_("The system wants to import the certificate '%s', but it is locked"), label);
		else if (type == GKR_PKIX_PUBLIC_KEY)
			return g_strdup_printf (_("The system wants to import the public key '%s', but it is locked"), label);
		else 
			return g_strdup_printf (_("The system wants to import '%s', but it is locked"), label);
	}
}

static gchar* 
parser_ask_password (GkrPkixParser *parser, GQuark loc, gkrid digest, 
                     GQuark type, const gchar *label, guint failures,
                     ParseContext *ctx)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (ctx->storage);
	GkrAskRequest *ask;
	gchar *custom_label, *ret, *display_name, *stype, *secondary;
	const gchar *password;
	gboolean imported = FALSE;
	gboolean importing = FALSE;
	guint flags;
	
	g_return_val_if_fail (loc == ctx->location, NULL);
	
	/*
	 * The password prompting is somewhat convoluted with the end goal of 
	 * not prompting the user more than necessary. 
	 * 
	 *  - Check and see if we have a password on record for this.
	 *  - Don't prompt unless the user is specifically requesting 
	 *    this object *or* we've never seen it before. 
	 *  - Make note of everything we've prompted for so that later 
	 *    we can note having seen it.
	 */ 
	
	/* See if we can find a valid password for this location */
	if (failures == 0) {
		password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD,
		                                            "pk-object", gkr_location_to_string (loc), NULL);
		if (password != NULL)
			return gkr_secure_strdup (password);
	} else {
		gkr_keyring_login_remove_secret (GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD,
		                                 "pk-object", gkr_location_to_string (loc), NULL); 
	}

	/*
	 * If we've parsed this before, then we can lookup in our index as to what 
	 * exactly this is we're talking about here.  
	 */
	stype = gkr_pk_index_get_string_full (loc, digest, "parsed-type");
	if (stype) {
		if (!type && stype[0])
			type = g_quark_from_string (stype);
		g_free (stype);
	}
	
	/* This is how we know if we've imported this object before */
	imported = gkr_pk_index_get_boolean_full (loc, digest, "imported", FALSE);

	/* 
	 * If the user isn't specifically requeting this object, then we don't 
	 * necessarily prompt for a password. 
	 */
	if (!g_hash_table_lookup (pv->specific_load_requests, digest)) {
		
		/* If the user specifically denied this earlier, then don't prompt */
		if (g_hash_table_lookup (pv->denied_import_requests, digest))
			return NULL;
		
		/* If this has been imported already, then don't prompt */
		if (imported)
			return NULL;
		
		importing = TRUE;
	}

	/* TODO: Load a better label if we have one */
	custom_label = NULL;
	
	if (custom_label != NULL)
		label = custom_label;
	
	/* Build up the prompt */
	if (importing)
		flags = GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_OK_CANCEL_BUTTONS;
	else
		flags = GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_OK_DENY_BUTTONS;
	ask = gkr_ask_request_new (prepare_ask_title (type), prepare_ask_primary (type), flags);

	secondary = prepare_ask_secondary (type, !importing, label); 
	gkr_ask_request_set_secondary (ask, secondary);
	g_free (secondary);

	gkr_ask_request_set_location (ask, loc);
		
	if (gkr_keyring_login_is_usable ())
		gkr_ask_request_set_check_option (ask, prepare_ask_check (type));
	
	/* Prompt the user */
	gkr_ask_daemon_process (ask);

	/* If the user denied ... */
	if (ask->response == GKR_ASK_RESPONSE_DENY) {
		
		/* If we were importing then don't try again */
		if (importing)
			g_hash_table_insert (pv->denied_import_requests, 
			                     gkr_id_dup (digest), NO_VALUE);
		
		ret = NULL;
	
	/* User cancelled or failure */
	} else if (ask->response < GKR_ASK_RESPONSE_ALLOW) {
		
		ret = NULL;
		
	/* Successful response */
	} else {
		ret = gkr_secure_strdup (ask->typed_password);
		if (ask->checked) {
			display_name =  g_strdup_printf (_("Unlock password for '%s'"), label);
			gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD,
			                                 display_name, ret,
			                                 "pk-object", gkr_location_to_string (loc), NULL);
		} 
		
		/* Track that we prompted for this */
		g_hash_table_insert (ctx->types_by_digest, gkr_id_dup (digest), 
		                     GUINT_TO_POINTER (type));
	}	
		
	g_free (custom_label);
	return ret;
}

static void
add_object_to_multihash (GHashTable *table, gpointer key, GkrPkObject *object)
{
	GArray *objs = (GArray*)g_hash_table_lookup (table, key);
		
	/* Add automatically if first at location */
	if (!objs) {
		objs = g_array_new (FALSE, TRUE, sizeof (GkrPkObject*));
		g_hash_table_replace (table, key, objs);
	}
		
	g_array_append_val (objs, object);
}

static gboolean
remove_object_from_multihash (GHashTable *table, gconstpointer key, GkrPkObject *object)
{
	GArray *objs;
	guint i; 
	
	objs = (GArray*)g_hash_table_lookup (table, key);
	if (!objs)
		return FALSE;
		
	for (i = 0; i < objs->len; ++i) {
		if (g_array_index (objs, GkrPkObject*, i) == object)
			break;
	}

	/* Not found */
	if (i == objs->len)
		return FALSE;	

	g_array_remove_index_fast (objs, i);
		
	/* Remove automatically if last one */
	if (objs->len == 0)
		g_hash_table_remove (table, key);
		
	return TRUE;
}

static void
add_object (GkrPkObjectStorage *storage, GkrPkObject *object)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
	gpointer k;
	
	g_assert (object);
	g_assert (GKR_IS_PK_OBJECT (object));
	g_assert (object->location);
	g_assert (!g_hash_table_lookup (pv->objects, object));
		
	/* Mapping of location to the index key */
	k = GUINT_TO_POINTER (object->location);
	add_object_to_multihash (pv->objects_by_location, k, object); 

	if (!object->storage)
		object->storage = storage;
	
	/* Take ownership of the object */
	g_object_ref (object);
	g_hash_table_insert (pv->objects, object, NO_VALUE);
}

static void
remove_object (GkrPkObjectStorage *storage, GkrPkObject *object)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
	gpointer k;

	g_assert (object);
	g_assert (GKR_IS_PK_OBJECT (object));
	g_assert (object->location);
	g_assert (g_hash_table_lookup (pv->objects, object));
		
	/* Mapping of location to the object */
	k = GUINT_TO_POINTER (object->location);
	if (!remove_object_from_multihash (pv->objects_by_location, k, object))
		g_assert (FALSE);

	if (object->storage == storage)
		object->storage = NULL;

	/* Release ownership */
	if (!g_hash_table_remove (pv->objects, object))
		g_assert (FALSE);
}

static GkrPkObject*
prepare_object (GkrPkObjectStorage *storage, GQuark location, 
                gkrconstid digest, GQuark type)
{
	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
	GkrPkObjectManager *manager;
	GkrPkObject *object;
	GType gtype;
	
	manager = gkr_pk_object_manager_for_token ();
	object = gkr_pk_object_manager_find_by_digest (manager, digest);
	
	/* The object already exists just reference it */
	if (object) {
		if (!g_hash_table_lookup (pv->objects, object))
			add_object (storage, object);
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
	add_object (storage, object);

	/* Object was reffed */
	g_object_unref (object);
	
	return object;
}

static void 
parser_parsed_partial (GkrPkixParser *parser, GQuark location, gkrid digest,
                       GQuark type, ParseContext *ctx)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (ctx->storage);
 	GkrPkObject *object;
 	gchar *stype;
 	
	/* If we don't know the type then look it up */
	if (!type) {
		stype = gkr_pk_index_get_string_full (location, digest, "parsed-type");
		if (stype && stype[0])
			type = g_quark_from_string (stype);
		g_free (stype);
	}
	
	if (type) { 
	 	object = prepare_object (ctx->storage, location, digest, type);
 		g_return_if_fail (object != NULL);
 	
		/* Make note of having seen this object in load requests */
		g_hash_table_remove (pv->specific_load_requests, digest);

		/* Make note of having seen this one */
		g_hash_table_remove (ctx->checks, object);
	}
	
	/* Track the type of this digest */
	g_hash_table_insert (ctx->types_by_digest, gkr_id_dup (digest), 
		                 GUINT_TO_POINTER (type));
}

static void
parser_parsed_sexp (GkrPkixParser *parser, GQuark location, gkrid digest,
	                GQuark type, gcry_sexp_t sexp, ParseContext *ctx)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (ctx->storage);
 	GkrPkObject *object;
 	
 	g_return_if_fail (type != 0);
 	
 	object = prepare_object (ctx->storage, location, digest, type);
 	g_return_if_fail (object != NULL);
	
	/* Make note of having seen this object in load requests */
	g_hash_table_remove (pv->specific_load_requests, digest);
	
	/* Make note of having seen this one */
	g_hash_table_remove (ctx->checks, object);
		
	/* Track the type of this digest */
	g_hash_table_insert (ctx->types_by_digest, gkr_id_dup (digest),
		                 GUINT_TO_POINTER (type));
	
	/* Setup the sexp, probably a key on this object */
	g_object_set (object, "gcrypt-sexp", sexp, NULL);
	
	/*
	 * Now we have the object loaded and everything, and since it's a fully
	 * loaded (if encrypted a password has been provided), take the 
	 * opportunity to 'import' it and make sure we have all necessary data
	 * on it.
	 */
	if (!gkr_pk_index_get_boolean (object, "imported", FALSE))
		gkr_pk_object_import (object);
}

static void
parser_parsed_asn1 (GkrPkixParser *parser, GQuark location, gkrconstid digest, 
                    GQuark type, ASN1_TYPE asn1, ParseContext *ctx)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (ctx->storage);
	GkrPkObject *object;
	
 	g_return_if_fail (type != 0);
 	
	object = prepare_object (ctx->storage, location, digest, type);
	g_return_if_fail (object != NULL);

	/* Make note of having seen this object in load requests */
	g_hash_table_remove (pv->specific_load_requests, digest);
	
	/* Make note of having seen this one */
	g_hash_table_remove (ctx->checks, object);
	
	/* Track the type for this digest */
	g_hash_table_insert (ctx->types_by_digest, gkr_id_dup (digest), 
		                 GUINT_TO_POINTER (type));

	/* Setup the asn1, probably a certificate on this object */
	g_object_set (object, "asn1-tree", asn1, NULL); 
	
	/*
	 * Now we have the object loaded and everything, and since it's a fully
	 * loaded (if encrypted a password has been provided), take the 
	 * opportunity to 'import' it and make sure we have all necessary data
	 * on it.
	 */
	if (gkr_pk_index_get_boolean (object, "imported", FALSE))
		gkr_pk_object_import (object);
}

static void
remove_each_object (GkrPkObject *object, gpointer unused, GkrPkObjectStorage *storage)
{
	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
	if (g_hash_table_lookup (pv->objects, object))
		remove_object (storage, object);
}

static void
index_each_digest (gkrid digest, gpointer value, gpointer data)
{
	GQuark location = GPOINTER_TO_UINT (data);
	GQuark type = GPOINTER_TO_UINT (value);
	
	if (!type)
		return;

	/* Stash away the parsed type, in case we need it when prompting for a password */
	gkr_pk_index_set_string_full (location, digest, "parsed-type", 
	                              g_quark_to_string (type));
}

static gboolean
load_objects_at_location (GkrPkObjectStorage *storage, GQuark loc, GError **err)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
 	GkrPkixParser *parser;
 	GkrPkixResult ret;
 	GkrPkObject *object;
	ParseContext ctx;
	GArray *objs;
	gpointer k;
	guint i;
	
	g_return_val_if_fail (loc != 0, FALSE);

	ctx.location = loc;
	ctx.storage = storage;
	ctx.checks = g_hash_table_new_full (g_direct_hash, g_direct_equal, 
	                                    g_object_unref, NULL);
	ctx.types_by_digest = g_hash_table_new_full (gkr_id_hash, gkr_id_equals, 
	                                             gkr_id_free, NULL);

	/* Create a table of what is at the location */
	k = GUINT_TO_POINTER (loc);
	objs = (GArray*)g_hash_table_lookup (pv->objects_by_location, k);
	for (i = 0; objs && i < objs->len; ++i) {	
		object = g_array_index (objs, GkrPkObject*, i);
		g_object_ref (object);
		g_hash_table_replace (ctx.checks, object, NO_VALUE);
	} 
	
	/* TODO: Try and use a shared parser? */
	parser = gkr_pkix_parser_new ();
	g_signal_connect (parser, "parsed-asn1", G_CALLBACK (parser_parsed_asn1), &ctx);
	g_signal_connect (parser, "parsed-sexp", G_CALLBACK (parser_parsed_sexp), &ctx);
	g_signal_connect (parser, "parsed-partial", G_CALLBACK (parser_parsed_partial), &ctx);
 	g_signal_connect (parser, "ask-password", G_CALLBACK (parser_ask_password), &ctx);

	ret = gkr_pkix_parser_parse_location (parser, loc, err);
	g_object_unref (parser);

	/* Remove any still in checks array */
	g_hash_table_foreach (ctx.checks, (GHFunc)remove_each_object, storage);
	g_hash_table_destroy (ctx.checks);
	
	/* 
	 * Note any in the index that we prompted for but didn't actually 
	 * get an object out about.
	 */  
	g_hash_table_foreach (ctx.types_by_digest, (GHFunc)index_each_digest, k);
	g_hash_table_destroy (ctx.types_by_digest);
	
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
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
	GArray *objs, *copy;
	gpointer k;
	guint i;
	
	/* Remove everything that is at that location */
	k = GUINT_TO_POINTER (loc);
	objs = (GArray*)g_hash_table_lookup (pv->objects_by_location, k);
	if (!objs)
		return;
		
	/* When removing we cleanup empty arrays */
	g_assert (objs->len);

	/* We copy because otherwise the array will change from underneath us */
	copy = g_array_sized_new (FALSE, FALSE, sizeof (GkrPkObject*), objs->len);
	g_array_append_vals (copy, objs->data, objs->len);
	for (i = 0; i < copy->len; ++i)
		remove_object (storage, g_array_index (copy, GkrPkObject*, i));
	 
	g_array_free (copy, TRUE);
}

static void
free_array (gpointer data)
{
	if (data)
		g_array_free ((GArray*)data, TRUE);	
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_object_storage_init (GkrPkObjectStorage *storage)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
 	GkrLocationWatch *watch;
 	const GkrPkPlace *place;
 	GQuark volume;
 	guint i;
 	
 	pv->objects = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);
 	pv->objects_by_location = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, free_array);
	pv->specific_load_requests = g_hash_table_new_full (gkr_id_hash, gkr_id_equals, gkr_id_free, NULL);
	pv->denied_import_requests = g_hash_table_new_full (gkr_id_hash, gkr_id_equals, gkr_id_free, NULL);
	
	for (i = 0; i < G_N_ELEMENTS (gkr_pk_places); ++i) {
		place = &gkr_pk_places[i];
		g_return_if_fail (place->directory);
		
		/* A null means any active volume */
		volume = place->volume ? gkr_location_from_string (place->volume) : 0;
		
		watch = gkr_location_watch_new (NULL, volume, place->directory, 
		                                place->include, place->exclude);
		g_return_if_fail (watch); 

 		g_signal_connect (watch, "location-added", G_CALLBACK (location_load), storage);
 		g_signal_connect (watch, "location-changed", G_CALLBACK (location_load), storage);
 		g_signal_connect (watch, "location-removed", G_CALLBACK (location_remove), storage);

		/* Assumes ownership */		
		pv->watches = g_slist_prepend (pv->watches, watch);
	}
}

static void
gkr_pk_object_storage_dispose (GObject *obj)
{
	GkrPkObjectStorage *storage = GKR_PK_OBJECT_STORAGE (obj);
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (obj);
 	GkrLocationWatch *watch;
 	GSList *l;
 	
 	g_hash_table_remove_all (pv->objects_by_location);
 	g_hash_table_remove_all (pv->specific_load_requests);
 	g_hash_table_remove_all (pv->denied_import_requests);
 	g_hash_table_remove_all (pv->objects);
 	
 	for (l = pv->watches; l; l = g_slist_next (l)) {
		watch = GKR_LOCATION_WATCH (l->data);
		g_signal_handlers_disconnect_by_func (watch, location_load, storage);
		g_signal_handlers_disconnect_by_func (watch, location_remove, storage);
 	}
 	
	G_OBJECT_CLASS (gkr_pk_object_storage_parent_class)->dispose (obj);
}

static void
gkr_pk_object_storage_finalize (GObject *obj)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (obj);
 	GkrLocationWatch *watch;
 	GSList *l;
 	
 	g_hash_table_destroy (pv->objects);
	g_hash_table_destroy (pv->objects_by_location);
	g_hash_table_destroy (pv->specific_load_requests);
	g_hash_table_destroy (pv->denied_import_requests);

 	for (l = pv->watches; l; l = g_slist_next (l)) {
		watch = GKR_LOCATION_WATCH (l->data);
		g_object_unref (watch);
 	}
 	g_slist_free (pv->watches);
 	pv->watches = NULL;
	
	G_OBJECT_CLASS (gkr_pk_object_storage_parent_class)->finalize (obj);
}

static void
gkr_pk_object_storage_class_init (GkrPkObjectStorageClass *klass)
{
	GObjectClass *gobject_class;
	gobject_class = (GObjectClass*)klass;

	gkr_pk_object_storage_parent_class = g_type_class_peek_parent (klass);
	gobject_class->dispose = gkr_pk_object_storage_dispose;
	gobject_class->finalize = gkr_pk_object_storage_finalize;

	g_type_class_add_private (gobject_class, sizeof (GkrPkObjectStoragePrivate));
}

GkrPkObjectStorage*
gkr_pk_object_storage_get (void)
{
	if (!object_storage_singleton) {
		object_storage_singleton = g_object_new (GKR_TYPE_PK_OBJECT_STORAGE, NULL);
		gkr_cleanup_register (cleanup_object_storage, NULL);
		gkr_pk_object_storage_refresh (object_storage_singleton);
	}
	
	return object_storage_singleton;
}	

void
gkr_pk_object_storage_refresh (GkrPkObjectStorage *storage)
{
	GkrPkObjectStoragePrivate *pv;
	GSList *l;
	
	if (!storage)
		storage = gkr_pk_object_storage_get ();
		
	g_return_if_fail (GKR_IS_PK_OBJECT_STORAGE (storage));
	pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
	
	for (l = pv->watches; l; l = g_slist_next (l)) 
		gkr_location_watch_refresh (GKR_LOCATION_WATCH (l->data), FALSE);
}

gboolean
gkr_pk_object_storage_load_complete (GkrPkObjectStorage *storage, GkrPkObject *obj, 
                                     GError **err)
{
 	GkrPkObjectStoragePrivate *pv = GKR_PK_OBJECT_STORAGE_GET_PRIVATE (storage);
	gboolean ret = FALSE;
	
	g_return_val_if_fail (obj, FALSE);
	
	g_object_ref (obj);
	
	/* We need to have this object */
	if (!obj->location) {
		g_set_error (err, GKR_PKIX_PARSE_ERROR, 0, "The object doesn't reside on disk");
		goto done;
	}

	
	/* Make note of the specific load request */
	g_hash_table_replace (pv->specific_load_requests, gkr_id_dup (obj->digest), NO_VALUE); 
	ret = load_objects_at_location (storage, obj->location, err);

	if (!ret) 
		goto done;
	 
	/* See if it was seen */
	if (g_hash_table_lookup (pv->specific_load_requests, obj->digest)) {
		g_set_error (err, GKR_PKIX_PARSE_ERROR, 0, "the object was not found at: %s",
		             g_quark_to_string (obj->location));
		goto done;
	}
	
	ret = TRUE;

done:
	g_hash_table_remove (pv->specific_load_requests, obj->digest);
	g_object_unref (obj);
	return ret;
}

gboolean
gkr_pk_object_storage_add (GkrPkObjectStorage *storage, GkrPkObject *obj, 
                           GError **err)
{
	/* TODO: Need to implement */
	g_return_val_if_reached (FALSE);
}

gboolean
gkr_pk_object_storage_remove (GkrPkObjectStorage *storage, GkrPkObject *obj, 
                              GError **err)
{
	/* TODO: Need to implement */
	g_return_val_if_reached (FALSE);
}
