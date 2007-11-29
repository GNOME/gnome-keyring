/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-object-manager.c - Manage all 'token' PK objects

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

#include "gkr-pk-object-manager.h"
#include "gkr-pk-privkey.h"
#include "gkr-pk-util.h"

#include "common/gkr-cleanup.h"
#include "common/gkr-location.h"
#include "common/gkr-location-watch.h"
#include "common/gkr-secure-memory.h"

#include "keyrings/gkr-keyring-login.h"

#include "pkcs11/pkcs11.h"

#include "pkix/gkr-pkix-cert.h"
#include "pkix/gkr-pkix-parser.h"

#include "ui/gkr-ask-daemon.h"
#include "ui/gkr-ask-request.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <stdarg.h>

/* list my signals  */
enum {
	/* MY_SIGNAL_1, */
	/* MY_SIGNAL_2, */
	LAST_SIGNAL
};

typedef struct _GkrPkObjectManagerPrivate GkrPkObjectManagerPrivate;

struct _GkrPkObjectManagerPrivate {
	GHashTable *object_by_handle;
	GHashTable *object_by_unique;
	GHashTable *objects_by_location;
	
	GHashTable *specific_load_requests;
	
	GkrLocationWatch *watch;
	GkrLocationWatch *ssh_watch;
};

#define GKR_PK_OBJECT_MANAGER_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PK_OBJECT_MANAGER, GkrPkObjectManagerPrivate))

G_DEFINE_TYPE(GkrPkObjectManager, gkr_pk_object_manager, G_TYPE_OBJECT);

static GkrPkObjectManager *object_manager_singleton = NULL; 

/* 
 * Constantly increasing counter for the token object handles. Starting at 
 * a non-zero offset so that apps will be well behaved.
 */
static CK_OBJECT_HANDLE next_object_handle = 0x000000F0;

typedef struct {
	GkrPkObjectManager *objmgr;	/* The object manager to parse into */
	GHashTable *checks;		/* The set that existed before parse */
	GkrPkObjectReason reason;	/* The reason we're doing this parse */
} ParseContext;

/* -----------------------------------------------------------------------------
 * HELPERS
 */
 
static void 
cleanup_object_manager (void *unused)
{
	g_assert (object_manager_singleton);
	g_object_unref (object_manager_singleton);
	object_manager_singleton = NULL;
}

static gchar* 
parser_ask_password (GkrPkixParser *parser, GQuark loc, gkrunique unique, 
                     GkrParsedType type, const gchar *orig_label, guint failures,
                     ParseContext *ctx)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (ctx->objmgr);
	GkrAskRequest *ask;
	gchar *title, *primary, *secondary;
	gchar *label, *ret;
	gchar *display_name;
	const gchar *password;
	const gchar *display_type;
	
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

	/* We never prompt for passwords unless the object is being specifically loaded */
	if (!g_hash_table_lookup (pv->specific_load_requests, unique))
		return NULL;
	
	/* TODO: Load a better label if we have one */
	label = NULL;
	
	/* 
	 * TRANSLATORS: 
	 *  display_type will be the type of the object like 'certificate' or 'key'
	 *  details will the name of the object to unlock.
	 */
	display_type = gkr_pkix_parsed_type_to_string (type);
	title = g_strdup_printf (_("Unlock %s"), display_type);
	primary = g_strdup_printf (_("Enter password for the %s to unlock"), display_type);
	
	switch (ctx->reason) {
	case GKR_PK_OBJECT_REASON_IMPORT:
		secondary = g_strdup_printf(_("The system wants to import the %s '%s', but it is locked."),
		                            display_type, label ? label : orig_label);
		break;
	default:
		secondary = g_strdup_printf (_("An application wants access to the %s '%s', but it is locked"), 
		                             display_type, label ? label : orig_label);
		break;
	};
	
	ask = gkr_ask_request_new (title, primary, GKR_ASK_REQUEST_PROMPT_PASSWORD);
	gkr_ask_request_set_secondary (ask, secondary);
	gkr_ask_request_set_location (ask, loc);

	g_free (title);
	g_free (primary);
	g_free (secondary);
		
	if (gkr_keyring_login_check ()) {
		label = g_strdup_printf (_("Automatically unlock this %s when I log in."), display_type);
		gkr_ask_request_set_check_option (ask, label);
		g_free (label);
	}
	
	gkr_ask_daemon_process (ask);
	
	if (ask->response < GKR_ASK_RESPONSE_ALLOW) {
		ret = NULL;
	} else {
		ret = gkr_secure_strdup (ask->typed_password);
		if (ask->checked) {
			display_name =  g_strdup_printf (_("Unlock password for %s"), orig_label);
			gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD,
			                                 display_name, ret,
			                                 "pk-object", gkr_location_to_string (loc), NULL);
		} 
	}	
		
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
add_object_for_unique (GkrPkObjectManager *objmgr, gkrconstunique unique, GkrPkObject *object)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
	gpointer k;
	
	g_assert (unique);
	g_assert (object);
	g_assert (gkr_unique_equals (object->unique, unique));
	g_assert (object->manager == NULL);
	
	if (!object->handle) {
		/* Make a new handle */
		object->handle = (++next_object_handle & GKR_PK_OBJECT_HANDLE_MASK);
		object->handle |= GKR_PK_OBJECT_IS_PERMANENT;
	}
	
	/* Mapping of objects by PKCS#11 'handle' */
	g_assert (object->handle);
	k = GUINT_TO_POINTER (object->handle);
	g_assert (g_hash_table_lookup (pv->object_by_handle, k) == NULL); 
	g_hash_table_replace (pv->object_by_handle, k, object);
	
	/* Mapping of objects by index key */
	g_assert (object->unique);
	g_assert (g_hash_table_lookup (pv->object_by_unique, object->unique) == NULL); 
	g_hash_table_replace (pv->object_by_unique, object->unique, object);
	
	/* Mapping of location to the index key */
	if (object->location) {
		k = GUINT_TO_POINTER (object->location);
		add_object_to_multihash (pv->objects_by_location, k, object); 
	}
	
	/* Take ownership of the object */
	objmgr->objects = g_list_prepend (objmgr->objects, object);
	object->manager = objmgr;
	g_object_ref (object);
}

static void
remove_object_at_unique (GkrPkObjectManager *objmgr, gkrconstunique unique)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
 	GkrPkObject *object;
	gpointer k;
	
	g_assert (unique);
	
	/* Get the object referred to */
	object = (GkrPkObject*)g_hash_table_lookup (pv->object_by_unique, unique);
	g_assert (GKR_IS_PK_OBJECT (object));
	g_assert (object->manager == objmgr);

	/* Mapping of objects by PKCS#11 'handle' */	
	k = GUINT_TO_POINTER (object->handle);
	g_assert (g_hash_table_lookup (pv->object_by_handle, k) == object); 
	g_hash_table_remove (pv->object_by_handle, k);
	
	/* Mapping of objects by index key */
	g_assert (gkr_unique_equals (object->unique, unique));
	g_hash_table_remove (pv->object_by_unique, unique); 
	
	/* Mapping of location to the object */
	if (object->location) {
		k = GUINT_TO_POINTER (object->location);
		remove_object_from_multihash (pv->objects_by_location, k, object);
	}

	/* Release ownership */		
	objmgr->objects = g_list_remove (objmgr->objects, object);
	object->manager = NULL;
	g_object_unref (object);
}

static GkrPkObject*
create_add_object (GkrPkObjectManager *objmgr, GQuark location, 
                   gkrconstunique unique, GkrParsedType type)
{
	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
	GkrPkObject *obj;
	GType gtype;
	
	obj = (GkrPkObject*)g_hash_table_lookup (pv->object_by_unique, unique);
	if (obj) {
		g_assert (gkr_unique_equals (unique, obj->unique));
		return obj;
	}
	
	switch (type) {
	case GKR_PARSED_PRIVATE_KEY:
		gtype = GKR_TYPE_PK_PRIVKEY;
		break;
	case GKR_PARSED_CERTIFICATE:
		gtype = GKR_TYPE_PKIX_CERT;
		break;
	default:
		g_return_val_if_reached (NULL);
		break;
	}
	
	obj = g_object_new (gtype, "location", location, 
	                           "unique", unique, NULL);

	add_object_for_unique (objmgr, unique, obj);
	
	/* Object was reffed */
	g_object_unref (obj);
	
	return obj;
}

static void 
parser_parsed_partial (GkrPkixParser *parser, GQuark location, gkrunique unique,
                       GkrParsedType type, ParseContext *ctx)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (ctx->objmgr);
 	
	/* Make note of having seen this object in load requests */
	g_hash_table_remove (pv->specific_load_requests, unique);

	/* Make note of having seen this one */
	g_hash_table_remove (ctx->checks, unique);
	
	create_add_object (ctx->objmgr, location, unique, type);
}

static void
parser_parsed_sexp (GkrPkixParser *parser, GQuark location, gkrunique unique,
	            GkrParsedType type, gcry_sexp_t sexp, ParseContext *ctx)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (ctx->objmgr);
	GkrPkObject *obj;
	
	/* Make note of having seen this object in load requests */
	g_hash_table_remove (pv->specific_load_requests, unique);
	
	/* Make note of having seen this one */
	g_hash_table_remove (ctx->checks, unique);
		
	obj = create_add_object (ctx->objmgr, location, unique, type);
	g_return_if_fail (obj != NULL);

	/* Setup the sexp, probably a key on this object */
	g_object_set (obj, "gcrypt-sexp", sexp, NULL);
}

static void
parser_parsed_asn1 (GkrPkixParser *parser, GQuark location, gkrconstunique unique, 
                    GkrParsedType type, ASN1_TYPE asn1, ParseContext *ctx)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (ctx->objmgr);
	GkrPkObject *obj;
	
	/* Make note of having seen this object in load requests */
	g_hash_table_remove (pv->specific_load_requests, unique);
	
	/* Make note of having seen this one */
	g_hash_table_remove (ctx->checks, unique);

	obj = create_add_object (ctx->objmgr, location, unique, type);
	g_return_if_fail (obj != NULL);

	/* Setup the asn1, probably a certificate on this object */
	g_object_set (obj, "asn1-tree", asn1, NULL); 
	
}

static void
remove_each_unique (gkrunique unique, gpointer unused, GkrPkObjectManager *objmgr)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
 	
	if (g_hash_table_lookup (pv->object_by_unique, unique)) 
		remove_object_at_unique (objmgr, unique);
}

static gboolean
load_objects_at_location (GkrPkObjectManager *objmgr, GQuark loc, 
                          GkrPkObjectReason reason, GError **err)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
 	GkrPkixParser *parser;
 	GkrParseResult ret;
 	GkrPkObject *object;
	ParseContext ctx;
	GArray *objs;
	gpointer k;
	guint i;

	ctx.objmgr = objmgr;
	ctx.reason = reason;
	ctx.checks = g_hash_table_new_full (gkr_unique_hash, gkr_unique_equals, 
	                                    gkr_unique_free, NULL);
	 		
	/* Create a table of what is at the location */
	k = GUINT_TO_POINTER (loc);
	objs = (GArray*)g_hash_table_lookup (pv->objects_by_location, k);
	for (i = 0; objs && i < objs->len; ++i) {	
		object = g_array_index (objs, GkrPkObject*, i);
		g_hash_table_replace (ctx.checks, gkr_unique_dup (object->unique), 
		                      GUINT_TO_POINTER (TRUE));
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
	g_hash_table_foreach (ctx.checks, (GHFunc)remove_each_unique, objmgr);
	g_hash_table_destroy (ctx.checks);
	
	return ret;
}

static void
location_load (GkrLocationWatch *watch, GQuark loc, GkrPkObjectManager *objmgr)
{
	GError *err = NULL;
	
	if (!load_objects_at_location (objmgr, loc, 0, &err)) {
		g_message ("couldn't parse data: %s: %s", g_quark_to_string (loc),
		           err && err->message ? err->message : "");
		g_error_free (err);
	}
}

static void
location_remove (GkrLocationWatch *watch, GQuark loc, GkrPkObjectManager *objmgr)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
	GArray *objs, *copy;
	GkrPkObject *object;
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
	for (i = 0; i < copy->len; ++i) {
		object = g_array_index (copy, GkrPkObject*, i);
		g_assert (object->unique);
		remove_object_at_unique (objmgr, object->unique);
	}
	 
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
gkr_pk_object_manager_init (GkrPkObjectManager *objmgr)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
 	
 	pv->object_by_handle = g_hash_table_new (g_direct_hash, g_direct_equal);
 	pv->object_by_unique = g_hash_table_new (gkr_unique_hash, gkr_unique_equals);
 	pv->objects_by_location = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, free_array);
	pv->specific_load_requests = g_hash_table_new_full (gkr_unique_hash, gkr_unique_equals, gkr_unique_free, NULL);
	
	pv->watch = gkr_location_watch_new (NULL, 0, "keyrings/pk", "*", "*.gkr");
 	g_signal_connect (pv->watch, "location-added", G_CALLBACK (location_load), objmgr);
 	g_signal_connect (pv->watch, "location-changed", G_CALLBACK (location_load), objmgr);
 	g_signal_connect (pv->watch, "location-removed", G_CALLBACK (location_remove), objmgr);
 	
 	/* Only match id_rsa and id_dsa SSH key files */
 	pv->ssh_watch = gkr_location_watch_new (NULL, GKR_LOCATION_VOLUME_HOME, ".ssh", "id_?sa", NULL);
 	g_signal_connect (pv->ssh_watch, "location-added", G_CALLBACK (location_load), objmgr);
 	g_signal_connect (pv->ssh_watch, "location-changed", G_CALLBACK (location_load), objmgr);
 	g_signal_connect (pv->ssh_watch, "location-removed", G_CALLBACK (location_remove), objmgr);
}

static void
gkr_pk_object_manager_dispose (GObject *obj)
{
	GkrPkObjectManager *objmgr = GKR_PK_OBJECT_MANAGER (obj);
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (obj);
 	GList *l;
 	
 	g_hash_table_remove_all (pv->object_by_handle);
 	g_hash_table_remove_all (pv->object_by_unique);
 	g_hash_table_remove_all (pv->objects_by_location);
 	g_hash_table_remove_all (pv->specific_load_requests);
 	
 	for (l = objmgr->objects; l; l = g_list_next (l)) 
 		g_object_unref (l->data);
 	g_list_free (objmgr->objects);
 	objmgr->objects = NULL;

	g_signal_handlers_disconnect_by_func (pv->watch, location_load, objmgr);
	g_signal_handlers_disconnect_by_func (pv->watch, location_remove, objmgr);
	g_signal_handlers_disconnect_by_func (pv->ssh_watch, location_load, objmgr);
	g_signal_handlers_disconnect_by_func (pv->ssh_watch, location_remove, objmgr);
 	
	G_OBJECT_CLASS (gkr_pk_object_manager_parent_class)->dispose (obj);
}

static void
gkr_pk_object_manager_finalize (GObject *obj)
{
	GkrPkObjectManager *man = GKR_PK_OBJECT_MANAGER (obj);
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (obj);
 	
	g_hash_table_destroy (pv->object_by_handle);
	g_hash_table_destroy (pv->object_by_unique);
	g_hash_table_destroy (pv->objects_by_location);
	g_hash_table_destroy (pv->specific_load_requests);
	g_assert (!man->objects);

	g_object_unref (pv->watch);
	g_object_unref (pv->ssh_watch);
	
	G_OBJECT_CLASS (gkr_pk_object_manager_parent_class)->finalize (obj);
}

static void
gkr_pk_object_manager_class_init (GkrPkObjectManagerClass *klass)
{
	GObjectClass *gobject_class;
	gobject_class = (GObjectClass*)klass;

	gkr_pk_object_manager_parent_class = g_type_class_peek_parent (klass);
	gobject_class->dispose = gkr_pk_object_manager_dispose;
	gobject_class->finalize = gkr_pk_object_manager_finalize;

	g_type_class_add_private (gobject_class, sizeof (GkrPkObjectManagerPrivate));
}

GkrPkObjectManager*
gkr_pk_object_manager_get (void)
{
	if (!object_manager_singleton) {
		object_manager_singleton = g_object_new (GKR_TYPE_PK_OBJECT_MANAGER, NULL);
		gkr_cleanup_register (cleanup_object_manager, NULL);
		gkr_pk_object_manager_refresh (object_manager_singleton);
	}
	
	return object_manager_singleton;
}	

void
gkr_pk_object_manager_register (GkrPkObjectManager *objmgr, GkrPkObject *object)
{
	GkrPkObjectManagerPrivate *pv;
	
	if (!objmgr)
		objmgr = gkr_pk_object_manager_get ();
		
	g_return_if_fail (GKR_IS_PK_OBJECT_MANAGER (objmgr));
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);

	g_return_if_fail (object->manager == NULL);
	g_return_if_fail (object->unique);

	/* Make sure we don't already have it */
	if (g_hash_table_lookup (pv->object_by_unique, object->unique))
		return;
		
	add_object_for_unique (objmgr, object->unique, object);
}

void
gkr_pk_object_manager_unregister (GkrPkObjectManager *objmgr, GkrPkObject *object)
{
	GkrPkObjectManagerPrivate *pv;
	
	if (!objmgr)
		objmgr = gkr_pk_object_manager_get ();
		
	g_return_if_fail (GKR_IS_PK_OBJECT_MANAGER (objmgr));
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
	
	g_return_if_fail (object->manager != objmgr);
	g_return_if_fail (object->unique);

	/* Make sure we have it */
	if (!g_hash_table_lookup (pv->object_by_unique, object->unique))
		return;
	
	remove_object_at_unique (objmgr, object->unique);
}

GkrPkObject*
gkr_pk_object_manager_lookup (GkrPkObjectManager *man, CK_OBJECT_HANDLE obj)
{
	GkrPkObjectManagerPrivate *pv;
	
	if (!man)
		man = gkr_pk_object_manager_get ();
		
	g_return_val_if_fail (GKR_IS_PK_OBJECT_MANAGER (man), NULL);
	g_return_val_if_fail (obj != 0, NULL);
	pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (man);
	
	return (GkrPkObject*)g_hash_table_lookup (pv->object_by_handle, 
	                                          GUINT_TO_POINTER (obj));
}

GList*
gkr_pk_object_manager_findv (GkrPkObjectManager *objmgr, GType gtype, ...)
{
	CK_ATTRIBUTE attr;
	GArray *attrs = NULL;
	va_list va;
	CK_ULONG uval, spacer;
	CK_BBOOL bval;
	CK_VOID_PTR value;
	GList *ret = NULL;
	
	va_start (va, gtype);
	
	for (;;) {
		memset (&attr, 0, sizeof (attr));
		
		attr.type = va_arg (va, CK_ATTRIBUTE_TYPE);
		if (!attr.type) {
			
			/* 
			 * We keep this in a lower scope that our alloca 
			 * allocations, just in case some compiler gets the 
			 * bright idea (like GNU C in some cases) that it'll
			 * cleanup at variable scope rather than function scope.
			 */
			 
			ret = gkr_pk_object_manager_find (objmgr, gtype, attrs);
			break;
		}	
		
		switch (gkr_pk_attribute_data_type (attr.type)) {
		case GKR_PK_DATA_ULONG:
			uval = va_arg (va, CK_ULONG);
			gkr_pk_attribute_set_uint (&attr, uval);
			spacer = va_arg (va, CK_ULONG);
			break;
		
		case GKR_PK_DATA_BOOL:
			bval = va_arg (va, int) ? CK_TRUE : CK_FALSE;
			gkr_pk_attribute_set_boolean (&attr, bval);
			spacer = va_arg (va, CK_ULONG);
			break;
		
		case GKR_PK_DATA_BYTES:
			value = va_arg (va, CK_VOID_PTR);
			uval = va_arg (va, CK_ULONG);
			gkr_pk_attribute_set_data (&attr, value, uval);
			break;

		default:
			g_warning ("unsupported type of data for attribute type: %d", (int)attr.type);
			return NULL;	
		};
		
		if (!attrs)
			attrs = gkr_pk_attribute_array_new ();
		g_array_append_val (attrs, attr);
	}

	va_end (va);
	
	gkr_pk_attribute_array_free (attrs);
	return ret;
}

GList*
gkr_pk_object_manager_find (GkrPkObjectManager *man, GType gtype, GArray *attrs)
{
	CK_OBJECT_CLASS *ocls = NULL;
	GkrPkObject *object;
	gboolean do_refresh = TRUE;
	GList *l, *objects = NULL;
	
	if (!man)
		man = gkr_pk_object_manager_get ();
		
	g_return_val_if_fail (GKR_IS_PK_OBJECT_MANAGER (man), NULL);

	/* Figure out the class of objects we're loading */
	if (attrs)
		ocls = (CK_OBJECT_CLASS*)gkr_pk_attribute_array_find (attrs, CKA_CLASS);
	if (ocls) {
		switch (*ocls) {
		/* TODO: Add here classes for which we don't want to refresh */
		default:
			break;
		}
	}
	
	if (gtype) {
		switch (gtype) {
		/* TODO: Add here classes for which we don't want to refresh */
		default:
			break;
		}
	}

	if (do_refresh) 
		gkr_pk_object_manager_refresh (man);

	/* TODO: We may want to only go through objects of CKA_CLASS */
	for (l = man->objects; l; l = g_list_next (l)) {
		object = GKR_PK_OBJECT (l->data);
		if (gtype && !G_TYPE_CHECK_INSTANCE_TYPE (l->data, gtype))
			continue;
		if (!attrs || gkr_pk_object_match (object, attrs))
			objects = g_list_prepend (objects, object);
	}
	
	return objects;
}

GkrPkObject*
gkr_pk_object_manager_find_by_id (GkrPkObjectManager *objmgr, GType gtype, 
                                  gkrconstunique id)
{
	CK_ATTRIBUTE attr;
	GkrPkObject *object;
	gsize len;
	GList *l;
	
	if (!objmgr)
		objmgr = gkr_pk_object_manager_get ();
		
	g_return_val_if_fail (id, NULL);
	g_return_val_if_fail (GKR_IS_PK_OBJECT_MANAGER (objmgr), NULL);

	attr.pValue = (CK_VOID_PTR)gkr_unique_get_raw (id, &len);
	attr.ulValueLen = len;
	attr.type = CKA_ID; 

	/* TODO: This needs to be done more efficiently */
	for (l = objmgr->objects; l; l = g_list_next (l)) {
		object = GKR_PK_OBJECT (l->data);
		if (gtype && !G_TYPE_CHECK_INSTANCE_TYPE (l->data, gtype))
			continue;
		if (gkr_pk_object_match_one (object, &attr))
			return object;
	}

	return NULL;	
}

void
gkr_pk_object_manager_refresh (GkrPkObjectManager *objmgr)
{
	GkrPkObjectManagerPrivate *pv;
	
	if (!objmgr)
		objmgr = gkr_pk_object_manager_get ();
		
	g_return_if_fail (GKR_IS_PK_OBJECT_MANAGER (objmgr));
	pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
		
	g_assert (pv->watch);
	gkr_location_watch_refresh (pv->watch, FALSE);

	g_assert (pv->ssh_watch);
	gkr_location_watch_refresh (pv->ssh_watch, FALSE);
}

gboolean
gkr_pk_object_manager_load_complete (GkrPkObjectManager *objmgr, GkrPkObject *obj, 
                                     GkrPkObjectReason reason, GError **err)
{
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);
	gkrunique uni;
	
	/* We need to have this object */
	g_return_val_if_fail (g_hash_table_lookup (pv->object_by_unique, obj->unique), FALSE); 
	
	if (!obj->location) {
		g_set_error (err, GKR_PKIX_PARSE_ERROR, 0, "the object doesn't reside on disk");
		return FALSE;
	}
	
	g_object_ref (obj);
	
	/* Make note of the specific load request */
	uni = gkr_unique_dup (obj->unique);
	g_hash_table_replace (pv->specific_load_requests, uni, uni); 

	if (!load_objects_at_location (objmgr, obj->location, reason, err))
		return FALSE;
	 
	/* See if it was seen */
	if (g_hash_table_remove (pv->specific_load_requests, obj->unique)) {
		g_set_error (err, GKR_PKIX_PARSE_ERROR, 0, "the object was not found at: %s",
		             g_quark_to_string (obj->location));
		return FALSE;
	}

	return TRUE;
}
