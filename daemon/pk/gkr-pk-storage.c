/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-storage.c - Base class for storage of PK objects

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

#include "gkr-pk-storage.h"
#include "gkr-pk-util.h"

#include "common/gkr-cleanup.h"
#include "common/gkr-location.h"
#include "common/gkr-secure-memory.h"

#include "keyrings/gkr-keyrings.h"
#include "keyrings/gkr-keyring-login.h"

#include "pkix/gkr-pkix-types.h"

#include "ui/gkr-ask-daemon.h"
#include "ui/gkr-ask-request.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <stdarg.h>

typedef struct _GkrPkStoragePrivate GkrPkStoragePrivate;

struct _GkrPkStoragePrivate {
	GHashTable *objects;
	GHashTable *objects_by_location;
	GkrPkIndex *index;
};

G_DEFINE_TYPE(GkrPkStorage, gkr_pk_storage, G_TYPE_OBJECT);

#define GKR_PK_STORAGE_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PK_STORAGE, GkrPkStoragePrivate))

static GSList *registered_storages = NULL;
static GkrPkStorage *default_storage = NULL;

#define NO_VALUE GUINT_TO_POINTER (TRUE)

/* -----------------------------------------------------------------------------
 * HELPERS
 */
 
static void 
cleanup_storages (void *unused)
{
	GSList *l;
	for (l = registered_storages; l; l = g_slist_next (l))
		g_object_unref (l->data);
	g_slist_free (registered_storages);
	registered_storages = NULL;
	default_storage = NULL;
}

static void
free_array (gpointer data)
{
	if (data)
		g_array_free ((GArray*)data, TRUE);	
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

static const gchar*
prepare_ask_load_title (GQuark type)
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
prepare_ask_store_title (GQuark type)
{
	/*
	 * Yes this is unmaintainable and stupid, but is required 
	 * for translations to work properly.
	 */
	if (type == GKR_PKIX_PRIVATE_KEY)
		return _("Lock private key");
	else 
		return _("Lock");
}

static const gchar*
prepare_ask_load_primary (GQuark type)
{
	/*
	 * Yes this is unmaintainable and dumb, but is required 
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
prepare_ask_store_primary (GQuark type)
{
	/*
	 * Yes this is unmaintainable and dumb, but is required 
	 * for translations to work properly.
	 */
	if (type == GKR_PKIX_PRIVATE_KEY)
		return _("Enter password to protect the private key");
	else 
		return _("Enter password to protect storage");
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
prepare_ask_load_secondary (GQuark type, const gchar *label)
{
	if (type == GKR_PKIX_PRIVATE_KEY)
		return g_strdup_printf (_("An application wants access to the private key '%s', but it is locked"), label);
	else if (type == GKR_PKIX_CERTIFICATE)
		return g_strdup_printf (_("An application wants access to the certificate '%s', but it is locked"), label);
	else if (type == GKR_PKIX_PUBLIC_KEY)
		return g_strdup_printf (_("An application wants access to the public key '%s', but it is locked"), label);
	else 
		return g_strdup_printf (_("An application wants access to '%s', but it is locked"), label);

}

static gchar*
prepare_ask_store_secondary (GQuark type, const gchar *label)
{
	/*
	 * Yes this is unmaintainable and stupid, but is required 
	 * for translations to work properly.
	 */

	if (type == GKR_PKIX_PRIVATE_KEY)
		return g_strdup_printf (_("The system wants to store the private key '%s' on your disk. Please enter a password to lock it with."), label);
	else 
		return g_strdup_printf (_("The system wants to store '%s' on your disk. Please enter a password to lock it with."), label);
}

static void
remove_each_object (GkrPkObject *object, gpointer unused, GkrPkStorage *storage)
{
	gkr_pk_storage_del_object (storage, object);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_storage_init (GkrPkStorage *storage)
{
 	GkrPkStoragePrivate *pv = GKR_PK_STORAGE_GET_PRIVATE (storage);
 	
 	pv->objects = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);
 	pv->objects_by_location = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, free_array);
 	pv->index = NULL;
}

static void 
gkr_pk_storage_internal_refresh (GkrPkStorage *storage)
{
	/* By default we do nothing */
}

static gboolean 
gkr_pk_storage_internal_load (GkrPkStorage *storage, GkrPkObject *object, GError **err)
{
	/* By default we do nothing */
	return TRUE;
}

static gboolean 
gkr_pk_storage_internal_store (GkrPkStorage *storage, GkrPkObject *object, GError **err)
{
	g_return_val_if_fail (object->storage == NULL, FALSE);
	
	/* By default just add the object */
	gkr_pk_storage_add_object (storage, object);
	return TRUE;
}

static gboolean 
gkr_pk_storage_internal_remove (GkrPkStorage *storage, GkrPkObject *object, GError **err)
{
	g_return_val_if_fail (object->storage == storage, FALSE);

	/* By default we just remove the object */
	gkr_pk_storage_del_object (storage, object);
	return TRUE;
}

static GkrPkIndex* 
gkr_pk_storage_internal_index (GkrPkStorage *storage, GQuark unused)
{
 	GkrPkStoragePrivate *pv = GKR_PK_STORAGE_GET_PRIVATE (storage);
	
	if (!pv->index) {
		pv->index = gkr_pk_index_open_login (NULL);
		if (!pv->index)
			pv->index = gkr_pk_index_open_session (NULL);
	}
	
	return pv->index;
}

static void
gkr_pk_storage_dispose (GObject *obj)
{
 	GkrPkStoragePrivate *pv = GKR_PK_STORAGE_GET_PRIVATE (obj);
 	
 	g_hash_table_remove_all (pv->objects_by_location);
 	g_hash_table_remove_all (pv->objects);
 	
 	if (pv->index)
 		g_object_unref (pv->index);
 	pv->index = NULL;
 	
	G_OBJECT_CLASS (gkr_pk_storage_parent_class)->dispose (obj);
}

static void
gkr_pk_storage_finalize (GObject *obj)
{
 	GkrPkStoragePrivate *pv = GKR_PK_STORAGE_GET_PRIVATE (obj);
 	
 	g_hash_table_destroy (pv->objects);
	g_hash_table_destroy (pv->objects_by_location);
	g_assert (pv->index == NULL);
	
	G_OBJECT_CLASS (gkr_pk_storage_parent_class)->finalize (obj);
}

static void
gkr_pk_storage_class_init (GkrPkStorageClass *klass)
{
	GObjectClass *gobject_class;

	gkr_pk_storage_parent_class = g_type_class_peek_parent (klass);

	gobject_class = (GObjectClass*)klass;
	gobject_class->dispose = gkr_pk_storage_dispose;
	gobject_class->finalize = gkr_pk_storage_finalize;
	
	klass->refresh = gkr_pk_storage_internal_refresh;
	klass->load = gkr_pk_storage_internal_load;
	klass->store = gkr_pk_storage_internal_store;
	klass->remove = gkr_pk_storage_internal_remove;
	klass->index = gkr_pk_storage_internal_index;

	gkr_cleanup_register (cleanup_storages, NULL);

	g_type_class_add_private (gobject_class, sizeof (GkrPkStoragePrivate));
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */


GQuark
gkr_pk_storage_get_error_domain (void)
{
	static GQuark domain = 0;
	if (domain == 0)
		domain = g_quark_from_static_string ("gkr-pk-storage-error");
	return domain;
}

GkrPkStorage*
gkr_pk_storage_get_default (void)
{
	g_return_val_if_fail (GKR_IS_PK_STORAGE (default_storage), NULL);
	return default_storage;
}

void
gkr_pk_storage_register (GkrPkStorage *storage, gboolean is_default)
{
	g_return_if_fail (GKR_IS_PK_STORAGE (storage));
	g_object_ref (storage);
	registered_storages = g_slist_prepend (registered_storages, storage);
	if (is_default)
		default_storage = storage;
}

void
gkr_pk_storage_refresh_all (void)
{
	GSList *l;
	for (l = registered_storages; l; l = g_slist_next (l))
		gkr_pk_storage_refresh (GKR_PK_STORAGE (l->data));
}

void
gkr_pk_storage_refresh (GkrPkStorage *storage)
{
	GkrPkStorageClass *klass;
	
	if (!storage) {
		g_return_if_fail (default_storage);
		storage = default_storage;
	}

	g_return_if_fail (GKR_IS_PK_STORAGE (storage));
	klass = GKR_PK_STORAGE_GET_CLASS (storage);
	g_return_if_fail (klass->refresh);
	(klass->refresh) (storage);
}

gboolean
gkr_pk_storage_load (GkrPkStorage *storage, GkrPkObject *obj, GError **err)
{
	GkrPkStorageClass *klass;

	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);

	if (!storage) {
		g_return_val_if_fail (obj->storage, FALSE);
		storage = obj->storage;
	}

	g_return_val_if_fail (GKR_IS_PK_STORAGE (storage), FALSE);
	klass = GKR_PK_STORAGE_GET_CLASS (storage);
	g_return_val_if_fail (klass->load, FALSE);
	return (klass->load) (storage, obj, err);	
}

gboolean
gkr_pk_storage_store (GkrPkStorage *storage, GkrPkObject *obj, GError **err)
{
	GkrPkStorageClass *klass;
	gboolean ret;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);
	
	if (!storage) {
		g_return_val_if_fail (default_storage, FALSE);
		storage = default_storage;
	}

	g_return_val_if_fail (GKR_IS_PK_STORAGE (storage), FALSE);
	klass = GKR_PK_STORAGE_GET_CLASS (storage);
	g_return_val_if_fail (klass->store, FALSE);
	ret = (klass->store) (storage, obj, err);
	
	
	if (!ret)
		return FALSE;
	
	/* Check to make sure the storage is working properly */
	if (!obj->digest)
		g_warning ("no digest setup on object after storing");
	if (obj->storage != storage)
		g_warning ("wrong storage setup on object after storing");
	
	return TRUE;
}

gboolean 
gkr_pk_storage_remove (GkrPkStorage *storage, GkrPkObject *obj, GError **err)
{
	GkrPkStorageClass *klass;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);
	
	if (!storage) {
		g_return_val_if_fail (obj->storage, FALSE);
		storage = obj->storage;
	}

	g_return_val_if_fail (GKR_IS_PK_STORAGE (storage), FALSE);
	klass = GKR_PK_STORAGE_GET_CLASS (storage);
	g_return_val_if_fail (klass->remove, FALSE);
	return (klass->remove) (storage, obj, err);	
}

GkrPkIndex*
gkr_pk_storage_index (GkrPkStorage *storage, GQuark location)
{
	GkrPkStorageClass *klass;

	if (!storage)
		storage = default_storage;
	g_return_val_if_fail (GKR_IS_PK_STORAGE (storage), NULL);

	klass = GKR_PK_STORAGE_GET_CLASS (storage);
	g_return_val_if_fail (klass->index, NULL);
	return (klass->index) (storage, location);
}

void
gkr_pk_storage_set_object (GkrPkStorage *storage, GkrPkObject *object)
{
	g_return_if_fail (GKR_IS_PK_STORAGE (storage));
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	g_return_if_fail (object->location);

	g_object_ref (object);
	
	gkr_pk_storage_clr_objects (storage, object->location);
	gkr_pk_storage_add_object (storage, object);
	
	g_object_unref (object);
}

void
gkr_pk_storage_add_object (GkrPkStorage *storage, GkrPkObject *object)
{
	GkrPkStoragePrivate *pv = GKR_PK_STORAGE_GET_PRIVATE (storage);
	gpointer k;
		
	g_return_if_fail (GKR_IS_PK_STORAGE (storage));
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	
	if (g_hash_table_lookup (pv->objects, object))
		return;
			
	/* Mapping of location to the index key */
	k = GUINT_TO_POINTER (object->location);
	add_object_to_multihash (pv->objects_by_location, k, object); 

	/* The storage of this object is ours from now on */
	g_object_set (object, "storage", storage, NULL);
		
	/* Take ownership of the object */
	g_object_ref (object);
	g_hash_table_insert (pv->objects, object, NO_VALUE);
}

void
gkr_pk_storage_del_object (GkrPkStorage *storage, GkrPkObject *object)
{
 	GkrPkStoragePrivate *pv = GKR_PK_STORAGE_GET_PRIVATE (storage);
	gpointer k;

	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	g_return_if_fail (GKR_IS_PK_STORAGE (storage));
	
	if (!g_hash_table_lookup (pv->objects, object))
		return;
		
	/* Mapping of location to the object */
	k = GUINT_TO_POINTER (object->location);
	if (!remove_object_from_multihash (pv->objects_by_location, k, object))
		g_assert (FALSE);

	/* Relinquish ownership of this object */
	if (object->storage == storage)
		g_object_set (object, "storage", storage, NULL);

	/* Release ownership */
	if (!g_hash_table_remove (pv->objects, object))
		g_assert (FALSE);
}

void
gkr_pk_storage_clr_objects (GkrPkStorage *storage, GQuark loc)
{
	GkrPkStoragePrivate *pv = GKR_PK_STORAGE_GET_PRIVATE (storage);
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
		gkr_pk_storage_del_object (storage, g_array_index (copy, GkrPkObject*, i));
		 
	g_array_free (copy, TRUE);
}

GSList*
gkr_pk_storage_get_objects (GkrPkStorage *storage, GQuark location)
{
	GkrPkStoragePrivate *pv = GKR_PK_STORAGE_GET_PRIVATE (storage);
	GArray *objs;
	gpointer k;
	GSList *result;
	guint i;
		
	/* Remove everything that is at that location */
	k = GUINT_TO_POINTER (location);
	objs = (GArray*)g_hash_table_lookup (pv->objects_by_location, k);
	if (!objs)
		return NULL;
			
	/* When removing we cleanup empty arrays */
	g_assert (objs->len);

	/* We copy because otherwise the array will change from underneath us */
	result = NULL;
	for (i = 0; i < objs->len; ++i)
		result = g_slist_prepend (result, g_array_index (objs, GkrPkObject*, i));
	
	return result;
}

GkrPkChecks*
gkr_pk_storage_checks_prepare (GkrPkStorage *storage, GQuark location)
{
 	GkrPkStoragePrivate *pv = GKR_PK_STORAGE_GET_PRIVATE (storage);
	GHashTable *checks;
	GkrPkObject *object;
	GArray *objs;
	gpointer k;
	guint i;
	
	g_return_val_if_fail (GKR_IS_PK_STORAGE (storage), NULL);
	g_return_val_if_fail (location != 0, NULL);

	checks = g_hash_table_new_full (g_direct_hash, g_direct_equal, 
	                                g_object_unref, NULL);

	/* Create a table of what is at the location */
	k = GUINT_TO_POINTER (location);
	objs = (GArray*)g_hash_table_lookup (pv->objects_by_location, k);
	for (i = 0; objs && i < objs->len; ++i) {
		object = g_array_index (objs, GkrPkObject*, i);
		g_object_ref (object);
		g_hash_table_replace (checks, object, NO_VALUE);
	} 
	
	return checks;
}

void
gkr_pk_storage_checks_mark (GkrPkChecks *checks, GkrPkObject *object)
{
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	g_return_if_fail (checks);

	g_hash_table_remove (checks, object);
}

void
gkr_pk_storage_checks_purge (GkrPkStorage *storage, GkrPkChecks *checks)
{
	g_return_if_fail (GKR_IS_PK_STORAGE (storage));
	g_return_if_fail (checks);
	
	g_hash_table_foreach (checks, (GHFunc)remove_each_object, storage);
	g_hash_table_destroy (checks);
}

gboolean
gkr_pk_storage_get_store_password (GkrPkStorage *storage, GQuark location, gkrconstid digest,
                                   GQuark type, const gchar *label, gchar **result)
{
	GkrAskRequest *ask;
	gchar *custom_label = NULL;
	gchar *secondary;
	gchar *display = NULL;
	gboolean ret = TRUE;
	guint flags;
	GkrPkIndex *index;
	GkrKeyring *login;
	
	g_return_val_if_fail (GKR_IS_PK_STORAGE (storage), FALSE);
	g_return_val_if_fail (result != NULL, FALSE);

	index = gkr_pk_storage_index (storage, location);

	/*
	 * We save the password while still here in this function.
	 *  - Optimistic, assuming it'll succeed.
	 *  - Can store to the possibly bogus digest, because objects
	 *    will move all index storage to the real digest later.
	 */

	/* See if we can just use the login keyring password for this */
	if (index && gkr_keyring_login_is_usable () && gkr_pk_index_allows_secrets (index)) {
		login = gkr_keyrings_get_login ();
		g_return_val_if_fail (login, FALSE);
		g_return_val_if_fail (login->password, FALSE);
		
		*result = gkr_secure_strdup (login->password);
		
		/* 
		 * Always same a 'login' password used as a secret. So that 
		 * the user can later change the login password, and this'll 
		 * still work. 
		 */
		gkr_pk_index_set_secret (index, digest, *result);
		return TRUE;
	}

	if (!label) 
		label = display = gkr_location_to_display (location);
		
	/* Build up the prompt */
	flags = GKR_ASK_REQUEST_NEW_PASSWORD;
	ask = gkr_ask_request_new (prepare_ask_store_title (type), 
	                           prepare_ask_store_primary (type), flags);

	secondary = prepare_ask_store_secondary (type, label); 
	gkr_ask_request_set_secondary (ask, secondary);
	g_free (secondary);

	gkr_ask_request_set_location (ask, location);
			
	if (index && gkr_pk_index_allows_secrets (index))
		gkr_ask_request_set_check_option (ask, prepare_ask_check (type));
		
	/* Prompt the user */
	gkr_ask_daemon_process (ask);

	/* If the user denied ... */
	if (ask->response == GKR_ASK_RESPONSE_DENY) {
		ret = FALSE;
		
	/* User cancelled or failure */
	} else if (ask->response < GKR_ASK_RESPONSE_ALLOW) {
		ret = FALSE;
			
	/* Successful response */
	} else {
		*result = gkr_secure_strdup (ask->typed_password);
		if (ask->checked)
			gkr_pk_index_set_secret (index, digest, *result);
	}
	
	g_free (display);
	g_free (custom_label);
	g_object_unref (ask);
	return ret;	
}

gboolean
gkr_pk_storage_get_load_password (GkrPkStorage *storage, GQuark location, gkrconstid digest, 
                                  GQuark type, const gchar *label, gint *state, 
                                  gchar **result)
{
	GkrAskRequest *ask;
	gchar *stype, *secondary;
	gchar *display = NULL;
	const gchar *password;
	gboolean ret = TRUE;
	GkrPkIndex *index;
	gint st;
	guint flags;
	
	g_return_val_if_fail (GKR_IS_PK_STORAGE (storage), FALSE);
	g_return_val_if_fail (digest != NULL, FALSE);
	g_return_val_if_fail (state != NULL, FALSE);
	g_return_val_if_fail (result != NULL, FALSE);
	
	st = *state;
	(*state)++;

	/* 
	 * On the first pass always try a NULL and then an empty password. 
	 * This helps with two things.
	 *  
	 * 1. Often code will call this function, without actually parsing
	 *    any data yet. So this prevents us prompting the user without
	 *    knowing it will parse. 
	 *  
	 * 2. In case it is actually an empty password, we don't want to 
	 *    prompt the user, just 'decrypt' it. Note that some systems
	 *    use the null password instead of empty, so we try both.
	 */

	if (st == 0) {
		*result = gkr_secure_strdup ("");
		return TRUE;
		
	} else if (st == 1) {
		*result = NULL;
		return TRUE;	
	}
	
	index = gkr_pk_storage_index (storage, location);
	
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
	if (st == 2) {
		*result = gkr_pk_index_get_secret (index, digest);
		if (*result != NULL)
			return TRUE;
		
		/* 
		 * COMPATIBILITY: This is for compatibility with old versions 2.22, which 
		 * stored a location/filename based password in the login keyring.
		 * This is wrong for locations with  more than one password, so we 
		 * migrate transparently to the new style (above).
		 */ 
		password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD,
				                            "pk-object", gkr_location_to_string (location), NULL);
		if (password != NULL) {
			*result = gkr_secure_strdup (password);
			return TRUE;
		}
		
	/* If we've already tried this password unsuccesfully, then clear */
	} else {
		gkr_pk_index_set_secret (index, digest, NULL);
	}

	/*
	 * If we've parsed this before, then we can lookup in our index as to what 
	 * exactly this is we're talking about here.  
	 */
	stype = gkr_pk_index_get_string (index, digest, "parsed-type");
	if (stype) {
		if (!type && stype[0])
			type = g_quark_from_string (stype);
		g_free (stype);
	}
	
	if (!label) 
		label = display = gkr_location_to_display (location);
		
	/* Build up the prompt */
	flags = GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_OK_DENY_BUTTONS;
	ask = gkr_ask_request_new (prepare_ask_load_title (type), 
	                           prepare_ask_load_primary (type), flags);

	secondary = prepare_ask_load_secondary (type, label); 
	gkr_ask_request_set_secondary (ask, secondary);
	g_free (secondary);

	gkr_ask_request_set_location (ask, location);
			
	if (index && gkr_pk_index_allows_secrets (index))
		gkr_ask_request_set_check_option (ask, prepare_ask_check (type));
		
	/* Prompt the user */
	gkr_ask_daemon_process (ask);

	/* If the user denied ... */
	if (ask->response == GKR_ASK_RESPONSE_DENY) {
		ret = FALSE;
		
	/* User cancelled or failure */
	} else if (ask->response < GKR_ASK_RESPONSE_ALLOW) {
		ret = FALSE;
			
	/* Successful response */
	} else {
		*result = gkr_secure_strdup (ask->typed_password);
		if (ask->checked) 
			gkr_pk_index_set_secret (index, digest, ask->typed_password);
	}
	
	g_free (display);
	g_object_unref (ask);
	return ret;
}
