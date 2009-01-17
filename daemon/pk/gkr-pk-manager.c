/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-manager.c - Manage all 'token' PK objects

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
#include "gkr-pk-manager.h"
#include "gkr-pk-privkey.h"
#include "gkr-pk-storage.h"
#include "gkr-pk-util.h"

#include "common/gkr-cleanup.h"
#include "common/gkr-location.h"
#include "common/gkr-location-watch.h"
#include "egg/egg-secure-memory.h"

#include "keyrings/gkr-keyring-login.h"

#include "pkcs11/pkcs11.h"

#include "pkix/gkr-pkix-parser.h"

#include "ui/gkr-ask-daemon.h"
#include "ui/gkr-ask-request.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <stdarg.h>

typedef struct _GkrPkManagerPrivate GkrPkManagerPrivate;

struct _GkrPkManagerPrivate {
	pid_t for_pid;
	gboolean is_token;
	
	GHashTable *object_by_handle;
	GHashTable *object_by_digest;
};

#define GKR_PK_MANAGER_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PK_MANAGER, GkrPkManagerPrivate))

G_DEFINE_TYPE(GkrPkManager, gkr_pk_manager, G_TYPE_OBJECT);

static GkrPkManager *manager_for_token = NULL; 
static GHashTable *managers_by_pid = NULL;

/* 
 * Constantly increasing counter for the token object handles. Starting at 
 * a non-zero offset so that apps will be well behaved.
 */
static CK_OBJECT_HANDLE next_object_handle = 0x00000010;

/* -----------------------------------------------------------------------------
 * HELPERS
 */
 
static void 
cleanup_manager (void *unused)
{
	g_assert (manager_for_token);
	g_object_unref (manager_for_token);
	manager_for_token = NULL;
}

static void
add_object (GkrPkManager *objmgr, GkrPkObject *object)
{
 	GkrPkManagerPrivate *pv = GKR_PK_MANAGER_GET_PRIVATE (objmgr);
	gpointer k;
	
	g_assert (GKR_IS_PK_OBJECT (object));
	g_assert (object->digest);
	g_assert (object->manager == NULL);
	
	if (!object->handle) {
		/* Make a new handle */
		object->handle = (++next_object_handle & GKR_PK_OBJECT_HANDLE_MASK);
		if (pv->is_token)
			object->handle |= GKR_PK_OBJECT_IS_PERMANENT;
	}
	
	/* Mapping of objects by PKCS#11 'handle' */
	g_assert (object->handle);
	k = GUINT_TO_POINTER (object->handle);
	g_assert (g_hash_table_lookup (pv->object_by_handle, k) == NULL); 
	g_hash_table_replace (pv->object_by_handle, k, object);
	
	/* 
	 * Mapping of objects by digest key. There may be multiple objects
	 * with a given digest key.
	 */
	g_assert (object->digest);
	g_hash_table_replace (pv->object_by_digest, object->digest, object);
	
	/* Note objects is being managed */
	objmgr->objects = g_list_prepend (objmgr->objects, object);
	object->manager = objmgr;
}

static void
remove_object (GkrPkManager *objmgr, GkrPkObject *object)
{
 	GkrPkManagerPrivate *pv = GKR_PK_MANAGER_GET_PRIVATE (objmgr);
	gpointer k;
	
	g_assert (GKR_IS_PK_OBJECT (object));
	g_assert (object->manager == objmgr);
	
	/* Mapping of objects by PKCS#11 'handle' */	
	k = GUINT_TO_POINTER (object->handle);
	g_assert (g_hash_table_lookup (pv->object_by_handle, k) == object); 
	g_hash_table_remove (pv->object_by_handle, k);
	
	/* 
	 * Mapping of objects by digest key. There may be multiple objects
	 * with a given digest, so just remove if it matches this one.
	 */
	if (g_hash_table_lookup (pv->object_by_digest, object->digest) == object)
		g_hash_table_remove (pv->object_by_digest, object->digest); 
	
	/* Release object management */		
	objmgr->objects = g_list_remove (objmgr->objects, object);
	object->manager = NULL;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_manager_init (GkrPkManager *objmgr)
{
 	GkrPkManagerPrivate *pv = GKR_PK_MANAGER_GET_PRIVATE (objmgr);
 	
 	pv->object_by_handle = g_hash_table_new (g_direct_hash, g_direct_equal);
 	pv->object_by_digest = g_hash_table_new (gkr_id_hash, gkr_id_equals);
}

static void
gkr_pk_manager_dispose (GObject *obj)
{
	GkrPkManager *objmgr = GKR_PK_MANAGER (obj);
 	GkrPkManagerPrivate *pv = GKR_PK_MANAGER_GET_PRIVATE (obj);
 	gpointer k;
 	GList *objects, *l;

	/* Unregister all objects */
	objects = g_list_copy (objmgr->objects);
	for (l = objects; l; l = g_list_next (l)) 
		gkr_pk_manager_unregister (objmgr, GKR_PK_OBJECT (l->data));
	g_list_free (objects);
	
	g_return_if_fail (objmgr->objects == NULL);
 	g_return_if_fail (g_hash_table_size (pv->object_by_handle) == 0);
 	g_return_if_fail (g_hash_table_size (pv->object_by_digest) == 0);
 	
 	if (pv->for_pid) {
 		g_assert (managers_by_pid);
 		
 		k =  GUINT_TO_POINTER (pv->for_pid);
 		pv->for_pid = 0; 

		/* Remove us from the hash table */
 		g_assert (g_hash_table_lookup (managers_by_pid, k) == objmgr);
 		g_hash_table_remove (managers_by_pid, k);
 		
 		/* Destroy the table if its empty */
 		if (g_hash_table_size (managers_by_pid) == 0) {
 			g_hash_table_destroy (managers_by_pid);
 			managers_by_pid = NULL;
 		} 
 	}

	G_OBJECT_CLASS (gkr_pk_manager_parent_class)->dispose (obj);
}

static void
gkr_pk_manager_finalize (GObject *obj)
{
	GkrPkManager *man = GKR_PK_MANAGER (obj);
 	GkrPkManagerPrivate *pv = GKR_PK_MANAGER_GET_PRIVATE (obj);
 	
	g_hash_table_destroy (pv->object_by_handle);
	g_hash_table_destroy (pv->object_by_digest);
	g_assert (!man->objects);
	g_assert (!pv->for_pid);

	G_OBJECT_CLASS (gkr_pk_manager_parent_class)->finalize (obj);
}

static void
gkr_pk_manager_class_init (GkrPkManagerClass *klass)
{
	GObjectClass *gobject_class;
	gobject_class = (GObjectClass*)klass;

	gkr_pk_manager_parent_class = g_type_class_peek_parent (klass);
	gobject_class->dispose = gkr_pk_manager_dispose;
	gobject_class->finalize = gkr_pk_manager_finalize;

	g_type_class_add_private (gobject_class, sizeof (GkrPkManagerPrivate));
}

/* ------------------------------------------------------------------------
 * PUBLIC METHODS
 */

GkrPkManager*
gkr_pk_manager_new (void)
{
	return g_object_new (GKR_TYPE_PK_MANAGER, NULL);
}

GkrPkManager*
gkr_pk_manager_for_token (void)
{
	if (!manager_for_token) {
		manager_for_token = g_object_new (GKR_TYPE_PK_MANAGER, NULL);
		GKR_PK_MANAGER_GET_PRIVATE (manager_for_token)->is_token = TRUE;
		gkr_cleanup_register (cleanup_manager, NULL);
	}
	
	return manager_for_token;
}

GkrPkManager*
gkr_pk_manager_for_client (pid_t pid)
{
	if (!managers_by_pid)
		return NULL;
	return GKR_PK_MANAGER (g_hash_table_lookup (managers_by_pid, 
	                                            GUINT_TO_POINTER (pid)));
}

GkrPkManager*
gkr_pk_manager_instance_for_client (pid_t pid)
{
	GkrPkManager *manager;
	
	manager = gkr_pk_manager_for_client (pid);
	if (manager) {
		g_object_ref (manager);
		return manager;
	}
	
	manager = g_object_new (GKR_TYPE_PK_MANAGER, NULL);
	GKR_PK_MANAGER_GET_PRIVATE (manager)->for_pid = pid;
		
	/* The first client? */
	if (!managers_by_pid)
		managers_by_pid = g_hash_table_new (g_direct_hash, g_direct_equal);

	/* Note us in the table */
	g_hash_table_insert (managers_by_pid, GUINT_TO_POINTER (pid), manager);
	return manager;
}

void
gkr_pk_manager_register (GkrPkManager *objmgr, GkrPkObject *object)
{
	GkrPkManagerPrivate *pv;
	
	g_return_if_fail (GKR_IS_PK_MANAGER (objmgr));
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	pv = GKR_PK_MANAGER_GET_PRIVATE (objmgr);

	g_return_if_fail (object->manager == NULL);
	g_return_if_fail (object->digest);

	add_object (objmgr, object);
}

void
gkr_pk_manager_unregister (GkrPkManager *objmgr, GkrPkObject *object)
{
	GkrPkManagerPrivate *pv;
	
	g_return_if_fail (GKR_IS_PK_MANAGER (objmgr));
	g_return_if_fail (GKR_IS_PK_OBJECT (object));
	pv = GKR_PK_MANAGER_GET_PRIVATE (objmgr);
	
	g_return_if_fail (object->manager == objmgr);
	g_return_if_fail (object->digest);

	remove_object (objmgr, object);
}

GkrPkObject*
gkr_pk_manager_lookup (GkrPkManager *man, CK_OBJECT_HANDLE obj)
{
	GkrPkManagerPrivate *pv;
	
	g_return_val_if_fail (GKR_IS_PK_MANAGER (man), NULL);
	g_return_val_if_fail (obj != 0, NULL);
	pv = GKR_PK_MANAGER_GET_PRIVATE (man);
	
	return (GkrPkObject*)g_hash_table_lookup (pv->object_by_handle, 
	                                          GUINT_TO_POINTER (obj));
}

GList*
gkr_pk_manager_findv (GkrPkManager *objmgr, GType gtype, ...)
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
			 
			ret = gkr_pk_manager_find (objmgr, gtype, attrs);
			break;
		}	
		
		switch (gkr_pk_attribute_data_type (attr.type)) {
		case GKR_PK_DATA_ULONG:
			uval = va_arg (va, CK_ULONG);
			gkr_pk_attribute_set_ulong (&attr, uval);
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
			attrs = gkr_pk_attributes_new ();
		g_array_append_val (attrs, attr);
	}

	va_end (va);
	
	gkr_pk_attributes_free (attrs);
	return ret;
}

GList*
gkr_pk_manager_find (GkrPkManager *man, GType gtype, GArray *attrs)
{
	CK_OBJECT_CLASS *ocls = NULL;
	GkrPkObject *object;
	gboolean do_refresh = TRUE;
	GList *l, *objects = NULL;
	
	g_return_val_if_fail (GKR_IS_PK_MANAGER (man), NULL);

	/* Figure out the class of objects we're loading */
	if (attrs)
		ocls = (CK_OBJECT_CLASS*)gkr_pk_attributes_find (attrs, CKA_CLASS);
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
		gkr_pk_storage_refresh_all ();

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
gkr_pk_manager_find_by_id (GkrPkManager *objmgr, GType gtype, gkrconstid id)
{
	CK_ATTRIBUTE attr;
	GkrPkObject *object;
	gsize len;
	GList *l;
	
	g_return_val_if_fail (id, NULL);
	g_return_val_if_fail (GKR_IS_PK_MANAGER (objmgr), NULL);

	attr.pValue = (CK_VOID_PTR)gkr_id_get_raw (id, &len);
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

GkrPkObject*
gkr_pk_manager_find_by_digest (GkrPkManager *objmgr, gkrconstid digest)
{
	GkrPkManagerPrivate *pv;
	GkrPkObject *object;
	
	g_return_val_if_fail (digest, NULL);
	g_return_val_if_fail (GKR_IS_PK_MANAGER (objmgr), NULL);
	pv = GKR_PK_MANAGER_GET_PRIVATE (objmgr);

	object = GKR_PK_OBJECT (g_hash_table_lookup (pv->object_by_digest, digest));
	return object;
}
