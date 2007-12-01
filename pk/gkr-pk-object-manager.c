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
#include "gkr-pk-object-storage.h"
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
	
	/* Note objects is being managed */
	objmgr->objects = g_list_prepend (objmgr->objects, object);
	object->manager = objmgr;
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
	
	/* Release object management */		
	objmgr->objects = g_list_remove (objmgr->objects, object);
	object->manager = NULL;
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
}

static void
gkr_pk_object_manager_dispose (GObject *obj)
{
	GkrPkObjectManager *objmgr = GKR_PK_OBJECT_MANAGER (obj);
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (obj);
 	
 	g_hash_table_remove_all (pv->object_by_handle);
 	g_hash_table_remove_all (pv->object_by_unique);
 	
 	g_list_free (objmgr->objects);
 	objmgr->objects = NULL;

	G_OBJECT_CLASS (gkr_pk_object_manager_parent_class)->dispose (obj);
}

static void
gkr_pk_object_manager_finalize (GObject *obj)
{
	GkrPkObjectManager *man = GKR_PK_OBJECT_MANAGER (obj);
 	GkrPkObjectManagerPrivate *pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (obj);
 	
	g_hash_table_destroy (pv->object_by_handle);
	g_hash_table_destroy (pv->object_by_unique);
	g_assert (!man->objects);

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
			attrs = gkr_pk_attributes_new ();
		g_array_append_val (attrs, attr);
	}

	va_end (va);
	
	gkr_pk_attributes_free (attrs);
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
		gkr_pk_object_storage_refresh (NULL);

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

GkrPkObject*
gkr_pk_object_manager_find_by_unique (GkrPkObjectManager *objmgr, gkrconstunique unique)
{
	GkrPkObjectManagerPrivate *pv;
	GkrPkObject *object;
	
	if (!objmgr)
		objmgr = gkr_pk_object_manager_get ();
		
	g_return_val_if_fail (unique, NULL);
	g_return_val_if_fail (GKR_IS_PK_OBJECT_MANAGER (objmgr), NULL);
	pv = GKR_PK_OBJECT_MANAGER_GET_PRIVATE (objmgr);

	object = GKR_PK_OBJECT (g_hash_table_lookup (pv->object_by_unique, unique));
	return object;
}
