/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "gkd-pkcs11-data.h"

#include "egg/egg-cleanup.h"
#include "egg/egg-secure-memory.h"

#include "login/gkd-login.h"

#include "pkcs11/pkcs11.h"

#include "ui/gku-prompt.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <unistd.h>

/*
 * THREADING INFO: These functions are called from multiple threads. All gkd_pkcs11_data_*()
 * functions here with the exception of gkd_pkcs11_data_free_object() are locked. Again with
 * the exception of gkd_pkcs11_data_free_object() they must not be called from one another.
 */

typedef struct _SlotData {
	gint open_sessions;
	GHashTable *session_to_data;
} SlotData;

typedef struct _SessionData {
	gpointer user_data;
	GDestroyNotify destroy_func;
} SessionData;

/* A hash table of CK_SLOT_ID_PTR to SlotData */
static GHashTable *per_slot_data = NULL;
G_LOCK_DEFINE_STATIC (pkcs11_data);

static void
free_slot_data (gpointer data)
{
	SlotData *sdata = data;
	g_assert (sdata);
	if (sdata->session_to_data)
		g_hash_table_destroy (sdata->session_to_data);
	g_slice_free (SlotData, sdata);
}

static void
free_session_data (gpointer data)
{
	SessionData *sdata = data;
	g_assert (sdata);
	if (sdata->destroy_func && sdata->user_data)
		(sdata->destroy_func) (sdata->user_data);
	g_slice_free (SessionData, sdata);
}

static gulong*
ulong_alloc (CK_ULONG value)
{
	return g_slice_dup (CK_ULONG, &value);
}

static void
ulong_free (gpointer ptr_to_ulong)
{
	g_slice_free (CK_ULONG, ptr_to_ulong);
}

static guint
ulong_hash (gconstpointer v)
{
	const signed char *p = v;
	guint32 i, h = *p;
	for(i = 0; i < sizeof (CK_ULONG); ++i)
		h = (h << 5) - h + *(p++);
	return h;
}

static gboolean
ulong_equal (gconstpointer v1, gconstpointer v2)
{
	return *((const CK_ULONG*)v1) == *((const CK_ULONG*)v2);
}

static void
store_data_unlocked (CK_SLOT_ID slot_id, CK_SESSION_HANDLE handle,
                     gpointer data, GDestroyNotify destroy_func)
{
	SessionData *sdata;
	SlotData *slot;

	/* Because we should have been notified when a session was opened */
	g_return_if_fail (per_slot_data);

	slot = g_hash_table_lookup (per_slot_data, &slot_id);
	g_return_if_fail (slot);

	/* Delayed allocation because we may never use this on a slot */
	if (slot->session_to_data == NULL)
		slot->session_to_data = g_hash_table_new_full (ulong_hash, ulong_equal, ulong_free, free_session_data);

	sdata = g_slice_new0 (SessionData);
	sdata->user_data = data;
	sdata->destroy_func = destroy_func;
	g_hash_table_replace (slot->session_to_data, ulong_alloc (handle), sdata);
}

void
gkd_pkcs11_data_session_store (CK_SLOT_ID slot_id, CK_SESSION_HANDLE handle,
                               gpointer data, GDestroyNotify destroy_func)
{
	G_LOCK(pkcs11_data);
	store_data_unlocked (slot_id, handle, data, destroy_func);
	G_UNLOCK (pkcs11_data);
}

static gpointer
lookup_data_unlocked (CK_SLOT_ID slot_id, CK_SESSION_HANDLE handle)
{
	SessionData *sdata;
	SlotData *slot;

	/* Because we should have been notified of open session */
	g_return_val_if_fail (per_slot_data, FALSE);

	/* Lookup the structure for this slot */
	slot = g_hash_table_lookup (per_slot_data, &slot_id);
	if (slot == NULL || slot->session_to_data == NULL)
		return NULL;

	sdata = g_hash_table_lookup (slot->session_to_data, &handle);
	if (sdata == NULL)
		return NULL;

	return sdata->user_data;
}

gpointer
gkd_pkcs11_data_session_lookup (CK_SLOT_ID slot_id, CK_SESSION_HANDLE handle)
{
	gpointer ret;
	G_LOCK (pkcs11_data);
	ret = lookup_data_unlocked (slot_id, handle);
	G_UNLOCK (pkcs11_data);
	return ret;
}

static void
remove_data_unlocked (CK_SLOT_ID slot_id, CK_SESSION_HANDLE handle)
{
	SlotData *slot;

	/* Because we should have been notified of open session */
	g_return_if_fail (per_slot_data);

	slot = g_hash_table_lookup (per_slot_data, &slot_id);
	g_assert (slot != NULL && slot->session_to_data != NULL);

	g_hash_table_remove (slot->session_to_data, &handle);
}

void
gkd_pkcs11_data_session_remove (CK_SLOT_ID slot_id, CK_SESSION_HANDLE handle)
{
	G_LOCK (pkcs11_data);
	remove_data_unlocked (slot_id, handle);
	G_UNLOCK (pkcs11_data);
}

void
gkd_pkcs11_data_initialized (void)
{
	G_LOCK (pkcs11_data);
	g_warn_if_fail (!per_slot_data);
	per_slot_data = g_hash_table_new_full (ulong_hash, ulong_equal, ulong_free,
	                                       (GDestroyNotify)free_slot_data);
	G_UNLOCK (pkcs11_data);
}

void
gkd_pkcs11_data_session_opened (CK_SLOT_ID slot_id, CK_SESSION_HANDLE handle)
{
	SlotData *slot;

	G_LOCK (pkcs11_data);

	slot = g_hash_table_lookup (per_slot_data, &slot_id);
	if (slot == NULL) {
		slot = g_slice_new0 (SlotData);
		g_hash_table_replace (per_slot_data, ulong_alloc (slot_id), slot);
	}

	/* Track how many open sessions there are */
	++slot->open_sessions;

	G_UNLOCK (pkcs11_data);
}

void
gkd_pkcs11_data_session_closed (CK_SLOT_ID slot_id, CK_SESSION_HANDLE handle)
{
	SlotData *slot;

	G_LOCK (pkcs11_data);

	g_warn_if_fail (per_slot_data);

	slot = g_hash_table_lookup (per_slot_data, &slot_id);
	g_warn_if_fail (slot);
	g_assert (slot->open_sessions > 0);

	/* Track how many open sessions there are */
	--(slot->open_sessions);
	if (slot->open_sessions == 0)
		g_hash_table_remove (per_slot_data, &slot_id);

	G_UNLOCK (pkcs11_data);
}

void
gkd_pkcs11_data_session_closed_all (CK_SLOT_ID id)
{
	G_LOCK (pkcs11_data);

	/* Remove all information about this slot */
	g_warn_if_fail (per_slot_data);
	g_hash_table_remove (per_slot_data, &id);

	G_UNLOCK (pkcs11_data);
}

void
gkd_pkcs11_data_finalized (void)
{
	G_LOCK (pkcs11_data);
	g_warn_if_fail (per_slot_data);
	g_hash_table_destroy (per_slot_data);
	per_slot_data = NULL;
	G_UNLOCK (pkcs11_data);
}
