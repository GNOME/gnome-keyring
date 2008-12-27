/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gp11-slot.c - the GObject PKCS#11 wrapper library

   Copyright (C) 2008, Stefan Walter

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

   Author: Stef Walter <nielsen@memberwebs.com>
*/

#include "config.h"

#include "gp11.h"
#include "gp11-private.h"
#include "gp11-marshal.h"

#include <string.h>

enum {
	PROP_0,
	PROP_MODULE,
	PROP_HANDLE,
	PROP_REUSE_SESSIONS,
	PROP_AUTO_LOGIN
};

enum {
	AUTHENTICATE_TOKEN,
#ifdef UNIMPLEMENTED
	AUTHENTICATE_KEY,
	SLOT_EVENT
#endif
	LAST_SIGNAL
};

typedef struct _GP11SlotData {
	GP11Module *module;
	CK_SLOT_ID handle;
} GP11SlotData;

typedef struct _GP11SlotPrivate {
	GP11SlotData data;
	GStaticMutex mutex;
	gboolean auto_login;
	GHashTable *open_sessions;
	GP11TokenInfo *token_info;
} GP11SlotPrivate;

G_DEFINE_TYPE (GP11Slot, gp11_slot, G_TYPE_OBJECT);

#define GP11_SLOT_GET_DATA(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GP11_TYPE_SLOT, GP11SlotData))

typedef struct _SessionPool {
	gulong flags;
	GP11Module *module; /* weak */
	GArray *sessions; /* array of CK_SESSION_HANDLE */
} SessionPool;

static guint signals[LAST_SIGNAL] = { 0 }; 

#ifndef HAVE_TIMEGM

time_t 
timegm(struct tm *t)
{
	time_t tl, tb;
	struct tm *tg;

	tl = mktime (t);
	if (tl == -1)
	{
		t->tm_hour--;
		tl = mktime (t);
		if (tl == -1)
			return -1; 
		tl += 3600;
	    }
	tg = gmtime (&tl);
	tg->tm_isdst = 0;
	tb = mktime (tg);
	if (tb == -1)
	{
		tg->tm_hour--;
		tb = mktime (tg);
		if (tb == -1)
			return -1; 
		tb += 3600;
	}
	return (tl - (tb - tl));
}

#endif

/* ----------------------------------------------------------------------------
 * HELPERS
 */

static guint
ulong_hash (gconstpointer v)
{
	const signed char *p = v;
	guint32 i, h = *p;

	for(i = 0; i < sizeof (gulong); ++i)
		h = (h << 5) - h + *(p++);

	return h;
}

static gboolean
ulong_equal (gconstpointer v1, gconstpointer v2)
{
	return *((const gulong*)v1) == *((const gulong*)v2);
}

static void
close_session (GP11Module *module, CK_SESSION_HANDLE handle)
{
	CK_FUNCTION_LIST_PTR funcs;
	CK_RV rv; 
	
	g_return_if_fail (GP11_IS_MODULE (module));
	
	g_object_ref (module);
	
	funcs = gp11_module_get_function_list (module);
	g_return_if_fail (funcs);
	
	rv = (funcs->C_CloseSession) (handle);
	if (rv != CKR_OK) {
		g_warning ("couldn't close session properly: %s",
		           gp11_message_from_rv (rv));
	}
	
	g_object_unref (module);
}

static GP11SlotPrivate*
lock_private (gpointer obj)
{
	GP11SlotPrivate *pv;
	GP11Slot *self;
	
	g_assert (GP11_IS_SLOT (obj));
	self = GP11_SLOT (obj);
	
	g_object_ref (self);
	
	pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GP11_TYPE_SLOT, GP11SlotPrivate);
	g_static_mutex_lock (&pv->mutex);
	
	return pv;
}

static void
unlock_private (gpointer obj, GP11SlotPrivate *pv)
{
	GP11Slot *self;

	g_assert (pv);
	g_assert (GP11_IS_SLOT (obj));
	
	self = GP11_SLOT (obj);
	
	g_assert (G_TYPE_INSTANCE_GET_PRIVATE (self, GP11_TYPE_SLOT, GP11SlotPrivate) == pv);
	
	g_static_mutex_unlock (&pv->mutex);
	g_object_unref (self);
}

static void
free_session_pool (gpointer p)
{
	SessionPool *pool = p;
	guint i;
	
	for(i = 0; i < pool->sessions->len; ++i)
		close_session (pool->module, g_array_index(pool->sessions, CK_SESSION_HANDLE, i));
	g_array_free(pool->sessions, TRUE);
	g_free (pool);
}

static gboolean
push_session_table (GP11SlotPrivate *pv, gulong flags, CK_SESSION_HANDLE handle)
{
	SessionPool *pool;

	g_assert (handle);
	g_assert (GP11_IS_MODULE (pv->data.module));

	if (pv->open_sessions == NULL)
		return FALSE;
		
	pool = g_hash_table_lookup (pv->open_sessions, &flags);
	if (!pool) {
		pool = g_new0 (SessionPool, 1);
		pool->flags = flags;
		pool->module = pv->data.module; /* weak ref */
		pool->sessions = g_array_new (FALSE, TRUE, sizeof (CK_SESSION_HANDLE));
		g_hash_table_insert (pv->open_sessions, g_memdup (&flags, sizeof (flags)), pool);
	}
	
	g_assert (pool->flags == flags);
	g_array_append_val (pool->sessions, handle);
	return TRUE;
}

static CK_SESSION_HANDLE
pop_session_table (GP11SlotPrivate *pv, gulong flags)
{
	CK_SESSION_HANDLE result = 0;
	SessionPool *pool;

	g_return_val_if_fail (pv, 0);


	g_assert (GP11_IS_MODULE (pv->data.module));

	if (pv->open_sessions) {
		pool = g_hash_table_lookup (pv->open_sessions, &flags);
		if (pool) {
			g_assert (pool->sessions->len > 0);
			result = g_array_index (pool->sessions, CK_SESSION_HANDLE, pool->sessions->len - 1);
			g_assert (result != 0);
			g_array_remove_index_fast (pool->sessions, pool->sessions->len - 1);
			if (!pool->sessions->len)
				g_hash_table_remove(pv->open_sessions, &flags);
		}
	}

	return result;
}

static void
destroy_session_table (GP11SlotPrivate *pv)
{
	if (pv->open_sessions)
		g_hash_table_unref (pv->open_sessions);
	pv->open_sessions = NULL;
}

static void
create_session_table (GP11SlotPrivate *pv)
{
	if (!pv->open_sessions)
		pv->open_sessions = g_hash_table_new_full (ulong_hash, ulong_equal, g_free, free_session_pool);
}

static gboolean
reuse_session_handle (GP11Session *session, CK_SESSION_HANDLE handle, GP11Slot *self)
{
	GP11SlotData *data = GP11_SLOT_GET_DATA (self);
	GP11SlotPrivate *pv;
	CK_FUNCTION_LIST_PTR funcs;
	CK_SESSION_INFO info;
	gboolean handled = FALSE;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SESSION (session), FALSE);
	g_return_val_if_fail (GP11_IS_SLOT (self), FALSE);
	
	funcs = gp11_module_get_function_list (data->module);
	g_return_val_if_fail (funcs, FALSE);

	/* Get the session info so we know where to categorize this */
	rv = (funcs->C_GetSessionInfo) (handle, &info);

	if (rv == CKR_OK) {
	
		/* Keep this one around for later use */
		pv = lock_private (self);
		
		{
			handled = push_session_table (pv, info.flags, handle);
		}
		
		unlock_private (self, pv);
	
	} else {
	
		/* An already closed session, we don't want to bother with */
		if (rv == CKR_SESSION_CLOSED || rv == CKR_SESSION_HANDLE_INVALID)
			handled = TRUE;
	}

	return handled;
}

static GP11Session*
make_session_object (GP11Slot *self, gulong flags, CK_SESSION_HANDLE handle)
{
	GP11Session *session;

	g_return_val_if_fail (handle != 0, NULL);

	g_object_ref (self);
	
		session = gp11_session_from_handle (self, handle);
		g_return_val_if_fail (session != NULL, NULL);
	
		/* Session keeps a reference to us, so this is safe */
		g_signal_connect (session, "discard-handle", G_CALLBACK (reuse_session_handle), self);
	
	g_object_unref (self);
	
	return session;
}

/* ----------------------------------------------------------------------------
 * OBJECT
 */

static void
gp11_slot_init (GP11Slot *self)
{
	GP11SlotPrivate *pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GP11_TYPE_SLOT, GP11SlotPrivate);
	g_static_mutex_init (&pv->mutex);
}

static void
gp11_slot_get_property (GObject *obj, guint prop_id, GValue *value, 
                        GParamSpec *pspec)
{
	GP11Slot *self = GP11_SLOT (obj);
	
	switch (prop_id) {
	case PROP_MODULE:
		g_value_take_object (value, gp11_slot_get_module (self));
		break;
	case PROP_HANDLE:
		g_value_set_ulong (value, gp11_slot_get_handle (self));
		break;
	case PROP_AUTO_LOGIN:
		g_value_set_boolean (value, gp11_slot_get_auto_login (self));
		break;
	case PROP_REUSE_SESSIONS:
		g_value_set_boolean (value, gp11_slot_get_reuse_sessions (self));
		break;
	}
}

static void
gp11_slot_set_property (GObject *obj, guint prop_id, const GValue *value, 
                        GParamSpec *pspec)
{
	GP11SlotData *data = GP11_SLOT_GET_DATA (obj);
	GP11Slot *self = GP11_SLOT (obj);

	/* All writes to data members below, happen only during construct phase */

	switch (prop_id) {
	case PROP_MODULE:
		g_assert (!data->module);
		data->module = g_value_get_object (value);
		g_assert (data->module);
		g_object_ref (data->module);
		break;
	case PROP_HANDLE:
		g_assert (!data->handle);
		data->handle = g_value_get_ulong (value);
		break;
	case PROP_AUTO_LOGIN:
		gp11_slot_set_auto_login (self, g_value_get_boolean (value));
		break;
	case PROP_REUSE_SESSIONS:
		gp11_slot_set_reuse_sessions (self, g_value_get_boolean (value));
		break;
	}
}

static void
gp11_slot_dispose (GObject *obj)
{
	GP11SlotPrivate *pv = lock_private (obj);
	
	{
		/* Need to do this before the module goes away */
		destroy_session_table (pv);
	}

	unlock_private (obj, pv);

	G_OBJECT_CLASS (gp11_slot_parent_class)->dispose (obj);
}

static void
gp11_slot_finalize (GObject *obj)
{
	GP11SlotPrivate *pv = G_TYPE_INSTANCE_GET_PRIVATE (obj, GP11_TYPE_SLOT, GP11SlotPrivate);
	GP11SlotData *data = GP11_SLOT_GET_DATA (obj);
	
	data->handle = 0;
	
	g_assert (!pv->open_sessions);
	
	if (data->module)
		g_object_unref (data->module);
	data->module = NULL;
		
	if (pv->token_info)
		gp11_token_info_free (pv->token_info);
	pv->token_info = NULL;	

	g_static_mutex_free (&pv->mutex);
	
	G_OBJECT_CLASS (gp11_slot_parent_class)->finalize (obj);
}


static void
gp11_slot_class_init (GP11SlotClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	gp11_slot_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->get_property = gp11_slot_get_property;
	gobject_class->set_property = gp11_slot_set_property;
	gobject_class->dispose = gp11_slot_dispose;
	gobject_class->finalize = gp11_slot_finalize;
	
	g_object_class_install_property (gobject_class, PROP_MODULE,
		g_param_spec_object ("module", "Module", "PKCS11 Module",
		                     GP11_TYPE_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_HANDLE,
		g_param_spec_ulong ("handle", "Handle", "PKCS11 Slot ID",
		                   0, G_MAXULONG, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_AUTO_LOGIN,
		g_param_spec_boolean ("auto-login", "Auto Login", "Auto Login to Token when necessary",
		                      FALSE, G_PARAM_READWRITE));
	
	g_object_class_install_property (gobject_class, PROP_REUSE_SESSIONS,
		g_param_spec_boolean ("reuse-sessions", "Reuse Sessions", "Reuse sessions?",
		                      FALSE, G_PARAM_READWRITE));
	
	signals[AUTHENTICATE_TOKEN] = g_signal_new ("authenticate-token", GP11_TYPE_SLOT, 
			G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GP11SlotClass, authenticate_token),
			g_signal_accumulator_true_handled, NULL, _gp11_marshal_BOOLEAN__POINTER, 
			G_TYPE_BOOLEAN, 1, G_TYPE_POINTER);

	g_type_class_add_private (gobject_class, sizeof (GP11SlotPrivate));
}

/* ----------------------------------------------------------------------------
 * INTERNAL
 */

gboolean 
_gp11_slot_token_authentication (GP11Slot *self, gchar **password)
{
	GP11SlotPrivate *pv = lock_private (self);
	gboolean emit_signal = FALSE;
	gboolean ret = FALSE;

	g_return_val_if_fail (GP11_IS_SLOT (self), FALSE);
	g_return_val_if_fail (password, FALSE);

	{
		if (pv->auto_login) {
			
			/* 
			 * If it's a protected authentication path style token, then 
			 * we don't prompt here, the hardware/software is expected
			 * to prompt the user in some other way.
			 */
			
			if (!pv->token_info) 
				pv->token_info = gp11_slot_get_token_info (self);

			if (pv->token_info && (pv->token_info->flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
				*password = NULL;
				ret = TRUE;
			} else {
				emit_signal = TRUE;
			}
		}
	}
	
	unlock_private (self, pv);

	if (emit_signal)
		g_signal_emit (self, signals[AUTHENTICATE_TOKEN], 0, password, &ret);

	return ret;
}

/* ----------------------------------------------------------------------------
 * PUBLIC 
 */

/**
 * gp11_slot_info_free:
 * @slot_info: The slot info to free, or NULL.
 * 
 * Free the GP11SlotInfo and associated resources. 
 **/
void
gp11_slot_info_free (GP11SlotInfo *slot_info)
{
	if (!slot_info)
		return;
	g_free (slot_info->slot_description);
	g_free (slot_info->manufacturer_id);
	g_free (slot_info);
}

/**
 * gp11_token_info_free:
 * @token_info: The token info to free, or NULL.
 * 
 * Free the GP11TokenInfo and associated resources.
 **/
void
gp11_token_info_free (GP11TokenInfo *token_info)
{
	if (!token_info)
		return;
	g_free (token_info->label);
	g_free (token_info->manufacturer_id);
	g_free (token_info->model);
	g_free (token_info->serial_number);
	g_free (token_info);
}

/**
 * gp11_mechanism_info_free:
 * @mech_info: The mechanism info to free, or NULL.
 * 
 * Free the GP11MechanismInfo and associated resources.
 **/
void
gp11_mechanism_info_free (GP11MechanismInfo *mech_info)
{
	if (!mech_info)
		return;
	g_free (mech_info);
}

/**
 * gp11_slot_get_handle:
 * @self: The slot to get the handle of.
 * 
 * Get the raw PKCS#11 handle of a slot.
 * 
 * Return value: The raw handle.
 **/
CK_SLOT_ID
gp11_slot_get_handle (GP11Slot *self)
{
	GP11SlotData *data = GP11_SLOT_GET_DATA (self);
	g_return_val_if_fail (GP11_IS_SLOT (self), (CK_SLOT_ID)-1);
	return data->handle;
}

/**
 * gp11_slot_get_module:
 * @self: The slot to get the module for.
 * 
 * Get the module that this slot is on.
 * 
 * Return value: The module, you must unreference this after you're done with it.
 */
GP11Module*
gp11_slot_get_module (GP11Slot *self)
{
	GP11SlotData *data = GP11_SLOT_GET_DATA (self);
	g_return_val_if_fail (GP11_IS_SLOT (self), NULL);
	g_return_val_if_fail (GP11_IS_MODULE (data->module), NULL);
	return g_object_ref (data->module);
}

/**
 * gp11_slot_get_reuse_sessions:
 * @self: The slot to get setting from.
 * 
 * Get the reuse sessions setting. When this is set, sessions
 * will be pooled and reused if their flags match when 
 * gp11_slot_open_session() is called. 
 * 
 * Return value: Whether reusing sessions or not.
 **/
gboolean
gp11_slot_get_reuse_sessions (GP11Slot *self)
{
	GP11SlotPrivate *pv = lock_private (self);
	gboolean ret;
	
	g_return_val_if_fail (pv, FALSE);
	
	{
		ret = pv->open_sessions != NULL;
	}
	
	unlock_private (self, pv);

	return ret;
}

/**
 * gp11_slot_set_reuse_sessions:
 * @self: The slot to set the setting on.
 * @reuse: Whether to reuse sessions or not.
 * 
 * When this is set, sessions will be pooled and reused
 * if their flags match when gp11_slot_open_session() is called.
 **/
void
gp11_slot_set_reuse_sessions (GP11Slot *self, gboolean reuse)
{
	GP11SlotPrivate *pv = lock_private (self);

	g_return_if_fail (pv);
	
	{
		if (reuse)
			create_session_table (pv);
		else
			destroy_session_table (pv);
	}
	
	unlock_private (self, pv);
	g_object_notify (G_OBJECT (self), "reuse-sessions");
}

/**
 * gp11_slot_get_auto_login:
 * @self: The slot to get setting from.
 * 
 * Get the auto login setting. When this is set, this slot 
 * will emit the 'authenticate-token' signal when a session
 * requires authentication.
 * 
 * Return value: Whether auto login or not.
 **/
gboolean
gp11_slot_get_auto_login (GP11Slot *self)
{
	GP11SlotPrivate *pv = lock_private (self);
	gboolean ret;
	
	g_return_val_if_fail (pv, FALSE);
	
	{
		ret = pv->auto_login;
	}
	
	unlock_private (self, pv);

	return ret;
}

/**
 * gp11_slot_set_auto_login:
 * @self: The slot to set the setting on.
 * @auto_login: Whether auto login or not.
 * 
 * When this is set, this slot 
 * will emit the 'authenticate-token' signal when a session
 * requires authentication.
 **/
void
gp11_slot_set_auto_login (GP11Slot *self, gboolean auto_login)
{
	GP11SlotPrivate *pv = lock_private (self);

	g_return_if_fail (pv);
	
	{
		pv->auto_login = auto_login;
	}
	
	unlock_private (self, pv);
	g_object_notify (G_OBJECT (self), "auto-login");
}

/**
 * gp11_slot_get_info:
 * @self: The slot to get info for.
 * 
 * Get the information for this slot.
 * 
 * Return value: The slot information. When done, use gp11_slot_info_free()
 * to release it.
 **/
GP11SlotInfo*
gp11_slot_get_info (GP11Slot *self)
{
	CK_SLOT_ID handle = (CK_SLOT_ID)-1;
	GP11Module *module = NULL;
	CK_FUNCTION_LIST_PTR funcs;
	GP11SlotInfo *slotinfo;
	CK_SLOT_INFO info;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SLOT (self), NULL);
	
	g_object_get (self, "module", &module, "handle", &handle, NULL);
	g_return_val_if_fail (GP11_IS_MODULE (module), NULL);
	
	funcs = gp11_module_get_function_list (module);
	g_return_val_if_fail (funcs, NULL);
	
	memset (&info, 0, sizeof (info));
	rv = (funcs->C_GetSlotInfo) (handle, &info);
	
	g_object_unref (module);
	
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot info: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	slotinfo = g_new0 (GP11SlotInfo, 1);
	slotinfo->slot_description = gp11_string_from_chars (info.slotDescription, 
	                                                     sizeof (info.slotDescription));
	slotinfo->manufacturer_id = gp11_string_from_chars (info.manufacturerID, 
	                                                    sizeof (info.manufacturerID));
	slotinfo->flags = info.flags;
	slotinfo->hardware_version_major = info.hardwareVersion.major;
	slotinfo->hardware_version_minor = info.hardwareVersion.minor;
	slotinfo->firmware_version_major = info.firmwareVersion.major;
	slotinfo->firmware_version_minor = info.firmwareVersion.minor;

	return slotinfo;
}

/**
 * gp11_slot_get_token_info:
 * @self: The slot to get info for.
 * 
 * Get the token information for this slot.
 * 
 * Return value: The token information. When done, use gp11_token_info_free()
 * to release it.
 **/
GP11TokenInfo*
gp11_slot_get_token_info (GP11Slot *self)
{
	CK_SLOT_ID handle = (CK_SLOT_ID)-1;
	CK_FUNCTION_LIST_PTR funcs;
	GP11Module *module = NULL;
	GP11TokenInfo *tokeninfo;
	CK_TOKEN_INFO info;
	gchar *string;
	struct tm tm;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SLOT (self), NULL);

	g_object_get (self, "module", &module, "handle", &handle, NULL);
	g_return_val_if_fail (GP11_IS_MODULE (module), NULL);
	
	funcs = gp11_module_get_function_list (module);
	g_return_val_if_fail (funcs, NULL);
	
	memset (&info, 0, sizeof (info));
	rv = (funcs->C_GetTokenInfo) (handle, &info);
	
	g_object_unref (module);
	
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot info: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	tokeninfo = g_new0 (GP11TokenInfo, 1);
	tokeninfo->label = gp11_string_from_chars (info.label, sizeof (info.label));
	tokeninfo->model = gp11_string_from_chars (info.model, sizeof (info.model));
	tokeninfo->manufacturer_id = gp11_string_from_chars (info.manufacturerID, 
	                                                     sizeof (info.manufacturerID));
	tokeninfo->serial_number = gp11_string_from_chars (info.serialNumber, 
	                                                   sizeof (info.serialNumber));
	tokeninfo->flags = info.flags;
	tokeninfo->max_session_count = info.ulMaxSessionCount;
	tokeninfo->session_count = info.ulSessionCount;
	tokeninfo->max_rw_session_count = info.ulMaxRwSessionCount;
	tokeninfo->rw_session_count = info.ulRwSessionCount;
	tokeninfo->max_pin_len = info.ulMaxPinLen;
	tokeninfo->min_pin_len = info.ulMinPinLen;
	tokeninfo->total_public_memory = info.ulTotalPublicMemory;
	tokeninfo->total_private_memory = info.ulTotalPrivateMemory;
	tokeninfo->free_private_memory = info.ulFreePrivateMemory;
	tokeninfo->free_public_memory = info.ulFreePublicMemory;
	tokeninfo->hardware_version_major = info.hardwareVersion.major;
	tokeninfo->hardware_version_minor = info.hardwareVersion.minor;
	tokeninfo->firmware_version_major = info.firmwareVersion.major;
	tokeninfo->firmware_version_minor = info.firmwareVersion.minor;
	
	/* Parse the time into seconds since epoch */
	if (info.flags & CKF_CLOCK_ON_TOKEN) {
		string = g_strndup ((gchar*)info.utcTime, MIN (14, sizeof (info.utcTime)));
		if (!strptime (string, "%Y%m%d%H%M%S", &tm))
			tokeninfo->utc_time = -1;
		else
			tokeninfo->utc_time = timegm (&tm);
	} else {
		tokeninfo->utc_time = -1;
	}
	
	return tokeninfo;
}

/**
 * gp11_slot_get_mechanisms:
 * @self: The slot to get mechanisms for.
 * 
 * Get the available mechanisms for this slot.
 * 
 * Return value: A list of the mechanisms for this slot. Use 
 * gp11_mechanisms_free() when done with this.
 **/
GP11Mechanisms*
gp11_slot_get_mechanisms (GP11Slot *self)
{
	CK_SLOT_ID handle = (CK_SLOT_ID)-1;
	CK_FUNCTION_LIST_PTR funcs;
	GP11Module *module = NULL;
	CK_MECHANISM_TYPE_PTR mech_list;
	CK_ULONG count, i;
	GP11Mechanisms *result;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SLOT (self), NULL);

	g_object_get (self, "module", &module, "handle", &handle, NULL);
	g_return_val_if_fail (GP11_IS_MODULE (module), NULL);

	funcs = gp11_module_get_function_list (module);
	g_return_val_if_fail (funcs, NULL);
	
	rv = (funcs->C_GetMechanismList) (handle, NULL, &count);
	if (rv != CKR_OK) {
		g_warning ("couldn't get mechanism count: %s", gp11_message_from_rv (rv));
		count = 0;
	} else {
		mech_list = g_new (CK_MECHANISM_TYPE, count);
		rv = (funcs->C_GetMechanismList) (handle, mech_list, &count);
		if (rv != CKR_OK) {
			g_warning ("couldn't get mechanism list: %s", gp11_message_from_rv (rv));
			g_free (mech_list);
			count = 0;
		}
	}
	
	g_object_unref (module);
	
	if (!count)
		return NULL;
	
	result = g_array_new (FALSE, TRUE, sizeof (CK_MECHANISM_TYPE));
	for (i = 0; i < count; ++i)
		g_array_append_val (result, mech_list[i]);
	
	g_free (mech_list);
	return result;

}

/**
 * gp11_slot_get_mechanism_info:
 * @self: The slot to get mechanism info from.
 * @mech_type: The mechanisms type to get info for.
 * 
 * Get information for the specified mechanism.
 * 
 * Return value: The mechanism information, or NULL if failed. Use 
 * gp11_mechanism_info_free() when done with it.
 **/
GP11MechanismInfo*
gp11_slot_get_mechanism_info (GP11Slot *self, gulong mech_type)
{
	CK_SLOT_ID handle = (CK_SLOT_ID)-1;
	CK_FUNCTION_LIST_PTR funcs;
	GP11MechanismInfo *mechinfo;
	GP11Module *module = NULL;
	CK_MECHANISM_INFO info;
	struct tm;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SLOT (self), NULL);

	g_object_get (self, "module", &module, "handle", &handle, NULL);
	g_return_val_if_fail (GP11_IS_MODULE (module), NULL);
	
	funcs = gp11_module_get_function_list (module);
	g_return_val_if_fail (funcs, NULL);
		
	memset (&info, 0, sizeof (info));
	rv = (funcs->C_GetMechanismInfo) (handle, mech_type, &info);
	
	g_object_unref (module);
	
	if (rv != CKR_OK) {
		g_warning ("couldn't get mechanism info: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	mechinfo = g_new0 (GP11MechanismInfo, 1);
	mechinfo->flags = info.flags;
	mechinfo->max_key_size = info.ulMaxKeySize;
	mechinfo->min_key_size = info.ulMinKeySize;
	
	return mechinfo;
}

#if UNIMPLEMENTED

typedef struct InitToken {
	GP11Arguments base;
	const guchar *pin;
	gsize length;
	const gchar *label;
} InitToken;

static CK_RV
perform_init_token (InitToken *args)
{
	return (args->base.pkcs11->C_InitToken) (args->base.handle, 
	                                         args->pin, args->length, 
	                                         args->label);
}

gboolean
gp11_slot_init_token (GP11Slot *self, const guchar *pin, gsize length, 
                      const gchar *label, GCancellable *cancellable,
                      GError **err)
{
	InitToken args = { GP11_ARGUMENTS_INIT, pin, length, label };
	return _gp11_call_sync (self, perform_init_token, &args, err);
}

void
gp11_slot_init_token_async (GP11Slot *self, const guchar *pin, gsize length, 
                            const gchar *label, GCancellable *cancellable,
                            GAsyncReadyCallback callback, gpointer user_data)
{
	InitToken* args = _gp11_call_async_prep (self, self, perform_init_token, 
	                                         sizeof (*args));
	
	args->pin = pin;
	args->length = length;
	args->label = label;
	
	_gp11_call_async_go (args, cancellable, callback, user_data);
}
	
gboolean
gp11_slot_init_token_finish (GP11Slot *self, GAsyncResult *result, GError **err)
{
	return _gp11_call_basic_finish (self, result, err);
}

#endif /* UNIMPLEMENTED */

typedef struct OpenSession {
	GP11Arguments base;
	gulong flags;
	CK_SESSION_HANDLE session;
} OpenSession;

static CK_RV
perform_open_session (OpenSession *args)
{
	return (args->base.pkcs11->C_OpenSession) (args->base.handle, 
	                                           args->flags | CKF_SERIAL_SESSION, 
	                                           NULL, NULL, &args->session);
}

/**
 * gp11_slot_open_session:
 * @self: The slot ot open a session on.
 * @flags: The flags to open a session with.
 * @err: A location to return an error, or NULL.
 * 
 * Open a session on the slot. If the 'auto reuse' setting is set,
 * then this may be a recycled session with the same flags.
 * 
 * This call may block for an indefinite period.
 * 
 * Return value: A new session or NULL if an error occurs.
 **/
GP11Session*
gp11_slot_open_session (GP11Slot *self, gulong flags, GError **err)
{
	return gp11_slot_open_session_full (self, flags, NULL, err);
}

/**
 * gp11_slot_open_session_full:
 * @self: The slot to open a session on.
 * @flags: The flags to open a session with.
 * @cancellable: Optional cancellation object, or NULL.
 * @err: A location to return an error, or NULL.
 * 
 * Open a session on the slot. If the 'auto reuse' setting is set,
 * then this may be a recycled session with the same flags.
 * 
 * This call may block for an indefinite period.
 * 
 * Return value: A new session or NULL if an error occurs.
 **/
GP11Session*
gp11_slot_open_session_full (GP11Slot *self, gulong flags, GCancellable *cancellable, GError **err)
{
	GP11SlotPrivate *pv;
	GP11Session *session = NULL;
	CK_SESSION_HANDLE handle;

	flags |= CKF_SERIAL_SESSION;
	
	g_object_ref (self);
	
	pv = lock_private (self);
	
	{
		/* Try to use a cached session */
		handle = pop_session_table (pv, flags);
		if (handle != 0) 
			session = make_session_object (self, flags, handle);
	}

	unlock_private (self, pv);

	/* Open a new session */
	if (session == NULL) {
		OpenSession args = { GP11_ARGUMENTS_INIT, flags, 0 };
		if (_gp11_call_sync (self, perform_open_session, &args, cancellable, err))
			session = make_session_object (self, flags, args.session);
	}

	g_object_unref (self);
	
	return session;
}

/**
 * gp11_slot_open_session_async:
 * @self: The slot to open a session on.
 * @flags: The flags to open a session with.
 * @cancellable: Optional cancellation object, or NULL.
 * @callback: Called when the operation completes.
 * @user_data: Data to pass to the callback.
 * 
 * Open a session on the slot. If the 'auto reuse' setting is set,
 * then this may be a recycled session with the same flags.
 * 
 * This call will return immediately and complete asynchronously.
 **/
void
gp11_slot_open_session_async (GP11Slot *self, gulong flags, GCancellable *cancellable, 
                              GAsyncReadyCallback callback, gpointer user_data)
{
	GP11SlotPrivate *pv;
	GP11Call *call;
	OpenSession *args;

	flags |= CKF_SERIAL_SESSION;
	
	g_object_ref (self);
	
	args =  _gp11_call_async_prep (self, self, perform_open_session, sizeof (*args), NULL);
	
	pv = lock_private (self);

	{
		/* Try to use a cached session */
		args->session = pop_session_table (pv, flags);
		args->flags = flags;
	}
	
	unlock_private (self, pv);
	
	call = _gp11_call_async_ready (args, cancellable, callback, user_data);
	if (args->session)
		_gp11_call_async_short (call, CKR_OK);
	else
		_gp11_call_async_go (call);
	
	g_object_unref (self);
}

/**
 * gp11_slot_open_session_finish:
 * @self: The slot to open a session on.
 * @result: The result passed to the callback.
 * @err: A location to return an error or NULL.
 * 
 * Get the result of an open session operation. If the 'auto reuse' setting is set,
 * then this may be a recycled session with the same flags.
 * 
 * Return value: The new session or NULL if an error occurs.
 */
GP11Session*
gp11_slot_open_session_finish (GP11Slot *self, GAsyncResult *result, GError **err)
{
	GP11Session *session = NULL;

	g_object_ref (self);
	
	{
		OpenSession *args;

		if (_gp11_call_basic_finish (result, err)) {
			args = _gp11_call_arguments (result, OpenSession);
			session = make_session_object (self, args->flags, args->session);
		}
	}
	
	g_object_unref (self);
	
	return session;
}
