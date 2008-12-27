/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gp11-session.h - the GObject PKCS#11 wrapper library

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
#include "gp11-marshal.h"
#include "gp11-private.h"

#include <string.h>

enum {
	DISCARD_HANDLE,
	LAST_SIGNAL
};

enum {
	PROP_0,
	PROP_MODULE,
	PROP_HANDLE,
	PROP_SLOT
};

typedef struct _GP11SessionData {
	GP11Slot *slot;
	GP11Module *module;
	CK_SESSION_HANDLE handle;
	gint discarded;
} GP11SessionData;

typedef struct _GP11SessionPrivate {
	GP11SessionData data;
	/* Add mutex and future MT-unsafe members here */
} GP11SessionPrivate;

#define GP11_SESSION_GET_DATA(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GP11_TYPE_SESSION, GP11SessionData))

G_DEFINE_TYPE (GP11Session, gp11_session, G_TYPE_OBJECT);

static guint signals[LAST_SIGNAL] = { 0 };

/* ----------------------------------------------------------------------------
 * OBJECT
 */

static gboolean
gp11_session_real_discard_handle (GP11Session *self, CK_OBJECT_HANDLE handle)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (self);
	CK_FUNCTION_LIST_PTR funcs;
	CK_RV rv;

	/* The default functionality, close the handle */

	g_return_val_if_fail (data->module, FALSE);
	g_object_ref (data->module);
	
	funcs = gp11_module_get_function_list (data->module);
	g_return_val_if_fail (funcs, FALSE);
	
	rv = (funcs->C_CloseSession) (handle);
	if (rv != CKR_OK) {
		g_warning ("couldn't close session properly: %s",
		           gp11_message_from_rv (rv));
	}
	
	g_object_unref (data->module);
	return TRUE;
}

static void
gp11_session_init (GP11Session *self)
{

}

static void
gp11_session_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
	GP11Session *self = GP11_SESSION (obj);

	switch (prop_id) {
	case PROP_MODULE:
		g_value_take_object (value, gp11_session_get_module (self));
		break;
	case PROP_HANDLE:
		g_value_set_ulong (value, gp11_session_get_handle (self));
		break;
	case PROP_SLOT:
		g_value_take_object (value, gp11_session_get_slot (self));
		break;
	}
}

static void
gp11_session_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (obj);
	
	/* Only valid calls are from constructor */

	switch (prop_id) {
	case PROP_MODULE:
		g_return_if_fail (!data->module);
		data->module = g_value_dup_object (value);
		g_return_if_fail (data->module);
		break;
	case PROP_HANDLE:
		g_return_if_fail (!data->handle);
		data->handle = g_value_get_ulong (value);
		break;
	case PROP_SLOT:
		g_return_if_fail (!data->slot);
		data->slot = g_value_dup_object (value);
		g_return_if_fail (data->slot);
		break;
	}
}

static void
gp11_session_dispose (GObject *obj)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (obj);
	GP11Session *self = GP11_SESSION (obj);
	gboolean handled;
	gint discarded;

	g_return_if_fail (GP11_IS_SESSION (self));
	
	discarded = g_atomic_int_get (&data->discarded);
	if (!discarded && g_atomic_int_compare_and_exchange (&data->discarded, discarded, 1)) {
	
		/* 
		 * Let the world know that we're discarding the session 
		 * handle. This allows session reuse to work.
		 */
		
		g_signal_emit_by_name (self, "discard-handle", data->handle, &handled);
		g_return_if_fail (handled);

	}

	G_OBJECT_CLASS (gp11_session_parent_class)->dispose (obj);
}

static void
gp11_session_finalize (GObject *obj)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (obj);

	g_assert (data->discarded != 0);
	
	if (data->slot)
		g_object_unref (data->slot);
	data->slot = NULL;

	if (data->module)
		g_object_unref (data->module);
	data->module = NULL;
	
	G_OBJECT_CLASS (gp11_session_parent_class)->finalize (obj);
}

static void
gp11_session_class_init (GP11SessionClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	gp11_session_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->get_property = gp11_session_get_property;
	gobject_class->set_property = gp11_session_set_property;
	gobject_class->dispose = gp11_session_dispose;
	gobject_class->finalize = gp11_session_finalize;
	
	klass->discard_handle = gp11_session_real_discard_handle;
	
	g_object_class_install_property (gobject_class, PROP_MODULE,
		g_param_spec_object ("module", "Module", "PKCS11 Module",
		                     GP11_TYPE_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_HANDLE,
		g_param_spec_ulong ("handle", "Session Handle", "PKCS11 Session Handle",
		                    0, G_MAXULONG, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_SLOT,
		g_param_spec_object ("slot", "Slot that this session uses", "PKCS11 Slot",
		                     GP11_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	signals[DISCARD_HANDLE] = g_signal_new ("discard-handle", GP11_TYPE_SESSION, 
	                G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GP11SessionClass, discard_handle),
			g_signal_accumulator_true_handled, NULL, 
			_gp11_marshal_BOOLEAN__ULONG, G_TYPE_BOOLEAN, 1, G_TYPE_ULONG);
	
	g_type_class_add_private (klass, sizeof (GP11SessionPrivate));
}

/* ----------------------------------------------------------------------------
 * PUBLIC 
 */

/**
 * gp11_session_info_free:
 * @session_info: Session info to free.
 * 
 * Free the GP11SessionInfo structure and all associated memory.
 **/
void
gp11_session_info_free (GP11SessionInfo *session_info)
{
	if (!session_info)
		return;
	g_free (session_info);
}

/**
 * gp11_session_from_handle:
 * @slot: The slot which the session belongs to.
 * @handle: The raw PKCS#11 handle of the session.
 * 
 * Initialize a GP11Session object from a raw PKCS#11 session handle.
 * Usually one would use the gp11_slot_open_session() function to 
 * create a session.
 * 
 * Return value: The new GP11Session object.
 **/
GP11Session*
gp11_session_from_handle (GP11Slot *slot, CK_SESSION_HANDLE handle)
{
	GP11Module *module;
	GP11Session *session;
	
	g_return_val_if_fail (GP11_IS_SLOT (slot), NULL);
	
	module = gp11_slot_get_module (slot);
	session = g_object_new (GP11_TYPE_SESSION, "module", module, 
	                        "handle", handle, "slot", slot, NULL);
	g_object_unref (module);
	
	return session;
}

/**
 * gp11_session_get_handle:
 * @self: The session object.
 * 
 * Get the raw PKCS#11 session handle from a GP11Session object.
 * 
 * Return value: The raw session handle.
 **/
CK_SESSION_HANDLE
gp11_session_get_handle (GP11Session *self)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (self);
	g_return_val_if_fail (GP11_IS_SESSION (self), (CK_SESSION_HANDLE)-1);
	return data->handle;
}

/**
 * gp11_session_get_module:
 * @self: The session object.
 * 
 * Get the PKCS#11 module to which this session belongs.
 * 
 * Return value: The module, which should be unreffed after use.
 **/
GP11Module*
gp11_session_get_module (GP11Session *self)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (self);
	g_return_val_if_fail (GP11_IS_SESSION (self), NULL);
	g_return_val_if_fail (GP11_IS_MODULE (data->module), NULL);
	return g_object_ref (data->module);
}

/**
 * gp11_session_get_slot:
 * @self: The session object.
 * 
 * Get the PKCS#11 slot to which this session belongs.
 * 
 * Return value: The slot, which should be unreffed after use.
 **/
GP11Slot*
gp11_session_get_slot (GP11Session *self)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (self);
	g_return_val_if_fail (GP11_IS_SESSION (self), NULL);
	g_return_val_if_fail (GP11_IS_SLOT (data->slot), NULL);
	return g_object_ref (data->slot);
}

/**
 * gp11_session_get_info: 
 * @self: The session object.
 * 
 * Get information about the session.
 * 
 * Return value: The session info. Use the gp11_session_info_free() to release
 * when done.
 **/
GP11SessionInfo*
gp11_session_get_info (GP11Session *self)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (self);
	GP11SessionInfo *sessioninfo;
	CK_FUNCTION_LIST_PTR funcs;
	CK_SESSION_INFO info;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SESSION (self), NULL);
	g_return_val_if_fail (GP11_IS_MODULE (data->module), NULL);
	
	g_object_ref (data->module);
	
	funcs = gp11_module_get_function_list (data->module);
	g_return_val_if_fail (funcs, NULL);
	
	memset (&info, 0, sizeof (info));
	rv = (funcs->C_GetSessionInfo) (data->handle, &info);
	
	g_object_unref (data->module);
	
	if (rv != CKR_OK) {
		g_warning ("couldn't get session info: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	sessioninfo = g_new0 (GP11SessionInfo, 1);
	sessioninfo->flags = info.flags;
	sessioninfo->slot_id = info.slotID;
	sessioninfo->state = info.state;
	sessioninfo->device_error = info.ulDeviceError;

	return sessioninfo;
}



/* LOGIN */

typedef struct _Login {
	GP11Arguments base;
	gulong user_type;
	guchar *pin;
	gsize n_pin;
} Login;

static void
free_login (Login *args)
{
	g_free (args->pin);
	g_free (args);
}

static CK_RV
perform_login (Login *args)
{
	return (args->base.pkcs11->C_Login) (args->base.handle, args->user_type,
	                                     (CK_BYTE_PTR)args->pin, args->n_pin);
}

/**
 * gp11_session_login:
 * @self: Log into this session.
 * @user_type: The type of login user.
 * @pin: The user's PIN, or NULL for protected authentication path.
 * @n_pin: The length of the PIN.
 * @err: A location to return an error.
 * 
 * Login the user on the session. This call may block
 * for an indefinite period.
 * 
 * Return value: Whether successful or not.
 **/
gboolean
gp11_session_login (GP11Session *self, gulong user_type, const guchar *pin,
                    gsize n_pin, GError **err)
{
	return gp11_session_login_full (self, user_type, pin, n_pin, NULL, err);
}

/**
 * gp11_session_login_full:
 * @self: Log into this session.
 * @user_type: The type of login user.
 * @pin: The user's PIN, or NULL for protected authentication path.
 * @n_pin: The length of the PIN.
 * @cancellable: Optional cancellation object, or NULL.
 * @err: A location to return an error.
 * 
 * Login the user on the session. This call may block for 
 * an indefinite period.
 * 
 * Return value: Whether successful or not.
 **/
gboolean
gp11_session_login_full (GP11Session *self, gulong user_type, const guchar *pin,
                         gsize n_pin, GCancellable *cancellable, GError **err)
{
	Login args = { GP11_ARGUMENTS_INIT, user_type, (guchar*)pin, n_pin };
	return _gp11_call_sync (self, perform_login, &args, cancellable, err);
	
}

/**
 * gp11_session_login_async:
 * @self: Log into this session.
 * @user_type: The type of login user.
 * @pin: The user's PIN, or NULL for protected authentication path.
 * @n_pin: The length of the PIN.
 * @cancellable: Optional cancellation object, or NULL.
 * @callback: Called when the operation completes.
 * @user_data: Data to pass to the callback.
 * 
 * Login the user on the session. This call will return 
 * immediately and completes asynchronously.
 **/
void
gp11_session_login_async (GP11Session *self, gulong user_type, const guchar *pin,
                          gsize n_pin, GCancellable *cancellable, GAsyncReadyCallback callback,
                          gpointer user_data)
{
	Login* args = _gp11_call_async_prep (self, self, perform_login, sizeof (*args), free_login);
	
	args->user_type = user_type;
	args->pin = pin && n_pin ? g_memdup (pin, n_pin) : NULL;
	args->n_pin = n_pin;
	
	_gp11_call_async_ready_go (args, cancellable, callback, user_data);

}

/**
 * gp11_session_login_finish:
 * @self: The session logged into.
 * @result: The result passed to the callback.
 * @err: A location to return an error.
 * 
 * Get the result of a login operation.
 * 
 * Return value: Whether the operation was successful or not.
 **/
gboolean
gp11_session_login_finish (GP11Session *self, GAsyncResult *result, GError **err)
{
	return _gp11_call_basic_finish (result, err);
}




/* LOGOUT */

static CK_RV
perform_logout (GP11Arguments *args)
{
	return (args->pkcs11->C_Logout) (args->handle);
}

/**
 * gp11_session_logout:
 * @self: Logout of this session.
 * @err: A location to return an error.
 * 
 * Log out of the session. This call may block for an indefinite period.
 * 
 * Return value: Whether the logout was successful or not.
 **/
gboolean
gp11_session_logout (GP11Session *self, GError **err)
{
	return gp11_session_logout_full (self, NULL, err);
}

/**
 * gp11_session_logout_full:
 * @self: Logout of this session.
 * @cancellable: Optional cancellation object, or NULL.
 * @err: A location to return an error.
 * 
 * Log out of the session. This call may block for an indefinite period.
 * 
 * Return value: Whether the logout was successful or not.
 **/
gboolean
gp11_session_logout_full (GP11Session *self, GCancellable *cancellable, GError **err)
{
	GP11Arguments args = GP11_ARGUMENTS_INIT;
	return _gp11_call_sync (self, perform_logout, &args, cancellable, err);	
}

/**
 * gp11_session_logout_async:
 * @self: Logout of this session.
 * @cancellable: Optional cancellation object, or NULL.
 * @callback: Called when the operation completes.
 * @user_data: Data to pass to the callback.
 * 
 * Log out of the session. This call returns immediately and completes
 * asynchronously.
 **/
void
gp11_session_logout_async (GP11Session *self, GCancellable *cancellable,
                           GAsyncReadyCallback callback, gpointer user_data)
{
	GP11Arguments *args = _gp11_call_async_prep (self, self, perform_logout, 0, NULL);
	_gp11_call_async_ready_go (args, cancellable, callback, user_data);
}

/**
 * gp11_session_logout_finish:
 * @self: Logout of this session.
 * @result: The result passed to the callback.
 * @err: A location to return an error.
 * 
 * Get the result of logging out of a session.
 * 
 * Return value: Whether the logout was successful or not.
 **/
gboolean
gp11_session_logout_finish (GP11Session *self, GAsyncResult *result, GError **err)
{
	return _gp11_call_basic_finish (result, err);
}




/* CREATE OBJECT */

typedef struct _CreateObject {
	GP11Arguments base;
	GP11Attributes *attrs;
	CK_OBJECT_HANDLE object;
} CreateObject;

static void
free_create_object (CreateObject *args)
{
	gp11_attributes_unref (args->attrs);
	g_free (args);
}

static CK_RV
perform_create_object (CreateObject *args)
{
	return (args->base.pkcs11->C_CreateObject) (args->base.handle, 
	                                            _gp11_attributes_raw (args->attrs),
	                                            gp11_attributes_count (args->attrs),
	                                            &args->object);
}

/**
 * gp11_session_create_object:
 * @self: The session to create the object on.
 * @err: A location to store an error.
 * ...: The attributes to create the new object with.
 * 
 * Create a new PKCS#11 object. This call may block 
 * for an indefinite period.
 * 
 * The arguments must be triples of: attribute type, data type, value
 * 
 * <para>The variable argument list should contain:
 * 	<variablelist>
 *		<varlistentry>
 * 			<term>a)</term>
 * 			<listitem><para>The gulong attribute type (ie: CKA_LABEL). </para></listitem>
 * 		</varlistentry>
 * 		<varlistentry>
 * 			<term>b)</term>
 * 			<listitem><para>The attribute data type (one of GP11_BOOLEAN, GP11_ULONG, 
 * 				GP11_STRING, GP11_DATE) orthe raw attribute value length.</para></listitem>
 * 		</varlistentry>
 * 		<varlistentry>
 * 			<term>c)</term>
 * 			<listitem><para>The attribute value, either a gboolean, gulong, gchar*, GDate* or 
 * 				a pointer to a raw attribute value.</para></listitem>
 * 		</varlistentry>
 * 	</variablelist>
 * 
 * The variable argument list should be terminated with GP11_INVALID.</para>
 * 
 * Return value: The newly created object, or NULL if an error occurred.
 **/
GP11Object*
gp11_session_create_object (GP11Session *self, GError **err, ...)
{
	GP11Attributes *attrs;
	GP11Object *object;
	va_list va;
	
	va_start (va, err);
	attrs = gp11_attributes_new_valist (va);
	va_end (va);
	
	object = gp11_session_create_object_full (self, attrs, NULL, err);
	gp11_attributes_unref (attrs);
	return object;
}

/**
 * gp11_session_create_object_full:
 * @self: The session to create the object on.
 * @attrs: The attributes to create the object with.
 * @cancellable: Optional cancellation object, or NULL.
 * @err: A location to return an error, or NULL.
 * 
 * Create a new PKCS#11 object. This call may block for an 
 * indefinite period. 
 * 
 * Return value: The newly created object or NULL if an error occurred.
 **/
GP11Object*
gp11_session_create_object_full (GP11Session *self, GP11Attributes *attrs,
                                 GCancellable *cancellable, GError **err)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (self);
	CreateObject args = { GP11_ARGUMENTS_INIT, attrs, 0 };
	if (!_gp11_call_sync (self, perform_create_object, &args, cancellable, err))
		return NULL;
	return gp11_object_from_handle (data->slot, args.object);
}

/**
 * gp11_session_create_object_async:
 * @self: The session to create the object on.
 * @attrs: The attributes to create the object with.
 * @cancellable: Optional cancellation object or NULL.
 * @callback: Called when the operation completes.
 * @user_data: Data to pass to the callback.
 * 
 * Create a new PKCS#11 object. This call will return immediately
 * and complete asynchronously.
 **/
void
gp11_session_create_object_async (GP11Session *self, GP11Attributes *attrs,
                                  GCancellable *cancellable, GAsyncReadyCallback callback, 
                                  gpointer user_data)
{
	CreateObject *args = _gp11_call_async_prep (self, self, perform_create_object, 
	                                            sizeof (*args), free_create_object);
	args->attrs = attrs;
	gp11_attributes_ref (attrs);
	_gp11_call_async_ready_go (args, cancellable, callback, user_data);
}

/**
 * gp11_session_create_object_finish:
 * @self: The session to create the object on.
 * @result: The result passed to the callback.
 * @err: A location to return an error, or NULL.
 * 
 * Get the result of creating a new PKCS#11 object.
 * 
 * Return value: The newly created object or NULL if an error occurred.
 **/
GP11Object*
gp11_session_create_object_finish (GP11Session *self, GAsyncResult *result, GError **err)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (self);
	CreateObject *args;
	
	if (!_gp11_call_basic_finish (result, err))
		return NULL;
	args = _gp11_call_arguments (result, CreateObject);
	return gp11_object_from_handle (data->slot, args->object);
}



/* FIND OBJECTS */

typedef struct _FindObjects {
	GP11Arguments base;
	GP11Attributes *attrs;
	CK_OBJECT_HANDLE_PTR objects;
	CK_ULONG n_objects;
} FindObjects;

static void
free_find_objects (FindObjects *args)
{
	gp11_attributes_unref (args->attrs);
	g_free (args->objects);
}

static CK_RV
perform_find_objects (FindObjects *args)
{
	CK_OBJECT_HANDLE_PTR batch;
	CK_ULONG n_batch, n_found;
	GArray *array;
	CK_RV rv;
	
	rv = (args->base.pkcs11->C_FindObjectsInit) (args->base.handle, 
	                                             _gp11_attributes_raw (args->attrs),
	                                             gp11_attributes_count (args->attrs));
	if (rv != CKR_OK)
		return rv;
	
	batch = NULL;
	n_found = n_batch = 4;
	array = g_array_new (0, 1, sizeof (CK_OBJECT_HANDLE));
	
	do {
		/* 
		 * Reallocate and double in size: 
		 *  - First time.
		 *  - Each time we found as many as batch
		 */
		
		if (n_found == n_batch) {
			n_batch *= 2;
			batch = g_realloc (batch, sizeof (CK_OBJECT_HANDLE) * n_batch);
		}

		rv = (args->base.pkcs11->C_FindObjects) (args->base.handle,
		                                         batch, n_batch, &n_found);
		if (rv != CKR_OK)
			break;
		
		g_array_append_vals (array, batch, n_found);
		
	} while (n_found > 0);
	
	g_free (batch);
	
	if (rv == CKR_OK) {
		args->n_objects = array->len;
		args->objects = (CK_OBJECT_HANDLE_PTR)g_array_free (array, FALSE);
		rv = (args->base.pkcs11->C_FindObjectsFinal) (args->base.handle);
	} else {
		args->objects = NULL;
		args->n_objects = 0;
		g_array_free (array, TRUE);
	}
	
	return rv;
}

static GList*
objlist_from_handles (GP11Session *self, CK_OBJECT_HANDLE_PTR objects, 
                      CK_ULONG n_objects)
{
	GP11SessionData *data = GP11_SESSION_GET_DATA (self);
	GList *results = NULL;
	
	while (n_objects > 0) {
		results = g_list_prepend (results, 
		                gp11_object_from_handle (data->slot, objects[--n_objects]));
	}
	
	return g_list_reverse (results);
}

/**
 * gp11_session_find_objects:
 * @self: The session to find objects on.
 * @err: A location to return an error or NULL.
 * ...: The attributes to match.
 * 
 * Find objects matching the passed attributes. This call may 
 * block for an indefinite period.
 * 
 * The arguments must be triples of: attribute type, data type, value
 * 
 * <para>The variable argument list should contain:
 * 	<variablelist>
 *		<varlistentry>
 * 			<term>a)</term>
 * 			<listitem><para>The gulong attribute type (ie: CKA_LABEL). </para></listitem>
 * 		</varlistentry>
 * 		<varlistentry>
 * 			<term>b)</term>
 * 			<listitem><para>The attribute data type (one of GP11_BOOLEAN, GP11_ULONG, 
 * 				GP11_STRING, GP11_DATE) orthe raw attribute value length.</para></listitem>
 * 		</varlistentry>
 * 		<varlistentry>
 * 			<term>c)</term>
 * 			<listitem><para>The attribute value, either a gboolean, gulong, gchar*, GDate* or 
 * 				a pointer to a raw attribute value.</para></listitem>
 * 		</varlistentry>
 * 	</variablelist>
 * The variable argument list should be terminated with GP11_INVALID.</para>
 * 
 * Return value: A list of the matching objects, which may be empty.  
 **/
GList*
gp11_session_find_objects (GP11Session *self, GError **err, ...)
{
	GP11Attributes *attrs;
	GList *results;
	va_list va;
	
	va_start (va, err);
	attrs = gp11_attributes_new_valist (va);
	va_end (va);

	results = gp11_session_find_objects_full (self, attrs, NULL, err);
	gp11_attributes_unref (attrs);
	return results;
}

/**
 * gp11_session_find_objects_full:
 * @self: The session to find objects on.
 * @attrs: The attributes to match.
 * @cancellable: Optional cancellation object or NULL.
 * @err: A location to return an error or NULL.
 * 
 * Find the objects matching the passed attributes. This call may 
 * block for an indefinite period.
 * 
 * Return value: A list of the matching objects, which may be empty.
 **/
GList*
gp11_session_find_objects_full (GP11Session *self, GP11Attributes *attrs, 
                                GCancellable *cancellable, GError **err)
{
	FindObjects args = { GP11_ARGUMENTS_INIT, attrs, NULL, 0 };
	GList *results = NULL;
	
	if (_gp11_call_sync (self, perform_find_objects, &args, cancellable, err)) 
		results = objlist_from_handles (self, args.objects, args.n_objects);
	g_free (args.objects);
	return results;
}

/**
 * gp11_session_find_objects_async:
 * @self: The session to find objects on.
 * @attrs: The attributes to match.
 * @cancellable: Optional cancellation object or NULL.
 * @callback: Called when the operation completes.
 * @user_data: Data to pass to the callback.
 * 
 * Find the objects matching the passed attributes. This call will 
 * return immediately and complete asynchronously.
 **/
void
gp11_session_find_objects_async (GP11Session *self, GP11Attributes *attrs, 
                                 GCancellable *cancellable, GAsyncReadyCallback callback, 
                                 gpointer user_data)
{
	FindObjects *args = _gp11_call_async_prep (self, self, perform_find_objects, 
	                                           sizeof (*args), free_find_objects);
	args->attrs = attrs;
	gp11_attributes_ref (attrs);
	_gp11_call_async_ready_go (args, cancellable, callback, user_data);
}

/**
 * gp11_session_find_objects_finish:
 * @self: The session to find objects on.
 * @result: The attributes to match.
 * @err: A location to return an error.
 * 
 * Get the result of a find operation.
 * 
 * Return value: A list of the matching objects, which may be empty.
 **/
GList*
gp11_session_find_objects_finish (GP11Session *self, GAsyncResult *result, GError **err)
{
	FindObjects *args;
	
	if (!_gp11_call_basic_finish (result, err))
		return NULL;
	args = _gp11_call_arguments (result, FindObjects);
	return objlist_from_handles (self, args->objects, args->n_objects);
}


#if UNTESTED 

/* ENCRYPT */


typedef struct _Crypt {
	GP11Arguments base;
	
	/* Functions to call */
	CK_C_EncryptInit init_func;
	CK_C_Encrypt complete_func;
	
	/* Input */
	CK_OBJECT_HANDLE key;
	CK_MECHANISM mech;
	guchar *input;
	CK_ULONG n_input;
	
	/* Output */
	guchar *result;
	CK_ULONG n_result;
} Crypt;

static void
free_crypt (Crypt *args)
{
	g_free (args->input);
	g_free (args->mech.pParameter);
	g_free (args->result);
}

static CK_RV
perform_crypt (Crypt *args)
{
	CK_RV rv;
	
	g_assert (args);
	g_assert (args->init_func);
	g_assert (args->complete_func);
	g_assert (!args->result);
	g_assert (!args->n_result);
	
	/* Initialize the crypt operation */
	rv = (args->init_func) (args->base.handle, &args->mech, args->key);
	if (rv != CKR_OK)
		return rv;
	
	/* Get the length of the result */
	rv = (args->complete_func) (args->base.handle, args->input, args->n_input, NULL, &args->n_result);
	if (rv != CKR_OK)
		return rv;
	
	/* And try again with a real buffer */
	args->result = g_malloc0 (args->n_result);
	return (args->complete_func) (args->base.handle, args->input, args->n_input, args->result, &args->n_result);
}

static guchar*
crypt_sync (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args, const guchar *input, 
            gsize n_input, gsize *n_result, GCancellable *cancellable, GError **err,
            CK_C_EncryptInit init_func, CK_C_Encrypt complete_func)
{
	Crypt args;
	
	g_return_val_if_fail (GP11_IS_OBJECT (key), NULL);
	g_return_val_if_fail (mech_args, NULL);
	g_return_val_if_fail (init_func, NULL);
	g_return_val_if_fail (complete_func, NULL);

	memset (&args, 0, sizeof (args));
	g_object_get (key, "handle", &args.key, NULL);
	g_return_val_if_fail (args.key != 0, NULL);
	
	args.mech.mechanism = mech_args->type;
	args.mech.pParameter = mech_args->parameter;
	args.mech.ulParameterLen = mech_args->n_parameter;
	
	/* No need to copy in this case */
	args.input = (guchar*)input;
	args.n_input = n_input;
	
	args.init_func = init_func;
	args.complete_func = complete_func;
	
	if (!_gp11_call_sync (self, perform_crypt, &args, cancellable, err)) {
		g_free (args.result);
		return NULL;
	}
	
	return args.result;
}

static void
crypt_async (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args, const guchar *input, 
             gsize n_input, GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data,
             CK_C_EncryptInit init_func, CK_C_Encrypt complete_func)
{
	Crypt *args = _gp11_call_async_prep (self, self, perform_crypt, sizeof (*args), free_crypt);

	g_return_if_fail (GP11_IS_OBJECT (key));
	g_return_if_fail (mech_args);
	g_return_if_fail (init_func);
	g_return_if_fail (complete_func);
	
	g_object_get (key, "handle", &args->key, NULL);
	g_return_if_fail (args->key != 0);

	args->mech.mechanism = mech_args->type;
	args->mech.pParameter = mech_args->parameter && mech_args->n_parameter ? 
	                                   g_memdup (mech_args->parameter, mech_args->n_parameter) : NULL;
	args->mech.ulParameterLen = mech_args->n_parameter;
	
	args->input = input && n_input ? g_memdup (input, n_input) : NULL;
	args->n_input = n_input;
	
	args->init_func = init_func;
	args->complete_func = complete_func;
	
	_gp11_call_async_go (args, cancellable, callback, user_data);
}

static guchar*
crypt_finish (GP11Session *self, GAsyncResult *result, gsize *n_result, GError **err)
{
	Crypt *args;
	guchar *res;
	
	if (!_gp11_call_basic_finish (self, result, err))
		return NULL;
	args = _gp11_call_arguments (result, Crypt);
	
	/* Steal the values from the results */
	res = args->result;
	args->result = NULL;
	*n_result = args->n_result;
	args->n_result = 0;
	
	return res;
}

guchar*
gp11_session_encrypt (GP11Session *self, GP11Object *key, gulong mech, const guchar *input, 
                      gsize n_input, gsize *n_result, GError **err)
{
	GP11Mechanism mech_args = { mech, NULL, 0 };
	return gp11_session_encrypt_full (self, key, &mech_args, input, n_input, n_result, NULL, err);
}

guchar*
gp11_session_encrypt_full (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args,
                           const guchar *input, gsize n_input, gsize *n_result,
                           GCancellable *cancellable, GError **err)
{
	GP11Module *module = NULL;
	guchar *ret;
	
	g_object_get (self, "module", &module, NULL);
	g_return_val_if_fail (module != NULL, NULL);

	ret = crypt_sync (self, key, mech_args, input, n_input, n_result, cancellable, err, 
	                  module->funcs->C_EncryptInit, module->funcs->C_Encrypt);
	
	g_object_unref (module);
	return ret;
}

void
gp11_session_encrypt_async (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args,
                            const guchar *input, gsize n_input, GCancellable *cancellable,
                            GAsyncReadyCallback callback, gpointer user_data)
{
	GP11Module *module = NULL;
	g_object_get (self, "module", &module, NULL);
	g_return_if_fail (module != NULL);

	crypt_async (self, key, mech_args, input, n_input, cancellable, callback, user_data,
	             module->funcs->C_EncryptInit, module->funcs->C_Encrypt);
	
	g_object_unref (module);
}

guchar*
gp11_session_encrypt_finish (GP11Session *self, GAsyncResult *result, gsize *n_result,
                             GError **err)
{
	return crypt_finish (self, result, n_result, err);
}

guchar*
gp11_session_decrypt (GP11Session *self, GP11Object *key, gulong mech_type, const guchar *input,
                      gsize n_input, gsize *n_result, GError **err)
{
	GP11Mechanism mech_args = { mech_type, NULL, 0 };
	return gp11_session_decrypt_full (self, key, &mech_args, input, n_input, n_result, NULL, err);
}

guchar*
gp11_session_decrypt_full (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args,
                           const guchar *input, gsize n_input, gsize *n_result,
                           GCancellable *cancellable, GError **err)
{
	GP11Module *module = NULL;
	guchar *ret;
	
	g_object_get (self, "module", &module, NULL);
	g_return_val_if_fail (module != NULL, NULL);

	ret = crypt_sync (self, key, mech_args, input, n_input, n_result, cancellable, err,
	                  module->funcs->C_DecryptInit, module->funcs->C_Decrypt);
	g_object_unref (module);
	return ret;
}

void
gp11_session_decrypt_async (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args,
                            const guchar *input, gsize n_input, GCancellable *cancellable,
                            GAsyncReadyCallback callback, gpointer user_data)
{
	GP11Module *module = NULL;
	g_object_get (self, "module", &module, NULL);
	g_return_if_fail (module != NULL);

	crypt_async (self, key, mech_args, input, n_input, cancellable, callback, user_data,
	             module->funcs->C_DecryptInit, module->funcs->C_Decrypt);
	g_object_unref (module);
}

guchar*
gp11_session_decrypt_finish (GP11Session *self, GAsyncResult *result,
                             gsize *n_result, GError **err)
{
	return crypt_finish (self, result, n_result, err);
}

guchar*
gp11_session_sign (GP11Session *self, GP11Object *key, gulong mech_type, const guchar *input, 
                   gsize n_input, gsize *n_result, GError **err)
{
	GP11Mechanism mech_args = { mech_type, NULL, 0 };
	return gp11_session_sign_full (self, key, &mech_args, input, n_input, n_result, NULL, err);
}

guchar*
gp11_session_sign_full (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args,
                        const guchar *input, gsize n_input, gsize *n_result,
                        GCancellable *cancellable, GError **err)
{
	GP11Module *module = NULL;
	guchar *ret;
	
	g_object_get (self, "module", &module, NULL);
	g_return_val_if_fail (module != NULL, NULL);

	return crypt_sync (self, key, mech_args, input, n_input, n_result, cancellable, err,
	                   module->funcs->C_SignInit, module->funcs->C_Sign);
	g_object_unref (module);
	return ret;
}

void
gp11_session_sign_async (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args,
                         const guchar *input, gsize n_input, GCancellable *cancellable,
                         GAsyncReadyCallback callback, gpointer user_data)
{
	GP11Module *module = NULL;
	g_object_get (self, "module", &module, NULL);
	g_return_if_fail (module != NULL);

	crypt_async (self, key, mech_args, input, n_input, cancellable, callback, user_data,
	             module->funcs->C_SignInit, module->funcs->C_Sign);
	g_object_unref (module);
}

guchar*
gp11_session_sign_finish (GP11Session *self, GAsyncResult *result, 
                          gsize *n_result, GError **err)
{
	return crypt_finish (self, result, n_result, err);	
}


typedef struct _Verify {
	GP11Arguments base;
	
	/* Input */
	CK_OBJECT_HANDLE key;
	CK_MECHANISM mech;
	guchar *input;
	CK_ULONG n_input;
	guchar *signature;
	CK_ULONG n_signature;
	
} Verify;

static void
free_verify (Verify *args)
{
	g_free (args->input);
	g_free (args->signature);
	g_free (args->mech.pParameter);
}

static CK_RV
perform_verify (Verify *args)
{
	CK_RV rv;
	
	/* Initialize the crypt operation */
	rv = (args->base.pkcs11->C_VerifyInit) (args->base.handle, &args->mech, args->key);
	if (rv != CKR_OK)
		return rv;
	
	/* Do the actual verify */
	return (args->base.pkcs11->C_Verify) (args->base.handle, args->input, args->n_input, 
	                                      args->signature, args->n_signature);
}

gboolean
gp11_session_verify (GP11Session *self, GP11Object *key, gulong mech_type, const guchar *input,
                     gsize n_input, const guchar *signature, gsize n_signature, GError **err)
{
	GP11Mechanism mech_args = { mech_type, NULL, 0 };
	return gp11_session_verify_full (self, key, &mech_args, input, n_input, 
	                                 signature, n_signature, NULL, err);	
}

gboolean
gp11_session_verify_full (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args,
                          const guchar *input, gsize n_input, const guchar *signature,
                          gsize n_signature, GCancellable *cancellable, GError **err)
{
	Verify args;
	
	g_return_val_if_fail (GP11_IS_OBJECT (key), FALSE);
	g_return_val_if_fail (mech_args, FALSE);

	memset (&args, 0, sizeof (args));
	g_object_get (key, "handle", &args.key, NULL);
	g_return_val_if_fail (args.key != 0, FALSE);
	
	args.mech.mechanism = mech_args->type;
	args.mech.pParameter = mech_args->parameter;
	args.mech.ulParameterLen = mech_args->n_parameter;
	
	/* No need to copy in this case */
	args.input = (guchar*)input;
	args.n_input = n_input;
	args.signature = (guchar*)signature;
	args.n_signature = n_signature;

	return _gp11_call_sync (self, perform_verify, &args, cancellable, err);
}

void
gp11_session_verify_async (GP11Session *self, GP11Object *key, GP11Mechanism *mech_args,
                           const guchar *input, gsize n_input, const guchar *signature,
                           gsize n_signature, GCancellable *cancellable,
                           GAsyncReadyCallback callback, gpointer user_data)
{
	Verify *args = _gp11_call_async_prep (self, self, perform_verify, sizeof (*args), free_verify);

	g_return_if_fail (GP11_IS_OBJECT (key));
	g_return_if_fail (mech_args);
	
	g_object_get (key, "handle", &args->key, NULL);
	g_return_if_fail (args->key != 0);

	args->mech.mechanism = mech_args->type;
	args->mech.pParameter = mech_args->parameter && mech_args->n_parameter ? 
	                                   g_memdup (mech_args->parameter, mech_args->n_parameter) : NULL;
	args->mech.ulParameterLen = mech_args->n_parameter;
	
	args->input = input && n_input ? g_memdup (input, n_input) : NULL;
	args->n_input = n_input;
	args->signature = signature && n_signature ? g_memdup (signature, n_signature) : NULL;
	args->n_input = n_signature;
	
	_gp11_call_async_go (args, cancellable, callback, user_data);
}

gboolean
gp11_session_verify_finish (GP11Session *self, GAsyncResult *result, GError **err)
{
	return _gp11_call_basic_finish (self, result, err);
}

#endif /* UNTESTED */
