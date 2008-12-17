/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gp11-object.c - the GObject PKCS#11 wrapper library

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

#include <string.h>

enum {
	PROP_0,
	PROP_MODULE,
	PROP_SLOT,
	PROP_HANDLE,
	PROP_SESSION
};

G_DEFINE_TYPE (GP11Object, gp11_object, G_TYPE_OBJECT);

/* ----------------------------------------------------------------------------
 * INTERNAL
 */

static void
run_call_with_session (GP11Call *call, GP11Session *session)
{
	g_assert (GP11_IS_CALL (call));
	g_assert (GP11_IS_SESSION (session));
	
	/* Hold onto this session for the length of the call */
	g_object_set_data_full (G_OBJECT (call), "call-opened-session", 
	                        g_object_ref (session), g_object_unref);

	_gp11_call_async_object (call, session);
	_gp11_call_async_go (call);	
}

static void
opened_session (GObject *obj, GAsyncResult *result, gpointer user_data)
{
	GP11Session *session;
	GError *err = NULL;
	GP11Call *call;
	
	g_assert (GP11_IS_CALL (user_data));
	call = GP11_CALL (user_data);
	
	session = gp11_slot_open_session_finish (GP11_SLOT (obj), result, &err);
	
	/* Transtfer the error to the outer call and finish */
	if (!session) {
		_gp11_call_async_short (user_data, err->code);
		g_error_free (err);
		return;
	}

	run_call_with_session (GP11_CALL (user_data), session);
	g_object_unref (session);
}

static void
require_session_async (GP11Object *object, GP11Call *call, 
                       gulong flags, GCancellable *cancellable)
{
	g_assert (GP11_IS_OBJECT (object));
	
	if (object->session)
		run_call_with_session (call, object->session);
	else
		gp11_slot_open_session_async (object->slot, flags, cancellable, opened_session, call);
}

static GP11Session*
require_session_sync (GP11Object *object, gulong flags, GError **err)
{
	g_assert (GP11_IS_OBJECT (object));

	if (object->session) 
		return g_object_ref (object->session);
	
	return gp11_slot_open_session (object->slot, flags, err);
}

/* ----------------------------------------------------------------------------
 * OBJECT
 */

static void
gp11_object_init (GP11Object *object)
{
	
}

static void
gp11_object_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
	GP11Object *object = GP11_OBJECT (obj);

	switch (prop_id) {
	case PROP_MODULE:
		g_value_set_object (value, object->module);
		break;
	case PROP_SLOT:
		g_value_set_object (value, object->slot);
		break;
	case PROP_SESSION:
		g_value_set_object (value, object->session);
		break;
	case PROP_HANDLE:
		g_value_set_uint (value, object->handle);
		break;
	}
}

static void
gp11_object_set_property (GObject *obj, guint prop_id, const GValue *value, 
                          GParamSpec *pspec)
{
	GP11Object *object = GP11_OBJECT (obj);
	
	switch (prop_id) {
	case PROP_MODULE:
		g_return_if_fail (!object->module);
		object->module = g_value_get_object (value);
		g_return_if_fail (object->module);
		g_object_ref (object->module);
		break;
	case PROP_SLOT:
		g_return_if_fail (!object->slot);
		object->slot = g_value_get_object (value);
		g_return_if_fail (object->slot);
		g_object_ref (object->slot);
		break;
	case PROP_SESSION:
		gp11_object_set_session (object, g_value_get_object (value));
		break;
	case PROP_HANDLE:
		g_return_if_fail (!object->handle);
		object->handle = g_value_get_uint (value);
		break;
	}
}

static void
gp11_object_dispose (GObject *obj)
{
	GP11Object *object = GP11_OBJECT (obj);
	
	if (object->slot)
		g_object_unref (object->slot);
	object->slot = NULL;
	
	if (object->module)
		g_object_unref (object->module);
	object->module = NULL;
	
	if (object->session)
		g_object_unref (object->session);
	object->session = NULL;

	G_OBJECT_CLASS (gp11_object_parent_class)->dispose (obj);
}

static void
gp11_object_finalize (GObject *obj)
{
	GP11Object *object = GP11_OBJECT (obj);

	g_assert (object->slot == NULL);
	g_assert (object->module == NULL);
	g_assert (object->session == NULL);
	
	object->handle = 0;
	
	G_OBJECT_CLASS (gp11_object_parent_class)->finalize (obj);
}


static void
gp11_object_class_init (GP11ObjectClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	gp11_object_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->get_property = gp11_object_get_property;
	gobject_class->set_property = gp11_object_set_property;
	gobject_class->dispose = gp11_object_dispose;
	gobject_class->finalize = gp11_object_finalize;
	
	g_object_class_install_property (gobject_class, PROP_MODULE,
		g_param_spec_object ("module", "Module", "PKCS11 Module",
		                     GP11_TYPE_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_SLOT,
		g_param_spec_object ("slot", "slot", "PKCS11 Slot",
		                     GP11_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_HANDLE,
		g_param_spec_uint ("handle", "Object Handle", "PKCS11 Object Handle",
		                   0, G_MAXUINT, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_SESSION,
		g_param_spec_object ("session", "session", "PKCS11 Session to make calls on",
		                     GP11_TYPE_SESSION, G_PARAM_READWRITE));
}

/* ----------------------------------------------------------------------------
 * PUBLIC 
 */

/**
 * gp11_object_from_handle:
 * @slot: The slot on which this object is present.
 * @handle: The raw handle of the object. 
 * 
 * Initialize a GP11Object from a raw PKCS#11 handle. Normally you would use 
 * gp11_session_create_object() or gp11_session_find_objects() to access objects. 
 * 
 * Return value: The new GP11Object. You should use g_object_unref() when done with this object.
 **/
GP11Object*
gp11_object_from_handle (GP11Slot *slot, CK_OBJECT_HANDLE handle)
{
	g_return_val_if_fail (GP11_IS_SLOT (slot), NULL);
	return g_object_new (GP11_TYPE_OBJECT, "module", slot->module, "handle", handle, "slot", slot, NULL);
}

/**
 * gp11_objects_from_handle_array:
 * @slot: The slot on which these objects are present.
 * @attr: The raw object handles, contained in an attribute.
 * 
 * Initialize a list of GP11Object from raw PKCS#11 handles contained inside 
 * of an attribute. The attribute must contain contiguous CK_OBJECT_HANDLE
 * handles in an array.
 * 
 * Return value: The list of GP11Object. You should use gp11_list_unref_free() when done with 
 * this list. 
 **/
GList*
gp11_objects_from_handle_array (GP11Slot *slot, const GP11Attribute *attr)
{
	GList *results = NULL;
	CK_OBJECT_HANDLE *array;
	guint i, n_array;
	
	g_return_val_if_fail (GP11_IS_SLOT (slot), NULL);
	
	array = (CK_OBJECT_HANDLE*)attr->value;
	n_array = attr->length / sizeof (CK_OBJECT_HANDLE);
	for (i = 0; i < n_array; ++i)
		results = g_list_prepend (results, gp11_object_from_handle (slot, array[i]));
	return g_list_reverse (results);
}

/**
 * gp11_object_get_handle:
 * @object: The object.
 * 
 * Get the raw PKCS#11 handle of a GP11Object.
 * 
 * Return value: The raw object handle.
 **/
CK_OBJECT_HANDLE
gp11_object_get_handle (GP11Object *object)
{
	g_return_val_if_fail (GP11_IS_OBJECT (object), (CK_OBJECT_HANDLE)-1);
	return object->handle;
}

/**
 * gp11_object_get_session:
 * @object: The object
 * 
 * Get the PKCS#11 session assigned to make calls on when operating
 * on this object.  
 * 
 * This will only return a session if it was set explitly on this 
 * object. By default an object will open and close sessions 
 * appropriate for its calls.
 * 
 * Return value: The assigned session.   
 **/
GP11Session*
gp11_object_get_session (GP11Object *object)
{
	g_return_val_if_fail (GP11_IS_OBJECT (object), NULL);
	return object->session;
}

/**
 * gp11_object_get_session:
 * @object: The object
 * @session: The assigned session
 * 
 * Set the PKCS#11 session assigned to make calls on when operating
 * on this object.  
 * 
 * It isn't always necessary to assign a session to an object. 
 * By default an object will open and close sessions appropriate for 
 * its calls.
 * 
 * If you assign a read-only session, then calls on this object
 * that modify the state of the object will probably fail.
 **/
void
gp11_object_set_session (GP11Object *object, GP11Session *session)
{
	g_return_if_fail (GP11_IS_OBJECT (object));
	if (object->session)
		g_object_unref (object->session);
	object->session = session;
	if (object->session)
		g_object_ref (object->session);
}

/* DESTROY */

typedef struct _Destroy {
	GP11Arguments base;
	CK_OBJECT_HANDLE object;
} Destroy;

static CK_RV
perform_destroy (Destroy *args)
{
	return (args->base.pkcs11->C_DestroyObject) (args->base.handle, args->object);
}

/**
 * gp11_object_destroy:
 * @object: The object to destroy.
 * @err: A location to return an error.
 * 
 * Destroy a PKCS#11 object, deleting it from storage or the session.
 * This call may block for an indefinite period.
 * 
 * Return value: Whether the call was successful or not.
 **/
gboolean
gp11_object_destroy (GP11Object *object, GError **err)
{
	return gp11_object_destroy_full (object, NULL, err);
}

/**
 * gp11_object_destroy_full:
 * @object: The object to destroy.
 * @cancellable: Optional cancellable object, or NULL to ignore. 
 * @err: A location to return an error.
 * 
 * Destroy a PKCS#11 object, deleting it from storage or the session.
 * This call may block for an indefinite period.
 * 
 * Return value: Whether the call was successful or not.
 **/
gboolean
gp11_object_destroy_full (GP11Object *object, GCancellable *cancellable, GError **err)
{
	Destroy args = { GP11_ARGUMENTS_INIT, 0 };
	GP11Session *session;
	gboolean ret = FALSE;
	
	g_return_val_if_fail (GP11_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (GP11_IS_SLOT (object->slot), FALSE);
	
	args.object = object->handle;

	session = require_session_sync (object, CKF_RW_SESSION, err);
	if (session)
		ret = _gp11_call_sync (session, perform_destroy, &args, cancellable, err);
	g_object_unref (session);
	return ret;
}

/**
 * gp11_object_destroy_async:
 * @object: The object to destroy.
 * @cancellable: Optional cancellable object, or NULL to ignore. 
 * @callback: Callback which is called when operation completes.
 * @user_data: Data to pass to the callback.
 * 
 * Destroy a PKCS#11 object, deleting it from storage or the session.
 * This call will return immediately and complete asynchronously.
 **/
void
gp11_object_destroy_async (GP11Object *object, GCancellable *cancellable,
                           GAsyncReadyCallback callback, gpointer user_data)
{
	Destroy* args;
	GP11Call *call;

	g_return_if_fail (GP11_IS_OBJECT (object));
	g_return_if_fail (GP11_IS_SLOT (object->slot));

	args = _gp11_call_async_prep (NULL, object, perform_destroy, sizeof (*args), NULL);
	args->object = object->handle;
	
	call = _gp11_call_async_ready (args, cancellable, callback, user_data);
	require_session_async (object, call, CKF_RW_SESSION, cancellable);
}

/**
 * gp11_object_destroy_finish:
 * @object: The object being destroyed.
 * @result: The result of the destory operation passed to the callback.
 * @err: A location to store an error.
 * 
 * Get the status of the operation to destroy a PKCS#11 object, begun with 
 * gp11_object_destroy_async(). 
 * 
 * Return value: Whether the object was destroyed successfully or not.
 */
gboolean
gp11_object_destroy_finish (GP11Object *object, GAsyncResult *result, GError **err)
{
	return _gp11_call_basic_finish (result, err);
}

typedef struct _SetAttributes {
	GP11Arguments base;
	GP11Attributes *attrs;
	CK_OBJECT_HANDLE object;
} SetAttributes;

static void
free_set_attributes (SetAttributes *args)
{
	gp11_attributes_unref (args->attrs);
	g_free (args);
}

static CK_RV
perform_set_attributes (SetAttributes *args)
{
	return (args->base.pkcs11->C_SetAttributeValue) (args->base.handle, args->object, 
	                                                 _gp11_attributes_raw (args->attrs),
	                                                 gp11_attributes_count (args->attrs));
}

/**
 * gp11_object_set:
 * @object: The object to set attributes on.
 * @err: A location to return an error.
 * ...: The attributes to set.
 *
 * Set PKCS#11 attributes on an object.
 * This call may block for an indefinite period.
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
 * Return value: Whether the call was successful or not.
 **/
gboolean
gp11_object_set (GP11Object *object, GError **err, ...)
{
	GP11Attributes *attrs;
	va_list va;
	CK_RV rv;
	
	va_start (va, err);
	attrs = gp11_attributes_new_valist (va);
	va_end (va);
	
	rv = gp11_object_set_full (object, attrs, NULL, err);
	
	gp11_attributes_unref (attrs);
	return rv;
}

/**
 * gp11_object_set_full:
 * @object: The object to set attributes on.
 * @attrs: The attributes to set on the object.
 * @cancellable: Optional cancellable object, or NULL to ignore. 
 * @err: A location to return an error.
 * 
 * Set PKCS#11 attributes on an object. This call may block for an indefinite period.
 * 
 * Return value: Whether the call was successful or not.
 **/
gboolean
gp11_object_set_full (GP11Object *object, GP11Attributes *attrs,
                      GCancellable *cancellable, GError **err)
{
	SetAttributes args;
	GP11Session *session;
	gboolean ret = FALSE;
	
	g_return_val_if_fail (GP11_IS_OBJECT (object), FALSE);
	
	memset (&args, 0, sizeof (args));
	args.attrs = attrs;
	args.object = object->handle;

	session = require_session_sync (object, CKF_RW_SESSION, err);
	if (session)
		ret = _gp11_call_sync (session, perform_set_attributes, &args, cancellable, err);
	g_object_unref (session);
	return ret;
}

/**
 * gp11_object_set_async:
 * @object: The object to set attributes on.
 * @attrs: The attributes to set on the object.
 * @cancellable: Optional cancellable object, or NULL to ignore. 
 * @callback: Callback which is called when operation completes.
 * @user_data: Data to pass to the callback.
 * 
 * Set PKCS#11 attributes on an object. This call will return 
 * immediately and completes asynchronously.
 **/
void
gp11_object_set_async (GP11Object *object, GP11Attributes *attrs, GCancellable *cancellable,
                       GAsyncReadyCallback callback, gpointer user_data)
{
	SetAttributes *args;
	GP11Call *call;
	
	g_return_if_fail (GP11_IS_OBJECT (object));

	args = _gp11_call_async_prep (object->slot, object, perform_set_attributes, 
	                              sizeof (*args), free_set_attributes);
	args->attrs = attrs;
	gp11_attributes_ref (attrs);
	args->object = object->handle;
	
	call = _gp11_call_async_ready (args, cancellable, callback, user_data);
	require_session_async (object, call, CKF_RW_SESSION, cancellable);
}

/**
 * gp11_object_set_finish:
 * @object: The object to set attributes on.
 * @result: The result of the destory operation passed to the callback.
 * @err: A location to store an error.
 * 
 * Get the status of the operation to set attributes on a PKCS#11 object, 
 * begun with gp11_object_set_async(). 
 * 
 * Return value: Whether the attributes were successfully set on the object or not.
 */
gboolean
gp11_object_set_finish (GP11Object *object, GAsyncResult *result, GError **err)
{
	return _gp11_call_basic_finish (result, err);
}

typedef struct _GetAttributes {
	GP11Arguments base;
	gulong *attr_types;
	gsize n_attr_types;
	CK_OBJECT_HANDLE object;
	GP11Attributes *results;
} GetAttributes;

static void
free_get_attributes (GetAttributes *args)
{
	g_free (args->attr_types);
	if (args->results)
		gp11_attributes_unref (args->results);
	g_free (args);
}

/* 
 * Certain failure return values only apply to individual attributes
 * being retrieved. These are ignored, since the attribute should 
 * already have -1 set as the length.
 */
static gboolean
is_ok_get_attributes_rv (CK_RV rv) 
{
	switch (rv) {
	case CKR_OK:
	case CKR_ATTRIBUTE_SENSITIVE:
	case CKR_ATTRIBUTE_TYPE_INVALID:
		return TRUE;
	default:
		return FALSE;
	}
}

static CK_RV
perform_get_attributes (GetAttributes *args)
{
	CK_ATTRIBUTE_PTR attrs;
	CK_ULONG i, n_attrs;
	CK_RV rv;
	
	/* Allocate the CK_ATTRIBUTE's */
	n_attrs = args->n_attr_types;
	if (n_attrs) {
		attrs = g_new0 (CK_ATTRIBUTE, n_attrs);
		for (i = 0; i < n_attrs; ++i)
			attrs[i].type = args->attr_types[i];
	} else {
		attrs = NULL;
	}

	/* Get the size of each value */
	rv = (args->base.pkcs11->C_GetAttributeValue) (args->base.handle, args->object,
	                                               attrs, n_attrs);
	if (!is_ok_get_attributes_rv (rv)) {
		g_free (attrs);
		return rv;
	}
	
	/* Allocate memory for each value */
	for (i = 0; i < n_attrs; ++i) {
		if (attrs[i].ulValueLen > 0 && attrs[i].ulValueLen != (CK_ULONG)-1)
			attrs[i].pValue = g_malloc0 (attrs[i].ulValueLen);
	}
	
	/* Now get the actual values */
	rv = (args->base.pkcs11->C_GetAttributeValue) (args->base.handle, args->object,
	                                               attrs, n_attrs);
	
	/* Transfer over the memory to the results */
	if (is_ok_get_attributes_rv (rv)) {
		g_assert (!args->results);
		args->results = gp11_attributes_new ();
		for (i = 0; i < n_attrs; ++i) {
			_gp11_attributes_add_take (args->results, attrs[i].type,
			                           attrs[i].pValue, attrs[i].ulValueLen);
			memset (&attrs[i], 0, sizeof (attrs[0]));
		}
	}

	/* Free any memory we didn't use */
	for (i = 0; i < n_attrs; ++i)
		g_free (attrs[i].pValue);
	g_free (attrs);
	
	if (is_ok_get_attributes_rv (rv))
		rv = CKR_OK;
	
	return rv;
}

/**
 * gp11_object_get:
 * @object: The object to get attributes from.
 * @err: A location to store an error.
 * ...: The attribute types to get.
 * 
 * Get the specified attributes from the object. This call may
 * block for an indefinite period.
 * 
 * Note that the returned attributes are not required to be 
 * in the order they were requested.
 * 
 * Return value: The resulting PKCS#11 attributes, or NULL if an error occurred. 
 **/
GP11Attributes*
gp11_object_get (GP11Object *object, GError **err, ...)
{
	GP11Attributes *result;
	GArray *array;
	va_list va;
	gulong type;
	
	array = g_array_new (0, 1, sizeof (gulong));
	va_start (va, err);
	for (;;) {
		type = va_arg (va, gulong);
		if (type == (gulong)-1)
			break;
		g_array_append_val (array, type);
	}
	va_end (va);
	
	result = gp11_object_get_full (object, (gulong*)array->data, array->len, NULL, err);
	g_array_free (array, TRUE);
	return result;
}

/**
 * gp11_object_get:
 * @object: The object to get attributes from.
 * @attr_types: The attributes to get.
 * @n_attr_types: The number of attributes to get.
 * @cancellable: Optional cancellation object, or NULL.
 * @err: A location to store an error.
 * 
 * Get the specified attributes from the object. This call may
 * block for an indefinite period.
 * 
 * Note that the returned attributes are not required to be 
 * in the order they were requested.
 * 
 * Return value: The resulting PKCS#11 attributes, or NULL if an error occurred. 
 **/
GP11Attributes*
gp11_object_get_full (GP11Object *object, const gulong *attr_types, gsize n_attr_types,
                      GCancellable *cancellable, GError **err)
{
	GetAttributes args;
	GP11Session *session;
	
	g_return_val_if_fail (GP11_IS_OBJECT (object), FALSE);
	
	session = require_session_sync (object, 0, err);
	if (!session)
		return FALSE;
	
	memset (&args, 0, sizeof (args));
	args.attr_types = (gulong*)attr_types;
	args.n_attr_types = n_attr_types;
	args.object = object->handle;

	if (!_gp11_call_sync (session, perform_get_attributes, &args, cancellable, err)) {
		gp11_attributes_unref (args.results);
		g_object_unref (session);
		return NULL;
	}
	
	g_object_unref (session);
	return args.results;
}

/**
 * gp11_object_get_async:
 * @object: The object to get attributes from.
 * @attr_types: The attributes to get.
 * @n_attr_types: The number of attributes to get.
 * @cancellable: Optional cancellation object, or NULL.
 * @callback: A callback which is called when the operation completes.
 * @user_data: Data to be passed to the callback.
 * 
 * Get the specified attributes from the object. This call returns
 * immediately and completes asynchronously.
 **/
void
gp11_object_get_async (GP11Object *object, const gulong *attr_types, gsize n_attr_types,
                       GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data)
{
	GetAttributes *args;
	GP11Call *call;
	
	g_return_if_fail (GP11_IS_OBJECT (object));

	args = _gp11_call_async_prep (object->session, object, perform_get_attributes, 
	                              sizeof (*args), free_get_attributes);
	args->n_attr_types = n_attr_types;
	if (n_attr_types)
		args->attr_types = g_memdup (attr_types, sizeof (gulong) * n_attr_types);
	args->object = object->handle;
	
	call = _gp11_call_async_ready (args, cancellable, callback, user_data);
	require_session_async (object, call, 0, cancellable);
}

/**
 * gp11_object_get_finish:
 * @object: The object to get attributes from.
 * @result: The result passed to the callback.
 * @err: A location to store an error.
 * 
 * Get the result of a get operation and return specified attributes from 
 * the object. 
 * 
 * Note that the returned attributes are not required to be 
 * in the order they were requested.
 * 
 * Return value: The resulting PKCS#11 attributes, or NULL if an error occurred. 
 **/
GP11Attributes*
gp11_object_get_finish (GP11Object *object, GAsyncResult *result, GError **err)
{
	GP11Attributes *results;
	GetAttributes *args;
	
	if (!_gp11_call_basic_finish (result, err))
		return NULL;
	
	args = _gp11_call_arguments (result, GetAttributes);
	
	results = args->results;
	args->results = NULL;
	
	return results;
}

/**
 * gp11_object_get_one:
 * @object: The object to get an attribute from.
 * @attr_type: The attribute to get.
 * @err: A location to store an error.
 * 
 * Get the specified attribute from the object. This call may
 * block for an indefinite period.
 * 
 * Return value: The resulting PKCS#11 attribute, or NULL if an error occurred. 
 **/
GP11Attribute*
gp11_object_get_one (GP11Object *object, gulong attr_type, GError **err)
{
	return gp11_object_get_one_full (object, attr_type, NULL, err);
}

/**
 * gp11_object_get_one_full:
 * @object: The object to get an attribute from.
 * @attr_type: The attribute to get.
 * @cancellable: Optional cancellation object, or NULL.
 * @err: A location to store an error.
 * 
 * Get the specified attribute from the object. This call may
 * block for an indefinite period.
 * 
 * Return value: The resulting PKCS#11 attribute, or NULL if an error occurred. 
 **/
GP11Attribute*
gp11_object_get_one_full (GP11Object *object, gulong attr_type, 
                          GCancellable *cancellable, GError **err)
{
	GP11Attributes *attrs;
	GP11Attribute *attr;
	
	attrs = gp11_object_get_full (object, &attr_type, 1, cancellable, err);
	if (!attrs || !gp11_attributes_count (attrs))
		return NULL;
	
	attr = gp11_attributes_at (attrs, 0);
	g_return_val_if_fail (attr, NULL);
	attr = gp11_attribute_dup (attr);
	gp11_attributes_unref (attrs);
	return attr;
}

/**
 * gp11_object_get_one_async:
 * @object: The object to get an attribute from.
 * @attr_type: The attribute to get.
 * @cancellable: Optional cancellation object, or NULL.
 * @callback: Called when the operation completes.
 * @user_data: Data to be passed to the callback.
 * 
 * Get the specified attribute from the object. This call will
 * return immediately and complete asynchronously.
 **/
void
gp11_object_get_one_async (GP11Object *object, gulong attr_type, GCancellable *cancellable,
                           GAsyncReadyCallback callback, gpointer user_data)
{
	gp11_object_get_async (object, &attr_type, 1, cancellable, callback, user_data);
}

/**
 * gp11_object_get_one_finish:
 * @object: The object to get an attribute from.
 * @result: The result passed to the callback.
 * @err: A location to store an error.
 *
 * Get the result of an operation to get an attribute from 
 * an object. 
 * 
 * Return value: The PKCS#11 attribute or NULL if an error occurred.
 **/

GP11Attribute*
gp11_object_get_one_finish (GP11Object *object, GAsyncResult *result, GError **err)
{
	GP11Attributes *attrs;
	GP11Attribute *attr;
	
	attrs = gp11_object_get_finish (object, result, err);
	if (!attrs)
		return NULL;
	
	attr = gp11_attributes_at (attrs, 0);
	g_return_val_if_fail (attr, NULL);
	attr = gp11_attribute_dup (attr);
	gp11_attributes_unref (attrs);
	return attr;
}

