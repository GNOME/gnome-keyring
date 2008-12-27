/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gp11-call.c - the GObject PKCS#11 wrapper library

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

#include "gp11-private.h"

#include <string.h>

typedef struct _GP11CallSource GP11CallSource;

static gpointer _gp11_call_parent_class = NULL;

struct _GP11Call {
	GObject parent;
	GP11Module *module;
	
	/* For making the call */
	GP11CallFunc func;
	GP11Arguments *args;
	GCancellable *cancellable;
	GDestroyNotify destroy;
	CK_RV rv;
	
	/* For result callback only */
	gpointer object;
	GAsyncReadyCallback callback;
	gpointer user_data;
	
	/* For authenticating */
	gboolean do_login;
	gchar *password;
};

struct _GP11CallClass {
	GObjectClass parent;
	GThreadPool *thread_pool;
	GAsyncQueue *completed_queue;
	guint completed_id;
};

struct _GP11CallSource {
	GSource source;
	GP11CallClass *klass;
};

/* ----------------------------------------------------------------------------
 * HELPER FUNCTIONS
 */

static CK_RV
perform_call (GP11CallFunc func, GCancellable *cancellable, GP11Arguments *args)
{
	CK_RV rv;
	
	/* Double check a few things */
	g_assert (func);
	g_assert (args);

	if (cancellable) {
		if (g_cancellable_is_cancelled (cancellable)) { 
			return CKR_FUNCTION_CANCELED;
		}
		
		/* Push for the notify callback */
		g_object_ref (cancellable);
		g_cancellable_push_current (cancellable);
	}
	
	rv = (func) (args);
	
	if (cancellable) {
		g_cancellable_pop_current (cancellable);
		g_object_unref (cancellable);
	}
	
	return rv;
}

static void
process_async_call (gpointer data, GP11CallClass *klass)
{
	GP11Call *call = GP11_CALL (data);
	CK_ULONG pin_len;
	
	g_assert (GP11_IS_CALL (call));
	
	/* Try to login to the token, with the provided password */
	if (call->do_login) {
		call->do_login = FALSE;

		pin_len = call->password ? strlen (call->password) : 0;
		call->rv = (call->args->pkcs11->C_Login) (call->args->handle, CKU_USER, 
		                                          (CK_UTF8CHAR_PTR)call->password, 
		                                          pin_len);
		
		/* Fix the result so that we'll try the login again */
		if (call->rv == CKR_PIN_INCORRECT)
			call->rv = CKR_USER_NOT_LOGGED_IN;
		
	/* An actual call */
	} else {
		call->rv = perform_call (call->func, call->cancellable, call->args);
	}
	
	g_async_queue_push (klass->completed_queue, call);
	
	/* Wakeup main thread if on a separate thread */
	g_main_context_wakeup (NULL);
}

static void 
process_result (GP11Call *call, gpointer unused)
{
	GP11Slot *slot;
	
	/* Double check a few things */
	g_assert (GP11_IS_CALL (call));
	
	if (call->cancellable) {
		/* Don't call the callback when cancelled */
		if (g_cancellable_is_cancelled (call->cancellable))
			call->rv = CKR_FUNCTION_CANCELED;
	}
	
	/* 
	 * Now if this is a session call, and the slot wants does 
	 * auto-login, then we try to get a password and do auto login.
	 */
	if (call->rv == CKR_USER_NOT_LOGGED_IN && GP11_IS_SESSION (call->object)) {
		g_free (call->password);
		call->password = NULL;
		slot = gp11_session_get_slot (GP11_SESSION (call->object));
		g_assert (GP11_IS_SLOT (slot));
		call->do_login = _gp11_slot_token_authentication (slot, &call->password);
		g_object_unref (slot);
	}
	
	/* If we're supposed to do a login, then queue this call again */
	if (call->do_login) {
		g_object_ref (call);
		g_thread_pool_push (GP11_CALL_GET_CLASS (call)->thread_pool, call, NULL);
		return;
	}
	
	/* All done, finish processing */
	if (call->callback) {
		g_assert (G_IS_OBJECT (call->object));
		(call->callback) (G_OBJECT (call->object), G_ASYNC_RESULT (call), 
				  call->user_data);
	}
}

static gboolean
process_completed (GP11CallClass *klass)
{
	gpointer call;

	g_assert (klass->completed_queue);

	call = g_async_queue_try_pop (klass->completed_queue);
	if (call) {
		process_result (call, NULL);
		g_object_unref (call);
		return TRUE;
	}
	
	return FALSE;
}

static gboolean
completed_prepare(GSource* base, gint *timeout)
{
	GP11CallSource *source = (GP11CallSource*)base;
	gboolean have;
	
	g_assert (source->klass->completed_queue);
	have = g_async_queue_length (source->klass->completed_queue) > 0;
	*timeout = have ? 0 : -1;
	return have;
}

static gboolean
completed_check(GSource* base)
{
	GP11CallSource *source = (GP11CallSource*)base;
	g_assert (source->klass->completed_queue);
	return g_async_queue_length (source->klass->completed_queue) > 0;
}

static gboolean
completed_dispatch(GSource* base, GSourceFunc callback, gpointer user_data)
{
	GP11CallSource *source = (GP11CallSource*)base;
	process_completed (source->klass);
	return TRUE;
}

static void
completed_finalize(GSource* base)
{
	
}

static GSourceFuncs completed_functions = {
	completed_prepare,
	completed_check,
	completed_dispatch,
	completed_finalize
};

/* ----------------------------------------------------------------------------
 * OBJECT 
 */

static void
_gp11_call_init (GP11Call *call)
{
	call->rv = CKR_OK;
}

static void
_gp11_call_finalize (GObject *obj)
{
	GP11Call *call = GP11_CALL (obj);
	
	if (call->module)
		g_object_unref (call->module);
	call->module = NULL;

	if (call->object)
		g_object_unref (call->object);
	call->object = NULL;
	
	if (call->cancellable)
		g_object_unref (call->cancellable);
	call->cancellable = NULL;

	if (call->destroy)
		(call->destroy) (call->args);
	call->destroy = NULL;
	call->args = NULL;
	
	if (call->password)
		g_free (call->password);
	call->password = NULL;
	
	G_OBJECT_CLASS (_gp11_call_parent_class)->finalize (obj);
}

static gpointer
_gp11_call_get_user_data (GAsyncResult *async_result)
{
	g_return_val_if_fail (GP11_IS_CALL (async_result), NULL);
	return GP11_CALL (async_result)->user_data;
}

static GObject*  
_gp11_call_get_source_object (GAsyncResult *async_result)
{
	g_return_val_if_fail (GP11_IS_CALL (async_result), NULL);
	return GP11_CALL (async_result)->object;	
}

static void 
_gp11_call_implement_async_result (GAsyncResultIface *iface)
{
	iface->get_user_data = _gp11_call_get_user_data;
	iface->get_source_object = _gp11_call_get_source_object;
}

static void
_gp11_call_class_init (GP11CallClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	_gp11_call_parent_class = g_type_class_peek_parent (klass);
	gobject_class->finalize = _gp11_call_finalize;
}

static void
_gp11_call_base_init (GP11CallClass *klass)
{
	GP11CallSource *source;
	GMainContext *context;
	GError *err = NULL;

	klass->thread_pool = g_thread_pool_new ((GFunc)process_async_call, klass, 16, FALSE, &err);
	if (!klass->thread_pool) {
		g_critical ("couldn't create thread pool: %s", 
		            err && err->message ? err->message : "");
		return;
	}
	
	klass->completed_queue = g_async_queue_new_full (g_object_unref);
	g_assert (klass->completed_queue);
	
	context = g_main_context_default ();
	g_assert (context);
	
	/* Add our idle handler which processes other tasks */
	source = (GP11CallSource*)g_source_new (&completed_functions, sizeof (GP11CallSource));
	source->klass = klass;
	klass->completed_id = g_source_attach ((GSource*)source, context);
	g_source_set_callback ((GSource*)source, NULL, NULL, NULL);
	g_source_unref ((GSource*)source);
}

static void
_gp11_call_base_finalize (GP11CallClass *klass)
{
	GMainContext *context;
	GSource *src;

	if (klass->thread_pool) {
		g_assert (g_thread_pool_unprocessed (klass->thread_pool) == 0);
		g_thread_pool_free (klass->thread_pool, FALSE, TRUE);
		klass->thread_pool = NULL;
	}
	
	if (klass->completed_id) {
		context = g_main_context_default ();
		g_return_if_fail (context);
		
		src = g_main_context_find_source_by_id (context, klass->completed_id);
		g_assert (src);
		g_source_destroy (src);
		klass->completed_id = 0;
	}
	
	if (klass->completed_queue) {
		g_assert (g_async_queue_length (klass->completed_queue));
		g_async_queue_unref (klass->completed_queue);
		klass->completed_queue = NULL;
	}
}

GType
_gp11_call_get_type (void) 
{
	static volatile gsize type_id__volatile = 0;
	
	if (g_once_init_enter (&type_id__volatile)) {
		
		static const GTypeInfo type_info = {
			sizeof (GP11CallClass), 
			(GBaseInitFunc)_gp11_call_base_init, 
			(GBaseFinalizeFunc)_gp11_call_base_finalize, 
			(GClassInitFunc)_gp11_call_class_init, 
			(GClassFinalizeFunc)NULL, 
			NULL,   // class_data 
			sizeof (GP11Call), 
			0,      // n_preallocs 
			(GInstanceInitFunc)_gp11_call_init, 
		};

		static const GInterfaceInfo interface_info = {
			(GInterfaceInitFunc)_gp11_call_implement_async_result
		};

		GType type_id = g_type_register_static (G_TYPE_OBJECT, "_GP11Call", &type_info, 0); 
		g_type_add_interface_static (type_id, G_TYPE_ASYNC_RESULT, &interface_info);

		g_once_init_leave (&type_id__volatile, type_id);
	}
	
	return type_id__volatile;
}

/* ----------------------------------------------------------------------------
 * PUBLIC
 */

void
_gp11_call_uninitialize (void)
{

}

gboolean
_gp11_call_sync (gpointer object, gpointer func, gpointer data, 
                 GCancellable *cancellable, GError **err)
{
	GP11Arguments *args = (GP11Arguments*)data;
	gchar *password = NULL;
	GP11Module *module = NULL;
	GP11Slot *slot; 
	CK_ULONG pin_len;
	CK_RV rv;
	
	g_assert (G_IS_OBJECT (object));
	g_assert (func);
	g_assert (args);
	
	g_object_get (object, "module", &module, "handle", &args->handle, NULL);
	g_assert (GP11_IS_MODULE (module));

	/* We now hold a reference to module until below */
	args->pkcs11 = gp11_module_get_function_list (module);
	g_assert (args->pkcs11);
	
	rv = perform_call ((GP11CallFunc)func, cancellable, args);
		
	/* 
	 * Now if this is a session call, and the slot wants does 
	 * auto-login, then we try to get a password and do auto login.
	 */
	if (rv == CKR_USER_NOT_LOGGED_IN && GP11_IS_SESSION (object)) {
		
		do {
			slot = gp11_session_get_slot (GP11_SESSION (object));
			if (!_gp11_slot_token_authentication (slot, &password)) {
				rv = CKR_USER_NOT_LOGGED_IN;
			} else {
				pin_len = password ? strlen (password) : 0; 
				rv = (args->pkcs11->C_Login) (args->handle, CKU_USER, 
				                              (CK_UTF8CHAR_PTR)password, pin_len);
			}
			g_object_unref (slot);
		} while (rv == CKR_PIN_INCORRECT);

		/* If we logged in successfully then try again */
		if (rv == CKR_OK)
			rv = perform_call ((GP11CallFunc)func, cancellable, args);
	}
	
	g_object_unref (module);

	if (rv == CKR_OK)
		return TRUE;

	g_set_error (err, GP11_ERROR, rv, "%s", gp11_message_from_rv (rv));
	return FALSE;
}

gpointer
_gp11_call_async_prep (gpointer object, gpointer cb_object, gpointer func, 
                       gsize args_size, gpointer destroy)
{
	GP11Arguments *args;
	GP11Call *call;

	g_assert (!object || G_IS_OBJECT (object));
	g_assert (func);
	
	if (!destroy)
		destroy = g_free;

	if (args_size == 0)
		args_size = sizeof (GP11Arguments);
	g_assert (args_size >= sizeof (GP11Arguments));
	
	args = g_malloc0 (args_size);
	call = g_object_new (GP11_TYPE_CALL, NULL);
	call->destroy = (GDestroyNotify)destroy;
	call->func = (GP11CallFunc)func;
	call->object = cb_object;
	g_object_ref (cb_object);

	/* Hook the two together */
	call->args = args;
	call->args->call = call;

	/* Setup call object if available */
	if (object != NULL)
		_gp11_call_async_object (call, object);

	return args;
}

void
_gp11_call_async_object (GP11Call *call, gpointer object)
{
	g_assert (GP11_IS_CALL (call));
	g_assert (call->args);
	
	if (call->module)
		g_object_unref (call->module);
	call->module = NULL;
	
	g_object_get (object, "module", &call->module, "handle", &call->args->handle, NULL);
	g_assert (GP11_IS_MODULE (call->module));
	call->args->pkcs11 = gp11_module_get_function_list (call->module);
	
	/* We now hold a reference on module until finalize */
}

GP11Call*
_gp11_call_async_ready (gpointer data, GCancellable *cancellable, 
                        GAsyncReadyCallback callback, gpointer user_data)
{
	GP11Arguments *args = (GP11Arguments*)data;
	g_assert (GP11_IS_CALL (args->call));
	
	args->call->cancellable = cancellable;
	if (cancellable) {
		g_assert (G_IS_CANCELLABLE (cancellable));
		g_object_ref (cancellable);
	}
	
	args->call->callback = callback;
	args->call->user_data = user_data;
	
	return args->call;
}

void
_gp11_call_async_go (GP11Call *call)
{
	g_assert (GP11_IS_CALL (call));
	g_assert (call->args->pkcs11);

	/* To keep things balanced, process at one completed event */
	process_completed(GP11_CALL_GET_CLASS (call));

	g_assert (GP11_CALL_GET_CLASS (call)->thread_pool);
	g_thread_pool_push (GP11_CALL_GET_CLASS (call)->thread_pool, call, NULL);
}

void
_gp11_call_async_ready_go (gpointer data, GCancellable *cancellable, 
                           GAsyncReadyCallback callback, gpointer user_data)
{
	GP11Call *call = _gp11_call_async_ready (data, cancellable, callback, user_data);
	_gp11_call_async_go (call);
}

gboolean
_gp11_call_basic_finish (GAsyncResult *result, GError **err)
{
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_CALL (result), FALSE);
	
	rv = GP11_CALL (result)->rv;
	if (rv == CKR_OK)
		return TRUE;
	
	g_set_error (err, GP11_ERROR, rv, "%s", gp11_message_from_rv (rv));
	return FALSE;	
}

void
_gp11_call_async_short (GP11Call *call, CK_RV rv)
{
	g_assert (GP11_IS_CALL (call));
	
	call->rv = rv;

	/* Already complete, so just push it for processing in main loop */
	g_assert (GP11_CALL_GET_CLASS (call)->completed_queue);
	g_async_queue_push (GP11_CALL_GET_CLASS (call)->completed_queue, call);
}

gpointer
_gp11_call_get_arguments (GP11Call *call)
{
	g_assert (GP11_IS_CALL (call));
	return call->args;
}
