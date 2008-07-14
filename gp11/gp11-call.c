
#include "gp11-private.h"


static GThreadPool *thread_pool = NULL;
static GAsyncQueue *completed_queue = NULL;
static guint completed_id = 0;

static void _gp11_call_implement_async_result (GAsyncResultIface *iface);

G_DEFINE_TYPE_EXTENDED (GP11Call, _gp11_call, G_TYPE_OBJECT, 0,
        G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_RESULT, _gp11_call_implement_async_result));

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
process_async_call (gpointer data, gpointer unused)
{
	GP11Call *call = GP11_CALL (data);
	g_assert (GP11_IS_CALL (call));

	g_assert (call->rv == CKR_OK);
	
	call->rv = perform_call (call->func, call->cancellable, 
	                         call->args);
	
	g_async_queue_push (completed_queue, call);
	
	/* Wakeup main thread if on a separate thread */
	g_main_context_wakeup (NULL);
}
static void 
process_result (GP11Call *call, gpointer unused)
{
	/* Double check a few things */
	g_assert (GP11_IS_CALL (call));
	
	if (call->cancellable) {
		/* Don't call the callback when cancelled */
		if (g_cancellable_is_cancelled (call->cancellable))
			return;
	}
	
	if (call->callback) {
		g_assert (G_IS_OBJECT (call->object));
		(call->callback) (G_OBJECT (call->object), G_ASYNC_RESULT (call), 
				  call->user_data);
	}
}

static gboolean
completed_prepare(GSource* source, gint *timeout)
{
	gboolean have;
	g_assert (completed_queue);
	have = g_async_queue_length (completed_queue) > 0;
	*timeout = have ? 0 : -1;
	return have;
}

static gboolean
completed_check(GSource* source)
{
	g_assert (completed_queue);
	return g_async_queue_length (completed_queue) > 0;
}

static gboolean
completed_dispatch(GSource* source, GSourceFunc callback, gpointer user_data)
{
	gpointer *call;
	
	g_assert (completed_queue);
	g_assert (callback);
	
	call = g_async_queue_try_pop (completed_queue);
	if (call) {
		((GFunc)callback) (call, user_data);
		g_object_unref (call);
	}

	return TRUE;
}

static void
completed_finalize(GSource* source)
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
	GMainContext *context;
	GError *err = NULL;
	GSource *src;

	_gp11_call_parent_class = g_type_class_peek_parent (klass);
	gobject_class->finalize = _gp11_call_finalize;
	
	g_assert (!thread_pool);
	thread_pool = g_thread_pool_new ((GFunc)process_async_call, NULL, -1, FALSE, &err);
	if (!thread_pool) {
		g_critical ("couldn't create thread pool: %s", 
		            err && err->message ? err->message : "");
		return;
	}
	
	g_assert (!completed_queue);
	completed_queue = g_async_queue_new_full (g_object_unref);
	g_assert (completed_queue);
	
	context = g_main_context_default ();
	g_assert (context);
	
	/* Add our idle handler which processes other tasks */
	g_assert (!completed_id);
	src = g_source_new (&completed_functions, sizeof (GSource));
	completed_id = g_source_attach (src, context);
	g_source_set_callback (src, (GSourceFunc)process_result, NULL, NULL);
	g_source_unref (src);
}

/* ----------------------------------------------------------------------------
 * PUBLIC
 */

void
_gp11_call_uninitialize (void)
{
	GMainContext *context;
	GSource *src;

	if (thread_pool) {
		g_thread_pool_free (thread_pool, FALSE, TRUE);
		thread_pool = NULL;
	}
	
	if (completed_id) {
		context = g_main_context_default ();
		g_return_if_fail (context);
		
		src = g_main_context_find_source_by_id (context, completed_id);
		g_assert (src);
		g_source_destroy (src);
		completed_id = 0;
	}
	if (completed_queue) {
		g_async_queue_unref (completed_queue);
		completed_queue = NULL;
	}
}

gboolean
_gp11_call_sync (gpointer object, gpointer func, gpointer data, 
                 GCancellable *cancellable, GError **err)
{
	GP11Arguments *args = (GP11Arguments*)data;
	GP11Module *module;
	CK_RV rv;
	
	g_assert (G_IS_OBJECT (object));
	g_assert (func);
	g_assert (args);
	
	g_object_get (object, "module", &module, "handle", &args->handle, NULL);
	g_assert (GP11_IS_MODULE (module));
	
	args->pkcs11 = module->funcs;
	g_object_unref (module);
	
	rv = perform_call ((GP11CallFunc)func, cancellable, args);
	if (rv == CKR_OK)
		return TRUE;
	
	g_set_error (err, GP11_ERROR, rv, gp11_message_from_rv (rv));
	return FALSE;
}

gpointer
_gp11_call_async_prep (gpointer object, gpointer func, gsize args_size, gpointer destroy)
{
	GP11Arguments *args;
	GP11Module *module;
	GP11Call *call;

	g_assert (G_IS_OBJECT (object));
	g_assert (func);
	
	if (!destroy)
		destroy = g_free;

	if (args_size == 0)
		args_size = sizeof (GP11Arguments);
	g_assert (args_size >= sizeof (GP11Arguments));
	
	args = g_malloc0 (args_size);
	g_object_get (object, "module", &module, "handle", &args->handle, NULL);
	g_assert (GP11_IS_MODULE (module));
	args->pkcs11 = module->funcs;
	g_object_unref (module);
	
	call = g_object_new (GP11_TYPE_CALL, NULL);
	call->destroy = (GDestroyNotify)destroy;
	call->func = (GP11CallFunc)func;
	call->object = object;
	g_object_ref (object);

	/* Hook the two together */
	call->args = args;
	call->args->call = call;

	return args;
}

void
_gp11_call_async_go (gpointer data, GCancellable *cancellable, 
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
	
	g_assert (thread_pool);
	g_thread_pool_push (thread_pool, args->call, NULL);
}

gboolean
_gp11_call_basic_finish (gpointer object, GAsyncResult *result, GError **err)
{
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_CALL (result), FALSE);
	
	rv = GP11_CALL (result)->rv;
	if (rv == CKR_OK)
		return TRUE;
	
	g_set_error (err, GP11_ERROR, rv, gp11_message_from_rv (rv));
	return FALSE;	
}
