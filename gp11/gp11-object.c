
#include "config.h"

#include "gp11.h"
#include "gp11-private.h"

#include <string.h>

enum {
	PROP_0,
	PROP_MODULE,
	PROP_SESSION,
	PROP_HANDLE
};

G_DEFINE_TYPE (GP11Object, gp11_object, G_TYPE_OBJECT);

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
	case PROP_SESSION:
		g_return_if_fail (!object->session);
		object->session = g_value_get_object (value);
		g_return_if_fail (object->session);
		g_object_ref (object->session);
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
	
	if (object->session)
		g_object_unref (object->session);
	object->session = NULL;
	
	if (object->module)
		g_object_unref (object->module);
	object->module = NULL;

	G_OBJECT_CLASS (gp11_object_parent_class)->dispose (obj);
}

static void
gp11_object_finalize (GObject *obj)
{
	GP11Object *object = GP11_OBJECT (obj);

	g_assert (object->session == NULL);
	g_assert (object->module == NULL);
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

	g_object_class_install_property (gobject_class, PROP_SESSION,
		g_param_spec_object ("session", "Session", "PKCS11 Session",
		                     GP11_TYPE_SESSION, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_HANDLE,
		g_param_spec_uint ("handle", "Object Handle", "PKCS11 Object Handle",
		                   0, G_MAXUINT, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* ----------------------------------------------------------------------------
 * PUBLIC 
 */

GP11Object*
gp11_object_from_handle (GP11Session *session, CK_OBJECT_HANDLE handle)
{
	g_return_val_if_fail (GP11_IS_SESSION (session), NULL);
	return g_object_new (GP11_TYPE_OBJECT, "module", session->module, "handle", handle, "session", session, NULL);
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

gboolean
gp11_object_destroy (GP11Object *object, GError **err)
{
	return gp11_object_destroy_full (object, NULL, err);
}

gboolean
gp11_object_destroy_full (GP11Object *object, GCancellable *cancellable, GError **err)
{
	Destroy args = { GP11_ARGUMENTS_INIT, 0 };
	g_return_val_if_fail (GP11_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (GP11_IS_SESSION (object->session), FALSE);
	args.object = object->handle;
	return _gp11_call_sync (object->session, perform_destroy, &args, cancellable, err);
}

void
gp11_object_destroy_async (GP11Object *object, GCancellable *cancellable,
                           GAsyncReadyCallback callback, gpointer user_data)
{
	Destroy* args;

	g_return_if_fail (GP11_IS_OBJECT (object));
	g_return_if_fail (GP11_IS_SESSION (object->session));

	args = _gp11_call_async_prep (object->session, perform_destroy, sizeof (*args), NULL);
	args->object = object->handle;
	
	_gp11_call_async_go (args, cancellable, callback, user_data);
}

gboolean
gp11_object_destroy_finish (GP11Object *object, GAsyncResult *result, GError **err)
{
	return _gp11_call_basic_finish (object, result, err);
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

gboolean
gp11_object_set_full (GP11Object *object, GP11Attributes *attrs,
                      GCancellable *cancellable, GError **err)
{
	SetAttributes args;
	
	g_return_val_if_fail (GP11_IS_OBJECT (object), FALSE);
	
	memset (&args, 0, sizeof (args));
	args.attrs = attrs;
	args.object = object->handle;

	return _gp11_call_sync (object->session, perform_set_attributes, &args, cancellable, err);
}

void
gp11_object_set_async (GP11Object *object, GP11Attributes *attrs, GCancellable *cancellable,
                       GAsyncReadyCallback callback, gpointer user_data)
{
	SetAttributes *args;

	g_return_if_fail (GP11_IS_OBJECT (object));

	args = _gp11_call_async_prep (object->session, perform_set_attributes, 
	                              sizeof (*args), free_set_attributes);
	args->attrs = attrs;
	gp11_attributes_ref (attrs);
	args->object = object->handle;
	
	_gp11_call_async_go (args, cancellable, callback, user_data);
}

gboolean
gp11_object_set_finish (GP11Object *object, GAsyncResult *result, GError **err)
{
	return _gp11_call_basic_finish (object, result, err);
}

typedef struct _GetAttributes {
	GP11Arguments base;
	guint *attr_types;
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
	if (rv != CKR_OK) {
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
	if (rv == CKR_OK) {
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
	return rv;
}

GP11Attributes*
gp11_object_get (GP11Object *object, GError **err, ...)
{
	GP11Attributes *result;
	GArray *array;
	va_list va;
	guint type;
	
	array = g_array_new (0, 1, sizeof (guint));
	va_start (va, err);
	for (;;) {
		type = va_arg (va, guint);
		if (type == (guint)-1)
			break;
		g_array_append_val (array, type);
	}
	va_end (va);
	
	result = gp11_object_get_full (object, (guint*)array->data, array->len, NULL, err);
	g_array_free (array, TRUE);
	return result;
}

GP11Attributes*
gp11_object_get_full (GP11Object *object, guint *attr_types, gsize n_attr_types,
                      GCancellable *cancellable, GError **err)
{
	GetAttributes args;
	
	g_return_val_if_fail (GP11_IS_OBJECT (object), FALSE);
	
	memset (&args, 0, sizeof (args));
	args.attr_types = attr_types;
	args.n_attr_types = n_attr_types;
	args.object = object->handle;

	if (!_gp11_call_sync (object->session, perform_get_attributes, &args, cancellable, err)) {
		gp11_attributes_unref (args.results);
		return NULL;
	}
	
	return args.results;
}

void
gp11_object_get_async (GP11Object *object, guint *attr_types, gsize n_attr_types,
                       GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data)
{
	GetAttributes *args;

	g_return_if_fail (GP11_IS_OBJECT (object));

	args = _gp11_call_async_prep (object->session, perform_get_attributes, 
	                              sizeof (*args), free_get_attributes);
	args->n_attr_types = n_attr_types;
	if (n_attr_types)
		args->attr_types = g_memdup (attr_types, sizeof (guint) * n_attr_types);
	args->object = object->handle;
	
	_gp11_call_async_go (args, cancellable, callback, user_data);
}

GP11Attributes*
gp11_object_get_finish (GP11Object *object, GAsyncResult *result, GError **err)
{
	GP11Attributes *results;
	GetAttributes *args;
	
	if (!_gp11_call_basic_finish (object, result, err))
		return NULL;
	
	args = _gp11_call_arguments (result, GetAttributes);
	
	results = args->results;
	args->results = NULL;
	
	return results;
}

GP11Attribute*
gp11_object_get_one (GP11Object *object, guint attr_type, GError **err)
{
	return gp11_object_get_one_full (object, attr_type, NULL, err);
}

GP11Attribute*
gp11_object_get_one_full (GP11Object *object, guint attr_type, 
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

void
gp11_object_get_one_async (GP11Object *object, guint attr_type, GCancellable *cancellable,
                           GAsyncReadyCallback callback, gpointer user_data)
{
	gp11_object_get_async (object, &attr_type, 1, cancellable, callback, user_data);
}

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
