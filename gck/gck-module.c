/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-module.c - the GObject PKCS#11 wrapper library

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

#include "gck.h"
#include "gck-private.h"
#include "gck-marshal.h"

#include <string.h>

/**
 * SECTION:gck-module
 * @title: GckModule
 * @short_description: A loaded and initialized PKCS#11 module.
 *
 * A GckModule object holds a loaded PKCS#11 module. A PKCS#11 module is a shared library.
 *
 * You can load and initialize a PKCS#11 module with the gck_module_initialize() call. If you already
 * have a loaded and initialized module that you'd like to use with the various gck functions, then
 * you can use gck_module_new().
 */

/**
 * GckModule:
 *
 * Holds a loaded and initialized PKCS#11 module.
 */

/**
 * GckModuleInfo:
 * @pkcs11_version_major: The major version of the module.
 * @pkcs11_version_minor: The minor version of the module.
 * @manufacturer_id: The module manufacturer.
 * @flags: The module PKCS&num;11 flags.
 * @library_description: The module description.
 * @library_version_major: The major version of the library.
 * @library_version_minor: The minor version of the library.
 *
 * Holds information about the PKCS&num;11 module.
 *
 * This structure corresponds to CK_MODULE_INFO in the PKCS#11 standard. The
 * strings are NULL terminated for easier use.
 *
 * Use gck_module_info_free() to release this structure when done with it.
 */

/*
 * MT safe
 *
 * The only thing that can change after object initialization in
 * a GckModule is the finalized flag, which can be set
 * to 1 in dispose.
 */

enum {
	PROP_0,
	PROP_PATH,
	PROP_FUNCTIONS,
	PROP_OPTIONS
};

enum {
	AUTHENTICATE_SLOT,
	AUTHENTICATE_OBJECT,
	LAST_SIGNAL
};

typedef struct _GckModuleData {
	GModule *module;
	gchar *path;
	gboolean initialized;
	CK_FUNCTION_LIST_PTR funcs;
	CK_C_INITIALIZE_ARGS init_args;
} GckModuleData;

typedef struct _GckModulePrivate {
	GckModuleData data;
	GStaticMutex mutex;
	gboolean finalized;
	guint options;
} GckModulePrivate;

#define gck_module_GET_DATA(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GCK_TYPE_MODULE, GckModuleData))

G_DEFINE_TYPE (GckModule, gck_module, G_TYPE_OBJECT);

static guint signals[LAST_SIGNAL] = { 0 };

/* ----------------------------------------------------------------------------
 * HELPERS
 */

static CK_RV
create_mutex (void **mutex)
{
	if (!mutex)
		return CKR_ARGUMENTS_BAD;

	if (!g_thread_supported ()) {
		g_warning ("cannot create pkcs11 mutex, threading has not been initialized");
		return CKR_GENERAL_ERROR;
	}

	*mutex = g_mutex_new ();
	g_return_val_if_fail (*mutex, CKR_GENERAL_ERROR);
	return CKR_OK;
}

static CK_RV
destroy_mutex (void *mutex)
{
	if (!mutex)
		return CKR_MUTEX_BAD;
	g_mutex_free ((GMutex*)mutex);
	return CKR_OK;
}

static CK_RV
lock_mutex (void *mutex)
{
	if (!mutex)
		return CKR_MUTEX_BAD;
	g_mutex_lock ((GMutex*)mutex);
	return CKR_OK;
}

static CK_RV
unlock_mutex (void *mutex)
{
	if (!mutex)
		return CKR_MUTEX_BAD;
	g_mutex_unlock ((GMutex*)mutex);
	return CKR_OK;
}

/* ----------------------------------------------------------------------------
 * INTERNAL
 */

static GckModulePrivate*
lock_private (gpointer obj)
{
	GckModulePrivate *pv;
	GckModule *self;

	g_assert (GCK_IS_MODULE (obj));
	self = GCK_MODULE (obj);

	g_object_ref (self);

	pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_MODULE, GckModulePrivate);
	g_static_mutex_lock (&pv->mutex);

	return pv;
}

static void
unlock_private (gpointer obj, GckModulePrivate *pv)
{
	GckModule *self;

	g_assert (pv);
	g_assert (GCK_IS_MODULE (obj));

	self = GCK_MODULE (obj);

	g_assert (G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_MODULE, GckModulePrivate) == pv);

	g_static_mutex_unlock (&pv->mutex);
	g_object_unref (self);
}

gboolean
_gck_module_fire_authenticate_slot (GckModule *self, GckSlot *slot, gchar *label, gchar **password)
{
	GckTokenInfo *info;
	gchar *allocated = NULL;
	gboolean ret;

	g_assert (GCK_IS_MODULE (self));

	info = gck_slot_get_token_info (slot);
	if (info != NULL) {

		/*
		 * We'll have tried to login at least once at this point,
		 * with NULL password. This means that CKF_PROTECTED_AUTHENTICATION_PATH
		 * tokens have had their chance and we don't need to prompt for it.
		 */

		if (info->flags & CKF_PROTECTED_AUTHENTICATION_PATH)
			return FALSE;

		if (label == NULL)
			label = allocated = g_strdup (info->label);

		gck_token_info_free (info);
	}

	g_signal_emit (self, signals[AUTHENTICATE_SLOT], 0, slot, label, password, &ret);
	g_free (allocated);
	return ret;
}

gboolean
_gck_module_fire_authenticate_object (GckModule *self, GckObject *object,
                                      gchar *label, gchar **password)
{
	GckTokenInfo *info;
	GckSession *session;
	GckSlot *slot;
	gboolean ret;

	g_assert (GCK_IS_MODULE (self));
	g_assert (GCK_IS_OBJECT (object));
	g_assert (password);

	session = gck_object_get_session (object);
	slot = gck_session_get_slot (session);
	g_object_unref (session);

	info = gck_slot_get_token_info (slot);
	g_object_unref (slot);

	if (info != NULL) {
		if (info->flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
			gck_token_info_free (info);
			*password = NULL;
			return TRUE;
		}

		gck_token_info_free (info);
	}

	g_signal_emit (self, signals[AUTHENTICATE_OBJECT], 0, object, label, password, &ret);
	return ret;
}

/* ----------------------------------------------------------------------------
 * OBJECT
 */

static gboolean
gck_module_real_authenticate_slot (GckModule *module, GckSlot *self, gchar *label, gchar **password)
{
	return FALSE;
}

static gboolean
gck_module_real_authenticate_object (GckModule *module, GckObject *object, gchar *label, gchar **password)
{
	return FALSE;
}

static void
gck_module_init (GckModule *self)
{
	GckModulePrivate *pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_MODULE, GckModulePrivate);
	g_static_mutex_init (&pv->mutex);
}

static void
gck_module_get_property (GObject *obj, guint prop_id, GValue *value,
                          GParamSpec *pspec)
{
	GckModule *self = GCK_MODULE (obj);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, gck_module_get_path (self));
		break;
	case PROP_FUNCTIONS:
		g_value_set_pointer (value, gck_module_get_functions (self));
		break;
	case PROP_OPTIONS:
		g_value_set_uint (value, gck_module_get_options (self));
		break;
	}
}

static void
gck_module_set_property (GObject *obj, guint prop_id, const GValue *value,
                          GParamSpec *pspec)
{
	GckModule *self = GCK_MODULE (obj);
	GckModuleData *data = gck_module_GET_DATA (obj);

	/* Only allowed during initialization */
	switch (prop_id) {
	case PROP_PATH:
		g_return_if_fail (!data->path);
		data->path = g_value_dup_string (value);
		break;
	case PROP_FUNCTIONS:
		g_return_if_fail (!data->funcs);
		data->funcs = g_value_get_pointer (value);
		break;
	case PROP_OPTIONS:
		gck_module_set_options (self, g_value_get_uint (value));
		break;
	}
}

static void
gck_module_dispose (GObject *obj)
{
	GckModuleData *data = gck_module_GET_DATA (obj);
	GckModulePrivate *pv = lock_private (obj);
	gboolean finalize = FALSE;
	CK_RV rv;

	{
		if (!pv->finalized && data->initialized && data->funcs) {
			finalize = TRUE;
			pv->finalized = TRUE;
		}
	}

	unlock_private (obj, pv);

	/* Must be careful when accessing funcs */
	if (finalize) {
		rv = (data->funcs->C_Finalize) (NULL);
		if (rv != CKR_OK) {
			g_warning ("C_Finalize on module '%s' failed: %s",
			           data->path, gck_message_from_rv (rv));
		}
	}

	G_OBJECT_CLASS (gck_module_parent_class)->dispose (obj);
}

static void
gck_module_finalize (GObject *obj)
{
	GckModulePrivate *pv = G_TYPE_INSTANCE_GET_PRIVATE (obj, GCK_TYPE_MODULE, GckModulePrivate);
	GckModuleData *data = gck_module_GET_DATA (obj);

	data->funcs = NULL;

	if (data->module) {
		if (!g_module_close (data->module))
			g_warning ("failed to close the pkcs11 module: %s",
			           g_module_error ());
		data->module = NULL;
	}

	g_free (data->path);
	data->path = NULL;

	g_static_mutex_free (&pv->mutex);

	G_OBJECT_CLASS (gck_module_parent_class)->finalize (obj);
}


static void
gck_module_class_init (GckModuleClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	gck_module_parent_class = g_type_class_peek_parent (klass);

	gobject_class->get_property = gck_module_get_property;
	gobject_class->set_property = gck_module_set_property;
	gobject_class->dispose = gck_module_dispose;
	gobject_class->finalize = gck_module_finalize;

	klass->authenticate_object = gck_module_real_authenticate_object;
	klass->authenticate_slot = gck_module_real_authenticate_slot;

	/**
	 * GckModule:path:
	 *
	 * The PKCS&num;11 module file path.
	 *
	 * This may be set to NULL if this object was created from an already
	 * initialized module via the gck_module_new() function.
	 */
	g_object_class_install_property (gobject_class, PROP_PATH,
		g_param_spec_string ("path", "Module Path", "Path to the PKCS11 Module",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/**
	 * GckModule:functions:
	 *
	 * The raw PKCS&num;11 function list for the module.
	 *
	 * This points to a CK_FUNCTION_LIST structure.
	 */
	g_object_class_install_property (gobject_class, PROP_FUNCTIONS,
		g_param_spec_pointer ("functions", "Function List", "PKCS11 Function List",
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/**
	 * GckModule:options:
	 *
	 * Various option flags related to authentication etc.
	 *
	 * The #GckModule::authenticate-object signal will be fired when an
	 * object needs to be authenticated.
	 */
	g_object_class_install_property (gobject_class, PROP_OPTIONS,
		g_param_spec_uint ("options", "Options", "Module options",
		                  0, G_MAXUINT, 0, G_PARAM_READWRITE));

	/**
	 * GckModule::authenticate-slot:
	 * @module: The module
	 * @slot: The slot to be authenticated.
	 * @string: A displayable label which describes the object.
	 * @password: A gchar** where a password should be returned.
	 *
	 * This signal is emitted when a password is needed to authenticate a PKCS&num;11
	 * slot. If the module prompts for passwords itself, then this signal will
	 * not be emitted.
	 *
	 * Returns: FALSE if the user cancelled, TRUE if we should proceed.
	 */
	signals[AUTHENTICATE_SLOT] = g_signal_new ("authenticate-slot", GCK_TYPE_MODULE,
			G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GckModuleClass, authenticate_slot),
			g_signal_accumulator_true_handled, NULL, _gck_marshal_BOOLEAN__OBJECT_STRING_POINTER,
			G_TYPE_BOOLEAN, 3, GCK_TYPE_SLOT, G_TYPE_STRING, G_TYPE_POINTER);

	/**
	 * GckModule::authenticate-object:
	 * @module: The module.
	 * @object: The object to be authenticated.
	 * @label: A displayable label which describes the object.
	 * @password: A gchar** where a password should be returned.
	 *
	 * This signal is emitted when a password is needed to authenticate a PKCS&num;11
	 * object like a key. If the module prompts for passwords itself, then this signal will
	 * not be emitted.
	 *
	 * Returns: FALSE if the user cancelled, TRUE if we should proceed.
	 */
	signals[AUTHENTICATE_OBJECT] = g_signal_new ("authenticate-object", GCK_TYPE_MODULE,
			G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GckModuleClass, authenticate_object),
			g_signal_accumulator_true_handled, NULL, _gck_marshal_BOOLEAN__OBJECT_STRING_POINTER,
			G_TYPE_BOOLEAN, 3, GCK_TYPE_OBJECT, G_TYPE_STRING, G_TYPE_POINTER);

	g_type_class_add_private (gobject_class, sizeof (GckModulePrivate));
}

/* ----------------------------------------------------------------------------
 * PUBLIC
 */

/**
 * gck_module_info_free:
 * @module_info: The module info to free, or NULL.
 *
 * Free a GckModuleInfo structure.
 **/
void
gck_module_info_free (GckModuleInfo *module_info)
{
	if (!module_info)
		return;
	g_free (module_info->library_description);
	g_free (module_info->manufacturer_id);
	g_free (module_info);
}

/**
 * gck_module_initialize:
 * @path: The file system path to the PKCS#11 module to load.
 * @reserved: Extra arguments for the PKCS#11 module, should usually be NULL.
 * @err: A location to store an error resulting from a failed load.
 *
 * Load and initialize a PKCS#11 module represented by a GckModule object.
 *
 * Return value: The loaded PKCS#11 module or NULL if failed.
 **/
GckModule*
gck_module_initialize (const gchar *path, gpointer reserved, GError **err)
{
	CK_C_GetFunctionList get_function_list;
	CK_FUNCTION_LIST_PTR funcs;
	GckModuleData *data;
	GModule *module;
	GckModule *mod;
	CK_RV rv;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (!err || !*err, NULL);

	/* Load the actual module */
	module = g_module_open (path, 0);
	if (!module) {
		g_set_error (err, GCK_ERROR, (int)CKR_GCK_MODULE_PROBLEM,
		             "Error loading pkcs11 module: %s", g_module_error ());
		return NULL;
	}

	/* Get the entry point */
	if (!g_module_symbol (module, "C_GetFunctionList", (void**)&get_function_list)) {
		g_set_error (err, GCK_ERROR, (int)CKR_GCK_MODULE_PROBLEM,
		             "Invalid pkcs11 module: %s", g_module_error ());
		g_module_close (module);
		return NULL;
	}

	/* Get the function list */
	rv = (get_function_list) (&funcs);
	if (rv != CKR_OK) {
		g_set_error (err, GCK_ERROR, rv, "Couldn't get pkcs11 function list: %s",
		             gck_message_from_rv (rv));
		g_module_close (module);
		return NULL;
	}

	mod = g_object_new (GCK_TYPE_MODULE, "functions", funcs, "path", path, NULL);
	data = gck_module_GET_DATA (mod);
	data->module = module;

	memset (&data->init_args, 0, sizeof (data->init_args));
	data->init_args.flags = CKF_OS_LOCKING_OK;
	data->init_args.CreateMutex = create_mutex;
	data->init_args.DestroyMutex = destroy_mutex;
	data->init_args.LockMutex = lock_mutex;
	data->init_args.UnlockMutex = unlock_mutex;
	data->init_args.pReserved = reserved;

	/* Now initialize the module */
	rv = (data->funcs->C_Initialize) (&data->init_args);
	if (rv != CKR_OK) {
		g_set_error (err, GCK_ERROR, rv, "Couldn't initialize module: %s",
		             gck_message_from_rv (rv));
		g_object_unref (mod);
		return NULL;
	}

	data->initialized = TRUE;
	return mod;
}

/**
 * gck_module_new:
 * @funcs: Initialized PKCS#11 function list pointer
 *
 * Create a GckModule representing a PKCS#11 module. It is assumed that
 * this the module is already initialized. In addition it will not be
 * finalized when complete.
 *
 * Return value: The new PKCS#11 module.
 **/
GckModule*
gck_module_new (CK_FUNCTION_LIST_PTR funcs)
{
	g_return_val_if_fail (funcs, NULL);
	return g_object_new (GCK_TYPE_MODULE, "functions", funcs, NULL);
}

/**
 * gck_module_equal:
 * @module1: A pointer to the first GckModule
 * @module2: A pointer to the second GckModule
 *
 * Checks equality of two modules. Two GckModule objects can point to the same
 * underlying PKCS#11 module.
 *
 * Return value: TRUE if module1 and module2 are equal. FALSE if either is not a GckModule.
 **/
gboolean
gck_module_equal (gconstpointer module1, gconstpointer module2)
{
	GckModuleData *data1, *data2;

	if (module1 == module2)
		return TRUE;
	if (!GCK_IS_MODULE (module1) || !GCK_IS_MODULE (module2))
		return FALSE;

	data1 = gck_module_GET_DATA (module1);
	data2 = gck_module_GET_DATA (module2);

	return data1->funcs == data2->funcs;
}

/**
 * gck_module_hash:
 * @module: A pointer to a GckModule
 *
 * Create a hash value for the GckModule.
 *
 * This function is intended for easily hashing a GckModule to add to
 * a GHashTable or similar data structure.
 *
 * Return value: An integer that can be used as a hash value, or 0 if invalid.
 **/
guint
gck_module_hash (gconstpointer module)
{
	GckModuleData *data;

	g_return_val_if_fail (GCK_IS_MODULE (module), 0);

	data = gck_module_GET_DATA (module);

	return g_direct_hash (data->funcs);
}

/**
 * gck_module_get_info:
 * @self: The module to get info for.
 *
 * Get the info about a PKCS#11 module.
 *
 * Return value: The module info. Release this with gck_module_info_free().
 **/
GckModuleInfo*
gck_module_get_info (GckModule *self)
{
	GckModuleData *data = gck_module_GET_DATA (self);
	GckModuleInfo *modinfo;
	CK_INFO info;
	CK_RV rv;

	g_return_val_if_fail (GCK_IS_MODULE (self), NULL);
	g_return_val_if_fail (data->funcs, NULL);

	memset (&info, 0, sizeof (info));
	rv = (data->funcs->C_GetInfo (&info));
	if (rv != CKR_OK) {
		g_warning ("couldn't get module info: %s", gck_message_from_rv (rv));
		return NULL;
	}

	modinfo = g_new0 (GckModuleInfo, 1);
	modinfo->flags = info.flags;
	modinfo->library_description = gck_string_from_chars (info.libraryDescription,
	                                                       sizeof (info.libraryDescription));
	modinfo->manufacturer_id = gck_string_from_chars (info.manufacturerID,
	                                                   sizeof (info.manufacturerID));
	modinfo->library_version_major = info.libraryVersion.major;
	modinfo->library_version_minor = info.libraryVersion.minor;
	modinfo->pkcs11_version_major = info.cryptokiVersion.major;
	modinfo->pkcs11_version_minor = info.cryptokiVersion.minor;

	return modinfo;
}

/**
 * gck_module_get_slots:
 * @self: The module for which to get the slots.
 * @token_present: Whether to limit only to slots with a token present.
 *
 * Get the GckSlot objects for a given module.
 *
 * Return value: The possibly empty list of slots. Release this with gck_list_unref_free().
 */
GList*
gck_module_get_slots (GckModule *self, gboolean token_present)
{
	GckModuleData *data = gck_module_GET_DATA (self);
	CK_SLOT_ID_PTR slot_list;
	CK_ULONG count, i;
	GList *result;
	CK_RV rv;

	g_return_val_if_fail (GCK_IS_MODULE (self), NULL);
	g_return_val_if_fail (data->funcs, NULL);

	rv = (data->funcs->C_GetSlotList) (token_present ? CK_TRUE : CK_FALSE, NULL, &count);
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot count: %s", gck_message_from_rv (rv));
		return NULL;
	}

	if (!count)
		return NULL;

	slot_list = g_new (CK_SLOT_ID, count);
	rv = (data->funcs->C_GetSlotList) (token_present ? CK_TRUE : CK_FALSE, slot_list, &count);
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot list: %s", gck_message_from_rv (rv));
		g_free (slot_list);
		return NULL;
	}

	result = NULL;
	for (i = 0; i < count; ++i) {
		result = g_list_prepend (result, g_object_new (GCK_TYPE_SLOT,
		                                               "handle", slot_list[i],
		                                               "module", self, NULL));
	}

	g_free (slot_list);
	return g_list_reverse (result);
}

/**
 * gck_module_get_path:
 * @self: The module for which to get the path.
 *
 * Get the file path of this module. This may not be an absolute path, and
 * usually reflects the path passed to gck_module_initialize().
 *
 * Return value: The path, do not modify or free this value.
 **/
const gchar*
gck_module_get_path (GckModule *self)
{
	GckModuleData *data = gck_module_GET_DATA (self);
	g_return_val_if_fail (GCK_IS_MODULE (self), NULL);
	return data->path;
}

/**
 * gck_module_get_functions:
 * @self: The module for which to get the function list.
 *
 * Get the PKCS#11 function list for the module.
 *
 * Return value: The function list, do not modify this structure.
 **/
CK_FUNCTION_LIST_PTR
gck_module_get_functions (GckModule *self)
{
	GckModuleData *data = gck_module_GET_DATA (self);
	g_return_val_if_fail (GCK_IS_MODULE (self), NULL);
	return data->funcs;
}


/**
 * gck_module_get_options:
 * @self: The module to get setting from.
 *
 * Get the various module options, such as auto authenticate etc.
 *
 * Return value: The module options.
 **/
guint
gck_module_get_options (GckModule *self)
{
	GckModulePrivate *pv = lock_private (self);
	guint ret;

	g_return_val_if_fail (pv, FALSE);

	{
		ret = pv->options;
	}

	unlock_private (self, pv);

	return ret;
}

/**
 * gck_module_set_options:
 * @self: The module to set the setting on.
 * @options: Authentication and other options..
 **/
void
gck_module_set_options (GckModule *self, guint options)
{
	GckModulePrivate *pv = lock_private (self);

	g_return_if_fail (pv);

	{
		pv->options = options;
	}

	unlock_private (self, pv);
	g_object_notify (G_OBJECT (self), "options");
}

/**
 * gck_module_add_options:
 * @self: The module to add the option on.
 * @options: Authentication and other options..
 **/
void
gck_module_add_options (GckModule *self, guint options)
{
	GckModulePrivate *pv = lock_private (self);

	g_return_if_fail (pv);

	{
		pv->options |= options;
	}

	unlock_private (self, pv);
	g_object_notify (G_OBJECT (self), "options");
}
