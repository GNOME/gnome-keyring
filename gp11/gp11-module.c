/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gp11-module.c - the GObject PKCS#11 wrapper library

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

#include <string.h>

/*
 * MT safe 
 * 
 * The only thing that can change after object initialization in
 * a GP11Module is the finalized flag, which can be set
 * to 1 in dispose.
 */

enum {
	PROP_0,
	PROP_PATH,
	PROP_FUNCTION_LIST
};

typedef struct _GP11ModuleData {
	GModule *module;
	gchar *path;
	gint finalized;
	CK_FUNCTION_LIST_PTR funcs;
	CK_C_INITIALIZE_ARGS init_args;
} GP11ModuleData;

typedef struct _GP11ModulePrivate {
	GP11ModuleData data;
	/* Add future mutex and non-MT-safe data here */
} GP11ModulePrivate;

#define GP11_MODULE_GET_DATA(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GP11_TYPE_MODULE, GP11ModuleData))

G_DEFINE_TYPE (GP11Module, gp11_module, G_TYPE_OBJECT);

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
 * OBJECT
 */

static void
gp11_module_init (GP11Module *self)
{
	
}

static void
gp11_module_get_property (GObject *obj, guint prop_id, GValue *value, 
                          GParamSpec *pspec)
{
	GP11Module *self = GP11_MODULE (obj);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, gp11_module_get_path (self));
		break;
	case PROP_FUNCTION_LIST:
		g_value_set_pointer (value, gp11_module_get_function_list (self));
		break;
	}
}

static void
gp11_module_set_property (GObject *obj, guint prop_id, const GValue *value, 
                          GParamSpec *pspec)
{
	GP11ModuleData *data = GP11_MODULE_GET_DATA (obj);

	/* Only allowed during initialization */
	switch (prop_id) {
	case PROP_PATH:
		g_return_if_fail (!data->path);
		data->path = g_value_dup_string (value);
		break;
	}
}

static void
gp11_module_dispose (GObject *obj)
{
	GP11ModuleData *data = GP11_MODULE_GET_DATA (obj);
	gint finalized = g_atomic_int_get (&data->finalized);
	CK_RV rv;

	/* Must be careful when accessing funcs */
	if (data->funcs && !finalized && 
	    g_atomic_int_compare_and_exchange (&data->finalized, finalized, 1)) {
		rv = (data->funcs->C_Finalize) (NULL);
		if (rv != CKR_OK) {
			g_warning ("C_Finalize on module '%s' failed: %s", 
			           data->path, gp11_message_from_rv (rv));
		}
	}
	
	G_OBJECT_CLASS (gp11_module_parent_class)->dispose (obj);
}

static void
gp11_module_finalize (GObject *obj)
{
	GP11ModuleData *data = GP11_MODULE_GET_DATA (obj);

	data->funcs = NULL;
	
	if (data->module) {
		if (!g_module_close (data->module))
			g_warning ("failed to close the pkcs11 module: %s", 
			           g_module_error ());
		data->module = NULL;
	}
	
	g_free (data->path);
	data->path = NULL;
	
	G_OBJECT_CLASS (gp11_module_parent_class)->finalize (obj);
}


static void
gp11_module_class_init (GP11ModuleClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	gp11_module_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->get_property = gp11_module_get_property;
	gobject_class->set_property = gp11_module_set_property;
	gobject_class->dispose = gp11_module_dispose;
	gobject_class->finalize = gp11_module_finalize;
	
	g_object_class_install_property (gobject_class, PROP_PATH,
		g_param_spec_string ("path", "Module Path", "Path to the PKCS11 Module",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_FUNCTION_LIST,
		g_param_spec_pointer ("function-list", "Function List", "PKCS11 Function List",
		                      G_PARAM_READABLE));

	g_type_class_add_private (gobject_class, sizeof (GP11ModulePrivate));
}

/* ----------------------------------------------------------------------------
 * PUBLIC 
 */

/**
 * gp11_module_info_free:
 * @module_info: The module info to free, or NULL.
 * 
 * Free a GP11ModuleInfo structure.
 **/
void
gp11_module_info_free (GP11ModuleInfo *module_info)
{
	if (!module_info)
		return;
	g_free (module_info->library_description);
	g_free (module_info->manufacturer_id);
	g_free (module_info);
}

/**
 * gp11_module_initialize:
 * @path: The file system path to the PKCS#11 module to load.
 * @reserved: Extra arguments for the PKCS#11 module, should usually be NULL.
 * @err: A location to store an error resulting from a failed load.
 * 
 * Load and initialize a PKCS#11 module represented by a GP11Module object.
 * 
 * Return value: The loaded PKCS#11 module or NULL if failed.
 **/
GP11Module*
gp11_module_initialize (const gchar *path, gpointer reserved, GError **err)
{
	CK_C_GetFunctionList get_function_list;
	CK_FUNCTION_LIST_PTR funcs;
	GP11ModuleData *data;
	GModule *module;
	GP11Module *mod;
	CK_RV rv;
	
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (!err || !*err, NULL);
	
	/* Load the actual module */
	module = g_module_open (path, 0);
	if (!module) {
		g_set_error (err, GP11_ERROR, (int)CKR_GP11_MODULE_PROBLEM,
		             "Error loading pkcs11 module: %s", g_module_error ());
		return NULL;
	}
	
	/* Get the entry point */
	if (!g_module_symbol (module, "C_GetFunctionList", (void**)&get_function_list)) {
		g_set_error (err, GP11_ERROR, (int)CKR_GP11_MODULE_PROBLEM,
		             "Invalid pkcs11 module: %s", g_module_error ());
		g_module_close (module);
		return NULL;
	}
	
	/* Get the function list */
	rv = (get_function_list) (&funcs);
	if (rv != CKR_OK) {
		g_set_error (err, GP11_ERROR, rv, "Couldn't get pkcs11 function list: %s",
		             gp11_message_from_rv (rv));
		g_module_close (module);
		return NULL;
	}
	
	mod = gp11_module_initialize_with_functions (funcs, reserved, err);
	if (mod == NULL) {
		g_module_close (module);
		return NULL;
	}
	
	data = GP11_MODULE_GET_DATA (mod);
	data->path = g_strdup (path);
	data->module = module;
	
	return mod;
}

/**
 * gp11_module_initialize_with_functions:
 * @funcs: Initialized PKCS#11 function list pointer
 * @reserved: Extra arguments for the PKCS#11 module, should usually be NULL.
 * @err: A location to store an error resulting from a failed load.
 * 
 * Initialize a PKCS#11 module represented by a GP11Module object.
 * 
 * Return value: The loaded PKCS#11 module or NULL if failed.
 **/
GP11Module*
gp11_module_initialize_with_functions (CK_FUNCTION_LIST_PTR funcs, gpointer reserved,
                                       GError **err)
{
	GP11ModuleData *data;
	GP11Module *mod;
	CK_RV rv;
	
	g_return_val_if_fail (funcs, NULL);
	g_return_val_if_fail (!err || !*err, NULL);

	mod = g_object_new (GP11_TYPE_MODULE, NULL);
	data = GP11_MODULE_GET_DATA (mod);
	
	data->funcs = funcs;

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
		g_set_error (err, GP11_ERROR, rv, "Couldn't initialize module: %s",
		             gp11_message_from_rv (rv));
		g_object_unref (mod);
		return NULL;
	}

	return mod;
}

/**
 * gp11_module_get_info:
 * @self: The module to get info for.
 * 
 * Get the info about a PKCS#11 module. 
 * 
 * Return value: The module info. Release this with gp11_module_info_free().
 **/
GP11ModuleInfo*
gp11_module_get_info (GP11Module *self)
{
	GP11ModuleData *data = GP11_MODULE_GET_DATA (self);
	GP11ModuleInfo *modinfo;
	CK_INFO info;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_MODULE (self), NULL);
	g_return_val_if_fail (data->funcs, NULL);
	
	memset (&info, 0, sizeof (info));
	rv = (data->funcs->C_GetInfo (&info));
	if (rv != CKR_OK) {
		g_warning ("couldn't get module info: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	modinfo = g_new0 (GP11ModuleInfo, 1);
	modinfo->flags = info.flags;
	modinfo->library_description = gp11_string_from_chars (info.libraryDescription, 
	                                                       sizeof (info.libraryDescription));
	modinfo->manufacturer_id = gp11_string_from_chars (info.manufacturerID,
	                                                   sizeof (info.manufacturerID));
	modinfo->library_version_major = info.libraryVersion.major;
	modinfo->library_version_minor = info.libraryVersion.minor;
	modinfo->pkcs11_version_major = info.cryptokiVersion.major;
	modinfo->pkcs11_version_minor = info.cryptokiVersion.minor;
	
	return modinfo;
}

/**
 * gp11_module_get_slots:
 * @self: The module for which to get the slots.
 * @token_present: Whether to limit only to slots with a token present.
 * 
 * Get the GP11Slot objects for a given module. 
 * 
 * Return value: The possibly empty list of slots. Release this with gp11_list_unref_free().
 */
GList*
gp11_module_get_slots (GP11Module *self, gboolean token_present)
{
	GP11ModuleData *data = GP11_MODULE_GET_DATA (self);
	CK_SLOT_ID_PTR slot_list;
	CK_ULONG count, i;
	GList *result;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_MODULE (self), NULL);
	g_return_val_if_fail (data->funcs, NULL);

	rv = (data->funcs->C_GetSlotList) (token_present ? CK_TRUE : CK_FALSE, NULL, &count);
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot count: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	if (!count)
		return NULL;
	
	slot_list = g_new (CK_SLOT_ID, count);
	rv = (data->funcs->C_GetSlotList) (token_present ? CK_TRUE : CK_FALSE, slot_list, &count);
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot list: %s", gp11_message_from_rv (rv));
		g_free (slot_list);
		return NULL;
	}
	
	result = NULL;
	for (i = 0; i < count; ++i) {
		result = g_list_prepend (result, g_object_new (GP11_TYPE_SLOT, 
		                                               "handle", slot_list[i],
		                                               "module", self, NULL));
	}
	
	g_free (slot_list);
	return g_list_reverse (result);
}

/**
 * gp11_module_get_path:
 * @self: The module for which to get the path.
 * 
 * Get the file path of this module. This may not be an absolute path, and 
 * usually reflects the path passed to gp11_module_initialize().
 * 
 * Return value: The path, do not modify or free this value. 
 **/
const gchar*
gp11_module_get_path (GP11Module *self)
{
	GP11ModuleData *data = GP11_MODULE_GET_DATA (self);
	g_return_val_if_fail (GP11_IS_MODULE (self), NULL);
	return data->path;
}

/**
 * gp11_module_get_function_list:
 * @self: The module for which to get the function list.
 * 
 * Get the PKCS#11 function list for the module.
 * 
 * Return value: The function list, do not modify this structure. 
 **/
CK_FUNCTION_LIST_PTR
gp11_module_get_function_list (GP11Module *self)
{
	GP11ModuleData *data = GP11_MODULE_GET_DATA (self);
	g_return_val_if_fail (GP11_IS_MODULE (self), NULL);
	return data->funcs;	
}
