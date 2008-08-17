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

enum {
	PROP_0,
	PROP_MODULE_PATH
};

typedef struct _GP11ModulePrivate {
	GModule *module;
} GP11ModulePrivate;

#define GP11_MODULE_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GP11_TYPE_MODULE, GP11ModulePrivate))

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
gp11_module_init (GP11Module *module)
{
	
}

static void
gp11_module_get_property (GObject *obj, guint prop_id, GValue *value, 
                          GParamSpec *pspec)
{
	GP11Module *module = GP11_MODULE (obj);

	switch (prop_id) {
	case PROP_MODULE_PATH:
		g_value_set_string (value, module->path);
		break;
	}
}

static void
gp11_module_set_property (GObject *obj, guint prop_id, const GValue *value, 
                          GParamSpec *pspec)
{
	GP11ModulePrivate *pv = GP11_MODULE_GET_PRIVATE (obj);
	GP11Module *module = GP11_MODULE (obj);

	switch (prop_id) {
	case PROP_MODULE_PATH:
		g_return_if_fail (!pv->module);
		module->path = g_value_dup_string (value);
		g_return_if_fail (module->path);
		break;
	}
}

static void
gp11_module_dispose (GObject *obj)
{
	GP11Module *module = GP11_MODULE (obj);
	CK_RV rv;
	
	if (module->funcs) {
		rv = (module->funcs->C_Finalize) (NULL);
		if (rv != CKR_OK) {
			g_warning ("C_Finalize on module '%s' failed: %s", 
			           module->path, gp11_message_from_rv (rv));
		}
		module->funcs = NULL;
	}
}

static void
gp11_module_finalize (GObject *obj)
{
	GP11ModulePrivate *pv = GP11_MODULE_GET_PRIVATE (obj);
	GP11Module *module = GP11_MODULE (obj);

	g_assert (module->funcs == NULL);
	
	if (pv->module) {
		if (!g_module_close (pv->module))
			g_warning ("failed to close the pkcs11 module: %s", 
			           g_module_error ());
		pv->module = NULL;
	}
	
	g_free (module->path);
	module->path = NULL;
	
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
	
	g_object_class_install_property (gobject_class, PROP_MODULE_PATH,
		g_param_spec_string ("module-path", "Module Path", "Path to the PKCS11 Module",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_type_class_add_private (gobject_class, sizeof (GP11ModulePrivate));
}

/* ----------------------------------------------------------------------------
 * PUBLIC 
 */

void
gp11_module_info_free (GP11ModuleInfo *module_info)
{
	if (!module_info)
		return;
	g_free (module_info->library_description);
	g_free (module_info->manufacturer_id);
	g_free (module_info);
}

GP11Module*
gp11_module_initialize (const gchar *path, gpointer reserved, GError **err)
{
	CK_C_INITIALIZE_ARGS init_args;
	CK_C_GetFunctionList get_function_list;
	GP11ModulePrivate *pv;
	GP11Module *mod;
	CK_RV rv;
	
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (!err || !*err, NULL);
	
	mod = g_object_new (GP11_TYPE_MODULE, "module-path", path, NULL);
	pv = GP11_MODULE_GET_PRIVATE (mod);
	
	/* Load the actual module */
	pv->module = g_module_open (path, 0);
	if (!pv->module) {
		g_set_error (err, GP11_ERROR, (int)CKR_GP11_MODULE_PROBLEM,
		             "Error loading pkcs11 module: %s", g_module_error ());
		g_object_unref (mod);
		return NULL;
	}
	
	/* Get the entry point */
	if (!g_module_symbol (pv->module, "C_GetFunctionList", (void**)&get_function_list)) {
		g_set_error (err, GP11_ERROR, (int)CKR_GP11_MODULE_PROBLEM,
		             "Invalid pkcs11 module: %s", g_module_error ());
		g_object_unref (mod);
		return NULL;
	}
	
	/* Get the function list */
	rv = (get_function_list) (&mod->funcs);
	if (rv != CKR_OK) {
		g_set_error (err, GP11_ERROR, rv, "Couldn't get pkcs11 function list: %s",
		             gp11_message_from_rv (rv));
		g_object_unref (mod);
		return NULL;
	}
	
	/* Make sure we have a compatible version */
	if (mod->funcs->version.major != CRYPTOKI_VERSION_MAJOR) {
		g_set_error (err, GP11_ERROR, (int)CKR_GP11_MODULE_PROBLEM,
		             "Incompatible version of pkcs11 module: %d.%d",
		             (int)mod->funcs->version.major,
		             (int)mod->funcs->version.minor);
		g_object_unref (mod);
		return NULL;
	}
	
	memset (&init_args, 0, sizeof (init_args));
	init_args.flags = CKF_OS_LOCKING_OK;
	init_args.CreateMutex = create_mutex;
	init_args.DestroyMutex = destroy_mutex;
	init_args.LockMutex = lock_mutex;
	init_args.UnlockMutex = unlock_mutex;
	init_args.pReserved = reserved;
	
	/* Now initialize the module */
	rv = (mod->funcs->C_Initialize) (&init_args);
	if (rv != CKR_OK) {
		g_set_error (err, GP11_ERROR, rv, "Couldn't initialize module: %s",
		             gp11_message_from_rv (rv));
		g_object_unref (mod);
		return NULL;
	}

	return mod;
}

GP11ModuleInfo*
gp11_module_get_info (GP11Module *module)
{
	GP11ModuleInfo *modinfo;
	CK_INFO info;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_MODULE (module), NULL);
	g_return_val_if_fail (module->funcs, NULL);
	
	memset (&info, 0, sizeof (info));
	rv = (module->funcs->C_GetInfo (&info));
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

GList*
gp11_module_get_slots (GP11Module *module, gboolean token_present)
{
	CK_SLOT_ID_PTR slot_list;
	CK_ULONG count, i;
	GList *result;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_MODULE (module), NULL);
	g_return_val_if_fail (module->funcs, NULL);

	rv = (module->funcs->C_GetSlotList) (token_present ? CK_TRUE : CK_FALSE, NULL, &count);
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot count: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	if (!count)
		return NULL;
	
	slot_list = g_new (CK_SLOT_ID, count);
	rv = (module->funcs->C_GetSlotList) (token_present ? CK_TRUE : CK_FALSE, slot_list, &count);
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot list: %s", gp11_message_from_rv (rv));
		g_free (slot_list);
		return NULL;
	}
	
	result = NULL;
	for (i = 0; i < count; ++i) {
		/* TODO: Should we be looking these up somewhere? */
		result = g_list_prepend (result, g_object_new (GP11_TYPE_SLOT, 
		                                               "handle", slot_list[i],
		                                               "module", module, NULL));
	}
	
	g_free (slot_list);
	return g_list_reverse (result);
}

