/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *  
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "gcr.h"
#include "gcr-certificate-renderer.h"
#define DEBUG_FLAG GCR_DEBUG_LIBRARY
#include "gcr-debug.h"
#include "gcr-internal.h"
#include "gcr-library.h"
#include "gcr-key-renderer.h"
#include "gcr-types.h"

#include "egg/egg-error.h"
#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

#include <p11-kit/p11-kit.h>

#include <gck/gck.h>

#include <gcrypt.h>

#include <glib/gi18n-lib.h>

/**
 * SECTION:gcr-library
 * @title: Library Settings
 * @short_description: functions for manipulating GCR library global settings.
 *
 * Manage or lookup various global aspesct and settings of the library.
 *
 * The GCR library maintains a global list of PKCS\#11 modules to use for
 * its various lookups and storage operations. Each module is represented by
 * a GckModule object. You can examine this list by using
 * gcr_pkcs11_get_modules().
 *
 * The list is configured automatically by looking for system installed
 * PKCS\#11 modules. It's not not normally necessary to modify this list. But
 * if you have special needs, you can use the gcr_pkcs11_set_modules() and
 * gcr_pkcs11_add_module() to do so.
 *
 * Trust assertions are stored and looked up in specific PKCS\#11 slots.
 * You can examine this list with gcr_pkcs11_get_trust_lookup_slots()
 */

/**
 * SECTION:gcr-private
 * @title: Private declarations
 * @short_description: private declarations to supress warnings.
 *
 * This section is only here to supress warnings, and should not be displayed.
 */

/**
 * GCR_DATA_ERROR:
 *
 * The #GError domain for data parsing errors.
 */

G_LOCK_DEFINE_STATIC (modules);
static GList *all_modules = NULL;
static gboolean initialized_modules = FALSE;

G_LOCK_DEFINE_STATIC (uris);
static gboolean initialized_uris = FALSE;
static gchar *trust_store_uri = NULL;
static gchar **trust_lookup_uris = NULL;

/* -----------------------------------------------------------------------------
 * ERRORS
 */

GQuark
gcr_data_error_get_domain (void)
{
	static GQuark domain = 0;
	if (domain == 0)
		domain = g_quark_from_static_string ("gcr-parser-error");
	return domain;
}

GQuark
gcr_error_get_domain (void)
{
	static GQuark domain = 0;
	if (domain == 0)
		domain = g_quark_from_static_string ("gcr-error");
	return domain;
}

/* -----------------------------------------------------------------------------
 * MEMORY
 */

static gboolean do_warning = TRUE;
#define WARNING  "couldn't allocate secure memory to keep passwords " \
		 "and or keys from being written to the disk"
		 
#define ABORTMSG "The GNOME_KEYRING_PARANOID environment variable was set. " \
                 "Exiting..."

static G_LOCK_DEFINE (memory_lock);

/* 
 * These are called from egg-secure-memory.c to provide appropriate
 * locking for memory between threads
 */ 

void
egg_memory_lock (void)
{
	G_LOCK (memory_lock);
}

void 
egg_memory_unlock (void)
{
	G_UNLOCK (memory_lock);
}

void*
egg_memory_fallback (void *p, size_t sz)
{
	const gchar *env;
	
	/* We were asked to free memory */
	if (!sz) {
		g_free (p);
		return NULL;
	}
	
	/* We were asked to allocate */
	if (!p) {
		if (do_warning) {
			g_message (WARNING);
			do_warning = FALSE;
		}
		
		env = g_getenv ("GNOME_KEYRING_PARANOID");
		if (env && *env) 
			g_error (ABORTMSG);
			
		return g_malloc0 (sz);
	}
	
	/* 
	 * Reallocation is a bit of a gray area, as we can be asked 
	 * by external libraries (like libgcrypt) to reallocate a 
	 * non-secure block into secure memory. We cannot satisfy 
	 * this request (as we don't know the size of the original 
	 * block) so we just try our best here.
	 */
			 
	return g_realloc (p, sz);
}

/* -----------------------------------------------------------------------------
 * INITIALIZATION
 */

void
_gcr_initialize_library (void)
{
	static gint gcr_initialize = 0;

	if (g_atomic_int_exchange_and_add (&gcr_initialize, 1) == 0)
		return;

	/* Initialize the libgcrypt library if needed */
	egg_libgcrypt_initialize ();

	g_type_class_unref (g_type_class_ref (GCR_TYPE_CERTIFICATE_RENDERER));
	g_type_class_unref (g_type_class_ref (GCR_TYPE_KEY_RENDERER));

	_gcr_debug ("initialized library");
}

static void
initialize_uris (void)
{
	GPtrArray *uris;
	GList *l;
	gchar *uri;
	gchar *debug;

	g_return_if_fail (initialized_modules);

	if (initialized_uris)
		return;

	G_LOCK (uris);

	if (!initialized_uris) {
		/* Ask for the global x-trust-store option */
		trust_store_uri = p11_kit_registered_option (NULL, "x-trust-store");
		for (l = all_modules; !trust_store_uri && l != NULL; l = g_list_next (l)) {
			trust_store_uri = p11_kit_registered_option (gck_module_get_functions (l->data),
			                                             "x-trust-store");
		}

		uris = g_ptr_array_new ();
		uri = p11_kit_registered_option (NULL, "x-trust-lookup");
		if (uri != NULL)
			g_ptr_array_add (uris, uri);
		for (l = all_modules; l != NULL; l = g_list_next (l)) {
			uri = p11_kit_registered_option (gck_module_get_functions (l->data),
			                                 "x-trust-lookup");
			if (uri != NULL)
				g_ptr_array_add (uris, uri);
		}
		g_ptr_array_add (uris, NULL);

		trust_lookup_uris = (gchar**)g_ptr_array_free (uris, FALSE);

		_gcr_debug ("trust store uri is: %s", trust_store_uri);
		debug = g_strjoinv (" ", trust_lookup_uris);
		_gcr_debug ("trust lookup uris are: %s", debug);
		g_free (debug);

		initialized_uris = TRUE;
	}

	G_UNLOCK (uris);
}

static void
on_initialize_registered (GObject *object,
                          GAsyncResult *result,
                          gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;
	GList *results;

	results = gck_modules_initialize_registered_finish (result, &error);
	if (error != NULL) {
		_gcr_debug ("failed %s", error->message);
		g_simple_async_result_take_error (res, error);

	} else {

		G_LOCK (modules);

		if (!initialized_modules) {
			all_modules = g_list_concat(all_modules, results);
			results = NULL;
			initialized_modules = TRUE;
		}

		G_UNLOCK (modules);
	}

	gck_list_unref_free (results);

	_gcr_debug ("completed initialize of registered modules");
	g_simple_async_result_complete (res);
	g_object_unref (res);
}

void
_gcr_initialize_pkcs11_async (GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	GSimpleAsyncResult *res;

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 _gcr_initialize_pkcs11_async);

	if (initialized_modules) {
		_gcr_debug ("already initialized, no need to async");
		g_simple_async_result_complete_in_idle (res);
	} else {
		gck_modules_initialize_registered_async (cancellable,
		                                         on_initialize_registered,
		                                         g_object_ref (res));
		_gcr_debug ("starting initialize of registered modules");
	}

	g_object_unref (res);
}

gboolean
_gcr_initialize_pkcs11_finish (GAsyncResult *result,
                               GError **error)
{
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      _gcr_initialize_pkcs11_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	return TRUE;
}

gboolean
_gcr_initialize_pkcs11 (GCancellable *cancellable,
                        GError **error)
{
	GList *results;
	GError *err = NULL;

	if (initialized_modules)
		return TRUE;

	results = gck_modules_initialize_registered (cancellable, &err);
	if (err == NULL) {

		_gcr_debug ("registered module initialize succeeded: %d modules",
		            g_list_length (results));

		G_LOCK (modules);

		if (!initialized_modules) {
			all_modules = g_list_concat (all_modules, results);
			results = NULL;
			initialized_modules = TRUE;
		}

		G_UNLOCK (modules);

	} else {
		_gcr_debug ("registered module initialize failed: %s", err->message);
		g_propagate_error (error, err);
	}

	gck_list_unref_free (results);
	return (err == NULL);
}

/**
 * gcr_pkcs11_get_modules:
 *
 * List all the PKCS\#11 modules that are used by the GCR library.
 * Each module is a #GckModule object.
 *
 * When done with the list, free it with gck_list_unref_free().
 *
 * Returns: A newly allocated list of #GckModule objects.
 */
GList*
gcr_pkcs11_get_modules (void)
{
	g_return_val_if_fail (initialized_modules, NULL);
	if (!all_modules)
		_gcr_debug ("no modules loaded");
	return gck_list_ref_copy (all_modules);
}

/**
 * gcr_pkcs11_set_modules:
 * @modules: a list of #GckModule
 *
 * Set the list of PKCS\#11 modules that are used by the GCR library.
 * Each module in the list is a #GckModule object.
 *
 * It is not normally necessary to call this function. The available
 * PKCS\#11 modules installed on the system are automatically loaded
 * by the GCR library.
 */
void
gcr_pkcs11_set_modules (GList *modules)
{
	GList *l;

	for (l = modules; l; l = g_list_next (l))
		g_return_if_fail (GCK_IS_MODULE (l->data));

	modules = gck_list_ref_copy (modules);
	gck_list_unref_free (all_modules);
	all_modules = modules;
	initialized_modules = TRUE;
}

/**
 * gcr_pkcs11_add_module:
 * @module: a #GckModule
 *
 * Add a #GckModule to the list of PKCS\#11 modules that are used by the
 * GCR library.
 *
 * It is not normally necessary to call this function. The available
 * PKCS\#11 modules installed on the system are automatically loaded
 * by the GCR library.
 */
void
gcr_pkcs11_add_module (GckModule *module)
{
	g_return_if_fail (GCK_IS_MODULE (module));
	all_modules = g_list_append (all_modules, g_object_ref (module));
}

/**
 * gcr_pkcs11_add_module_from_file:
 * @module_path: the full file path of the PKCS\#11 module
 * @unused: unused
 * @error: a #GError or NULL
 *
 * Initialize a PKCS\#11 module and add it to the modules that are
 * used by the GCR library. Note that is an error to initialize the same
 * PKCS\#11 module twice.
 *
 * It is not normally necessary to call this function. The available
 * PKCS\#11 modules installed on the system are automatically loaded
 * by the GCR library.
 *
 * Returns: whether the module was sucessfully added.
 */
gboolean
gcr_pkcs11_add_module_from_file (const gchar *module_path, gpointer unused,
                                 GError **error)
{
	GckModule *module;
	GError *err = NULL;

	g_return_val_if_fail (module_path, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	module = gck_module_initialize (module_path, NULL, &err);
	if (module == NULL) {
		_gcr_debug ("initializing module failed: %s: %s",
		            module_path, err->message);
		g_propagate_error (error, err);
		return FALSE;
	}

	gcr_pkcs11_add_module (module);

	_gcr_debug ("initialized and added module: %s", module_path);
	g_object_unref (module);
	return TRUE;
}

/**
 * gcr_pkcs11_get_trust_store_slot:
 *
 * Selects an appropriate PKCS\#11 slot to store trust assertions. The slot
 * to use is normally configured automatically by the system.
 *
 * When done with the #GckSlot, use g_object_unref() to release it.
 *
 * Returns: the #GckSlot to use for trust assertions.
 */
GckSlot*
gcr_pkcs11_get_trust_store_slot (void)
{
	GckSlot *slot;
	GError *error = NULL;

	g_return_val_if_fail (initialized_modules, NULL);

	initialize_uris ();
	slot = gck_modules_token_for_uri (all_modules, trust_store_uri, &error);
	if (!slot) {
		if (error) {
			g_warning ("error finding slot to store trust assertions: %s: %s",
			           trust_store_uri, egg_error_message (error));
			g_clear_error (&error);
		} else {
			_gcr_debug ("no trust store slot found");
		}
	}

	return slot;
}

/**
 * gcr_pkcs11_get_trust_lookup_slots:
 *
 * List all the PKCS\#11 slots that are used by the GCR library for lookup
 * of trust assertions. Each slot is a #GckSlot object.
 *
 * When done with the list, free it with gck_list_unref_free().
 *
 * Returns: a list of #GckSlot objects to use for lookup of trust.
 */
GList*
gcr_pkcs11_get_trust_lookup_slots (void)
{
	GList *results = NULL;
	GError *error = NULL;
	GckSlot *slot;
	gchar **uri;

	g_return_val_if_fail (initialized_modules, NULL);
	initialize_uris ();

	for (uri = trust_lookup_uris; uri && *uri; ++uri) {
		slot = gck_modules_token_for_uri (all_modules, *uri, &error);
		if (slot) {
			results = g_list_append (results, slot);
		} else if (error) {
			g_warning ("error finding slot for trust assertions: %s: %s",
			           *uri, egg_error_message (error));
			g_clear_error (&error);
		}
	}

	if (results == NULL)
		_gcr_debug ("no trust lookup slots found");

	return results;
}

/**
 * gcr_pkcs11_get_trust_store_uri:
 *
 * Get the PKCS\#11 URI that is used to identify which slot to use for
 * storing trust storage.
 *
 * Returns: the uri which identifies trust storage slot
 */
const gchar*
gcr_pkcs11_get_trust_store_uri (void)
{
	initialize_uris ();
	return trust_store_uri;
}

/**
 * gcr_pkcs11_set_trust_store_uri:
 * @pkcs11_uri: the uri which identifies trust storage slot
 *
 * Set the PKCS\#11 URI that is used to identify which slot to use for
 * storing trust assertions.
 *
 * It is not normally necessary to call this function. The relevant
 * PKCS\#11 slot is automatically configured by the GCR library.
 */
void
gcr_pkcs11_set_trust_store_uri (const gchar *pkcs11_uri)
{
	G_LOCK (uris);

	g_free (trust_store_uri);
	trust_store_uri = g_strdup (pkcs11_uri);
	initialized_uris = TRUE;

	G_UNLOCK (uris);
}


/**
 * gcr_pkcs11_get_trust_lookup_uris:
 *
 * Get the PKCS\#11 URIs that are used to identify which slots to use for
 * lookup trust assertions.
 *
 * Returns: the uri which identifies trust storage slot
 */
const gchar**
gcr_pkcs11_get_trust_lookup_uris (void)
{
	initialize_uris ();
	return (const gchar **)trust_lookup_uris;
}

/**
 * gcr_pkcs11_set_trust_lookup_uris:
 * @pkcs11_uris: the uris which identifies trust lookup slots
 *
 * Set the PKCS\#11 URIs that are used to identify which slots to use for
 * lookup of trust assertions.
 *
 * It is not normally necessary to call this function. The relevant
 * PKCS\#11 slots are automatically configured by the GCR library.
 */
void
gcr_pkcs11_set_trust_lookup_uris (const gchar **pkcs11_uris)
{
	G_LOCK (uris);

	g_strfreev (trust_lookup_uris);
	trust_lookup_uris = g_strdupv ((gchar**)pkcs11_uris);
	initialized_uris = TRUE;

	G_UNLOCK (uris);
}
