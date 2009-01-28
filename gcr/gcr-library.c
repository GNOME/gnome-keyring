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
#include "gcr-types.h"
#include "gcr-internal.h"

#include "egg/egg-secure-memory.h"

#include <gcrypt.h>

static GList *all_modules = NULL;

GQuark
gcr_data_error_get_domain (void)
{
	static GQuark domain = 0;
	if (domain == 0)
		domain = g_quark_from_static_string ("gcr-parser-error");
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
egg_memory_fallback (void *p, unsigned long sz)
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

/* ------------------------------------------------------------------------------
 * GCRYPT HOOKS
 */

static void
log_handler (gpointer unused, int unknown, const gchar *msg, va_list va)
{
	/* TODO: Figure out additional arguments */
	g_logv ("gcrypt", G_LOG_LEVEL_MESSAGE, msg, va);
}

static int 
no_mem_handler (gpointer unused, size_t sz, unsigned int unknown)
{
	/* TODO: Figure out additional arguments */
	g_error ("couldn't allocate %lu bytes of memory", 
	         (unsigned long int)sz);
	return 0;
}

static void
fatal_handler (gpointer unused, int unknown, const gchar *msg)
{
	/* TODO: Figure out additional arguments */
	g_log ("gcrypt", G_LOG_LEVEL_ERROR, "%s", msg);
}

static int
glib_thread_mutex_init (void **lock)
{
	*lock = g_mutex_new ();
	return 0;
}

static int 
glib_thread_mutex_destroy (void **lock)
{
	g_mutex_free (*lock);
	return 0;
}

static int 
glib_thread_mutex_lock (void **lock)
{
	g_mutex_lock (*lock);
	return 0;
}

static int 
glib_thread_mutex_unlock (void **lock)
{
	g_mutex_unlock (*lock);
	return 0;
}

static struct gcry_thread_cbs glib_thread_cbs = {
	GCRY_THREAD_OPTION_USER, NULL,
	glib_thread_mutex_init, glib_thread_mutex_destroy,
	glib_thread_mutex_lock, glib_thread_mutex_unlock,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL 
};

void
_gcr_initialize (void)
{
	static volatile gsize gcr_initialized = 0;
	GP11Module *module;
	GError *error = NULL;
	unsigned seed;

	if (g_once_init_enter (&gcr_initialized)) {
		
		/* Only initialize libgcrypt if it hasn't already been initialized */
		if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
			if (g_thread_supported())
				gcry_control (GCRYCTL_SET_THREAD_CBS, &glib_thread_cbs);
			gcry_check_version (LIBGCRYPT_VERSION);
			gcry_set_log_handler (log_handler, NULL);
			gcry_set_outofcore_handler (no_mem_handler, NULL);
			gcry_set_fatalerror_handler (fatal_handler, NULL);
			gcry_set_allocation_handler ((gcry_handler_alloc_t)g_malloc, 
			                             (gcry_handler_alloc_t)egg_secure_alloc, 
			                             egg_secure_check, 
			                             (gcry_handler_realloc_t)egg_secure_realloc, 
			                             egg_secure_free);
			gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
		}
		
		gcry_create_nonce (&seed, sizeof (seed));
		srand (seed);

		/* TODO: This needs reworking for multiple modules */
		module = gp11_module_initialize (PKCS11_MODULE_PATH, NULL, &error);
		if (module) 
			all_modules = g_list_prepend (all_modules, module);
		else 
			g_warning ("couldn't initialize PKCS#11 module: %s", 
			           error && error->message ? error->message : "");

		g_once_init_leave (&gcr_initialized, 1);
	}
}

GList*
_gcr_get_pkcs11_modules (void)
{
	return all_modules;
}
