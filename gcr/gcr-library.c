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

#include "egg/egg-error.h"
#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

#include <gck/gck.h>

#include <gcrypt.h>

#include <glib/gi18n-lib.h>

static GList *all_modules = NULL;
static const gchar *trust_slot_uri = "pkcs11:manufacturer=Gnome%20Keyring;serial=1:XDG:DEFAULT";

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

void
_gcr_initialize (void)
{
	static volatile gsize gcr_initialized = 0;

	/* Initialize the libgcrypt library if needed */
	egg_libgcrypt_initialize ();

	if (g_once_init_enter (&gcr_initialized)) {
		all_modules = gck_modules_initialize_registered (0);
		g_once_init_leave (&gcr_initialized, 1);
	}
}

GList*
_gcr_get_pkcs11_modules (void)
{
	return all_modules;
}

GckSlot*
_gcr_slot_for_storing_trust (GError **error)
{
	GList *modules;
	GckSlot *slot;

	modules = _gcr_get_pkcs11_modules ();

	/*
	 * TODO: We need a better way to figure this out as far as
	 * being able to store trust. But for now just hard code in
	 * gnome-keyring.
	 */

	slot = gck_modules_token_for_uri (modules, trust_slot_uri, error);
	if (!slot) {
		if (error && !*error) {
			g_set_error (error, GCR_ERROR, /* TODO: */ 0,
			             _("Unable to find a place to store trust choices."));
		}
	}

	return slot;
}

#ifdef WITH_TESTS

void
_gcr_set_test_pkcs11_modules (GList *modules)
{
	modules = gck_list_ref_copy (modules);
	gck_list_unref_free (all_modules);
	all_modules = modules;
}

void
_gcr_set_test_trust_slot (const gchar *uri)
{
	trust_slot_uri = uri;
}

#endif /* WITH_TESTS */
