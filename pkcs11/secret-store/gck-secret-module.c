/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
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

#include "gck-secret-collection.h"
#include "gck-secret-module.h"
#include "gck-secret-store.h"

#include "gck/gck-file-tracker.h"

#include <fcntl.h>
#include <string.h>

struct _GckSecretModule {
	GckModule parent;
	GckFileTracker *tracker;
	GHashTable *collections;
	gchar *directory;
};

static const CK_SLOT_INFO gck_secret_module_slot_info = {
	"Secret Store",
	"Gnome Keyring",
	CKF_TOKEN_PRESENT,
	{ 0, 0 },
	{ 0, 0 }
};

static const CK_TOKEN_INFO gck_secret_module_token_info = {
	"Secret Store",
	"Gnome Keyring",
	"1.0",
	"1:SECRET:DEFAULT", /* Unique serial number for manufacturer */
	CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED,
	CK_EFFECTIVELY_INFINITE,
	CK_EFFECTIVELY_INFINITE,
	CK_EFFECTIVELY_INFINITE,
	CK_EFFECTIVELY_INFINITE,
	1024,
	1,
	CK_UNAVAILABLE_INFORMATION,
	CK_UNAVAILABLE_INFORMATION,
	CK_UNAVAILABLE_INFORMATION,
	CK_UNAVAILABLE_INFORMATION,
	{ 0, 0 },
	{ 0, 0 },
	""
};

G_DEFINE_TYPE (GckSecretModule, gck_secret_module, GCK_TYPE_MODULE);

GckModule*  _gck_secret_store_get_module_for_testing (void);

/* -----------------------------------------------------------------------------
 * ACTUAL PKCS#11 Module Implementation 
 */

/* Include all the module entry points */
#include "gck/gck-module-ep.h"
GCK_DEFINE_MODULE (gck_secret_module, GCK_TYPE_SECRET_MODULE);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static void
on_file_load (GckFileTracker *tracker, const gchar *path, GckSecretModule *self)
{
	GckSecretCollection *collection;
	GckManager *manager;
	GckDataResult res;
	gboolean created;
	gchar *basename;

	manager = gck_module_get_manager (GCK_MODULE (self));
	g_return_if_fail (manager);

	/* Do we have one for this path yet? */
	basename = g_path_get_basename (path);
	collection = g_hash_table_lookup (self->collections, basename);

	if (collection == NULL) {
		created = TRUE;
		collection = g_object_new (GCK_TYPE_SECRET_COLLECTION,
		                           "module", self,
		                           "identifier", basename,
		                           "filename", path,
		                           "manager", manager,
		                           NULL);
	}

	res = gck_secret_collection_load (collection);

	switch (res) {
	case GCK_DATA_SUCCESS:
		if (created) {
			g_hash_table_replace (self->collections, basename, collection);
			gck_object_expose (GCK_OBJECT (collection), TRUE);
			basename = NULL;
		}
		break;
	case GCK_DATA_LOCKED:
		g_message ("master password for keyring changed without our knowledge: %s", path);
		gck_secret_collection_unlocked_clear (collection);
		break;
	case GCK_DATA_UNRECOGNIZED:
		g_message ("keyring was in an invalid or unrecognized format: %s", path);
		break;
	case GCK_DATA_FAILURE:
		g_message ("failed to parse keyring: %s", path);
		break;
	default:
		g_assert_not_reached ();
	}

	g_free (basename);
}

static void
on_file_remove (GckFileTracker *tracker, const gchar *path, GckSecretModule *self)
{
	gchar *basename;

	g_return_if_fail (path);
	g_return_if_fail (GCK_IS_SECRET_MODULE (self));

	basename = g_path_get_basename (path);
	if (!g_hash_table_remove (self->collections, basename))
		g_return_if_reached ();
	g_free (basename);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static const CK_SLOT_INFO* 
gck_secret_module_real_get_slot_info (GckModule *self)
{
	return &gck_secret_module_slot_info;
}

static const CK_TOKEN_INFO*
gck_secret_module_real_get_token_info (GckModule *self)
{
	return &gck_secret_module_token_info;
}

static void 
gck_secret_module_real_parse_argument (GckModule *base, const gchar *name, const gchar *value)
{
	GckSecretModule *self = GCK_SECRET_MODULE (base);
	if (g_str_equal (name, "directory")) {
		g_free (self->directory);
		self->directory = g_strdup (value);
	}
}

static CK_RV
gck_secret_module_real_refresh_token (GckModule *base)
{
	GckSecretModule *self = GCK_SECRET_MODULE (base);
	if (self->tracker)
		gck_file_tracker_refresh (self->tracker, FALSE);
	return CKR_OK;
}

static GObject* 
gck_secret_module_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckSecretModule *self = GCK_SECRET_MODULE (G_OBJECT_CLASS (gck_secret_module_parent_class)->constructor(type, n_props, props));

	g_return_val_if_fail (self, NULL);

	if (!self->directory) {
		self->directory = g_build_filename (g_get_home_dir (), ".gnome2", "keyrings", NULL);
		if (g_mkdir_with_parents (self->directory, S_IRWXU) < 0)
			g_warning ("unable to create keyring dir: %s", self->directory);
	}

	self->tracker = gck_file_tracker_new (self->directory, "*.keyring", NULL);
	g_signal_connect (self->tracker, "file-added", G_CALLBACK (on_file_load), self);
	g_signal_connect (self->tracker, "file-changed", G_CALLBACK (on_file_load), self);
	g_signal_connect (self->tracker, "file-removed", G_CALLBACK (on_file_remove), self);

	return G_OBJECT (self);
}

static void
gck_secret_module_init (GckSecretModule *self)
{
	self->collections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

static void
gck_secret_module_dispose (GObject *obj)
{
	GckSecretModule *self = GCK_SECRET_MODULE (obj);
	
	if (self->tracker)
		g_object_unref (self->tracker);
	self->tracker = NULL;

	g_hash_table_remove_all (self->collections);

	G_OBJECT_CLASS (gck_secret_module_parent_class)->dispose (obj);
}

static void
gck_secret_module_finalize (GObject *obj)
{
	GckSecretModule *self = GCK_SECRET_MODULE (obj);
	
	g_assert (self->tracker == NULL);

	g_hash_table_destroy (self->collections);
	self->collections = NULL;

	g_free (self->directory);
	self->directory = NULL;

	G_OBJECT_CLASS (gck_secret_module_parent_class)->finalize (obj);
}

static void
gck_secret_module_class_init (GckSecretModuleClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckModuleClass *module_class = GCK_MODULE_CLASS (klass);
	
	gobject_class->constructor = gck_secret_module_constructor;
	gobject_class->dispose = gck_secret_module_dispose;
	gobject_class->finalize = gck_secret_module_finalize;
	
	module_class->get_slot_info = gck_secret_module_real_get_slot_info;
	module_class->get_token_info = gck_secret_module_real_get_token_info;
	module_class->parse_argument = gck_secret_module_real_parse_argument;
	module_class->refresh_token = gck_secret_module_real_refresh_token;
}

/* ---------------------------------------------------------------------------------------
 * PUBLIC 
 */

CK_FUNCTION_LIST_PTR
gck_secret_store_get_functions (void)
{
	gck_crypto_initialize ();
	return gck_secret_module_function_list;
}

GckModule*
_gck_secret_store_get_module_for_testing (void)
{
	return pkcs11_module;
}
