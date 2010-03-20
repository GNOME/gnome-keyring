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
#include "gck-secret-item.h"
#include "gck-secret-module.h"
#include "gck-secret-search.h"
#include "gck-secret-store.h"

#include "gck/gck-credential.h"
#include "gck/gck-file-tracker.h"
#include "gck/gck-transaction.h"

#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>

struct _GckSecretModule {
	GckModule parent;
	GckFileTracker *tracker;
	GHashTable *collections;
	gchar *directory;
	GckCredential *session_credential;
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
	"1:SECRET:MAIN", /* Unique serial number for manufacturer */
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

/* Forward declarations */
static void add_collection (GckSecretModule *, GckTransaction *, GckSecretCollection *);
static void remove_collection (GckSecretModule *, GckTransaction *, GckSecretCollection *);

/* -----------------------------------------------------------------------------
 * ACTUAL PKCS#11 Module Implementation 
 */

/* Include all the module entry points */
#include "gck/gck-module-ep.h"
GCK_DEFINE_MODULE (gck_secret_module, GCK_TYPE_SECRET_MODULE);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static gboolean
complete_add (GckTransaction *transaction, GObject *obj, gpointer user_data)
{
	GckSecretCollection *collection = GCK_SECRET_COLLECTION (user_data);
	if (gck_transaction_get_failed (transaction))
		remove_collection (GCK_SECRET_MODULE (obj), NULL, collection);
	g_object_unref (collection);
	return TRUE;
}

static void
add_collection (GckSecretModule *self, GckTransaction *transaction, GckSecretCollection  *collection)
{
	const gchar *filename;

	g_assert (GCK_IS_SECRET_MODULE(self));
	g_assert (GCK_IS_SECRET_COLLECTION (collection));

	filename = gck_secret_collection_get_filename (collection);
	g_return_if_fail (filename);

	g_hash_table_replace (self->collections, g_strdup (filename), g_object_ref (collection));

	gck_object_expose_full (GCK_OBJECT (collection), transaction, TRUE);
	if (transaction)
		gck_transaction_add (transaction, self, complete_add, g_object_ref (collection));
}

static gboolean
complete_remove (GckTransaction *transaction, GObject *obj, gpointer user_data)
{
	GckSecretCollection *collection = GCK_SECRET_COLLECTION (user_data);
	if (gck_transaction_get_failed (transaction))
		add_collection (GCK_SECRET_MODULE (obj), NULL, collection);
	g_object_unref (collection);
	return TRUE;
}

static void
remove_collection (GckSecretModule *self, GckTransaction *transaction, GckSecretCollection *collection)
{
	const gchar *filename;

	g_assert (GCK_IS_SECRET_MODULE (self));
	g_assert (GCK_IS_SECRET_COLLECTION (collection));

	filename = gck_secret_collection_get_filename (collection);
	g_return_if_fail (filename);

	g_hash_table_remove (self->collections, filename);

	gck_object_expose_full (GCK_OBJECT (collection), transaction, FALSE);
	if (transaction)
		gck_transaction_add (transaction, self, complete_remove, g_object_ref (collection));
}

static gchar*
identifier_from_filename (GckSecretModule *self, const gchar *filename)
{
	gchar *identifier;

	/* Do we have one for this path yet? */
	identifier = g_path_get_basename (filename);

	/* Remove the keyring suffix */
	if (g_str_has_suffix (identifier, ".keyring"))
		identifier[strlen(identifier) - 8] = 0;

	return identifier;
}

static gchar*
identifier_to_new_filename (GckSecretModule *self, const gchar *identifier)
{
	gchar *filename;
	gint i;
	int fd;

	for (i = 0; i < G_MAXINT; ++i) {
		if (i == 0)
			filename = g_strdup_printf ("%s/%s.keyring", self->directory, identifier);
		else
			filename = g_strdup_printf ("%s/%s_%d.keyring", self->directory, identifier, i);

		/* Try to create the file, and check that it doesn't exist */
		fd = g_open (filename, O_RDONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
		if (fd == -1) {
			if (errno != EEXIST)
				break;
		} else {
			close (fd);
			break;
		}

		g_free (filename);
	}

	return filename;
}


static void
on_file_load (GckFileTracker *tracker, const gchar *path, GckSecretModule *self)
{
	GckSecretCollection *collection;
	GckManager *manager;
	GckDataResult res;
	gboolean created;
	gchar *identifier;

	manager = gck_module_get_manager (GCK_MODULE (self));
	g_return_if_fail (manager);

	/* Do we have one for this path yet? */
	identifier = identifier_from_filename (self, path);
	collection = g_hash_table_lookup (self->collections, path);

	if (collection == NULL) {
		created = TRUE;
		collection = g_object_new (GCK_TYPE_SECRET_COLLECTION,
		                           "module", self,
		                           "identifier", identifier,
		                           "filename", path,
		                           "manager", manager,
		                           NULL);
	} else {
		created = FALSE;
		g_object_ref (collection);
	}

	res = gck_secret_collection_load (collection);

	switch (res) {
	case GCK_DATA_SUCCESS:
		if (created)
			add_collection (self, NULL, collection);
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

	g_object_unref (collection);
	g_free (identifier);
}

static void
on_file_remove (GckFileTracker *tracker, const gchar *path, GckSecretModule *self)
{
	GckSecretCollection *collection;

	g_return_if_fail (path);
	g_return_if_fail (GCK_IS_SECRET_MODULE (self));

	collection = g_hash_table_lookup (self->collections, path);
	if (collection)
		remove_collection (self, NULL, collection);
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

static void
gck_secret_module_real_add_object (GckModule *module, GckTransaction *transaction,
                                   GckObject *object)
{
	GckSecretModule *self = GCK_SECRET_MODULE (module);
	GckSecretCollection *collection;
	const gchar *identifier;
	gchar *filename;

	g_return_if_fail (!gck_transaction_get_failed (transaction));

	if (GCK_IS_SECRET_COLLECTION (object)) {
		collection = GCK_SECRET_COLLECTION (object);

		/* Setup a filename for this collection */
		identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (collection));
		filename = identifier_to_new_filename (self, identifier);
		gck_secret_collection_set_filename (collection, filename);
		g_free (filename);

		add_collection (self, transaction, collection);
	}
}

static void
gck_secret_module_real_store_object (GckModule *module, GckTransaction *transaction,
                                     GckObject *object)
{
	GckSecretModule *self = GCK_SECRET_MODULE (module);
	GckSecretCollection *collection = NULL;

	/* Store the item's collection */
	if (GCK_IS_SECRET_ITEM (object)) {
		collection = gck_secret_item_get_collection (GCK_SECRET_ITEM (object));
		g_return_if_fail (GCK_IS_SECRET_COLLECTION (collection));
		gck_module_store_token_object (GCK_MODULE (self), transaction, GCK_OBJECT (collection));

	/* Storing a collection */
	} else if (GCK_IS_SECRET_COLLECTION (object)) {
		collection = GCK_SECRET_COLLECTION (object);
		gck_secret_collection_save (collection, transaction);

	/* No other kind of token object */
	} else {
		g_warning ("can't store object of type '%s' on secret token", G_OBJECT_TYPE_NAME (object));
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
	}
}

static void
gck_secret_module_real_remove_object (GckModule *module, GckTransaction *transaction,
                                      GckObject *object)
{
	GckSecretModule *self = GCK_SECRET_MODULE (module);
	GckSecretCollection *collection;

	/* Ignore the session keyring credentials */
	if (self->session_credential != NULL &&
	    GCK_OBJECT (self->session_credential) == object)
		return;

	/* Removing an item */
	if (GCK_IS_SECRET_ITEM (object)) {
		collection = gck_secret_item_get_collection (GCK_SECRET_ITEM (object));
		g_return_if_fail (GCK_IS_SECRET_COLLECTION (collection));
		gck_secret_collection_destroy_item (collection, transaction, GCK_SECRET_ITEM (object));
		if (!gck_transaction_get_failed (transaction))
			gck_secret_collection_save (collection, transaction);

	/* Removing a collection */
	} else if (GCK_IS_SECRET_COLLECTION (object)) {
		collection = GCK_SECRET_COLLECTION (object);
		gck_secret_collection_destroy (collection, transaction);
		if (!gck_transaction_get_failed (transaction))
			remove_collection (self, transaction, collection);

	/* No other token objects */
	} else {
		g_warning ("Trying to remove token object of type '%s' from secret "
		           "module, but that type is not supported.", G_OBJECT_TYPE_NAME (object));
		gck_transaction_fail (transaction, CKR_FUNCTION_NOT_SUPPORTED);
	}
}

static GObject* 
gck_secret_module_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckSecretModule *self = GCK_SECRET_MODULE (G_OBJECT_CLASS (gck_secret_module_parent_class)->constructor(type, n_props, props));
	GckManager *manager;
	GckObject *collection;
	CK_RV rv;

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

	manager = gck_module_get_manager (GCK_MODULE (self));

	collection = g_object_new (GCK_TYPE_SECRET_COLLECTION,
	                           "module", self,
	                           "identifier", "session",
	                           "manager", manager,
	                           "transient", TRUE,
	                           NULL);

	/* Create the 'session' keyring, which is not stored to disk */
	g_return_val_if_fail (gck_object_is_transient (collection), NULL);
	gck_module_add_token_object (GCK_MODULE (self), NULL, collection);
	gck_object_expose (collection, TRUE);

	/* Unlock the 'session' keyring */
	rv = gck_credential_create (GCK_MODULE (self), manager, GCK_OBJECT (collection),
	                            NULL, 0, &self->session_credential);
	if (rv == CKR_OK)
		gck_object_expose (GCK_OBJECT (self->session_credential), TRUE);
	else
		g_warning ("couldn't unlock the 'session' keyring");

	g_object_unref (collection);
	return G_OBJECT (self);
}

static void
gck_secret_module_init (GckSecretModule *self)
{
	self->collections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
	gck_module_register_factory (GCK_MODULE (self), GCK_FACTORY_SECRET_SEARCH);
	gck_module_register_factory (GCK_MODULE (self), GCK_FACTORY_SECRET_ITEM);
	gck_module_register_factory (GCK_MODULE (self), GCK_FACTORY_SECRET_COLLECTION);
}

static void
gck_secret_module_dispose (GObject *obj)
{
	GckSecretModule *self = GCK_SECRET_MODULE (obj);

	if (self->tracker)
		g_object_unref (self->tracker);
	self->tracker = NULL;

	if (self->session_credential)
		g_object_unref (self->session_credential);
	self->session_credential = NULL;

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

	g_assert (!self->session_credential);

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
	module_class->add_token_object = gck_secret_module_real_add_object;
	module_class->store_token_object = gck_secret_module_real_store_object;
	module_class->remove_token_object = gck_secret_module_real_remove_object;
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
