/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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

#include "gkm-xdg-module.h"
#include "gkm-xdg-store.h"
#include "gkm-xdg-trust.h"

#include "egg/egg-error.h"

#include "gkm/gkm-file-tracker.h"
#include "gkm/gkm-serializable.h"
#include "gkm/gkm-util.h"

#include <string.h>

struct _GkmXdgModule {
	GkmModule parent;
	gchar *directory;
	GHashTable *objects_by_path;
	GkmFileTracker *tracker;
	CK_TOKEN_INFO token_info;
};

static const CK_SLOT_INFO user_module_slot_info = {
	"User Key Storage",
	"Gnome Keyring",
	CKF_TOKEN_PRESENT,
	{ 0, 0 },
	{ 0, 0 }
};

static const CK_TOKEN_INFO user_module_token_info = {
	"User Key Storage",
	"Gnome Keyring",
	"1.0",
	"1:XDG:DEFAULT", /* Unique serial number for manufacturer */
	CKF_TOKEN_INITIALIZED,
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

#define UNUSED_VALUE (GUINT_TO_POINTER (1))

G_DEFINE_TYPE (GkmXdgModule, gkm_xdg_module, GKM_TYPE_MODULE);

/* -----------------------------------------------------------------------------
 * ACTUAL PKCS#11 Module Implementation
 */

/* Include all the module entry points */
#include "gkm/gkm-module-ep.h"
GKM_DEFINE_MODULE (gkm_xdg_module, GKM_TYPE_XDG_MODULE);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static GType
type_from_path (const gchar *path)
{
	const gchar *ext;

	ext = strrchr (path, '.');
	if (ext == NULL)
		return 0;

	if (g_str_equal (ext, ".trust"))
		return GKM_XDG_TYPE_TRUST;

#if 0
	else if (strcmp (extension, ".pkcs8") == 0)
		return GKM_TYPE_GNOME2_PRIVATE_KEY;
	else if (strcmp (extension, ".pub") == 0)
		return GKM_TYPE_GNOME2_PUBLIC_KEY;
	else if (strcmp (extension, ".cer") == 0)
		return GKM_TYPE_CERTIFICATE;
#endif

	return 0;
}

static void
file_load (GkmFileTracker *tracker, const gchar *path, GkmXdgModule *self)
{
	GkmObject *object;
	GkmManager *manager;
	gboolean added = FALSE;
	GError *error = NULL;
	GType type;
	guchar *data;
	gsize n_data;

	g_return_if_fail (path);
	g_return_if_fail (GKM_IS_XDG_MODULE (self));

	manager = gkm_module_get_manager (GKM_MODULE (self));

	/* Already have this object? */
	object = g_hash_table_lookup (self->objects_by_path, path);
	if (object == NULL) {

		/* Figure out what type of object we're dealing with */
		type = type_from_path (path);
		if (type == 0) {
			g_warning ("don't know how to load file in key store: %s", path);
			return;
		}

		/* Create a new object for this identifier */
		object = g_object_new (type,
		                       "module", GKM_MODULE (self),
		                       "manager", manager, NULL);
		g_return_if_fail (GKM_IS_SERIALIZABLE (object));
		g_return_if_fail (GKM_SERIALIZABLE_GET_INTERFACE (object)->extension);

		added = TRUE;

	} else {
		g_object_ref (object);
	}

	/* Read the file in */
	if (!g_file_get_contents (path, (gchar**)&data, &n_data, &error)) {
		g_warning ("couldn't read file in key store: %s: %s", path,
		           egg_error_message (error));
		g_object_unref (object);
		g_clear_error (&error);
		return;

	/* And load the data into it */
	} else if (gkm_serializable_load (GKM_SERIALIZABLE (object), NULL, data, n_data)) {
		if (added)
			g_hash_table_insert (self->objects_by_path, g_strdup (path), g_object_ref (object));
		gkm_object_expose (object, TRUE);

	} else {
		g_message ("failed to load file in user store: %s", path);
		if (!added)
			gkm_object_expose (object, FALSE);
	}

	g_object_unref (object);
}

static void
file_remove (GkmFileTracker *tracker, const gchar *path, GkmXdgModule *self)
{
	g_return_if_fail (path);
	g_return_if_fail (GKM_IS_XDG_MODULE (self));
	g_hash_table_remove (self->objects_by_path, path);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static const CK_SLOT_INFO*
gkm_xdg_module_real_get_slot_info (GkmModule *base)
{
	return &user_module_slot_info;
}

static const CK_TOKEN_INFO*
gkm_xdg_module_real_get_token_info (GkmModule *base)
{
	GkmXdgModule *self = GKM_XDG_MODULE (base);

	/* TODO: Update the info with current info */
	return &self->token_info;
}

static void
gkm_xdg_module_real_parse_argument (GkmModule *base, const gchar *name, const gchar *value)
{
	GkmXdgModule *self = GKM_XDG_MODULE (base);
	if (g_str_equal (name, "directory")) {
		g_free (self->directory);
		self->directory = g_strdup (value);
	}
}

static CK_RV
gkm_xdg_module_real_refresh_token (GkmModule *base)
{
	GkmXdgModule *self = GKM_XDG_MODULE (base);
	gkm_file_tracker_refresh (self->tracker, FALSE);
	return CKR_OK;
}

static GObject*
gkm_xdg_module_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkmXdgModule *self = GKM_XDG_MODULE (G_OBJECT_CLASS (gkm_xdg_module_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);

	if (!self->directory)
		self->directory = g_build_filename (g_get_user_data_dir (), "keystore", NULL);

	self->tracker = gkm_file_tracker_new (self->directory, "*.*", NULL);
	g_signal_connect (self->tracker, "file-added", G_CALLBACK (file_load), self);
	g_signal_connect (self->tracker, "file-changed", G_CALLBACK (file_load), self);
	g_signal_connect (self->tracker, "file-removed", G_CALLBACK (file_remove), self);

	return G_OBJECT (self);
}

static void
gkm_xdg_module_init (GkmXdgModule *self)
{
	self->objects_by_path = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

	/* Our default token info, updated as module runs */
	memcpy (&self->token_info, &user_module_token_info, sizeof (CK_TOKEN_INFO));

	/* For creating stored keys */
	gkm_module_register_factory (GKM_MODULE (self), GKM_XDG_FACTORY_TRUST);
}

static void
gkm_xdg_module_dispose (GObject *obj)
{
	GkmXdgModule *self = GKM_XDG_MODULE (obj);

	if (self->tracker)
		g_object_unref (self->tracker);
	self->tracker = NULL;

	g_hash_table_remove_all (self->objects_by_path);

	G_OBJECT_CLASS (gkm_xdg_module_parent_class)->dispose (obj);
}

static void
gkm_xdg_module_finalize (GObject *obj)
{
	GkmXdgModule *self = GKM_XDG_MODULE (obj);

	g_assert (self->tracker == NULL);

	g_hash_table_destroy (self->objects_by_path);
	self->objects_by_path = NULL;

	g_free (self->directory);
	self->directory = NULL;

	G_OBJECT_CLASS (gkm_xdg_module_parent_class)->finalize (obj);
}

static void
gkm_xdg_module_class_init (GkmXdgModuleClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GkmModuleClass *module_class = GKM_MODULE_CLASS (klass);

	gobject_class->constructor = gkm_xdg_module_constructor;
	gobject_class->dispose = gkm_xdg_module_dispose;
	gobject_class->finalize = gkm_xdg_module_finalize;

	module_class->get_slot_info = gkm_xdg_module_real_get_slot_info;
	module_class->get_token_info = gkm_xdg_module_real_get_token_info;
	module_class->parse_argument = gkm_xdg_module_real_parse_argument;
	module_class->refresh_token = gkm_xdg_module_real_refresh_token;
}

/* ----------------------------------------------------------------------------
 * PUBLIC
 */

CK_FUNCTION_LIST_PTR
gkm_xdg_store_get_functions (void)
{
	gkm_crypto_initialize ();
	return gkm_xdg_module_function_list;
}
