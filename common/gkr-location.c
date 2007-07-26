/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-location.c - A filesystem location with some resiliency

   Copyright (C) 2007 Stefan Walter

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-location.h"

#include "gkr-cleanup.h"
#include "gkr-dbus.h"

#ifdef WITH_HAL
#include <libhal.h>
#include <libhal-storage.h>
#endif 

#include <glib.h>

#include <string.h>

#define DEFAULT_NAME    "FILE"
#define HOME_NAME       "HOME"
#define GNOME_NAME      "LOCAL"
#define LOC_DELIMITER   ":"
#define LOC_DELIMITER_C ':'
#define CHILD_DELIMITER "-"

enum {
    LOCATION_ADDED,
    LOCATION_REMOVED,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (GkrLocationManager, gkr_location_manager, G_TYPE_OBJECT);

struct _GkrLocationManagerPrivate;
typedef struct _GkrLocationManagerPrivate GkrLocationManagerPrivate;

struct _GkrLocationManagerPrivate {
	LibHalContext *hal_ctx;
	GHashTable *volumes_by_name;
	GHashTable *volumes_by_prefix;	
};

typedef struct _GkrLocationVolume {
	GQuark base_loc;
	gchar *name;
	gchar *prefix;
} GkrLocationVolume;

#define GKR_LOCATION_MANAGER_GET_PRIVATE(o)  \
	(G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_LOCATION_MANAGER, GkrLocationManagerPrivate))

static GkrLocationManager *location_manager_singleton = NULL; 

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void 
cleanup_location_manager (void *unused)
{
	g_assert (location_manager_singleton);
	g_object_unref (location_manager_singleton);
	location_manager_singleton = NULL;
}

static void
list_locations (const gchar *name, GkrLocationVolume *locvol, GSList **l)
{
	*l = g_slist_append (*l, GUINT_TO_POINTER (locvol->base_loc));
}

static void
free_location_volume (GkrLocationVolume *locvol) 
{
	if (locvol) {
		g_free (locvol->name);
		g_free (locvol->prefix);
		g_slice_free (GkrLocationVolume, locvol);
	}
}

#ifdef WITH_HAL

static gboolean 
handle_retrieve_error (const char *what, const char *udi, DBusError *error)
{
	if (!dbus_error_is_set (error))
		return FALSE;
	g_warning ("Error retrieving %s on '%s': Error: '%s' Message: '%s'",
	           what, udi, error->name, error->message);
	dbus_error_free (error);
	return TRUE;
}

static gchar*
udi_to_location_name (LibHalContext *hal_ctx, const char *udi)
{
	const char *x; 
	char *name, *c;
	
	x = strrchr (udi, '/');
	if (x)
		udi = x + 1;
	
	name = g_strdup (udi);
	
	/*
	 * Replace all the ':' with '_' as a colon is a special
	 * character in our full location paths.
	 */
	 
	for (c = name; *c; ++c) {
		if (*c == ':')
			*c = '_';
	}
	
	return name;
}

static void 
hal_device_added (LibHalContext *hal_ctx, const char *udi)
{
	DBusError error;
	
	dbus_error_init (&error);
	
	/* Make sure it's a drive volume */
	if (!libhal_device_query_capability (hal_ctx, udi, "volume", NULL))
		return;

	if (!libhal_device_add_property_watch (hal_ctx, udi, &error)) {
		g_warning ("Error adding watch on %s: Error: '%s' Message: '%s'",
		           udi, error.name, error.message);
		dbus_error_free (&error);
	}
}

static void 
hal_device_removed (LibHalContext *hal_ctx, const char *udi)
{
	GkrLocationManager *locmgr = GKR_LOCATION_MANAGER (libhal_ctx_get_user_data (hal_ctx));
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	DBusError error;
	char *name = NULL;
	
	dbus_error_init (&error);
	
	if (!libhal_device_remove_property_watch (hal_ctx, udi, &error)) {
		g_warning ("Error removing watch on %s: Error: '%s' Message: '%s'",
		           udi, error.name, error.message);
		dbus_error_free (&error);
	}

	name = udi_to_location_name (hal_ctx, udi);
	g_assert (name && name[0]);
	
	if (g_hash_table_lookup (pv->volumes_by_name, name)) {
		g_message ("removing removable location: %s", name); 
		gkr_location_manager_unregister (locmgr, name);
	}
	
	g_free (name);

}

static void
hal_device_property (LibHalContext *hal_ctx, const char *udi, const char *key, 
                     dbus_bool_t is_removed, dbus_bool_t is_added)
{
	GkrLocationManager *locmgr = GKR_LOCATION_MANAGER (libhal_ctx_get_user_data (hal_ctx));
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	char *drive_udi = NULL;
	char *mount = NULL;
	char *name = NULL;
	DBusError error;
	gboolean removable, is_mounted;

	if (g_ascii_strcasecmp (key, "volume.is_mounted") != 0)
		return;

	dbus_error_init(&error);

	/* Make sure it's a drive volume */
	if (!libhal_device_query_capability (hal_ctx, udi, "volume", NULL))
		goto done;
		
	is_mounted = libhal_device_get_property_bool (hal_ctx, udi, "volume.is_mounted", &error);
	if (handle_retrieve_error ("volume.is_mounted", udi, &error))
		goto done;

	name = udi_to_location_name (hal_ctx, udi);
	g_assert (name && name[0]);
	
	/* A mount was added? */
	if (is_mounted &&  !g_hash_table_lookup (pv->volumes_by_name, name)) {
		
		drive_udi = libhal_device_get_property_string (hal_ctx, udi, "block.storage_device", &error);
		if (!drive_udi) {
			handle_retrieve_error ("block.storage_device", udi, &error);
			goto done;
		}

		removable = libhal_device_get_property_bool (hal_ctx, drive_udi, "storage.removable", &error);
		if (!removable)
			goto done;
		
		/* Get the mount point */
		mount = libhal_device_get_property_string (hal_ctx, udi, "volume.mount_point", &error);
		if (!mount) {
			handle_retrieve_error ("volume.mount_point", udi, &error);
			goto done;
		}
	
		if (!mount[0])
			goto done;
		
		g_message ("adding removable location: %s at %s", name, mount); 
		gkr_location_manager_register (locmgr, name, mount);

	/* A mount was removed? */		
	} else if (!is_mounted && g_hash_table_lookup (pv->volumes_by_name, name)) {
		
		g_message ("removing removable location: %s", name); 
		gkr_location_manager_unregister (locmgr, name);
		
	}
	
done:
	if (drive_udi)
		libhal_free_string (drive_udi);
	if (mount)
		libhal_free_string (mount);
	g_free (name);

}

static void
populate_all_volumes (GkrLocationManager *locmgr)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	char **volumes;
	int num_volumes, i;
	DBusError error;

	dbus_error_init (&error);
	volumes = libhal_find_device_by_capability (pv->hal_ctx, "volume", &num_volumes, &error);
		
	if (volumes) {
		for (i = 0; volumes && i < num_volumes; i++) {
			hal_device_added (pv->hal_ctx, volumes[i]);
			hal_device_property (pv->hal_ctx, volumes[i], "volume.is_mounted", FALSE, TRUE);
		}
		libhal_free_string_array (volumes);
	}
}	

static void
location_manager_hal_init (GkrLocationManager *locmgr)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	DBusConnection *dbus_connection;
	DBusError error;
	
	pv->hal_ctx = libhal_ctx_new ();
	if (!pv->hal_ctx) {
		g_warning ("failed to create a HAL context\n");
		return;
	}
	
	/* 
	 * Although we can be started before the session bus, we should be 
	 * able to connect to the system bus without any trouble at all.
	 */

	dbus_error_init (&error);
	dbus_connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (dbus_error_is_set (&error)) {
		g_warning ("Error connecting to D-BUS system bus: %s", error.message);
		dbus_error_free (&error);
		return;
	}
	
	gkr_dbus_connect_with_mainloop (dbus_connection, NULL);

	libhal_ctx_set_dbus_connection (pv->hal_ctx, dbus_connection);

	libhal_ctx_set_device_added (pv->hal_ctx, hal_device_added);
	libhal_ctx_set_device_removed (pv->hal_ctx, hal_device_removed);
	libhal_ctx_set_device_property_modified (pv->hal_ctx, hal_device_property);
	
	if (!libhal_ctx_init (pv->hal_ctx, &error)) {
		g_warning ("failed to initialize a HAL context: %s\n", error.message);
		dbus_error_free (&error);
		return;
	}
	
	libhal_ctx_set_user_data (pv->hal_ctx, locmgr);
	
	populate_all_volumes (locmgr);
}

static void
location_manager_hal_uninit (GkrLocationManager *locmgr)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	DBusError error;

	if (pv->hal_ctx) {
		if (!libhal_ctx_shutdown (pv->hal_ctx, &error))
			g_warning ("failed to shutdown HAL context: %s\n", error.message);
		else if (!libhal_ctx_free (pv->hal_ctx)) 
			g_warning ("failed to free HAL context");
		pv->hal_ctx = NULL;
	}
}

#endif /* WITH_HAL */

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_location_manager_init (GkrLocationManager *locmgr)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	const gchar *home, *env;
	gchar *local = NULL;

	pv->volumes_by_name = g_hash_table_new_full (g_str_hash, g_str_equal, 
	                                             NULL, (GDestroyNotify)free_location_volume);
	pv->volumes_by_prefix = g_hash_table_new (g_str_hash, g_str_equal);
	
	/* We always register the home directory */
	home = g_get_home_dir ();
	if (home)
		gkr_location_manager_register (locmgr, HOME_NAME, home);
		
#ifdef WITH_TESTS
	env = g_getenv ("GNOME_KEYRING_TEST_PATH");
	if (env && *env)
		local = g_strdup (env);
#endif 
	if (!local && home)
		local = g_build_filename (home, ".gnome2", NULL);
	
	if (local)
		gkr_location_manager_register (locmgr, GNOME_NAME, local);

	g_free (local);
	
#ifdef WITH_HAL
	location_manager_hal_init (locmgr);
#endif
}

static void 
gkr_location_manager_dispose (GObject *obj)
{
	GkrLocationManager *locmgr = GKR_LOCATION_MANAGER (obj);

#ifdef WITH_HAL
	location_manager_hal_uninit (locmgr);
#endif	
	
	G_OBJECT_CLASS (gkr_location_manager_parent_class)->dispose (obj);
}

static void
gkr_location_manager_finalize (GObject *obj)
{
	GkrLocationManager *locmgr = GKR_LOCATION_MANAGER (obj);
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);

	g_hash_table_destroy (pv->volumes_by_prefix);
	pv->volumes_by_prefix = NULL;
	g_hash_table_destroy (pv->volumes_by_name);
	pv->volumes_by_name = NULL;

	G_OBJECT_CLASS (gkr_location_manager_parent_class)->finalize (obj);
}

static void
gkr_location_manager_class_init (GkrLocationManagerClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gkr_location_manager_parent_class  = g_type_class_peek_parent (klass);
	
	gobject_class->dispose = gkr_location_manager_dispose;
	gobject_class->finalize = gkr_location_manager_finalize;
	
	signals[LOCATION_ADDED] = g_signal_new ("location-added", GKR_TYPE_LOCATION_MANAGER, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrLocationManagerClass, location_added),
			NULL, NULL, g_cclosure_marshal_VOID__UINT, 
			G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[LOCATION_REMOVED] = g_signal_new ("location-removed", GKR_TYPE_LOCATION_MANAGER, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrLocationManagerClass, location_removed),
			NULL, NULL, g_cclosure_marshal_VOID__UINT, 
			G_TYPE_NONE, 1, G_TYPE_UINT);
			
	g_type_class_add_private (klass, sizeof (GkrLocationManagerPrivate));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkrLocationManager*
gkr_location_manager_get (void)
{
	if (!location_manager_singleton) {
		location_manager_singleton = g_object_new (GKR_TYPE_LOCATION_MANAGER, NULL);
		gkr_cleanup_register (cleanup_location_manager, NULL);
	}
	
	return location_manager_singleton;
}

void
gkr_location_manager_register (GkrLocationManager *locmgr, const gchar *name, const gchar *prefix)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	GkrLocationVolume *locvol;
	GQuark base_loc;
	gchar *sloc;

	g_return_if_fail (GKR_IS_LOCATION_MANAGER (locmgr));	
	g_return_if_fail (name && name[0]);
	g_return_if_fail (prefix && prefix[0]);
	
	locvol = g_hash_table_lookup (pv->volumes_by_prefix, prefix);
	if (locvol) {
		g_warning ("location device '%s' already registered at: %s", 
		           locvol->name, locvol->prefix);
		return;
	}
	
	locvol = g_hash_table_lookup (pv->volumes_by_prefix, name);
	if (locvol) {
		g_warning ("location device '%s' already registered at: %s", 
		           name, locvol->prefix);
		return;
	}

	sloc = g_strdup_printf ("%s:/", name);
	base_loc = gkr_location_from_string (sloc);
	g_free (sloc);
		
	locvol = g_slice_new (GkrLocationVolume);
	locvol->name = g_strdup (name);
	locvol->prefix = g_strdup (prefix);
	locvol->base_loc = base_loc;
	
	/* TODO: What about trailing slashes? */
	
	g_hash_table_replace (pv->volumes_by_name, locvol->name, locvol);
	g_hash_table_replace (pv->volumes_by_prefix, locvol->prefix, locvol);
	
	g_signal_emit (locmgr, signals[LOCATION_ADDED], 0, base_loc);
}

void
gkr_location_manager_unregister (GkrLocationManager *locmgr, const gchar *name)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	GkrLocationVolume *locvol;
	GQuark base_loc;
	
	g_return_if_fail (GKR_IS_LOCATION_MANAGER (locmgr));	
	g_return_if_fail (name && name[0]);
	
	locvol = g_hash_table_lookup (pv->volumes_by_name, name);
	if (!locvol) {
		g_warning ("location device not registered: %s", name);
		return;
	}
	
	base_loc = locvol->base_loc;
	g_hash_table_remove (pv->volumes_by_prefix, locvol->prefix);
	g_hash_table_remove (pv->volumes_by_name, name);
	
	g_signal_emit (locmgr, signals[LOCATION_REMOVED], 0, base_loc);
}

GSList*
gkr_location_manager_get_locations (GkrLocationManager *locmgr)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	GSList *ret = NULL;	

	g_return_val_if_fail (GKR_IS_LOCATION_MANAGER (locmgr), NULL);	

	g_hash_table_foreach (pv->volumes_by_name, (GHFunc)list_locations, &ret);
	return ret; 
}


/* -----------------------------------------------------------------------------
 * GLOBAL FUNCTIONS
 */

typedef struct _FindClosestName {
	const gchar *search;
	const gchar *matched;
	const gchar *name;
} FindClosestName;

static void
find_closest_name (const gchar* name, GkrLocationVolume *locvol, FindClosestName *ctx)
{
	guint len;
	
	g_assert (name && name[0]);
	g_assert (locvol);
	
	len = strlen (locvol->prefix);
	if (strncmp (ctx->search, locvol->prefix, len) == 0) {
		if (!ctx->matched || strlen (ctx->matched) < len)
			ctx->matched = locvol->prefix;
			ctx->name = name;
	} 
}

GQuark
gkr_location_from_string (const gchar *str)
{
	g_assert (str && str[0]);
	
	/* TODO: Some sort of validation? */
	
	return g_quark_from_string (str);
}

GQuark
gkr_location_from_path (const gchar *path)
{
	GkrLocationManager *locmgr = gkr_location_manager_get ();
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	FindClosestName ctx = { path, NULL, NULL };
	GQuark res;
	gchar *loc;
	
	g_assert (path && path[0]);
	g_assert (g_path_is_absolute (path));

	g_hash_table_foreach (pv->volumes_by_name, (GHFunc)find_closest_name, &ctx); 
	
	if (!ctx.name) {
		ctx.name = DEFAULT_NAME;
		ctx.matched = "";
	}		
	
	/* Take off the prefix */
	path += strlen (ctx.matched);
		
	loc = g_strconcat (ctx.name, LOC_DELIMITER, path, NULL);
	res = g_quark_from_string (loc);
	g_free (loc);
	return res;
}

GQuark
gkr_location_from_child (GQuark parent, const gchar *child)
{
	gchar *path;
	GQuark loc;
	
	g_assert (parent);
	
	path = g_build_path (G_DIR_SEPARATOR_S, g_quark_to_string (parent), child, NULL);
	loc = g_quark_from_string (path);
	g_free (path);
	return loc;
}

gchar* 
gkr_location_to_path (GQuark location)
{
	GkrLocationManager *locmgr = gkr_location_manager_get ();
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	GkrLocationVolume *locvol;
	const gchar *current;
	const gchar *bdelim, *edelim;
	gchar *name, *res;
	guint l;
	
	g_assert (location);

	current = g_quark_to_string (location);
	g_assert (current);
	
	bdelim = strchr (current, LOC_DELIMITER_C);
	edelim = strrchr (current, LOC_DELIMITER_C);
	if (edelim == bdelim)
		edelim = current + strlen (current);
	
	if (!bdelim || !edelim) {
		g_warning ("The '%s' location is invalid", current);
		g_assert_not_reached ();
		return NULL;
	}
	
	g_assert (bdelim < edelim);
	
	name = g_strndup (current, bdelim - current);
	locvol = g_hash_table_lookup (pv->volumes_by_name, name);
	g_free (name);
	
	if (!locvol) {
		g_warning ("The '%s' location is invalid or no longer exists", current);		
		return NULL;
	}

	++bdelim;
	
	/* Assemble carefully */
	l = strlen (locvol->prefix);
	res = g_malloc0 (l + (edelim - bdelim) + 1);
	memcpy (res, locvol->prefix, l);
	memcpy (res + l, bdelim, (edelim - bdelim));
	return res;
}

const gchar*
gkr_location_to_string (GQuark loc)
{
	if (!loc)
		return NULL;
	return g_quark_to_string (loc);
}

gboolean
gkr_location_is_descendant (GQuark parent, GQuark descendant)
{
	const gchar *sparent = g_quark_to_string (parent);
	const gchar *sdescendant = g_quark_to_string (descendant);
	if (!sparent || !sdescendant)
		return FALSE;
	return memcmp (sparent, sdescendant, strlen (sparent)) == 0;
}
