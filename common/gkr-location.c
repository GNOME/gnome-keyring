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
#include <glib/gi18n-lib.h>

#include <string.h>

#define LOC_DELIMITER   ":"
#define LOC_DELIMITER_C ':'

typedef struct _GkrLocationVolume {
	GQuark volume_loc;
	gchar *name;
	gchar *prefix;
	gchar *friendly;
	gboolean hidden;
#ifdef WITH_HAL
	gboolean hal_volume;
#endif
} GkrLocationVolume;

enum {
    VOLUME_ADDED,
    VOLUME_REMOVED,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (GkrLocationManager, gkr_location_manager, G_TYPE_OBJECT);

struct _GkrLocationManagerPrivate;
typedef struct _GkrLocationManagerPrivate GkrLocationManagerPrivate;

struct _GkrLocationManagerPrivate {
#ifdef WITH_HAL
	LibHalContext *hal_ctx;
	guint hal_retry;
	DBusConnection *dbus_connection;
#endif
	GHashTable *volumes_by_name;
	GHashTable *volumes_by_loc;
	GHashTable *volumes_by_prefix;
	
	/* Some special locations, that we don't advertize, but support */
	GkrLocationVolume file_volume;
	GkrLocationVolume home_volume;
	
	/* Last modified time of locations */
	GHashTable *last_modified;
};

#define GKR_LOCATION_MANAGER_GET_PRIVATE(o)  \
	(G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_LOCATION_MANAGER, GkrLocationManagerPrivate))

static GkrLocationManager *location_manager_singleton = NULL; 

#ifdef WITH_HAL
/* Forward declaration */
static void location_manager_hal_init (GkrLocationManager *locmgr);
#endif

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

#if 0
static gboolean
purge_last_modified (gpointer key, gpointer unused, gpointer user_data)
{
	GQuark loc = GPOINTER_TO_UINT (key);
	GQuark volume = GPOINTER_TO_UINT (user_data);
	return gkr_location_is_descendant (volume, loc);
}
#endif

static void
list_locations (const gchar *name, GkrLocationVolume *locvol, GSList **l)
{
	if (!locvol->hidden)
		*l = g_slist_append (*l, GUINT_TO_POINTER (locvol->volume_loc));
}

static void
free_mtime (time_t *mtime)
{
	if (mtime)
		g_slice_free (time_t, mtime);
}

static void
free_location_volume (GkrLocationVolume *locvol) 
{
	if (locvol) {
		/* Hidden volumes are freed elsewhere */
		if (locvol->hidden)
			return;
		g_free (locvol->name);
		g_free (locvol->prefix);
		g_slice_free (GkrLocationVolume, locvol);
	}
}

static GQuark
make_volume_location (const gchar *name)
{
	gchar *sloc;
	GQuark loc;
	
	sloc = g_strdup_printf ("%s:", name);
	loc = gkr_location_from_string (sloc);
	g_free (sloc);
	
	return loc;
}

static void
make_hidden_volume (GkrLocationManager *locmgr, GkrLocationVolume *locvol, 
                    const gchar *name, const gchar *prefix, const gchar *friendly)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	GQuark volume_loc = make_volume_location (name);
	
	locvol->name = (gchar*)name;
	locvol->volume_loc = volume_loc;
	locvol->prefix = (gchar*)prefix; 
	locvol->hidden = TRUE;
	locvol->friendly = friendly ? g_strdup (friendly) : NULL;
	
	g_hash_table_replace (pv->volumes_by_name, locvol->name, locvol);
	g_hash_table_replace (pv->volumes_by_prefix, locvol->prefix, locvol);
	g_hash_table_replace (pv->volumes_by_loc, GUINT_TO_POINTER (volume_loc), locvol);
	
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
	g_return_if_fail (name && name[0]);
	
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
	char *friendly = NULL;
	char *product = NULL;
	DBusError error;
	gboolean removable, is_mounted;
	GkrLocationVolume *locvol;

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
	g_return_if_fail (name && name[0]);
	
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
			
		product = libhal_device_get_property_string (hal_ctx, udi, "info.product", &error);
		if (product && product)
			friendly = g_strdup_printf (_("Removable Disk: %s"), product);
		else 
			friendly = g_strdup (_("Removable Disk"));
		
		g_message ("adding removable location: %s at %s", name, mount); 
		gkr_location_manager_register (locmgr, name, mount, friendly);
		
		locvol = g_hash_table_lookup (pv->volumes_by_name, name);
		if (locvol)
			locvol->hal_volume = TRUE;

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
	if (product)
		libhal_free_string (product);
	g_free (friendly);
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

static gboolean
location_manager_try_hal_connection (gpointer data) 
{
	GkrLocationManager *locmgr = GKR_LOCATION_MANAGER (data);
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);

	pv->hal_retry = 0;

	location_manager_hal_init (locmgr);

	return FALSE;
}

static void
location_manager_schedule_hal_retry (GkrLocationManager *locmgr) {
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);

	g_message ("Scheduling hal init retry");

	if (pv->hal_retry == 0)
		pv->hal_retry = g_timeout_add_seconds (30, location_manager_try_hal_connection, 
		                                       locmgr);
}

static void
location_manager_hal_uninit (GkrLocationManager *locmgr)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	DBusError error;

	if (pv->hal_ctx) {
		dbus_error_init (&error);
		if (pv->dbus_connection != NULL && !libhal_ctx_shutdown (pv->hal_ctx, &error)) {
			g_warning ("failed to shutdown HAL context: %s\n", error.message);
			dbus_error_free (&error);
		} 
		
		if (!libhal_ctx_free (pv->hal_ctx)) 
			g_warning ("failed to free HAL context");
		pv->hal_ctx = NULL;
	}

	if (pv->dbus_connection != NULL) {
		gkr_dbus_disconnect_from_mainloop (pv->dbus_connection, NULL);
		dbus_connection_unref (pv->dbus_connection);
		pv->dbus_connection = NULL;
	}
}

static void
gather_hal_volume_names (gpointer key, gpointer value, gpointer user_data)
{
	GList **list = (GList**)user_data;
	GkrLocationVolume *locvol = (GkrLocationVolume*)value;
	if (locvol->hal_volume)
		*list = g_list_prepend (*list, key);
}

static DBusHandlerResult
location_manager_dbus_filter_function (DBusConnection *connection, DBusMessage *message, void *user_data) 
{
	GkrLocationManager *locmgr = GKR_LOCATION_MANAGER (user_data);
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	GList *l, *names = NULL;
	
	if (dbus_message_is_signal (message, DBUS_INTERFACE_LOCAL, "Disconnected") &&
	    strcmp (dbus_message_get_path (message), DBUS_PATH_LOCAL) == 0) {
		
		/* Reconnect to HAL when we can */
		location_manager_hal_uninit (locmgr);
		location_manager_schedule_hal_retry (locmgr);

		/* Remove all our HAL based volumes */
		g_hash_table_foreach (pv->volumes_by_name, gather_hal_volume_names, &names);
		for (l = names; l; l = g_list_next (l))
			gkr_location_manager_unregister (locmgr, (const gchar*)l->data);
		g_list_free (names);

		return DBUS_HANDLER_RESULT_HANDLED;
	}
	
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
location_manager_hal_init (GkrLocationManager *locmgr)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	DBusError error;

	pv->hal_ctx = libhal_ctx_new ();
	if (!pv->hal_ctx) {
		g_warning ("failed to create a HAL context");
		goto failed;
	}
	
	/* 
	 * Although we can be started before the session bus, we should be 
	 * able to connect to the system bus without any trouble at all.
	 */

	dbus_error_init (&error);
	pv->dbus_connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (dbus_error_is_set (&error)) {
		g_warning ("error connecting to D-BUS system bus: %s", error.message);
		dbus_error_free (&error);
		goto failed;
	}
	
	gkr_dbus_connect_with_mainloop (pv->dbus_connection, NULL);
	dbus_connection_set_exit_on_disconnect (pv->dbus_connection, FALSE);

	dbus_connection_add_filter (pv->dbus_connection, location_manager_dbus_filter_function, locmgr, NULL);

	libhal_ctx_set_dbus_connection (pv->hal_ctx, pv->dbus_connection);

	libhal_ctx_set_device_added (pv->hal_ctx, hal_device_added);
	libhal_ctx_set_device_removed (pv->hal_ctx, hal_device_removed);
	libhal_ctx_set_device_property_modified (pv->hal_ctx, hal_device_property);
	
	if (!libhal_ctx_init (pv->hal_ctx, &error)) {
		g_warning ("failed to initialize a HAL context: %s\n", error.message);
		dbus_error_free (&error);
		goto failed;
	}
	
	libhal_ctx_set_user_data (pv->hal_ctx, locmgr);
	
	populate_all_volumes (locmgr);

	return;

failed:
	location_manager_hal_uninit (locmgr);
	location_manager_schedule_hal_retry (locmgr);
}

#endif /* WITH_HAL */

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_location_manager_init (GkrLocationManager *locmgr)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	const gchar *home;
#ifdef WITH_TESTS
	const gchar *env;
#endif
	gchar *local = NULL;

	pv->volumes_by_name = g_hash_table_new_full (g_str_hash, g_str_equal, 
	                                             NULL, (GDestroyNotify)free_location_volume);
	pv->volumes_by_prefix = g_hash_table_new (g_str_hash, g_str_equal);
	pv->volumes_by_loc = g_hash_table_new (g_direct_hash, g_direct_equal);

	pv->last_modified = g_hash_table_new_full (g_direct_hash, g_direct_equal, 
	                                           NULL, (GDestroyNotify)free_mtime);

	home = g_get_home_dir ();
	g_return_if_fail (home && home[0]);
	
	/* Hidden location relative to file system and home directory */
	make_hidden_volume (locmgr, &pv->file_volume, GKR_LOCATION_NAME_FILE, "/", NULL);
	make_hidden_volume (locmgr, &pv->home_volume, GKR_LOCATION_NAME_HOME, home, _("Home"));

	
	/* We always register the .gnome2 local directory */		
#ifdef WITH_TESTS
	env = g_getenv ("GNOME_KEYRING_TEST_PATH");
	if (env && *env)
		local = g_strdup (env);
#endif 
	if (!local)
		local = g_build_filename (home, ".gnome2", NULL);

	gkr_location_manager_register (locmgr, GKR_LOCATION_NAME_LOCAL, local, _("Home"));
	g_free (local);
	
#ifdef WITH_HAL
	location_manager_hal_init (locmgr);
#endif
}

static void 
gkr_location_manager_dispose (GObject *obj)
{
	GkrLocationManager *locmgr = GKR_LOCATION_MANAGER (obj);
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);

#ifdef WITH_HAL
	location_manager_hal_uninit (locmgr);
	if (pv->hal_retry != 0)
		g_source_remove (pv->hal_retry);
	pv->hal_retry = 0;
#endif

	g_hash_table_remove_all (pv->volumes_by_loc);
	g_hash_table_remove_all (pv->volumes_by_prefix);
	g_hash_table_remove_all (pv->volumes_by_name);
	
	g_hash_table_remove_all (pv->last_modified);
	
	G_OBJECT_CLASS (gkr_location_manager_parent_class)->dispose (obj);
}

static void
gkr_location_manager_finalize (GObject *obj)
{
	GkrLocationManager *locmgr = GKR_LOCATION_MANAGER (obj);
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);

	g_hash_table_destroy (pv->volumes_by_loc);
	pv->volumes_by_loc = NULL;
	g_hash_table_destroy (pv->volumes_by_prefix);
	pv->volumes_by_prefix = NULL;
	g_hash_table_destroy (pv->volumes_by_name);
	pv->volumes_by_name = NULL;
	
	g_hash_table_destroy (pv->last_modified);
	pv->last_modified = NULL;

	G_OBJECT_CLASS (gkr_location_manager_parent_class)->finalize (obj);
}

static void
gkr_location_manager_class_init (GkrLocationManagerClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gkr_location_manager_parent_class  = g_type_class_peek_parent (klass);
	
	gobject_class->dispose = gkr_location_manager_dispose;
	gobject_class->finalize = gkr_location_manager_finalize;
	
	signals[VOLUME_ADDED] = g_signal_new ("volume-added", GKR_TYPE_LOCATION_MANAGER, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrLocationManagerClass, volume_added),
			NULL, NULL, g_cclosure_marshal_VOID__UINT, 
			G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[VOLUME_REMOVED] = g_signal_new ("volume-removed", GKR_TYPE_LOCATION_MANAGER, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrLocationManagerClass, volume_removed),
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
gkr_location_manager_register (GkrLocationManager *locmgr, const gchar *name, 
                               const gchar *prefix, const gchar *friendly)
{
	GkrLocationManagerPrivate *pv;
	GkrLocationVolume *locvol;
	GQuark volume_loc;

	if (!locmgr)
		locmgr = gkr_location_manager_get ();
	
	g_return_if_fail (GKR_IS_LOCATION_MANAGER (locmgr));	
 	pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);

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

	volume_loc = make_volume_location (name);
			
	locvol = g_slice_new (GkrLocationVolume);
	locvol->name = g_strdup (name);
	locvol->prefix = g_strdup (prefix);
	locvol->friendly = g_strdup (friendly);
	locvol->volume_loc = volume_loc;
	locvol->hidden = FALSE;
#ifdef WITH_HAL
	locvol->hal_volume = FALSE;
#endif
	
	/* TODO: What about trailing slashes? */
	
	g_hash_table_replace (pv->volumes_by_name, locvol->name, locvol);
	g_hash_table_replace (pv->volumes_by_prefix, locvol->prefix, locvol);
	g_hash_table_replace (pv->volumes_by_loc, GUINT_TO_POINTER (volume_loc), locvol);
	 
	g_signal_emit (locmgr, signals[VOLUME_ADDED], 0, volume_loc);
}

void
gkr_location_manager_unregister (GkrLocationManager *locmgr, const gchar *name)
{
	GkrLocationManagerPrivate *pv;
	GkrLocationVolume *locvol;
	GQuark volume_loc;
	
	if (!locmgr)
		locmgr = gkr_location_manager_get ();
	
	g_return_if_fail (GKR_IS_LOCATION_MANAGER (locmgr));	
 	pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr); 	
	g_return_if_fail (name && name[0]);
	
	locvol = g_hash_table_lookup (pv->volumes_by_name, name);
	if (!locvol) {
		g_warning ("location device not registered: %s", name);
		return;
	}
	
	volume_loc = locvol->volume_loc;
	g_hash_table_remove (pv->volumes_by_loc, GUINT_TO_POINTER (volume_loc));
	g_hash_table_remove (pv->volumes_by_prefix, locvol->prefix);
	g_hash_table_remove (pv->volumes_by_name, name);
	
	g_signal_emit (locmgr, signals[VOLUME_REMOVED], 0, volume_loc);
}

gboolean 
gkr_location_manager_has_volume (GkrLocationManager *locmgr, GQuark volume)
{
	GkrLocationManagerPrivate *pv;

	if (!locmgr)
		locmgr = gkr_location_manager_get ();
	
	g_return_val_if_fail (GKR_IS_LOCATION_MANAGER (locmgr), FALSE);	
 	pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);

	return g_hash_table_lookup (pv->volumes_by_loc, GUINT_TO_POINTER (volume)) ? TRUE : FALSE;
}

GSList*
gkr_location_manager_get_volumes (GkrLocationManager *locmgr)
{
	GkrLocationManagerPrivate *pv;
	GSList *ret = NULL;	

	if (!locmgr)
		locmgr = gkr_location_manager_get ();
	
	g_return_val_if_fail (GKR_IS_LOCATION_MANAGER (locmgr), NULL);	
 	pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);

	g_hash_table_foreach (pv->volumes_by_name, (GHFunc)list_locations, &ret);
	return ret; 
}

const gchar*
gkr_location_manager_get_volume_display (GkrLocationManager *locmgr, GQuark volume_loc)
{
	GkrLocationManagerPrivate *pv;
	GkrLocationVolume *locvol;

	if (!locmgr)
		locmgr = gkr_location_manager_get ();
	
	g_return_val_if_fail (GKR_IS_LOCATION_MANAGER (locmgr), NULL);	
 	pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	
	locvol = g_hash_table_lookup (pv->volumes_by_loc, GUINT_TO_POINTER (volume_loc));
	if (!locvol) {
		g_warning ("'%s' is not a valid volume location", g_quark_to_string (volume_loc));
		return NULL;
	}
	
	return locvol->friendly;
}

gboolean
gkr_location_manager_note_mtime (GkrLocationManager *locmgr, GQuark location, time_t mtime)
{
	GkrLocationManagerPrivate *pv;
	gboolean ret;
	gpointer key;
	time_t *last;
	
	if (!locmgr)
		locmgr = gkr_location_manager_get ();
	if (mtime <= 0)
		mtime = time (NULL);
			
	g_return_val_if_fail (GKR_IS_LOCATION_MANAGER (locmgr), FALSE);	
 	pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
 	g_return_val_if_fail (mtime > 0, FALSE);

	key = GUINT_TO_POINTER (location);
	last = g_hash_table_lookup (pv->last_modified, key);
	
	ret = (!last || *last < mtime);
	
	if (!last) {
		last = g_slice_new0 (time_t);
		g_hash_table_replace (pv->last_modified, key, last);
	}
	
	if (*last != mtime)
		*last = mtime;
		
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
find_closest_name (gpointer unused, GkrLocationVolume *locvol, FindClosestName *ctx)
{
	guint len;
	
	g_assert (locvol);
	
	len = strlen (locvol->prefix);
	if (strncmp (ctx->search, locvol->prefix, len) == 0) {
		if (!ctx->matched || strlen (ctx->matched) < len) {
			ctx->matched = locvol->prefix;
			ctx->name = locvol->name;
		}
	} 
}

GQuark
gkr_location_from_string (const gchar *str)
{
	g_return_val_if_fail (str && str[0], 0);
	
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
	const gchar *c;
	
	g_return_val_if_fail (path && path[0], 0);
	g_return_val_if_fail (g_path_is_absolute (path), 0);
	
	/* We don't allow a colon in our paths */
	for (c = path; *c; ++c) {
		if (*c == ':') {
			g_warning ("path has a colon in it. It cannot be used as a location: %s", path);
			g_return_val_if_reached (0);
		}
	}

	g_hash_table_foreach (pv->volumes_by_name, (GHFunc)find_closest_name, &ctx); 
	
	/* Manually use filesystem if nothing matched */
	if (!ctx.name) {
		ctx.name = pv->file_volume.name;
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
	const gchar *c;
	gchar *path, *p;
	GQuark loc;
	
	g_return_val_if_fail (parent, 0);
	
	/* We don't allow a colon in our paths */
	for (c = child; *c; ++c) {
		if (*c == ':') {
			g_warning ("path has a colon in it. It cannot be used as a location: %s", child);
			g_return_val_if_reached (0);
		}
	}

	path = g_build_path (G_DIR_SEPARATOR_S, g_quark_to_string (parent), child, NULL);
	
	/* Strip out trailing slashes */
	p = path + strlen (path);
	while (p > path + 1) {
		*(p--) = 0;
		if (!G_IS_DIR_SEPARATOR (*p))
			break;
	}
	
	/* Strip out any trailing slashes */
	loc = g_quark_from_string (path);
	g_free (path);
	return loc;
}

static GkrLocationVolume*
location_to_volume (GQuark loc, const gchar **remainder)
{
	GkrLocationManager *locmgr = gkr_location_manager_get ();
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);
	GkrLocationVolume *locvol;
	const gchar *bdelim, *sloc;
	gchar *name;
	
	g_return_val_if_fail (loc, NULL);

	sloc = g_quark_to_string (loc);
	g_return_val_if_fail (sloc, NULL);

	bdelim = strchr (sloc, LOC_DELIMITER_C);
	if (!bdelim) {
		g_warning ("The '%s' location is invalid", sloc);
		return NULL;
	}
	
	name = g_strndup (sloc, bdelim - sloc);
	
	locvol = g_hash_table_lookup (pv->volumes_by_name, name);
	if (!locvol) {
		g_free (name);
		return NULL;
	}

	g_free (name);
	if (remainder)
		*remainder = bdelim + 1;
	return locvol;
} 

GQuark
gkr_location_to_parent (GQuark parent)
{
	const gchar *del, *sloc, *part;
	GQuark ret;
	gchar *str;
	
	g_return_val_if_fail (parent, 0);

	sloc = g_quark_to_string (parent);
	g_return_val_if_fail (sloc, 0);

	del = strchr (sloc, LOC_DELIMITER_C);
	if (!del) {
		g_warning ("The '%s' location is invalid", sloc);
		return 0;
	}
	
	part = strrchr (del + 1, G_DIR_SEPARATOR);
	str = g_strndup (sloc, (part ? part : del) - sloc);
	ret = g_quark_from_string (str);
	g_free (str);
	
	return ret;
} 

gchar* 
gkr_location_to_path (GQuark loc)
{
	GkrLocationVolume *locvol;
	const gchar *edelim, *path;
	gsize l;
	gchar *res;
	
	g_return_val_if_fail (loc, NULL);
	
	locvol = location_to_volume (loc, &path);
	if (!locvol)
		return NULL;

	edelim = strrchr (path, LOC_DELIMITER_C);
	if (edelim == NULL)
		edelim = path + strlen (path);

	/* Assemble carefully */
	l = strlen (locvol->prefix);
	res = g_malloc0 (l + (edelim - path) + 2);
	memcpy (res, locvol->prefix, l);
	memcpy (res + l, path, (edelim - path));
	return res;
}

const gchar*
gkr_location_to_string (GQuark loc)
{
	if (!loc)
		return NULL;
	return g_quark_to_string (loc);
}

gchar* 
gkr_location_to_display (GQuark loc)
{
	gchar *filename;
	gchar *display;
	
	if (!loc)
		return g_strdup ("");
	
	filename = gkr_location_to_path (loc);
	if (!filename)
		return g_strdup ("");
	
	display = g_filename_display_basename (filename);
	g_free (filename);
	if (!display)
		return g_strdup ("");
		
	return display;
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

GQuark
gkr_location_get_volume (GQuark loc)
{
	GkrLocationVolume *locvol;
	
	g_return_val_if_fail (loc, 0);
	
	locvol = location_to_volume (loc, NULL);
	if (!locvol)
		return 0;
		
	return locvol->volume_loc;
}

gboolean
gkr_location_test_file (GQuark loc, GFileTest test)
{
	gboolean ret;
	gchar *path;

	g_return_val_if_fail (loc != 0, FALSE);
	
	path = gkr_location_to_path (loc);
	if (!path)
		return FALSE;
	
	ret = g_file_test (path, test);
	g_free (path);
	
	return ret;
}
 
gboolean
gkr_location_read_file (GQuark loc, guchar **data, gsize *len, GError **err)
{
	gboolean ret;
	gchar *path;
	
	g_return_val_if_fail (loc != 0, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);
	
	path = gkr_location_to_path (loc);
	if (!path) {
		g_set_error (err, G_FILE_ERROR, G_FILE_ERROR_NODEV, "%s",  
		             _("The disk or drive this file is located on is not present"));
		return FALSE;
	}

	ret = g_file_get_contents (path, (gchar**)data, len, err);
	g_free (path);
	
	return ret;
}

gboolean
gkr_location_write_file (GQuark loc, const guchar *data, gssize len, GError **err)
{
	gboolean ret;
	gchar *path;
	
	g_return_val_if_fail (loc != 0, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);
	
	path = gkr_location_to_path (loc);
	if (!path) {
		g_set_error (err, G_FILE_ERROR, G_FILE_ERROR_NODEV, "%s",  
		             _("The disk or drive this file is located on is not present"));
		return FALSE;
	}

	ret = g_file_set_contents (path, (const gchar*)data, len, err);
	g_free (path);
	
	return ret;
}
