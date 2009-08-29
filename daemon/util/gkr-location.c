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

#include "egg/egg-cleanup.h"
#include "egg/egg-dbus.h"

#include <gio/gio.h>

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <string.h>

#define LOC_DELIMITER   ":"
#define LOC_DELIMITER_C ':'

typedef struct _GkrLocationVolume {
	GQuark volume_loc;
	gchar *name;
	gchar *prefix;
	gchar *friendly;
	gboolean hidden;
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
	GVolumeMonitor *monitor;

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

static void
remove_location_volume (GkrLocationManager *self, GkrLocationVolume *locvol)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (self);
	GQuark volume_loc;

	volume_loc = locvol->volume_loc;
	g_hash_table_remove (pv->volumes_by_loc, GUINT_TO_POINTER (volume_loc));
	g_hash_table_remove (pv->volumes_by_prefix, locvol->prefix);
	g_hash_table_remove (pv->volumes_by_name, locvol->name);

	g_signal_emit (self, signals[VOLUME_REMOVED], 0, volume_loc);
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

static gchar*
udi_to_location_name (const char *udi)
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
mount_added (GVolumeMonitor *monitor, GMount *mount, GkrLocationManager *self)
{
	gboolean removable;
	gchar *identifier;
	gchar *name, *friendly, *path;
	GDrive *drive;
	GVolume *volume;
	GFile *root;

	drive = g_mount_get_drive (mount);
	removable = drive && g_drive_is_media_removable (drive);
	if (drive)
		g_object_unref (drive);

	if (!removable)
		return;

	volume = g_mount_get_volume (mount);
	g_return_if_fail (volume);

	/* Figure out the location name */
	identifier = g_volume_get_identifier (volume, G_VOLUME_IDENTIFIER_KIND_HAL_UDI);
	if (!identifier) {
		g_object_unref (volume);
		return;
	}

	name = udi_to_location_name (identifier);
	g_free (identifier);

	/* Figure out the friendly name */
	identifier = g_volume_get_identifier (volume, G_VOLUME_IDENTIFIER_KIND_LABEL);
	if (identifier)
		friendly = g_strdup_printf (_("Removable Disk: %s"), identifier);
	else
		friendly = g_strdup (_("Removable Disk"));
	g_free (identifier);

	g_object_unref (volume);

	/* Figure out the mount point */
	root = g_mount_get_root (mount);
	g_return_if_fail (root);
	path = g_file_get_path (root);
	g_return_if_fail (path);
	g_object_unref (root);

	g_message ("adding removable location: %s at %s", name, path);
	gkr_location_manager_register (self, name, path, friendly);

	g_free (name);
	g_free (friendly);
	g_free (path);
}

static void
mount_removed (GVolumeMonitor *monitor, GMount *mount, GkrLocationManager *self)
{
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (self);
	GkrLocationVolume *locvol;
	GFile *root;
	gchar *path;

	root = g_mount_get_root (mount);
	g_return_if_fail (root);
	path = g_file_get_path (root);
	g_return_if_fail (path);
	g_object_unref (root);

	g_message ("removing removable location: %s", path);

	locvol = g_hash_table_lookup (pv->volumes_by_prefix, path);
	if (!locvol)
		g_warning ("no volume registered at: %s", path);
	else
		remove_location_volume (self, locvol);
	g_free (path);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gkr_location_manager_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkrLocationManager *self = GKR_LOCATION_MANAGER (G_OBJECT_CLASS (gkr_location_manager_parent_class)->constructor(type, n_props, props));
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (self);
	GList *mounts, *l;

	g_return_val_if_fail (self, NULL);

	/* Add all mounted drives */
	mounts = g_volume_monitor_get_mounts (pv->monitor);
	for (l = mounts; l; l = g_list_next (l)) {
		mount_added (pv->monitor, l->data, self);
		g_object_unref (l->data);
	}
	g_list_free (mounts);

	return G_OBJECT (self);
}

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

	pv->monitor = g_volume_monitor_get ();
	g_signal_connect (pv->monitor, "mount-added", G_CALLBACK (mount_added), locmgr);
	g_signal_connect (pv->monitor, "mount-removed", G_CALLBACK (mount_removed), locmgr);
}

static void 
gkr_location_manager_dispose (GObject *obj)
{
	GkrLocationManager *locmgr = GKR_LOCATION_MANAGER (obj);
	GkrLocationManagerPrivate *pv = GKR_LOCATION_MANAGER_GET_PRIVATE (locmgr);

	if (pv->monitor) {
		g_signal_handlers_disconnect_by_func (pv->monitor, mount_added, locmgr);
		g_signal_handlers_disconnect_by_func (pv->monitor, mount_removed, locmgr);
		g_object_unref (pv->monitor);
		pv->monitor = NULL;
	}

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

	g_assert (!pv->monitor);

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

	gobject_class->constructor = gkr_location_manager_constructor;
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
		egg_cleanup_register (cleanup_location_manager, NULL);
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

	remove_location_volume (locmgr, locvol);
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
gkr_location_is_volume (GQuark loc)
{
	const gchar *sloc;
	const gchar *delim;
	
	if (!loc)
		return FALSE;
	
	sloc = g_quark_to_string (loc);
	g_return_val_if_fail (sloc, FALSE);

	delim = strchr (sloc, LOC_DELIMITER_C);
	if (!delim) {
		g_warning ("The '%s' location is invalid", sloc);
		return FALSE;
	}
	
	return (delim[1] == 0);
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
	gboolean ret = TRUE;
	gchar *dirname;
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
	
	dirname = g_path_get_dirname (path);
	if (dirname && dirname[0]) {
		if (g_mkdir_with_parents (dirname, 0700) < 0) {
			g_set_error (err, G_FILE_ERROR, g_file_error_from_errno (errno),
			             _("Couldn't create directory: %s"), dirname);
			ret = FALSE;
		}
	}

	if (ret)
		ret = g_file_set_contents (path, (const gchar*)data, len, err);
	
	g_free (path);
	g_free (dirname);
	
	return ret;
}

gboolean
gkr_location_delete_file (GQuark loc, GError **err)
{
	gchar *path;
	int eno;
	
	g_return_val_if_fail (loc != 0, FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);

	/* Should be successful when file doesn't exist */
	path = gkr_location_to_path (loc);
	if (!path)
		return TRUE;

	if (g_unlink (path) < 0) {
		eno = errno;
		
		/* Should be successful when file doesn't exist */
		if (eno != ENOENT) {
			g_set_error (err, G_FILE_ERROR, g_file_error_from_errno (eno), 
			             _("Couldn't delete the file: %s"), g_strerror (eno));
			return FALSE;
		}
	}
	
	g_free (path);
	return TRUE;	
}
