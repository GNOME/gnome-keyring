/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-location-watch.c - Watch for changes in all base locations

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

#include "gkr-location-watch.h"

#include <glib.h>
#include <glib/gstdio.h>

#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

enum {
	LOCATION_ADDED,
	LOCATION_REMOVED,
	LOCATION_CHANGED,
	LAST_SIGNAL
};

typedef struct {
	GQuark parent;
	GkrLocationWatch *watch;
	GHashTable *checks;
} UpdateDescendants;

typedef struct _GkrLocationWatchPrivate GkrLocationWatchPrivate;
struct _GkrLocationWatchPrivate {
	/* Specification */
	GPatternSpec *include;
	GPatternSpec *exclude;
	gchar *subdir;
	GQuark only_volume;
	
	/* Matched Locations */
	GHashTable *locations;
};

#define GKR_LOCATION_WATCH_GET_PRIVATE(o) \
	(G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_LOCATION_WATCH, GkrLocationWatchPrivate))

G_DEFINE_TYPE (GkrLocationWatch, gkr_location_watch, G_TYPE_OBJECT);

static guint signals[LAST_SIGNAL] = { 0 };

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void
copy_key_value (gpointer key, gpointer value, gpointer data)
{
	GHashTable *dest = (GHashTable*)data;
	g_hash_table_replace (dest, key, value);
}

static void
remove_locations (gpointer key, gpointer value, gpointer data)
{
	GkrLocationWatch *watch = GKR_LOCATION_WATCH (data);
	GkrLocationWatchPrivate *pv = GKR_LOCATION_WATCH_GET_PRIVATE (watch);

	g_hash_table_remove (pv->locations, key);
	g_signal_emit (watch, signals[LOCATION_REMOVED], 0, GPOINTER_TO_UINT(key));
} 

static gboolean
update_location (GkrLocationWatch *watch, gboolean force_all, GQuark location)
{
	GkrLocationWatchPrivate *pv = GKR_LOCATION_WATCH_GET_PRIVATE (watch);
	struct stat sb;
	gchar *path;

	/* TODO: Allocating and freeing this all the time is braindead */
	path = gkr_location_to_path (location);
	if (!path)
		return FALSE;

	if (stat (path, &sb) < 0) {
		if (errno != ENOENT && errno != ENOTDIR && errno != EPERM)
			g_warning ("couldn't stat file: %s: %s", path, g_strerror (errno));
		g_free (path);
		return FALSE;
	}
	
	g_free (path);


	/* See if it has actually changed */
	if (gkr_location_manager_note_mtime (watch->manager, location, sb.st_mtime) || 
	    force_all) {
		g_assert (g_hash_table_lookup (pv->locations, GUINT_TO_POINTER (location)));
		g_signal_emit (watch, signals[LOCATION_CHANGED], 0, location);
	}
	
	return TRUE;
}
		
static void
update_each_descendant (gpointer key, gpointer unused, gpointer data)
{
	UpdateDescendants *ctx = (UpdateDescendants*)data;
	GQuark location = GPOINTER_TO_UINT (key);
	
	if (!gkr_location_is_descendant (ctx->parent, location))
		return;

	if (update_location (ctx->watch, FALSE, location))
		g_hash_table_remove (ctx->checks, GUINT_TO_POINTER (location));
}

static void
update_volume (GkrLocationWatch *watch, GQuark volume, gboolean force_all, 
               GHashTable *checks)
{
	GkrLocationWatchPrivate *pv = GKR_LOCATION_WATCH_GET_PRIVATE (watch);
	UpdateDescendants uctx;
	struct stat sb;
	GQuark dirloc;
	GError *err = NULL;
	const char *filename;
	gpointer key;
	gchar *path;
	gchar *file;
	GDir *dir;
	GQuark loc;
	int ret, lasterr;

	g_assert (volume);
	g_assert (checks);
	g_assert (GKR_IS_LOCATION_WATCH (watch));
	
	dirloc = pv->subdir ? gkr_location_from_child (volume, pv->subdir) : volume;
	path = gkr_location_to_path (dirloc);
	
	/* Can't resolve the location? Skip. */
	if (!path)
		return;

	if (stat (path, &sb) < 0) {
		if (errno != ENOENT && errno != ENOTDIR && errno != EPERM)
			g_message ("couldn't stat directory: %s: %s", path, g_strerror (errno));
		g_free (path);
		return;
	}

	/* See if it was updated since last seen or not */
	if (!gkr_location_manager_note_mtime (watch->manager, dirloc, sb.st_mtime) && 
	    !force_all) {

		uctx.parent = dirloc;
		uctx.watch = watch;
		uctx.checks = checks;
		
		/* Still need to check for individual file updates */
		g_hash_table_foreach (pv->locations, update_each_descendant, &uctx);
		
		g_free (path);
		return;
	} 

	/* Actually list the directory */
	dir = g_dir_open (path, 0, &err);
	if (dir == NULL) {
		if (errno != ENOENT && errno != ENOTDIR && errno != EPERM)
			g_message ("couldn't list keyrings at: %s: %s", path, 
		        	   err && err->message ? err->message : "");
		g_error_free (err);  
		g_free (path);
		return;
	}
	
	while ((filename = g_dir_read_name (dir)) != NULL) {
		if (filename[0] == '.')
			continue;
		if (pv->include && !g_pattern_match_string (pv->include, filename))
			continue;
		if (pv->exclude && g_pattern_match_string (pv->exclude, filename))
			continue;
			
		loc = gkr_location_from_child (dirloc, filename);
		g_assert (loc);

		/* If we hadn't yet seen this, then add it */
		key = GUINT_TO_POINTER (loc);
		if (!g_hash_table_remove (checks, key)) {
			
			/* Get the last modified time for this one */
			file = gkr_location_to_path (loc);
			g_assert (file);
			ret = g_stat (file, &sb);
			lasterr = errno;
			
			/* Couldn't access the file */
			if (ret < 0) {
				g_message ("couldn't stat file: %s: %s", file, g_strerror (lasterr));
				g_free (file);
				continue;
			}
			
			g_free (file);
			
			/* We don't do directories */
			if (sb.st_mode & S_IFDIR)
				continue;

			g_hash_table_replace (pv->locations, key, key);				
			gkr_location_manager_note_mtime (watch->manager, loc, sb.st_mtime);
			g_signal_emit (watch, signals[LOCATION_ADDED], 0, loc);
			
		/* Otherwise we already had it, see if it needs updating */
		} else {
			update_location (watch, force_all, loc);
		}
	}

	g_dir_close (dir);
	g_free (path);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_location_watch_init (GkrLocationWatch *obj)
{
	GkrLocationWatchPrivate *pv = GKR_LOCATION_WATCH_GET_PRIVATE (obj);
	pv->locations = g_hash_table_new (g_direct_hash, g_direct_equal);
}

static void
gkr_location_watch_dispose (GObject *obj)
{
	GkrLocationWatch *watch = GKR_LOCATION_WATCH (obj);

	if (watch->manager)
		g_object_unref (watch->manager);
	watch->manager = NULL;	 
	
	G_OBJECT_CLASS (gkr_location_watch_parent_class)->dispose (obj);
}

static void
gkr_location_watch_finalize (GObject *obj)
{
	GkrLocationWatch *watch = GKR_LOCATION_WATCH (obj);
	GkrLocationWatchPrivate *pv = GKR_LOCATION_WATCH_GET_PRIVATE (watch);
	 
	if (pv->include)
		g_pattern_spec_free (pv->include);
	if (pv->exclude)
		g_pattern_spec_free (pv->exclude);
	g_free (pv->subdir);
	
	g_hash_table_destroy (pv->locations);
	
	G_OBJECT_CLASS (gkr_location_watch_parent_class)->finalize (obj);
}

static void
gkr_location_watch_class_init (GkrLocationWatchClass *klass)
{
	GObjectClass *gobject_class;
	gobject_class = (GObjectClass*) klass;

	gkr_location_watch_parent_class = g_type_class_peek_parent (klass);
	gobject_class->dispose = gkr_location_watch_dispose;
	gobject_class->finalize = gkr_location_watch_finalize;

	g_type_class_add_private (gobject_class, sizeof (GkrLocationWatchPrivate));

	signals[LOCATION_ADDED] = g_signal_new ("location-added", GKR_TYPE_LOCATION_WATCH, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrLocationWatchClass, location_added),
			NULL, NULL, g_cclosure_marshal_VOID__UINT, 
			G_TYPE_NONE, 1, G_TYPE_UINT);
			
	signals[LOCATION_CHANGED] = g_signal_new ("location-changed", GKR_TYPE_LOCATION_WATCH, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrLocationWatchClass, location_changed),
			NULL, NULL, g_cclosure_marshal_VOID__UINT, 
			G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[LOCATION_REMOVED] = g_signal_new ("location-removed", GKR_TYPE_LOCATION_WATCH, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrLocationWatchClass, location_removed),
			NULL, NULL, g_cclosure_marshal_VOID__UINT, 
			G_TYPE_NONE, 1, G_TYPE_UINT);
}

GkrLocationWatch* 
gkr_location_watch_new (GkrLocationManager *locmgr, GQuark only_volume, 
                        const gchar *subdir, const gchar *include, const gchar *exclude)
{
	GkrLocationWatch *watch = g_object_new (GKR_TYPE_LOCATION_WATCH, NULL);
	GkrLocationWatchPrivate *pv = GKR_LOCATION_WATCH_GET_PRIVATE (watch);
	
	if (!locmgr)
		locmgr = gkr_location_manager_get ();
		
	g_return_val_if_fail (GKR_IS_LOCATION_MANAGER (locmgr), NULL);
		
	/* TODO: Use properties */	
	pv->include = include ? g_pattern_spec_new (include) : NULL;
	pv->exclude = exclude ? g_pattern_spec_new (exclude) : NULL;
	pv->subdir = g_strdup (subdir);
	pv->only_volume = only_volume;
	
	watch->manager = locmgr;
	g_object_ref (locmgr);
	
	return watch;
}

void
gkr_location_watch_refresh (GkrLocationWatch *watch, gboolean force_all)
{
	GkrLocationWatchPrivate *pv = GKR_LOCATION_WATCH_GET_PRIVATE (watch);
	GHashTable *checks;
	GSList *l, *volumes;
	GQuark volume;
	
	g_return_if_fail (GKR_IS_LOCATION_WATCH (watch));
	
	/* Copy into our check set */
	checks = g_hash_table_new (g_direct_hash, g_direct_equal);
	g_hash_table_foreach (pv->locations, copy_key_value, checks);
	
	/* If only one volume, then just try and access it directly */
	if (pv->only_volume) {
		if (gkr_location_manager_has_volume (watch->manager, pv->only_volume))
			update_volume (watch, pv->only_volume, force_all, checks);
		
	/* Go through each base location and update */
	} else {
		volumes = gkr_location_manager_get_volumes (watch->manager);
		for (l = volumes; l; l = g_slist_next (l)) {
			volume = GPOINTER_TO_UINT (l->data);
			update_volume (watch, volume, force_all, checks);
		}
	}
	
	/* Find any keyrings whose paths we didn't see */
	g_hash_table_foreach (checks, remove_locations, watch); 
	g_hash_table_destroy (checks);
}
