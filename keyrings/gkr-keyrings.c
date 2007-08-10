/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyrings.c - the global list of keyrings

   Copyright (C) 2003 Red Hat, Inc
   Copyright (C) 2007 Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Alexander Larsson <alexl@redhat.com>
   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-keyrings.h"

#include "common/gkr-cleanup.h"
#include "common/gkr-location.h"

#include "library/gnome-keyring-proto.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <glib.h>

#define LOC_DEFAULT_FILE    (gkr_location_from_string ("LOCAL:/keyrings/default"))

static gboolean keyrings_inited = FALSE;

static GList *keyrings = NULL;

static GkrKeyring *session_keyring = NULL;
static gchar *default_keyring = NULL;

typedef struct _LocationInfo {
	GQuark keyring_loc;
	time_t dir_mtime;
} LocationInfo;

static GHashTable *keyring_locations = NULL;

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static int
write_all (int fd, const char *buf, size_t len)
{
	size_t bytes;
	int res;

	bytes = 0;
	while (bytes < len) {
		res = write (fd, buf + bytes, len - bytes);
		if (res < 0) {
			if (errno != EINTR &&
			    errno != EAGAIN) {
				perror ("write_all write failure:");
				return -1;
			}
		} else {
			bytes += res;
		}
	}
	return 0;
}

static gboolean
ends_with (const gchar *haystack, const gchar *needle)
{
	gsize lhaystack = strlen (haystack);
	gsize lneedle = strlen (needle);
	if (lneedle > lhaystack)
		return FALSE;
	return strcmp (haystack + (lhaystack - lneedle), needle) == 0;
}

static void
location_free (LocationInfo *info)
{
	g_slice_free (LocationInfo, info);
}

static void 
location_added (GkrLocationManager *locmgr, GQuark loc, gpointer unused)
{
	LocationInfo *info;
	GQuark keyring_loc;
	gchar *path;

	g_return_if_fail (keyring_locations);
	
	keyring_loc = gkr_location_from_child (loc, "keyrings");
	path = gkr_location_to_path (keyring_loc);
	
	if (g_file_test (path, G_FILE_TEST_IS_DIR)) {
		info = g_slice_new0 (LocationInfo);
		info->keyring_loc = keyring_loc;
		info->dir_mtime = 0;
		g_hash_table_replace (keyring_locations, GUINT_TO_POINTER (loc), info);
	}
	
	g_free (path);
}

static void
location_removed (GkrLocationManager *locmgr, GQuark loc, gpointer unused)
{
	g_return_if_fail (keyring_locations);
	g_hash_table_remove (keyring_locations, GUINT_TO_POINTER (loc));
}

static void
update_default (void)
{
	gchar *path;
	gchar *contents;

	path = gkr_location_to_path (LOC_DEFAULT_FILE);
	if (g_file_get_contents (path, &contents, NULL, NULL)) {
		g_strstrip (contents);
		if (!contents[0]) {
			g_free (contents);
			contents = NULL;
		}
		g_free (default_keyring);
		default_keyring = contents;
	}
	
	g_free (path);
}

static gboolean
update_keyring_location (gpointer key, LocationInfo *locinfo, GHashTable *checks)
{
	char *dirname;
	const char *filename;
	struct stat statbuf;
	GDir *dir;
	GList *l;
	GQuark loc;
	GError *error = NULL;
	GkrKeyring *keyring;
	
	dirname = gkr_location_to_path (locinfo->keyring_loc);
	
	/* Can't resolve the location? Remove it. */
	if (!dirname)
		return TRUE;

	if (stat (dirname, &statbuf) < 0) {
		g_free (dirname);
		
		/* If it doesn't yet exist, then keep checking */
		if (errno == ENOENT || errno == ENOTDIR)
			return FALSE;
		
		/* Otherwise, some other error, remove from list */
		return TRUE;
	}
	
	if (statbuf.st_mtime == locinfo->dir_mtime) {

		/* Still need to check for file updates */
		for (l = keyrings; l != NULL; l = l->next) { 
			keyring = GKR_KEYRING (l->data);
			if (!gkr_location_is_descendant (locinfo->keyring_loc, keyring->location))
				continue;
			gkr_keyring_update_from_disk (keyring, FALSE);
			
			/* Make note of seeing a given keyring path */
			g_hash_table_remove (checks, GUINT_TO_POINTER (keyring->location));
		}

		g_free (dirname);		

		/* Don't remove this location */
		return FALSE;
	}

	/* Make note of the last modification time */
	locinfo->dir_mtime = statbuf.st_mtime;

	dir = g_dir_open (dirname, 0, &error);
	
	if (dir == NULL) {
		g_message ("couldn't list keyrings at: %s: %s",
		           dirname, error->message);
		g_error_free (error);  
		g_free (dirname);
		
		/* Remove this location from the list */
		return TRUE;
	}
		
	while ((filename = g_dir_read_name (dir)) != NULL) {
		if (filename[0] == '.')
			continue;
		if (!ends_with (filename, ".keyring"))
			continue;

		loc = gkr_location_from_child (locinfo->keyring_loc, filename);
		g_assert (loc);
		
		keyring = g_hash_table_lookup (checks, GUINT_TO_POINTER (loc));
		if (keyring == NULL) {
			/* Make a new blank keyring and add it */
			keyring = gkr_keyring_new ("", loc);
			gkr_keyrings_add (keyring);
			g_object_unref (keyring);
		} else {
			/* Make note of seeing a given keyring path */
			g_hash_table_remove (checks, GUINT_TO_POINTER (loc));
		}

		/* Try and update/load it */
		if (!gkr_keyring_update_from_disk (keyring, FALSE) ||
		    !keyring->keyring_name || !keyring->keyring_name[0]) {
			gkr_keyrings_remove (keyring);
		} 
	}

	g_dir_close (dir);
	g_free (dirname);
	
	/* Don't remove location */
	return FALSE;
}

static void 
keyrings_cleanup (gpointer unused)
{
	GkrKeyring *keyring;
	
	g_assert (keyrings_inited);
	
	while (keyrings) {
		keyring = GKR_KEYRING (keyrings->data);
		if (keyring == session_keyring)
			session_keyring = NULL;
		gkr_keyrings_remove (keyring);
	}
	
	g_free (default_keyring);
	default_keyring = NULL;
	
	g_assert (session_keyring == NULL);
	keyrings_inited = FALSE;
}

static void
keyrings_init (void)
{
	GkrLocationManager *locmgr;
	GSList *locations, *l;
	GQuark loc;
	gchar *path;
	
	if (keyrings_inited)
		return;
	keyrings_inited = TRUE;
	
	g_assert (!keyring_locations);
	keyring_locations = g_hash_table_new_full (g_direct_hash, g_direct_equal, 
	                                           NULL, (GDestroyNotify)location_free); 

	/* Make the local keyrings directory */
	loc = gkr_location_from_string ("LOCAL:/keyrings");
	g_assert (loc);
	path = gkr_location_to_path (loc);
	if (g_mkdir_with_parents (path, S_IRWXU) < 0)
		g_warning ("unable to create keyring dir");
	g_free (path);

	/* Create the session keyring */
	g_assert (!session_keyring);
	session_keyring = gkr_keyring_new ("session", 0);
	gkr_keyrings_add (session_keyring);
	
	/* 
	 * Hook into all the loaded locations, and watch for more 
	 * added and/or removed.
	 */
	locmgr = gkr_location_manager_get ();
	g_signal_connect (locmgr, "location-added", G_CALLBACK (location_added), NULL);
	g_signal_connect (locmgr, "location-removed", G_CALLBACK (location_removed), NULL);
	locations = gkr_location_manager_get_base_locations (locmgr);
	for (l = locations; l; l = g_slist_next (l))
		location_added (locmgr, GPOINTER_TO_UINT (l->data), NULL);
	g_slist_free (locations);
	
	gkr_keyrings_update ();
	
	gkr_cleanup_register (keyrings_cleanup, NULL);	
}


/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GkrKeyring*
gkr_keyrings_get_default (void)
{
	GkrKeyring *keyring = NULL;
	
	keyrings_init ();
	if (!default_keyring)
		update_default ();
		
	if (default_keyring != NULL)
		keyring = gkr_keyrings_find (default_keyring);
		
	/* 
	 * We prefer to make the 'login' keyring the default
	 * keyring when nothing else is setup.
	 */
	if (keyring == NULL)
		keyring = gkr_keyrings_get_login ();
		
	/* 
	 * Otherwise fall back to the 'default' keyring setup 
	 * if PAM integration is borked, and the user had to 
	 * create a new keyring.
	 */
	if (keyring == NULL)
		keyring = gkr_keyrings_find ("default");

	return keyring;
}

void
gkr_keyrings_set_default (GkrKeyring *keyring)
{
	char *path;
	const gchar *data;
	int fd;
	
	keyrings_init ();
	
	path = gkr_location_to_path (LOC_DEFAULT_FILE);
	fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd != -1) {
		data = (keyring && keyring->keyring_name) ? keyring->keyring_name : "";
		write_all (fd, data, strlen (data));
#ifdef HAVE_FSYNC
		fsync (fd);
#endif
		close (fd);
	}
	
	g_free (path);

	g_free (default_keyring);
	default_keyring = keyring ? g_strdup (keyring->keyring_name) : NULL;
}

GkrKeyring*
gkr_keyrings_get_login (void)
{
	return gkr_keyrings_find ("login");
}

void
gkr_keyrings_update (void)
{
	GList *l;
	GkrKeyring *keyring;
	GHashTable *checks = NULL;
	
	keyrings_init ();
	
	/* 
	 * A hash table for tracking which loaded keyrings no longer 
	 * exist. A keyring that has the same file is considered 
	 * identical. Keyrings without files aren't considered. 
	 */
	checks = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, NULL);
	for (l = keyrings; l; l = g_list_next (l)) {
		keyring = GKR_KEYRING (l->data);
		if (!keyring->location)
			continue;
		g_hash_table_insert (checks, GUINT_TO_POINTER (keyring->location), keyring);
	}
	
	/* Update each and every one */
	g_hash_table_foreach_remove (keyring_locations, (GHRFunc)update_keyring_location, checks);
	
	/* Find any keyrings whose paths we didn't see */
	for (l = keyrings; l; l = g_list_next (l)) {
		keyring = GKR_KEYRING (l->data);
		if (!keyring->location)
			continue;
		if (g_hash_table_lookup (checks, GUINT_TO_POINTER (keyring->location)))
			gkr_keyrings_remove (keyring);
	}
	g_hash_table_destroy (checks);

	update_default ();
}


void 
gkr_keyrings_add (GkrKeyring *keyring)
{
	keyrings_init ();
	
	g_assert (GKR_IS_KEYRING (keyring));
	
	/* Can't add the same keyring twice */
	g_assert (g_list_find (keyrings, keyring) == NULL);
	
	keyrings = g_list_prepend (keyrings, keyring);
	g_object_ref (keyring);
}

void 
gkr_keyrings_remove (GkrKeyring *keyring)
{
	keyrings_init ();
	
	g_assert (GKR_IS_KEYRING (keyring));
	
	if (g_list_find (keyrings, keyring)) {

		if (default_keyring && 
		    strcmp (keyring->keyring_name, default_keyring) == 0)
			gkr_keyrings_set_default (NULL);
		
		keyrings = g_list_remove (keyrings, keyring);

		g_object_unref (keyring);
	}
}

GkrKeyring*
gkr_keyrings_get_session (void)
{
	keyrings_init ();
	g_assert (session_keyring);
	return session_keyring;
}

GkrKeyring*
gkr_keyrings_find (const gchar *name)
{
	GkrKeyring *keyring;
	GList *l;
	
	keyrings_init ();

	if (name == NULL)
		return gkr_keyrings_get_default ();

	for (l = keyrings; l != NULL; l = l->next) {
		keyring = GKR_KEYRING (l->data);
		if (strcmp (keyring->keyring_name, name) == 0) {
			return keyring;
		}
	}
	
	return NULL;
}

gboolean 
gkr_keyrings_foreach (GkrKeyringEnumFunc func, gpointer data)
{
	GList *l;
	
	keyrings_init ();
	
	for (l = keyrings; l != NULL; l = l->next) {
		if (!(func) (GKR_KEYRING (l->data), data))
			return FALSE;
	}
	
	return TRUE;
}

guint
gkr_keyrings_get_count (void)
{
	keyrings_init ();
	return g_list_length (keyrings);
}
