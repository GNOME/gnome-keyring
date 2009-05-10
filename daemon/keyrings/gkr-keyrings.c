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

#include "egg/egg-cleanup.h"

#include "library/gnome-keyring-proto.h"

#include "util/gkr-location.h"
#include "util/gkr-location-watch.h"

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
#include <strings.h>

#define LOC_DEFAULT_FILE    (gkr_location_from_string ("LOCAL:/keyrings/default"))

static gboolean keyrings_inited = FALSE;
static gboolean keyrings_loaded = FALSE;

static GList *keyrings = NULL;

static GkrKeyring *session_keyring = NULL;
static gchar *default_keyring = NULL;

static GkrLocationWatch *location_watch = NULL;

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

static void
update_default (void)
{
	gchar *contents;

	if (gkr_location_read_file (LOC_DEFAULT_FILE, (guchar**)&contents, NULL, NULL)) {
		g_strstrip (contents);
		if (!contents[0]) {
			g_free (contents);
			contents = NULL;
		}
		g_free (default_keyring);
		default_keyring = contents;
	}
}

static void
load_keyring (GkrLocationWatch *watch, GQuark loc, gpointer unused)
{
	GkrKeyring *keyring;
	gboolean updated = FALSE;
	GList *l;
	
	/* Still need to check for file updates */
	for (l = keyrings; l != NULL; l = l->next) { 
		keyring = GKR_KEYRING (l->data);
		if (keyring->location && keyring->location == loc) {
			gkr_keyring_update_from_disk (keyring);
			updated = TRUE;
		}
	}
	
	if (updated)
		return;
		
	/* Make a new blank keyring and add it */
	keyring = gkr_keyring_new ("", loc);
	gkr_keyrings_add (keyring);
	g_object_unref (keyring);

	/* Try and update/load it */
	if (!gkr_keyring_update_from_disk (keyring) ||
	    !keyring->keyring_name || !keyring->keyring_name[0]) 
		gkr_keyrings_remove (keyring);
}

static void
remove_keyring (GkrLocationWatch *watch, GQuark loc, gpointer unused)
{
	GkrKeyring *keyring;
	GList *l;
	
	g_return_if_fail (loc);
	
	/* Find the keyring that dissappeared, and remove it from our list */
	for (l = keyrings; l; l = g_list_next (l)) {
		keyring = GKR_KEYRING (l->data);
		if (keyring->location && keyring->location == loc)
			gkr_keyrings_remove (keyring);
	}	
}

static void 
keyrings_cleanup (gpointer unused)
{
	GkrKeyring *keyring;
	
	g_assert (keyrings_inited);
	
	g_assert (location_watch);
	g_object_unref (location_watch);
	location_watch = NULL;
	
	while (keyrings) {
		keyring = GKR_KEYRING (keyrings->data);
		if (keyring == session_keyring)
			session_keyring = NULL;
		keyrings = g_list_remove (keyrings, keyring);
		g_object_unref (keyring);
	}
	
	g_free (default_keyring);
	default_keyring = NULL;
	
	g_assert (session_keyring == NULL);
	keyrings_inited = FALSE;
}

static void
keyrings_init (void)
{
	GQuark loc;
	gchar *path;
	
	if (keyrings_inited)
		return;
	keyrings_inited = TRUE;
	
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
	g_object_unref (session_keyring);
	
	g_assert (!location_watch);
	location_watch = gkr_location_watch_new (NULL, 0, "keyrings", "*.keyring", NULL);
	g_signal_connect (location_watch, "location-added", G_CALLBACK (load_keyring), NULL);
	g_signal_connect (location_watch, "location-changed", G_CALLBACK (load_keyring), NULL);
	g_signal_connect (location_watch, "location-removed", G_CALLBACK (remove_keyring), NULL);
	
	egg_cleanup_register (keyrings_cleanup, NULL);
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
	keyrings_init ();
	gkr_location_watch_refresh (location_watch, FALSE);
	update_default ();
	keyrings_loaded = TRUE;
}

void 
gkr_keyrings_add (GkrKeyring *keyring)
{
	GList *l;
	
	keyrings_init ();
	
	g_assert (GKR_IS_KEYRING (keyring));
	
	/* Can't add the same keyring twice */
	g_assert (g_list_find (keyrings, keyring) == NULL);
	
	/* Can't add two keyrings for the same location */
	for (l = keyrings; l; l = g_list_next (l)) { 
		if (((GkrKeyring*)l->data)->location == keyring->location) {
			g_warning ("two keyrings added for the same location: %s",
			           gkr_location_to_string (keyring->location));
		}
	}
	
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
	
	if (!keyrings_loaded)
		gkr_keyrings_update ();

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

GkrKeyring*
gkr_keyrings_for_location (GQuark location)
{
	GkrKeyring *keyring;
	GList *l;
	
	keyrings_init ();

	for (l = keyrings; l != NULL; l = l->next) {
		keyring = GKR_KEYRING (l->data);
		if (keyring->location == location)
			return keyring;
	}

	/* Try and load the keyring */
	if (gkr_location_test_file (location, G_FILE_TEST_IS_REGULAR)) {
		keyring = gkr_keyring_new ("", location);
		if (gkr_keyring_update_from_disk (keyring)) {
			gkr_keyrings_add (keyring);
			g_object_unref (keyring);
			return keyring;
		} 
		
		g_object_unref (keyring);
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
