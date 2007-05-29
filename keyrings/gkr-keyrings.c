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


static GList *keyrings = NULL;

static GkrKeyring *session_keyring = NULL;
static GkrKeyring *default_keyring = NULL;

static time_t keyring_dir_mtime = 0;

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
	char *dirname, *path, *newline;
	char *contents;
	GkrKeyring *keyring;
	
	dirname = gkr_keyrings_get_dir ();
	path = g_build_filename (dirname, "default", NULL);

	keyring = NULL;
	
	if (g_file_get_contents (path,
				 &contents, NULL, NULL)) {
		/* remove any final newlines */
		newline = strchr (contents, '\n');
		if (newline != NULL) {
			*newline = 0;
		}

		keyring = gkr_keyrings_find (contents);
		
		g_free (contents);
	}
	
	g_free (path);
	g_free (dirname);

	if (keyring == NULL)
		keyring = gkr_keyrings_find ("default");
	
	default_keyring = keyring;
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

gchar*
gkr_keyrings_get_dir (void)
{
	char *dir, *gnome2_dir;
	
	dir = g_build_filename (g_get_home_dir (), ".gnome2/keyrings", NULL);
	if (!g_file_test (dir, G_FILE_TEST_IS_DIR)) {
		gnome2_dir = g_build_filename (g_get_home_dir (), ".gnome2", NULL);
		if (!g_file_test (gnome2_dir, G_FILE_TEST_IS_DIR)) {
			mkdir (gnome2_dir, S_IRWXU);
		}
		g_free (gnome2_dir);
		
		if (mkdir (dir, S_IRWXU) < 0) {
			g_warning ("unable to create keyring dir");
		}
	}
	return dir;
}

GkrKeyring*
gkr_keyrings_get_default (void)
{
	if (!default_keyring)
		update_default ();
	return default_keyring;
}

void
gkr_keyrings_set_default (GkrKeyring *keyring)
{
	char *dirname, *path;
	int fd;
	
	dirname = gkr_keyrings_get_dir ();
	path = g_build_filename (dirname, "default", NULL);
	
	fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd != -1) {
		if (keyring != NULL && keyring->keyring_name != NULL) {
			write_all (fd, keyring->keyring_name,
			           strlen (keyring->keyring_name));
#ifdef HAVE_FSYNC
			fsync (fd);
#endif
		}
		close (fd);
	}
	
	g_free (path);
	g_free (dirname);

	default_keyring = keyring;
}

void
gkr_keyrings_update (void)
{
	char *dirname, *path;
	const char *filename;
	struct stat statbuf;
	GDir *dir;
	GList *l;
	GkrKeyring *keyring;
	GHashTable *checks = NULL;
	
	dirname = gkr_keyrings_get_dir ();

	if (stat (dirname, &statbuf) < 0) {
		g_free (dirname);
		return;
	}
	if (statbuf.st_mtime == keyring_dir_mtime) {
		/* Still need to check for file updates */

		for (l = keyrings; l != NULL; l = l->next) {
			gkr_keyring_update_from_disk (l->data, FALSE);
		}
		
		update_default ();
		
		return;
	}

	/* 
	 * A hash table for tracking which loaded keyrings no longer 
	 * exist. A keyring that has the same file is considered 
	 * identical. Keyrings without files aren't considered. 
	 */
	checks = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	for (l = keyrings; l; l = g_list_next (l)) {
		keyring = GKR_KEYRING (l->data);
		if (keyring->file) {
			g_hash_table_insert (checks, g_strdup (keyring->file), 
			                     keyring);
		}
	}
	
	dir = g_dir_open (dirname, 0, NULL);
	if (dir != NULL) {
		while ((filename = g_dir_read_name (dir)) != NULL) {
			if (filename[0] == '.') {
				continue;
			}
			if (strcmp (filename, "default") == 0) {
				continue;
			}
			path = g_build_filename (dirname, filename, NULL);
			keyring = NULL;
			
			keyring = g_hash_table_lookup (checks, path);
			if (keyring == NULL) {
				/* Make a new blank keyring and add it */
				keyring = gkr_keyring_new (NULL, path);
				gkr_keyrings_add (keyring);
				g_object_unref (keyring);
			} else {
				/* Make note of seeing a given keyring path */
				g_hash_table_remove (checks, path);
			}

			/* Try and update/load it */
			if (!gkr_keyring_update_from_disk (keyring, FALSE) ||
			    keyring->keyring_name == NULL) {
				gkr_keyrings_remove (keyring);
			} 
			
			g_free (path);
		}
		g_dir_close (dir);
	}
	
	/* Find any keyrings whose paths we didn't see */
	for (l = keyrings; l; l = g_list_next (l)) {
		keyring = GKR_KEYRING (l->data);
		if (!keyring->file)
			continue;
		if (g_hash_table_lookup (checks, keyring->file))
			gkr_keyrings_remove (keyring);
	}
	g_hash_table_destroy (checks);

	update_default ();
	
	keyring_dir_mtime = statbuf.st_mtime;

	g_free (dirname);
}


void 
gkr_keyrings_add (GkrKeyring *keyring)
{
	g_assert (GKR_IS_KEYRING (keyring));
	
	/* Can't add the same keyring twice */
	g_assert (g_list_find (keyrings, keyring) == NULL);
	
	keyrings = g_list_prepend (keyrings, keyring);
	g_object_ref (keyring);
}

void 
gkr_keyrings_remove (GkrKeyring *keyring)
{
	g_assert (GKR_IS_KEYRING (keyring));
	
	if (g_list_find (keyrings, keyring)) {

		if (keyring == default_keyring)
			gkr_keyrings_set_default (NULL);
		
		keyrings = g_list_remove (keyrings, keyring);

		g_object_unref (keyring);
	}
}

GkrKeyring*
gkr_keyrings_get_session (void)
{
	g_assert (session_keyring);
	return session_keyring;
}

GkrKeyring*
gkr_keyrings_find (const gchar *name)
{
	GkrKeyring *keyring;
	GList *l;

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
	
	for (l = keyrings; l != NULL; l = l->next) {
		if (!(func) (GKR_KEYRING (l->data), data))
			return FALSE;
	}
	
	return TRUE;
}

guint
gkr_keyrings_get_count (void)
{
	return g_list_length (keyrings);
}

void
gkr_keyrings_init (void)
{
	g_assert (!session_keyring);
	session_keyring = gkr_keyring_new ("session", NULL);
	gkr_keyrings_add (session_keyring);
	
	gkr_keyrings_update ();
}

void 
gkr_keyrings_cleanup (void)
{
	GkrKeyring *keyring;
	
	while (keyrings) {
		keyring = GKR_KEYRING (keyrings->data);
		if (keyring == session_keyring)
			session_keyring = NULL;
		gkr_keyrings_remove (keyring);
	}
	
	g_assert (session_keyring == NULL);
}
