/*
 * Copyright (C) 2014 Stef Walter
 *
 * Gnome keyring is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * Gnome keyring is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"

#include "gkd-ssh-agent-preload.h"
#include "gkd-ssh-openssh.h"

#include "egg/egg-file-tracker.h"

#include <string.h>

typedef struct {
	gchar *filename;
	GBytes *public_key;
	GBytes *private_file;
	gchar *comment;
} Preload;

static GMutex preload_mutex;
static GHashTable *preloads_by_filename;
static GHashTable *preloads_by_key;
static EggFileTracker *file_tracker;

static void
preload_free (gpointer data)
{
	Preload *preload = data;
	if (preload->private_file)
		g_bytes_unref (preload->private_file);
	g_bytes_unref (preload->public_key);
	g_free (preload->comment);
	g_free (preload->filename);
	g_free (preload);
}

static gchar *
private_path_for_public (const gchar *public_path)
{
	gsize length;

	length = strlen (public_path);
	if (length > 4 && g_str_equal (public_path + (length - 4), ".pub"))
		return g_strndup (public_path, length - 4);

	return NULL;
}

static GBytes *
file_get_contents (const gchar *path,
                   gboolean must_be_present)
{
	GError *error = NULL;
	gchar *contents;
	gsize length;

	if (!g_file_get_contents (path, &contents, &length, &error)) {
		if (must_be_present || error->code != G_FILE_ERROR_NOENT)
			g_message ("couldn't read file: %s: %s", path, error->message);
		g_error_free (error);
		return NULL;
	}

	return g_bytes_new_take (contents, length);
}

static void
file_remove_inlock (EggFileTracker *tracker,
                    const gchar *path,
                    gpointer user_data)
{
	Preload *preload;

	preload = g_hash_table_lookup (preloads_by_filename, path);
	if (preload) {
		g_hash_table_remove (preloads_by_filename, path);
		g_hash_table_remove (preloads_by_key, preload->public_key);
	}
}

static void
file_load_inlock (EggFileTracker *tracker,
                  const gchar *path,
                  gpointer user_data)
{
	gchar *private_path;
	GBytes *private_bytes;
	GBytes *public_bytes;
	GBytes *public_key;
	Preload *preload;
	gchar *comment;

	file_remove_inlock (tracker, path, user_data);

	private_path = private_path_for_public (path);

	private_bytes = file_get_contents (private_path, FALSE);
	if (!private_bytes) {
		g_debug ("no private key present for public key: %s", path);
		g_free (private_path);
		return;
	}

	public_bytes = file_get_contents (path, TRUE);
	if (public_bytes) {
		public_key = gkd_ssh_openssh_parse_public_key (public_bytes, &comment);
		if (public_key) {
			preload = g_new0 (Preload, 1);
			preload->filename = g_strdup (path);
			preload->public_key = public_key;
			preload->comment = comment;
			g_hash_table_replace (preloads_by_filename, preload->filename, preload);
			g_hash_table_replace (preloads_by_key, preload->public_key, preload);
		} else {
			g_message ("failed to parse ssh public key: %s", path);
		}

		g_bytes_unref (public_bytes);
	}

	g_bytes_unref (private_bytes);
	g_free (private_path);
}

static gboolean
preload_lock_and_update (void)
{
	g_mutex_lock (&preload_mutex);

	if (!preloads_by_filename)
		preloads_by_filename = g_hash_table_new (g_str_hash, g_str_equal);

	if (!preloads_by_key)
		preloads_by_key = g_hash_table_new_full (g_bytes_hash, g_bytes_equal, NULL, preload_free);

	if (!file_tracker) {
		file_tracker = egg_file_tracker_new ("~/.ssh", "*.pub", NULL);
		g_signal_connect (file_tracker, "file-added", G_CALLBACK (file_load_inlock), NULL);
		g_signal_connect (file_tracker, "file-removed", G_CALLBACK (file_remove_inlock), NULL);
	}

	egg_file_tracker_refresh (file_tracker, FALSE);

	return TRUE;
}

static void
preload_unlock (void)
{
	g_mutex_unlock (&preload_mutex);
}

GList *
gkd_ssh_agent_preload_keys (void)
{
	GList *keys = NULL;
	GHashTableIter iter;
	Preload *preload;

	preload_lock_and_update ();

	g_hash_table_iter_init (&iter, preloads_by_key);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *)&preload)) {
		if (preload->private_file)
			keys = g_list_prepend (keys, g_bytes_ref (preload->public_key));
	}

	preload_unlock ();

	return keys;
}

gchar *
gkd_ssh_agent_preload_comment (GBytes *key)
{
	gchar *comment = NULL;
	Preload *preload;

	preload_lock_and_update ();

	preload = g_hash_table_lookup (preloads_by_key, key);
	if (preload)
		comment = g_strdup (preload->comment);

	preload_unlock ();

	return comment;
}

gchar *
gkd_ssh_agent_preload_path (GBytes *key)
{
	gchar *path = NULL;
	Preload *preload;

	preload_lock_and_update ();

	preload = g_hash_table_lookup (preloads_by_key, key);
	if (preload)
		path = g_strdup (preload->filename);

	preload_unlock ();

	return path;
}

void
gkd_ssh_agent_preload_clear (GBytes *key)
{
	Preload *preload;

	preload_lock_and_update ();

	preload = g_hash_table_lookup (preloads_by_key, key);
	if (preload) {
		g_bytes_unref (preload->private_file);
		preload->private_file = NULL;
	}

	preload_unlock ();
}

void
gkd_ssh_agent_preload_clear_all (void)
{
	GHashTableIter iter;
	Preload *preload;

	preload_lock_and_update ();

	g_hash_table_iter_init (&iter, preloads_by_key);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *)&preload)) {
		if (preload->private_file) {
			g_bytes_unref (preload->private_file);
			preload->private_file = NULL;
		}
	}

	preload_unlock ();
}

void
gkd_ssh_agent_preload_cleanup (void)
{
	g_mutex_lock (&preload_mutex);

	if (preloads_by_key)
		g_hash_table_destroy (preloads_by_key);
	preloads_by_key = NULL;

	if (preloads_by_filename)
		g_hash_table_destroy (preloads_by_filename);
	preloads_by_filename = NULL;

	if (file_tracker)
		g_object_unref (file_tracker);
	file_tracker = NULL;

	g_mutex_unlock (&preload_mutex);
}
