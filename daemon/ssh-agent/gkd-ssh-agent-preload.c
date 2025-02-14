/*
 * gnome-keyring
 *
 * Copyright (C) 2014 Stef Walter
 * Copyright (C) 2018 Red Hat, Inc.
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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Stef Walter <stef@thewalter.net>, Daiki Ueno
 */

#include "config.h"

#include "gkd-ssh-agent-preload.h"
#include "gkd-ssh-agent-util.h"

#include "egg/egg-file-tracker.h"
#include <string.h>

enum {
	PROP_0,
	PROP_PATH
};

struct _GkdSshAgentPreload
{
	GObject object;

	gchar *path;
	GHashTable *keys_by_public_filename;
	GHashTable *keys_by_public_key;
	EggFileTracker *file_tracker;
	GMutex lock;
};

G_DEFINE_TYPE (GkdSshAgentPreload, gkd_ssh_agent_preload, G_TYPE_OBJECT);

void
gkd_ssh_agent_key_info_free (gpointer boxed)
{
	GkdSshAgentKeyInfo *info = boxed;
	if (!info)
		return;
	g_bytes_unref (info->public_key);
	g_free (info->comment);
	g_free (info->filename);
	g_free (info);
}

gpointer
gkd_ssh_agent_key_info_copy (gpointer boxed)
{
	GkdSshAgentKeyInfo *info = boxed;
	GkdSshAgentKeyInfo *copy = g_new0 (GkdSshAgentKeyInfo, 1);
	copy->public_key = g_bytes_ref (info->public_key);
	copy->comment = g_strdup (info->comment);
	copy->filename = g_strdup (info->filename);
	return copy;
}

static void file_load_inlock   (EggFileTracker *tracker,
                                const gchar *path,
                                gpointer user_data);
static void file_remove_inlock (EggFileTracker *tracker,
                                const gchar *path,
                                gpointer user_data);

static void
gkd_ssh_agent_preload_init (GkdSshAgentPreload *self)
{
	g_mutex_init (&self->lock);
	self->keys_by_public_filename = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	self->keys_by_public_key = g_hash_table_new_full (g_bytes_hash, g_bytes_equal, NULL, gkd_ssh_agent_key_info_free);
}

static void
gkd_ssh_agent_preload_constructed (GObject *object)
{
	GkdSshAgentPreload *self = GKD_SSH_AGENT_PRELOAD (object);

	self->file_tracker = egg_file_tracker_new (self->path, "*.pub", NULL);
	g_signal_connect (self->file_tracker, "file-added", G_CALLBACK (file_load_inlock), self);
	g_signal_connect (self->file_tracker, "file-removed", G_CALLBACK (file_remove_inlock), self);
	g_signal_connect (self->file_tracker, "file-changed", G_CALLBACK (file_load_inlock), self);

	G_OBJECT_CLASS (gkd_ssh_agent_preload_parent_class)->constructed (object);
}

static void
gkd_ssh_agent_preload_set_property (GObject *object,
                                    guint prop_id,
                                    const GValue *value,
                                    GParamSpec *pspec)
{
	GkdSshAgentPreload *self = GKD_SSH_AGENT_PRELOAD (object);

	switch (prop_id) {
	case PROP_PATH:
		self->path = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gkd_ssh_agent_preload_finalize (GObject *object)
{
	GkdSshAgentPreload *self = GKD_SSH_AGENT_PRELOAD (object);

	g_free (self->path);
	g_clear_pointer (&self->keys_by_public_key, g_hash_table_unref);
	g_clear_pointer (&self->keys_by_public_filename, g_hash_table_unref);
	g_clear_object (&self->file_tracker);

	g_mutex_clear (&self->lock);

	G_OBJECT_CLASS (gkd_ssh_agent_preload_parent_class)->finalize (object);
}

static void
gkd_ssh_agent_preload_class_init (GkdSshAgentPreloadClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->constructed = gkd_ssh_agent_preload_constructed;
	gobject_class->set_property = gkd_ssh_agent_preload_set_property;
	gobject_class->finalize = gkd_ssh_agent_preload_finalize;
	g_object_class_install_property (gobject_class, PROP_PATH,
		 g_param_spec_string ("path", "Path", "Path",
				      "",
				      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
}

static gchar *
private_path_for_public (const gchar *public_path)
{
	if (g_str_has_suffix (public_path, ".pub"))
		return g_strndup (public_path, strlen (public_path) - 4);

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
	GkdSshAgentPreload *self = GKD_SSH_AGENT_PRELOAD (user_data);
	GkdSshAgentKeyInfo *info;

	info = g_hash_table_lookup (self->keys_by_public_filename, path);
	if (info) {
		g_hash_table_remove (self->keys_by_public_filename, path);
		g_hash_table_remove (self->keys_by_public_key, info->public_key);
	}
}

static void
file_load_inlock (EggFileTracker *tracker,
                  const gchar *path,
                  gpointer user_data)
{
	GkdSshAgentPreload *self = GKD_SSH_AGENT_PRELOAD (user_data);
	gchar *private_path;
	GBytes *private_bytes;
	GBytes *public_bytes;
	GBytes *public_key;
	GkdSshAgentKeyInfo *info;
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
		public_key = _gkd_ssh_agent_parse_public_key (public_bytes, &comment);
		if (public_key) {
			info = g_new0 (GkdSshAgentKeyInfo, 1);
			info->filename = private_path;
			private_path = NULL;
			info->public_key = public_key;
			info->comment = comment;
			g_hash_table_replace (self->keys_by_public_filename, g_strdup (path), info);
			g_hash_table_replace (self->keys_by_public_key, info->public_key, info);
		} else {
			g_message ("failed to parse ssh public key: %s", path);
		}

		g_bytes_unref (public_bytes);
	}

	g_bytes_unref (private_bytes);
	g_free (private_path);
}

GkdSshAgentPreload *
gkd_ssh_agent_preload_new (const gchar *path)
{
	g_return_val_if_fail (path, NULL);

	return g_object_new (GKD_TYPE_SSH_AGENT_PRELOAD, "path", path, NULL);
}

GList *
gkd_ssh_agent_preload_get_keys (GkdSshAgentPreload *self)
{
	GList *keys = NULL;
	GHashTableIter iter;
	GkdSshAgentKeyInfo *info;

	g_mutex_lock (&self->lock);

	egg_file_tracker_refresh (self->file_tracker, FALSE);

	g_hash_table_iter_init (&iter, self->keys_by_public_key);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *)&info))
		keys = g_list_prepend (keys, gkd_ssh_agent_key_info_copy (info));

	g_mutex_unlock (&self->lock);

	return keys;
}

GkdSshAgentKeyInfo *
gkd_ssh_agent_preload_lookup_by_public_key (GkdSshAgentPreload *self,
					    GBytes *public_key)
{
	GkdSshAgentKeyInfo *info;

	g_mutex_lock (&self->lock);

	egg_file_tracker_refresh (self->file_tracker, FALSE);

	info = g_hash_table_lookup (self->keys_by_public_key, public_key);
	if (info)
		info = gkd_ssh_agent_key_info_copy (info);

	g_mutex_unlock (&self->lock);

	return info;
}
