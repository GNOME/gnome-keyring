/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-index.c - indexes to store values related to pk objects

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

#include "gkr-pk-index.h"

#include "common/gkr-async.h"
#include "common/gkr-cleanup.h"
#include "common/gkr-crypto.h"
#include "common/gkr-location.h"

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_LOCK_TRIES 16

#define GKR_TYPE_PK_INDEX             (gkr_pk_index_get_type())
#define GKR_PK_INDEX(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GKR_TYPE_PK_INDEX, GkrPkIndex))
#define GKR_IS_PK_INDEX(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GKR_TYPE_PK_INDEX))

typedef struct _GkrPkIndex      GkrPkIndex;
typedef struct _GkrPkIndexClass GkrPkIndexClass;

struct _GkrPkIndex {
	 GObject parent;
	 GHashTable *path_by_location;
	 GHashTable *mtime_by_location;
	 GHashTable *file_by_location;
};

struct _GkrPkIndexClass {
	GObjectClass parent_class;
};

static GType gkr_pk_index_get_type (void);
G_DEFINE_TYPE (GkrPkIndex, gkr_pk_index, G_TYPE_OBJECT);

static GkrPkIndex *index_singleton = NULL; 
static GQuark no_location = 0;

/* -----------------------------------------------------------------------------
 * HELPERS
 */
 
static void 
free_mtime (gpointer v)
{
	g_slice_free (time_t, v);
}

static gpointer
location_to_key (GQuark loc)
{
	return GUINT_TO_POINTER (loc ? loc : no_location);
}

static GQuark
location_from_key (gpointer key)
{
	GQuark ret = GPOINTER_TO_UINT (key);
	return ret == no_location ? 0 : ret;
}

static const gchar*
index_path_for_location (GkrPkIndex *index, GQuark loc)
{
	gchar *locpath;
	gchar *path;
	
	if (!loc)
		return NULL; 
	
	path = g_hash_table_lookup (index->path_by_location, location_to_key (loc));
	if (!path) {
		locpath = gkr_location_to_path (loc);
		if (!locpath) {
			g_message ("The disk or drive this file is located on is not present: %s",
			           g_quark_to_string (loc));
			return NULL;
		}
		
		/* Our index files have a .gkr extension */
		path = g_strconcat (locpath, ".gkr", NULL);
		g_free (locpath);
		
		g_hash_table_replace (index->path_by_location, location_to_key (loc), path);
	}
	
	return path;
}

static gboolean
check_index_mtime (GkrPkIndex *index, GQuark loc, time_t mtime)
{
	gpointer k;
	gboolean ret = FALSE;
	time_t *last;
	
	k = location_to_key (loc);
	
	/* Check on last mtime */
	last = (time_t*)g_hash_table_lookup (index->mtime_by_location, k);
	ret = !last || (*last != mtime);
	
	/* Setup new mtime */
	if (ret) {
		last = g_slice_new (time_t);
		*last = mtime;
		g_hash_table_replace (index->mtime_by_location, k, last);
	}
	
	return ret;
}

static gchar*
unique_to_group (gkrconstunique uni)
{
	const guchar *unidata;
	gsize n_group, n_unidata;
	gboolean r;
	gchar *group;
		
	unidata = gkr_unique_get_raw (uni, &n_unidata);
	g_assert (unidata);
	n_group = (n_unidata * 2) + 1;
	group = g_malloc0 (n_group);
	
	r = gkr_crypto_hex_encode (unidata, n_unidata, group, &n_group);
	g_assert (r == TRUE);
	
	return group;
}

static gboolean
get_keyfile_value (GKeyFile *key_file, gkrconstunique uni, 
                   const gchar *field, GValue *value)
{
	GError *err = NULL;
	gchar *group;

	g_assert (key_file);
	g_assert (uni);
	g_assert (field);
	g_assert (value);

	/* TODO: Cache this somehow? */
	group = unique_to_group (uni);

	switch (G_VALUE_TYPE (value)) {
	case G_TYPE_BOOLEAN:
		{
			gboolean v = g_key_file_get_boolean (key_file, group, field, &err);
			if (err == NULL)
				g_value_set_boolean (value, v);
		}
		break;
		
	case G_TYPE_INT:
		{
			gint v = g_key_file_get_integer (key_file, group, field, &err);
			if (err == NULL)
				g_value_set_int (value, v);
		}
		break;
		
	case G_TYPE_STRING:
		{
			gchar *v = g_key_file_get_string (key_file, group, field, &err);
			if (v != NULL) {
				g_assert (err == NULL);
				g_value_take_string (value, v);
			}
		}
		break;
		
	default:
		g_assert_not_reached();
		break;
	}
	
	g_free (group);
	
	if (err != NULL) {
		if (err->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND &&
		    err->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
		    	g_warning ("couldn't read field '%s' from index: %s", 
		    	           field, err->message ? err->message : "");
		g_error_free (err);
		return FALSE;
	}
	
	return TRUE;
}

static void
set_keyfile_value (GKeyFile *key_file, gkrconstunique uni, 
                   const gchar *field, const GValue *value,
                   gboolean *updated)
{
	GError *err = NULL;
	gchar *group;
	
	g_assert (key_file);
	g_assert (uni);
	g_assert (field);
	g_assert (value);
	g_assert (updated);
	
	*updated = FALSE;
	
	/* TODO: Cache this somehow? */
	group = unique_to_group (uni);
	
	switch (G_VALUE_TYPE (value)) {
	case G_TYPE_POINTER:
		/* GValue can't be set to NULL, so for us empty pointer means delete */
		g_assert (g_value_get_pointer (value) == NULL);
		if (g_key_file_has_key (key_file, group, field, NULL)) {
			g_key_file_remove_key (key_file, group, field, NULL);
			*updated = TRUE;
		}
		break;
		
	case G_TYPE_BOOLEAN:
		{
			gboolean v = g_value_get_boolean (value);
			if (g_key_file_get_boolean (key_file, group, field, &err) != v || err != NULL) {
				g_key_file_set_boolean (key_file, group, field, v);
				*updated = TRUE;
			}
		}
		break;
		
	case G_TYPE_INT:
		{
			gint v = g_value_get_int (value);
			if (g_key_file_get_integer (key_file, group, field, &err) != v || err != NULL) {
				g_key_file_set_integer (key_file, group, field, v);
				*updated = TRUE;
			}
		}
		break;
	case G_TYPE_STRING:
		{
			const gchar *v = g_value_get_string (value);
			gchar *o = g_key_file_get_value (key_file, group, field, &err);
			
			g_assert (v != NULL);
			if (!o || !g_str_equal (o, v)) {
				g_key_file_set_string (key_file, group, field, v);
				*updated = TRUE;
			}
			
			g_free (o);
		}
		break;
	default:
		g_assert_not_reached();
		break;
	}
	
	if (err)
		g_error_free (err);
	g_free (group);
}	

static GKeyFile*
read_key_file (int fd, GError **err)
{
	GKeyFile *key_file = NULL;
	gchar *contents;
	gboolean res;
	struct stat sb;
		
	g_assert (fd != -1);
	
	if (fstat (fd, &sb) == -1) {
		g_set_error (err, G_FILE_ERROR, g_file_error_from_errno (errno),
		             "failed to get index file size: %s", g_strerror (errno));
		return NULL;		
	}

	/* Empty file, empty key file */
	if (sb.st_size == 0 || sb.st_size > G_MAXSIZE)
		return g_key_file_new ();
				
	contents = (gchar*)mmap (NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!contents) {
		g_set_error (err, G_FILE_ERROR, g_file_error_from_errno (errno),
		             "failed to read (map) index file: %s", g_strerror (errno));
		return NULL;
	}
		
	key_file = g_key_file_new ();
	res = g_key_file_load_from_data (key_file, contents, sb.st_size, G_KEY_FILE_KEEP_COMMENTS, err);
	munmap (contents, sb.st_size);

	if (!res) {	
		g_key_file_free (key_file);
		key_file = NULL;
	}
	
	return key_file;
}
			
static GKeyFile*
load_index_key_file (GkrPkIndex *index, GQuark loc, int fd, gboolean force)
{
	GKeyFile *key_file = NULL;
	const gchar *path;
	gboolean closefd = FALSE;
	GError *err = NULL;
	
	/* If we've never seen it then we should try to read it */
	if (loc && !force && 
	    !g_hash_table_lookup (index->file_by_location, location_to_key (loc)))
		force = TRUE;
		
	/* Read it when necessary and possible */
	if (force) {
		path = index_path_for_location (index, loc);
		if (path) {
			fd = open (path, O_RDONLY, S_IRUSR | S_IWUSR);
			if (fd == -1) {
				if (errno != ENOTDIR && errno != ENOENT) {
					g_message ("couldn't open index file: %s: %s", 
				        	   path, g_strerror (errno));
					return NULL;
				}
			}
			
			closefd = TRUE;
		}

		/* No file on disk, no index */
		if (fd == -1) {
			g_hash_table_remove (index->file_by_location, 
			                     location_to_key (loc));
			                     
		/* Read in the open file */
		} else {
			key_file = read_key_file (fd, &err);
			if (closefd)
				close (fd);
				
			if (!key_file) {
				g_message ("couldn't read index file: %s: %s", path ? path : "", 
				            err && err->message ? err->message : "");
				return NULL;
			}
			
			g_hash_table_replace (index->file_by_location, 
			                      location_to_key (loc), key_file);
		}
	}
	
	key_file = g_hash_table_lookup (index->file_by_location,
	                                location_to_key (loc));

	/* Automatically create an in memory key file for 'no location' */
	if (!key_file && !loc) {
		key_file = g_key_file_new ();
		g_hash_table_replace (index->file_by_location,
		                      location_to_key (loc), key_file);
	}

	if (!key_file) {
		g_message ("no index available for location: %s", 
		           g_quark_to_string (loc));
		return NULL;
	}

	return key_file;
}


static gboolean
read_pk_index_value (GkrPkIndex *index, GQuark loc, gkrconstunique uni, 
                     const gchar *field, GValue *value)
{
	const gchar *path = NULL;
	struct stat sb;
	gboolean force = FALSE;
	GKeyFile *key_file = NULL;

	if (loc) {
		path = index_path_for_location (index, loc);
		if (!path) 
			return FALSE;

		/* TODO: Any way to do this less often? */
		force = (stat (path, &sb) < 0 || check_index_mtime (index, loc, sb.st_mtime));
	}
	
	key_file = load_index_key_file (index, loc, -1, force);
	if (!key_file)
		return FALSE;
	
	if (!get_keyfile_value (key_file, uni, field, value))
		return FALSE;
	
	return TRUE;
}

static gboolean
update_pk_index_value (GkrPkIndex *index, GQuark loc, gkrconstunique uni, 
                       const gchar *field, GValue *value)
{
	const gchar *path = NULL;
	gchar *data = NULL;
	gboolean ret = FALSE;
	gboolean force = FALSE;
	gboolean updated = FALSE;
	GError *err = NULL;
	GKeyFile *key_file = NULL;
	gsize n_data;
	struct stat sb;
	int tries = 0;
	int fd = -1;
	
	if (loc) {
		path = index_path_for_location (index, loc);
		if (!path) 
			return FALSE;
	
		/* File lock retry loop */
		for (;;) {
			if (tries > MAX_LOCK_TRIES) {
				g_message ("couldn't write index '%s' value to file: %s: file is locked", 
			        	   field, path);
				goto done;
			}
			
			fd = open (path, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR);
			if (fd == -1) {
				g_message ("couldn't open index file: %s: %s", path, g_strerror (errno));
				goto done;
			}
			
			if (flock (fd, LOCK_EX | LOCK_NB) < 0) {
				if (errno == EWOULDBLOCK) {
					close (fd);
					fd = -1;
					++tries;
					gkr_async_usleep (200000);
					continue;
				} 
				g_message ("couldn't lock index file: %s: %s", path, g_strerror (errno));
				goto done;
			}
			
			/* Successfully opened file */;
			break;
		}

	
		/* See if file needs updating */
		force = (fstat (fd, &sb) < 0 || check_index_mtime (index, loc, sb.st_mtime));
	}
	
	key_file = load_index_key_file (index, loc, -1, force);
	if (!key_file)
		goto done;

	set_keyfile_value (key_file, uni, field, value, &updated);
	if (updated && loc) {
		
		/* Serialize the key file into memory */
		data = g_key_file_to_data (key_file, &n_data, &err);
		if (!data) {
			g_warning ("couldn't serialize index file: %s", 
			           err && err->message ? err->message : "");
			g_error_free (err);
			goto done;
		}
		
		g_assert (path);
		
		/* And write that memory to disk atomically */
		if (!g_file_set_contents (path, data, n_data, &err)) {
			g_message ("couldn't write index file to disk: %s: %s", 
			           path, err && err->message ? err->message : "");
			g_error_free (err);
			goto done;
		}
	}
	
	ret = TRUE;
	
done:
	if (fd != -1)
		close (fd);
	g_free (data);
	
	return ret;	
}

static void 
cleanup_index_singleton (void *unused)
{
	g_assert (index_singleton);
	g_object_unref (index_singleton);
	index_singleton = NULL;
}

static GkrPkIndex*
get_index_singleton (void)
{
	if (!index_singleton) {
		index_singleton = g_object_new (GKR_TYPE_PK_INDEX, NULL);
		gkr_cleanup_register (cleanup_index_singleton, NULL);
	}
	
	return index_singleton;
}

static gboolean
remove_descendent_locations (gpointer key, gpointer value, gpointer user_data)
{
	GQuark loc = location_from_key (key);
	GQuark volume = GPOINTER_TO_UINT (user_data);
	return loc && gkr_location_is_descendant (volume, loc);
}

static void
flush_caches (GkrLocationManager *locmgr, GQuark volume, GkrPkIndex *index)
{
	/* 
	 * Called when the location manager adds or removes a prefix
	 * possibly invalidating our cached paths.
	 */
	
	g_hash_table_foreach_remove (index->path_by_location, remove_descendent_locations, 
	                             GUINT_TO_POINTER (volume));
	g_hash_table_foreach_remove (index->file_by_location, remove_descendent_locations, 
	                             GUINT_TO_POINTER (volume));
	g_hash_table_foreach_remove (index->mtime_by_location, remove_descendent_locations, 
	                             GUINT_TO_POINTER (volume));
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_index_init (GkrPkIndex *index)
{
	GkrLocationManager *locmgr;
	
	index->path_by_location = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free); 
	index->mtime_by_location = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, free_mtime);
	index->file_by_location = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, 
	                                                 (GDestroyNotify)g_key_file_free);
	
	locmgr = gkr_location_manager_get ();
	g_signal_connect (locmgr, "volume-removed", G_CALLBACK (flush_caches), index);
}

static void
gkr_pk_index_finalize (GObject *obj)
{
	GkrPkIndex *index = GKR_PK_INDEX (obj);
	GkrLocationManager *locmgr;
	
	locmgr = gkr_location_manager_get ();
	g_signal_handlers_disconnect_by_func (locmgr, flush_caches, index);
	
	g_hash_table_destroy (index->path_by_location);
	g_hash_table_destroy (index->mtime_by_location);
	g_hash_table_destroy (index->file_by_location);
	index->path_by_location = index->mtime_by_location = index->file_by_location = NULL;
	
	G_OBJECT_CLASS (gkr_pk_index_parent_class)->finalize (obj);
}

static void
gkr_pk_index_class_init (GkrPkIndexClass *klass)
{
	GObjectClass *gobject_class;

	gkr_pk_index_parent_class = g_type_class_peek_parent (klass);

	gobject_class = (GObjectClass*)klass;
	gobject_class->finalize = gkr_pk_index_finalize;
	
	/* A special quark that denotes stored in memory */
	no_location = g_quark_from_static_string ("MEMORY");
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

gboolean
gkr_pk_index_get_boolean (GQuark loc, gkrconstunique uni, 
                          const gchar *field, gboolean defvalue)
{
	GValue value;
	gboolean ret = defvalue;
	
	g_return_val_if_fail (uni != NULL, ret);	
	g_return_val_if_fail (field != NULL, ret);	
	
	memset (&value, 0, sizeof (value));
	g_value_init (&value, G_TYPE_BOOLEAN);
	
	if (read_pk_index_value (get_index_singleton (), loc, uni, field, &value))
		ret = g_value_get_boolean (&value);

	g_value_unset (&value);	
	return ret;
}

gint
gkr_pk_index_get_int (GQuark loc, gkrconstunique uni, 
                      const gchar *field, gint defvalue)
{
	GValue value;
	gint ret = defvalue;
	
	g_return_val_if_fail (uni != NULL, ret);	
	g_return_val_if_fail (field != NULL, ret);	
	
	memset (&value, 0, sizeof (value));
	g_value_init (&value, G_TYPE_INT);
	
	if (read_pk_index_value (get_index_singleton (), loc, uni, field, &value))
		ret = g_value_get_int (&value);

	g_value_unset (&value);	
	return ret;	
}                                                                 

gchar*
gkr_pk_index_get_string (GQuark loc, gkrconstunique uni, const gchar *field)
{
	GValue value;
	gchar *ret = NULL;
	
	g_return_val_if_fail (uni != NULL, NULL);	
	g_return_val_if_fail (field != NULL, NULL);	
	
	memset (&value, 0, sizeof (value));
	g_value_init (&value, G_TYPE_STRING);
	
	if (read_pk_index_value (get_index_singleton (), loc, uni, field, &value)) {
		/* No way to steal value's string, so just don't unset it */
		ret = (gchar*)g_value_get_string (&value);
	}
	
	return ret;
}

guchar*
gkr_pk_index_get_binary (GQuark loc, gkrconstunique unique, const gchar *field, gsize *n_data)
{
	guchar *data;
	gchar *str;
	gsize n_str;

	g_return_val_if_fail (unique != NULL, NULL);	
	g_return_val_if_fail (field != NULL, NULL);	
	g_return_val_if_fail (n_data != NULL, NULL);	

	str = gkr_pk_index_get_string (loc, unique, field);
	if (!str)
		return NULL;
		
	n_str = strlen (str);
	*n_data = (n_str / 2) + 1;
	data = g_malloc0 (*n_data);
	if (!gkr_crypto_hex_decode (str, n_str, data, n_data)) {
		g_message ("invalid binary data in index under field '%s'", field);
		g_free (data);
		data = NULL;
	}

	g_free (str);
	return data;	
}

gboolean
gkr_pk_index_set_boolean (GQuark loc, gkrconstunique uni, 
                          const gchar *field, gboolean val)
{
	GValue value;
	gboolean ret;

	g_return_val_if_fail (uni != NULL, FALSE);	
	g_return_val_if_fail (field != NULL, FALSE);
		
	memset (&value, 0, sizeof (value));
	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, val);
	
	ret = update_pk_index_value (get_index_singleton (), loc, uni, field, &value);
	g_value_unset (&value);
	
	return ret;
}

gboolean
gkr_pk_index_set_int (GQuark loc, gkrconstunique uni, 
                      const gchar *field, gint val)
{
	GValue value;
	gboolean ret;

	g_return_val_if_fail (uni != NULL, FALSE);	
	g_return_val_if_fail (field != NULL, FALSE);
		
	memset (&value, 0, sizeof (value));
	g_value_init (&value, G_TYPE_INT);
	g_value_set_int (&value, val);
	
	ret = update_pk_index_value (get_index_singleton (), loc, uni, field, &value);
	g_value_unset (&value);
	
	return ret;
}                                                       
                                                        
gboolean 
gkr_pk_index_set_string (GQuark loc, gkrconstunique uni, const gchar *field, const gchar *val)
{
	GValue value;
	gboolean ret;

	g_return_val_if_fail (uni != NULL, FALSE);	
	g_return_val_if_fail (field != NULL, FALSE);
	g_return_val_if_fail (val != NULL, FALSE);
		
	memset (&value, 0, sizeof (value));
	g_value_init (&value, G_TYPE_STRING);
	g_value_set_string (&value, val);
	
	ret = update_pk_index_value (get_index_singleton (), loc, uni, field, &value);
	g_value_unset (&value);
	
	return ret;
}

gboolean
gkr_pk_index_set_binary (GQuark loc, gkrconstunique unique, const gchar *field, 
                         const guchar *data, gsize n_data)
{
	gboolean ret, r;
	gchar *str;
	gsize n_str;
	
	g_return_val_if_fail (unique != NULL, FALSE);	
	g_return_val_if_fail (field != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);
	
	n_str = (n_data * 2) + 1;
	str = g_malloc0 (n_str);
	
	r = gkr_crypto_hex_encode (data, n_data, str, &n_str);
	g_assert (r == TRUE);
	
	ret = gkr_pk_index_set_string (loc, unique, field, str);
	g_free (str);

	return ret;
}

gboolean
gkr_pk_index_delete (GQuark loc, gkrconstunique uni, const gchar *field)
{
	GValue value;
	gboolean ret;

	g_return_val_if_fail (uni != NULL, FALSE);	
	g_return_val_if_fail (field != NULL, FALSE);
	
	/* Values can't be set to NULL, so for us an empty pointer means delete */
	memset (&value, 0, sizeof (value));
	g_value_init (&value, G_TYPE_POINTER);
	g_value_set_pointer (&value, NULL);
	
	ret = update_pk_index_value (get_index_singleton (), loc, uni, field, &value);
	g_value_unset (&value);

	return ret;	
}
