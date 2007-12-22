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
#include "gkr-pk-places.h"

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
	 GHashTable *defaults_by_parent;
};

struct _GkrPkIndexClass {
	GObjectClass parent_class;
};

static GType gkr_pk_index_get_type (void);
G_DEFINE_TYPE (GkrPkIndex, gkr_pk_index, G_TYPE_OBJECT);

static GkrPkIndex *index_singleton = NULL; 
static GQuark no_location = 0;

typedef gboolean (*ReadValueFunc) (GKeyFile *file, const gchar *group, const gchar *field, 
                                   GError **err, gpointer user_data);
                                   
typedef gboolean (*WriteValueFunc) (GKeyFile *file, const gchar *group, const gchar *field, 
                                    GError **err, gpointer user_data);

/* -----------------------------------------------------------------------------
 * HELPERS
 */
 
#ifndef HAVE_FLOCK
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

static int flock(int fd, int operation)
{
	struct flock flock;

	switch (operation & ~LOCK_NB) {
	case LOCK_SH:
		flock.l_type = F_RDLCK;
		break;
	case LOCK_EX:
		flock.l_type = F_WRLCK;
		break;
	case LOCK_UN:
		flock.l_type = F_UNLCK;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	flock.l_whence = 0;
	flock.l_start = 0;
	flock.l_len = 0;

	return fcntl(fd, (operation & LOCK_NB) ? F_SETLK : F_SETLKW, &flock);
}
#endif //NOT_HAVE_FLOCK

static void 
free_mtime (gpointer v)
{
	g_slice_free (time_t, v);
}

static GQuark* 
quarks_from_strings (const gchar **strv, gsize *n_quarks)
{
	GArray *arr;
	GQuark quark;
	
	arr = g_array_new (TRUE, TRUE, sizeof (GQuark));
	while (*strv) {
		quark = g_quark_from_string (*strv);
		g_array_append_val (arr, quark);
		++strv;
	}
	
	if (n_quarks)
		*n_quarks = arr->len;
	
	return (GQuark*)g_array_free (arr, FALSE);
}

static gchar**
quarks_to_strings (const GQuark* quarks, gsize *n_strings)
{
	const gchar *value;
	GArray *arr;
	
	arr = g_array_new (TRUE, TRUE, sizeof (const gchar*));
	while (*quarks) {
		value = g_quark_to_string (*quarks);
		g_array_append_val (arr, value);
		++quarks;
	}
	
	if (n_strings)
		*n_strings = arr->len;
	return (gchar**)g_array_free (arr, FALSE);
}

static gboolean
strings_are_equal (const gchar **one, const gchar **two)
{
	while (*one && *two) {
		if (!g_str_equal (*one, *two))
			return FALSE;
		++one;
		++two;
	}
	
	return *one == *two;
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
		
		/* Our index files have a .keystore extension */
		path = g_strconcat (locpath, ".keystore", NULL);
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
	
	g_return_val_if_fail (uni, NULL);
		
	unidata = gkr_unique_get_raw (uni, &n_unidata);
	g_assert (unidata);
	n_group = (n_unidata * 2) + 1;
	group = g_malloc0 (n_group);
	
	r = gkr_crypto_hex_encode (unidata, n_unidata, group, &n_group);
	g_assert (r == TRUE);
	
	return group;
}

static gboolean
read_exists_any_value (GKeyFile *file, const gchar *group, const gchar *field,
                       GError **err, gboolean *value)
{
	g_assert (value);
	*value = g_key_file_has_group (file, group);
	return TRUE;
}

static gboolean
read_exists_value (GKeyFile *file, const gchar *group, const gchar *field, 
                   GError **err, gboolean *value)
{
	g_assert (value);
	g_assert (field);
	*value = g_key_file_has_key (file, group, field, err);
	return *err == NULL;	
}

static gboolean
read_boolean_value (GKeyFile *file, const gchar *group, const gchar *field, 
                    GError **err, gboolean *value)
{
	g_assert (value);
	g_assert (field);
	*value = g_key_file_get_boolean (file, group, field, err);
	return *err == NULL;
}

static gboolean
read_int_value (GKeyFile *file, const gchar *group, const gchar *field,
                GError **err, gint *value)
{
	g_assert (value);
	g_assert (field);
	*value = g_key_file_get_integer (file, group, field, err);
	return *err == NULL;
}

static gboolean
read_string_value (GKeyFile *file, const gchar *group, const gchar *field,
                   GError **err, gchar **value)
{
	g_assert (value);
	g_assert (field);
	*value = g_key_file_get_string (file, group, field, err);
	return *value != NULL;
}

static gboolean
read_quarks_value (GKeyFile *file, const gchar *group, const gchar *field,
                   GError **err, GQuark **value)
{
	gchar **vals;
	
	g_assert (value);
	g_assert (field);
	
	vals = g_key_file_get_string_list (file, group, field, NULL, err);
	if (vals != NULL) {
		g_assert (*err == NULL);
		*value = quarks_from_strings ((const gchar**)vals, NULL);
		g_strfreev (vals);
		return TRUE;
	}
	
	return FALSE;
}
	
static gint
get_keyfile_value (GKeyFile *key_file, const gchar *group, 
                   const gchar *field, ReadValueFunc func, gpointer data)
{
	GError *err = NULL;
	
	g_assert (key_file);
	g_assert (group);
	g_assert (func);
	
	if ((func) (key_file, group, field, &err, data))
		return 1;
	
	if (err != NULL) {
		if (err->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND &&
		    err->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
		    	g_warning ("couldn't read field '%s' from index: %s", 
		    	           field, err->message ? err->message : "");
			g_error_free (err);
			return -1;
		}
		
		g_error_free (err);
	}

	return 0;
}

static gboolean
write_clear (GKeyFile *file, const gchar *group, const gchar *field,
             GError **err, gpointer user_data)
{
	if (!g_key_file_has_group (file, group))
		return FALSE;
	g_key_file_remove_group (file, group, err);
	return TRUE; 	
}

static gboolean 
write_delete (GKeyFile *file, const gchar *group, const gchar *field, 
              GError **err, gpointer user_data)
{
	g_assert (field);
	
	if (g_key_file_has_key (file, group, field, err)) {
		g_key_file_remove_key (file, group, field, err);
		return TRUE;
	}
	
	return FALSE;
}

static gboolean 
write_boolean_value (GKeyFile *file, const gchar *group, const gchar *field, 
                     GError **err, gboolean *value)
{
	g_assert (value);
	g_assert (field);
	
	if (g_key_file_get_boolean (file, group, field, err) != *value || err != NULL) {
		g_clear_error (err);
		g_key_file_set_boolean (file, group, field, *value);
		return TRUE;
	}
	
	return FALSE;
}

static gboolean
write_int_value (GKeyFile *file, const gchar *group, const gchar *field, 
                 GError **err, gint *value)
{
	g_assert (value);
	g_assert (field);
	
	if (g_key_file_get_integer (file, group, field, err) != *value || err != NULL) {
		g_clear_error (err);
		g_key_file_set_integer (file, group, field, *value);
		return TRUE;
	}
	
	return FALSE;
}

static gboolean
write_string_value (GKeyFile *file, const gchar *group, const gchar *field, 
                    GError **err, const gchar **value)
{
	gboolean ret = FALSE;
	gchar *o;
	
	g_assert (value);
	g_assert (*value);
	g_assert (field);
	
	o = g_key_file_get_value (file, group, field, NULL);

	if (!o || !g_str_equal (o, *value)) {
		g_key_file_set_string (file, group, field, *value);
		ret = TRUE;
	}
			
	g_free (o);
	return ret;
}

static gboolean
write_quarks_value (GKeyFile *file, const gchar *group, const gchar *field, 
                    GError **err, GQuark **value)
{
	GQuark *quarks;
	gsize n_strings;
	gchar **strings, **o;
	gboolean ret = FALSE;
	
	g_assert (value);
	g_assert (*value);
	g_assert (field);
	
	quarks = *value;
	strings = quarks_to_strings (quarks, &n_strings);
	o = g_key_file_get_string_list (file, group, field, NULL, NULL);
		
	if (!o || !strings_are_equal ((const gchar**)strings, (const gchar**)o)) {
		g_key_file_set_string_list (file, group, field, (const gchar**)strings, n_strings);
		ret = TRUE;
	}
		
	g_strfreev (o);
	g_free (strings);
	return ret;
}

static void
set_keyfile_value (GKeyFile *key_file, gkrconstunique uni, 
                   const gchar *field, WriteValueFunc func, 
                   gpointer data, gboolean *updated)
{
	GError *err = NULL;
	gchar *group;
	
	g_assert (key_file);
	g_assert (uni);
	g_assert (func);
	g_assert (updated);
	
	/* TODO: Cache this somehow? */
	group = unique_to_group (uni);
	g_return_if_fail (group);
	
	*updated = (func) (key_file, group, field, &err, data);

	if (err) {
	    	g_warning ("couldn't write field '%s' to index: %s", 
	    	           field, err->message ? err->message : "");
		g_error_free (err);
	}
	
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

static const gchar*
find_parent_defaults (GQuark parent)
{
	const GkrPkPlace *place;
	const gchar *defaults = NULL;
	GSList *volumes, *l;
	GQuark loc;
	guint i;
	
	for (i = 0; i < G_N_ELEMENTS (gkr_pk_places); ++i) {
		place = &(gkr_pk_places[i]);
		
		/* With a specific volume */
		if (place->volume) {
			loc = gkr_location_from_string (place->volume);
			loc = gkr_location_from_child (loc, place->directory);
			if (loc == parent)
				defaults = place->defaults;
				
		/* With any volume */
		} else {
			volumes = gkr_location_manager_get_volumes (NULL);
			for (l = volumes; l; l = g_slist_next (l)) {
				loc = gkr_location_from_child (GPOINTER_TO_UINT (l->data), 
				                               place->directory);
				if (loc == parent) {
					defaults = place->defaults;
					break;
				}
			}
			g_slist_free (volumes);
		}
		
		/* Found something? */
		if (defaults)
			return defaults;
	}
	
	return NULL;	
}

static GKeyFile*
load_parent_key_file (GkrPkIndex *index, GQuark loc)
{
	GKeyFile *file;
	GQuark parent;
	const gchar *defaults;
	
	if (!loc)
		return NULL;
		
	parent = gkr_location_to_parent (loc);
	if (!parent)
		return NULL;
		
	file = g_hash_table_lookup (index->defaults_by_parent, GUINT_TO_POINTER (parent));
	if (!file) {
		file = g_key_file_new ();
		g_hash_table_insert (index->defaults_by_parent, GUINT_TO_POINTER (parent), file);	

		/* 
		 * Look in the places list and load any default index data 
		 * from there. 
		 */
		defaults = find_parent_defaults (parent);
		if (defaults) {
			if (!g_key_file_load_from_data (file, defaults, strlen (defaults), 
			                                G_KEY_FILE_NONE, NULL))
				g_warning ("couldn't parse builtin parent defaults");
		}
	}
	
	return file;
}

static gboolean
read_pk_index_value (GkrPkIndex *index, GQuark loc, gkrconstunique uni, 
                     const gchar *field, GkrPkObject *object, 
                     ReadValueFunc func, gpointer data)
{
	const gchar *path = NULL;
	struct stat sb;
	gboolean force = FALSE;
	GKeyFile *key_file = NULL;
	gchar *group;
	gint ret = 0;
	
	g_return_val_if_fail (uni, FALSE);

	if (loc) {
		path = index_path_for_location (index, loc);
		if (!path) 
			return FALSE;

		/* TODO: Any way to do this less often? */
		force = (stat (path, &sb) < 0 || check_index_mtime (index, loc, sb.st_mtime));
	}
	
	key_file = load_index_key_file (index, loc, -1, force);
	
	/* Try the actual item first */
	if (key_file) {
		group = unique_to_group (uni);
		g_return_val_if_fail (group, FALSE);
	
		ret = get_keyfile_value (key_file, group, field, func, data);
		g_free (group);

		/* If not found, look in the default section */
		if (ret == 0)
			ret = get_keyfile_value (key_file, "default", field, func, data);
	}
		
	/* Look in the parent directory defaults */
	if (ret == 0) {
		key_file = load_parent_key_file (index, loc);
		if (key_file) 
			ret = get_keyfile_value (key_file, "default", field, func, data);
	}

	/* 
	 * If we saw that the file was changed, then tell the object
	 * to flush all of its caches and etc...
	 */ 
	if (force && object)
		gkr_pk_object_flush (object);
	
	return ret == 1;
}

static gboolean
update_pk_index_value (GkrPkIndex *index, GQuark loc, gkrconstunique uni, 
                       const gchar *field, GkrPkObject *object, 
                       WriteValueFunc func, gpointer data)
{
	const gchar *path = NULL;
	gchar *contents = NULL;
	gboolean ret = FALSE;
	gboolean force = FALSE;
	gboolean updated = FALSE;
	GError *err = NULL;
	GKeyFile *key_file = NULL;
	gsize n_contents;
	struct stat sb;
	int tries = 0;
	int fd = -1;
	
	g_return_val_if_fail (uni, FALSE);
	
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

	set_keyfile_value (key_file, uni, field, func, data, &updated);
	if (updated && loc) {
		
		/* Serialize the key file into memory */
		contents = g_key_file_to_data (key_file, &n_contents, &err);
		if (!contents) {
			g_warning ("couldn't serialize index file: %s", 
			           err && err->message ? err->message : "");
			g_error_free (err);
			goto done;
		}
		
		g_assert (path);
		
		/* And write that memory to disk atomically */
		if (!g_file_set_contents (path, contents, n_contents, &err)) {
			g_message ("couldn't write index file to disk: %s: %s", 
			           path, err && err->message ? err->message : "");
			g_error_free (err);
			goto done;
		}
	}
	
	/* 
	 * If the file was updated then tell the object to flush all of 
	 * its caches and other optimizations...
	 */
	if ((force || updated) && object)
		gkr_pk_object_flush (object);
		
	ret = TRUE;
	
done:
	if (fd != -1)
		close (fd);
	g_free (contents);
	
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
	g_hash_table_foreach_remove (index->defaults_by_parent, remove_descendent_locations,
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
	index->defaults_by_parent = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL,
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
	g_hash_table_destroy (index->defaults_by_parent);
	index->path_by_location = index->mtime_by_location = NULL;
	index->file_by_location = index->defaults_by_parent = NULL;
	
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
gkr_pk_index_get_boolean (GkrPkObject *obj, const gchar *field, gboolean defvalue)
{
	gboolean ret = defvalue;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), ret);
	g_return_val_if_fail (field != NULL, ret);	
	
	if (!read_pk_index_value (get_index_singleton (), obj->location, obj->unique,
	                          field, obj, (ReadValueFunc)read_boolean_value, &ret))
		ret = defvalue;

	return ret;
}

gint
gkr_pk_index_get_int (GkrPkObject *obj, const gchar *field, gint defvalue)
{
	gint ret = defvalue;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), ret);	
	g_return_val_if_fail (field != NULL, ret);	

	if (!read_pk_index_value (get_index_singleton (), obj->location, obj->unique,
	                          field, obj, (ReadValueFunc)read_int_value, &ret))
		ret = defvalue;

	return ret;	
}                                                                 

gchar*
gkr_pk_index_get_string (GkrPkObject *obj, const gchar *field)
{
	gchar *ret = NULL;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), NULL);
	g_return_val_if_fail (field != NULL, NULL);	
	
	if (!read_pk_index_value (get_index_singleton (), obj->location, obj->unique,
	                          field, obj, (ReadValueFunc)read_string_value, &ret))
		ret = NULL;

	return ret;
}

gchar*
gkr_pk_index_get_string_full (GQuark location, gkrconstunique uni, 
                              const gchar *field)
{
	gchar *ret = NULL;
	
	g_return_val_if_fail (uni, NULL);
	g_return_val_if_fail (field != NULL, NULL);	
	
	if (!read_pk_index_value (get_index_singleton (), location, uni, field,
	                          NULL, (ReadValueFunc)read_string_value, &ret))
		ret = NULL;

	return ret;	
}

guchar*
gkr_pk_index_get_binary (GkrPkObject *obj, const gchar *field, gsize *n_data)
{
	guchar *data;
	gchar *str;
	gsize n_str;

	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), NULL);
	g_return_val_if_fail (field != NULL, NULL);	
	g_return_val_if_fail (n_data != NULL, NULL);	

	str = gkr_pk_index_get_string (obj, field);
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

GQuark* 
gkr_pk_index_get_quarks (GkrPkObject *obj, const gchar *field)
{
	GQuark *ret = NULL;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), NULL);
	g_return_val_if_fail (field != NULL, NULL);	
	
	if (!read_pk_index_value (get_index_singleton (), obj->location, obj->unique,
	                          field, obj, (ReadValueFunc)read_quarks_value, &ret))
		ret = NULL;
		
	return ret;
}

gboolean
gkr_pk_index_has_value (GkrPkObject *obj, const gchar *field)
{
	gboolean ret;

	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);
	
	if (!read_pk_index_value (get_index_singleton (), obj->location, obj->unique,
	                          field, obj, (ReadValueFunc)read_exists_value, &ret))
		ret = FALSE;

	return ret;
}

gboolean
gkr_pk_index_have (GkrPkObject *obj)
{
	gboolean ret;

	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	
	if (!read_pk_index_value (get_index_singleton (), obj->location, obj->unique,
	                          NULL, obj, (ReadValueFunc)read_exists_any_value, &ret))
		ret = FALSE;

	return ret;
}

gboolean
gkr_pk_index_have_full (GQuark location, gkrconstunique uni)
{
	gboolean ret;

	g_return_val_if_fail (uni, FALSE);
	
	if (!read_pk_index_value (get_index_singleton (), location, uni, NULL,
	                          NULL, (ReadValueFunc)read_exists_any_value, &ret))
		ret = FALSE;

	return ret;
}

gboolean
gkr_pk_index_set_boolean (GkrPkObject *obj, const gchar *field, gboolean val)
{
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);
		
	return update_pk_index_value (get_index_singleton (), obj->location, obj->unique, 
	                              field, obj, (WriteValueFunc)write_boolean_value, &val);
}

gboolean
gkr_pk_index_set_int (GkrPkObject *obj, const gchar *field, gint val)
{
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	return update_pk_index_value (get_index_singleton (), obj->location, obj->unique, 
	                              field, obj, (WriteValueFunc)write_int_value, &val);
}                                                       
                                                        
gboolean 
gkr_pk_index_set_string (GkrPkObject *obj, const gchar *field, const gchar *val)
{
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	return update_pk_index_value (get_index_singleton (), obj->location, obj->unique, 
	                              field, obj, (WriteValueFunc)write_string_value, &val);
}

gboolean
gkr_pk_index_set_string_full (GQuark location, gkrconstunique uni, const gchar *field, 
                              const gchar *val)
{
	g_return_val_if_fail (uni, FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	return update_pk_index_value (get_index_singleton (), location, uni, field, 
	                              NULL, (WriteValueFunc)write_string_value, &val);	
}

gboolean
gkr_pk_index_set_binary (GkrPkObject *obj, const gchar *field, 
                         const guchar *data, gsize n_data)
{
	gboolean ret, r;
	gchar *str;
	gsize n_str;
	
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);
	
	n_str = (n_data * 2) + 1;
	str = g_malloc0 (n_str);
	
	r = gkr_crypto_hex_encode (data, n_data, str, &n_str);
	g_assert (r == TRUE);
	
	ret = gkr_pk_index_set_string (obj, field, str);
	g_free (str);

	return ret;
}

gboolean
gkr_pk_index_set_quarks (GkrPkObject *obj, const gchar *field, GQuark *quarks)
{
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	return update_pk_index_value (get_index_singleton (), obj->location, obj->unique, 
	                              field, obj, (WriteValueFunc)write_quarks_value, &quarks);
}

gboolean
gkr_pk_index_delete (GkrPkObject *obj, const gchar *field)
{
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	return update_pk_index_value (get_index_singleton (), obj->location, obj->unique, 
	                              field, obj, (WriteValueFunc)write_delete, NULL);

}

gboolean
gkr_pk_index_clear (GkrPkObject *obj)
{
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);

	return update_pk_index_value (get_index_singleton (), obj->location, obj->unique, 
	                              NULL, obj, (WriteValueFunc)write_clear, NULL);

}

gboolean
gkr_pk_index_quarks_has (GQuark *quarks, GQuark check)
{
	while (*quarks) {
		if (*quarks == check)
			return TRUE;
		++quarks;
	}
	
	return FALSE;
}

GQuark*
gkr_pk_index_quarks_dup (GQuark *quarks)
{
	GQuark *last = quarks;
	
	/* Figure out how many there are */	
	while (*last)
		++last;
		
	/* Include the null termination */
	++last;
	return g_memdup (quarks, (last - quarks) * sizeof (GQuark));
}

void
gkr_pk_index_quarks_free (GQuark *quarks)
{
	g_free (quarks);
}
