/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
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
 */

/*
 * PORTIONS FROM: ----------------------------------------------------------
 *
 * GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * --------------------------------------------------------------------------
 */

/*
 * PORTIONS FROM: ----------------------------------------------------------
 *
 * Modified by the GLib Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/.
 *
 * --------------------------------------------------------------------------
 */

#include "config.h"

#include "gkm-util.h"

#include <glib.h>
#include <glib-object.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

/* Only access using atomic operations */
static gint next_handle = 0x00000010;



gulong*
gkm_util_ulong_alloc (gulong value)
{
	return g_slice_dup (gulong, &value);
}

void
gkm_util_ulong_free (gpointer ptr_to_ulong)
{
	g_slice_free (gulong, ptr_to_ulong);
}

guint
gkm_util_ulong_hash (gconstpointer v)
{
	const signed char *p = v;
	guint32 i, h = *p;
	for(i = 0; i < sizeof (gulong); ++i)
		h = (h << 5) - h + *(p++);
	return h;
}

gboolean
gkm_util_ulong_equal (gconstpointer v1, gconstpointer v2)
{
	return *((const gulong*)v1) == *((const gulong*)v2);
}

CK_RV
gkm_util_return_data (CK_VOID_PTR output, CK_ULONG_PTR n_output,
                      gconstpointer input, gsize n_input)
{
	g_return_val_if_fail (n_output, CKR_GENERAL_ERROR);
	g_return_val_if_fail (input || !n_input, CKR_GENERAL_ERROR);

	/* Just asking for the length */
	if (!output) {
		*n_output = n_input;
		return CKR_OK;
	}

	/* Buffer is too short */
	if (n_input > *n_output) {
		*n_output = n_input;
		return CKR_BUFFER_TOO_SMALL;
	}

	*n_output = n_input;
	if (n_input)
		memcpy (output, input, n_input);
	return CKR_OK;
}

CK_ULONG
gkm_util_next_handle (void)
{
	return (CK_ULONG)g_atomic_int_add (&next_handle, 1);
}

void
gkm_util_dispose_unref (gpointer object)
{
	g_return_if_fail (G_IS_OBJECT (object));
	g_object_run_dispose (G_OBJECT (object));
	g_object_unref (object);
}

gchar *
gkm_util_locate_keyrings_directory (void)
{
	gchar *old_directory;
	gchar *new_directory;
	gchar *directory;

	old_directory = g_build_filename (g_get_home_dir (), ".gnome2", "keyrings", NULL);
	new_directory = g_build_filename (g_get_user_data_dir (), "keyrings", NULL);

	/*
	 * If the new XDG directory doesn't exist, and the old one does,
	 * use the old one, otherwise create/use the new XDG location.
	 */

	if (!g_file_test (new_directory, G_FILE_TEST_IS_DIR) &&
	    g_file_test (old_directory, G_FILE_TEST_IS_DIR)) {
		directory = old_directory;
		old_directory = NULL;

		g_message ("using old keyring directory: %s", directory);
	} else {
		directory = new_directory;
		new_directory = NULL;

		if (g_mkdir_with_parents (directory, S_IRWXU) < 0)
			g_warning ("unable to create keyring dir: %s", directory);
	}

	g_free (old_directory);
	g_free (new_directory);
	return directory;
}
