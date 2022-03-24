/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-xdg-module.c: A test PKCS#11 module implementation

   Copyright (C) 2010 Stefan Walter
   Copyright (C) 2010 Collabora Ltd

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "mock-xdg-module.h"

#include "xdg-store/gkm-xdg-store.h"

#include "egg/egg-secure-memory.h"
#include "egg/egg-testing.h"

#include "gkm/gkm-session.h"
#include "gkm/gkm-module.h"

#include <glib/gstdio.h>

#include <errno.h>
#include <sys/time.h>

#include <string.h>

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

static GMutex *mutex = NULL;
static gchar *directory = NULL;

GkmModule*  _gkm_xdg_store_get_module_for_testing (void);
GMutex* _gkm_module_get_scary_mutex_that_you_should_not_touch (GkmModule *module);

void
mock_xdg_module_remove_file (const gchar *name)
{
	gchar *filename;
	gchar *basename;

	basename = g_path_get_basename (name);
	filename = g_build_filename (directory, basename, NULL);
	if (g_unlink (filename) < 0)
		g_error ("couldn't remove: %s", filename);
	g_free (filename);
	g_free (basename);
}


void
mock_xdg_module_empty_file (const gchar *name)
{
	gchar *filename;
	gchar *basename;

	basename = g_path_get_basename (name);
	filename = g_build_filename (directory, basename, NULL);
	if (!g_file_set_contents (filename, "", 0, NULL))
		g_error ("couldn't write: %s", filename);
	g_free (filename);
	g_free (basename);
}

void
mock_xdg_module_touch_file (const gchar *name, gint future)
{
	gchar *basename;
	gchar *filename;
	struct timeval tv[2];

	basename = g_path_get_basename (name);
	filename = g_build_filename (directory, basename, NULL);

	/* Initialize the access and modification times */
	gettimeofday (tv, NULL);
	tv[0].tv_sec += future;
	memcpy (tv + 1, tv, sizeof (struct timeval));

	if (utimes (filename, tv) < 0)
		g_error ("couldn't update file time: %s: %s", filename, g_strerror (errno));

	g_free (basename);
	g_free (filename);
}

GkmModule*
mock_xdg_module_initialize_and_enter (void)
{
	CK_FUNCTION_LIST_PTR funcs;
	CK_C_INITIALIZE_ARGS args;
	GkmModule *module;
	gchar *string;
	CK_RV rv;

	directory = egg_tests_create_scratch_directory (
		SRCDIR "/pkcs11/xdg-store/fixtures/test-refer-1.trust",
		SRCDIR "/pkcs11/xdg-store/fixtures/test-certificate-1.cer",
		NULL);

	/* Setup test directory to work in */
	memset (&args, 0, sizeof (args));
	string = g_strdup_printf ("directory='%s'", directory);
	args.pReserved = string;
	args.flags = CKF_OS_LOCKING_OK;

	/* Copy fixtures from test-data to scratch */
	mock_xdg_module_empty_file ("invalid-without-ext");
	mock_xdg_module_empty_file ("test-file.unknown");
	mock_xdg_module_empty_file ("test-invalid.trust");

	funcs = gkm_xdg_store_get_functions ();
	rv = (funcs->C_Initialize) (&args);
	g_return_val_if_fail (rv == CKR_OK, NULL);

	module = _gkm_xdg_store_get_module_for_testing ();
	g_return_val_if_fail (module, NULL);

	mutex = _gkm_module_get_scary_mutex_that_you_should_not_touch (module);
	mock_xdg_module_enter ();

	g_free (string);

	return module;
}

void
mock_xdg_module_leave_and_finalize (void)
{
	CK_FUNCTION_LIST_PTR funcs;
	CK_RV rv;

	mock_xdg_module_leave ();

	funcs = gkm_xdg_store_get_functions ();
	rv = (funcs->C_Finalize) (NULL);
	g_return_if_fail (rv == CKR_OK);

	egg_tests_remove_scratch_directory (directory);
	g_free (directory);
	directory = NULL;
}

void
mock_xdg_module_leave (void)
{
	g_assert (mutex);
	g_mutex_unlock (mutex);
}

void
mock_xdg_module_enter (void)
{
	g_assert (mutex);
	g_mutex_lock (mutex);
}

GkmSession*
mock_xdg_module_open_session (gboolean writable)
{
	CK_ULONG flags = CKF_SERIAL_SESSION;
	CK_SESSION_HANDLE handle;
	GkmModule *module;
	GkmSession *session;
	CK_RV rv;

	module = _gkm_xdg_store_get_module_for_testing ();
	g_return_val_if_fail (module, NULL);

	if (writable)
		flags |= CKF_RW_SESSION;

	rv = gkm_module_C_OpenSession (module, 1, flags, NULL, NULL, &handle);
	g_assert (rv == CKR_OK);

	session = gkm_module_lookup_session (module, handle);
	g_assert (session);

	return session;
}
