/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#include "config.h"

#include "gcr/gcr.h"
#include "gcr/gcr-gnupg-collection.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>
#include <string.h>

#if 0
typedef struct {

} Test;

static void
setup (Test *test, gconstpointer unused)
{

}

static void
teardown (Test *test, gconstpointer unused)
{

}
#endif

static void
test_create (void)
{
	GcrCollection *collection;

	collection = _gcr_gnupg_collection_new ("files/gnupg-homedir/");

	g_object_unref (collection);
}


int
main (int argc, char **argv)
{
	const gchar *srcdir;

	g_type_init ();
	g_test_init (&argc, &argv, NULL);

	srcdir = g_getenv ("SRCDIR");
	if (srcdir && chdir (srcdir) < 0)
		g_error ("couldn't change directory to: %s: %s", srcdir, g_strerror (errno));

	g_test_add_func ("/gcr/gnupg-collection/create", test_create);
#if 0
	g_test_add ("/gcr/certificate/issuer_dn", Test, NULL, setup, test_issuer_dn, teardown);
#endif

	return g_test_run ();
}
