/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-secret-collection.c: Test the collection keyring

   Copyright (C) 2009 Stefan Walter

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

#include "run-auto-test.h"
#include "test-secret-module.h"

#include "gck-secret-data.h"
#include "gck-secret-collection.h"

#include "gck/gck-authenticator.h"
#include "gck/gck-session.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static GckModule *module = NULL;
static GckSession *session = NULL;
static GckSecretCollection *collection = NULL;

DEFINE_SETUP(secret_collection)
{
	module = test_secret_module_initialize_and_enter ();
	session = test_secret_module_open_session (TRUE);

	collection = g_object_new (GCK_TYPE_SECRET_COLLECTION,
	                           "module", module,
	                           "identifier", "test",
	                           NULL);

	g_assert (GCK_IS_SECRET_COLLECTION (collection));
}

DEFINE_TEARDOWN(secret_collection)
{
	if (collection)
		g_object_unref (collection);
	collection = NULL;

	test_secret_module_leave_and_finalize ();
	module = NULL;
	session = NULL;

}

DEFINE_TEST(secret_collection_is_locked)
{
	gboolean locked;

	/* By default is locked */
	locked = gck_secret_object_is_locked (GCK_SECRET_OBJECT (collection), session);
	g_assert (locked == TRUE);
}

DEFINE_TEST(secret_collection_unlocked_data)
{
	GckAuthenticator *auth;
	GckSecretData *sdata;
	CK_RV rv;

	/* Create authenticator, which unlocks collection */
	rv = gck_authenticator_create (GCK_OBJECT (collection), NULL, 0, &auth); 
	g_assert (rv == CKR_OK);
	gck_session_add_session_object (session, NULL, GCK_OBJECT (auth));
	g_object_unref (auth);

	/* Collection should now be unlocked */
	sdata = gck_secret_collection_unlocked_data (collection, session);
	g_assert (GCK_IS_SECRET_DATA (sdata));
	g_assert (!gck_secret_object_is_locked (GCK_SECRET_OBJECT (collection), session));
}
