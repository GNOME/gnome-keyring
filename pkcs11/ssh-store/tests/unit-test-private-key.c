/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-private-key.c: Test SSH Key Private key functionality

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

#include "run-auto-test.h"
#include "test-ssh-module.h"

#include "gck/gck-authenticator.h"
#include "gck/gck-session.h"
#include "gck/gck-module.h"

#include "ssh-store/gck-ssh-private-key.h"

#include "pkcs11g.h"

static GckModule *module = NULL;
static GckSession *session = NULL;

DEFINE_SETUP(private_key_setup)
{
	module = test_ssh_module_initialize_and_enter ();
	session = test_ssh_module_open_session (TRUE);
}

DEFINE_TEARDOWN(private_key_teardown)
{
	test_ssh_module_leave_and_finalize ();
	module = NULL;
	session = NULL;
}

DEFINE_TEST(private_key_parse_plain)
{
	GckSshPrivateKey *key;
	gchar *pub_path, *priv_path;
	gboolean ret;
	
	key = gck_ssh_private_key_new (module, "my-unique");
	g_assert (GCK_IS_SSH_PRIVATE_KEY (key));

	pub_path = g_build_filename (test_dir_testdata (), "id_dsa_plain.pub", NULL);
	priv_path = g_build_filename (test_dir_testdata (), "id_dsa_plain", NULL);
	
	ret = gck_ssh_private_key_parse (key, pub_path, priv_path, NULL);
	g_assert (ret == TRUE);
	
	g_object_unref (key);
	g_free (pub_path);
	g_free (priv_path);
}


DEFINE_TEST(private_key_parse_and_unlock)
{
	GckSshPrivateKey *key;
	GckAuthenticator *auth;
	gchar *pub_path, *priv_path;
	gboolean ret;
	CK_RV rv;
	
	key = gck_ssh_private_key_new (module, "my-unique");
	g_assert (GCK_IS_SSH_PRIVATE_KEY (key));

	pub_path = g_build_filename (test_dir_testdata (), "id_dsa_encrypted.pub", NULL);
	priv_path = g_build_filename (test_dir_testdata (), "id_dsa_encrypted", NULL);
	
	ret = gck_ssh_private_key_parse (key, pub_path, priv_path, NULL);
	g_assert (ret == TRUE);

	g_free (pub_path);
	g_free (priv_path);

	rv = gck_authenticator_create (GCK_OBJECT (key), (guchar*)"password", 8, &auth);
	g_assert (rv == CKR_OK);
	
	g_object_unref (auth);
	g_object_unref (key);
}
