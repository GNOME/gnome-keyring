/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-keyrings-login.c: Test Login Keyring

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

#include "run-auto-test.h"

#include "keyrings/gkr-keyrings.h"
#include "keyrings/gkr-keyring-login.h"

#include "ui/gkr-ask-daemon.h"

#include "util/gkr-location.h"

#include <glib.h>
#include <memory.h>

DEFINE_SETUP(keyrings_login)
{
	gkr_keyrings_update();

	/* Remove the current login keyring */
	GkrKeyring *login = gkr_keyrings_get_login ();
	if (login) {
		gkr_keyring_remove_from_disk (login);
		gkr_keyrings_remove (login);
	}
}

static void 
verify_no_ask (GkrAskRequest *req, gpointer unused)
{
	/* "should not have prompted" */
	g_assert_not_reached ();
}

DEFINE_TEST(keyrings_login)
{
	GkrKeyring *login;
	gboolean ret;

	gkr_ask_daemon_set_hook (verify_no_ask, NULL);
	
	/* Unlock and create a new login keyring */
	ret = gkr_keyring_login_unlock ("blah");
	/* "gkr_keyring_login_unlock() return FALSE" */
	g_assert (ret);
	/* "login not marked unlocked" */
	g_assert (gkr_keyring_login_is_unlocked ());
	
	/* Make sure it worked */
	login = gkr_keyrings_get_login ();
	/* "invalid keyring created by gkr_keyring_login_unlock()" */
	g_assert (login != NULL);
	
	/* Now lock it */
	gkr_keyring_login_lock ();
	/* "didn't lock right keyring" */
	g_assert (login->locked);
	/* "login not marked locked" */
	g_assert (!gkr_keyring_login_is_unlocked ());
	
	/* And unlock it again */
	ret = gkr_keyring_login_unlock ("blah");
	/* "gkr_keyring_login_unlock() returned FALSE" */
	g_assert (ret);
	
	/* Make sure it didn't create a new keyring */
	/* "gkr_keyring_login_unlock() created a second keyring" */
	g_assert (login == gkr_keyrings_get_login());
}

DEFINE_TEST(keyrings_login_master)
{
	const gchar *master;
	gboolean ret;
	
	/* Unlock and create a new login keyring */
	ret = gkr_keyring_login_unlock ("blah");
	g_assert (ret);
	
	master = gkr_keyring_login_master();
	/* "no master password in login keyring" */
	g_assert (master != NULL);
	/* "wrong master password in login keyring" */
	g_assert_cmpstr (master, ==, "blah");
}

DEFINE_TEST(keyrings_login_secrets)
{
	const gchar *password;

	/* Unlock and create a new login keyring */
	gkr_keyring_login_unlock ("blah");

	/* Save a password away */
	gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "Display Name", "secret", 
	                                 "attr-string", "string",
	                                 NULL);

	/* Look it up */
	password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "attr-string", "string",
	                                 NULL);
	/* "no secret found in login keyring */
	g_assert (password != NULL);
	/* "wrong secret found in login keyring" */
	g_assert_cmpstr (password, ==, "secret");
	
	/* Change it to a different password */
	gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "Display Name", "other", 
	                                 "attr-string", "string",
	                                 NULL);

	/* Look it up */
	password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "attr-string", "string",
	                                 NULL);
	/* "no secret found in login keyring" */
	g_assert (password != NULL);
	/* "wrong secret found in login keyring" */
	g_assert_cmpstr (password, ==, "other");

	/* Remove it */
	gkr_keyring_login_remove_secret  (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "attr-string", "string",
	                                  NULL);
	
	/* Look it up */
	password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "attr-string", "string",
	                                 NULL);
	/* "secret wasn't deleted properly" */
	g_assert (password == NULL);
}
