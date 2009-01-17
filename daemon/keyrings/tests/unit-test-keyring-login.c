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

#include "common/gkr-location.h"

#include "keyrings/gkr-keyrings.h"
#include "keyrings/gkr-keyring-login.h"

#include "ui/gkr-ask-daemon.h"

#include <glib.h>
#include <memory.h>

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void)
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void)
 * 
 * Tests be run in the order specified here.
 */

void unit_setup_keyrings_login (void)
{
	gkr_keyrings_update();

	/* Remove the current login keyring */
	GkrKeyring *login = gkr_keyrings_get_login ();
	if (login) {
		g_printerr ("removing old login keyring: %s\n", 
                            gkr_location_to_path (login->location));
		gkr_keyring_remove_from_disk (login);
		gkr_keyrings_remove (login);
	}
}

static void 
verify_no_ask (GkrAskRequest *req, gpointer data)
{
	CuTest *cu = (CuTest*)data;
	CuAssert (cu, "should not have prompted", FALSE);
}

void unit_test_keyrings_login (CuTest* cu)
{
	GkrKeyring *login;
	gboolean ret;

	gkr_ask_daemon_set_hook (verify_no_ask, cu);
	
	/* Unlock and create a new login keyring */
	ret = gkr_keyring_login_unlock ("blah");
	CuAssert (cu, "gkr_keyring_login_unlock() return FALSE", ret);
	CuAssert (cu, "login not marked unlocked", gkr_keyring_login_is_unlocked ());
	
	/* Make sure it worked */
	login = gkr_keyrings_get_login ();
	CuAssert (cu, "invalid keyring created by gkr_keyring_login_unlock()", login != NULL);
	
	/* Now lock it */
	gkr_keyring_login_lock ();
	CuAssert (cu, "didn't lock right keyring", login->locked);
	CuAssert (cu, "login not marked locked", !gkr_keyring_login_is_unlocked ());
	
	/* And unlock it again */
	ret = gkr_keyring_login_unlock ("blah");
	CuAssert (cu, "gkr_keyring_login_unlock() returned FALSE", ret);
	
	/* Make sure it didn't create a new keyring */
	CuAssert (cu, "gkr_keyring_login_unlock() created a second keyring", 
	          login == gkr_keyrings_get_login());
}

void unit_test_keyrings_login_master (CuTest *cu)
{
	const gchar *master = gkr_keyring_login_master();
	CuAssert (cu, "no master password in login keyring", master != NULL);
	CuAssert (cu, "wrong master password in login keyring", strcmp (master, "blah") == 0);
}

void unit_test_keyrings_login_secrets (CuTest* cu)
{
	const gchar *password;
	
	/* Save a password away */
	gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "Display Name", "secret", 
	                                 "attr-string", "string",
	                                 NULL);

	/* Look it up */
	password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "attr-string", "string",
	                                 NULL);
	CuAssert (cu, "no secret found in login keyring", password != NULL);
	CuAssert (cu, "wrong secret found in login keyring", strcmp (password, "secret") == 0);
	
	/* Change it to a different password */
	gkr_keyring_login_attach_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "Display Name", "other", 
	                                 "attr-string", "string",
	                                 NULL);

	/* Look it up */
	password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "attr-string", "string",
	                                 NULL);
	CuAssert (cu, "no secret found in login keyring", password != NULL);
	CuAssert (cu, "wrong secret found in login keyring", strcmp (password, "other") == 0);

	/* Remove it */
	gkr_keyring_login_remove_secret  (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "attr-string", "string",
	                                  NULL);
	
	/* Look it up */
	password = gkr_keyring_login_lookup_secret (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                 "attr-string", "string",
	                                 NULL);
	CuAssert (cu, "secret wasn't deleted properly", password == NULL);
}
