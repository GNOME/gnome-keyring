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

#include "run-prompt-test.h"

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

static void 
TELL(const char* what)
	{ printf("INTERACTION: %s\n", what); }

DEFINE_START(keyrings_login)
{
	/* Remove the current login keyring */
	GkrKeyring *login = gkr_keyrings_get_login ();
	if (login)
		gkr_keyrings_remove (login);
}

static gboolean had_prompt = FALSE;

static void 
verify_ask (GkrAskRequest *req, gpointer unused)
{
	/* "should only have one prompt" */
	g_assert (!had_prompt);
	had_prompt = TRUE;
}

DEFINE_TEST(keyrings_login)
{
	gboolean ret;

	gkr_ask_daemon_set_hook (verify_ask, NULL);

	/* "login not marked locked" */
	g_assert (!gkr_keyring_login_is_unlocked ());
	
	/* cancel the prompt */
	TELL("Press 'DENY'");
	had_prompt = FALSE;
	ret = gkr_keyring_login_unlock (NULL);
	/* "no prompt appeared" */
	g_assert (had_prompt);
	/* "gkr_keyring_login_unlock() return TRUE" */
	g_assert (!ret);
	/* "login not marked locked" */
	g_assert (!gkr_keyring_login_is_unlocked ());
	
	/* Now create a keyring */
	TELL("Type 'blah' and press 'OK'");
	had_prompt = FALSE;
	ret = gkr_keyring_login_unlock (NULL);
	/*  "no prompt appeared" */
	g_assert (had_prompt);
	/* "gkr_keyring_login_unlock() return FALSE" */
	g_assert (ret);
	/* "login not marked unlocked" */
	g_assert (gkr_keyring_login_is_unlocked ());
	
	/* Now lock it */
	gkr_keyring_login_lock ();
	/* "didn't lock right keyring" */
	g_assert (!gkr_keyring_login_is_unlocked ());
	
	/* cancel the prompt */
	TELL("Press 'DENY'");
	had_prompt = FALSE;
	ret = gkr_keyring_login_unlock (NULL);
	/* "no prompt appeared" */
	g_assert (had_prompt);
	/* "gkr_keyring_login_unlock() return TRUE" */
	g_assert (!ret);
	/* "login not marked locked" */
	g_assert (!gkr_keyring_login_is_unlocked ());
	
	/* Now create a keyring */
	TELL("Type 'blah' and press 'OK'");
	had_prompt = FALSE;
	ret = gkr_keyring_login_unlock (NULL);
	/* "no prompt appeared" */
	g_assert (had_prompt);
	/* "gkr_keyring_login_unlock() return FALSE" */
	g_assert (ret);
	/* "login not marked unlocked" */
	g_assert (gkr_keyring_login_is_unlocked ());
}
