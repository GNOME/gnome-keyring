/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-keyrings-prompt.c: Test basic prompt functionality

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "run-prompt-test.h"

#include "library/gnome-keyring.h"
 
static void 
TELL(const char* what)
{
	printf("INTERACTION: %s\n", what);
}


#define THE_PASSWORD "test"
#define OTHER_PASSWORD "other"
#define KEYRING_LOGIN "login"
#define KEYRING_NAME "auto-unlock-keyring"
#define DISPLAY_NAME "Item Display Name"
#define SECRET "item-secret"

DEFINE_TEST(create_unlock_login)
{
	GnomeKeyringResult res;
	
	/* Remove the login keyring */
	res = gnome_keyring_delete_sync (KEYRING_LOGIN);
	if (res != GNOME_KEYRING_RESULT_NO_SUCH_KEYRING)
		g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	/* Now create it with our password */
	res = gnome_keyring_create_sync (KEYRING_LOGIN, THE_PASSWORD);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
}

DEFINE_TEST(auto_keyring)
{
	GnomeKeyringResult res;

	/* Remove the auto unlock keyring */
	res = gnome_keyring_delete_sync (KEYRING_NAME);
	if (res != GNOME_KEYRING_RESULT_NO_SUCH_KEYRING)
		g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	res = gnome_keyring_create_sync (KEYRING_NAME, THE_PASSWORD);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	res = gnome_keyring_lock_sync (KEYRING_NAME);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	/* Prompt the user to unlock, and check the option */
	TELL("type 'test' as the password and check the 'Automatically unlock' option");
	res = gnome_keyring_unlock_sync (KEYRING_NAME, NULL);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	res = gnome_keyring_lock_sync (KEYRING_NAME);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	TELL("No prompt should show up at this point");
	res = gnome_keyring_unlock_sync (KEYRING_NAME, NULL);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	sleep(2);
}

DEFINE_TEST(auto_keyring_stale)
{
	GnomeKeyringResult res;
	
	/* Remove the auto unlock keyring */
	res = gnome_keyring_change_password_sync (KEYRING_NAME, THE_PASSWORD, OTHER_PASSWORD);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);

	res = gnome_keyring_lock_sync (KEYRING_NAME);
	g_assert_cmpint (GNOME_KEYRING_RESULT_OK, ==, res);
	
	TELL("Press 'deny' here");	
	res = gnome_keyring_unlock_sync (KEYRING_NAME, NULL);
	g_assert_cmpint (GNOME_KEYRING_RESULT_DENIED, ==, res);
}
