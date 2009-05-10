/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pam.c: Test PAM module

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

#include <security/pam_appl.h>
 
extern pam_handle_t *test_pamh;

DEFINE_TEST(pam_open)
{
	char** pam_env;

	/* Clear out this environment variable so we force a new daemon */
	putenv("GNOME_KEYRING_SOCKET=");

	int ret = pam_authenticate (test_pamh, 0);
	if (ret != PAM_SUCCESS)
		g_printerr ("Bad user/password?\n\n");
	g_assert_cmpint (PAM_SUCCESS, ==, ret);
	
	pam_env = pam_getenvlist (test_pamh);
	while (*pam_env)
		putenv ((char*)*(pam_env++));

	ret = pam_open_session (test_pamh, 0);
	g_assert_cmpint (PAM_SUCCESS, ==, ret);
}

DEFINE_TEST(pam_env)
{
	const char *socket;

	socket = g_getenv ("GNOME_KEYRING_SOCKET");
	/* "socket should have been setup" */
	g_assert (socket && socket[0]);
	/* "socket should have been created" */
	g_assert (g_file_test (socket, G_FILE_TEST_EXISTS));

	g_printerr ("GNOME_KEYRING_SOCKET is: %s\n", g_getenv ("GNOME_KEYRING_SOCKET"));
	sleep (3);
}

DEFINE_TEST(pam_close)
{
	int ret = pam_close_session (test_pamh, 0);
	g_assert_cmpint (PAM_SUCCESS, ==, ret);
}
