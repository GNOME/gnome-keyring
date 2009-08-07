/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-login.c: Test gck-login.c 

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

#include "run-auto-test.h"

#include "gck/gck-login.h"

DEFINE_TEST(test_login)
{
	GckLogin *login;
	const gchar *password;
	gsize n_password;
	
	login = gck_login_new ((CK_UTF8CHAR_PTR)"test-pin", 8);
	g_assert (GCK_IS_LOGIN (login));
	
	password = gck_login_get_password (login, &n_password);
	g_assert (password);
	g_assert_cmpuint (n_password, ==, 8);
	g_assert (memcmp (password, "test-pin", 8) == 0);
	
	g_assert (gck_login_equals (login, (CK_UTF8CHAR_PTR)"test-pin", 8));
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"test-pino", 9));
	g_assert (!gck_login_equals (login, NULL, 0));
	g_assert (gck_login_equals (login, (CK_UTF8CHAR_PTR)"test-pin", -1));
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"", 0));
	
	g_object_unref (login);
}

DEFINE_TEST(test_null_terminated)
{
	GckLogin *login;
	const gchar *password;
	gsize n_password;
	
	login = gck_login_new ((CK_UTF8CHAR_PTR)"null-terminated", -1);
	g_assert (GCK_IS_LOGIN (login));
	
	password = gck_login_get_password (login, &n_password);
	g_assert (password);
	g_assert_cmpstr (password, ==, "null-terminated");
	g_assert_cmpuint (n_password, ==, strlen ("null-terminated"));
	
	g_assert (gck_login_equals (login, (CK_UTF8CHAR_PTR)"null-terminated", strlen ("null-terminated")));
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"test-pino", 9));
	g_assert (!gck_login_equals (login, NULL, 0));
	g_assert (gck_login_equals (login, (CK_UTF8CHAR_PTR)"null-terminated", -1));
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"", 0));

	g_object_unref (login);
}

DEFINE_TEST(test_null)
{
	GckLogin *login;
	const gchar *password;
	gsize n_password;
	
	login = gck_login_new (NULL, 0);
	g_assert (GCK_IS_LOGIN (login));
	
	password = gck_login_get_password (login, &n_password);
	g_assert (password == NULL);
	g_assert_cmpuint (n_password, ==, 0);
	
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"null-terminated", strlen ("null-terminated")));
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"test-pino", 9));
	g_assert (gck_login_equals (login, NULL, 0));
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"null-terminated", -1));
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"", 0));

	g_object_unref (login);
}

DEFINE_TEST(test_empty)
{
	GckLogin *login;
	const gchar *password;
	gsize n_password;
	
	login = gck_login_new ((CK_UTF8CHAR_PTR)"", 0);
	g_assert (GCK_IS_LOGIN (login));
	
	password = gck_login_get_password (login, &n_password);
	g_assert_cmpstr (password, ==, "");
	g_assert_cmpuint (n_password, ==, 0);
	
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"null-terminated", strlen ("null-terminated")));
	g_assert (!gck_login_equals (login, (CK_UTF8CHAR_PTR)"test-pino", 9));
	g_assert (!gck_login_equals (login, NULL, 0));
	g_assert (gck_login_equals (login, (CK_UTF8CHAR_PTR)"", -1));
	g_assert (gck_login_equals (login, (CK_UTF8CHAR_PTR)"", 0));

	g_object_unref (login);
}
