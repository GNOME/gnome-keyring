/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-ssh-openssh.c: Test OpenSSH parsing

   Copyright (C) 2008 Stefan Walter

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

#include "gck-secret-compat.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

DEFINE_TEST(access_free)
{
	GckSecretAccess *ac;

	ac = g_new0 (GckSecretAccess, 1);
	ac->pathname = g_strdup ("/path");
	ac->display_name = g_strdup ("Display");
	ac->types_allowed = GCK_SECRET_ACCESS_READ;
	
	gck_secret_compat_access_free (ac);
}

DEFINE_TEST(acl_free)
{
	GckSecretAccess *ac;
	GList *acl = NULL;
	int i;
	
	for (i = 0; i < 10; ++i) {
		ac = g_new0 (GckSecretAccess, 1);
		ac->pathname = g_strdup ("/path");
		ac->display_name = g_strdup ("Display");
		ac->types_allowed = GCK_SECRET_ACCESS_READ;
		acl = g_list_prepend (acl, ac);
	}
	
	gck_secret_compat_acl_free (acl);
}
