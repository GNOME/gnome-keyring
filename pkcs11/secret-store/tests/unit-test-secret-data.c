/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-secret-compat.c: Test secret compat files

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

#include "gck-secret-data.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

DEFINE_TEST(secret_data_new)
{
	GckSecretData *data = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	g_assert (GCK_IS_SECRET_DATA (data));
	g_object_unref (data);
}

DEFINE_TEST(secret_data_get_set)
{
	GckSecretData *data = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	GckSecret *secret = gck_secret_new_from_password ("barn");
	GckSecret *check;
	
	gck_secret_data_set_secret (data, "my-identifier", secret);
	g_object_unref (secret);
	
	check = gck_secret_data_get_secret (data, "my-identifier");
	g_assert (GCK_IS_SECRET (check));
	g_assert (secret == check);
	g_assert (gck_secret_equals (check, (guchar*)"barn", -1));
	
	g_object_unref (data);
}

DEFINE_TEST(secret_data_remove)
{
	GckSecretData *data = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	GckSecret *secret = gck_secret_new_from_password ("barn");

	gck_secret_data_set_secret (data, "my-identifier", secret);
	g_object_unref (secret);
	
	secret = gck_secret_data_get_secret (data, "my-identifier");
	g_assert (GCK_IS_SECRET (secret));

	gck_secret_data_remove_secret (data, "my-identifier");
	secret = gck_secret_data_get_secret (data, "my-identifier");
	g_assert (!secret);
	
	g_object_unref (data);
}

DEFINE_TEST(secret_data_get_set_master)
{
	GckSecretData *data = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	GckSecret *master = gck_secret_new_from_password ("master");
	GckSecret *check;
	
	gck_secret_data_set_master (data, master);
	g_object_unref (master);
	
	check = gck_secret_data_get_master (data);
	g_assert (GCK_IS_SECRET (check));
	g_assert (master == check);
	g_assert (gck_secret_equals (check, (guchar*)"master", -1));
	
	g_object_unref (data);
}
