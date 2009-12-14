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

#include "gck/gck-secret.h"
#include "gck/gck-transaction.h"

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

DEFINE_TEST(secret_data_get_raw)
{
	GckSecretData *data = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	GckSecret *secret = gck_secret_new_from_password ("barn");
	const guchar *raw;
	gsize n_raw;

	gck_secret_data_set_secret (data, "my-identifier", secret);
	g_object_unref (secret);

	raw = gck_secret_data_get_raw (data, "my-identifier", &n_raw);
	g_assert (raw);
	g_assert_cmpuint (n_raw, ==, 4);
	g_assert (memcmp (raw, "barn", 4) == 0);

	raw = gck_secret_data_get_raw (data, "not-identifier", &n_raw);
	g_assert (raw == NULL);

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

DEFINE_TEST(secret_data_set_transacted)
{
	GckTransaction *transaction = gck_transaction_new ();
	GckSecretData *data = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	GckSecret *secret = gck_secret_new_from_password ("barn");

	/* Transaction, but not complete */
	gck_secret_data_set_transacted (data, transaction, "my-identifier", secret);
	g_assert (!gck_transaction_get_failed (transaction));
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == secret);

	/* Transaction complete */
	gck_transaction_complete (transaction);
	g_assert (!gck_transaction_get_failed (transaction));
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == secret);

	g_object_unref (data);
	g_object_unref (secret);
	g_object_unref (transaction);
}

DEFINE_TEST(secret_data_set_transacted_replace)
{
	GckTransaction *transaction = gck_transaction_new ();
	GckSecretData *data = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	GckSecret *old = gck_secret_new_from_password ("old");
	GckSecret *secret = gck_secret_new_from_password ("secret");

	/* The old secret */
	gck_secret_data_set_secret (data, "my-identifier", old);
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == old);

	/* Transaction, but not complete */
	gck_secret_data_set_transacted (data, transaction, "my-identifier", secret);
	g_assert (!gck_transaction_get_failed (transaction));
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == secret);

	/* Transaction complete */
	gck_transaction_complete (transaction);
	g_assert (!gck_transaction_get_failed (transaction));
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == secret);

	g_object_unref (old);
	g_object_unref (data);
	g_object_unref (secret);
	g_object_unref (transaction);
}

DEFINE_TEST(secret_data_set_transacted_fail)
{
	GckTransaction *transaction = gck_transaction_new ();
	GckSecretData *data = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	GckSecret *secret = gck_secret_new_from_password ("barn");

	/* Transaction, but not complete */
	gck_secret_data_set_transacted (data, transaction, "my-identifier", secret);
	g_assert (!gck_transaction_get_failed (transaction));
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == secret);

	/* Transaction fails here */
	gck_transaction_fail (transaction, CKR_CANCEL);
	gck_transaction_complete (transaction);
	g_assert (gck_transaction_get_failed (transaction));
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == NULL);

	g_object_unref (data);
	g_object_unref (secret);
	g_object_unref (transaction);
}

DEFINE_TEST(secret_data_set_transacted_fail_revert)
{
	GckTransaction *transaction = gck_transaction_new ();
	GckSecretData *data = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	GckSecret *old = gck_secret_new_from_password ("old");
	GckSecret *secret = gck_secret_new_from_password ("secret");

	/* The old secret */
	gck_secret_data_set_secret (data, "my-identifier", old);
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == old);

	/* Transaction, but not complete */
	gck_secret_data_set_transacted (data, transaction, "my-identifier", secret);
	g_assert (!gck_transaction_get_failed (transaction));
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == secret);

	/* Transaction fails here */
	gck_transaction_fail (transaction, CKR_CANCEL);
	gck_transaction_complete (transaction);
	g_assert (gck_transaction_get_failed (transaction));
	g_assert (gck_secret_data_get_secret (data, "my-identifier") == old);

	g_object_unref (old);
	g_object_unref (data);
	g_object_unref (secret);
	g_object_unref (transaction);
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
