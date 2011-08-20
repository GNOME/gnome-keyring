/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2011 Collabora Ltd

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

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#include "config.h"

#include "gcr/gcr.h"

#include <glib.h>

#include <errno.h>

typedef struct {
	GcrSecretExchange *caller;
	GcrSecretExchange *callee;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	test->caller = gcr_secret_exchange_new ();
	g_assert (GCR_IS_SECRET_EXCHANGE (test->caller));
	test->callee = gcr_secret_exchange_new ();
	g_assert (GCR_IS_SECRET_EXCHANGE (test->callee));
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	g_object_unref (test->caller);
	g_assert (!GCR_IS_SECRET_EXCHANGE (test->caller));
	g_object_unref (test->callee);
	g_assert (!GCR_IS_SECRET_EXCHANGE (test->callee));
}

static void
test_perform_exchange (Test *test,
                       gconstpointer unused)
{
	gchar *exchange;

	exchange = gcr_secret_exchange_begin (test->caller);
	g_assert (exchange);

	if (!gcr_secret_exchange_receive (test->callee, exchange))
		g_assert_not_reached ();

	g_free (exchange);

	exchange = gcr_secret_exchange_send (test->callee, "the secret", -1);
	g_assert (exchange);

	if (!gcr_secret_exchange_receive (test->caller, exchange))
		g_assert_not_reached ();

	g_assert_cmpstr (gcr_secret_exchange_get_secret (test->caller, NULL), ==, "the secret");

	g_free (exchange);
}

static void
test_perform_reverse (Test *test,
                       gconstpointer unused)
{
	gchar *exchange;

	exchange = gcr_secret_exchange_begin (test->caller);
	g_assert (exchange);

	if (!gcr_secret_exchange_receive (test->callee, exchange))
		g_assert_not_reached ();

	g_free (exchange);

	exchange = gcr_secret_exchange_send (test->callee, NULL, -1);
	g_assert (exchange);

	if (!gcr_secret_exchange_receive (test->caller, exchange))
		g_assert_not_reached ();

	g_free (exchange);

	g_assert (gcr_secret_exchange_get_secret (test->caller, NULL) == NULL);

	exchange = gcr_secret_exchange_send (test->caller, "reverse secret", -1);
	g_assert (exchange);

	if (!gcr_secret_exchange_receive (test->callee, exchange))
		g_assert_not_reached ();

	g_free (exchange);

	g_assert_cmpstr (gcr_secret_exchange_get_secret (test->callee, NULL), ==, "reverse secret");
}

static void
test_perform_multiple (Test *test,
                       gconstpointer unused)
{
	gchar *exchange;

	exchange = gcr_secret_exchange_begin (test->caller);
	g_assert (exchange);

	if (!gcr_secret_exchange_receive (test->callee, exchange))
		g_assert_not_reached ();

	g_free (exchange);

	exchange = gcr_secret_exchange_send (test->callee, "first secret", -1);
	g_assert (exchange);

	if (!gcr_secret_exchange_receive (test->caller, exchange))
		g_assert_not_reached ();

	g_free (exchange);

	g_assert_cmpstr (gcr_secret_exchange_get_secret (test->caller, NULL), ==, "first secret");

	exchange = gcr_secret_exchange_send (test->callee, "second secret", -1);
	g_assert (exchange);

	if (!gcr_secret_exchange_receive (test->caller, exchange))
		g_assert_not_reached ();

	g_free (exchange);

	g_assert_cmpstr (gcr_secret_exchange_get_secret (test->caller, NULL), ==, "second secret");
}

int
main (int argc, char **argv)
{
	g_type_init ();
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-secret-exchange");

	g_test_add ("/gcr/secret-exchange/perform-exchange", Test, NULL, setup, test_perform_exchange, teardown);
	g_test_add ("/gcr/secret-exchange/perform-reverse", Test, NULL, setup, test_perform_reverse, teardown);
	g_test_add ("/gcr/secret-exchange/perform-multiple", Test, NULL, setup, test_perform_multiple, teardown);

	return g_test_run ();
}
