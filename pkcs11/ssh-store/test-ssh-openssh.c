/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "egg/egg-secure-memory.h"

#include "ssh-store/gkm-ssh-openssh.h"

#include "gkm/gkm-sexp.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

static const gchar *PRIVATE_FILES[] = {
	SRCDIR "/pkcs11/ssh-store/fixtures/id_rsa_encrypted",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_rsa_plain",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_dsa_encrypted",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_dsa_plain",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_encrypted",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_plain",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_384",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_521"
};

static const gchar *PUBLIC_FILES[] = {
	SRCDIR "/pkcs11/ssh-store/fixtures/id_rsa_test.pub",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_dsa_test.pub",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_test.pub",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_384.pub",
	SRCDIR "/pkcs11/ssh-store/fixtures/id_ecdsa_521.pub"
};

#define COMMENT "A public key comment"

static void
test_parse_public (void)
{
	gcry_sexp_t sexp;
	gchar *comment;
	gchar *data;
	gsize n_data;
	int algorithm;
	gboolean is_private;
	guint i;
	GkmDataResult res;


	for (i = 0; i < G_N_ELEMENTS (PUBLIC_FILES); ++i) {

		if (!g_file_get_contents (PUBLIC_FILES[i], &data, &n_data, NULL))
			g_assert_not_reached ();

		res = gkm_ssh_openssh_parse_public_key (data, n_data, &sexp, &comment);
		if (res != GKM_DATA_SUCCESS) {
			g_warning ("couldn't parse public key: %s", PUBLIC_FILES[i]);
			g_assert_cmpint (res, ==, GKM_DATA_SUCCESS);
		}

		if (!gkm_sexp_parse_key (sexp, &algorithm, &is_private, NULL))
			g_assert_not_reached ();

		g_assert_cmpstr (comment, ==, COMMENT);
		g_assert_cmpint (algorithm, !=, 0);
		g_assert (!is_private);

		g_free (data);
		g_free (comment);
		gcry_sexp_release (sexp);
	}
}

static void
test_parse_private (void)
{
	gcry_sexp_t sexp;
	gchar *data;
	gsize n_data;
	int algorithm;
	gboolean is_private;
	GBytes *bytes;
	guint i;
	GkmDataResult res;


	for (i = 0; i < G_N_ELEMENTS (PRIVATE_FILES); ++i) {

		if (!g_file_get_contents (PRIVATE_FILES[i], &data, &n_data, NULL))
			g_assert_not_reached ();

		bytes = g_bytes_new_take (data, n_data);
		res = gkm_ssh_openssh_parse_private_key (bytes, "password", 8, &sexp);
		g_bytes_unref (bytes);

		if (res != GKM_DATA_SUCCESS) {
			g_warning ("couldn't parse private key: %s", PRIVATE_FILES[i]);
			g_assert_cmpint (res, ==, GKM_DATA_SUCCESS);
		}

		if (!gkm_sexp_parse_key (sexp, &algorithm, &is_private, NULL))
			g_assert_not_reached ();

		g_assert_cmpint (algorithm, !=, 0);
		g_assert (is_private);

		gcry_sexp_release (sexp);
	}
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/ssh-store/openssh/parse_private", test_parse_private);
	g_test_add_func ("/ssh-store/openssh/parse_public", test_parse_public);

	return g_test_run ();
}
