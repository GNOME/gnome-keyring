/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-keytypes.c: Parsing and generating key types from SSH

   Copyright (C) 2017 Red Hat, Inc.

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

   Author: Jakub Jelen <jjelen@redhat.com>
*/

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "pkcs11/pkcs11.h"
#include "gkd-ssh-agent-private.h"

#define GKD_SSH_OID_ANSI_SECP256R1 "1.2.840.10045.3.1.7"
#define GKD_SSH_OID_ANSI_SECP384R1 "1.3.132.0.34"
#define GKD_SSH_OID_ANSI_SECP521R1 "1.3.132.0.35"

struct alg {
	gchar *name;
	CK_KEY_TYPE id;
	gchar *curve_oid;
	GChecksumType hash;
};

/* known algorithms */
static struct alg algs_known[] = {
	{ "ssh-rsa", CKK_RSA, NULL, 0 },
	{ "rsa-sha2-256", CKK_RSA, NULL, G_CHECKSUM_SHA256 },
	{ "rsa-sha2-512", CKK_RSA, NULL, G_CHECKSUM_SHA512 },
	{ "ssh-dss", CKK_DSA, NULL, 0},
	{ "ecdsa-sha2-nistp256", CKK_EC, GKD_SSH_OID_ANSI_SECP256R1, 0 },
	{ "ecdsa-sha2-nistp384", CKK_EC, GKD_SSH_OID_ANSI_SECP384R1, 0 },
	{ "ecdsa-sha2-nistp521", CKK_EC, GKD_SSH_OID_ANSI_SECP521R1, 0 },

	/* terminator */
	{ NULL, 0, 0 }
};

/* unknown algorithms */
static struct alg algs_parse_unknown[] = {
	/* no certificates */
	{ "ssh-rsa-cert-v01@openssh.com", G_MAXULONG, NULL, 0 },
	{ "ssh-dss-cert-v01@openssh.com", G_MAXULONG, NULL, 0 },
	{ "ecdsa-sha2-nistp256-cert-v01@openssh.com", G_MAXULONG, NULL, 0 },
	{ "ecdsa-sha2-nistp384-cert-v01@openssh.com", G_MAXULONG, NULL, 0 },
	{ "ecdsa-sha2-nistp521-cert-v01@openssh.com", G_MAXULONG, NULL, 0 },
	/* no new signatures/algorithms */
	{ "ssh-ed25519", G_MAXULONG, NULL, 0 },
	{ "ssh-ed25519-cert-v01@openssh.com", G_MAXULONG, NULL, 0 },

	/* terminator */
	{ NULL, 0, 0 }
};

static struct alg curves[] = {
	{ "ecdsa-sha2-nistp256", CKK_EC, GKD_SSH_OID_ANSI_SECP256R1 },
	{ "ecdsa-sha2-nistp384", CKK_EC, GKD_SSH_OID_ANSI_SECP384R1 },
	{ "ecdsa-sha2-nistp521", CKK_EC, GKD_SSH_OID_ANSI_SECP521R1 },

	/* terminator */
	{ NULL, 0, 0 }
};

typedef struct {
	const struct alg	*algs_known;
	const struct alg	*algs_parse_unknown;
	const struct alg	*curves;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	test->algs_known = algs_known;
	test->algs_parse_unknown = algs_parse_unknown;
	test->curves = curves;
}

static void
teardown (Test *test, gconstpointer unused)
{
}

static void
test_parse (Test *test, gconstpointer unused)
{
	const struct alg *a;
	gulong alg_id;

	/* known */
	for (a = test->algs_known; a->name != NULL; a++) {
		alg_id = gkd_ssh_agent_proto_keytype_to_algo (a->name);
		g_assert_cmpuint (a->id, ==, alg_id);
	}

	g_assert_cmpuint (a->id, ==, 0);

	/* we do not recognize nor fail with the unknown */
	for (a = test->algs_parse_unknown; a->name != NULL; a++) {
		alg_id = gkd_ssh_agent_proto_keytype_to_algo (a->name);
		g_assert_cmpuint (a->id, ==, alg_id);
	}

	g_assert_cmpuint (a->id, ==, 0);
}

static void
test_generate (Test *test, gconstpointer unused)
{
	const struct alg *a;

	for (a = test->algs_known; a->name != NULL; a++) {
		const gchar *alg_name = NULL;
		GQuark oid;
		switch (a->id) {
		case CKK_RSA:
			alg_name = gkd_ssh_agent_proto_rsa_algo_to_keytype (a->hash);
			break;
		case CKK_EC:
			oid = g_quark_from_string (a->curve_oid);
			alg_name = gkd_ssh_agent_proto_ecc_algo_to_keytype (oid);
			break;
		case CKK_DSA:
			alg_name = gkd_ssh_agent_proto_dsa_algo_to_keytype ();
			break;
		}
		g_assert_cmpstr (a->name, ==, alg_name);
	}
}

static void
test_curve_from_ssh (Test *test, gconstpointer unused)
{
	const struct alg *a;
	const gchar *alg_name;

	/* known */
	for (a = test->curves; a->name != NULL; a++) {
		GQuark oid = g_quark_from_string (a->curve_oid);
		alg_name = gkd_ssh_agent_proto_ecc_algo_to_keytype (oid);
		g_assert_cmpstr (a->name, ==, alg_name);
	}
}

static void
test_ssh_from_curve (Test *test, gconstpointer unused)
{
	const struct alg *a;
	const gchar *curve;
	GQuark oid;

	/* known */
	for (a = test->curves; a->name != NULL; a++) {
		/* curve is in the end of the keytype -- skip 11 chars */
		curve = a->name + 11;
		oid = gkd_ssh_agent_proto_curve_to_oid (curve);
		g_assert_cmpstr (g_quark_to_string (oid), ==, a->curve_oid);
	}

	oid = gkd_ssh_agent_proto_curve_to_oid ("nistpunknown");
	g_assert_cmpuint (oid, ==, 0);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/daemon/ssh-agent/keytypes/parse", Test, NULL, setup, test_parse, teardown);
	g_test_add ("/daemon/ssh-agent/keytypes/generate", Test, NULL, setup, test_generate, teardown);
	g_test_add ("/daemon/ssh-agent/keytypes/curve_from_ssh", Test, NULL, setup, test_curve_from_ssh, teardown);
	g_test_add ("/daemon/ssh-agent/keytypes/ssh_from_curve", Test, NULL, setup, test_ssh_from_curve, teardown);

	return g_test_run ();
}
