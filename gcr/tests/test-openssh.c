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
#include "gcr/gcr-openssh.h"

#include "egg/egg-testing.h"

#include <gcrypt.h>
#include <glib.h>
#include <string.h>

typedef struct {
	const gchar *expected_label;
	const gchar *expected_options;
} Test;

#define OPENSSH_PUBLIC_RSA1 \
	"2048 65537 19574029774826276058535216798260123376543523095248321838931" \
	"8476099051534660565418100376122247153936738716140984293302866595208305" \
	"7124376564328644357957081508003798389808113087527047927841196160520784" \
	"3971799891833860159372766201922902824211581515042106928142039998651198" \
	"7806024885997262427984841536983221992403267030558391252672804492615887" \
	"9294713324466630490990131504557923061505441555447586185019409756877006" \
	"5871190731807718592844942425524851665039303855329966512492845780563670" \
	"0617451083369174928502647995734856960603065454655489558179113130210712" \
	"74638931037011169213563881172297734240201883475566393175838117784693 r" \
	"sa-key@example.com\n"

#define OPENSSH_PUBLIC_RSA2 \
	"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCs8z2y0cCPYRAPkq8tAt6FC/kdfnR/p" \
	"8B2ZoY0oiLNt7kQEwJfexgwLqTxWYd2fSDUSSDPrsqAxZAwLLS/eF04kXiJO2VfqAWFpTL" \
	"NToERHpFF1yZQe26ELTlNNfna7LqfCRvpNDwu6AqndsT3eFt7DWvBDXbbEiTLW21Z2OFAA" \
	"H/J2iCFn4c0a8Myf7IaMYcy5GG3mpk39kEO4aNV/67U7kfooek24ObwD0vlXzlsi5VZIUF" \
	"OIUi0UdkNEMCtUWpfkZ1STUlmwp9HVM7xb7/9PESQKDnZdxpB09S9cIjdpDecpDlMDDEbE" \
	"UECM1PIas3ndhB7gAN1i2JsPHTcXZ1 rsa-key@example.com\r\n" \
	"# Comment\n"

#define OPENSSH_PUBLIC_DSA2 \
	"ssh-dss AAAAB3NzaC1kc3MAAACBAL4z+ad0ZJYzMOQuGp00UJ+AijKhrPVUEYLcxBmFQo" \
	"nb/KIlLSWJua4Rl9DB4tDj30Y9c/oApqC4n+FIYlUZMSnxmpvcLF6aeXOiHHPvm0EDYjjy" \
	"VubyYQWI7CROrrzSc+x++ha3TuJEvF3PlKlZmTKKVYEkZNjwFqYysGyPxPalAAAAFQDtDS" \
	"EF9Gvnv5fQtSbbsp7j78uVBwAAAIAtNpAg/Mbd/E2241enedB9AxAbJWZ5QYnoPe6/zx5d" \
	"OmU7+qz8mG6tgvF8F7IgXPabuAKslzTDGS3zgaEhWicDS3CIYik2UR8hXdxfovIEqZKZe7" \
	"u02FCEoXYCEiFUAdzDGzjI7PswgtEJWWNqKeNis3HmDDha9lMkqz/3fLZGXwAAAIEAiaRP" \
	"YKZDMoJG+aVZ5A3R/m2gl+mYE2MsjPKXuBKcrZ6ItA9BMe4G/An0/+E3A+DuoGxdeNNMF8" \
	"U9Dy2N8Sch/Ngtg2E/FBo5geljWobJXd1jxmPtF2WAliYJXDdIt6RBVPGL9H/KSjDmBMsV" \
	"d42wxVJywawzypklVZjSUuWuBMI= dsa-key@example.com \n"

#define EXTRA_LINES_WITHOUT_KEY \
	"\n# Comment\n\n" \
	"20aa3\n" \
	"not a key\n"

static void
setup (Test *test,
       gconstpointer unused)
{

}

static void
teardown (Test *test,
          gconstpointer unused)
{

}

static void
on_openssh_pub_parse (GckAttributes *attrs,
                      const gchar *label,
                      const gchar *options,
                      const gchar *outer,
                      gsize n_outer,
                      gpointer user_data)
{
	Test *test = user_data;
	guint keys;

	if (test->expected_label)
		g_assert_cmpstr (label, ==, test->expected_label);
	if (test->expected_options)
		g_assert_cmpstr (options, ==, test->expected_options);

	/* The block should parse properly */
	keys = _gcr_openssh_pub_parse (outer, n_outer, NULL, NULL);
	g_assert_cmpuint (keys, ==, 1);
}

static void
test_parse_v1_rsa (Test *test,
                   gconstpointer unused)
{
	const gchar *data = OPENSSH_PUBLIC_RSA1 EXTRA_LINES_WITHOUT_KEY;
	gint keys;

	test->expected_label = "rsa-key@example.com";

	keys = _gcr_openssh_pub_parse (data, strlen (data),
	                               on_openssh_pub_parse, test);
	g_assert_cmpint (keys, ==, 1);

}

static void
test_parse_v2_rsa (Test *test,
                   gconstpointer unused)
{
	const gchar *data = OPENSSH_PUBLIC_RSA2 EXTRA_LINES_WITHOUT_KEY;
	gint keys;

	test->expected_label = "rsa-key@example.com";

	keys = _gcr_openssh_pub_parse (data, strlen (data),
	                               on_openssh_pub_parse, test);
	g_assert_cmpint (keys, ==, 1);
}

static void
test_parse_v2_dsa (Test *test,
               gconstpointer unused)
{
	const gchar *data = OPENSSH_PUBLIC_DSA2 EXTRA_LINES_WITHOUT_KEY;
	gint keys;

	test->expected_label = "dsa-key@example.com";

	keys = _gcr_openssh_pub_parse (data, strlen (data),
	                               on_openssh_pub_parse, test);
	g_assert_cmpint (keys, ==, 1);
}

static void
test_parse_v1_options (Test *test,
                       gconstpointer unused)
{
	const gchar *data = "option1,option2=\"value 2\",option3 " OPENSSH_PUBLIC_RSA1;
	gint keys;

	test->expected_options = "option1,option2=\"value 2\",option3";

	keys = _gcr_openssh_pub_parse (data, strlen (data),
	                               on_openssh_pub_parse, test);
	g_assert_cmpint (keys, ==, 1);
}

static void
test_parse_v2_options (Test *test,
                       gconstpointer unused)
{
	const gchar *data = "option1,option2=\"value 2\",option3 " OPENSSH_PUBLIC_RSA2;
	gint keys;

	test->expected_options = "option1,option2=\"value 2\",option3";

	keys = _gcr_openssh_pub_parse (data, strlen (data),
	                               on_openssh_pub_parse, test);
	g_assert_cmpint (keys, ==, 1);
}

int
main (int argc, char **argv)
{
	g_type_init ();
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-gnupg-process");

	g_test_add ("/gcr/openssh/parse_v1_rsa", Test, NULL, setup, test_parse_v1_rsa, teardown);
	g_test_add ("/gcr/openssh/parse_v2_rsa", Test, NULL, setup, test_parse_v2_rsa, teardown);
	g_test_add ("/gcr/openssh/parse_v2_dsa", Test, NULL, setup, test_parse_v2_dsa, teardown);
	g_test_add ("/gcr/openssh/parse_v1_options", Test, NULL, setup, test_parse_v1_options, teardown);
	g_test_add ("/gcr/openssh/parse_v2_options", Test, NULL, setup, test_parse_v2_options, teardown);

	return egg_tests_run_in_thread_with_loop ();
}
