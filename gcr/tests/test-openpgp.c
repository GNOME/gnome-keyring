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
#include "gcr/gcr-openpgp.h"
#include "gcr/gcr-record.h"

#include "egg/egg-armor.h"
#include "egg/egg-testing.h"

#include <gcrypt.h>
#include <glib.h>
#include <string.h>

typedef struct {
	const gchar *name;
	const gchar **records;
	const gchar *filename;
	const gchar *version;
	GcrOpenpgpParseFlags flags;
} Fixture;

static const gchar *werner_koch_records[] = {
	"pub:e:1024:17:68B7AB8957548DCD:899816990:1136043547::o:::sca:\n"
	"uid:e::::1102866526::B712A25DC2ABEF1579696C2925859931078C2C3E::Werner Koch (gnupg sig) <dd9jn@gnu.org>:\n",

	"pub:e:1024:17:5DE249965B0358A2:921520361:1247335656::o:::sc:\n"
	"uid:e::::1113145458::F5B5738FAFB7543A01BAB31A6D767FBC789FF8A8::Werner Koch <wk@gnupg.org>:\n"
	"uid:e::::1113145466::60095F7DAD08129CCE39E15BEB6BBE21937E3AA6::Werner Koch <wk@g10code.com>:\n"
	"uid:e::::921520362::392B892CF897AD0F03EB26343C4C20A48B36513E::Werner Koch:\n"
	"uid:e::::1113145466::3E000C0F7D13A3C57C633C16ABDC97F12EAF16C1::Werner Koch <werner@fsfe.org>:\n"
	"sub:e:1024:17:60784E94010A57ED:1079892559:1199124559:::::s:\n"
	"sub:e:2048:1:7299C628B604F148:1079892777:1136052777:::::e:\n"
	"sub:e:2048:1:35E52D69C3680A6E:1136137762:1199123362:::::e:\n",

	"pub:e:1024:1:53B620D01CE0C630:1136130759:1230738759::o:::sc:\n"
	"uid:e::::1136130760::142B958D9816ECF810DBB83BD257E5C7DB36C99A::Werner Koch (dist sig) <dd9jn@gnu.org>:\n",

	NULL
};

static const gchar *werner_sig_records[] = {
	"pub:e:1024:17:68B7AB8957548DCD:899816990:1136043547::o:::sca:\n"
	"uid:e::::1102866526::B712A25DC2ABEF1579696C2925859931078C2C3E::Werner Koch (gnupg sig) <dd9jn@gnu.org>:\n"
	"sig:::17:68B7AB8957548DCD:1102866526:::::13x:\n",

	"pub:e:1024:17:5DE249965B0358A2:921520361:1247335656::o:::sc:\n"
	"uid:e::::1113145458::F5B5738FAFB7543A01BAB31A6D767FBC789FF8A8::Werner Koch <wk@gnupg.org>:\n"
	"sig:::17:5DE249965B0358A2:1113145458:::::13x:\n"
	"uid:e::::1113145466::60095F7DAD08129CCE39E15BEB6BBE21937E3AA6::Werner Koch <wk@g10code.com>:\n"
	"sig:::17:5DE249965B0358A2:1113145466:::::13x:\n"
	"uid:e::::921520362::392B892CF897AD0F03EB26343C4C20A48B36513E::Werner Koch:\n"
	"sig:::17:5DE249965B0358A2:921520362:::::13x:\n"
	"uid:e::::1113145466::3E000C0F7D13A3C57C633C16ABDC97F12EAF16C1::Werner Koch <werner@fsfe.org>:\n"
	"sig:::17:5DE249965B0358A2:1113145466:::::13x:\n"
	"sub:e:1024:17:60784E94010A57ED:1079892559:1199124559:::::s:\n"
	"sig:::17:5DE249965B0358A2:1148562461:::::18x:\n"
	"sub:e:2048:1:7299C628B604F148:1079892777:1136052777:::::e:\n"
	"sig:::17:5DE249965B0358A2:1079892777:::::18x:\n"
	"sub:e:2048:1:35E52D69C3680A6E:1136137762:1199123362:::::e:\n"
	"sig:::17:5DE249965B0358A2:1136137762:::::18x:\n",

	"pub:e:1024:1:53B620D01CE0C630:1136130759:1230738759::o:::sc:\n"
	"uid:e::::1136130760::142B958D9816ECF810DBB83BD257E5C7DB36C99A::Werner Koch (dist sig) <dd9jn@gnu.org>:\n"
	"sig:::1:53B620D01CE0C630:1136130760:::::13x:\n",

	NULL
};

static const gchar *pubring_records[] = {
	"pub:o:2048:1:4842D952AFC000FD:1305189489:::o:::scSCE:\n"
	"uid:o::::1305189489::D449F1605254754B0BBFA424FC34E50609103BBB::Test Number 1 (unlimited) <test-number-1@example.com>:\n"
	"uid:o::::1305189849::D0A8FA7B15DC4BE3F8F03A49C372F2718C78AFC0::Dr. Strangelove <lovingbomb@example.com>:\n"
	"sub:o:2048:1:4852132BBED15014:1305189489::::::e:\n",

	"pub:e:1024:1:268FEE686262C395:1305189628:1305276028::o:::sc:\n"
	"uid:e::::1305189628::2E9D48BD771DA765D2B48A0233D0E8F393F6E839::Test Number 2 (all gone) <test-number-2@example.com>:\n"
	"sub:e:1024:1:C5877FABF4772E4F:1305189628:1305276028:::::e:\n",

	"pub:e:1024:17:68B7AB8957548DCD:899816990:1136043547::o:::sca:\n"
	"uid:e::::1102866526::B712A25DC2ABEF1579696C2925859931078C2C3E::Werner Koch (gnupg sig) <dd9jn@gnu.org>:\n",

	"pub:e:1024:17:5DE249965B0358A2:921520361:1247335656::o:::sc:\n"
	"uid:e::::1113145458::F5B5738FAFB7543A01BAB31A6D767FBC789FF8A8::Werner Koch <wk@gnupg.org>:\n"
	"uid:e::::1113145466::60095F7DAD08129CCE39E15BEB6BBE21937E3AA6::Werner Koch <wk@g10code.com>:\n"
	"uid:e::::921520362::392B892CF897AD0F03EB26343C4C20A48B36513E::Werner Koch:\n"
	"uid:e::::1113145466::3E000C0F7D13A3C57C633C16ABDC97F12EAF16C1::Werner Koch <werner@fsfe.org>:\n"
	"sub:e:1024:17:60784E94010A57ED:1079892559:1199124559:::::s:\n"
	"sub:e:2048:1:7299C628B604F148:1079892777:1136052777:::::e:\n"
	"sub:e:2048:1:35E52D69C3680A6E:1136137762:1199123362:::::e:\n",

	"pub:o:1024:17:C7463639B2D7795E:978642983:::o:::scSCE:\n"
	"rvk:o::17::::::3FC732041D23E9EA66DDB5009C9DBC21DF74DC61:80:\n"
	"uid:o::::978642983::44C6F00AAE524A8955CAB76F2BB16126530BB203::Philip R. Zimmermann <prz@mit.edu>:\n"
	"uid:o::::978643127::BD93DF0D0D564E85F73ECBECFFB1B5BA5FF2838D::Philip R. Zimmermann <prz@acm.org>:\n"
	"uat:o::::978751266::E0F87F37495D4ED247BB66A08D7360D8D81F9976::1 3391:\n"
	"uat:o::::1013326898::10A2C49F62C540090ECD679C518AACAA8E960BA5::1 3479:\n"
	"uid:o::::1052692250::09D1F68A1C44AC42E7FCC5615EEDBB0FD581DCDE::Philip R. Zimmermann <prz@philzimmermann.com>:\n"
	"sub:o:3072:16:C4EB1C56A8E92834:978642983::::::e:\n",

	"pub:o:4096:1:DB698D7199242560:1012189561:::o:::scSCEA:\n"
	"uid:o::::1012189561::0E5FC22DD5518890217F20F1FF832597932B46C1::David M. Shaw <dshaw@jabberwocky.com>:\n"
	"sub:o:2048:16:AE2827D11643B926:1012189956:1327549956:::::e:\n"
	"sub:o:1024:17:E2665C8749E1CBC9:1012190171:1327550171:::::sca:\n",

	"pub:o:2048:1:9710B89BCA57AD7C:1102303986:::o:::scSC:\n"
	"uid:o::::1112650864::A96F758EFD5D67EA9450860C7D15A96DAA1B40E2::PGP Global Directory Verification Key:\n"
	"uat:o::::1112650864::83B0B68B95892BBCE32F04BA0FBAC6CEAD4EDE49::1 3422:\n",

	"pub:e:1024:1:53B620D01CE0C630:1136130759:1230738759::o:::sc:\n"
	"uid:e::::1136130760::142B958D9816ECF810DBB83BD257E5C7DB36C99A::Werner Koch (dist sig) <dd9jn@gnu.org>:\n",

	NULL
};

static const gchar *secring_records[] = {
	"sec::2048:1:4842D952AFC000FD:1305189489::::::::::\n"
	"uid:::::::D449F1605254754B0BBFA424FC34E50609103BBB::Test Number 1 (unlimited) <test-number-1@example.com>:\n"
	"uid:::::::D0A8FA7B15DC4BE3F8F03A49C372F2718C78AFC0::Dr. Strangelove <lovingbomb@example.com>:\n"
	"ssb::2048:1:4852132BBED15014:1305189489::::::::::\n",

	"sec::1024:1:268FEE686262C395:1305189628:1305276028:::::::::\n"
	"uid:::::::2E9D48BD771DA765D2B48A0233D0E8F393F6E839::Test Number 2 (all gone) <test-number-2@example.com>:\n"
	"ssb::1024:1:C5877FABF4772E4F:1305189628::::::::::\n",

	NULL
};

static Fixture fixtures[] = {
	{
	  "werner_koch",
	  werner_koch_records,
	  SRCDIR "/files/werner-koch.asc",
	  "GnuPG v1.4.11 (GNU/Linux)",
	  GCR_OPENPGP_PARSE_KEYS
	},
	{
	  "werner_koch_with_sigs",
	  werner_sig_records,
	  SRCDIR "/files/werner-koch.asc",
	  "GnuPG v1.4.11 (GNU/Linux)",
	  GCR_OPENPGP_PARSE_KEYS | GCR_OPENPGP_PARSE_SIGNATURES
	},
	{
	  "pubring",
	  pubring_records,
	  SRCDIR "/files/pubring.gpg",
	  NULL,
	  GCR_OPENPGP_PARSE_KEYS
	},
	{
	  "secring",
	  secring_records,
	  SRCDIR "/files/secring.gpg",
	  NULL,
	  GCR_OPENPGP_PARSE_KEYS
	}
};

typedef struct {
	const gchar **at;
	const Fixture *fixture;
} Test;

static void
setup (Test *test,
       gconstpointer data)
{
	const Fixture *fixture = data;
	test->fixture = fixture;
	test->at = fixture->records;
}

static void
teardown (Test *test,
          gconstpointer data)
{

}

static void
compare_fixture_with_records (const gchar *fixture,
                              GPtrArray *records)
{
	gchar *record;
	gchar **lines;
	guint i;

	lines = g_strsplit (fixture, "\n", -1);
	for (i = 0; i < records->len; i++) {
		record = _gcr_record_format (records->pdata[i]);
		g_assert_cmpstr (record, ==, lines[i]);
		g_free (record);
	}

	if (lines[i] == NULL) {
		g_test_message ("more openpgp records parsed than in fixture");
		g_assert_not_reached ();
	}

	g_strfreev (lines);
}

static void
on_openpgp_packet  (GPtrArray *records,
                    const guchar *outer,
                    gsize n_outer,
                    gpointer user_data)
{
	Test *test = user_data;
	guint seen;

	/* Should be parseable again */
	seen = _gcr_openpgp_parse (outer, n_outer, test->fixture->flags |
	                           GCR_OPENPGP_PARSE_NO_RECORDS, NULL, NULL);
	g_assert_cmpuint (seen, ==, 1);

	if (*(test->at) == NULL) {
		g_test_message ("more openpgp packets parsed than in fixture");
		g_assert_not_reached ();
	}

	compare_fixture_with_records (*(test->at), records);
	test->at++;
}

static void
on_armor_parsed (GQuark type,
                 const guchar *data,
                 gsize n_data,
                 const gchar *outer,
                 gsize n_outer,
                 GHashTable *headers,
                 gpointer user_data)
{
	Test *test = user_data;
	const gchar *value;
	guint seen;

	if (test->fixture->version) {
		value = g_hash_table_lookup (headers, "Version");
		g_assert_cmpstr (value, ==, test->fixture->version);
	}

	seen = _gcr_openpgp_parse (data, n_data, test->fixture->flags,
	                           on_openpgp_packet, test);
	g_assert_cmpuint (seen, >, 0);

	if (*(test->at) != NULL) {
		g_test_message ("less openpgp packets parsed than in fixture");
		g_assert_not_reached ();
	}
}

static void
test_openpgp_armor (Test *test,
                    gconstpointer data)
{
	GError *error = NULL;
	gchar *armor;
	gsize length;
	guint parts;

	g_file_get_contents (test->fixture->filename, &armor, &length, &error);
	g_assert_no_error (error);

	parts = egg_armor_parse (armor, length, on_armor_parsed, test);
	g_assert_cmpuint (parts, ==, 1);

	g_free (armor);
}

static void
test_openpgp_binary (Test *test,
                     gconstpointer data)
{
	GError *error = NULL;
	gchar *binary;
	gsize length;
	guint seen;

	g_file_get_contents (test->fixture->filename, &binary, &length, &error);
	g_assert_no_error (error);

	seen = _gcr_openpgp_parse (binary, length, test->fixture->flags,
	                           on_openpgp_packet, test);
	g_assert_cmpuint (seen, >, 0);

	if (*(test->at) != NULL) {
		g_test_message ("less openpgp packets parsed than in fixture");
		g_assert_not_reached ();
	}

	g_free (binary);
}

int
main (int argc, char **argv)
{
	guint i;
	gchar *test_path;

	g_type_init ();
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-openpgp");

	for (i = 0; i < G_N_ELEMENTS (fixtures); i++) {
		test_path = g_strdup_printf ("/gcr/openpgp/%s", fixtures[i].name);
		if (g_str_has_suffix (fixtures[i].filename, ".asc"))
			g_test_add (test_path, Test, fixtures + i, setup, test_openpgp_armor, teardown);
		else
			g_test_add (test_path, Test, fixtures + i, setup, test_openpgp_binary, teardown);
		g_free (test_path);
	}

	return g_test_run ();
}
