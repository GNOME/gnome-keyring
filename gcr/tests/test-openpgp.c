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

#include "egg/egg-armor.h"
#include "egg/egg-testing.h"

#include <gcrypt.h>
#include <glib.h>
#include <string.h>

static void
on_openpgp_packet  (GPtrArray *records,
                    const guchar *outer,
                    gsize n_outer,
                    gpointer user_data)
{
	guint num_packets;

	/* Should be parseable again */
	num_packets = _gcr_openpgp_parse (outer, n_outer, NULL, NULL);
	g_assert_cmpuint (num_packets, ==, 1);
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
	const gchar *value;
	guint num_packets;

	value = g_hash_table_lookup (headers, "Version");
	g_assert_cmpstr (value, ==, "GnuPG v1.4.11 (GNU/Linux)");

	num_packets = _gcr_openpgp_parse (data, n_data, on_openpgp_packet, NULL);
	g_assert_cmpuint (num_packets, ==, 21);
}

static void
test_armor_parse (void)
{
	GError *error = NULL;
	gchar *armor;
	gsize length;
	guint parts;

	g_file_get_contents (SRCDIR "/files/werner-koch.asc", &armor, &length, &error);
	g_assert_no_error (error);

	parts = egg_armor_parse (armor, length, on_armor_parsed, NULL);
	g_assert_cmpuint (parts, ==, 1);

	g_free (armor);
}

int
main (int argc, char **argv)
{
	g_type_init ();
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-gnupg-process");

	g_test_add_func ("/gcr/openpgp/armor_parse", test_armor_parse);

	return g_test_run ();
}
