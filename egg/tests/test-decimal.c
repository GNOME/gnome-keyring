/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-util.c: Test gck-util.c

   Copyright (C) 2011 Collabora Ltd.

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

#include "egg/egg-decimal.h"
#include "egg/egg-testing.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
	const gchar *decimal;
	const gchar *result;
	gsize length;
} TestDecimal;

static TestDecimal decimal_fixtures[] = {
	{ "35", "\x23", 1 },
	{ "2048", "\x08\x00", 2 },
	{ "209328042309", "\x30\xBC\xEC\x71\x45", 5 },
	{ "0002048", "\x08\x00", 2 },
	{ "20480000", "\x01\x38\x80\x00", 4 },
	{ "2521368004379664277055118629334750468402260732427135194366161280379"
	  "6661942758264006541602516197962800670706891657576953487072507942596"
	  "6374424122494538738176144081024494339591946626053519298721214406983"
	  "3606711407748948613853344896472022957466922483835202523097287025430"
	  "5078987427716449092979306938082113263545271808186244259338032237756"
	  "9175402872261192563172038927792670653714043622677577357160052045893"
	  "9513984477743817388078699536715866468499111753894230211101792648120"
	  "1128688482121549927434503046858485918719606735307033123916744787670"
	  "4316000505177621722934283063062034258685067324811300901286708201589"
	  "59867993533757",
	  "\xC7\xBB\x16\xF4\xB8\x04\x24\x0F\xFC\xC2\xA7\xAF\x8C\x6E\x67\xE1\x16"
	  "\x7F\xEB\xFA\x7F\xAA\x9D\xFD\x7C\xF2\x75\xB8\xA5\x1F\x27\x35\xF2\xD4"
	  "\x9D\x78\xFB\xF6\x5C\xED\x10\xB4\xE4\x32\x58\x2D\xC9\x1E\x86\x54\xF7"
	  "\x89\x7F\x03\x84\x68\x32\x76\xA9\xA7\x97\xC3\xA3\x6F\x7A\x46\x85\x43"
	  "\x5E\x14\x4D\x47\x01\x81\x06\xE5\xC0\x61\xD7\xC8\x7C\x9B\xE1\x9D\x84"
	  "\x87\x75\x77\x80\x0E\xAE\x91\xB1\x05\x12\xDE\x92\xF2\x98\x84\x1F\x43"
	  "\xD4\xC4\x57\x77\x95\xC5\xE6\x82\xEE\xEA\x0A\xB3\xDD\x8C\x44\x45\x9A"
	  "\x12\xAC\xF9\xC2\x22\xA1\x3F\x03\x31\xDD\x84\xF7\x75\x51\xE0\xFA\x24"
	  "\x8E\x6F\xE9\x58\x4C\xA3\x42\x73\xB9\x5E\x2F\x0D\xCC\xDC\x22\x8A\x48"
	  "\x75\x4A\x76\xA2\x9D\x03\xBA\x5F\xC8\x57\xB5\x1F\x5C\x85\x7E\x8C\x0F"
	  "\xF2\x73\xDA\x96\x67\x7C\xC6\x4D\x54\x2C\x45\x63\xD1\xA6\x7F\xF1\xA0"
	  "\x1F\x3F\x9E\xDF\xF3\x7F\x24\x3D\x6E\xB8\xF7\x4C\xC8\xA7\x27\x95\xA1"
	  "\xDA\x8F\x98\x32\x32\x1B\x7D\xB6\x1B\xFC\x8D\x73\x7C\xD1\x48\x99\xD0"
	  "\xAC\x7C\xF1\x5B\x95\xA5\xFE\xD8\x12\x57\x5C\x7A\x6B\xC5\x5C\x7D\x92"
	  "\xB1\x91\x88\x36\x58\x19\x30\x67\x2D\x73\xF3\x5A\xA6\x31\xC4\x5C\x2D"
	  "\x3D"
	  , 256 }
};

static const gchar *decimal_failures[] = {
	"-35",
	"abcd",
	" 3 33",
};

static void
test_decode_success (gconstpointer data)
{
	const TestDecimal *fixture = data;
	guchar *decoded;
	gsize n_decoded;

	decoded = egg_decimal_decode (fixture->decimal, -1, &n_decoded);
	egg_assert_cmpmem (fixture->result, fixture->length, ==, decoded, n_decoded);
	g_free (decoded);
}

static void
test_decode_failure (gconstpointer data)
{
	const gchar *failure = data;
	guchar *decoded;
	gsize n_decoded;

	decoded = egg_decimal_decode (failure, -1, &n_decoded);
	g_assert (decoded == NULL);
}

int
main (int argc, char **argv)
{
	gchar *name;
	gchar *decimal;
	const gchar *suffix;
	guint i;

	g_test_init (&argc, &argv, NULL);

	for (i = 0; i < G_N_ELEMENTS (decimal_fixtures); i++) {
		/* Ellipsize long numbers in test names */
		decimal = g_strndup (decimal_fixtures[i].decimal, 41);
		if (strlen (decimal) == 41) {
			decimal[40] = 0;
			suffix = "_long";
		} else {
			suffix = "";
		}
		name = g_strdup_printf ("/decimal/decode-success/%s%s", decimal, suffix);
		g_test_add_data_func (name, &decimal_fixtures[i], test_decode_success);
		g_free (name);
		g_free (decimal);
	}

	for (i = 0; i < G_N_ELEMENTS (decimal_failures); i++) {
		name = g_strdup_printf ("/decimal/decode-failure/%s", decimal_failures[i]);
		g_strcanon (name, "abcdefghijklmnopqrstuvwxyz-_/0123456789", '_');
		g_test_add_data_func (name, decimal_failures[i], test_decode_failure);
		g_free (name);
	}

	return g_test_run ();
}
