/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-tool-trust.c: Command line certificate trust exceptions

   Copyright (C) 2010 Stefan Walter

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

#include "gkr-tool.h"

#include "gck/gck.h"

#include "gcr/gcr.h"

#include "egg/egg-hex.h"

#if 0
static gchar **trust_files = NULL;
#endif

struct {
	const gchar *name;
	GcrPurpose purpose;
} purpose_names[] = {
	{ "server", GCR_PURPOSE_SERVER_AUTH },
	{ "client", GCR_PURPOSE_CLIENT_AUTH },
	{ "code", GCR_PURPOSE_CODE_SIGNING },
	{ "email", GCR_PURPOSE_EMAIL },
	{ "timestamp", GCR_PURPOSE_TIME_STAMPING },
	{ "ipsec-endpoint", GCR_PURPOSE_IPSEC_ENDPOINT },
	{ "ipsec-tunnel", GCR_PURPOSE_IPSEC_TUNNEL },
	{ "ipsec-user", GCR_PURPOSE_IPSEC_USER },
	{ "ipsec-ike-intermediate", GCR_PURPOSE_IKE_INTERMEDIATE },
};

static GcrPurpose
purpose_for_string (const gchar *string)
{
	guint i;

	g_assert (string);

	for (i = 0; i < G_N_ELEMENTS (purpose_names); ++i) {
		if (g_str_equal (purpose_names[i].name, string))
			return purpose_names[i].purpose;
	}

	return 0;
}

static const gchar*
purpose_to_string (GcrPurpose purpose)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (purpose_names); ++i) {
		if (purpose == purpose_names[i].purpose)
			return purpose_names[i].name;
	}

	return NULL;
}

static GOptionEntry trust_entries[] = {
	GKR_TOOL_BASIC_OPTIONS
	{ NULL }
};

static int
get_certificate_exceptions (GcrCertificate *certificate, GcrPurpose purpose)
{
	GError *error = NULL;
	const gchar *string;
	GcrTrust trust;

	trust = gcr_trust_get_certificate_exception (certificate, purpose, NULL, &error);
	if (error != NULL) {
		gkr_tool_handle_error (&error, "retrieving trust exception failed");
		return 1;
	}

	string = purpose_to_string (purpose);
	if (trust == GCR_TRUST_UNKNOWN && !gkr_tool_mode_quiet)
		g_print ("%s: no trust exception\n", string);
	else if (trust == GCR_TRUST_TRUSTED)
		g_print ("%s: certificate is explicitly trusted\n", string);
	else if (trust == GCR_TRUST_UNTRUSTED)
		g_print ("%s: certificate is explicitly untrusted\n", string);

	return 0;
}

int
gkr_tool_trust (int argc, char *argv[])
{
	GcrCertificate *certificate = NULL;
	GcrPurpose purpose;
	GError *error = NULL;
	GArray *purposes = NULL;
	GFile *file = NULL;
	gchar *contents;
	gsize length;
	int ret = 2;
	guint i;

	ret = gkr_tool_parse_options (&argc, &argv, trust_entries);
	if (ret != 0)
		return ret;

	if (argc < 3) {
		gkr_tool_handle_error (NULL, "specify certificate file followed by one or more purposes");
		goto done;
	}

	purposes = g_array_new (FALSE, TRUE, sizeof (GcrPurpose));
	for (i = 2; i < argc; ++i) {
		purpose = purpose_for_string (argv[i]);
		if (purpose == 0) {
			gkr_tool_handle_error (NULL, "invalid purpose: %s", argv[i]);
			goto done;
		}
		g_array_append_val (purposes, purpose);
	}

	ret = 1;

	file = g_file_new_for_commandline_arg (argv[1]);
	if (!g_file_load_contents (file, NULL, &contents, &length, NULL, &error)) {
		gkr_tool_handle_error (&error, "couldn't read file: %s", argv[1]);
		goto done;
	}

	certificate = gcr_simple_certificate_new (contents, length);
	g_free (contents);

	for (i = 0; i < purposes->len; ++i) {
		ret = get_certificate_exceptions (certificate, g_array_index (purposes, GcrPurpose, i));
		if (ret != 0)
			break;
	}

done:
	if (file != NULL)
		g_object_unref (file);
	if (purposes != NULL)
		g_array_free (purposes, TRUE);
	if (certificate != NULL)
		g_object_unref (certificate);
	return ret;
}
