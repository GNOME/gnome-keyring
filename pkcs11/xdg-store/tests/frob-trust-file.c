/*
 * gnome-keyring
 *
 * Copyright 2010 (C) Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-dn.h"
#include "egg/egg-error.h"
#include "egg/egg-asn1-defs.h"

#include <stdlib.h>

#include "xdg-store/gkm-xdg-asn1-defs.h"

static void
barf_and_die (const gchar *msg, const gchar *detail)
{
	if (detail)
		g_printerr ("diddle-trust-file: %s: %s\n", msg, detail);
	else
		g_printerr ("diddle-trust-file: %s\n", msg);
	exit (1);
}

static void
create_trust_file_for_certificate (const gchar *filename, const gchar *certificate)
{
	GError *err = NULL;
	GNode *asn, *cert, *choice, *ref;
	GBytes *bytes, *result;
	gchar *data;
	gsize n_data;

	if (!g_file_get_contents (certificate, &data, &n_data, &err))
		barf_and_die ("couldn't read certificate file", egg_error_message (err));

	/* Make sure the certificate is */
	cert = egg_asn1x_create (pkix_asn1_tab, "Certificate");
	g_return_if_fail (cert);

	bytes = g_bytes_new_take (data, n_data);
	if (!egg_asn1x_decode (cert, bytes))
		barf_and_die ("couldn't parse der certificate file", egg_asn1x_message (cert));

	asn = egg_asn1x_create (xdg_asn1_tab, "trust-1");
	g_return_if_fail (asn);

	ref = egg_asn1x_node (asn, "reference", NULL);
	choice = egg_asn1x_node (ref, "certComplete", NULL);

	if (!egg_asn1x_set_choice (ref, choice) || !egg_asn1x_set_any_raw (choice, bytes))
		g_return_if_reached ();

	g_bytes_unref (bytes);

	result = egg_asn1x_encode (asn, NULL);
	if (result == NULL)
		barf_and_die ("couldn't encode the trust file", egg_asn1x_message (asn));

	egg_asn1x_destroy (asn);
	egg_asn1x_destroy (cert);

	if (!g_file_set_contents (filename, g_bytes_get_data (result, NULL),
	                          g_bytes_get_size (result), &err))
		barf_and_die ("couldn't write trust file", egg_error_message (err));

	g_bytes_unref (result);
}

static void
create_trust_file_for_issuer_and_serial (const gchar *filename, const gchar *certificate)
{
	GError *err = NULL;
	GNode *asn, *cert, *choice, *ref;
	GNode *issuer, *serial;
	gchar *data;
	GBytes *result;
	GBytes *value;
	GBytes *element;
	gsize n_data;
	GBytes *bytes;

	if (!g_file_get_contents (certificate, &data, &n_data, &err))
		barf_and_die ("couldn't read certificate file", egg_error_message (err));

	/* Make sure the certificate is */
	cert = egg_asn1x_create (pkix_asn1_tab, "Certificate");
	g_return_if_fail (cert);

	bytes = g_bytes_new_take (data, n_data);
	if (!egg_asn1x_decode (cert, bytes))
		barf_and_die ("couldn't parse der certificate file", egg_asn1x_message (cert));
	g_bytes_unref (bytes);

	/* Dig out the issuer and serial */
	issuer = egg_asn1x_node (cert, "tbsCertificate", "issuer", NULL);
	serial = egg_asn1x_node (cert, "tbsCertificate", "serialNumber", NULL);
	g_return_if_fail (issuer && serial);

	/* Create up the trust structure */
	asn = egg_asn1x_create (xdg_asn1_tab, "trust-1");
	g_return_if_fail (asn);

	/* Setup the type of trust assertion */
	ref = egg_asn1x_node (asn, "reference", NULL);
	choice = egg_asn1x_node (ref, "certReference", NULL);
	if (!egg_asn1x_set_choice (ref, choice))
		g_return_if_reached ();

	/* Copy over the serial and issuer */
	element = egg_asn1x_get_element_raw (issuer);
	if (!egg_asn1x_set_any_raw (egg_asn1x_node (choice, "issuer", NULL), element))
		g_return_if_reached ();
	g_bytes_unref (element);

	value = egg_asn1x_get_integer_as_raw (serial);
	egg_asn1x_set_integer_as_raw (egg_asn1x_node (choice, "serialNumber", NULL), value);
	g_bytes_unref (value);

	result = egg_asn1x_encode (asn, NULL);
	if (result == NULL)
		barf_and_die ("couldn't encode the trust file", egg_asn1x_message (asn));

	g_free (data);
	egg_asn1x_destroy (cert);
	egg_asn1x_destroy (asn);

	if (!g_file_set_contents (filename, g_bytes_get_data (result, NULL),
	                          g_bytes_get_size (result), &err))
		barf_and_die ("couldn't write trust file", egg_error_message (err));

	g_bytes_unref (result);
}

static void
add_trust_purpose_to_file (const gchar *filename, const gchar *purpose)
{
	GError *err = NULL;
	gchar *data;
	GBytes *result;
	gsize n_data;
	GNode *asn, *assertion;
	GBytes *bytes;

	if (!g_file_get_contents (filename, &data, &n_data, &err))
		barf_and_die ("couldn't read trust file", egg_error_message (err));

	/* Create up the trust structure */
	asn = egg_asn1x_create (xdg_asn1_tab, "trust-1");
	g_return_if_fail (asn);

	/* And parse it */
	bytes = g_bytes_new_take (data, n_data);
	if (!egg_asn1x_decode (asn, bytes))
		barf_and_die ("couldn't parse trust file", egg_asn1x_message (asn));
	g_bytes_unref (bytes);

	assertion = egg_asn1x_append (egg_asn1x_node (asn, "assertions", NULL));
	g_return_if_fail (assertion);

	if (!egg_asn1x_set_string_as_utf8 (egg_asn1x_node (assertion, "purpose", NULL), g_strdup (purpose), g_free))
		g_return_if_reached ();
	egg_asn1x_set_enumerated (egg_asn1x_node (assertion, "level", NULL), g_quark_from_string ("trusted"));

	result = egg_asn1x_encode (asn, NULL);
	if (result == NULL)
		barf_and_die ("couldn't encode trust file", egg_asn1x_message (asn));

	egg_asn1x_destroy (asn);

	if (!g_file_set_contents (filename, g_bytes_get_data (result, NULL),
	                          g_bytes_get_size (result), &err))
		barf_and_die ("couldn't write trust file", egg_error_message (err));

	g_bytes_unref (result);
}

/* --------------------------------------------------------------------------------
 * MAIN
 */

static gchar *create_for_file = NULL;
static gchar *refer_for_file = NULL;
static gchar *add_trust_purpose = NULL;

static GOptionEntry option_entries[] = {
	{ "create", '\0', 0, G_OPTION_ARG_FILENAME, &create_for_file,
	  "Create trust file for full certificate.", "certificate" },
	{ "refer", '\0', 0, G_OPTION_ARG_FILENAME, &refer_for_file,
	  "Create trust file for issuer+serial certificate", "certificate" },
	{ "add-trust", '\0', 0, G_OPTION_ARG_STRING, &add_trust_purpose,
	  "Add trust purpose to trust file", "purpose" },
	{ NULL }
};

int
main(int argc, char* argv[])
{
	GError *err = NULL;
	GOptionContext *context;

	context = g_option_context_new ("trust-file");
	g_option_context_add_main_entries (context, option_entries, GETTEXT_PACKAGE);
	if (!g_option_context_parse (context, &argc, &argv, &err))
		barf_and_die (egg_error_message (err), NULL);

	g_option_context_free (context);

	if (argc != 2)
		barf_and_die ("specify trust-file", NULL);

	if (((create_for_file ? 1 : 0) +
	     (refer_for_file ? 1 : 0) +
	     (add_trust_purpose ? 1 : 0)) > 1)
		barf_and_die ("incompatible options specified", NULL);

	if (create_for_file)
		create_trust_file_for_certificate (argv[1], create_for_file);
	else if (refer_for_file)
		create_trust_file_for_issuer_and_serial (argv[1], refer_for_file);
	else if (add_trust_purpose)
		add_trust_purpose_to_file (argv[1], add_trust_purpose);

	g_free (create_for_file);
	g_free (refer_for_file);
	g_free (add_trust_purpose);

	return 0;
}
