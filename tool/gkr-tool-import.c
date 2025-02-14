/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-tool-import.c: Command line key/certificate import

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

#include "gkr-tool.h"

#include <gck/gck.h>
#include <gcr/gcr-base.h>

#include "egg/egg-hex.h"

static gchar **import_files = NULL;

static GOptionEntry import_entries[] = {
	GKR_TOOL_BASIC_OPTIONS
	{ G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &import_files, "Filename", NULL },
	{ NULL }
};

static void
imported_fingerprint (const gchar *fingerprint,
                      const gchar *destination)
{
	g_print ("%s: imported openpgp\n", destination);
	g_print ("\tfingerprint: %s\n", fingerprint);
}

static void
imported_object (GckObject *object,
                 const gchar *destination)
{
	gulong attr_types[3];
	GckAttributes *attrs;
	const GckAttribute *id;
	CK_OBJECT_CLASS klass;
	const gchar *message;
	GError *err = NULL;
	gchar *label, *hex;

	attr_types[0] = CKA_LABEL;
	attr_types[1] = CKA_CLASS;
	attr_types[2] = CKA_ID;

	attrs = gck_object_get_full (object, attr_types, G_N_ELEMENTS (attr_types), NULL, &err);
	if (attrs == NULL) {
		gkr_tool_handle_error (&err, "couldn't get imported object info");
		return;
	}

	if (!gck_attributes_find_string (attrs, CKA_LABEL, &label))
		label = g_strdup ("unknown");
	if (!gck_attributes_find_ulong (attrs, CKA_CLASS, &klass))
		klass = CKO_DATA;
	id = gck_attributes_find (attrs, CKA_ID);
	
	switch (klass) {
	case CKO_CERTIFICATE:
		message = "%s: imported certificate: %s\n";
		break;
	case CKO_DATA:
		message = "%s: imported data: %s\n";
		break;
	case CKO_PRIVATE_KEY:
		message = "%s: imported private key: %s\n";
		break;
	case CKO_PUBLIC_KEY:
		message = "%s: imported public key: %s\n";
		break;
	case CKO_SECRET_KEY:
		message = "%s: imported secret key: %s\n";
		break;
	default:
		message = "%s: imported object: %s\n";
		break;
	};
	
	g_print (message, destination, label);

	if (id) {
		hex = egg_hex_encode (id->value, id->length);
		g_print ("\tidentifier: %s\n", hex);
		g_free (hex);
	}

	gck_attributes_unref (attrs);
	g_free (label);
}

static void
imported_display (GcrImporter *importer)
{
	GParamSpec *spec;
	gchar *label = NULL;

	spec = g_object_class_find_property (G_OBJECT_GET_CLASS (importer), "imported");
	if (spec == NULL)
		return;

	g_object_get (importer, "label", &label, NULL);

	if (spec->value_type == GCK_TYPE_LIST) {
		GList *list, *l;
		g_object_get (importer, "imported", &list, NULL);
		for (l = list; l != NULL; l = g_list_next (l))
			imported_object (l->data, label);
		gck_list_unref_free (list);

	} else if (spec->value_type == G_TYPE_STRV) {
		gchar **fingerprints;
		guint i;
		g_object_get (importer, "imported", &fingerprints, NULL);
		for (i = 0; fingerprints && fingerprints[i] != NULL; i++)
			imported_fingerprint (fingerprints[i], label);
		g_strfreev (fingerprints);
	}
}

typedef struct {
	GList *importers;
	gboolean num_parsed;
} ImportClosure;

static void
on_parser_parsed (GcrParser *parser,
                  gpointer user_data)
{
	ImportClosure *closure = user_data;
	GcrParsed *parsed;
	GList *filtered;

	parsed = gcr_parser_get_parsed (parser);
	if (closure->num_parsed == 0) {
		closure->importers = gcr_importer_create_for_parsed (parsed);
	} else {
		filtered = gcr_importer_queue_and_filter_for_parsed (closure->importers, parsed);
		gck_list_unref_free (closure->importers);
		closure->importers = filtered;
	}

	closure->num_parsed++;
}

int
gkr_tool_import (int argc, char *argv[])
{
	GcrParser *parser;
	GError *error = NULL;
	GInputStream *input;
	ImportClosure *closure;
	GFile *file;
	gchar **imp;
	int ret = 0;
	GList *l;

	ret = gkr_tool_parse_options (&argc, &argv, import_entries);
	if (ret != 0)
		return ret;
	
	if(!import_files || !*import_files) {
		gkr_tool_handle_error (NULL, "specify files to import");
		return 2;
	}

	if (!gcr_pkcs11_initialize (NULL, &error)) {
		gkr_tool_handle_error (&error, "couldn't initialize pkcs11 modules");
		return 1;
	}

	parser = gcr_parser_new ();
	closure = g_new0 (ImportClosure, 1);
	g_signal_connect (parser, "parsed", G_CALLBACK (on_parser_parsed), closure);

	for (imp = import_files; *imp; ++imp) {
		file = g_file_new_for_commandline_arg (*imp);
		
		input = G_INPUT_STREAM (g_file_read (file, NULL, &error));
		g_object_unref (file);
		if (input == NULL) {
			gkr_tool_handle_error (&error, "couldn't read file: %s", *imp);
			ret = 1;

		} else {
			if (!gcr_parser_parse_stream (parser, input, NULL, &error)) {
				if (error->code != GCR_ERROR_CANCELLED)
					gkr_tool_handle_error (&error, "couldn't parse: %s", *imp);
				ret = 1;
			}

			g_object_unref (input);
		}
	}

	if (closure->importers == NULL) {
		gkr_tool_handle_error (NULL, "couldn't find any place to import files");
		ret = 1;
	}

	for (l = closure->importers; l != NULL; l = g_list_next (l)) {
		if (gcr_importer_import (l->data, NULL, &error)) {
			if (!gkr_tool_mode_quiet)
				imported_display (l->data);
		} else {
			if (error->code != GCR_ERROR_CANCELLED)
				gkr_tool_handle_error (&error, "couldn't import");
			ret = 1;
		}
	}

	gck_list_unref_free (closure->importers);
	g_free (closure);

	g_object_unref (parser);
	return ret;
}
