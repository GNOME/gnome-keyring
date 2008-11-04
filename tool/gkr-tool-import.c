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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-tool.h"

#include "gp11/gp11.h"

#include "pkcs11/pkcs11g.h"

static gchar **import_files = NULL;

static GOptionEntry import_entries[] = {
	GKR_TOOL_BASIC_OPTIONS
	{ G_OPTION_REMAINING, 0, G_OPTION_FLAG_FILENAME, G_OPTION_ARG_FILENAME_ARRAY, &import_files, "Filename", NULL },
	{ NULL }
};

static const gulong ATTR_TYPES[] = {
	CKA_LABEL,
	CKA_CLASS,
	CKA_ID
};

static const char HEXC[] = "0123456789ABCDEF";

static void
print_object_information (GP11Object *object)
{
	GP11Attributes *attrs;
	GP11Attribute *id;
	CK_OBJECT_CLASS klass;
	const gchar *message;
	GError *err = NULL;
	gchar *label;
	
	attrs = gp11_object_get_full (object, ATTR_TYPES, G_N_ELEMENTS(ATTR_TYPES), NULL, &err);
	if(!attrs) {
		gkr_tool_handle_error (&err, "couldn't get imported object info");
		return;
	}

	if (!gp11_attributes_find_string (attrs, CKA_LABEL, &label))
		label = g_strdup ("unknown");
	if (!gp11_attributes_find_ulong (attrs, CKA_CLASS, &klass))
		klass = CKO_DATA;
	id = gp11_attributes_find (attrs, CKA_ID);
	
	switch (klass) {
	case CKO_CERTIFICATE:
		message = "Imported certificate: %s\n";
		break;
	case CKO_DATA:
		message = "Imported data: %s\n";
		break;
	case CKO_PRIVATE_KEY:
		message = "Imported private key: %s\n";
		break;
	case CKO_PUBLIC_KEY:
		message = "Imported public key: %s\n";
		break;
	case CKO_SECRET_KEY:
		message = "Imported secret key: %s\n";
		break;
	default:
		message = "Imported object: %s\n";
		break;
	};
	
	g_print (message, label);

	if (id) {
		guchar *data = id->value;
		gsize n_data = id->length;
		gchar pair[3];
		
		g_print ("\tID: ");
		
		while(n_data > 0) {
			pair[0] = HEXC[*(data) >> 4 & 0xf];
			pair[1] = HEXC[*(data++) & 0xf];
			pair[2] = 0;
			n_data--;
			g_print ("%s", pair);
		}

		g_print ("\n");
	}
	
	gp11_attributes_unref (attrs);
	g_free (label);
}

static void
print_import_information (GP11Session *session, GP11Object *import)
{
	GP11Attribute *attr;
	GList *objects, *l;
	GError *err;
	
	attr = gp11_object_get_one (import, CKA_GNOME_IMPORT_OBJECTS, &err);
	if (!attr) {
		gkr_tool_handle_error (&err, "couldn't find imported objects");
		return;
	}

	objects = gp11_objects_from_handle_array (session, attr);
	gp11_attribute_free (attr);

	for (l = objects; l; l = g_list_next (l))
		print_object_information (GP11_OBJECT (l->data));
	
	gp11_list_unref_free (objects);
}

static int
import_from_file (GP11Session *session, const gchar *filename)
{
	GError *err = NULL;
	GP11Object *import;
	GP11Attributes *attrs;
	gchar *basename;
	gchar *data;
	gsize n_data;
	
	/* Read in the file data */
	if (!g_file_get_contents (filename, &data, &n_data, &err)) {
		gkr_tool_handle_error (&err, NULL);
		return 1;
	}
	
	/* Setup the attributes on the object */
	attrs = gp11_attributes_new ();
	gp11_attributes_add_data (attrs, CKA_VALUE, data, n_data);
	gp11_attributes_add_boolean (attrs, CKA_TOKEN, FALSE);
	gp11_attributes_add_ulong (attrs, CKA_CLASS, CKO_GNOME_IMPORT);
	gp11_attributes_add_boolean (attrs, CKA_GNOME_IMPORT_TOKEN, TRUE);
	basename = g_path_get_basename (filename);
	gp11_attributes_add_string (attrs, CKA_GNOME_IMPORT_LABEL, basename);
	g_free (basename);
	
	import = gp11_session_create_object_full (session, attrs, NULL, &err);
	gp11_attributes_unref (attrs);
	g_free (data);
	
	if (!import) {
		gkr_tool_handle_error (&err, "couldn't import file: %s", filename);
		return 1;
	}
	
	if (!gkr_tool_mode_quiet)
		print_import_information (session, import);
	
	g_object_unref (import);
	return 0;
}

static GP11Session*
open_import_session (void)
{
	GP11Module *module;
	GP11Session *session;
	GList *slots;
	GError *err = NULL;
	
	module = gp11_module_initialize (PKCS11_MODULE_PATH, NULL, &err);
	if (!module) {
		gkr_tool_handle_error (&err, NULL);
		return NULL;
	}
	
	slots = gp11_module_get_slots (module, FALSE);
	g_return_val_if_fail (slots && slots->data, NULL);
	
	session = gp11_slot_open_session(slots->data, CKF_RW_SESSION, &err);
	gp11_list_unref_free (slots);
	g_object_unref (module);
	
	if (!session) {
		gkr_tool_handle_error (&err, "couldn't connect to gnome-keyring");
		return NULL;
	}
	
	return session;
}

int
gkr_tool_import (int argc, char *argv[])
{
	GP11Session *session;
	gchar **imp;
	int ret = 0;
	
	ret = gkr_tool_parse_options (&argc, &argv, import_entries);
	if (ret != 0)
		return ret;
	
	if(!import_files || !*import_files) {
		gkr_tool_handle_error (NULL, "specify files to import");
		return 2;
	}
	
	/* Open a session */
	session = open_import_session ();
	if (!session)
		return 1;
	
	for (imp = import_files; *imp; ++imp) {
		ret = import_from_file (session, *imp);
		if (ret != 0)
			break;
	}
	
	g_object_unref (session);
	return ret;
}
