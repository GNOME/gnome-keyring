/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-dbus.c - hook into dbus, call other bits

   Copyright (C) 2007, 2009, Stefan Walter

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

#include "gkd-dbus-util.h"
#include "gkd-secret-types.h"

#include "egg/egg-error.h"

#include <string.h>

GType
gkd_dbus_connection_get_boxed_type (void)
{
	static GType type = 0;
	if (!type)
		type = g_boxed_type_register_static ("GkdDBusConnection",
		                                     (GBoxedCopyFunc)dbus_connection_ref,
		                                     (GBoxedFreeFunc)dbus_connection_unref);
	return type;
}

gboolean
gkd_dbus_interface_match (const gchar *interface, const gchar *match)
{
	g_return_val_if_fail (interface, FALSE);

	/* Null or zero length matches anything */
	if (!match || !match[0])
		return TRUE;

	return strcmp (interface, match) == 0;
}

static gchar *
build_child_node_xml (const gchar *parent,
                      const gchar **children)
{
	GString *result;
	const gchar *child;
	guint i;

	result = g_string_new ("");
	for (i = 0; children != NULL && children[i] != NULL; i++) {
		if (children[i][0] == '/') {
			if (!g_str_has_prefix (children[i], parent)) {
				g_warning ("in introspection data child '%s' is not descendant of parent '%s'",
				           children[i], parent);
				continue;
			}
			child = children[i] + strlen (parent);
			while (child[0] == '/')
				child++;
		} else {
			child = children[i];
		}

		g_string_append_printf (result, "\t<node name=\"%s\"/>\n", child);
	}

	return g_string_free (result, FALSE);
}

static gboolean
string_replace (GString *string,
                const gchar *search,
                const gchar *replace)
{
	const gchar *pos;

	pos = strstr (string->str, search);
	if (pos == NULL)
		return FALSE;

	g_string_erase (string, pos - string->str, strlen (search));
	g_string_insert (string, pos - string->str, replace);
	return TRUE;
}

DBusMessage *
gkd_dbus_introspect_handle (DBusMessage *message,
                            const gchar *data,
                            const gchar **children)
{
	DBusMessage *reply;
	GString *output = NULL;
	gchar *nodes;

	g_return_val_if_fail (message, NULL);
	g_return_val_if_fail (data, NULL);

	if (dbus_message_is_method_call (message, DBUS_INTERFACE_INTROSPECTABLE, "Introspect") &&
	    dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID)) {

		if (children != NULL) {
			output = g_string_new (data);
			nodes = build_child_node_xml (dbus_message_get_path (message), children);
			if (!string_replace (output, "<!--@children@-->", nodes))
				g_warning ("introspection data contained no location for child nodes");
			g_free (nodes);
			data = output->str;
		}

		reply = dbus_message_new_method_return (message);
		if (!dbus_message_append_args (reply, DBUS_TYPE_STRING, &data, DBUS_TYPE_INVALID))
			g_return_val_if_reached (NULL);

		if (output)
			g_string_free (output, TRUE);
		return reply;
	}

	return NULL;
}
