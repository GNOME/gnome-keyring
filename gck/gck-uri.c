/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-uri.c - the GObject PKCS#11 wrapper library

   Copyright (C) 2010, Stefan Walter

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

#include "gck.h"
#include "gck-private.h"
#include "gck-marshal.h"

#include <glib/gi18n-lib.h>

#include <string.h>

#include "egg/egg-hex.h"

/**
 * SECTION:gck-uri
 * @title: PKCS11 URIs
 * @short_description: Parsing and building PKCS\#11 URIs.
 *
 * <ulink href='http://tools.ietf.org/html/draft-pechanec-pkcs11uri-03'>PKCS#11 URIs</ulink>
 * are a standard for referring to PKCS#11 modules, tokens, or objects. What the
 * PKCS\#11 URI refers to depends on the context in which it is used.
 *
 * A PKCS\#11 URI can always resolve to more than one object, token or module. A
 * PKCS\#11 URI that refers to a token, would (when used in a context that expects
 * objects) refer to all the token on that module.
 *
 * In most cases the parsing or building of URIs is handled elsewhere in the GCK
 * library. For example to enumerate objects that match a PKCS\#11 URI use the
 * gck_modules_enumerate_uri() function. Or to build a PKCS\#11 URI for a given
 * object, use the gck_object_build_uri() function.
 *
 * To parse a PKCS\#11 URI use the gck_uri_parse() function passing in the type of
 * context in which you're using the URI. To build a URI use the gck_uri_build()
 * function.
 **/

/**
 * GckUriInfo:
 * @any_unrecognized: whether any parts of the PKCS\#11 URI were unsupported or unrecognized.
 * @module_info: information about the PKCS\#11 modules matching the URI.
 * @token_info: information about the PKCS\#11 tokens matching the URI.
 * @attributes: information about the PKCS\#11 objects matching the URI.
 *
 * Information about the contents of a PKCS\#11 URI. Various fields may be %NULL
 * depending on the context that the URI was parsed for.
 *
 * Since PKCS\#11 URIs represent a set which results from the intersections of
 * all of the URI parts, if @any_recognized is set to %TRUE then usually the URI
 * should be treated as not matching anything.
 */

/**
 * GckUriContext:
 * @GCK_URI_CONTEXT_MODULE: the URI will be used to match modules.
 * @GCK_URI_CONTEXT_TOKEN: the URI will be used to match tokens.
 * @GCK_URI_CONTEXT_OBJECT: the URI will be used to match objects.
 * @GCK_URI_CONTEXT_ANY: parse all recognized components of the URI.
 *
 * Which context the PKCS\#11 URI will be used in.
 */

#define URI_PREFIX "pkcs11:"
#define N_URI_PREFIX 7

GQuark
gck_uri_get_error_quark (void)
{
	static GQuark domain = 0;
	static volatile gsize quark_inited = 0;

	if (g_once_init_enter (&quark_inited)) {
		domain = g_quark_from_static_string ("gck-uri-error");
		g_once_init_leave (&quark_inited, 1);
	}

	return domain;
}

GckUriInfo*
_gck_uri_info_new (void)
{
	return g_slice_new0 (GckUriInfo);
}

static gint
parse_string_attribute (const gchar *name, const gchar *start, const gchar *end,
                        GckAttributes *attrs, GError **error)
{
	gchar *value;
	gint res = 0;

	g_assert (name);
	g_assert (start);
	g_assert (end);

	if (!g_str_equal (name, "object") && !g_str_equal (name, "objecttype"))
		return 0;

	value = g_uri_unescape_segment (start, end, "");
	if (value == NULL) {
		g_set_error (error, GCK_URI_ERROR, GCK_URI_BAD_ENCODING,
		             _("The URI has invalid syntax. The '%s' field encoding is invalid."), name);
		return -1;
	}

	if (g_str_equal (name, "object")) {
		gck_attributes_add_string (attrs, CKA_LABEL, value);
		res = 1;

	} else if (g_str_equal (name, "objecttype")) {

		res = 1;
		if (g_str_equal (value, "cert"))
			gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_CERTIFICATE);
		else if (g_str_equal (value, "public"))
			gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_PUBLIC_KEY);
		else if (g_str_equal (value, "private"))
			gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_PRIVATE_KEY);
		else if (g_str_equal (value, "secretkey"))
			gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_SECRET_KEY);
		else if (g_str_equal (value, "data"))
			gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_DATA);
		else {
			g_message ("ignoring unsupported value for '%s'", value);
			res = 0;
		}
	} else {
		g_assert_not_reached ();
	}

	g_free (value);
	return res;
}

static gint
parse_binary_attribute (const gchar *name, const gchar *start, const gchar *end,
                        GckAttributes *attrs, GError **error)
{
	guchar *data;
	gsize n_data;

	g_assert (name);
	g_assert (start);
	g_assert (end);
	g_assert (attrs);

	if (!g_str_equal (name, "id"))
		return 0;

	/*
	 * TODO: This requires some work. We're not yet sure about the actual
	 * encoding that's supported here.
	 */

	g_assert (end >= start);
	data = egg_hex_decode_full (start, end - start, ':', 1, &n_data);
	if (data == NULL) {
		g_set_error (error, GCK_URI_ERROR, GCK_URI_BAD_ENCODING,
		             _("The URI has invalid syntax. The '%s' field encoding is invalid."), name);
		return -1;
	}

	gck_attributes_add_data (attrs, CKA_ID, data, n_data);
	g_free (data);
	return 1;
}

static gint
parse_token_attribute (const gchar *name, const gchar *start, const gchar *end,
                       GckTokenInfo *token, GError **error)
{
	gchar **value;
	gchar *string;

	g_assert (name);
	g_assert (start);
	g_assert (end);
	g_assert (token);

	if (g_str_equal (name, "model"))
		value = &(token->model);
	else if (g_str_equal (name, "manufacturer"))
		value = &(token->manufacturer_id);
	else if (g_str_equal (name, "serial"))
		value = &(token->serial_number);
	else if (g_str_equal (name, "token"))
		value = &(token->label);
	else
		return 0;

	string = g_uri_unescape_segment (start, end, "");
	if (string == NULL) {
		g_set_error (error, GCK_URI_ERROR, GCK_URI_BAD_ENCODING,
		             _("The URI has invalid syntax. The '%s' field encoding is invalid."), name);
		return -1;
	}

	g_free (*value);
	*value = string;

	return 1;
}

static gint
parse_library_attribute (const gchar *name, const gchar *start, const gchar *end,
                         GckModuleInfo *library, GError **error)
{
	gchar **value;
	gchar *string;

	g_assert (name);
	g_assert (start);
	g_assert (end);
	g_assert (library);

	if (g_str_equal (name, "library-description"))
		value = &(library->library_description);
	else if (g_str_equal (name, "library-manufacturer"))
		value = &(library->manufacturer_id);
	else
		return 0;

	string = g_uri_unescape_segment (start, end, "");
	if (string == NULL) {
		g_set_error (error, GCK_URI_ERROR, GCK_URI_BAD_ENCODING,
		             _("The URI has invalid syntax. The '%s' field encoding is invalid."), name);
		return -1;
	}

	g_free (*value);
	*value = string;

	return 1;
}

/**
 * gck_uri_parse:
 * @uri: the URI to parse.
 * @flags: the context in which the URI will be used.
 * @error: a #GError, or %NULL.
 *
 * Parse a PKCS\#11 URI for use in a given context.
 *
 * The result will contain the fields that are relevant for
 * the given context. See #GckUriInfo  for more info.
 * Other fields will be set to %NULL.
 *
 * Return value: a newly allocated #GckUriInfo, which should be freed with
 * 	gck_uri_info_free().
 */
GckUriInfo*
gck_uri_parse (const gchar *uri, GckUriParseFlags flags, GError **error)
{
	const gchar *spos, *epos;
	gchar *key = NULL;
	gboolean ret = FALSE;
	GckUriInfo *uri_info = NULL;
	gint res;

	g_return_val_if_fail (uri, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (!g_str_has_prefix (uri, URI_PREFIX)) {
		g_set_error_literal (error, GCK_URI_ERROR, GCK_URI_BAD_PREFIX,
		                     _("The URI has does not have the 'pkcs11' scheme."));
		goto cleanup;
	}

	uri += N_URI_PREFIX;

	uri_info = _gck_uri_info_new ();
	if ((flags & GCK_URI_PARSE_MODULE) == GCK_URI_PARSE_MODULE)
		uri_info->module_info = g_new0 (GckModuleInfo, 1);
	if ((flags & GCK_URI_PARSE_TOKEN) == GCK_URI_PARSE_TOKEN)
		uri_info->token_info = g_new0 (GckTokenInfo, 1);
	if ((flags & GCK_URI_PARSE_OBJECT) == GCK_URI_PARSE_OBJECT)
		uri_info->attributes = gck_attributes_new ();

	for (;;) {
		spos = strchr (uri, ';');
		if (spos == NULL) {
			spos = uri + strlen (uri);
			g_assert (*spos == '\0');
			if (spos == uri)
				break;
		}

		epos = strchr (uri, '=');
		if (epos == NULL || spos == uri || epos == uri || epos >= spos) {
			g_set_error_literal (error, GCK_URI_ERROR, GCK_URI_BAD_SYNTAX,
			                     "The URI has invalid syntax. It must consist of key=value pairs.");
			goto cleanup;
		}

		g_free (key);
		key = g_strndup (uri, epos - uri);
		epos++;

		res = 0;
		if (uri_info->attributes)
			res = parse_string_attribute (key, epos, spos, uri_info->attributes, error);
		if (res == 0 && uri_info->attributes)
			res = parse_binary_attribute (key, epos, spos, uri_info->attributes, error);
		if (res == 0 && uri_info->token_info)
			res = parse_token_attribute (key, epos, spos, uri_info->token_info, error);
		if (res == 0 && uri_info->module_info)
			res = parse_library_attribute (key, epos, spos, uri_info->module_info, error);
		if (res < 0)
			goto cleanup;
		if (res == 0) {
			g_message ("Ignoring unrecognized or unsupported field '%s'", key);
			uri_info->any_unrecognized = TRUE;
		}

		if (*spos == '\0')
			break;
		uri = spos + 1;
	}

	ret = TRUE;

cleanup:
	if (!ret) {
		gck_uri_info_free (uri_info);
		uri_info = NULL;
	}

	g_free (key);
	return uri_info;
}

static void
build_string_attribute (const gchar *name, const gchar *value,
                        GString *result, gboolean *first)
{
	gchar *segment;

	g_assert (first);
	g_assert (result);
	g_assert (name);

	if (!value)
		return;

	segment = g_uri_escape_string (value, "", FALSE);
	if (!*first)
		g_string_append_c (result, ';');
	*first = FALSE;

	g_string_append (result, name);
	g_string_append_c (result, '=');
	g_string_append (result, segment);
	g_free (segment);
}

static void
build_binary_attribute (const gchar *name, gconstpointer data, gsize n_data,
                        GString *result, gboolean *first)
{
	gchar *segment;

	g_assert (first);
	g_assert (result);
	g_assert (name);
	g_assert (!n_data || data);

	segment = egg_hex_encode_full (data, n_data, FALSE, ':', 1);
	if (!*first)
		g_string_append_c (result, ';');
	*first = FALSE;

	g_string_append (result, name);
	g_string_append_c (result, '=');
	g_string_append (result, segment);
	g_free (segment);
}

/**
 * gck_uri_build:
 * @uri_info: the info to build the URI from.
 *
 * Build a PKCS\#11 URI. Any set fields of @uri_info will be used to build
 * the URI.
 *
 * Return value: a newly allocated string containing a PKCS\#11 URI.
 */
gchar*
gck_uri_build (GckUriInfo *uri_info)
{
	GckAttribute *attr;
	GString *result;
	gchar *value;
	gulong klass;
	gboolean first = TRUE;

	g_return_val_if_fail (uri_info, NULL);

	result = g_string_new (URI_PREFIX);

	if (uri_info->module_info) {
		build_string_attribute ("library-description", uri_info->module_info->library_description, result, &first);
		build_string_attribute ("library-manufacturer", uri_info->module_info->manufacturer_id, result, &first);
	}

	if (uri_info->token_info) {
		build_string_attribute ("model", uri_info->token_info->model, result, &first);
		build_string_attribute ("manufacturer", uri_info->token_info->manufacturer_id, result, &first);
		build_string_attribute ("serial", uri_info->token_info->serial_number, result, &first);
		build_string_attribute ("token", uri_info->token_info->label, result, &first);
	}

	if (uri_info->attributes) {
		if (gck_attributes_find_string (uri_info->attributes, CKA_LABEL, &value)) {
			build_string_attribute ("object", value, result, &first);
			g_free (value);
		}
		if (gck_attributes_find_ulong (uri_info->attributes, CKA_CLASS, &klass)) {
			if (klass == CKO_CERTIFICATE)
				build_string_attribute ("objecttype", "cert", result, &first);
			else if (klass == CKO_PUBLIC_KEY)
				build_string_attribute ("objecttype", "public", result, &first);
			else if (klass == CKO_PRIVATE_KEY)
				build_string_attribute ("objecttype", "private", result, &first);
			else if (klass == CKO_SECRET_KEY)
				build_string_attribute ("objecttype", "secretkey", result, &first);
			else if (klass == CKO_DATA)
				build_string_attribute ("objecttype", "data", result, &first);
		}
		attr = gck_attributes_find (uri_info->attributes, CKA_ID);
		if (attr != NULL)
			build_binary_attribute ("id", attr->value, attr->length, result, &first);
	}

	return g_string_free (result, FALSE);
}

/**
 * gck_uri_info_free:
 * @uri_info: URI info to free.
 *
 * Free a #GckUriInfo.
 */
void
gck_uri_info_free (GckUriInfo *uri_info)
{
	if (uri_info) {
		if (uri_info->attributes)
			gck_attributes_unref (uri_info->attributes);
		if (uri_info->module_info)
			gck_module_info_free (uri_info->module_info);
		if (uri_info->token_info)
			gck_token_info_free (uri_info->token_info);
		g_slice_free (GckUriInfo, uri_info);
	}
}
