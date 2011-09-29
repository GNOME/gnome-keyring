/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-modules.c - the GObject PKCS#11 wrapper library

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

#include <glib/gi18n.h>

#define P11_KIT_FUTURE_UNSTABLE_API 1
#include <p11-kit/p11-kit.h>

#include <string.h>
#include <stdlib.h>

/**
 * SECTION:gck-modules
 * @title: GckModule lists
 * @short_description: Dealing with lists of PKCS\#11 modules.
 *
 * These functions are useful for dealing with lists of modules, and performing
 * operations on all of them.
 */

typedef struct {
	GckArguments base;
	GList *results;
	GError *error;
} InitializeRegistered;

static CK_RV
perform_initialize_registered (InitializeRegistered *args)
{
	GckModule *module;
	CK_FUNCTION_LIST_PTR *modules, *funcs;
	const gchar *message;
	CK_RV rv;

	rv = p11_kit_initialize_registered ();
	if (rv != CKR_OK) {
		message = p11_kit_message ();
		if (message == NULL)
			message = gck_message_from_rv (rv);
		g_set_error (&args->error, GCK_ERROR, (int)CKR_GCK_MODULE_PROBLEM,
		             _("Couldn't initialize registered PKCS#11 modules: %s"), message);
		return rv;
	}

	modules = p11_kit_registered_modules ();
	for (funcs = modules; *funcs; ++funcs) {
		module = _gck_module_new_initialized (*funcs);
		args->results = g_list_prepend (args->results, module);
	}

	free (modules);
	return CKR_OK;
}

static void
free_initialize_registered (InitializeRegistered *args)
{
	g_clear_error (&args->error);
	gck_list_unref_free (args->results);
	g_free (args);
}

/**
 * gck_modules_initialize_registered:
 * @cancellable: (allow-none): optional cancellation object
 * @error: (allow-none): location to place an error on failure
 *
 * Load and initialize all the registered modules.
 *
 * Returns: (transfer full) (element-type Gck.Module): A newly allocated list
 * of #GckModule objects, which should be released with gck_list_unref_free().
 */
GList*
gck_modules_initialize_registered (GCancellable *cancellable,
                                   GError **error)
{
	InitializeRegistered args = { GCK_ARGUMENTS_INIT, 0,  };

	if (!_gck_call_sync (NULL, perform_initialize_registered, NULL, &args, cancellable, error)) {
		if (args.error) {
			g_clear_error (error);
			g_propagate_error (error, args.error);
			args.error = NULL;
		}
	}

	g_clear_error (&args.error);
	return args.results;
}

/**
 * gck_modules_initialize_registered_async:
 * @cancellable: optional cancellation object
 * @callback: a callback which will be called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Load and initialize all the registered modules asynchronously.
 */
void
gck_modules_initialize_registered_async (GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
	InitializeRegistered *args;

	args =  _gck_call_async_prep (NULL, NULL, perform_initialize_registered, NULL,
	                              sizeof (*args), free_initialize_registered);

	_gck_call_async_ready_go (args, cancellable, callback, user_data);
}

/**
 * gck_modules_initialize_registered_finish:
 * @result: the asynchronous result
 * @error: location to place an error on failure
 *
 * Finishes the asynchronous operation to initialize the registered
 * PKCS\#11 modules.
 *
 * Returns: (transfer full) (element-type Gck.Module): a list of newly
 * initialized #GckModule objects
 */
GList *
gck_modules_initialize_registered_finish (GAsyncResult *result,
                                          GError **error)
{
	GList *modules = NULL;
	InitializeRegistered *args;

	args = _gck_call_arguments (result, InitializeRegistered);
	if (_gck_call_basic_finish (result, error)) {
		modules = args->results;
		args->results = NULL;

	} else {
		/* A custom error from perform_initialize */
		if (args->error) {
			g_clear_error (error);
			g_propagate_error (error, args->error);
			args->error = NULL;
		}
	}

	return modules;
}

/**
 * gck_modules_get_slots:
 * @modules: (element-type Gck.Module): The modules
 * @token_present: Whether to only list slots with token present
 *
 * Get a list of slots for across all of the modules.
 *
 * Returns: (transfer full) (element-type Gck.Slot): A list of #GckSlot
 * objects, which should be freed with gck_list_unref_free().
 */
GList*
gck_modules_get_slots (GList *modules, gboolean token_present)
{
	GList *result = NULL;
	GList *m;

	for (m = modules; m; m = g_list_next (m)) {
		result = g_list_concat (result, gck_module_get_slots (m->data, token_present));
	}

	return result;
}

/**
 * gck_modules_enumerate_objects:
 * @modules: (element-type Gck.Module): The modules
 * @attrs: Attributes that the objects must have, or empty for all objects
 * @session_options: Options from GckSessionOptions
 *
 * Setup an enumerator for listing matching objects on the modules.
 *
 * This call will not block but will return an enumerator immediately.

 * Return value: (transfer full): A new enumerator, which should be released
 * with g_object_unref().
 **/
GckEnumerator*
gck_modules_enumerate_objects (GList *modules, GckAttributes *attrs, guint session_options)
{
	GckUriData *uri_data;

	g_return_val_if_fail (attrs, NULL);

	uri_data = gck_uri_data_new ();
	uri_data->attributes = gck_attributes_ref (attrs);

	return _gck_enumerator_new (modules, session_options, uri_data);
}

static GList *
tokens_for_uri (GList *modules,
                const gchar *uri,
                gboolean only_one,
                GError **error)
{
	GckTokenInfo *token_info;
	GList *results = NULL;
	GckUriData *uri_data;
	GckModuleInfo *module_info;
	GList *slots;
	GList *m, *s;
	gboolean matched;
	GckUriFlags flags;

	flags = GCK_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE | GCK_URI_FOR_MODULE_WITH_VERSION;
	uri_data = gck_uri_parse (uri, flags, error);
	if (uri_data == NULL)
		return NULL;

	if (!uri_data->any_unrecognized) {
		for (m = modules; m != NULL; m = g_list_next (m)) {
			if (only_one && results)
				break;
			if (uri_data->module_info) {
				module_info = gck_module_get_info (m->data);
				matched = _gck_module_info_match (uri_data->module_info, module_info);
				gck_module_info_free (module_info);
				if (!matched)
					continue;
			}

			slots = gck_module_get_slots (m->data, TRUE);
			for (s = slots; s != NULL; s = g_list_next (s)) {
				if (only_one && results)
					break;
				if (!uri_data->token_info) {
					results = g_list_prepend (results, g_object_ref (s->data));
				} else {
					token_info = gck_slot_get_token_info (s->data);
					if (token_info && _gck_token_info_match (uri_data->token_info, token_info))
						results = g_list_prepend (results, g_object_ref (s->data));
					gck_token_info_free (token_info);
				}
			}
			gck_list_unref_free (slots);
		}
	}

	gck_uri_data_free (uri_data);
	return results;
}

/**
 * gck_modules_token_for_uri:
 * @modules: (element-type Gck.Module): The modules
 * @uri: The URI that the token must match
 * @error: A location to raise an error on failure
 *
 * Lookup a token that matches the URI.
 *
 * Returns: (transfer full): A newly allocated #GckSlot or %NULL if no such
 * token was found.
 */
GckSlot*
gck_modules_token_for_uri (GList *modules,
                           const gchar *uri,
                           GError **error)
{
	GList *results;
	GckSlot *slot = NULL;

	results = tokens_for_uri (modules, uri, TRUE, error);
	if (results)
		slot = g_object_ref (results->data);
	gck_list_unref_free (results);

	return slot;
}

/**
 * gck_modules_tokens_for_uri:
 * @modules: (element-type Gck.Module): The modules
 * @uri: The URI that the token must match
 * @error: A location to raise an error on failure
 *
 * Lookup a token that matches the URI.
 *
 * Returns: (transfer full) (element-type Gck.Slot): A list of newly allocated
 * #GckSlot objects. Use gck_list_unref_free() to release the list once you're
 * done with it.
 */
GList *
gck_modules_tokens_for_uri (GList *modules,
                            const gchar *uri,
                            GError **error)
{
	return tokens_for_uri (modules, uri, FALSE, error);
}

/**
 * gck_modules_object_for_uri:
 * @modules: (element-type Gck.Module): The modules
 * @uri: The URI the objects must match
 * @session_options: Options from GckSessionOptions
 * @error: A location to raise an error on failure.
 *
 * Find an object that matches a URI.
 *
 * This call can block. Use gck_modules_enumerate_uri() for a non-blocking
 * version.
 *
 * Returns: (transfer full) (allow-none): A new #GckObject which should be released with
 * g_object_unref(), or %NULL if no matching object was found.
 */
GckObject*
gck_modules_object_for_uri (GList *modules, const gchar *uri, guint session_options,
                            GError **error)
{
	GckEnumerator *en;
	GckObject *result;

	g_return_val_if_fail (uri, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	en = gck_modules_enumerate_uri (modules, uri, session_options, error);
	if (en == NULL)
		return NULL;

	result = gck_enumerator_next (en, NULL, error);
	g_object_unref (en);

	return result;
}

/**
 * gck_modules_objects_for_uri:
 * @modules: (element-type Gck.Module): The modules
 * @uri: The URI the objects must match
 * @session_options: Options from GckSessionOptions
 * @error: A location to raise an error on failure.
 *
 * Find objects that match a URI.
 *
 * This call can block. Use gck_modules_enumerate_uri() for a non-blocking
 * version.
 *
 * Returns: (transfer full) (element-type Gck.Object): A list of #GckObject which
 * should be released with gck_list_unref_free(), or %NULL if no matching object
 * was found.
 */
GList*
gck_modules_objects_for_uri (GList *modules, const gchar *uri, guint session_options,
                             GError **error)
{
	GckEnumerator *en;
	GList *results;

	g_return_val_if_fail (uri, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	en = gck_modules_enumerate_uri (modules, uri, session_options, error);
	if (en == NULL)
		return NULL;

	results = gck_enumerator_next_n (en, -1, NULL, error);
	g_object_unref (en);

	return results;
}

/**
 * gck_modules_enumerate_uri:
 * @modules: (element-type Gck.Module): The modules
 * @uri: The URI that the enumerator will match
 * @session_options: Options from GckSessionOptions
 * @error: A location to raise an error on failure.
 *
 * Enumerate objects that match a URI.
 *
 * This call will not block. Use the #GckEnumerator functions in order to
 * get at the actual objects that match.
 *
 * Returns: (transfer full): A new #GckEnumerator, or %NULL if an error occurs.
 */
GckEnumerator*
gck_modules_enumerate_uri (GList *modules, const gchar *uri, guint session_options,
                           GError **error)
{
	GckUriData *uri_data;

	uri_data = gck_uri_parse (uri, GCK_URI_FOR_ANY, error);
	if (uri_data == NULL)
		return NULL;

	/* Takes ownership of uri_info */
	return _gck_enumerator_new (modules, session_options, uri_data);
}
