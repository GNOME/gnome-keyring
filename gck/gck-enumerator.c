/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-enumerator.c - the GObject PKCS#11 wrapper library

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

   Author: Stef Walter <nielsen@memberwebs.com>
*/

#include "config.h"

#include "gck.h"
#define DEBUG_FLAG GCK_DEBUG_ENUMERATOR
#include "gck-debug.h"
#include "gck-private.h"

#include <string.h>

/**
 * SECTION:gck-enumerator
 * @title: GckEnumerator
 * @short_description: Enumerates through PKCS\#11 objects.
 *
 * A GckEnumerator can be used to enumerate through PKCS\#11 objects. It will
 * automatically create sessions as necessary.
 *
 * Use gck_modules_enumerate_objects() or gck_modules_enumerate_uri() to create
 * an enumerator. To get the objects use gck_enumerator_next() or
 * gck_enumerator_next_async() functions.
 */

enum {
	PROP_0,
	PROP_INTERACTION
};

/**
 * GckEnumerator:
 * @parent: derived from this.
 *
 * An object that allows enumerating of objects across modules, tokens.
 */

typedef struct _GckEnumeratorState GckEnumeratorState;

typedef gpointer (*GckEnumeratorFunc) (GckEnumeratorState *args, gboolean forward);

struct _GckEnumeratorState {
	/* For the current call */
	gint want_objects;

	/* The state we're currently in */
	GckEnumeratorFunc handler;

	/* Input to enumerator */
	GList *modules;
	GckUriData *match;
	GckSessionOptions session_options;
	GTlsInteraction *interaction;

	/* state_slots */
	GList *slots;

	/* state_slot */
	GckSlot *slot;
	GckTokenInfo *token_info;
	CK_FUNCTION_LIST_PTR funcs;

	/* state_session */
	GckSession *session;

	/* state_results */
	GArray *objects;

	/* Output from enumerator */
	GList *results;
};

struct _GckEnumeratorPrivate {
	GMutex *mutex;
	GckEnumeratorState *the_state;
	GTlsInteraction *interaction;
};

G_DEFINE_TYPE (GckEnumerator, gck_enumerator, G_TYPE_OBJECT);

static gpointer state_modules        (GckEnumeratorState *args, gboolean forward);
static gpointer state_slots          (GckEnumeratorState *args, gboolean forward);
static gpointer state_slot           (GckEnumeratorState *args, gboolean forward);
static gpointer state_session        (GckEnumeratorState *args, gboolean forward);
static gpointer state_authenticated  (GckEnumeratorState *args, gboolean forward);
static gpointer state_results        (GckEnumeratorState *args, gboolean forward);

/* ----------------------------------------------------------------------------
 * INTERNAL
 */

static gpointer
rewind_state (GckEnumeratorState *args, GckEnumeratorFunc handler)
{
	g_assert (args);
	g_assert (handler);
	g_assert (args->handler);

	while (handler != args->handler) {
		args->handler = (args->handler) (args, FALSE);
		g_assert (args->handler);
	}

	return handler;
}

static void
cleanup_state (GckEnumeratorState *args)
{
	g_assert (args);

	/* Have each state cleanup */
	rewind_state (args, state_modules);

	/* state_slots */
	g_assert (!args->slots);

	/* state_slot */
	g_assert (!args->slot);
	g_assert (!args->token_info);
	g_assert (!args->funcs);

	/* state_session */
	g_assert (!args->session);

	/* state_results */
	if (args->objects)
		g_array_free (args->objects, TRUE);
	args->objects = NULL;

	/* Other cleanup */
	gck_list_unref_free (args->results);
	args->results = NULL;

	gck_list_unref_free (args->modules);
	args->modules = NULL;

	g_clear_object (&args->interaction);

	if (args->match) {
		if (args->match->attributes)
			_gck_attributes_unlock (args->match->attributes);
		gck_uri_data_free (args->match);
		args->match = NULL;
	}
}

static gpointer
state_modules (GckEnumeratorState *args, gboolean forward)
{
	GckModule *module;

	g_assert (args->slots == NULL);

	if (forward) {

		/* There are no more modules? */
		if (!args->modules) {
			_gck_debug ("no more modules, stopping enumerator");
			return NULL;
		}

		/* Pop off the current module */
		module = args->modules->data;
		g_assert (GCK_IS_MODULE (module));
		args->modules = g_list_delete_link (args->modules, args->modules);

		args->slots = gck_module_get_slots (module, TRUE);

		if (_gck_debugging) {
			GckModuleInfo *info = gck_module_get_info (module);
			_gck_debug ("enumerating into module: %s", info->library_description);
			gck_module_info_free (info);
		}

		g_object_unref (module);
		return state_slots;
	}

	/* Should never be asked to go backward from start state */
	g_assert_not_reached ();
}

static gpointer
state_slots (GckEnumeratorState *args, gboolean forward)
{
	GckSlot *slot;
	GckModule *module;
	GckTokenInfo *token_info;
	gboolean matched;

	g_assert (args->slot == NULL);

	/* slots to slot state */
	if (forward) {

		/* If there are no more slots go back to start state */
		if (!args->slots) {
			_gck_debug ("no more slots, want next module");
			return rewind_state (args, state_modules);
		}

		/* Pop the next slot off the stack */
		slot = args->slots->data;
		args->slots = g_list_delete_link (args->slots, args->slots);

		token_info = gck_slot_get_token_info (slot);
		if (!token_info) {
			g_message ("couldn't get token info while enumerating");
			g_object_unref (slot);
			return rewind_state (args, state_modules);
		}

		/* Do we have unrecognized matches? */
		if (args->match->any_unrecognized) {
			_gck_debug ("token uri had unrecognized, not matching any tokens");
			matched = FALSE;

		/* Are we trying to match the slot? */
		} else if (args->match->token_info) {
			/* No match? Go to next slot */
			matched = _gck_token_info_match (args->match->token_info, token_info);

			_gck_debug ("%s token: %s", matched ? "matched" : "did not match",
			            token_info->label);

		} else {
			_gck_debug ("matching all tokens: %s", token_info->label);
			matched = TRUE;
		}

		if (!matched) {
			g_object_unref (slot);
			gck_token_info_free (token_info);
			return state_slots;
		}

		module = gck_slot_get_module (slot);
		args->funcs = gck_module_get_functions (module);
		g_assert (args->funcs);
		g_object_unref (module);

		/* We have a slot */
		args->slot = slot;
		args->token_info = token_info;
		return state_slot;

	/* slots state to modules state */
	} else {

		gck_list_unref_free (args->slots);
		args->slots = NULL;
		return state_modules;
	}
}

static gpointer
state_slot (GckEnumeratorState *args, gboolean forward)
{
	CK_SESSION_HANDLE session;
	CK_FLAGS flags;
	CK_RV rv;

	g_assert (args->slot);
	g_assert (args->funcs);
	g_assert (args->session == NULL);

	/* slot to session state */
	if (forward) {
		flags = CKF_SERIAL_SESSION;
		if ((args->session_options & GCK_SESSION_READ_WRITE) == GCK_SESSION_READ_WRITE)
			flags |= CKF_RW_SESSION;

		rv = (args->funcs->C_OpenSession) (gck_slot_get_handle (args->slot),
		                                   flags, NULL, NULL, &session);

		if (rv != CKR_OK) {
			g_message ("couldn't open session on module while enumerating objects: %s",
			           gck_message_from_rv (rv));
			return rewind_state (args, state_slots);
		}

		_gck_debug ("opened %s session", flags & CKF_RW_SESSION ? "read-write" : "read-only");
		args->session = gck_session_from_handle (args->slot, session, args->session_options);
		return state_session;

	/* slot to slots state */
	} else {
		g_object_unref (args->slot);
		args->slot = NULL;
		args->funcs = NULL;

		gck_token_info_free (args->token_info);
		args->token_info = NULL;

		return state_slots;
	}
}

static gpointer
state_session (GckEnumeratorState *args, gboolean forward)
{
	GTlsInteraction *interaction;
	CK_RV rv;

	g_assert (args->funcs);
	g_assert (args->session);
	g_assert (args->token_info);

	/* session to authenticated state */
	if (forward) {

		/* Don't want to authenticate? */
		if ((args->session_options & GCK_SESSION_LOGIN_USER) == 0) {
			_gck_debug ("no authentication necessary, skipping");
			return state_authenticated;
		}

		/* Compatibility, hook into GckModule signals if no interaction set */
		if (args->interaction)
			interaction = g_object_ref (args->interaction);
		else
			interaction = _gck_interaction_new (args->slot);

		rv = _gck_session_authenticate_token (args->funcs,
		                                      gck_session_get_handle (args->session),
		                                      args->slot, interaction, NULL);

		g_object_unref (interaction);

		if (rv != CKR_OK)
			g_message ("couldn't authenticate when enumerating: %s", gck_message_from_rv (rv));

		/* We try to proceed anyway with the enumeration */
		return state_authenticated;

	/* Session to slot state */
	} else {
		g_object_unref (args->session);
		args->session = NULL;
		return state_slot;
	}
}

static gpointer
state_authenticated (GckEnumeratorState *args, gboolean forward)
{
	CK_OBJECT_HANDLE objects[128];
	CK_SESSION_HANDLE session;
	CK_ATTRIBUTE_PTR attrs;
	CK_ULONG n_attrs, count;
	CK_RV rv;

	/* Just go back, no logout */
	if (!forward)
		return state_session;

	/* This is where we do the actual searching */

	g_assert (args->session);
	g_assert (args->want_objects);
	g_assert (args->funcs);

	if (args->match->attributes) {
		attrs = _gck_attributes_commit_out (args->match->attributes, &n_attrs);
		if (_gck_debugging) {
			gchar *string = _gck_attributes_format (args->match->attributes);
			_gck_debug ("finding objects matching: %s", string);
			g_free (string);
		}
	} else {
		attrs = NULL;
		n_attrs = 0;
		_gck_debug ("finding all objects");
	}

	session = gck_session_get_handle (args->session);
	g_return_val_if_fail (session, NULL);

	/* Get all the objects */
	rv = (args->funcs->C_FindObjectsInit) (session, attrs, n_attrs);

	if (rv == CKR_OK) {
		for(;;) {
			rv = (args->funcs->C_FindObjects) (session, objects, G_N_ELEMENTS (objects), &count);
			if (rv != CKR_OK || count == 0)
				break;

			if (!args->objects)
				args->objects = g_array_new (FALSE, TRUE, sizeof (CK_OBJECT_HANDLE));
			_gck_debug ("matched %lu objects", count);
			g_array_append_vals (args->objects, objects, count);
		}

		(args->funcs->C_FindObjectsFinal) (session);
	}

	_gck_debug ("finding objects completed with: %s", _gck_stringize_rv (rv));
	return state_results;
}

static GckObject*
extract_result (GckEnumeratorState *args)
{
	CK_OBJECT_HANDLE handle;

	if (!args->objects || !args->objects->len)
		return NULL;

	g_assert (args->session);

	handle = g_array_index (args->objects, CK_OBJECT_HANDLE, 0);
	g_array_remove_index_fast (args->objects, 0);

	return gck_object_from_handle (args->session, handle);
}

static gpointer
state_results (GckEnumeratorState *args, gboolean forward)
{
	GckObject *object;
	guint have;

	g_assert (args->session);

	/* No cleanup, just unwind */
	if (!forward)
		return state_authenticated;

	/* Create result objects from what we have */
	have = g_list_length (args->results);

	while (have < args->want_objects) {

		object = extract_result (args);
		if (!object) {
			_gck_debug ("wanted %d objects, have %d, looking for more",
			            args->want_objects, have);
			return rewind_state (args, state_slots);
		}

		args->results = g_list_append (args->results, object);
		++have;
	}

	_gck_debug ("wanted %d objects, returned %d objects",
	            args->want_objects, have);

	/* We got all the results we wanted */
	return NULL;
}

/* ----------------------------------------------------------------------------
 * OBJECT
 */

static void
gck_enumerator_init (GckEnumerator *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_ENUMERATOR, GckEnumeratorPrivate);
	self->pv->mutex = g_mutex_new ();
	self->pv->the_state = g_new0 (GckEnumeratorState, 1);
}

static void
gck_enumerator_get_property (GObject *obj,
                             guint prop_id,
                             GValue *value,
                             GParamSpec *pspec)
{
	GckEnumerator *self = GCK_ENUMERATOR (obj);

	switch (prop_id) {
	case PROP_INTERACTION:
		g_value_take_object (value, gck_enumerator_get_interaction (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_enumerator_set_property (GObject *obj,
                             guint prop_id,
                             const GValue *value,
                             GParamSpec *pspec)
{
	GckEnumerator *self = GCK_ENUMERATOR (obj);

	switch (prop_id) {
	case PROP_INTERACTION:
		gck_enumerator_set_interaction (self, g_value_get_object (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_enumerator_dispose (GObject *obj)
{
	GckEnumerator *self = GCK_ENUMERATOR (obj);

	gck_enumerator_set_interaction (self, NULL);

	G_OBJECT_CLASS (gck_enumerator_parent_class)->dispose (obj);
}

static void
gck_enumerator_finalize (GObject *obj)
{
	GckEnumerator *self = GCK_ENUMERATOR (obj);

	g_assert (self->pv->interaction == NULL);

	g_assert (self->pv->the_state != NULL);
	cleanup_state (self->pv->the_state);
	g_free (self->pv->the_state);

	g_mutex_free (self->pv->mutex);

	G_OBJECT_CLASS (gck_enumerator_parent_class)->finalize (obj);
}

static void
gck_enumerator_class_init (GckEnumeratorClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gobject_class->get_property = gck_enumerator_get_property;
	gobject_class->set_property = gck_enumerator_set_property;
	gobject_class->dispose = gck_enumerator_dispose;
	gobject_class->finalize = gck_enumerator_finalize;

	g_type_class_add_private (klass, sizeof (GckEnumeratorPrivate));

	/**
	 * GckEnumerator:interaction:
	 *
	 * Interaction object used to ask the user for pins when opening
	 * sessions. Used if the session_options of the enumerator have
	 * %GCK_SESSION_LOGIN_USER
	 */
	g_object_class_install_property (gobject_class, PROP_INTERACTION,
		g_param_spec_object ("interaction", "Interaction", "Interaction asking for pins",
		                     G_TYPE_TLS_INTERACTION, G_PARAM_READWRITE));
}

/* ----------------------------------------------------------------------------
 * PUBLIC
 */

GckEnumerator*
_gck_enumerator_new (GList *modules_or_slots,
                     GckSessionOptions session_options,
                     GckUriData *uri_data)
{
	GckEnumerator *self;
	GckEnumeratorState *state;

	self = g_object_new (GCK_TYPE_ENUMERATOR, NULL);
	state = self->pv->the_state;

	state->session_options = session_options;

	if (modules_or_slots && GCK_IS_SLOT (modules_or_slots->data)) {
		state->slots = gck_list_ref_copy (modules_or_slots);
		state->modules = NULL;
		state->handler = state_slots;
	} else {
		state->modules = gck_list_ref_copy (modules_or_slots);
		state->slots = NULL;
		state->handler = state_modules;
	}

	state->match = uri_data;
	if (uri_data->attributes)
		_gck_attributes_lock (uri_data->attributes);

	if (_gck_debugging) {
		gchar *attrs, *uri;
		attrs = uri_data->attributes ? _gck_attributes_format (uri_data->attributes) : NULL;
		uri = uri_data ? gck_uri_build (uri_data, GCK_URI_FOR_TOKEN | GCK_URI_FOR_MODULE) : NULL;
		_gck_debug ("new enumerator: tokens = %s, objects = %s", uri, attrs);
		g_free (attrs);
		g_free (uri);
	}

	return self;
}

typedef struct _EnumerateNext {
	GckArguments base;
	GckEnumeratorState *state;
} EnumerateNext;

static CK_RV
perform_enumerate_next (EnumerateNext *args)
{
	GckEnumeratorFunc handler;
	GckEnumeratorState *state;

	g_assert (args->state);
	state = args->state;

	g_assert (state->handler);

	for (;;) {
		handler = (state->handler) (state, TRUE);
		if (!handler)
			break;
		state->handler = handler;
	}

	/* TODO: In some modes, errors */
	return CKR_OK;
}

static void
free_enumerate_next (EnumerateNext *args)
{
	/* Should have been assigned back to enumerator */
	g_assert (!args->state);

	g_free (args);
}

/**
 * gck_enumerator_get_interaction:
 * @self: the enumerator
 *
 * Get the interaction used when a pin is needed
 *
 * Returns: (transfer full) (allow-none): the interaction or %NULL
 */
GTlsInteraction *
gck_enumerator_get_interaction (GckEnumerator *self)
{
	GTlsInteraction *result = NULL;

	g_return_val_if_fail (GCK_IS_ENUMERATOR (self), NULL);

	g_mutex_lock (self->pv->mutex);

		if (self->pv->interaction)
			result = g_object_ref (self->pv->interaction);

	g_mutex_unlock (self->pv->mutex);

	return result;
}

/**
 * gck_enumerator_set_interaction:
 * @self: the enumerator
 * @interaction: (allow-none): the interaction or %NULL
 *
 * Set the interaction used when a pin is needed
 */
void
gck_enumerator_set_interaction (GckEnumerator *self,
                                GTlsInteraction *interaction)
{
	GTlsInteraction *previous = NULL;

	g_return_if_fail (GCK_IS_ENUMERATOR (self));
	g_return_if_fail (interaction == NULL || G_IS_TLS_INTERACTION (interaction));

	g_mutex_lock (self->pv->mutex);

		if (interaction != self->pv->interaction) {
			previous = self->pv->interaction;
			self->pv->interaction = interaction;
			if (interaction)
				g_object_ref (interaction);
		}

	g_mutex_unlock (self->pv->mutex);

	g_clear_object (&previous);
	g_object_notify (G_OBJECT (self), "interaction");
}

static GckEnumeratorState *
check_out_enumerator_state (GckEnumerator *self)
{
	GckEnumeratorState *state = NULL;

	g_mutex_lock (self->pv->mutex);

		if (self->pv->the_state) {
			state = self->pv->the_state;
			self->pv->the_state = NULL;

			g_clear_object (&state->interaction);
			if (self->pv->interaction)
				state->interaction = g_object_ref (self->pv->interaction);
		}

	g_mutex_unlock (self->pv->mutex);

	if (state == NULL)
		g_warning ("this enumerator is already running a next operation");

	return state;
}

static void
check_in_enumerator_state (GckEnumerator *self,
                           GckEnumeratorState *state)
{
	g_mutex_lock (self->pv->mutex);

		g_assert (self->pv->the_state == NULL);
		self->pv->the_state = state;

	g_mutex_unlock (self->pv->mutex);
}

/**
 * gck_enumerator_next:
 * @self: The enumerator
 * @cancellable: A #GCancellable or %NULL
 * @error: A location to store an error on failure
 *
 * Get the next object in the enumerator, or %NULL if there are no more objects.
 *
 * %NULL is also returned if the function fails. Use the @error to determine
 * whether a failure occurred or not.
 *
 * Returns: (transfer full) (allow-none): The next object, which must be released
 * using g_object_unref, or %NULL.
 */
GckObject*
gck_enumerator_next (GckEnumerator *self, GCancellable *cancellable, GError **error)
{
	EnumerateNext args = { GCK_ARGUMENTS_INIT, NULL, };
	GckObject *result = NULL;

	g_return_val_if_fail (GCK_IS_ENUMERATOR (self), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	args.state = check_out_enumerator_state (self);
	g_return_val_if_fail (args.state != NULL, NULL);

	/* A result from a previous run? */
	result = extract_result (args.state);
	if (!result) {
		args.state->want_objects = 1;

		/* Run the operation and steal away the results */
		if (_gck_call_sync (NULL, perform_enumerate_next, NULL, &args, cancellable, error)) {
			if (args.state->results) {
				g_assert (g_list_length (args.state->results) == 1);
				result = g_object_ref (args.state->results->data);
				gck_list_unref_free (args.state->results);
				args.state->results = NULL;
			}
		}

		args.state->want_objects = 0;
	}

	/* Put the state back */
	check_in_enumerator_state (self, args.state);

	return result;
}

/**
 * gck_enumerator_next_n:
 * @self: An enumerator
 * @max_objects: The maximum amount of objects to enumerate
 * @cancellable: A #GCancellable or %NULL
 * @error: A location to store an error on failure
 *
 * Get the next set of objects from the enumerator. The maximum number of
 * objects can be specified with @max_objects. If -1 is specified, then all
 * the remaining objects will be returned.
 *
 * %NULL is also returned if the function fails. Use the @error to determine
 * whether a failure occurred or not.
 *
 * Returns: (transfer full) (element-type Gck.Object): A list of objects, which
 * should be freed using gck_list_unref_free().
 */
GList*
gck_enumerator_next_n (GckEnumerator *self, gint max_objects, GCancellable *cancellable,
                       GError **error)
{
	EnumerateNext args = { GCK_ARGUMENTS_INIT, NULL, };
	GList *results = NULL;

	g_return_val_if_fail (GCK_IS_ENUMERATOR (self), NULL);
	g_return_val_if_fail (max_objects == -1 || max_objects > 0, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	/* Remove the state and own it ourselves */
	args.state = check_out_enumerator_state (self);
	g_return_val_if_fail (args.state != NULL, NULL);

	args.state->want_objects = max_objects <= 0 ? G_MAXINT : max_objects;

	/* Run the operation and steal away the results */
	if (_gck_call_sync (NULL, perform_enumerate_next, NULL, &args, cancellable, error)) {
		results = args.state->results;
		args.state->results = NULL;
	}

	args.state->want_objects = 0;

	/* Put the state back */
	check_in_enumerator_state (self, args.state);

	return results;
}

/**
 * gck_enumerator_next_async:
 * @self: An enumerator
 * @max_objects: The maximum number of objects to get
 * @cancellable: A #GCancellable or %NULL
 * @callback: Called when the result is ready
 * @user_data: Data to pass to the callback
 *
 * Get the next set of objects from the enumerator. This operation completes
 * asynchronously.The maximum number of objects can be specified with
 * @max_objects. If -1 is specified, then all the remaining objects will be
 * enumerated.
 */
void
gck_enumerator_next_async (GckEnumerator *self, gint max_objects, GCancellable *cancellable,
                           GAsyncReadyCallback callback, gpointer user_data)
{
	GckEnumeratorState *state;
	EnumerateNext *args;

	g_return_if_fail (GCK_IS_ENUMERATOR (self));
	g_return_if_fail (max_objects == -1 || max_objects > 0);

	g_object_ref (self);

	/* Remove the state and own it ourselves */
	state = check_out_enumerator_state (self);
	g_return_if_fail (state != NULL);

	state->want_objects = max_objects <= 0 ? G_MAXINT : max_objects;
	args =  _gck_call_async_prep (NULL, self, perform_enumerate_next, NULL,
	                               sizeof (*args), free_enumerate_next);

	args->state = state;
	_gck_call_async_ready_go (args, cancellable, callback, user_data);
	g_object_unref (self);
}

/**
 * gck_enumerator_next_finish:
 * @self: An enumerator
 * @result: The result passed to the callback
 * @error: A location to raise an error on failure.
 *
 * Complete an operation to enumerate next objects.
 *
 * %NULL is also returned if the function fails. Use the @error to determine
 * whether a failure occurred or not.
 *
 * Returns: (element-type Gck.Module) (transfer full): The list of objects, which
 * should be freed with gck_list_unref_free()
 */
GList*
gck_enumerator_next_finish (GckEnumerator *self, GAsyncResult *result, GError **error)
{
	EnumerateNext *args;
	GckEnumeratorState *state;
	GList *results = NULL;

	g_object_ref (self);

	args = _gck_call_arguments (result, EnumerateNext);
	state = args->state;
	args->state = NULL;
	state->want_objects = 0;

	if (_gck_call_basic_finish (result, error)) {
		results = state->results;
		state->results = NULL;
	}

	/* Put the state back */
	check_in_enumerator_state (self, state);

	g_object_unref (self);

	return results;
}
