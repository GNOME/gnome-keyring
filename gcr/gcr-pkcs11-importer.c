/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2011 Collabora Ltd.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gcr-base.h"
#include "gcr-internal.h"
#include "gcr-library.h"
#include "gcr-internal.h"
#include "gcr-parser.h"
#include "gcr-pkcs11-importer.h"

#include <gck/gck.h>

#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_LABEL,
	PROP_ICON,
	PROP_SLOT,
	PROP_IMPORTED
};

struct _GcrPkcs11ImporterPrivate {
	GckSlot *slot;
	GList *objects;
	GckSession *session;
	GQueue queue;
	gboolean any_private;
};

typedef struct  {
	GcrPkcs11Importer *importer;
	GCancellable *cancellable;
	gboolean prompted;
	gboolean async;
} GcrImporterData;

/* State forward declarations */
static void   state_cancelled                  (GSimpleAsyncResult *res,
                                                gboolean async);

static void   state_complete                   (GSimpleAsyncResult *res,
                                                gboolean async);

static void   state_create_object              (GSimpleAsyncResult *res,
                                                gboolean async);

static void   state_open_session               (GSimpleAsyncResult *res,
                                                gboolean async);

static void   _gcr_pkcs11_importer_init_iface  (GcrImporterIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrPkcs11Importer, _gcr_pkcs11_importer, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GCR_TYPE_IMPORTER, _gcr_pkcs11_importer_init_iface);
);

#define BLOCK 4096

static void
gcr_importer_data_free (gpointer data)
{
	GcrImporterData *state = data;

	g_clear_object (&state->cancellable);
	g_clear_object (&state->importer);
	g_free (state);
}

static void
next_state (GSimpleAsyncResult *res,
            void (*state) (GSimpleAsyncResult *, gboolean))
{
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);

	g_assert (state);

	if (g_cancellable_is_cancelled (data->cancellable))
		state = state_cancelled;

	(state) (res, data->async);
}

/* ---------------------------------------------------------------------------------
 * COMPLETE
 */

static void
state_complete (GSimpleAsyncResult *res,
                gboolean async)
{
	g_simple_async_result_complete (res);
}

static void
state_cancelled (GSimpleAsyncResult *res,
                 gboolean async)
{
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	if (data->cancellable && !g_cancellable_is_cancelled (data->cancellable))
		g_cancellable_cancel (data->cancellable);

	g_cancellable_set_error_if_cancelled (data->cancellable, &error);
	g_simple_async_result_take_error (res, error);
	next_state (res, state_complete);
}

/* ---------------------------------------------------------------------------------
 * CREATE OBJECTS
 */

static void
complete_create_object (GSimpleAsyncResult *res,
                        GckObject *object,
                        GError *error)
{
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);
	GcrPkcs11Importer *self = data->importer;

	if (object == NULL) {
		g_simple_async_result_take_error (res, error);
		next_state (res, state_complete);

	} else {
		self->pv->objects = g_list_append (self->pv->objects, object);
		next_state (res, state_create_object);
	}
}

static void
on_create_object (GObject *source,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;
	GckObject *object;

	object = gck_session_create_object_finish (GCK_SESSION (source), result, &error);
	complete_create_object (res, object, error);
	g_object_unref (res);
}

static void
state_create_object (GSimpleAsyncResult *res,
                     gboolean async)
{
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);
	GcrPkcs11Importer *self = data->importer;
	GckAttributes *attrs;
	GckObject *object;
	GError *error = NULL;

	/* No more objects */
	if (g_queue_is_empty (&self->pv->queue)) {
		next_state (res, state_complete);

	} else {

		/* Pop first one off the list */
		attrs = g_queue_pop_head (&self->pv->queue);
		g_assert (attrs != NULL);

		gck_attributes_add_boolean (attrs, CKA_TOKEN, CK_TRUE);

		if (async) {
			gck_session_create_object_async (self->pv->session, attrs,
			                                 data->cancellable, on_create_object,
			                                 g_object_ref (res));
		} else {
			object = gck_session_create_object (self->pv->session, attrs,
			                                    data->cancellable, &error);
			complete_create_object (res, object, error);
		}

		gck_attributes_unref (attrs);
	}
}

/* ---------------------------------------------------------------------------------
 * OPEN SESSION
 */

static void
complete_open_session (GSimpleAsyncResult *res,
                       GckSession *session,
                       GError *error)
{
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);
	GcrPkcs11Importer *self = data->importer;

	if (!session) {
		g_simple_async_result_take_error (res, error);
		next_state (res, state_complete);

	} else {
		g_clear_object (&self->pv->session);
		self->pv->session = session;
		next_state (res, state_create_object);
	}
}

static void
on_open_session (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;
	GckSession *session;

	session = gck_slot_open_session_finish (GCK_SLOT (source), result, &error);
	complete_open_session (res, session, error);
	g_object_unref (res);
}

static void
state_open_session (GSimpleAsyncResult *res,
                    gboolean async)
{
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);
	GcrPkcs11Importer *self = data->importer;
	guint options = GCK_SESSION_READ_WRITE;
	GckSession *session;
	GError *error = NULL;

	if (self->pv->any_private)
		options |= GCK_SESSION_LOGIN_USER;

	if (async) {
		gck_slot_open_session_async (self->pv->slot, options,
		                             data->cancellable, on_open_session,
		                             g_object_ref (res));
	} else {
		session = gck_slot_open_session_full (self->pv->slot, options, 0,
		                                      NULL, NULL, data->cancellable, &error);
		complete_open_session (res, session, error);
	}
}

static void
_gcr_pkcs11_importer_init (GcrPkcs11Importer *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_PKCS11_IMPORTER, GcrPkcs11ImporterPrivate);
	g_queue_init (&self->pv->queue);
}

static void
_gcr_pkcs11_importer_dispose (GObject *obj)
{
	GcrPkcs11Importer *self = GCR_PKCS11_IMPORTER (obj);

	gck_list_unref_free (self->pv->objects);
	self->pv->objects = NULL;
	g_clear_object (&self->pv->session);

	while (!g_queue_is_empty (&self->pv->queue))
		gck_attributes_unref (g_queue_pop_head (&self->pv->queue));

	G_OBJECT_CLASS (_gcr_pkcs11_importer_parent_class)->dispose (obj);
}

static void
_gcr_pkcs11_importer_finalize (GObject *obj)
{
	GcrPkcs11Importer *self = GCR_PKCS11_IMPORTER (obj);

	g_clear_object (&self->pv->slot);

	G_OBJECT_CLASS (_gcr_pkcs11_importer_parent_class)->finalize (obj);
}

static void
_gcr_pkcs11_importer_set_property (GObject *obj,
                                   guint prop_id,
                                   const GValue *value,
                                   GParamSpec *pspec)
{
	GcrPkcs11Importer *self = GCR_PKCS11_IMPORTER (obj);

	switch (prop_id) {
	case PROP_SLOT:
		self->pv->slot = g_value_dup_object (value);
		g_return_if_fail (self->pv->slot);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static gchar *
calculate_label (GcrPkcs11Importer *self)
{
	GckTokenInfo *info;
	gchar *result;

	info = gck_slot_get_token_info (self->pv->slot);
	result = g_strdup (info->label);
	gck_token_info_free (info);

	return result;
}

static GIcon *
calculate_icon (GcrPkcs11Importer *self,
                GckTokenInfo *token_info)
{
	GckTokenInfo *info = NULL;
	GIcon *result;

	if (token_info == NULL)
		info = token_info = gck_slot_get_token_info (self->pv->slot);
	result = gcr_icon_for_token (token_info);
	gck_token_info_free (info);

	return result;
}

static void
_gcr_pkcs11_importer_get_property (GObject *obj,
                                   guint prop_id,
                                   GValue *value,
                                   GParamSpec *pspec)
{
	GcrPkcs11Importer *self = GCR_PKCS11_IMPORTER (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_take_string (value, calculate_label (self));
		break;
	case PROP_ICON:
		g_value_take_object (value, calculate_icon (self, NULL));
		break;
	case PROP_SLOT:
		g_value_set_object (value, _gcr_pkcs11_importer_get_slot (self));
		break;
	case PROP_IMPORTED:
		g_value_set_boxed (value, _gcr_pkcs11_importer_get_imported (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_pkcs11_importer_class_init (GcrPkcs11ImporterClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckAttributes *registered;

	gobject_class->dispose = _gcr_pkcs11_importer_dispose;
	gobject_class->finalize = _gcr_pkcs11_importer_finalize;
	gobject_class->set_property = _gcr_pkcs11_importer_set_property;
	gobject_class->get_property = _gcr_pkcs11_importer_get_property;

	g_type_class_add_private (gobject_class, sizeof (GcrPkcs11ImporterPrivate));

	g_object_class_override_property (gobject_class, PROP_LABEL, "label");

	g_object_class_override_property (gobject_class, PROP_ICON, "icon");

	g_object_class_install_property (gobject_class, PROP_SLOT,
	           g_param_spec_object ("slot", "Slot", "PKCS#11 slot to import data into",
	                                GCK_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_IMPORTED,
	           g_param_spec_boxed ("imported", "Imported", "Imported objects",
	                               GCK_TYPE_LIST, G_PARAM_READABLE));

	registered = gck_attributes_new ();
	gck_attributes_add_ulong (registered, CKA_CLASS, CKO_CERTIFICATE);
	gck_attributes_add_ulong (registered, CKA_CERTIFICATE_TYPE, CKC_X_509);
	gcr_importer_register (GCR_TYPE_PKCS11_IMPORTER, registered);
	gck_attributes_unref (registered);

	registered = gck_attributes_new ();
	gck_attributes_add_ulong (registered, CKA_CLASS, CKO_PRIVATE_KEY);
	gcr_importer_register (GCR_TYPE_PKCS11_IMPORTER, registered);
	gck_attributes_unref (registered);

	_gcr_initialize_library ();
}

static GList *
list_all_slots (void)
{
	GList *modules;
	GList *results;

	modules = gcr_pkcs11_get_modules ();
	results = gck_modules_get_slots (modules, TRUE);
	gck_list_unref_free (modules);

	return results;
}

static const char *token_blacklist[] = {
	"pkcs11:manufacturer=Gnome%20Keyring;serial=1:SECRET:MAIN",
	NULL
};

static gboolean
is_slot_importable (GckSlot *slot,
                    GckTokenInfo *token)
{
	GError *error = NULL;
	GckUriData *uri;
	gboolean match;
	guint i;

	if (token->flags & CKF_WRITE_PROTECTED)
		return FALSE;
	if (!(token->flags & CKF_TOKEN_INITIALIZED))
		return FALSE;
	if ((token->flags & CKF_LOGIN_REQUIRED) &&
	    !(token->flags & CKF_USER_PIN_INITIALIZED))
		return FALSE;

	for (i = 0; token_blacklist[i] != NULL; i++) {
		uri = gck_uri_parse (token_blacklist[i], GCK_URI_FOR_TOKEN | GCK_URI_FOR_MODULE, &error);
		if (uri == NULL) {
			g_warning ("couldn't parse pkcs11 blacklist uri: %s", error->message);
			g_clear_error (&error);
			continue;
		}

		match = gck_slot_match (slot, uri);
		gck_uri_data_free (uri);

		if (match)
			return FALSE;
	}

	return TRUE;
}

static GList *
_gcr_pkcs11_importer_create_for_parsed (GcrParsed *parsed)
{
	GcrImporter *self;
	GList *slots, *l;
	GList *results = NULL;
	GckTokenInfo *token_info;
	gboolean importable;

	slots = list_all_slots ();
	for (l = slots; l != NULL; l = g_list_next (l)) {
		token_info = gck_slot_get_token_info (l->data);
		importable = is_slot_importable (l->data, token_info);
		gck_token_info_free (token_info);

		if (importable) {
			self = _gcr_pkcs11_importer_new (l->data);
			if (!gcr_importer_queue_for_parsed (self, parsed))
				g_assert_not_reached ();
			results = g_list_prepend (results, self);
		}
	}
	gck_list_unref_free (slots);

	return g_list_reverse (results);
}

static gboolean
_gcr_pkcs11_importer_queue_for_parsed (GcrImporter *importer,
                                       GcrParsed *parsed)
{
	GcrPkcs11Importer *self = GCR_PKCS11_IMPORTER (importer);
	GckAttributes *attrs;
	gboolean is_private;

	attrs = gcr_parsed_get_attributes (parsed);

	if (!gck_attributes_find_boolean (attrs, CKA_PRIVATE, &is_private))
		is_private = FALSE;
	if (is_private)
		self->pv->any_private = TRUE;

	g_queue_push_tail (&self->pv->queue, gck_attributes_ref (attrs));
	return TRUE;
}

static void
_gcr_pkcs11_importer_import_async (GcrImporter *importer,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
	GSimpleAsyncResult *res;
	GcrImporterData *data;

	res = g_simple_async_result_new (G_OBJECT (importer), callback, user_data,
	                                 _gcr_pkcs11_importer_import_async);
	data = g_new0 (GcrImporterData, 1);
	data->async = TRUE;
	data->importer = g_object_ref (importer);
	data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, data, gcr_importer_data_free);

	next_state (res, state_open_session);
	g_object_unref (res);
}

static gboolean
_gcr_pkcs11_importer_import_finish (GcrImporter *importer,
                                    GAsyncResult *result,
                                    GError **error)
{
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (importer),
	                      _gcr_pkcs11_importer_import_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	return TRUE;
}

static void
_gcr_pkcs11_importer_init_iface (GcrImporterIface *iface)
{
	iface->create_for_parsed = _gcr_pkcs11_importer_create_for_parsed;
	iface->queue_for_parsed = _gcr_pkcs11_importer_queue_for_parsed;
	iface->import_async = _gcr_pkcs11_importer_import_async;
	iface->import_finish = _gcr_pkcs11_importer_import_finish;
}

GcrImporter *
_gcr_pkcs11_importer_new (GckSlot *slot)
{
	g_return_val_if_fail (GCK_IS_SLOT (slot), NULL);

	return g_object_new (GCR_TYPE_PKCS11_IMPORTER,
	                     "slot", slot,
	                     NULL);
}

GckSlot *
_gcr_pkcs11_importer_get_slot (GcrPkcs11Importer *self)
{
	g_return_val_if_fail (GCR_IS_PKCS11_IMPORTER (self), NULL);
	return self->pv->slot;
}

GList *
_gcr_pkcs11_importer_get_imported (GcrPkcs11Importer *self)
{
	g_return_val_if_fail (GCR_IS_PKCS11_IMPORTER (self), NULL);
	return self->pv->objects;
}

void
_gcr_pkcs11_importer_queue (GcrPkcs11Importer *self,
                            GckAttributes *attrs)
{
	gboolean is_private;

	g_return_if_fail (GCR_IS_PKCS11_IMPORTER (self));
	g_return_if_fail (attrs != NULL);

	if (!gck_attributes_find_boolean (attrs, CKA_PRIVATE, &is_private))
		is_private = FALSE;
	if (is_private)
		self->pv->any_private = TRUE;

	g_queue_push_tail (&self->pv->queue, gck_attributes_ref (attrs));
}
