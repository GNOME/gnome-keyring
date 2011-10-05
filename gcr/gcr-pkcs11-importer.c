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

#define DEBUG_FLAG GCR_DEBUG_IMPORT
#include "gcr-debug.h"
#include "gcr-fingerprint.h"
#include "gcr-icons.h"
#include "gcr-internal.h"
#include "gcr-library.h"
#include "gcr-import-interaction.h"
#include "gcr-internal.h"
#include "gcr-parser.h"
#include "gcr-pkcs11-importer.h"

#include "egg/egg-hex.h"

#include <gck/gck.h>

#include <gcrypt.h>

#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_LABEL,
	PROP_ICON,
	PROP_INTERACTION,
	PROP_SLOT,
	PROP_IMPORTED,
	PROP_QUEUED
};

typedef struct _GcrPkcs11ImporterClass GcrPkcs11ImporterClass;

struct _GcrPkcs11Importer {
	GObject parent;
	GckSlot *slot;
	GList *objects;
	GckSession *session;
	GQueue *queue;
	GTlsInteraction *interaction;
	gboolean any_private;
};

struct _GcrPkcs11ImporterClass {
	GObjectClass parent_class;
};

typedef struct  {
	GcrPkcs11Importer *importer;
	GCancellable *cancellable;
	gboolean prompted;
	gboolean async;
	GckAttributes *supplement;
} GcrImporterData;

/* State forward declarations */
static void   state_cancelled                  (GSimpleAsyncResult *res,
                                                gboolean async);

static void   state_complete                   (GSimpleAsyncResult *res,
                                                gboolean async);

static void   state_create_object              (GSimpleAsyncResult *res,
                                                gboolean async);

static void   state_supplement                 (GSimpleAsyncResult *res,
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
		self->objects = g_list_append (self->objects, object);
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
	if (g_queue_is_empty (self->queue)) {
		next_state (res, state_complete);

	} else {

		/* Pop first one off the list */
		attrs = g_queue_pop_head (self->queue);
		g_assert (attrs != NULL);

		if (async) {
			gck_session_create_object_async (self->session, attrs,
			                                 data->cancellable, on_create_object,
			                                 g_object_ref (res));
		} else {
			object = gck_session_create_object (self->session, attrs,
			                                    data->cancellable, &error);
			complete_create_object (res, object, error);
		}

		gck_attributes_unref (attrs);
	}
}

/* ---------------------------------------------------------------------------------
 * SUPPLEMENTING and FIXING UP
 */

typedef struct {
	GckAttributes *certificate;
	GckAttributes *private_key;
} CertificateKeyPair;

static void
supplement_with_attributes (GckAttributes *attrs,
                            GckAttributes *supplements)
{
	GckAttribute *supplement;
	gint i;

	for (i = 0; i < gck_attributes_count (supplements); i++) {
		supplement = gck_attributes_at (supplements, i);
		if (!gck_attribute_is_invalid (supplement) && supplement->length != 0)
			gck_attributes_add (attrs, supplement);
	}
}

static void
supplement_id_for_data (GckAttributes *attrs,
                        guchar *nonce,
                        gsize n_once,
                        gpointer data,
                        gsize n_data)
{
	gcry_md_hd_t mdh;
	gcry_error_t gcry;

	if (gck_attributes_find (attrs, CKA_ID) != NULL)
		return;

	gcry = gcry_md_open (&mdh, GCRY_MD_SHA1, 0);
	g_return_if_fail (gcry == 0);

	gcry_md_write (mdh, nonce, n_once);
	gcry_md_write (mdh, data, n_data);

	gck_attributes_add_data (attrs, CKA_ID,
	                         gcry_md_read (mdh, 0),
	                         gcry_md_get_algo_dlen (GCRY_MD_SHA1));

	gcry_md_close (mdh);
}

static void
supplement_attributes (GcrPkcs11Importer *self,
                       GckAttributes *supplements)
{
	GHashTable *pairs;
	GHashTable *paired;
	CertificateKeyPair *pair;
	gboolean supplemented = FALSE;
	GckAttributes *attrs;
	gulong klass;
	guchar *finger;
	gchar *fingerprint;
	guchar nonce[20];
	GHashTableIter iter;
	gsize n_finger;
	GQueue *queue;
	GList *l;

	/* A table of certificate/key pairs by fingerprint */
	pairs = g_hash_table_new_full (g_str_hash, g_str_equal,
	                               g_free, g_free);

	for (l = self->queue->head; l != NULL; l = g_list_next (l)) {
		attrs = l->data;
		if (!gck_attributes_find_ulong (attrs, CKA_CLASS, &klass))
			g_return_if_reached ();

		/* Make a string fingerprint for this guy */
		finger = gcr_fingerprint_from_attributes (attrs, G_CHECKSUM_SHA1,
		                                          &n_finger);
		if (finger) {
			fingerprint = egg_hex_encode (finger, n_finger);
			g_free (finger);

			pair = g_hash_table_lookup (pairs, fingerprint);
			if (pair == NULL) {
				pair = g_new0 (CertificateKeyPair, 1);
				g_hash_table_insert (pairs, fingerprint, pair);
			} else {
				g_free (fingerprint);
			}
		} else {
			pair = NULL;
		}

		fingerprint = NULL;

		gck_attributes_set_boolean (attrs, CKA_TOKEN, CK_TRUE);

		switch (klass) {
		case CKO_CERTIFICATE:
			gck_attributes_set_boolean (attrs, CKA_PRIVATE, FALSE);
			if (pair != NULL && pair->certificate == NULL)
				pair->certificate = attrs;
			break;
		case CKO_PRIVATE_KEY:
			gck_attributes_set_boolean (attrs, CKA_PRIVATE, TRUE);
			gck_attributes_add_boolean (attrs, CKA_DECRYPT, TRUE);
			gck_attributes_add_boolean (attrs, CKA_SIGN, TRUE);
			gck_attributes_add_boolean (attrs, CKA_SIGN_RECOVER, TRUE);
			gck_attributes_add_boolean (attrs, CKA_UNWRAP, TRUE);
			gck_attributes_add_boolean (attrs, CKA_SENSITIVE, TRUE);
			if (pair != NULL && pair->private_key == NULL)
				pair->private_key = attrs;
			break;
		}
	}

	/* For generation of CKA_ID's */
	gcry_create_nonce (nonce, sizeof (nonce));

	/* A table for marking which attributes are in the pairs table */
	paired = g_hash_table_new (g_direct_hash, g_direct_equal);

	/* Now move everything in pairs to the front */
	queue = g_queue_new ();
	g_hash_table_iter_init (&iter, pairs);
	while (g_hash_table_iter_next (&iter, (gpointer *)&fingerprint, (gpointer *)&pair)) {
		if (pair->certificate != NULL && pair->private_key != NULL) {
			/*
			 * Generate a CKA_ID based on the fingerprint and nonce,
			 * and do the same CKA_ID for both private key and certificate.
			 */

			supplement_with_attributes (pair->private_key, supplements);
			supplement_id_for_data (pair->private_key, nonce, sizeof (nonce),
			                        fingerprint, strlen (fingerprint));
			g_queue_push_tail (queue, pair->private_key);
			g_hash_table_insert (paired, pair->private_key, "present");

			supplement_with_attributes (pair->private_key, supplements);
			supplement_id_for_data (pair->certificate, nonce, sizeof (nonce),
			                        fingerprint, strlen (fingerprint));
			g_queue_push_tail (queue, pair->certificate);
			g_hash_table_insert (paired, pair->certificate, "present");

			/* Used the suplements for the pairs, don't use for unpaired stuff */
			supplemented = TRUE;
		}
	}

	/* Go through the old queue, and look for anything not paired */
	for (l = self->queue->head; l != NULL; l = g_list_next (l)) {
		attrs = l->data;
		if (!g_hash_table_lookup (paired, attrs)) {
			if (!supplemented)
				supplement_with_attributes (attrs, supplements);

			/*
			 * Generate a CKA_ID based on the location of attrs in,
			 * memory, since this together with the nonce should
			 * be unique.
			 */
			supplement_id_for_data (attrs, nonce, sizeof (nonce),
			                        &attrs, sizeof (gpointer));

			g_queue_push_tail (queue, l->data);
		}
	}

	/* And swap the new queue into place */
	g_queue_free (self->queue);
	self->queue = queue;

	g_hash_table_destroy (paired);
	g_hash_table_destroy (pairs);
}

static void
complete_supplement (GSimpleAsyncResult *res,
                     GError *error)
{
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);

	if (error == NULL) {
		supplement_attributes (data->importer, data->supplement);
		next_state (res, state_create_object);
	} else {
		g_simple_async_result_take_error (res, error);
		next_state (res, state_complete);
	}
}

static void
on_supplement_done (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);
	GcrPkcs11Importer *self = data->importer;
	GError *error = NULL;

	gcr_import_interaction_supplement_finish (GCR_IMPORT_INTERACTION (self->interaction),
	                                          result, &error);
	complete_supplement (res, error);
	g_object_unref (res);
}

static void
state_supplement (GSimpleAsyncResult *res,
                  gboolean async)
{
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);
	GcrPkcs11Importer *self = data->importer;
	GError *error = NULL;

	if (self->interaction == NULL || !GCR_IS_IMPORT_INTERACTION (self->interaction)) {
		complete_supplement (res, NULL);

	} else if (async) {
		gcr_import_interaction_supplement_async (GCR_IMPORT_INTERACTION (self->interaction),
		                                         data->supplement, data->cancellable,
		                                         on_supplement_done, g_object_ref (res));

	} else {
		gcr_import_interaction_supplement (GCR_IMPORT_INTERACTION (self->interaction),
		                                   data->supplement, data->cancellable, &error);
		complete_supplement (res, error);
	}
}

static void
supplement_prep (GSimpleAsyncResult *res)
{
	GcrImporterData *data = g_simple_async_result_get_op_res_gpointer (res);
	GcrPkcs11Importer *self = data->importer;
	GckAttribute *the_label = NULL;
	GckAttribute *attr;
	gboolean first = TRUE;
	GList *l;

	if (data->supplement)
		gck_attributes_unref (data->supplement);
	data->supplement = gck_attributes_new ();

	/* Do we have a consistent label across all objects? */
	for (l = self->queue->head; l != NULL; l = g_list_next (l)) {
		attr = gck_attributes_find (l->data, CKA_LABEL);
		if (first)
			the_label = attr;
		else if (!gck_attribute_equal (the_label, attr))
			the_label = NULL;
		first = FALSE;
	}

	/* If consistent label, set that in supplement data */
	if (the_label != NULL)
		gck_attributes_add (data->supplement, the_label);
	else
		gck_attributes_add_empty (data->supplement, CKA_LABEL);

	if (GCR_IS_IMPORT_INTERACTION (self->interaction))
		gcr_import_interaction_supplement_prep (GCR_IMPORT_INTERACTION (self->interaction),
		                                        data->supplement);
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
		g_clear_object (&self->session);
		self->session = session;
		next_state (res, state_supplement);
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
	guint options = GCK_SESSION_READ_WRITE | GCK_SESSION_LOGIN_USER;
	GckSession *session;
	GError *error = NULL;

	if (async) {
		gck_slot_open_session_async (self->slot, options,
		                             data->cancellable, on_open_session,
		                             g_object_ref (res));
	} else {
		session = gck_slot_open_session_full (self->slot, options, 0,
		                                      NULL, NULL, data->cancellable, &error);
		complete_open_session (res, session, error);
	}
}

static void
_gcr_pkcs11_importer_init (GcrPkcs11Importer *self)
{
	self->queue = g_queue_new ();
}

static void
_gcr_pkcs11_importer_dispose (GObject *obj)
{
	GcrPkcs11Importer *self = GCR_PKCS11_IMPORTER (obj);

	gck_list_unref_free (self->objects);
	self->objects = NULL;
	g_clear_object (&self->session);
	g_clear_object (&self->interaction);

	while (!g_queue_is_empty (self->queue))
		gck_attributes_unref (g_queue_pop_head (self->queue));

	G_OBJECT_CLASS (_gcr_pkcs11_importer_parent_class)->dispose (obj);
}

static void
_gcr_pkcs11_importer_finalize (GObject *obj)
{
	GcrPkcs11Importer *self = GCR_PKCS11_IMPORTER (obj);

	g_clear_object (&self->slot);

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
		self->slot = g_value_dup_object (value);
		g_return_if_fail (self->slot);
		break;
	case PROP_INTERACTION:
		g_clear_object (&self->interaction);
		self->interaction = g_value_dup_object (value);
		g_object_notify (G_OBJECT (self), "interaction");
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

	info = gck_slot_get_token_info (self->slot);
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
		info = token_info = gck_slot_get_token_info (self->slot);
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
		g_value_take_boxed (value, _gcr_pkcs11_importer_get_imported (self));
		break;
	case PROP_QUEUED:
		g_value_set_pointer (value, _gcr_pkcs11_importer_get_queued (self));
		break;
	case PROP_INTERACTION:
		g_value_set_object (value, self->interaction);
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

	g_object_class_override_property (gobject_class, PROP_LABEL, "label");

	g_object_class_override_property (gobject_class, PROP_ICON, "icon");

	g_object_class_override_property (gobject_class, PROP_INTERACTION, "interaction");

	g_object_class_install_property (gobject_class, PROP_SLOT,
	           g_param_spec_object ("slot", "Slot", "PKCS#11 slot to import data into",
	                                GCK_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_IMPORTED,
	           g_param_spec_boxed ("imported", "Imported", "Imported objects",
	                               GCK_TYPE_LIST, G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_QUEUED,
	           g_param_spec_pointer ("queued", "Queued", "Queued attributes",
	                                 G_PARAM_READABLE));

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
	"pkcs11:manufacturer=Gnome%20Keyring;serial=1:USER:DEFAULT",
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

	if (token->flags & CKF_WRITE_PROTECTED) {
		_gcr_debug ("token is not importable: %s: write protected", token->label);
		return FALSE;
	}
	if (!(token->flags & CKF_TOKEN_INITIALIZED)) {
		_gcr_debug ("token is not importable: %s: not initialized", token->label);
		return FALSE;
	}
	if ((token->flags & CKF_LOGIN_REQUIRED) &&
	    !(token->flags & CKF_USER_PIN_INITIALIZED)) {
		_gcr_debug ("token is not importable: %s: user pin not initialized", token->label);
		return FALSE;
	}

	for (i = 0; token_blacklist[i] != NULL; i++) {
		uri = gck_uri_parse (token_blacklist[i], GCK_URI_FOR_TOKEN | GCK_URI_FOR_MODULE, &error);
		if (uri == NULL) {
			g_warning ("couldn't parse pkcs11 blacklist uri: %s", error->message);
			g_clear_error (&error);
			continue;
		}

		match = gck_slot_match (slot, uri);
		gck_uri_data_free (uri);

		if (match) {
			_gcr_debug ("token is not importable: %s: on the black list", token->label);
			return FALSE;
		}
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

		if (importable) {
			_gcr_debug ("creating importer for token: %s", token_info->label);
			self = _gcr_pkcs11_importer_new (l->data);
			if (!gcr_importer_queue_for_parsed (self, parsed))
				g_assert_not_reached ();
			results = g_list_prepend (results, self);
		}

		gck_token_info_free (token_info);
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
	const gchar *label;

	attrs = gcr_parsed_get_attributes (parsed);
	label = gcr_parsed_get_label (parsed);
	_gcr_pkcs11_importer_queue (self, label, attrs);

	return TRUE;
}

static void
_gcr_pkcs11_importer_import_async (GcrImporter *importer,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
	GcrPkcs11Importer *self = GCR_PKCS11_IMPORTER (importer);
	GSimpleAsyncResult *res;
	GcrImporterData *data;

	res = g_simple_async_result_new (G_OBJECT (importer), callback, user_data,
	                                 _gcr_pkcs11_importer_import_async);
	data = g_new0 (GcrImporterData, 1);
	data->async = TRUE;
	data->importer = g_object_ref (importer);
	data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, data, gcr_importer_data_free);

	supplement_prep (res);
	gck_slot_set_interaction (self->slot, self->interaction);

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

/**
 * _gcr_pkcs11_importer_new:
 *
 * Returns: (transfer full) (type Gcr.Pkcs11Importer): the new importer
 */
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
	return self->slot;
}

GList *
_gcr_pkcs11_importer_get_imported (GcrPkcs11Importer *self)
{
	g_return_val_if_fail (GCR_IS_PKCS11_IMPORTER (self), NULL);
	return g_list_copy (self->objects);
}

GList *
_gcr_pkcs11_importer_get_queued (GcrPkcs11Importer *self)
{
	g_return_val_if_fail (GCR_IS_PKCS11_IMPORTER (self), NULL);
	return g_list_copy (self->queue->head);
}

void
_gcr_pkcs11_importer_queue (GcrPkcs11Importer *self,
                            const gchar *label,
                            GckAttributes *attrs)
{
	g_return_if_fail (GCR_IS_PKCS11_IMPORTER (self));
	g_return_if_fail (attrs != NULL);

	if (label != NULL && !gck_attributes_find (attrs, CKA_LABEL))
		gck_attributes_add_string (attrs, CKA_LABEL, label);

	g_queue_push_tail (self->queue, gck_attributes_ref (attrs));
}
