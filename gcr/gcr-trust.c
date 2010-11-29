/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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
 */

#include "config.h"

#include "gcr.h"
#include "gcr-types.h"
#include "gcr-internal.h"
#include "gcr-trust.h"

#include <gck/gck.h>

#include "pkcs11/pkcs11n.h"
#include "pkcs11/pkcs11i.h"

/* ----------------------------------------------------------------------------------
 * HELPERS
 */

typedef struct _GcrTrustOperation {
	GckEnumerator *en;
	GckAttributes *attrs;
	gboolean found;
} GcrTrustOperation;

static void
trust_operation_free (gpointer data)
{
	GcrTrustOperation *op = data;
	g_assert (data);

	/* No reference held */
	g_assert (GCK_IS_ENUMERATOR (op->en));
	op->en = NULL;

	g_assert (op->attrs);
	gck_attributes_unref (op->attrs);
	op->attrs = NULL;

	g_slice_free (GcrTrustOperation, op);
}

static void
trust_operation_init (GckEnumerator *en, GckAttributes *attrs)
{
	GcrTrustOperation *op;

	g_assert (GCK_IS_ENUMERATOR (en));
	g_assert (!g_object_get_data (G_OBJECT (en), "trust-operation"));
	g_assert (attrs);

	op = g_slice_new0 (GcrTrustOperation);
	op->attrs = gck_attributes_ref (attrs);

	/* No reference held, GckEnumerator owns */
	op->en = en;
	g_object_set_data_full (G_OBJECT (en), "trust-operation", op, trust_operation_free);
}

static GcrTrustOperation*
trust_operation_get (GckEnumerator *en)
{
	GcrTrustOperation *op = g_object_get_data (G_OBJECT (en), "trust-operation");
	g_assert (op);
	g_assert (op->en == en);
	return op;
}

static GckAttributes*
prepare_trust_attrs (GcrCertificate *cert, CK_ASSERTION_TYPE type)
{
	GckAttributes *attrs;
	gconstpointer data;
	gsize n_data;

	attrs = gck_attributes_new ();
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_G_TRUST_ASSERTION);
	gck_attributes_add_ulong (attrs, CKA_G_ASSERTION_TYPE, type);

	data = gcr_certificate_get_der_data (cert, &n_data);
	g_return_val_if_fail (data, NULL);
	gck_attributes_add_data (attrs, CKA_G_CERTIFICATE_VALUE, data, n_data);

	return attrs;
}

/* ----------------------------------------------------------------------------------
 * GET CERTIFICATE EXCEPTION
 */

static GckEnumerator*
prepare_is_certificate_exception (GcrCertificate *cert, const gchar *purpose, const gchar *peer)
{
	GckAttributes *attrs;
	GckEnumerator *en;
	GList *modules;

	modules = _gcr_get_pkcs11_modules ();

	attrs = prepare_trust_attrs (cert, CKT_G_CERTIFICATE_TRUST_EXCEPTION);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_string (attrs, CKA_G_PURPOSE, purpose);
	gck_attributes_add_string (attrs, CKA_G_PEER, peer);

	/*
	 * TODO: We need to be able to sort the modules by preference
	 * on which sources of trust storage we want to read over which
	 * others.
	 */

	en = gck_modules_enumerate_objects (modules, attrs, 0);
	trust_operation_init (en, attrs);
	gck_attributes_unref (attrs);

	return en;
}

static gboolean
perform_is_certificate_exception (GckEnumerator *en, GCancellable *cancel, GError **error)
{
	GcrTrustOperation *op;
	GckObject *object;

	op = trust_operation_get (en);

	g_assert (op != NULL);
	g_assert (op->found == FALSE);

	object = gck_enumerator_next (en, cancel, error);
	op->found = (object != NULL);

	if (object)
		g_object_unref (object);

	return op->found;
}

gboolean
gcr_trust_is_certificate_exception (GcrCertificate *cert, const gchar *purpose,
                                    const gchar *peer, GCancellable *cancel, GError **error)
{
	GckEnumerator *en;
	gboolean ret;

	g_return_val_if_fail (GCR_IS_CERTIFICATE (cert), FALSE);
	g_return_val_if_fail (purpose, FALSE);
	g_return_val_if_fail (peer, FALSE);

	en = prepare_is_certificate_exception (cert, purpose, peer);
	g_return_val_if_fail (en, FALSE);

	ret = perform_is_certificate_exception (en, cancel, error);

	g_object_unref (en);

	return ret;
}

static void
thread_is_certificate_exception (GSimpleAsyncResult *res, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;

	perform_is_certificate_exception (GCK_ENUMERATOR (object), cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (res, error);
		g_clear_error (&error);
	}
}

void
gcr_trust_is_certificate_exception_async (GcrCertificate *cert, const gchar *purpose,
                                          const gchar *peer, GCancellable *cancel,
                                          GAsyncReadyCallback callback, gpointer user_data)
{
	GSimpleAsyncResult *async;
	GckEnumerator *en;

	en = prepare_is_certificate_exception (cert, purpose, peer);
	g_return_if_fail (en);

	async = g_simple_async_result_new (G_OBJECT (en), callback, user_data,
	                                   gcr_trust_is_certificate_exception_async);

	g_simple_async_result_run_in_thread (async, thread_is_certificate_exception,
	                                     G_PRIORITY_DEFAULT, cancel);

	g_object_unref (async);
	g_object_unref (en);
}

gboolean
gcr_trust_is_certificate_exception_finish (GAsyncResult *res, GError **error)
{
	GcrTrustOperation *op;
	GObject *object;

	object = g_async_result_get_source_object (res);
	g_return_val_if_fail (g_simple_async_result_is_valid (res, object,
	                      gcr_trust_is_certificate_exception_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
		return FALSE;

	op = trust_operation_get (GCK_ENUMERATOR (object));
	return op->found;
}

/* ----------------------------------------------------------------------------------
 * ADD CERTIFICATE EXCEPTION
 */

static GckEnumerator*
prepare_add_certificate_exception (GcrCertificate *cert, const gchar *purpose, const gchar *peer)
{
	GckAttributes *attrs;
	GckEnumerator *en;
	GList *modules;

	modules = _gcr_get_pkcs11_modules ();

	attrs = prepare_trust_attrs (cert, CKT_G_CERTIFICATE_TRUST_EXCEPTION);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_string (attrs, CKA_G_PURPOSE, purpose);
	gck_attributes_add_string (attrs, CKA_G_PEER, peer);
	gck_attributes_add_boolean (attrs, CKA_TOKEN, TRUE);

	/*
	 * TODO: We need to be able to sort the modules by preference
	 * on which sources of trust storage we want to read over which
	 * others.
	 */

	en = gck_modules_enumerate_objects (modules, attrs, CKF_RW_SESSION);
	trust_operation_init (en, attrs);
	gck_attributes_unref (attrs);

	return en;
}

static gboolean
perform_add_certificate_exception (GckEnumerator *en, GCancellable *cancel, GError **error)
{
	GcrTrustOperation *op;
	GckAttributes *attrs;
	gboolean ret = FALSE;
	GError *lerr = NULL;
	GckObject *object;
	GckSession *session;
	GckSlot *slot;

	op = trust_operation_get (en);
	g_assert (op != NULL);

	/* We need an error below */
	if (error && !*error)
		*error = lerr;

	object = gck_enumerator_next (en, cancel, error);
	if (*error)
		return FALSE;

	/* It already exists */
	if (object) {
		g_object_unref (object);
		return TRUE;
	}

	attrs = gck_attributes_new ();
	gck_attributes_add_all (attrs, op->attrs);

	/* TODO: Add relevant label */

	/* Find an appropriate token */
	slot = _gcr_slot_for_storing_trust (error);
	if (slot != NULL) {
		session = gck_slot_open_session (slot, CKF_RW_SESSION, NULL, error);
		if (session != NULL) {
			object = gck_session_create_object (session, attrs, cancel, error);
			if (object != NULL) {
				g_object_unref (object);
				ret = TRUE;
			}

			g_object_unref (session);
		}

		g_object_unref (slot);
	}

	gck_attributes_unref (attrs);

	/* Our own local error pointer */
	g_clear_error (&lerr);

	return ret;
}

gboolean
gcr_trust_add_certificate_exception (GcrCertificate *cert, const gchar *purpose, const gchar *peer,
                                     GCancellable *cancel, GError **error)
{
	GckEnumerator *en;
	gboolean ret;

	en = prepare_add_certificate_exception (cert, purpose, peer);
	g_return_val_if_fail (en, FALSE);

	ret = perform_add_certificate_exception (en, cancel, error);

	g_object_unref (en);

	return ret;
}

static void
thread_add_certificate_exception (GSimpleAsyncResult *res, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;

	perform_add_certificate_exception (GCK_ENUMERATOR (object), cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (res, error);
		g_clear_error (&error);
	}
}

void
gcr_trust_add_certificate_exception_async (GcrCertificate *cert, const gchar *purpose,
                                           const gchar *peer, GCancellable *cancel,
                                           GAsyncReadyCallback callback, gpointer user_data)
{
	GSimpleAsyncResult *async;
	GckEnumerator *en;

	en = prepare_add_certificate_exception (cert, purpose, peer);
	g_return_if_fail (en);

	async = g_simple_async_result_new (G_OBJECT (en), callback, user_data,
	                                   gcr_trust_add_certificate_exception_async);

	g_simple_async_result_run_in_thread (async, thread_add_certificate_exception,
	                                     G_PRIORITY_DEFAULT, cancel);

	g_object_unref (async);
	g_object_unref (en);
}

gboolean
gcr_trust_add_certificate_exception_finish (GAsyncResult *res, GError **error)
{
	GObject *object;

	object = g_async_result_get_source_object (res);
	g_return_val_if_fail (g_simple_async_result_is_valid (res, object,
	                      gcr_trust_add_certificate_exception_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
		return FALSE;

	return TRUE;
}

/* -----------------------------------------------------------------------
 * REMOVE CERTIFICATE EXCEPTION
 */

static GckEnumerator*
prepare_remove_certificate_exception (GcrCertificate *cert, const gchar *purpose,
                                      const gchar *peer)
{
	GckAttributes *attrs;
	GckEnumerator *en;
	GList *modules;

	modules = _gcr_get_pkcs11_modules ();

	attrs = prepare_trust_attrs (cert, CKT_G_CERTIFICATE_TRUST_EXCEPTION);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_string (attrs, CKA_G_PURPOSE, purpose);
	gck_attributes_add_string (attrs, CKA_G_PEER, peer);

	/*
	 * TODO: We need to be able to sort the modules by preference
	 * on which sources of trust storage we want to read over which
	 * others.
	 */

	en = gck_modules_enumerate_objects (modules, attrs, CKF_RW_SESSION);
	trust_operation_init (en, attrs);
	gck_attributes_unref (attrs);

	return en;
}

static gboolean
perform_remove_certificate_exception (GckEnumerator *en, GCancellable *cancel, GError **error)
{
	GcrTrustOperation *op;
	GList *objects, *l;
	GError *lerr = NULL;

	op = trust_operation_get (en);
	g_assert (op != NULL);

	/* We need an error below */
	if (error && !*error)
		*error = lerr;

	objects = gck_enumerator_next_n (en, -1, cancel, error);
	if (*error)
		return FALSE;

	for (l = objects; l; l = g_list_next (l)) {
		if (!gck_object_destroy (l->data, cancel, error)) {
			gck_list_unref_free (objects);
			return FALSE;
		}
	}

	gck_list_unref_free (objects);
	return TRUE;
}

gboolean
gcr_trust_remove_certificate_exception (GcrCertificate *cert, const gchar *purpose, const gchar *peer,
                                        GCancellable *cancel, GError **error)
{
	GckEnumerator *en;
	gboolean ret;

	en = prepare_remove_certificate_exception (cert, purpose, peer);
	g_return_val_if_fail (en, FALSE);

	ret = perform_remove_certificate_exception (en, cancel, error);

	g_object_unref (en);

	return ret;
}

static void
thread_remove_certificate_exception (GSimpleAsyncResult *res, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;

	perform_remove_certificate_exception (GCK_ENUMERATOR (object), cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (res, error);
		g_clear_error (&error);
	}
}

void
gcr_trust_remove_certificate_exception_async (GcrCertificate *cert, const gchar *purpose,
                                              const gchar *peer, GCancellable *cancel,
                                              GAsyncReadyCallback callback, gpointer user_data)
{
	GSimpleAsyncResult *async;
	GckEnumerator *en;

	en = prepare_remove_certificate_exception (cert, purpose, peer);
	g_return_if_fail (en);

	async = g_simple_async_result_new (G_OBJECT (en), callback, user_data,
	                                   gcr_trust_remove_certificate_exception_async);

	g_simple_async_result_run_in_thread (async, thread_remove_certificate_exception,
	                                     G_PRIORITY_DEFAULT, cancel);

	g_object_unref (async);
	g_object_unref (en);
}

gboolean
gcr_trust_remove_certificate_exception_finish (GAsyncResult *res, GError **error)
{
	GObject *object;

	object = g_async_result_get_source_object (res);
	g_return_val_if_fail (g_simple_async_result_is_valid (res, object,
	                      gcr_trust_remove_certificate_exception_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
		return FALSE;

	return TRUE;
}

/* ----------------------------------------------------------------------------------
 * CERTIFICATE ROOT
 */

static GckEnumerator*
prepare_is_certificate_anchor (GcrCertificate *cert, const gchar *purpose)
{
	GckAttributes *attrs;
	GckEnumerator *en;
	GList *modules;

	modules = _gcr_get_pkcs11_modules ();

	attrs = prepare_trust_attrs (cert, CKT_G_CERTIFICATE_TRUST_ANCHOR);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_string (attrs, CKA_G_PURPOSE, purpose);

	/*
	 * TODO: We need to be able to sort the modules by preference
	 * on which sources of trust storage we want to read over which
	 * others.
	 */

	en = gck_modules_enumerate_objects (modules, attrs, 0);
	trust_operation_init (en, attrs);
	gck_attributes_unref (attrs);

	return en;
}

static gboolean
perform_is_certificate_anchor (GckEnumerator *en, GCancellable *cancel, GError **error)
{
	GcrTrustOperation *op;
	GckObject *object;

	op = trust_operation_get (en);
	g_assert (op != NULL);

	object = gck_enumerator_next (en, cancel, error);
	if (object != NULL) {
		op->found = TRUE;
		g_object_unref (object);
	} else {
		op->found = FALSE;
	}

	return op->found;
}

gboolean
gcr_trust_is_certificate_anchor (GcrCertificate *cert, const gchar *purpose,
                                 GCancellable *cancel, GError **error)
{
	GckEnumerator *en;
	gboolean ret;

	en = prepare_is_certificate_anchor (cert, purpose);
	g_return_val_if_fail (en, FALSE);

	ret = perform_is_certificate_anchor (en, cancel, error);

	g_object_unref (en);

	return ret;
}

static void
thread_is_certificate_anchor (GSimpleAsyncResult *res, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;

	perform_is_certificate_anchor (GCK_ENUMERATOR (object), cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (res, error);
		g_clear_error (&error);
	}
}

void
gcr_trust_is_certificate_anchor_async (GcrCertificate *cert, const gchar *purpose,
                                       GCancellable *cancel, GAsyncReadyCallback callback,
                                       gpointer user_data)
{
	GSimpleAsyncResult *async;
	GckEnumerator *en;

	en = prepare_is_certificate_anchor (cert, purpose);
	g_return_if_fail (en);

	async = g_simple_async_result_new (G_OBJECT (en), callback, user_data,
	                                   gcr_trust_is_certificate_anchor_async);

	g_simple_async_result_run_in_thread (async, thread_is_certificate_anchor,
	                                     G_PRIORITY_DEFAULT, cancel);

	g_object_unref (async);
	g_object_unref (en);
}

gboolean
gcr_trust_is_certificate_anchor_finish (GAsyncResult *res, GError **error)
{
	GcrTrustOperation *op;
	GObject *object;

	object = g_async_result_get_source_object (res);
	g_return_val_if_fail (g_simple_async_result_is_valid (res, object,
	                      gcr_trust_is_certificate_anchor_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
		return FALSE;

	op = trust_operation_get (GCK_ENUMERATOR (object));
	return op->found;
}
