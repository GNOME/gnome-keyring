/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Collabora Ltd
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

#include "gcr.h"
#define DEBUG_FLAG GCR_DEBUG_TRUST
#include "gcr-debug.h"
#include "gcr-types.h"
#include "gcr-internal.h"
#include "gcr-library.h"
#include "gcr-trust.h"

#include <gck/gck.h>

#include "pkcs11/pkcs11n.h"
#include "pkcs11/pkcs11i.h"
#include "pkcs11/pkcs11x.h"

#include <glib/gi18n-lib.h>

/**
 * SECTION:gcr-trust
 * @title: Trust Storage and Lookups
 * @short_description: Store and lookup bits of information used for
 * verifying certificates.
 *
 * These functions provide access to stored information about which
 * certificates the system and user trusts as certificate authority trust
 * anchors, or overrides to the normal verification of certificates.
 *
 * Trust anchors are used to verify the certificate authority in a certificate
 * chain. Trust anchors are always valid for a given purpose. The most common
 * purpose is the #GCR_PURPOSE_SERVER_AUTH and is used for a client application
 * to verify that the certificate at the server side of a TLS connection is
 * authorized to act as such. To check if a certificate is a trust anchor use
 * gcr_trust_is_certificate_anchored().
 *
 * Pinned certificates are used when a user overrides the default trust
 * decision for a given certificate. They're often used with self-signed
 * certificates. Pinned certificates are always only valid for a single peer
 * such as the remote host with which TLS is being performed. To lookup
 * pinned certificates use gcr_trust_is_certificate_pinned().
 *
 * After the user has requested to override the trust decision
 * about a given certificate then a pinned certificates can be added by using
 * the gcr_trust_add_pinned_certificate() function.
 *
 * These functions do not constitute a viable method for verifying certificates
 * used in TLS or other locations. Instead they support such verification
 * by providing some of the needed data for a trust decision.
 *
 * The storage is provided by pluggable PKCS\#11 modules.
 */

/**
 * GCR_PURPOSE_SERVER_AUTH:
 *
 * The purpose used to verify the server certificate in a TLS connection. This
 * is the most common purpose in use.
 */

/**
 * GCR_PURPOSE_CLIENT_AUTH:
 *
 * The purpose used to verify the client certificate in a TLS connection.
 */

/**
 * GCR_PURPOSE_CODE_SIGNING:
 *
 * The purpose used to verify certificate used for the signature on signed code.
 */

/**
 * GCR_PURPOSE_EMAIL:
 *
 * The purpose used to verify certificates that are used in email communication
 * such as S/MIME.
 */

/* ----------------------------------------------------------------------------------
 * HELPERS
 */

typedef struct {
	GckAttributes *attrs;
	gboolean found;
} trust_closure;

static void
trust_closure_free (gpointer data)
{
	trust_closure *closure = data;
	gck_attributes_unref (closure->attrs);
	g_free (closure);
}

static GckAttributes*
prepare_trust_attrs (GcrCertificate *certificate, CK_X_ASSERTION_TYPE type)
{
	GckAttributes *attrs;
	gconstpointer data;
	gsize n_data;

	attrs = gck_attributes_new ();
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_X_TRUST_ASSERTION);
	gck_attributes_add_ulong (attrs, CKA_X_ASSERTION_TYPE, type);

	data = gcr_certificate_get_der_data (certificate, &n_data);
	g_return_val_if_fail (data, NULL);
	gck_attributes_add_data (attrs, CKA_X_CERTIFICATE_VALUE, data, n_data);

	return attrs;
}

/* ----------------------------------------------------------------------------------
 * GET PINNED CERTIFICATE
 */

static GckAttributes *
prepare_is_certificate_pinned (GcrCertificate *certificate, const gchar *purpose, const gchar *peer)
{
	GckAttributes *attrs;

	attrs = prepare_trust_attrs (certificate, CKT_X_PINNED_CERTIFICATE);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_string (attrs, CKA_X_PURPOSE, purpose);
	gck_attributes_add_string (attrs, CKA_X_PEER, peer);

	return attrs;
}

static gboolean
perform_is_certificate_pinned (GckAttributes *search,
                               GCancellable *cancellable,
                               GError **error)
{
	GckEnumerator *en;
	GList *slots;
	GckObject *object;

	if (!_gcr_initialize_pkcs11 (cancellable, error))
		return FALSE;

	slots = gcr_pkcs11_get_trust_lookup_slots ();
	_gcr_debug ("searching for pinned certificate in %d slots",
	            g_list_length (slots));
	en = gck_slots_enumerate_objects (slots, search, 0);
	gck_list_unref_free (slots);

	object = gck_enumerator_next (en, cancellable, error);
	g_object_unref (en);

	if (object)
		g_object_unref (object);

	_gcr_debug ("%s certificate anchor", object ? "found" : "did not find");
	return (object != NULL);
}

/**
 * gcr_trust_is_certificate_pinned:
 * @certificate: a #GcrCertificate to check
 * @purpose: the purpose string
 * @peer: the peer for this pinned
 * @cancellable: a #GCancellable
 * @error: a #GError, or NULL
 *
 * Check if @certificate is pinned for @purpose to communicate with @peer.
 * A pinned certificate overrides all other certificate verification.
 *
 * This call may block, see gcr_trust_is_certificate_pinned_async() for the
 * non-blocking version.
 *
 * In the case of an error, %FALSE is also returned. Check @error to detect
 * if an error occurred.
 *
 * Returns: %TRUE if the certificate is pinned for the host and purpose
 */
gboolean
gcr_trust_is_certificate_pinned (GcrCertificate *certificate, const gchar *purpose,
                                 const gchar *peer, GCancellable *cancellable, GError **error)
{
	GckAttributes *search;
	gboolean ret;

	g_return_val_if_fail (GCR_IS_CERTIFICATE (certificate), FALSE);
	g_return_val_if_fail (purpose, FALSE);
	g_return_val_if_fail (peer, FALSE);

	search = prepare_is_certificate_pinned (certificate, purpose, peer);
	g_return_val_if_fail (search, FALSE);

	ret = perform_is_certificate_pinned (search, cancellable, error);
	gck_attributes_unref (search);

	return ret;
}

static void
thread_is_certificate_pinned (GSimpleAsyncResult *result, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;
	trust_closure *closure;

	closure = g_simple_async_result_get_op_res_gpointer (result);
	closure->found = perform_is_certificate_pinned (closure->attrs, cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (result, error);
		g_clear_error (&error);
	}
}

/**
 * gcr_trust_is_certificate_pinned_async:
 * @certificate: a #GcrCertificate to check
 * @purpose: the purpose string
 * @peer: the peer for this pinned
 * @cancellable: a #GCancellable
 * @callback: a #GAsyncReadyCallback to call when the operation completes
 * @user_data: the data to pass to callback function
 *
 * Check if @certificate is pinned for @purpose to communicate with @peer. A
 * pinned certificate overrides all other certificate verification.
 *
 * When the operation is finished, callback will be called. You can then call
 * gcr_trust_is_certificate_pinned_finish() to get the result of the
 * operation.
 */
void
gcr_trust_is_certificate_pinned_async (GcrCertificate *certificate, const gchar *purpose,
                                       const gchar *peer, GCancellable *cancellable,
                                       GAsyncReadyCallback callback, gpointer user_data)
{
	GSimpleAsyncResult *async;
	trust_closure *closure;

	g_return_if_fail (GCR_CERTIFICATE (certificate));
	g_return_if_fail (purpose);
	g_return_if_fail (peer);

	async = g_simple_async_result_new (NULL, callback, user_data,
	                                   gcr_trust_is_certificate_pinned_async);
	closure = g_new0 (trust_closure, 1);
	closure->attrs = prepare_is_certificate_pinned (certificate, purpose, peer);
	g_return_if_fail (closure->attrs);
	g_simple_async_result_set_op_res_gpointer (async, closure, trust_closure_free);

	g_simple_async_result_run_in_thread (async, thread_is_certificate_pinned,
	                                     G_PRIORITY_DEFAULT, cancellable);

	g_object_unref (async);
}

/**
 * gcr_trust_is_certificate_pinned_finish:
 * @result: the #GAsyncResult passed to the callback
 * @error: a #GError, or NULL
 *
 * Finishes an asynchronous operation started by
 * gcr_trust_is_certificate_pinned_async().
 *
 * In the case of an error, %FALSE is also returned. Check @error to detect
 * if an error occurred.
 *
 * Returns: %TRUE if the certificate is pinned.
 */
gboolean
gcr_trust_is_certificate_pinned_finish (GAsyncResult *result, GError **error)
{
	trust_closure *closure;

	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      gcr_trust_is_certificate_pinned_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (result));
	return closure->found;
}

/* ----------------------------------------------------------------------------------
 * ADD PINNED CERTIFICATE
 */

static GckAttributes *
prepare_add_pinned_certificate (GcrCertificate *certificate, const gchar *purpose, const gchar *peer)
{
	GckAttributes *attrs;

	attrs = prepare_trust_attrs (certificate, CKT_X_PINNED_CERTIFICATE);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_string (attrs, CKA_X_PURPOSE, purpose);
	gck_attributes_add_string (attrs, CKA_X_PEER, peer);
	gck_attributes_add_boolean (attrs, CKA_TOKEN, TRUE);

	return attrs;
}

static gboolean
perform_add_pinned_certificate (GckAttributes *search,
                                GCancellable *cancellable,
                                GError **error)
{
	GckAttributes *attrs;
	gboolean ret = FALSE;
	GError *lerr = NULL;
	GckObject *object;
	GckSession *session;
	GckSlot *slot;
	GckEnumerator *en;
	GList *slots;

	if (!_gcr_initialize_pkcs11 (cancellable, error))
		return FALSE;

	slots = gcr_pkcs11_get_trust_lookup_slots ();
	en = gck_slots_enumerate_objects (slots, search, CKF_RW_SESSION);
	gck_list_unref_free (slots);

	/* We need an error below */
	if (error && !*error)
		*error = lerr;

	object = gck_enumerator_next (en, cancellable, error);
	g_object_unref (en);

	if (*error)
		return FALSE;

	/* It already exists */
	if (object) {
		g_object_unref (object);
		return TRUE;
	}

	attrs = gck_attributes_new ();
	gck_attributes_add_all (attrs, search);

	/* TODO: Add relevant label */

	/* Find an appropriate token */
	slot = gcr_pkcs11_get_trust_store_slot ();
	if (slot == NULL) {
		g_set_error (error, GCK_ERROR, CKR_FUNCTION_FAILED,
		             /* Translators: A pinned certificate is an exception which
		                trusts a given certificate explicitly for a purpose and
		                communication with a certain peer. */
		             _("Couldn't find a place to store the pinned certificate"));
		ret = FALSE;
	} else {
		session = gck_slot_open_session (slot, CKF_RW_SESSION, NULL, error);
		if (session != NULL) {
			object = gck_session_create_object (session, attrs, cancellable, error);
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

/**
 * gcr_trust_add_pinned_certificate:
 * @certificate: a #GcrCertificate
 * @purpose: the purpose string
 * @peer: the peer for this pinned certificate
 * @cancellable: a #GCancellable
 * @error: a #GError, or NULL
 *
 * Add a pinned @certificate for connections to @peer for @purpose. A pinned
 * certificate overrides all other certificate verification and should be
 * used with care.
 *
 * If the same pinned certificate already exists, then this operation
 * does not add another, and succeeds without error.
 *
 * This call may block, see gcr_trust_add_pinned_certificate_async() for the
 * non-blocking version.
 *
 * Returns: %TRUE if the pinned certificate is recorded successfully
 */
gboolean
gcr_trust_add_pinned_certificate (GcrCertificate *certificate, const gchar *purpose, const gchar *peer,
                                  GCancellable *cancellable, GError **error)
{
	GckAttributes *search;
	gboolean ret;

	g_return_val_if_fail (GCR_IS_CERTIFICATE (certificate), FALSE);
	g_return_val_if_fail (purpose, FALSE);
	g_return_val_if_fail (peer, FALSE);

	search = prepare_add_pinned_certificate (certificate, purpose, peer);
	g_return_val_if_fail (search, FALSE);

	ret = perform_add_pinned_certificate (search, cancellable, error);
	gck_attributes_unref (search);

	return ret;
}

static void
thread_add_pinned_certificate (GSimpleAsyncResult *result, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;
	trust_closure *closure;

	closure = g_simple_async_result_get_op_res_gpointer (result);
	perform_add_pinned_certificate (closure->attrs, cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (result, error);
		g_clear_error (&error);
	}
}

/**
 * gcr_trust_add_pinned_certificate_async:
 * @certificate: a #GcrCertificate
 * @purpose: the purpose string
 * @peer: the peer for this pinned certificate
 * @cancellable: a #GCancellable
 * @callback: a #GAsyncReadyCallback to call when the operation completes
 * @user_data: the data to pass to callback function
 *
 * Add a pinned certificate for communication with @peer for @purpose. A pinned
 * certificate overrides all other certificate verification and should be used
 * with care.
 *
 * If the same pinned certificate already exists, then this operation
 * does not add another, and succeeds without error.
 *
 * When the operation is finished, callback will be called. You can then call
 * gcr_trust_add_pinned_certificate_finish() to get the result of the
 * operation.
 */
void
gcr_trust_add_pinned_certificate_async (GcrCertificate *certificate, const gchar *purpose,
                                        const gchar *peer, GCancellable *cancellable,
                                        GAsyncReadyCallback callback, gpointer user_data)
{
	GSimpleAsyncResult *async;
	trust_closure *closure;

	g_return_if_fail (GCR_IS_CERTIFICATE (certificate));
	g_return_if_fail (purpose);
	g_return_if_fail (peer);

	async = g_simple_async_result_new (NULL, callback, user_data,
	                                   gcr_trust_add_pinned_certificate_async);
	closure = g_new0 (trust_closure, 1);
	closure->attrs = prepare_add_pinned_certificate (certificate, purpose, peer);
	g_return_if_fail (closure->attrs);
	g_simple_async_result_set_op_res_gpointer (async, closure, trust_closure_free);

	g_simple_async_result_run_in_thread (async, thread_add_pinned_certificate,
	                                     G_PRIORITY_DEFAULT, cancellable);

	g_object_unref (async);
}

/**
 * gcr_trust_add_pinned_certificate_finish:
 * @result: the #GAsyncResult passed to the callback
 * @error: a #GError, or NULL
 *
 * Finishes an asynchronous operation started by
 * gcr_trust_add_pinned_certificate_async().
 *
 * Returns: %TRUE if the pinned certificate is recorded successfully
 */
gboolean
gcr_trust_add_pinned_certificate_finish (GAsyncResult *result, GError **error)
{
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      gcr_trust_add_pinned_certificate_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	return TRUE;
}

/* -----------------------------------------------------------------------
 * REMOVE PINNED CERTIFICATE
 */

static GckAttributes *
prepare_remove_pinned_certificate (GcrCertificate *certificate, const gchar *purpose,
                                   const gchar *peer)
{
	GckAttributes *attrs;

	attrs = prepare_trust_attrs (certificate, CKT_X_PINNED_CERTIFICATE);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_string (attrs, CKA_X_PURPOSE, purpose);
	gck_attributes_add_string (attrs, CKA_X_PEER, peer);

	return attrs;
}

static gboolean
perform_remove_pinned_certificate (GckAttributes *attrs,
                                   GCancellable *cancellable,
                                   GError **error)
{
	GList *objects, *l;
	GError *lerr = NULL;
	GckEnumerator *en;
	GList *slots;

	if (!_gcr_initialize_pkcs11 (cancellable, error))
		return FALSE;

	slots = gcr_pkcs11_get_trust_lookup_slots ();
	en = gck_slots_enumerate_objects (slots, attrs, CKF_RW_SESSION);
	gck_list_unref_free (slots);

	/* We need an error below */
	if (error && !*error)
		*error = lerr;

	objects = gck_enumerator_next_n (en, -1, cancellable, error);
	g_object_unref (en);

	if (*error)
		return FALSE;

	for (l = objects; l; l = g_list_next (l)) {
		if (!gck_object_destroy (l->data, cancellable, error)) {

			/* In case there's a race condition */
			if (g_error_matches (*error, GCK_ERROR, CKR_OBJECT_HANDLE_INVALID)) {
				g_clear_error (error);
				continue;
			}

			gck_list_unref_free (objects);
			return FALSE;
		}
	}

	gck_list_unref_free (objects);
	return TRUE;
}

/**
 * gcr_trust_remove_pinned_certificate:
 * @certificate: a #GcrCertificate
 * @purpose: the purpose string
 * @peer: the peer for this pinned certificate
 * @cancellable: a #GCancellable
 * @error: a #GError, or NULL
 *
 * Remove a pinned certificate for communication with @peer for @purpose.
 *
 * If the same pinned certificate does not exist, or was already removed,
 * then this operation succeeds without error.
 *
 * This call may block, see gcr_trust_remove_pinned_certificate_async() for the
 * non-blocking version.
 *
 * Returns: %TRUE if the pinned certificate no longer exists
 */
gboolean
gcr_trust_remove_pinned_certificate (GcrCertificate *certificate, const gchar *purpose, const gchar *peer,
                                     GCancellable *cancellable, GError **error)
{
	GckAttributes *search;
	gboolean ret;

	g_return_val_if_fail (GCR_IS_CERTIFICATE (certificate), FALSE);
	g_return_val_if_fail (purpose, FALSE);
	g_return_val_if_fail (peer, FALSE);

	search = prepare_remove_pinned_certificate (certificate, purpose, peer);
	g_return_val_if_fail (search, FALSE);

	ret = perform_remove_pinned_certificate (search, cancellable, error);
	gck_attributes_unref (search);

	return ret;
}

static void
thread_remove_pinned_certificate (GSimpleAsyncResult *result, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;
	trust_closure *closure;

	closure = g_simple_async_result_get_op_res_gpointer (result);
	perform_remove_pinned_certificate (closure->attrs, cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (result, error);
		g_clear_error (&error);
	}
}

/**
 * gcr_trust_remove_pinned_certificate_async:
 * @certificate: a #GcrCertificate
 * @purpose: the purpose string
 * @peer: the peer for this pinned certificate
 * @cancellable: a #GCancellable
 * @callback: a #GAsyncReadyCallback to call when the operation completes
 * @user_data: the data to pass to callback function
 *
 * Remove a pinned certificate for communication with @peer for @purpose.
 *
 * If the same pinned certificate does not exist, or was already removed,
 * then this operation succeeds without error.
 *
 * When the operation is finished, callback will be called. You can then call
 * gcr_trust_remove_pinned_certificate_finish() to get the result of the
 * operation.
 */
void
gcr_trust_remove_pinned_certificate_async (GcrCertificate *certificate, const gchar *purpose,
                                           const gchar *peer, GCancellable *cancellable,
                                           GAsyncReadyCallback callback, gpointer user_data)
{
	GSimpleAsyncResult *async;
	trust_closure *closure;

	g_return_if_fail (GCR_IS_CERTIFICATE (certificate));
	g_return_if_fail (purpose);
	g_return_if_fail (peer);

	async = g_simple_async_result_new (NULL, callback, user_data,
	                                   gcr_trust_remove_pinned_certificate_async);
	closure = g_new0 (trust_closure, 1);
	closure->attrs = prepare_remove_pinned_certificate (certificate, purpose, peer);
	g_return_if_fail (closure->attrs);
	g_simple_async_result_set_op_res_gpointer (async, closure, trust_closure_free);

	g_simple_async_result_run_in_thread (async, thread_remove_pinned_certificate,
	                                     G_PRIORITY_DEFAULT, cancellable);

	g_object_unref (async);
}

/**
 * gcr_trust_remove_pinned_certificate_finish:
 * @result: the #GAsyncResult passed to the callback
 * @error: a #GError, or NULL
 *
 * Finishes an asynchronous operation started by
 * gcr_trust_remove_pinned_certificate_async().
 *
 * Returns: %TRUE if the pinned certificate no longer exists
 */
gboolean
gcr_trust_remove_pinned_certificate_finish (GAsyncResult *result, GError **error)
{
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      gcr_trust_remove_pinned_certificate_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	return TRUE;
}

/* ----------------------------------------------------------------------------------
 * CERTIFICATE ROOT
 */

static GckAttributes *
prepare_is_certificate_anchored (GcrCertificate *certificate, const gchar *purpose)
{
	GckAttributes *attrs;

	attrs = prepare_trust_attrs (certificate, CKT_X_ANCHORED_CERTIFICATE);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_string (attrs, CKA_X_PURPOSE, purpose);

	return attrs;
}

static gboolean
perform_is_certificate_anchored (GckAttributes *attrs,
                                 GCancellable *cancellable,
                                 GError **error)
{
	GckEnumerator *en;
	GList *slots;
	GckObject *object;

	if (!_gcr_initialize_pkcs11 (cancellable, error))
		return FALSE;

	slots = gcr_pkcs11_get_trust_lookup_slots ();
	_gcr_debug ("searching for certificate anchor in %d slots",
	            g_list_length (slots));
	en = gck_slots_enumerate_objects (slots, attrs, 0);
	gck_list_unref_free (slots);

	object = gck_enumerator_next (en, cancellable, error);
	g_object_unref (en);

	if (object != NULL)
		g_object_unref (object);

	_gcr_debug ("%s certificate anchor", object ? "found" : "did not find");
	return (object != NULL);
}

/**
 * gcr_trust_is_certificate_anchored:
 * @certificate: a #GcrCertificate to check
 * @purpose: the purpose string
 * @cancellable: a #GCancellable
 * @error: a #GError, or NULL
 *
 * Check if the @certificate is a trust anchor for the given @purpose. A trust
 * anchor is used to verify the signatures on other certificates when verifying
 * a certificate chain. Also known as a trusted certificate authority.
 *
 * This call may block, see gcr_trust_is_certificate_anchored_async() for the
 * non-blocking version.
 *
 * In the case of an error, %FALSE is also returned. Check @error to detect
 * if an error occurred.
 *
 * Returns: %TRUE if the certificate is a trust anchor
 */
gboolean
gcr_trust_is_certificate_anchored (GcrCertificate *certificate, const gchar *purpose,
                                   GCancellable *cancellable, GError **error)
{
	GckAttributes *search;
	gboolean ret;

	g_return_val_if_fail (GCR_IS_CERTIFICATE (certificate), FALSE);
	g_return_val_if_fail (purpose, FALSE);

	search = prepare_is_certificate_anchored (certificate, purpose);
	g_return_val_if_fail (search, FALSE);

	ret = perform_is_certificate_anchored (search, cancellable, error);
	gck_attributes_unref (search);

	return ret;
}

static void
thread_is_certificate_anchored (GSimpleAsyncResult *result, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;
	trust_closure *closure;

	closure = g_simple_async_result_get_op_res_gpointer (result);
	closure->found = perform_is_certificate_anchored (closure->attrs, cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (result, error);
		g_clear_error (&error);
	}
}

/**
 * gcr_trust_is_certificate_anchored_async:
 * @certificate: a #GcrCertificate to check
 * @purpose: the purpose string
 * @cancellable: a #GCancellable
 * @callback: a #GAsyncReadyCallback to call when the operation completes
 * @user_data: the data to pass to callback function
 *
 * Check if the @certificate is a trust anchor for the given @purpose. A trust
 * anchor is used to verify the signatures on other certificates when verifying
 * a certificate chain. Also known as a trusted certificate authority.
 *
 * When the operation is finished, callback will be called. You can then call
 * gcr_trust_is_certificate_anchored_finish() to get the result of the operation.
 */
void
gcr_trust_is_certificate_anchored_async (GcrCertificate *certificate, const gchar *purpose,
                                         GCancellable *cancellable, GAsyncReadyCallback callback,
                                         gpointer user_data)
{
	GSimpleAsyncResult *async;
	trust_closure *closure;

	g_return_if_fail (GCR_IS_CERTIFICATE (certificate));
	g_return_if_fail (purpose);

	async = g_simple_async_result_new (NULL, callback, user_data,
	                                   gcr_trust_is_certificate_anchored_async);
	closure = g_new0 (trust_closure, 1);
	closure->attrs = prepare_is_certificate_anchored (certificate, purpose);
	g_return_if_fail (closure->attrs);
	g_simple_async_result_set_op_res_gpointer (async, closure, trust_closure_free);

	g_simple_async_result_run_in_thread (async, thread_is_certificate_anchored,
	                                     G_PRIORITY_DEFAULT, cancellable);

	g_object_unref (async);
}

/**
 * gcr_trust_is_certificate_anchored_finish:
 * @result: the #GAsyncResult passed to the callback
 * @error: a #GError, or NULL
 *
 * Finishes an asynchronous operation started by
 * gcr_trust_is_certificate_anchored_async().
 *
 * In the case of an error, %FALSE is also returned. Check @error to detect
 * if an error occurred.
 *
 * Returns: %TRUE if the certificate is a trust anchor
 */
gboolean
gcr_trust_is_certificate_anchored_finish (GAsyncResult *result, GError **error)
{
	trust_closure *closure;

	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      gcr_trust_is_certificate_anchored_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (result));
	return closure->found;
}
