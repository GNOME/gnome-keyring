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

#include <pkcs11/pkcs11n.h>

/* ----------------------------------------------------------------------------------
 * HELPERS
 */

typedef struct _GcrTrustOperation {
	GckEnumerator *en;
	GckAttributes *attrs;
	GcrPurpose purpose;
	GcrTrust trust;
} GcrTrustOperation;

static CK_ATTRIBUTE_TYPE
attribute_type_for_purpose (GcrPurpose purpose)
{
	switch (purpose) {
	case GCR_PURPOSE_SERVER_AUTH:
		return CKA_TRUST_SERVER_AUTH;
	case GCR_PURPOSE_CLIENT_AUTH:
		return CKA_TRUST_CLIENT_AUTH;
	case GCR_PURPOSE_CODE_SIGNING:
		return CKA_TRUST_CODE_SIGNING;
	case GCR_PURPOSE_EMAIL:
		return CKA_TRUST_EMAIL_PROTECTION;
	case GCR_PURPOSE_TIME_STAMPING:
		return CKA_TRUST_TIME_STAMPING;
	case GCR_PURPOSE_IPSEC_ENDPOINT:
		return CKA_TRUST_IPSEC_END_SYSTEM;
	case GCR_PURPOSE_IPSEC_TUNNEL:
		return CKA_TRUST_IPSEC_TUNNEL;
	case GCR_PURPOSE_IPSEC_USER:
		return CKA_TRUST_IPSEC_USER;
	case GCR_PURPOSE_IKE_INTERMEDIATE:
		g_return_val_if_reached ((CK_ULONG)-1);
	default:
		g_return_val_if_reached ((CK_ULONG)-1);
	};
}

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
trust_operation_init (GckEnumerator *en, GckAttributes *attrs,
                      GcrPurpose purpose, GcrTrust trust)
{
	GcrTrustOperation *op;

	g_assert (GCK_IS_ENUMERATOR (en));
	g_assert (!g_object_get_data (G_OBJECT (en), "trust-operation"));
	g_assert (attrs);

	op = g_slice_new0 (GcrTrustOperation);
	op->purpose = purpose;
	op->trust = trust;
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
prepare_trust_attrs (GcrCertificate *cert)
{
	GckAttributes *attrs;
	gpointer data;
	gsize n_data;

	attrs = gck_attributes_new ();
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_NETSCAPE_TRUST);

	data = gcr_certificate_get_issuer_raw (cert, &n_data);
	g_return_val_if_fail (data, NULL);
	gck_attributes_add_data (attrs, CKA_ISSUER, data, n_data);
	g_free (data);

	data = gcr_certificate_get_serial_number (cert, &n_data);
	g_return_val_if_fail (data, NULL);
	gck_attributes_add_data (attrs, CKA_SERIAL_NUMBER, data, n_data);
	g_free (data);

	data = gcr_certificate_get_fingerprint (cert, G_CHECKSUM_SHA1, &n_data);
	g_return_val_if_fail (data, NULL);
	gck_attributes_add_data (attrs, CKA_CERT_SHA1_HASH, data, n_data);
	g_free (data);

	return attrs;
}

/* ----------------------------------------------------------------------------------
 * GET CERTIFICATE EXCEPTION
 */

static GckEnumerator*
prepare_get_certificate_exception (GcrCertificate *cert, GcrPurpose purpose)
{
	GckAttributes *attrs;
	GckEnumerator *en;
	GList *modules;

	modules = _gcr_get_pkcs11_modules ();

	attrs = prepare_trust_attrs (cert);
	g_return_val_if_fail (attrs, NULL);

	/*
	 * TODO: We need to be able to sort the modules by preference
	 * on which sources of trust storage we want to read over which
	 * others.
	 */

	en = gck_modules_enumerate_objects (modules, attrs, 0);
	trust_operation_init (en, attrs, purpose, GCR_TRUST_UNKNOWN);
	gck_attributes_unref (attrs);

	return en;
}

static GcrTrust
perform_get_certificate_exception (GckEnumerator *en, GCancellable *cancel, GError **error)
{
	CK_ATTRIBUTE_TYPE type;
	GcrTrustOperation *op;
	GckObject *object;
	gpointer data;
	gsize n_data;
	gulong value;

	op = trust_operation_get (en);

	g_assert (op != NULL);
	g_assert (op->trust == GCR_TRUST_UNKNOWN);

	type = attribute_type_for_purpose (op->purpose);

	while (op->trust == GCR_TRUST_UNKNOWN) {
		object = gck_enumerator_next (en, cancel, error);
		if (!object)
			break;

		data = gck_object_get_data (object, type, &n_data, error);

		g_object_unref (object);

		if (!data)
			break;

		if (!gck_value_to_ulong (data, n_data, &value)) {
			g_message ("an invalid sized value was received for trust attribute");
			value = CKT_NETSCAPE_TRUST_UNKNOWN;
		}

		if (value == CKT_NETSCAPE_TRUSTED)
			op->trust = GCR_TRUST_TRUSTED;
		else if (value == CKT_NETSCAPE_UNTRUSTED)
			op->trust = GCR_TRUST_UNTRUSTED;

		g_free (data);
	}

	return op->trust;
}

GcrTrust
gcr_trust_get_certificate_exception (GcrCertificate *cert, GcrPurpose purpose,
                                     GCancellable *cancel, GError **error)
{
	GckEnumerator *en;
	GcrTrust trust;

	en = prepare_get_certificate_exception (cert, purpose);
	g_return_val_if_fail (en, GCR_TRUST_UNKNOWN);

	trust = perform_get_certificate_exception (en, cancel, error);

	g_object_unref (en);

	return trust;
}

static void
thread_get_certificate_exception (GSimpleAsyncResult *res, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;

	perform_get_certificate_exception (GCK_ENUMERATOR (object), cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (res, error);
		g_clear_error (&error);
	}
}

void
gcr_trust_get_certificate_exception_async (GcrCertificate *cert, GcrPurpose purpose,
                                           GCancellable *cancel, GAsyncReadyCallback callback,
                                           gpointer user_data)
{
	GSimpleAsyncResult *async;
	GckEnumerator *en;

	en = prepare_get_certificate_exception (cert, purpose);
	g_return_if_fail (en);

	async = g_simple_async_result_new (G_OBJECT (en), callback, user_data,
	                                   gcr_trust_get_certificate_exception_async);

	g_simple_async_result_run_in_thread (async, thread_get_certificate_exception,
	                                     G_PRIORITY_DEFAULT, cancel);

	g_object_unref (async);
	g_object_unref (en);
}

GcrTrust
gcr_trust_get_certificate_exception_finish (GAsyncResult *res, GError **error)
{
	GcrTrustOperation *op;
	GObject *object;

	object = g_async_result_get_source_object (res);
	g_return_val_if_fail (g_simple_async_result_is_valid (res, object,
	                      gcr_trust_get_certificate_exception_async), GCR_TRUST_UNKNOWN);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
		return GCR_TRUST_UNKNOWN;

	op = trust_operation_get (GCK_ENUMERATOR (object));
	return op->trust;
}

/* ----------------------------------------------------------------------------------
 * SET CERTIFICATE EXCEPTION
 */

static GckEnumerator*
prepare_set_certificate_exception (GcrCertificate *cert, GcrPurpose purpose, GcrTrust trust)
{
	GckAttributes *attrs;
	GckEnumerator *en;
	GList *modules;
	gpointer data;
	gsize n_data;

	modules = _gcr_get_pkcs11_modules ();

	attrs = prepare_trust_attrs (cert);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_boolean (attrs, CKA_MODIFIABLE, TRUE);
	gck_attributes_add_boolean (attrs, CKA_TOKEN, TRUE);

	data = gcr_certificate_get_subject_raw (cert, &n_data);
	g_return_val_if_fail (data, NULL);
	gck_attributes_add_data (attrs, CKA_SUBJECT, data, n_data);
	g_free (data);

	data = gcr_certificate_get_fingerprint (cert, G_CHECKSUM_MD5, &n_data);
	g_return_val_if_fail (data, NULL);
	gck_attributes_add_data (attrs, CKA_CERT_MD5_HASH, data, n_data);
	g_free (data);

	/*
	 * TODO: We need to be able to sort the modules by preference
	 * on which sources of trust storage we want to read over which
	 * others.
	 */

	en = gck_modules_enumerate_objects (modules, attrs, CKF_RW_SESSION);
	trust_operation_init (en, attrs, purpose, trust);
	gck_attributes_unref (attrs);

	return en;
}

static gboolean
perform_set_certificate_exception (GckEnumerator *en, GCancellable *cancel, GError **error)
{
	CK_ATTRIBUTE_TYPE type;
	GcrTrustOperation *op;
	GckAttributes *attrs;
	gboolean ret = FALSE;
	GError *lerr = NULL;
	GckObject *object;
	GckSession *session;
	gulong value;
	GckSlot *slot;

	op = trust_operation_get (en);
	g_assert (op != NULL);

	/* We need an error below */
	if (error && !*error)
		*error = lerr;

	switch (op->trust) {
	case GCR_TRUST_UNKNOWN:
		value = CKT_NETSCAPE_TRUST_UNKNOWN;
		break;
	case GCR_TRUST_UNTRUSTED:
		value = CKT_NETSCAPE_UNTRUSTED;
		break;
	case GCR_TRUST_TRUSTED:
		value = CKT_NETSCAPE_TRUSTED;
		break;
	}

	type = attribute_type_for_purpose (op->purpose);
	attrs = gck_attributes_new ();

	object = gck_enumerator_next (en, cancel, error);

	/* Only set this one attribute */
	if (object) {

		gck_attributes_add_ulong (attrs, type, value);
		ret = gck_object_set (object, attrs, cancel, error);

	/* Use all trust attributes to create trust object */
	} else if (!*error) {

		gck_attributes_add_all (attrs, op->attrs);
		gck_attributes_add_ulong (attrs, type, value);

		/* Find an appropriate token */
		slot = _gcr_slot_for_storing_trust (error);
		if (slot != NULL) {
			session = gck_slot_open_session (slot, CKF_RW_SESSION, error);
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
	}

	gck_attributes_unref (attrs);

	/* Our own local error pointer */
	g_clear_error (&lerr);

	return ret;
}

gboolean
gcr_trust_set_certificate_exception (GcrCertificate *cert, GcrPurpose purpose, GcrTrust trust,
                                     GCancellable *cancel, GError **error)
{
	GckEnumerator *en;
	gboolean ret;

	en = prepare_set_certificate_exception (cert, purpose, trust);
	g_return_val_if_fail (en, FALSE);

	ret = perform_set_certificate_exception (en, cancel, error);

	g_object_unref (en);

	return ret;
}

static void
thread_set_certificate_exception (GSimpleAsyncResult *res, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;

	perform_set_certificate_exception (GCK_ENUMERATOR (object), cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (res, error);
		g_clear_error (&error);
	}
}

void
gcr_trust_set_certificate_exception_async (GcrCertificate *cert, GcrPurpose purpose,
                                           GcrTrust trust, GCancellable *cancel,
                                           GAsyncReadyCallback callback, gpointer user_data)
{
	GSimpleAsyncResult *async;
	GckEnumerator *en;

	en = prepare_set_certificate_exception (cert, purpose, trust);
	g_return_if_fail (en);

	async = g_simple_async_result_new (G_OBJECT (en), callback, user_data,
	                                   gcr_trust_set_certificate_exception_async);

	g_simple_async_result_run_in_thread (async, thread_set_certificate_exception,
	                                     G_PRIORITY_DEFAULT, cancel);

	g_object_unref (async);
	g_object_unref (en);
}

gboolean
gcr_trust_set_certificate_exception_finish (GAsyncResult *res, GError **error)
{
	GObject *object;

	object = g_async_result_get_source_object (res);
	g_return_val_if_fail (g_simple_async_result_is_valid (res, object,
	                      gcr_trust_set_certificate_exception_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
		return FALSE;

	return TRUE;
}

/* ----------------------------------------------------------------------------------
 * CERTIFICATE ROOT
 */

static GckEnumerator*
prepare_is_certificate_root (GcrCertificate *cert, GcrPurpose purpose)
{
	GckAttributes *attrs;
	GckEnumerator *en;
	GList *modules;

	modules = _gcr_get_pkcs11_modules ();

	attrs = prepare_trust_attrs (cert);
	g_return_val_if_fail (attrs, NULL);

	gck_attributes_add_ulong (attrs, attribute_type_for_purpose (purpose),
	                          CKT_NETSCAPE_TRUSTED_DELEGATOR);

	/*
	 * TODO: We need to be able to sort the modules by preference
	 * on which sources of trust storage we want to read over which
	 * others.
	 */

	en = gck_modules_enumerate_objects (modules, attrs, CKF_RW_SESSION);
	trust_operation_init (en, attrs, purpose, GCR_TRUST_UNKNOWN);
	gck_attributes_unref (attrs);

	return en;
}

static gboolean
perform_is_certificate_root (GckEnumerator *en, GCancellable *cancel, GError **error)
{
	GcrTrustOperation *op;
	GckObject *object;

	op = trust_operation_get (en);
	g_assert (op != NULL);

	object = gck_enumerator_next (en, cancel, error);
	if (object != NULL) {
		op->trust = GCR_TRUST_TRUSTED;
		g_object_unref (object);
		return TRUE;
	}

	return FALSE;
}

gboolean
gcr_trust_is_certificate_root (GcrCertificate *cert, GcrPurpose purpose,
                               GCancellable *cancel, GError **error)
{
	GckEnumerator *en;
	gboolean ret;

	en = prepare_is_certificate_root (cert, purpose);
	g_return_val_if_fail (en, FALSE);

	ret = perform_is_certificate_root (en, cancel, error);

	g_object_unref (en);

	return ret;
}

static void
thread_is_certificate_root (GSimpleAsyncResult *res, GObject *object, GCancellable *cancel)
{
	GError *error = NULL;

	perform_is_certificate_root (GCK_ENUMERATOR (object), cancel, &error);

	if (error != NULL) {
		g_simple_async_result_set_from_error (res, error);
		g_clear_error (&error);
	}
}

void
gcr_trust_is_certificate_root_async (GcrCertificate *cert, GcrPurpose purpose,
                                     GCancellable *cancel, GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	GSimpleAsyncResult *async;
	GckEnumerator *en;

	en = prepare_is_certificate_root (cert, purpose);
	g_return_if_fail (en);

	async = g_simple_async_result_new (G_OBJECT (en), callback, user_data,
	                                   gcr_trust_is_certificate_root_async);

	g_simple_async_result_run_in_thread (async, thread_is_certificate_root,
	                                     G_PRIORITY_DEFAULT, cancel);

	g_object_unref (async);
	g_object_unref (en);
}

gboolean
gcr_trust_is_certificate_root_finish (GAsyncResult *res, GError **error)
{
	GcrTrustOperation *op;
	GObject *object;

	object = g_async_result_get_source_object (res);
	g_return_val_if_fail (g_simple_async_result_is_valid (res, object,
	                      gcr_trust_is_certificate_root_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
		return FALSE;

	op = trust_operation_get (GCK_ENUMERATOR (object));
	return op->trust == GCR_TRUST_TRUSTED;
}
