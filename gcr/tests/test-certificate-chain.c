
#include "config.h"
#include "test-suite.h"

#include "egg/egg-asn1x.h"
#include "egg/egg-asn1-defs.h"

#include "gcr/gcr.h"

#include "gck/gck-mock.h"
#include "gck/gck-test.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11x.h"

#include <glib.h>

#include <string.h>

/* ---------------------------------------------------------------------------
 * A Mock certificate that checks that it's always called on the
 * same thread. A GcrCertificate implemented on top of a non-thread-safe
 * crypto library would require this behavior.
 */

GType               mock_certificate_get_type               (void);

#define MOCK_CERTIFICATE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST ((obj), mock_certificate_get_type (), MockCertificate))

typedef struct _MockCertificate {
	GObject parent;
	GThread *created_on;
	gpointer data;
	gsize n_data;
} MockCertificate;

typedef struct _MockCertificateClass {
	GObjectClass parent_class;
} MockCertificateClass;

static void mock_certificate_iface (GcrCertificateIface *iface);
G_DEFINE_TYPE_WITH_CODE (MockCertificate, mock_certificate, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GCR_TYPE_CERTIFICATE, mock_certificate_iface));

static void
mock_certificate_init (MockCertificate *self)
{
	self->created_on = g_thread_self ();
}

static void
mock_certificate_finalize (GObject *obj)
{
	MockCertificate *self = MOCK_CERTIFICATE (obj);
	g_assert (self->created_on == g_thread_self ());
	g_free (self->data);
	G_OBJECT_CLASS (mock_certificate_parent_class)->finalize (obj);
}

static void
mock_certificate_class_init (MockCertificateClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->finalize = mock_certificate_finalize;
}

static gconstpointer
mock_certificate_real_get_der_data (GcrCertificate *base, gsize *n_data)
{
	MockCertificate *self = MOCK_CERTIFICATE (base);
	g_assert (self->created_on == g_thread_self ());
	*n_data = self->n_data;
	return self->data;
}

static void
mock_certificate_iface (GcrCertificateIface *iface)
{
	iface->get_der_data = (gpointer)mock_certificate_real_get_der_data;
}

static GcrCertificate*
mock_certificate_new (gconstpointer data, gsize n_data)
{
	MockCertificate *self = g_object_new (mock_certificate_get_type (), NULL);
	self->data = g_memdup (data, n_data);
	self->n_data = n_data;
	g_assert (self->created_on == g_thread_self ());
	return GCR_CERTIFICATE (self);
}

/* ----------------------------------------------------------------------------
 * TESTS
 */

static GcrCertificate *cert_self = NULL;
static GcrCertificate *cert_ca = NULL;
static GcrCertificate *cert_signed = NULL;
static CK_FUNCTION_LIST funcs;

TESTING_SETUP (certificate_chain)
{
	GList *modules = NULL;
	CK_FUNCTION_LIST_PTR f;
	guchar *contents;
	gsize n_contents;
	CK_RV rv;
	GckModule *module;

	rv = gck_mock_C_GetFunctionList (&f);
	gck_assert_cmprv (rv, ==, CKR_OK);
	memcpy (&funcs, f, sizeof (funcs));

	/* Open a session */
	rv = (funcs.C_Initialize) (NULL);
	gck_assert_cmprv (rv, ==, CKR_OK);

	g_assert (!modules);
	module = gck_module_new (&funcs, 0);
	modules = g_list_prepend (modules, module);
	gcr_pkcs11_set_modules (modules);
	gcr_pkcs11_set_trust_store_uri (GCK_MOCK_SLOT_ONE_URI);
	gck_list_unref_free (modules);

	/* A self-signed certificate */
	contents = testing_data_read ("der-certificate.crt", &n_contents);
	cert_self = gcr_simple_certificate_new (contents, n_contents);
	g_free (contents);

	/* A signed certificate */
	contents = testing_data_read ("dhansak-collabora.cer", &n_contents);
	cert_signed = mock_certificate_new (contents, n_contents);
	g_free (contents);

	/* The signer for the above certificate */
	contents = testing_data_read ("collabora-ca.cer", &n_contents);
	cert_ca = mock_certificate_new (contents, n_contents);
	g_free (contents);
}

static void
add_certificate_to_module (GcrCertificate *certificate)
{
	GckAttributes *attrs;
	gconstpointer data;
	gsize n_data, n_subject;
	gpointer subject;

	data = gcr_certificate_get_der_data (certificate, &n_data);
	g_assert (data);

	subject = gcr_certificate_get_subject_raw (certificate, &n_subject);
	g_assert (subject);

	/* Add a certificate to the module */
	attrs = gck_attributes_new ();
	gck_attributes_add_data (attrs, CKA_VALUE, data, n_data);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_CERTIFICATE);
	gck_attributes_add_ulong (attrs, CKA_CERTIFICATE_TYPE, CKC_X_509);
	gck_attributes_add_data (attrs, CKA_SUBJECT, subject, n_subject);
	gck_mock_module_take_object (attrs);

	g_free (subject);
}

static void
add_anchor_to_module (GcrCertificate *certificate, const gchar *purpose)
{
	GckAttributes *attrs;
	gconstpointer data;
	gsize n_data;

	data = gcr_certificate_get_der_data (certificate, &n_data);
	g_assert (data);

	/* And add a pinned certificate for the signed certificate */
	attrs = gck_attributes_new ();
	gck_attributes_add_data (attrs, CKA_X_CERTIFICATE_VALUE, data, n_data);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_X_TRUST_ASSERTION);
	gck_attributes_add_ulong (attrs, CKA_X_ASSERTION_TYPE, CKT_X_ANCHORED_CERTIFICATE);
	gck_attributes_add_string (attrs, CKA_X_PURPOSE, purpose);
	gck_mock_module_take_object (attrs);
}

static void
add_pinned_to_module (GcrCertificate *certificate, const gchar *purpose, const gchar *host)
{
	GckAttributes *attrs;
	gconstpointer data;
	gsize n_data;

	data = gcr_certificate_get_der_data (certificate, &n_data);
	g_assert (data);

	/* And add a pinned certificate for the signed certificate */
	attrs = gck_attributes_new ();
	gck_attributes_add_data (attrs, CKA_X_CERTIFICATE_VALUE, data, n_data);
	gck_attributes_add_ulong (attrs, CKA_CLASS, CKO_X_TRUST_ASSERTION);
	gck_attributes_add_ulong (attrs, CKA_X_ASSERTION_TYPE, CKT_X_PINNED_CERTIFICATE);
	gck_attributes_add_string (attrs, CKA_X_PURPOSE, purpose);
	gck_attributes_add_string (attrs, CKA_X_PEER, host);
	gck_mock_module_take_object (attrs);
}

TESTING_TEARDOWN (certificate_chain)
{
	CK_RV rv;

	g_object_unref (cert_self);
	cert_self = NULL;

	g_object_unref (cert_signed);
	cert_signed = NULL;

	g_object_unref (cert_ca);
	cert_ca = NULL;

	rv = (funcs.C_Finalize) (NULL);
	gck_assert_cmprv (rv, ==, CKR_OK);
}

TESTING_TEST (certificate_chain_new)
{
	GcrCertificateChain *chain;

	chain = gcr_certificate_chain_new ();

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_UNKNOWN);
	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 0);

	g_assert (gcr_certificate_chain_get_endpoint (chain) == NULL);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_new_with_cert)
{
	GcrCertificateChain *chain;
	GcrCertificate *check;
	guint status, length;

	chain = gcr_certificate_chain_new ();
	gcr_certificate_chain_add (chain, cert_signed);
	gcr_certificate_chain_add (chain, cert_ca);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_UNKNOWN);
	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 2);

	status = G_MAXUINT;
	length = 0;
	g_object_get (chain, "status", &status, "length", &length, NULL);
	g_assert_cmpuint (status, ==, GCR_CERTIFICATE_CHAIN_UNKNOWN);
	g_assert_cmpuint (length, ==, 2);

	check = gcr_certificate_chain_get_certificate (chain, 1);
	g_assert (check == cert_ca);

	/* Not yet completed */
	check = gcr_certificate_chain_get_anchor (chain);
	g_assert (check == NULL);

	check = gcr_certificate_chain_get_endpoint (chain);
	g_assert (check == cert_signed);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_selfsigned)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	chain = gcr_certificate_chain_new ();

	/* Add a self-signed certificate */
	gcr_certificate_chain_add (chain, cert_self);

	if (!gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                  NULL, 0, NULL, &error))
		g_assert_not_reached ();
	g_assert_no_error (error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_SELFSIGNED);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_incomplete)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	chain = gcr_certificate_chain_new ();

	/* Add a signed certificate */
	gcr_certificate_chain_add (chain, cert_signed);

	if (!gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                  NULL, 0, NULL, &error))
		g_assert_not_reached ();
	g_assert_no_error (error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_INCOMPLETE);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_empty)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	chain = gcr_certificate_chain_new ();

	/* Add no certificate */

	if (!gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                  NULL, 0, NULL, &error))
		g_assert_not_reached ();
	g_assert_no_error (error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_UNKNOWN);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_trim_extras)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	chain = gcr_certificate_chain_new ();

	/* Add two unrelated certificates */
	gcr_certificate_chain_add (chain, cert_self);
	gcr_certificate_chain_add (chain, cert_signed);

	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 2);

	if (!gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                  NULL, 0, NULL, &error))
		g_assert_not_reached ();
	g_assert_no_error (error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_SELFSIGNED);
	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 1);

	g_object_unref (chain);
}

static void
fetch_async_result (GObject *source, GAsyncResult *result, gpointer user_data)
{
	*((GAsyncResult**)user_data) = result;
	g_object_ref (result);
	testing_wait_stop ();
}

TESTING_TEST (certificate_chain_complete_async)
{
	GcrCertificateChain *chain;
	GError *error = NULL;
	GAsyncResult *result;

	chain = gcr_certificate_chain_new ();

	/* Add a whole bunch of certificates */
	gcr_certificate_chain_add (chain, cert_signed);
	gcr_certificate_chain_add (chain, cert_ca);
	gcr_certificate_chain_add (chain, cert_self);

	gcr_certificate_chain_build_async (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                   NULL, 0, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	if (!gcr_certificate_chain_build_finish (chain, result, &error))
		g_assert_not_reached ();
	g_assert_no_error (error);
	g_object_unref (result);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_SELFSIGNED);
	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 2);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_with_anchor)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	chain = gcr_certificate_chain_new ();

	/* Two certificates in chain with ca trust anchor */
	gcr_certificate_chain_add (chain, cert_signed);
	gcr_certificate_chain_add (chain, cert_ca);
	add_anchor_to_module (cert_ca, GCR_PURPOSE_CLIENT_AUTH);

	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 2);

	if (!gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                  NULL, 0, NULL, &error))
		g_assert_not_reached ();
	g_assert_no_error (error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_ANCHORED);
	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 2);
	g_assert (gcr_certificate_chain_get_anchor (chain) == cert_ca);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_with_anchor_and_lookup_ca)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	chain = gcr_certificate_chain_new ();

	/* One signed certificate, with CA in pkcs11, and trust anchor */
	gcr_certificate_chain_add (chain, cert_signed);
	add_certificate_to_module (cert_ca);
	add_anchor_to_module (cert_ca, GCR_PURPOSE_CLIENT_AUTH);

	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 1);

	if (!gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                  NULL, 0, NULL, &error))
		g_assert_not_reached ();
	g_assert_no_error (error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_ANCHORED);
	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 2);
	g_assert (gcr_certificate_chain_get_anchor (chain) != NULL);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_with_pinned)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	chain = gcr_certificate_chain_new ();

	/* One certificate, and add CA to pkcs11 */
	gcr_certificate_chain_add (chain, cert_signed);
	gcr_certificate_chain_add (chain, cert_ca);
	add_pinned_to_module (cert_signed, GCR_PURPOSE_CLIENT_AUTH, "pinned.example.com");

	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 2);

	/* But we don't allow the lookup to happen */
	if (!gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                  "pinned.example.com", 0, NULL, &error))
		g_assert_not_reached ();
	g_assert_no_error (error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_PINNED);
	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 1);
	g_assert (gcr_certificate_chain_get_anchor (chain) == NULL);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_without_lookups)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	chain = gcr_certificate_chain_new ();

	/* One certificate, and add CA to pkcs11 */
	gcr_certificate_chain_add (chain, cert_signed);
	add_certificate_to_module (cert_ca);

	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 1);

	/* But we don't allow the lookup to happen */
	if (!gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                  NULL, GCR_CERTIFICATE_CHAIN_FLAG_NO_LOOKUPS,
	                                  NULL, &error))
		g_assert_not_reached ();
	g_assert_no_error (error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_INCOMPLETE);
	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 1);
	g_assert (gcr_certificate_chain_get_anchor (chain) == NULL);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_with_lookup_error)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	/* Make the lookup fail */
	funcs.C_GetAttributeValue = gck_mock_fail_C_GetAttributeValue;

	chain = gcr_certificate_chain_new ();

	/* Two certificates in chain with ca trust anchor */
	gcr_certificate_chain_add (chain, cert_signed);
	add_certificate_to_module (cert_ca);

	g_assert_cmpuint (gcr_certificate_chain_get_length (chain), ==, 1);

	if (gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                 NULL, 0, NULL, &error))
		g_assert_not_reached ();
	g_assert_error (error, GCK_ERROR, CKR_FUNCTION_FAILED);
	g_clear_error (&error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_UNKNOWN);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_with_anchor_error)
{
	GcrCertificateChain *chain;
	GError *error = NULL;

	/* Make the lookup fail */
	funcs.C_GetAttributeValue = gck_mock_fail_C_GetAttributeValue;

	chain = gcr_certificate_chain_new ();

	/* Two certificates in chain with ca trust anchor */
	gcr_certificate_chain_add (chain, cert_signed);
	add_certificate_to_module (cert_ca);

	if (gcr_certificate_chain_build (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                 NULL, 0, NULL, &error))
		g_assert_not_reached ();
	g_assert_error (error, GCK_ERROR, CKR_FUNCTION_FAILED);
	g_clear_error (&error);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_UNKNOWN);

	g_object_unref (chain);
}

TESTING_TEST (certificate_chain_with_anchor_error_async)
{
	GcrCertificateChain *chain;
	GError *error = NULL;
	GAsyncResult *result;

	/* Make the lookup fail */
	funcs.C_GetAttributeValue = gck_mock_fail_C_GetAttributeValue;

	chain = gcr_certificate_chain_new ();

	/* Two certificates in chain with ca trust anchor */
	gcr_certificate_chain_add (chain, cert_signed);
	add_certificate_to_module (cert_ca);

	gcr_certificate_chain_build_async (chain, GCR_PURPOSE_CLIENT_AUTH,
	                                   NULL, 0, NULL, fetch_async_result, &result);
	testing_wait_until (500);
	if (gcr_certificate_chain_build_finish (chain, result, &error))
		g_assert_not_reached ();
	g_assert_error (error, GCK_ERROR, CKR_FUNCTION_FAILED);
	g_clear_error (&error);
	g_object_unref (result);

	g_assert_cmpuint (gcr_certificate_chain_get_status (chain), ==,
	                  GCR_CERTIFICATE_CHAIN_UNKNOWN);

	g_object_unref (chain);
}
