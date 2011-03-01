
#include "config.h"
#include "test-suite.h"

#include "gcr/gcr.h"
#include "gcr/gcr-internal.h"

#include <glib.h>

#include <string.h>

static GcrCertificate *certificate = NULL;
static GcrCertificate *dsa_cert = NULL;
static GcrCertificate *dhansak_cert = NULL;

TESTING_SETUP(certificate)
{
	guchar *contents;
	gsize n_contents;

	contents = testing_data_read ("der-certificate.crt", &n_contents);
	certificate = gcr_simple_certificate_new (contents, n_contents);
	g_assert (certificate);
	g_free (contents);

	contents = testing_data_read ("der-certificate-dsa.cer", &n_contents);
	dsa_cert = gcr_simple_certificate_new (contents, n_contents);
	g_assert (dsa_cert);
	g_free (contents);

	contents = testing_data_read ("dhansak-collabora.cer", &n_contents);
	dhansak_cert = gcr_simple_certificate_new (contents, n_contents);
	g_assert (certificate);
	g_free (contents);
}

TESTING_TEARDOWN(certificate)
{
	g_object_unref (certificate);
	certificate = NULL;
	g_object_unref (dsa_cert);
	dsa_cert = NULL;
	g_object_unref (dhansak_cert);
	dhansak_cert = NULL;
}

TESTING_TEST(issuer_cn)
{
	gchar *cn = gcr_certificate_get_issuer_cn (certificate);
	g_assert (cn);
	g_assert_cmpstr (cn, ==, "http://www.valicert.com/");
	g_free (cn);
}

TESTING_TEST(issuer_dn)
{
	gchar *dn = gcr_certificate_get_issuer_dn (certificate);
	g_assert (dn);
	g_assert_cmpstr (dn, ==, "L=ValiCert Validation Network, O=ValiCert, Inc., OU=ValiCert Class 3 Policy Validation Authority, CN=http://www.valicert.com/, EMAIL=info@valicert.com");
	g_free (dn);
}

TESTING_TEST(issuer_part)
{
	gchar *part = gcr_certificate_get_issuer_part (certificate, "l");
	g_assert (part);
	g_assert_cmpstr (part, ==, "ValiCert Validation Network");
	g_free (part);
}

TESTING_TEST(issuer_raw)
{
	gpointer der;
	gsize n_der;

	der = gcr_certificate_get_issuer_raw (certificate, &n_der);
	g_assert (der);
	g_assert_cmpsize (n_der, ==, 190);
	g_free (der);
}

TESTING_TEST(subject_cn)
{
	gchar *cn = gcr_certificate_get_subject_cn (certificate);
	g_assert (cn);
	g_assert_cmpstr (cn, ==, "http://www.valicert.com/");
	g_free (cn);

	cn = gcr_certificate_get_subject_cn (dhansak_cert);
	g_assert (cn);
	g_assert_cmpstr (cn, ==, "dhansak.collabora.co.uk");
	g_free (cn);
}

TESTING_TEST(subject_dn)
{
	gchar *dn = gcr_certificate_get_subject_dn (certificate);
	g_assert (dn);
	g_assert_cmpstr (dn, ==, "L=ValiCert Validation Network, O=ValiCert, Inc., OU=ValiCert Class 3 Policy Validation Authority, CN=http://www.valicert.com/, EMAIL=info@valicert.com");
	g_free (dn);

	dn = gcr_certificate_get_subject_dn (dhansak_cert);
	g_assert (dn);
	g_assert_cmpstr (dn, ==, "CN=dhansak.collabora.co.uk, EMAIL=sysadmin@collabora.co.uk");
	g_free (dn);

}

TESTING_TEST(subject_part)
{
	gchar *part = gcr_certificate_get_subject_part (certificate, "OU");
	g_assert (part);
	g_assert_cmpstr (part, ==, "ValiCert Class 3 Policy Validation Authority");
	g_free (part);

	part = gcr_certificate_get_subject_part (dhansak_cert, "EMAIL");
	g_assert (part);
	g_assert_cmpstr (part, ==, "sysadmin@collabora.co.uk");
	g_free (part);

}

TESTING_TEST(subject_raw)
{
	gpointer der;
	gsize n_der;

	der = gcr_certificate_get_subject_raw (certificate, &n_der);
	g_assert (der);
	g_assert_cmpsize (n_der, ==, 190);
	g_free (der);

	der = gcr_certificate_get_subject_raw (dhansak_cert, &n_der);
	g_assert (der);
	g_assert_cmpsize (n_der, ==, 77);
	g_free (der);
}

TESTING_TEST(issued_date)
{
	GDate *date = gcr_certificate_get_issued_date (certificate);
	g_assert (date);
	g_assert_cmpuint (g_date_get_year (date), ==, 1999);
	g_assert_cmpuint (g_date_get_month (date), ==, 6);
	g_assert_cmpuint (g_date_get_day (date), ==, 26);
	g_date_free (date);
}

TESTING_TEST(expiry_date)
{
	GDate *date = gcr_certificate_get_expiry_date (certificate);
	g_assert (date);
	g_assert_cmpuint (g_date_get_year (date), ==, 2019);
	g_assert_cmpuint (g_date_get_month (date), ==, 6);
	g_assert_cmpuint (g_date_get_day (date), ==, 26);
	g_date_free (date);
}

TESTING_TEST(serial_number)
{
	gsize n_serial;
	guchar *serial;
	gchar *hex;

	serial = gcr_certificate_get_serial_number (certificate, &n_serial);
	g_assert (serial);
	g_assert_cmpuint (n_serial, ==, 1);
	g_assert (memcmp (serial, "\1", n_serial) == 0);
	g_free (serial);

	hex = gcr_certificate_get_serial_number_hex (certificate);
	g_assert (hex);
	g_assert_cmpstr (hex, ==, "01");
	g_free (hex);
}

TESTING_TEST(fingerprint)
{
	gsize n_print;
	guchar *print = gcr_certificate_get_fingerprint (certificate, G_CHECKSUM_MD5, &n_print);
	g_assert (print);
	g_assert_cmpuint (n_print, ==, g_checksum_type_get_length (G_CHECKSUM_MD5));
	g_assert (memcmp (print, "\xa2\x6f\x53\xb7\xee\x40\xdb\x4a\x68\xe7\xfa\x18\xd9\x10\x4b\x72", n_print) == 0);
	g_free (print);
}

TESTING_TEST(fingerprint_hex)
{
	gchar *print = gcr_certificate_get_fingerprint_hex (certificate, G_CHECKSUM_MD5);
	g_assert (print);
	g_assert_cmpstr (print, ==, "A2 6F 53 B7 EE 40 DB 4A 68 E7 FA 18 D9 10 4B 72");
	g_free (print);
}

TESTING_TEST (certificate_key_size)
{
	guint key_size = gcr_certificate_get_key_size (certificate);
	g_assert_cmpuint (key_size, ==, 1024);

	key_size = gcr_certificate_get_key_size (dsa_cert);
	g_assert_cmpuint (key_size, ==, 1024);
}

TESTING_TEST (certificate_is_issuer)
{
	gboolean ret = gcr_certificate_is_issuer (certificate, certificate);
	g_assert (ret == TRUE);

	ret = gcr_certificate_is_issuer (certificate, dsa_cert);
	g_assert (ret == FALSE);
}
