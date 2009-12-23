
#include "egg/egg-asn1x.h"
#include "testing/testing.h"

#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#define extern
#include "egg/asn1-def-pkix.h"
#include "egg/asn1-def-pk.h"
#undef extern

static int
run (void)
{
	GNode *asn;
	gpointer data;
	gsize n_data;

	data = testing_data_read ("test-pkcs7-1.der", &n_data);
	asn = egg_asn1x_create (pkix_asn1_tab, "pkcs-7-ContentInfo");
	egg_asn1x_dump (asn);
	if (!egg_asn1x_decode (asn, data, n_data))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
	g_free (data);

	data = testing_data_read ("test-rsakey-1.der", &n_data);
	asn = egg_asn1x_create (pk_asn1_tab, "RSAPrivateKey");
	egg_asn1x_dump (asn);
	if (!egg_asn1x_decode (asn, data, n_data))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
	g_free (data);

	data = testing_data_read ("test-pkcs8-1.der", &n_data);
	asn = egg_asn1x_create (pkix_asn1_tab, "pkcs-8-PrivateKeyInfo");
	egg_asn1x_dump (asn);
	if (!egg_asn1x_decode (asn, data, n_data))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
	g_free (data);

	data = testing_data_read ("test-certificate-1.der", &n_data);
	asn = egg_asn1x_create (pkix_asn1_tab, "Certificate");
	egg_asn1x_dump (asn);
	if (!egg_asn1x_decode (asn, data, n_data))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
	g_free (data);

	data = testing_data_read ("test-pkcs12-1.der", &n_data);
	asn = egg_asn1x_create (pkix_asn1_tab, "pkcs-12-PFX");
	egg_asn1x_dump (asn);
	if (!egg_asn1x_decode (asn, data, n_data))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
	g_free (data);

	return 0;
}

#include "testing/testing.c"
