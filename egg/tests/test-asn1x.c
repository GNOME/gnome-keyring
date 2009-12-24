
#include "egg/egg-asn1x.h"
#include "testing/testing.h"

#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#define extern
#include "egg/asn1-def-pkix.h"
#include "egg/asn1-def-pk.h"
#undef extern

#if 0
static void
build_personal_name (void)
{
	ASN1_TYPE asn1_pkix = NULL, asn;
	guchar buffer[10024];
	int res, len;

	res = asn1_array2tree (pkix_asn1_tab, &asn1_pkix, NULL);
	g_assert (res == ASN1_SUCCESS);

	res = asn1_create_element (asn1_pkix, "PKIX1.PersonalName", &asn);
	g_assert (res == ASN1_SUCCESS);

	asn1_write_value (asn, "surname", "Turanga", 7);
	asn1_write_value (asn, "given-name", "Leela", 5);
	asn1_write_value (asn, "initials", NULL, 0);
	asn1_write_value (asn, "generation-qualifier", "Alien", 5);

	len = sizeof (buffer);
	res = asn1_der_coding (asn, "", buffer, &len, NULL);
	g_assert (res == ASN1_SUCCESS);

	asn1_delete_structure (&asn);
	asn1_delete_structure (&asn1_pkix);

	if (!g_file_set_contents ("/tmp/personal-name.der", (gchar*)buffer, len, NULL))
		g_assert (FALSE);

}
#endif

static int
run (void)
{
	GNode *asn;
	gpointer data;
	gsize n_data;

	/* Build up a personal name, which is a set */
#if 0
	build_personal_name ();
#endif

	data = testing_data_read ("test-certificate-1.der", &n_data);
	asn = egg_asn1x_create (pkix_asn1_tab, "Certificate");
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

	data = testing_data_read ("test-rsakey-1.der", &n_data);
	asn = egg_asn1x_create (pk_asn1_tab, "RSAPrivateKey");
	egg_asn1x_dump (asn);
	if (!egg_asn1x_decode (asn, data, n_data))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
	g_free (data);

	data = testing_data_read ("test-personalname-1.der", &n_data);
	asn = egg_asn1x_create (pkix_asn1_tab, "PersonalName");
	egg_asn1x_dump (asn);
	if (!egg_asn1x_decode (asn, data, n_data))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
	g_free (data);

	data = testing_data_read ("test-pkcs7-1.der", &n_data);
	asn = egg_asn1x_create (pkix_asn1_tab, "pkcs-7-ContentInfo");
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
