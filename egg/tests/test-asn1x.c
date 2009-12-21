
#include "egg/egg-asn1x.h"
#include "testing/testing.h"

#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#define extern
#include "egg/asn1-def-pkix.h"
#undef extern

static int
run (void)
{
	GNode *asn;
	gpointer data;
	gsize n_data;

	data = testing_data_read ("test-certificate-1.der", &n_data);

	asn = egg_asn1x_create (pkix_asn1_tab, "Certificate");
	egg_asn1x_dump (asn);
	if (!egg_asn1x_decode (asn, data, n_data))
		g_assert_not_reached ();
	egg_asn1x_destroy (asn);
	return 0;
}

#include "testing/testing.c"
