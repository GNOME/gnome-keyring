
#include <glib.h>
#include <string.h>

#include "test-suite.h"
#include "gck-test.h"

#define MECH_TYPE 55
#define MECH_DATA "TEST DATA"
#define N_MECH_DATA ((gsize)9)

DEFINE_TEST(mech_new)
{
	GckMechanism *mech;

	mech = gck_mechanism_new (MECH_TYPE);

	g_assert (mech);
	g_assert (mech->type == MECH_TYPE);
	g_assert (mech->parameter == NULL);
	g_assert (mech->n_parameter == 0);

	gck_mechanism_unref (mech);
}

DEFINE_TEST(mech_new_with_param)
{
	GckMechanism *mech;
	gpointer parameter = MECH_DATA;

	mech = gck_mechanism_new_with_param (MECH_TYPE, parameter, N_MECH_DATA);

	g_assert (mech);
	g_assert (mech->type == MECH_TYPE);
	g_assert (mech->parameter != NULL);
	g_assert (mech->parameter != parameter); /* Copied */
	g_assert (mech->n_parameter == N_MECH_DATA);
	g_assert (memcmp (mech->parameter, MECH_DATA, N_MECH_DATA) == 0);

	gck_mechanism_unref (mech);
}

DEFINE_TEST(mech_ref_unref)
{
	GckMechanism *mech, *check;

	mech = gck_mechanism_new (MECH_TYPE);
	g_assert (mech);

	check = gck_mechanism_ref (mech);
	g_assert (check == mech);

	gck_mechanism_unref (check);
	gck_mechanism_unref (mech);
}

DEFINE_TEST(mech_unref_null)
{
	gck_mechanism_unref (NULL);
}
