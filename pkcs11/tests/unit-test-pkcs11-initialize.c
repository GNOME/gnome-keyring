
#include <glib.h>
#include <string.h>

#include "run-auto-test.h"

#include "gp11/gp11.h"

DEFINE_TEST(module_arguments)
{
	GP11Module *module;
	GError *err = NULL;

	/* Test that extra arguments allow successful initialize */
	module = gp11_module_initialize ("../.libs/gnome-keyring-pkcs11.so", "socket='/tmp/blah' invalid=yes", &err);
	g_assert (module);
	g_assert (!err);
	
	g_object_unref (module);
}
