
#include <check.h>

#include <glib.h>
#include <string.h>

#include "run-auto-test.h"
#include "gp11-test.h"

static GP11Module *module = NULL;

DEFINE_SETUP(load_module)
{
	GError *err = NULL;

	/* Successful load */
	module = gp11_module_initialize (".libs/libgp11-test-module.so", &err);
	SUCCESS_RES (module, err);
}

DEFINE_TEARDOWN(load_module)
{
	g_object_unref (module);
}

DEFINE_TEST(invalid_modules)
{
	GP11Module *invalid;
	GError *err = NULL;
	
	/* Shouldn't be able to load modules */
	invalid = gp11_module_initialize ("blah-blah-non-existant", &err);
	FAIL_RES (invalid, err);

	/* Shouldn't be able to load any file successfully */ 
	invalid = gp11_module_initialize ("/usr/lib/libm.so", &err);
	FAIL_RES (invalid, err);

}

DEFINE_TEST(module_props)
{
	gchar *path;

	g_object_get (module, "module-path", &path, NULL);
	fail_unless (path != NULL, "no module-path");
	fail_unless (strcmp (".libs/libgp11-test-module.so", path) == 0, "module path wrong");
	g_free (path);
}

DEFINE_TEST(module_info)
{
	GP11ModuleInfo *info;
	
	info = gp11_module_get_info (module);
	fail_unless (info != NULL, "no module info");
	
	fail_unless (info->pkcs11_version_major == CRYPTOKI_VERSION_MAJOR, "wrong major version"); 
	fail_unless (info->pkcs11_version_minor == CRYPTOKI_VERSION_MINOR, "wrong minor version"); 
	fail_unless (strcmp ("TEST MANUFACTURER", info->manufacturer_id) == 0);
	fail_unless (strcmp ("TEST LIBRARY", info->library_description) == 0);
	fail_unless (0 == info->flags);
	fail_unless (45 == info->library_version_major);
	fail_unless (145 == info->library_version_minor);
	
	gp11_module_info_free (info);
}
