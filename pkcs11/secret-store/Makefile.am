
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	-I$(top_srcdir)/pkcs11 \
	-DSRCDIR="\"@abs_srcdir@\"" \
    	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS)

# ------------------------------------------------------------------------------
# The secret store component code

noinst_LTLIBRARIES = \
	libgkm-secret-store.la

libgkm_secret_store_la_SOURCES = \
	gkm-secret-binary.c gkm-secret-binary.h \
	gkm-secret-collection.h gkm-secret-collection.c \
	gkm-secret-compat.h gkm-secret-compat.c \
	gkm-secret-data.h gkm-secret-data.c \
	gkm-secret-fields.h gkm-secret-fields.c \
	gkm-secret-item.h gkm-secret-item.c \
	gkm-secret-module.h gkm-secret-module.c \
	gkm-secret-object.h gkm-secret-object.c \
	gkm-secret-search.h gkm-secret-search.c \
	gkm-secret-store.h \
	gkm-secret-types.h \
	gkm-secret-textual.c gkm-secret-textual.h

# ------------------------------------------------------------------------------
# The standalone module

moduledir = $(pkcs11standalonedir)

module_LTLIBRARIES = \
	gkm-secret-store-standalone.la

gkm_secret_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList|g_module_check_init'

gkm_secret_store_standalone_la_SOURCES = \
	gkm-secret-standalone.c

gkm_secret_store_standalone_la_LIBADD = \
	libgkm-secret-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(LIBGCRYPT_LIBS)

# -------------------------------------------------------------------------------
# TESTS

LDADD = \
	libgkm-mock-secret-module.a \
	$(top_builddir)/pkcs11/secret-store/libgkm-secret-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

noinst_LIBRARIES = libgkm-mock-secret-module.a

libgkm_mock_secret_module_a_SOURCES = \
	mock-secret-module.c mock-secret-module.h

noinst_PROGRAMS = dump-keyring0-format

TEST_PROGS = \
	test-secret-compat \
	test-secret-fields \
	test-secret-data \
	test-secret-object \
	test-secret-collection \
	test-secret-item \
	test-secret-schema \
	test-secret-search \
	test-secret-textual \
	test-secret-binary \
	test-secret-schema

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

check-local: test

all-local: $(check_PROGRAMS)

EXTRA_DIST = \
	fixtures
