include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	-I$(top_srcdir)/pkcs11 \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS)

# ------------------------------------------------------------------------------
# The xdg-store component code

noinst_LTLIBRARIES = \
	libgkm-xdg-store.la

libgkm_xdg_store_la_SOURCES = \
	gkm-xdg-store.h \
	gkm-xdg-asn1-defs.c gkm-xdg-asn1-defs.h \
	gkm-xdg-assertion.c gkm-xdg-assertion.h \
	gkm-xdg-module.c gkm-xdg-module.h \
	gkm-xdg-trust.c gkm-xdg-trust.h \
	xdg.asn.h \
	$(NULL)

EXTRA_DIST = \
	xdg.asn \
	$(NULL)

# ------------------------------------------------------------------------------
# The standalone module

moduledir = $(pkcs11standalonedir)

module_LTLIBRARIES = \
	gkm-xdg-store-standalone.la

gkm_xdg_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList|g_module_check_init'

gkm_xdg_store_standalone_la_SOURCES = \
	gkm-xdg-standalone.c

gkm_xdg_store_standalone_la_LIBADD = \
	libgkm-xdg-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(LIBGCRYPT_LIBS)

asn:
	asn1Parser -o xdg.asn.h xdg.asn
	sed -i 's|#include.*|/* \0 */|' xdg.asn.h

# -------------------------------------------------------------------------------
# TESTS

LDADD = \
	libgkm-mock-xdg-module.a \
	$(top_builddir)/pkcs11/xdg-store/libgkm-xdg-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(LIBGCRYPT_LIBS)

if WITH_P11_TESTS
CHECK_PROGS = check-xdg-module
else
CHECK_PROGS =
endif

TEST_PROGS = \
	test-xdg-module \
	test-xdg-trust

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS) $(CHECK_PROGS)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)
	@for prog in $(CHECK_PROGS); do SRCDIR='.' ./$$prog || exit 1; done

check-local: test

all-local: $(check_PROGRAMS)

EXTRA_DIST += \
	p11-tests.conf \
	fixtures

noinst_PROGRAMS = \
	frob-trust-file \
	dump-trust-file \
	$(CHECK_PROGS)

check_xdg_module_CFLAGS = $(P11_TESTS_CFLAGS)
check_xdg_module_LDADD = $(P11_TESTS_LIBS) $(LDADD)

noinst_LIBRARIES = libgkm-mock-xdg-module.a

libgkm_mock_xdg_module_a_SOURCES = \
	mock-xdg-module.c mock-xdg-module.h
