
# Test files should be listed in order they need to run
TESTING_FILES = \
	test-xdg-module.c test-xdg-module.h \
	test-xdg-trust.c

TESTING_LIBS =  \
	$(top_builddir)/pkcs11/xdg-store/libgkm-xdg-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la

EXTRA_DIST = \
	p11-tests.conf \
	test-data

include $(top_srcdir)/testing/testing.make

# ------------------------------------------------------------------------------

noinst_PROGRAMS += \
	diddle-trust-file

diddle_trust_file_LDADD =  \
	$(top_builddir)/egg/libegg.la
