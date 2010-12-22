
TESTING_SOURCES = \
	test-xdg-module.h

# Test files should be listed in order they need to run
TESTING_FILES = \
	test-xdg-module.c \
	test-xdg-trust.c

TESTING_LIBS =  \
	$(top_builddir)/pkcs11/xdg-store/libgkm-xdg-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/testing/testing.make

EXTRA_DIST += \
	p11-tests.conf \
	test-data

# ------------------------------------------------------------------------------

noinst_PROGRAMS += \
	diddle-trust-file \
	dump-trust-file

diddle_trust_file_LDADD =  \
	$(top_builddir)/egg/libegg.la
dump_trust_file_LDADD =  \
	$(top_builddir)/egg/libegg.la
