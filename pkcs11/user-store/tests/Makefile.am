
TESTING_FILES = \
	test-module.c \
	unit-test-user-file.c

TESTING_LIBS = \
	$(top_builddir)/pkcs11/user-store/libgkm-user-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/testing/testing.make

EXTRA_DIST = \
	test-data \
	p11-tests.conf

# ---------------------------------------------------------------------

noinst_PROGRAMS += \
	dump-data-file

dump_data_file_SOURCES = \
	dump-data-file.c

dump_data_file_LDADD = \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/pkcs11/user-store/libgkm-user-store.la \
	$(top_builddir)/egg/libegg.la \
	$(DAEMON_LIBS)
