
TESTING_FILES = \
	unit-test-gnome2-file.c \
	test-module.c

TESTING_LIBS = \
	$(top_builddir)/pkcs11/gnome2-store/libgkm-gnome2-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/testing/testing.make

EXTRA_DIST = \
	test-data \
	p11-tests.conf

# ---------------------------------------------------------------------

noinst_PROGRAMS += \
	dump-gnome2-file

dump_gnome2_file_SOURCES = \
	dump-gnome2-file.c

dump_gnome2_file_LDADD = \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/pkcs11/gnome2-store/libgkm-gnome2-store.la \
	$(top_builddir)/egg/libegg.la \
	$(DAEMON_LIBS)
