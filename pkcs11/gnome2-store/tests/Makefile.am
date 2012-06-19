include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	-I$(top_srcdir)/pkcs11 \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(GLIB_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

LDADD = \
	$(top_builddir)/pkcs11/gnome2-store/libgkm-gnome2-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

if WITH_P11_TESTS
CHECK_PROGS = check-gnome2-module
else
CHECK_PROGS =
endif

CHECK_FILES = \
	p11-tests.conf

TEST_PROGS = \
	test-gnome2-file \
	test-gnome2-storage \
	test-gnome2-private-key \
	test-import

test_gnome2_storage_SOURCES = \
	test-gnome2-storage.c \
	mock-gnome2-module.c mock-gnome2-module.h

test_gnome2_private_key_SOURCES = \
	test-gnome2-private-key.c \
	mock-gnome2-module.c mock-gnome2-module.h

test_import_CFLAGS = $(GCR_BASE_CFLAGS) $(GCK_CFLAGS)
test_import_LDADD = $(GCR_BASE_LIBS) $(GCK_LIBS) $(LDADD)

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS) $(CHECK_PROGS) $(CHECK_FILES)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)
	@for prog in $(CHECK_PROGS); do SRCDIR='.' ./$$prog || exit 1; done

check-local: test

all-local: $(check_PROGRAMS)

noinst_PROGRAMS = \
	frob-gnome2-file \
	$(CHECK_PROGS)

check_gnome2_module_CFLAGS = $(P11_TESTS_CFLAGS)
check_gnome2_module_LDADD = $(P11_TESTS_LIBS) $(LDADD)

EXTRA_DIST = \
	p11-tests.conf.in \
	files

CLEANFILES = \
	$(CHECK_FILES)
